"""
Intel Manager - Orchestrates all threat intelligence adapters
"""
import asyncio
import logging
from typing import Dict, Any, List, Optional, Set
from datetime import datetime

import redis.asyncio as redis

from .base import IntelAdapter, IntelResult, IntelVerdict, IntelSource, CacheConfig
from .google_safe_browsing import GoogleSafeBrowsingAdapter
from .virustotal import VirusTotalAdapter
from .openphish import OpenPhishAdapter
from .phishtank import PhishTankAdapter
from .rdap import RDAPAdapter
from .dns import DNSAdapter
from .tls import TLSAdapter

logger = logging.getLogger(__name__)


class IntelManager:
    """
    Manages all threat intelligence adapters.
    Provides unified interface for checking URLs/domains against all sources.
    """

    def __init__(
        self,
        redis_client: redis.Redis,
        config: Dict[str, Any],
    ):
        self.redis = redis_client
        self.config = config
        self.adapters: Dict[IntelSource, IntelAdapter] = {}
        self._enabled_sources: Set[IntelSource] = set()
        self._initialize_adapters()

    def _initialize_adapters(self):
        """Initialize all configured adapters."""
        cache_config = CacheConfig(
            clean_ttl=self.config.get("cache_clean_ttl", 86400 * 7),
            suspicious_ttl=self.config.get("cache_suspicious_ttl", 86400),
            malicious_ttl=self.config.get("cache_malicious_ttl", 86400 * 30),
            unknown_ttl=self.config.get("cache_unknown_ttl", 3600),
            error_ttl=self.config.get("cache_error_ttl", 300),
        )

        # Google Safe Browsing
        gsb_key = self.config.get("google_safe_browsing_api_key")
        if gsb_key:
            self.adapters[IntelSource.GOOGLE_SAFE_BROWSING] = GoogleSafeBrowsingAdapter(
                redis_client=self.redis,
                api_key=gsb_key,
                timeout=self.config.get("gsb_timeout", 10.0),
                rate_limit=self.config.get("gsb_rate_limit", 10000),
            )
            self._enabled_sources.add(IntelSource.GOOGLE_SAFE_BROWSING)

        # VirusTotal
        vt_key = self.config.get("virustotal_api_key")
        if vt_key:
            self.adapters[IntelSource.VIRUSTOTAL] = VirusTotalAdapter(
                redis_client=self.redis,
                api_key=vt_key,
                timeout=self.config.get("vt_timeout", 15.0),
                rate_limit=self.config.get("vt_rate_limit", 4),
            )
            self._enabled_sources.add(IntelSource.VIRUSTOTAL)

        # OpenPhish (local feed)
        openphish_path = self.config.get("openphish_feed_path", "data/feeds/openphish.txt")
        self.adapters[IntelSource.OPENPHISH] = OpenPhishAdapter(
            redis_client=self.redis,
            feed_path=openphish_path,
            timeout=self.config.get("feed_timeout", 1.0),
        )
        self._enabled_sources.add(IntelSource.OPENPHISH)

        # PhishTank (local feed)
        phishtank_path = self.config.get("phishtank_feed_path", "data/feeds/phishtank.json")
        self.adapters[IntelSource.PHISHTANK] = PhishTankAdapter(
            redis_client=self.redis,
            feed_path=phishtank_path,
            timeout=self.config.get("feed_timeout", 1.0),
        )
        self._enabled_sources.add(IntelSource.PHISHTANK)

        # RDAP (domain age)
        self.adapters[IntelSource.RDAP] = RDAPAdapter(
            redis_client=self.redis,
            timeout=self.config.get("rdap_timeout", 10.0),
            rate_limit=self.config.get("rdap_rate_limit", 60),
        )
        self._enabled_sources.add(IntelSource.RDAP)

        # DNS
        self.adapters[IntelSource.DNS] = DNSAdapter(
            redis_client=self.redis,
            timeout=self.config.get("dns_timeout", 5.0),
            rate_limit=self.config.get("dns_rate_limit", 200),
        )
        self._enabled_sources.add(IntelSource.DNS)

        # TLS
        self.adapters[IntelSource.TLS] = TLSAdapter(
            redis_client=self.redis,
            timeout=self.config.get("tls_timeout", 10.0),
            rate_limit=self.config.get("tls_rate_limit", 100),
        )
        self._enabled_sources.add(IntelSource.TLS)

        logger.info(f"Initialized {len(self.adapters)} intel adapters: {[s.value for s in self._enabled_sources]}")

    async def check_url(self, url: str, sources: Optional[List[IntelSource]] = None) -> Dict[IntelSource, IntelResult]:
        """Check a URL against selected intel sources."""
        return await self._check_indicator(url, "url", sources)

    async def check_domain(self, domain: str, sources: Optional[List[IntelSource]] = None) -> Dict[IntelSource, IntelResult]:
        """Check a domain against selected intel sources."""
        return await self._check_indicator(domain, "domain", sources)

    async def _check_indicator(
        self,
        indicator: str,
        indicator_type: str,
        sources: Optional[List[IntelSource]] = None,
    ) -> Dict[IntelSource, IntelResult]:
        """Check indicator against specified sources (or all enabled)."""
        if sources is None:
            sources = list(self._enabled_sources)
        else:
            sources = [s for s in sources if s in self._enabled_sources]

        tasks = []
        for source in sources:
            adapter = self.adapters.get(source)
            if adapter:
                if indicator_type == "url":
                    tasks.append(adapter.check(indicator, "url"))
                else:
                    tasks.append(adapter.check(indicator, "domain"))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        output = {}
        for source, result in zip(sources, results):
            if isinstance(result, Exception):
                logger.error(f"Intel check failed for {source.value}: {result}")
                output[source] = IntelResult(
                    source=source,
                    verdict=IntelVerdict.UNKNOWN,
                    confidence=0,
                    details={"error": str(result)},
                    note=f"intel_unavailable: {type(result).__name__}",
                )
            else:
                output[source] = result

        return output

    async def check_batch(
        self,
        indicators: List[str],
        indicator_type: str = "url",
        sources: Optional[List[IntelSource]] = None,
    ) -> Dict[str, Dict[IntelSource, IntelResult]]:
        """Check multiple indicators against selected sources."""
        if sources is None:
            sources = list(self._enabled_sources)
        else:
            sources = [s for s in sources if s in self._enabled_sources]

        output = {}
        for indicator in indicators:
            output[indicator] = await self._check_indicator(indicator, indicator_type, sources)

        return output

    def get_enabled_sources(self) -> List[IntelSource]:
        """Get list of enabled intel sources."""
        return list(self._enabled_sources)

    async def reload_feeds(self):
        """Reload local feeds (OpenPhish, PhishTank)."""
        for source in [IntelSource.OPENPHISH, IntelSource.PHISHTANK]:
            adapter = self.adapters.get(source)
            if adapter and hasattr(adapter, "reload"):
                await adapter.reload()
                logger.info(f"Reloaded feed for {source.value}")

    async def close(self):
        """Close all adapters."""
        for adapter in self.adapters.values():
            if hasattr(adapter, "close"):
                await adapter.close()
        logger.info("Closed all intel adapters")


async def create_intel_manager(redis_client: redis.Redis, config: Dict[str, Any]) -> IntelManager:
    """Factory function to create IntelManager."""
    return IntelManager(redis_client, config)