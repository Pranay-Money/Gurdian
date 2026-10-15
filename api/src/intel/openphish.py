"""
OpenPhish Feed Adapter (local feed)
"""
import asyncio
import hashlib
import logging
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional, Set

from .base import IntelAdapter, IntelResult, IntelVerdict, IntelSource

logger = logging.getLogger(__name__)


class OpenPhishAdapter(IntelAdapter):
    """
    OpenPhish feed adapter.
    Loads phishing URLs from local feed file (updated periodically by blocklist job).
    Feed format: one URL per line.
    """

    def __init__(
        self,
        redis_client,
        feed_path: str = "data/feeds/openphish.txt",
        timeout: float = 1.0,
        **kwargs,
    ):
        super().__init__(
            source=IntelSource.OPENPHISH,
            redis_client=redis_client,
            api_key=None,
            timeout=timeout,
            rate_limit=kwargs.get("rate_limit", 10000),  # Local, no real limit
            circuit_breaker_threshold=100,  # Essentially disabled for local
            **kwargs,
        )
        self.feed_path = Path(feed_path)
        self._url_set: Set[str] = set()
        self._domain_set: Set[str] = set()
        self._loaded_at: Optional[datetime] = None
        self._reload_interval = timedelta(hours=1)
        self._load_lock = asyncio.Lock()

    async def _ensure_loaded(self):
        """Load feed if not loaded or stale."""
        async with self._load_lock:
            now = datetime.utcnow()
            if self._loaded_at and (now - self._loaded_at) < self._reload_interval:
                return

            await self._load_feed()
            self._loaded_at = now

    async def _load_feed(self):
        """Load phishing URLs from feed file."""
        if not self.feed_path.exists():
            logger.warning(f"OpenPhish feed not found at {self.feed_path}")
            self._url_set = set()
            self._domain_set = set()
            return

        try:
            urls = set()
            domains = set()
            with open(self.feed_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Extract URL
                    url = line
                    urls.add(url)
                    # Extract domain for domain-level checks
                    from urllib.parse import urlparse
                    try:
                        parsed = urlparse(url)
                        if parsed.netloc:
                            domains.add(parsed.netloc.lower())
                    except Exception:
                        pass

            self._url_set = urls
            self._domain_set = domains
            logger.info(f"Loaded {len(urls)} URLs and {len(domains)} domains from OpenPhish feed")
        except Exception as e:
            logger.error(f"Failed to load OpenPhish feed: {e}")

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for comparison."""
        # Remove scheme, www, trailing slash
        url = url.lower().strip()
        if url.startswith("http://"):
            url = url[7:]
        elif url.startswith("https://"):
            url = url[8:]
        if url.startswith("www."):
            url = url[4:]
        if url.endswith("/"):
            url = url[:-1]
        return url

    def _extract_domain(self, indicator: str, indicator_type: str) -> str:
        """Extract domain from URL or return domain as-is."""
        if indicator_type == "domain":
            return indicator.lower()
        from urllib.parse import urlparse
        try:
            parsed = urlparse(indicator)
            return parsed.netloc.lower()
        except Exception:
            return indicator.lower()

    async def _check_impl(self, indicator: str, indicator_type: str) -> IntelResult:
        """Check if URL or domain is in OpenPhish feed."""
        await self._ensure_loaded()

        if indicator_type == "url":
            normalized = self._normalize_url(indicator)
            # Check exact match and prefix match
            matched = any(
                normalized == self._normalize_url(u) or normalized.startswith(self._normalize_url(u).rstrip("/") + "/")
                for u in self._url_set
            )
            if matched:
                return IntelResult(
                    source=self.source,
                    verdict=IntelVerdict.MALICIOUS,
                    confidence=90,
                    details={"feed": "openphish", "matched_url": indicator},
                    note="Found in OpenPhish phishing feed",
                )
        elif indicator_type == "domain":
            domain = self._extract_domain(indicator, indicator_type)
            if domain in self._domain_set:
                return IntelResult(
                    source=self.source,
                    verdict=IntelVerdict.MALICIOUS,
                    confidence=85,
                    details={"feed": "openphish", "matched_domain": domain},
                    note="Domain found in OpenPhish phishing feed",
                )

        return IntelResult(
            source=self.source,
            verdict=IntelVerdict.CLEAN,
            confidence=70,
            details={"feed": "openphish"},
            note="Not found in OpenPhish feed",
        )

    async def _check_batch_impl(self, indicators: List[str], indicator_type: str) -> List[IntelResult]:
        """Batch check against loaded feed."""
        await self._ensure_loaded()
        results = []

        if indicator_type == "url":
            normalized_indicators = [self._normalize_url(i) for i in indicators]
            for orig, norm in zip(indicators, normalized_indicators):
                matched = any(
                    norm == self._normalize_url(u) or norm.startswith(self._normalize_url(u).rstrip("/") + "/")
                    for u in self._url_set
                )
                if matched:
                    results.append(IntelResult(
                        source=self.source,
                        verdict=IntelVerdict.MALICIOUS,
                        confidence=90,
                        details={"feed": "openphish", "matched_url": orig},
                        note="Found in OpenPhish phishing feed",
                    ))
                else:
                    results.append(IntelResult(
                        source=self.source,
                        verdict=IntelVerdict.CLEAN,
                        confidence=70,
                        details={"feed": "openphish"},
                        note="Not found in OpenPhish feed",
                    ))
        elif indicator_type == "domain":
            domains = [self._extract_domain(i, indicator_type) for i in indicators]
            for orig, dom in zip(indicators, domains):
                if dom in self._domain_set:
                    results.append(IntelResult(
                        source=self.source,
                        verdict=IntelVerdict.MALICIOUS,
                        confidence=85,
                        details={"feed": "openphish", "matched_domain": dom},
                        note="Domain found in OpenPhish phishing feed",
                    ))
                else:
                    results.append(IntelResult(
                        source=self.source,
                        verdict=IntelVerdict.CLEAN,
                        confidence=70,
                        details={"feed": "openphish"},
                        note="Not found in OpenPhish feed",
                    ))
        else:
            results = [IntelResult(
                source=self.source,
                verdict=IntelVerdict.UNKNOWN,
                confidence=0,
                details={"error": f"Unsupported indicator type: {indicator_type}"},
                note="intel_unavailable: unsupported indicator type",
            ) for _ in indicators]

        return results

    async def reload(self):
        """Force reload of feed."""
        async with self._load_lock:
            await self._load_feed()
            self._loaded_at = datetime.utcnow()