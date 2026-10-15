"""
RDAP Adapter for Domain Age
"""
import asyncio
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

import httpx

from .base import IntelAdapter, IntelResult, IntelVerdict, IntelSource

logger = logging.getLogger(__name__)


class RDAPAdapter(IntelAdapter):
    """
    RDAP (Registration Data Access Protocol) adapter for domain age.
    Queries RDAP servers to get domain registration date.
    Does NOT use scraped WHOIS - uses official RDAP only.
    """

    # RDAP bootstrap URLs for different TLDs
    BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
    DEFAULT_RDAP_SERVERS = {
        "com": "https://rdap.verisign.com/com/v1/domain/",
        "net": "https://rdap.verisign.com/net/v1/domain/",
        "org": "https://rdap.publicinterestregistry.org/rdap/domain/",
        "info": "https://rdap.afilias.net/rdap/domain/",
        "biz": "https://rdap.neustar.biz/rdap/domain/",
    }

    def __init__(
        self,
        redis_client,
        timeout: float = 10.0,
        **kwargs,
    ):
        super().__init__(
            source=IntelSource.RDAP,
            redis_client=redis_client,
            api_key=None,
            timeout=timeout,
            rate_limit=kwargs.get("rate_limit", 60),  # Be nice to RDAP servers
            circuit_breaker_threshold=10,
            circuit_breaker_timeout=120,
            **kwargs,
        )
        self.client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)
        self._bootstrap_cache: Optional[Dict[str, str]] = None
        self._bootstrap_loaded_at: Optional[datetime] = None

    async def _get_rdap_server(self, domain: str) -> Optional[str]:
        """Get RDAP server for a domain's TLD."""
        # Extract TLD
        import tldextract
        extracted = tldextract.extract(domain)
        tld = extracted.suffix.lower()

        # Check bootstrap cache
        if self._bootstrap_cache is None or \
           (self._bootstrap_loaded_at and (datetime.utcnow() - self._bootstrap_loaded_at) > timedelta(days=1)):
            await self._load_bootstrap()

        # Check known servers first
        if tld in self.DEFAULT_RDAP_SERVERS:
            return self.DEFAULT_RDAP_SERVERS[tld]

        # Check bootstrap data
        if self._bootstrap_cache and tld in self._bootstrap_cache:
            return self._bootstrap_cache[tld]

        # Fallback: try common patterns
        return f"https://rdap.{tld}/domain/"

    async def _load_bootstrap(self):
        """Load RDAP bootstrap data from IANA."""
        try:
            response = await self.client.get(self.BOOTSTRAP_URL)
            response.raise_for_status()
            data = response.json()

            # Parse bootstrap: { "services": [ [["tld1", "tld2"], ["rdap://server"]] ] }
            services = data.get("services", [])
            bootstrap = {}
            for service in services:
                tlds = service[0]
                urls = service[1]
                for tld in tlds:
                    for url in urls:
                        if url.startswith("rdap://"):
                            # Convert rdap:// to https://
                            url = "https://" + url[7:]
                        if not url.endswith("/"):
                            url += "/"
                        bootstrap[tld] = url
                        break  # Use first URL

            self._bootstrap_cache = bootstrap
            self._bootstrap_loaded_at = datetime.utcnow()
            logger.debug(f"Loaded RDAP bootstrap for {len(bootstrap)} TLDs")
        except Exception as e:
            logger.warning(f"Failed to load RDAP bootstrap: {e}")
            self._bootstrap_cache = {}

    def _parse_registration_date(self, rdap_data: Dict[str, Any]) -> Optional[datetime]:
        """Extract registration date from RDAP response."""
        # RDAP uses "events" array with "eventAction": "registration"
        events = rdap_data.get("events", [])
        for event in events:
            if event.get("eventAction") == "registration":
                date_str = event.get("eventDate")
                if date_str:
                    try:
                        # Parse ISO format with or without timezone
                        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                    except Exception:
                        pass

        # Fallback: check "registrationDate" field (some servers)
        if "registrationDate" in rdap_data:
            try:
                return datetime.fromisoformat(rdap_data["registrationDate"].replace("Z", "+00:00"))
            except Exception:
                pass

        return None

    async def _check_impl(self, indicator: str, indicator_type: str) -> IntelResult:
        """Get domain age via RDAP."""
        if indicator_type not in ("domain", "url"):
            return IntelResult(
                source=self.source,
                verdict=IntelVerdict.UNKNOWN,
                confidence=0,
                details={"error": f"Unsupported indicator type: {indicator_type}"},
                note="intel_unavailable: unsupported indicator type",
            )

        # Extract domain
        if indicator_type == "url":
            parsed = urlparse(indicator)
            domain = parsed.netloc.lower()
            # Remove port
            if ":" in domain:
                domain = domain.split(":")[0]
        else:
            domain = indicator.lower()

        # Get RDAP server
        rdap_server = await self._get_rdap_server(domain)
        if not rdap_server:
            return IntelResult(
                source=self.source,
                verdict=IntelVerdict.UNKNOWN,
                confidence=0,
                details={"error": "No RDAP server found for TLD", "domain": domain},
                note="intel_unavailable: no RDAP server for TLD",
            )

        # Query RDAP
        url = f"{rdap_server}{domain}"
        try:
            response = await self.client.get(url, headers={"Accept": "application/rdap+json"})
            if response.status_code == 404:
                return IntelResult(
                    source=self.source,
                    verdict=IntelVerdict.UNKNOWN,
                    confidence=0,
                    details={"error": "Domain not found in RDAP", "domain": domain},
                    note="Domain not found in RDAP",
                )
            response.raise_for_status()
            data = response.json()

            reg_date = self._parse_registration_date(data)
            if not reg_date:
                return IntelResult(
                    source=self.source,
                    verdict=IntelVerdict.UNKNOWN,
                    confidence=0,
                    details={"error": "No registration date in RDAP response", "domain": domain},
                    note="intel_unavailable: no registration date in RDAP",
                )

            age_days = (datetime.utcnow() - reg_date.replace(tzinfo=None)).days

            # Determine verdict based on age
            # New domains (< 30 days) are suspicious
            if age_days < 7:
                verdict = IntelVerdict.SUSPICIOUS
                confidence = 70
                note = f"Domain registered {age_days} days ago (very new)"
            elif age_days < 30:
                verdict = IntelVerdict.SUSPICIOUS
                confidence = 60
                note = f"Domain registered {age_days} days ago (new)"
            elif age_days < 90:
                verdict = IntelVerdict.CLEAN
                confidence = 50
                note = f"Domain registered {age_days} days ago (recent)"
            else:
                verdict = IntelVerdict.CLEAN
                confidence = 80
                note = f"Domain age: {age_days} days"

            return IntelResult(
                source=self.source,
                verdict=verdict,
                confidence=confidence,
                details={
                    "domain": domain,
                    "registration_date": reg_date.isoformat(),
                    "age_days": age_days,
                    "rdap_server": rdap_server,
                },
                note=note,
            )

        except httpx.HTTPStatusError as e:
            logger.warning(f"RDAP query failed for {domain}: {e.response.status_code}")
            raise
        except Exception as e:
            logger.error(f"RDAP error for {domain}: {e}")
            raise

    async def _check_batch_impl(self, indicators: List[str], indicator_type: str) -> List[IntelResult]:
        """Batch check - RDAP doesn't support batch, so sequential."""
        results = []
        for indicator in indicators:
            result = await self._check_impl(indicator, indicator_type)
            results.append(result)
            # Small delay to be nice to servers
            await asyncio.sleep(0.1)
        return results

    async def close(self):
        await self.client.aclose()