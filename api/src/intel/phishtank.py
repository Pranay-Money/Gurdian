"""
PhishTank Feed Adapter (local feed)
"""
import asyncio
import csv
import gzip
import logging
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional, Set

from .base import IntelAdapter, IntelResult, IntelVerdict, IntelSource

logger = logging.getLogger(__name__)


class PhishTankAdapter(IntelAdapter):
    """
    PhishTank feed adapter.
    Loads phishing data from local feed file (CSV or JSON format).
    Supports both phishtank.com export formats.
    """

    def __init__(
        self,
        redis_client,
        feed_path: str = "data/feeds/phishtank.json",
        timeout: float = 1.0,
        **kwargs,
    ):
        super().__init__(
            source=IntelSource.PHISHTANK,
            redis_client=redis_client,
            api_key=None,
            timeout=timeout,
            rate_limit=kwargs.get("rate_limit", 10000),
            circuit_breaker_threshold=100,
            **kwargs,
        )
        self.feed_path = Path(feed_path)
        self._url_set: Set[str] = set()
        self._domain_set: Set[str] = set()
        self._phish_details: Dict[str, Dict[str, Any]] = {}  # url -> details
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
        """Load phishing data from feed file (JSON or CSV)."""
        if not self.feed_path.exists():
            logger.warning(f"PhishTank feed not found at {self.feed_path}")
            self._url_set = set()
            self._domain_set = set()
            self._phish_details = {}
            return

        try:
            urls = set()
            domains = set()
            details = {}

            if self.feed_path.suffix == ".gz":
                # Handle gzipped files
                import gzip
                opener = gzip.open
                mode = "rt"
            else:
                opener = open
                mode = "r"

            with opener(self.feed_path, mode, encoding="utf-8") as f:
                if self.feed_path.suffix in (".json", ".json.gz"):
                    # JSON format: array of objects with url, phish_id, verified, etc.
                    import json
                    data = json.load(f)
                    for entry in data:
                        url = entry.get("url") or entry.get("phish_url")
                        if url:
                            urls.add(url)
                            details[url] = entry
                            from urllib.parse import urlparse
                            try:
                                parsed = urlparse(url)
                                if parsed.netloc:
                                    domains.add(parsed.netloc.lower())
                            except Exception:
                                pass

                elif self.feed_path.suffix in (".csv", ".csv.gz"):
                    # CSV format: phish_id,url,phish_detail_url,submission_time,verified,online,target
                    reader = csv.DictReader(f)
                    for row in reader:
                        url = row.get("url") or row.get("phish_url")
                        if url:
                            urls.add(url)
                            details[url] = row
                            from urllib.parse import urlparse
                            try:
                                parsed = urlparse(url)
                                if parsed.netloc:
                                    domains.add(parsed.netloc.lower())
                            except Exception:
                                pass
                else:
                    # Plain text: one URL per line
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        urls.add(line)
                        from urllib.parse import urlparse
                        try:
                            parsed = urlparse(line)
                            if parsed.netloc:
                                domains.add(parsed.netloc.lower())
                        except Exception:
                            pass

            self._url_set = urls
            self._domain_set = domains
            self._phish_details = details
            logger.info(f"Loaded {len(urls)} URLs and {len(domains)} domains from PhishTank feed")
        except Exception as e:
            logger.error(f"Failed to load PhishTank feed: {e}")

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for comparison."""
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
        """Check if URL or domain is in PhishTank feed."""
        await self._ensure_loaded()

        if indicator_type == "url":
            normalized = self._normalize_url(indicator)
            matched_url = None
            for u in self._url_set:
                u_norm = self._normalize_url(u)
                if normalized == u_norm or normalized.startswith(u_norm.rstrip("/") + "/"):
                    matched_url = u
                    break

            if matched_url:
                detail = self._phish_details.get(matched_url, {})
                verified = detail.get("verified", "unknown")
                target = detail.get("target", "unknown")
                confidence = 95 if verified == "yes" else 80

                return IntelResult(
                    source=self.source,
                    verdict=IntelVerdict.MALICIOUS,
                    confidence=confidence,
                    details={
                        "feed": "phishtank",
                        "matched_url": matched_url,
                        "phish_id": detail.get("phish_id"),
                        "verified": verified,
                        "target": target,
                    },
                    note=f"Found in PhishTank feed (verified: {verified})",
                )
        elif indicator_type == "domain":
            domain = self._extract_domain(indicator, indicator_type)
            if domain in self._domain_set:
                return IntelResult(
                    source=self.source,
                    verdict=IntelVerdict.MALICIOUS,
                    confidence=80,
                    details={"feed": "phishtank", "matched_domain": domain},
                    note="Domain found in PhishTank phishing feed",
                )

        return IntelResult(
            source=self.source,
            verdict=IntelVerdict.CLEAN,
            confidence=70,
            details={"feed": "phishtank"},
            note="Not found in PhishTank feed",
        )

    async def _check_batch_impl(self, indicators: List[str], indicator_type: str) -> List[IntelResult]:
        """Batch check against loaded feed."""
        await self._ensure_loaded()
        results = []

        if indicator_type == "url":
            normalized_indicators = [self._normalize_url(i) for i in indicators]
            for orig, norm in zip(indicators, normalized_indicators):
                matched_url = None
                for u in self._url_set:
                    u_norm = self._normalize_url(u)
                    if norm == u_norm or norm.startswith(u_norm.rstrip("/") + "/"):
                        matched_url = u
                        break

                if matched_url:
                    detail = self._phish_details.get(matched_url, {})
                    verified = detail.get("verified", "unknown")
                    confidence = 95 if verified == "yes" else 80
                    results.append(IntelResult(
                        source=self.source,
                        verdict=IntelVerdict.MALICIOUS,
                        confidence=confidence,
                        details={
                            "feed": "phishtank",
                            "matched_url": matched_url,
                            "phish_id": detail.get("phish_id"),
                            "verified": verified,
                            "target": detail.get("target"),
                        },
                        note=f"Found in PhishTank feed (verified: {verified})",
                    ))
                else:
                    results.append(IntelResult(
                        source=self.source,
                        verdict=IntelVerdict.CLEAN,
                        confidence=70,
                        details={"feed": "phishtank"},
                        note="Not found in PhishTank feed",
                    ))
        elif indicator_type == "domain":
            domains = [self._extract_domain(i, indicator_type) for i in indicators]
            for orig, dom in zip(indicators, domains):
                if dom in self._domain_set:
                    results.append(IntelResult(
                        source=self.source,
                        verdict=IntelVerdict.MALICIOUS,
                        confidence=80,
                        details={"feed": "phishtank", "matched_domain": dom},
                        note="Domain found in PhishTank phishing feed",
                    ))
                else:
                    results.append(IntelResult(
                        source=self.source,
                        verdict=IntelVerdict.CLEAN,
                        confidence=70,
                        details={"feed": "phishtank"},
                        note="Not found in PhishTank feed",
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