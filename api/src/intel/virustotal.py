"""
VirusTotal v3 Adapter
"""
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

import httpx

from .base import IntelAdapter, IntelResult, IntelVerdict, IntelSource

logger = logging.getLogger(__name__)


class VirusTotalAdapter(IntelAdapter):
    """
    VirusTotal API v3 adapter.
    Checks URLs, domains, IPs against 70+ antivirus engines and URL scanners.
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(
        self,
        redis_client,
        api_key: str,
        timeout: float = 15.0,
        **kwargs,
    ):
        super().__init__(
            source=IntelSource.VIRUSTOTAL,
            redis_client=redis_client,
            api_key=api_key,
            timeout=timeout,
            rate_limit=kwargs.get("rate_limit", 4),  # 4 requests/minute free tier
            **kwargs,
        )
        self.client = httpx.AsyncClient(
            timeout=timeout,
            headers={"x-apikey": api_key},
        )

    async def _check_impl(self, indicator: str, indicator_type: str) -> IntelResult:
        """Check a URL or domain against VirusTotal."""
        if indicator_type == "url":
            return await self._check_url(indicator)
        elif indicator_type == "domain":
            return await self._check_domain(indicator)
        else:
            return IntelResult(
                source=self.source,
                verdict=IntelVerdict.UNKNOWN,
                confidence=0,
                details={"error": f"Unsupported indicator type: {indicator_type}"},
                note="intel_unavailable: unsupported indicator type",
            )

    async def _check_url(self, url: str) -> IntelResult:
        """Check a URL via VirusTotal."""
        # URL ID is base64 encoded URL without padding
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        try:
            response = await self.client.get(f"{self.BASE_URL}/urls/{url_id}")
            if response.status_code == 404:
                # URL not scanned yet, submit for scanning
                return await self._submit_url(url)
            response.raise_for_status()
            data = response.json()

            return self._parse_url_result(data, url)

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                logger.warning("VT API rate limited")
            raise
        except Exception as e:
            logger.error(f"VT URL check failed for {url}: {e}")
            raise

    async def _submit_url(self, url: str) -> IntelResult:
        """Submit URL for scanning."""
        try:
            response = await self.client.post(
                f"{self.BASE_URL}/urls",
                data={"url": url},
            )
            response.raise_for_status()
            data = response.json()

            # Return pending result
            return IntelResult(
                source=self.source,
                verdict=IntelVerdict.UNKNOWN,
                confidence=0,
                details={
                    "status": "submitted",
                    "analysis_id": data.get("data", {}).get("id"),
                },
                note="URL submitted for analysis, check later",
            )
        except Exception as e:
            logger.error(f"VT URL submit failed: {e}")
            raise

    async def _check_domain(self, domain: str) -> IntelResult:
        """Check a domain via VirusTotal."""
        try:
            response = await self.client.get(f"{self.BASE_URL}/domains/{domain}")
            response.raise_for_status()
            data = response.json()

            return self._parse_domain_result(data, domain)

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return IntelResult(
                    source=self.source,
                    verdict=IntelVerdict.UNKNOWN,
                    confidence=0,
                    details={"error": "Domain not found in VT"},
                    note="Domain not in VirusTotal database",
                )
            raise
        except Exception as e:
            logger.error(f"VT domain check failed for {domain}: {e}")
            raise

    def _parse_url_result(self, data: Dict[str, Any], url: str) -> IntelResult:
        """Parse VirusTotal URL analysis result."""
        attributes = data.get("data", {}).get("attributes", {})
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        total_votes = attributes.get("total_votes", {})
        categories = attributes.get("categories", {})

        malicious = last_analysis_stats.get("malicious", 0)
        suspicious = last_analysis_stats.get("suspicious", 0)
        harmless = last_analysis_stats.get("harmless", 0)
        undetected = last_analysis_stats.get("undetected", 0)
        timeout = last_analysis_stats.get("timeout", 0)

        total_engines = malicious + suspicious + harmless + undetected + timeout

        if total_engines == 0:
            return IntelResult(
                source=self.source,
                verdict=IntelVerdict.UNKNOWN,
                confidence=0,
                details={"last_analysis_stats": last_analysis_stats},
                note="No engine results yet",
            )

        detection_rate = (malicious + suspicious) / total_engines if total_engines > 0 else 0

        # Determine verdict
        if malicious >= 3 or detection_rate > 0.1:
            verdict = IntelVerdict.MALICIOUS
            confidence = min(95, 50 + int(detection_rate * 50))
        elif suspicious >= 2 or detection_rate > 0.05:
            verdict = IntelVerdict.SUSPICIOUS
            confidence = min(80, 40 + int(detection_rate * 40))
        else:
            verdict = IntelVerdict.CLEAN
            confidence = min(90, 60 + harmless // 2)

        return IntelResult(
            source=self.source,
            verdict=verdict,
            confidence=confidence,
            details={
                "last_analysis_stats": last_analysis_stats,
                "total_votes": total_votes,
                "categories": categories,
                "detection_rate": detection_rate,
                "total_engines": total_engines,
                "url": url,
            },
            note=f"{malicious}/{total_engines} engines malicious",
        )

    def _parse_domain_result(self, data: Dict[str, Any], domain: str) -> IntelResult:
        """Parse VirusTotal domain analysis result."""
        attributes = data.get("data", {}).get("attributes", {})
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        categories = attributes.get("categories", {})
        reputation = attributes.get("reputation", 0)

        malicious = last_analysis_stats.get("malicious", 0)
        suspicious = last_analysis_stats.get("suspicious", 0)
        harmless = last_analysis_stats.get("harmless", 0)
        undetected = last_analysis_stats.get("undetected", 0)

        total_engines = malicious + suspicious + harmless + undetected

        if total_engines == 0:
            return IntelResult(
                source=self.source,
                verdict=IntelVerdict.UNKNOWN,
                confidence=0,
                details={"last_analysis_stats": last_analysis_stats, "reputation": reputation},
                note="No engine results for domain",
            )

        detection_rate = (malicious + suspicious) / total_engines if total_engines > 0 else 0

        # Domain reputation influences verdict
        if reputation < -10 or malicious >= 2 or detection_rate > 0.1:
            verdict = IntelVerdict.MALICIOUS
            confidence = min(95, 60 + int(detection_rate * 35))
        elif reputation < 0 or suspicious >= 1 or detection_rate > 0.03:
            verdict = IntelVerdict.SUSPICIOUS
            confidence = min(80, 40 + int(detection_rate * 40))
        else:
            verdict = IntelVerdict.CLEAN
            confidence = min(90, 60 + harmless // 2)

        return IntelResult(
            source=self.source,
            verdict=verdict,
            confidence=confidence,
            details={
                "last_analysis_stats": last_analysis_stats,
                "categories": categories,
                "reputation": reputation,
                "detection_rate": detection_rate,
                "total_engines": total_engines,
                "domain": domain,
            },
            note=f"Reputation: {reputation}, {malicious}/{total_engines} malicious",
        )

    async def _check_batch_impl(self, indicators: List[str], indicator_type: str) -> List[IntelResult]:
        """Check multiple indicators - VT doesn't have native batch, so sequential with rate limiting."""
        results = []
        for indicator in indicators:
            # Rate limiter will handle spacing
            result = await self._check_impl(indicator, indicator_type)
            results.append(result)
        return results

    async def close(self):
        await self.client.aclose()