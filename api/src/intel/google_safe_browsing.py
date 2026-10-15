"""
Google Safe Browsing v4 Adapter (Lookup API)
"""
import hashlib
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

import httpx

from .base import IntelAdapter, IntelResult, IntelVerdict, IntelSource

logger = logging.getLogger(__name__)


class GoogleSafeBrowsingAdapter(IntelAdapter):
    """
    Google Safe Browsing Lookup API v4 adapter.
    Checks URLs against Google's constantly updated lists of unsafe web resources.
    """

    API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    THREAT_TYPES = [
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION",
    ]
    PLATFORM_TYPES = ["ANY_PLATFORM"]
    THREAT_ENTRY_TYPES = ["URL"]

    def __init__(
        self,
        redis_client,
        api_key: str,
        timeout: float = 10.0,
        **kwargs,
    ):
        super().__init__(
            source=IntelSource.GOOGLE_SAFE_BROWSING,
            redis_client=redis_client,
            api_key=api_key,
            timeout=timeout,
            rate_limit=kwargs.get("rate_limit", 10000),  # 10k/day free tier
            **kwargs,
        )
        self.client = httpx.AsyncClient(timeout=timeout)

    async def _check_impl(self, indicator: str, indicator_type: str) -> IntelResult:
        """Check a single URL against Google Safe Browsing."""
        if indicator_type not in ("url", "domain"):
            return IntelResult(
                source=self.source,
                verdict=IntelVerdict.UNKNOWN,
                confidence=0,
                details={"error": f"Unsupported indicator type: {indicator_type}"},
                note="intel_unavailable: unsupported indicator type",
            )

        # For domains, check a representative URL
        check_url = indicator
        if indicator_type == "domain":
            check_url = f"http://{indicator}/"

        payload = {
            "client": {
                "clientId": "guardian",
                "clientVersion": "1.0.0",
            },
            "threatInfo": {
                "threatTypes": self.THREAT_TYPES,
                "platformTypes": self.PLATFORM_TYPES,
                "threatEntryTypes": self.THREAT_ENTRY_TYPES,
                "threatEntries": [{"url": check_url}],
            },
        }

        try:
            response = await self.client.post(
                self.API_URL,
                params={"key": self.api_key},
                json=payload,
            )
            response.raise_for_status()
            data = response.json()

            matches = data.get("matches", [])
            if matches:
                threat_types = [m.get("threatType") for m in matches]
                platform_types = [m.get("platformType") for m in matches]

                # Determine verdict based on threat types
                if "MALWARE" in threat_types:
                    verdict = IntelVerdict.MALICIOUS
                    confidence = 95
                elif "SOCIAL_ENGINEERING" in threat_types:
                    verdict = IntelVerdict.MALICIOUS
                    confidence = 90
                elif "UNWANTED_SOFTWARE" in threat_types or "POTENTIALLY_HARMFUL_APPLICATION" in threat_types:
                    verdict = IntelVerdict.SUSPICIOUS
                    confidence = 75
                else:
                    verdict = IntelVerdict.SUSPICIOUS
                    confidence = 70

                return IntelResult(
                    source=self.source,
                    verdict=verdict,
                    confidence=confidence,
                    details={
                        "matches": matches,
                        "threat_types": threat_types,
                        "platform_types": platform_types,
                    },
                    note=f"Matched {len(matches)} threat list(s)",
                )
            else:
                return IntelResult(
                    source=self.source,
                    verdict=IntelVerdict.CLEAN,
                    confidence=80,
                    details={"matches": []},
                    note="No threats found",
                )

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 400:
                logger.warning(f"GSB API bad request: {e.response.text}")
            elif e.response.status_code == 403:
                logger.error(f"GSB API key invalid or quota exceeded")
            raise
        except Exception as e:
            logger.error(f"GSB check failed for {indicator}: {e}")
            raise

    async def _check_batch_impl(self, indicators: List[str], indicator_type: str) -> List[IntelResult]:
        """Check multiple URLs in a single request (up to 500 per request)."""
        if indicator_type not in ("url", "domain"):
            return [IntelResult(
                source=self.source,
                verdict=IntelVerdict.UNKNOWN,
                confidence=0,
                details={"error": f"Unsupported indicator type: {indicator_type}"},
                note="intel_unavailable: unsupported indicator type",
            ) for _ in indicators]

        # Convert domains to URLs
        check_urls = []
        for ind in indicators:
            if indicator_type == "domain":
                check_urls.append(f"http://{ind}/")
            else:
                check_urls.append(ind)

        # GSB supports up to 500 entries per request
        batch_size = 500
        all_results = []

        for i in range(0, len(check_urls), batch_size):
            batch = check_urls[i:i + batch_size]
            payload = {
                "client": {
                    "clientId": "guardian",
                    "clientVersion": "1.0.0",
                },
                "threatInfo": {
                    "threatTypes": self.THREAT_TYPES,
                    "platformTypes": self.PLATFORM_TYPES,
                    "threatEntryTypes": self.THREAT_ENTRY_TYPES,
                    "threatEntries": [{"url": url} for url in batch],
                },
            }

            try:
                response = await self.client.post(
                    self.API_URL,
                    params={"key": self.api_key},
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()

                matches_by_url = {}
                for match in data.get("matches", []):
                    url = match.get("threatEntry", {}).get("url", "")
                    if url not in matches_by_url:
                        matches_by_url[url] = []
                    matches_by_url[url].append(match)

                for url in batch:
                    matches = matches_by_url.get(url, [])
                    if matches:
                        threat_types = [m.get("threatType") for m in matches]
                        if "MALWARE" in threat_types:
                            verdict = IntelVerdict.MALICIOUS
                            confidence = 95
                        elif "SOCIAL_ENGINEERING" in threat_types:
                            verdict = IntelVerdict.MALICIOUS
                            confidence = 90
                        else:
                            verdict = IntelVerdict.SUSPICIOUS
                            confidence = 75

                        all_results.append(IntelResult(
                            source=self.source,
                            verdict=verdict,
                            confidence=confidence,
                            details={
                                "matches": matches,
                                "threat_types": threat_types,
                            },
                            note=f"Matched {len(matches)} threat list(s)",
                        ))
                    else:
                        all_results.append(IntelResult(
                            source=self.source,
                            verdict=IntelVerdict.CLEAN,
                            confidence=80,
                            details={"matches": []},
                            note="No threats found",
                        ))

            except Exception as e:
                logger.error(f"GSB batch check failed: {e}")
                # Fail open for this batch
                for _ in batch:
                    all_results.append(IntelResult(
                        source=self.source,
                        verdict=IntelVerdict.UNKNOWN,
                        confidence=0,
                        details={"error": str(e)},
                        note=f"intel_unavailable: {type(e).__name__}",
                    ))

        return all_results

    async def close(self):
        await self.client.aclose()