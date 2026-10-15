"""
DNS Adapter for DNS Records Analysis
"""
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

import dns.asyncresolver
import dns.exception
import dns.rdatatype

from .base import IntelAdapter, IntelResult, IntelVerdict, IntelSource

logger = logging.getLogger(__name__)


class DNSAdapter(IntelAdapter):
    """
    DNS adapter for analyzing DNS records.
    Checks: A, AAAA, MX, NS, TXT, CNAME records.
    Flags: Fast-flux (many A records), suspicious NS, missing MX for mail domains, etc.
    """

    def __init__(
        self,
        redis_client,
        timeout: float = 5.0,
        **kwargs,
    ):
        super().__init__(
            source=IntelSource.DNS,
            redis_client=redis_client,
            api_key=None,
            timeout=timeout,
            rate_limit=kwargs.get("rate_limit", 200),
            circuit_breaker_threshold=20,
            **kwargs,
        )
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    async def _check_impl(self, indicator: str, indicator_type: str) -> IntelResult:
        """Analyze DNS records for a domain."""
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
            from urllib.parse import urlparse
            parsed = urlparse(indicator)
            domain = parsed.netloc.lower()
            if ":" in domain:
                domain = domain.split(":")[0]
        else:
            domain = indicator.lower()

        results = {
            "domain": domain,
            "records": {},
            "flags": [],
        }

        # Query multiple record types concurrently
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        tasks = [self._query_record(domain, rtype) for rtype in record_types]
        records = await asyncio.gather(*tasks, return_exceptions=True)

        for rtype, result in zip(record_types, records):
            if isinstance(result, Exception):
                results["records"][rtype] = {"error": str(result)}
            else:
                results["records"][rtype] = result

        # Analyze for suspicious patterns
        flags = self._analyze_dns(results["records"])
        results["flags"] = flags

        # Determine verdict
        if any(f["severity"] == "high" for f in flags):
            verdict = IntelVerdict.SUSPICIOUS
            confidence = 70
        elif any(f["severity"] == "medium" for f in flags):
            verdict = IntelVerdict.SUSPICIOUS
            confidence = 55
        else:
            verdict = IntelVerdict.CLEAN
            confidence = 65

        return IntelResult(
            source=self.source,
            verdict=verdict,
            confidence=confidence,
            details=results,
            note=f"DNS analysis: {len(flags)} flags" if flags else "DNS records normal",
        )

    async def _query_record(self, domain: str, rtype: str) -> Dict[str, Any]:
        """Query a single DNS record type."""
        try:
            answers = await self.resolver.resolve(domain, rtype)
            records = []
            for rdata in answers:
                if rtype == "A":
                    records.append({"type": "A", "value": rdata.address, "ttl": answers.rrset.ttl})
                elif rtype == "AAAA":
                    records.append({"type": "AAAA", "value": rdata.address, "ttl": answers.rrset.ttl})
                elif rtype == "MX":
                    records.append({
                        "type": "MX",
                        "preference": rdata.preference,
                        "exchange": str(rdata.exchange).rstrip("."),
                        "ttl": answers.rrset.ttl,
                    })
                elif rtype == "NS":
                    records.append({"type": "NS", "value": str(rdata.target).rstrip("."), "ttl": answers.rrset.ttl})
                elif rtype == "TXT":
                    strings = [s.decode() if isinstance(s, bytes) else s for s in rdata.strings]
                    records.append({"type": "TXT", "value": " ".join(strings), "ttl": answers.rrset.ttl})
                elif rtype == "CNAME":
                    records.append({"type": "CNAME", "value": str(rdata.target).rstrip("."), "ttl": answers.rrset.ttl})
                elif rtype == "SOA":
                    records.append({
                        "type": "SOA",
                        "mname": str(rdata.mname).rstrip("."),
                        "rname": str(rdata.rname).rstrip("."),
                        "serial": rdata.serial,
                        "ttl": answers.rrset.ttl,
                    })
            return {"count": len(records), "records": records, "ttl": answers.rrset.ttl}
        except dns.resolver.NXDOMAIN:
            return {"count": 0, "records": [], "error": "NXDOMAIN"}
        except dns.resolver.NoAnswer:
            return {"count": 0, "records": [], "error": "NoAnswer"}
        except dns.exception.Timeout:
            return {"count": 0, "records": [], "error": "Timeout"}
        except Exception as e:
            return {"count": 0, "records": [], "error": str(e)}

    def _analyze_dns(self, records: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze DNS records for suspicious patterns."""
        flags = []

        # Fast-flux: many A records with low TTL
        a_records = records.get("A", {}).get("records", [])
        if len(a_records) >= 5:
            ttls = [r.get("ttl", 0) for r in a_records]
            avg_ttl = sum(ttls) / len(ttls) if ttls else 0
            if avg_ttl < 300:  # Less than 5 minutes
                flags.append({
                    "type": "fast_flux",
                    "severity": "high",
                    "description": f"Possible fast-flux: {len(a_records)} A records with low TTL (avg {avg_ttl}s)",
                    "details": {"a_count": len(a_records), "avg_ttl": avg_ttl},
                })

        # Many A records (could be load balancing or fast-flux)
        elif len(a_records) >= 10:
            flags.append({
                "type": "many_a_records",
                "severity": "medium",
                "description": f"Many A records ({len(a_records)}) - possible load balancing or fast-flux",
                "details": {"a_count": len(a_records)},
            })

        # Missing MX for domains that should have email
        mx_records = records.get("MX", {}).get("records", [])
        if not mx_records:
            flags.append({
                "type": "no_mx",
                "severity": "low",
                "description": "No MX records - domain may not receive email",
                "details": {},
            })

        # Suspicious NS records (non-authoritative, many NS)
        ns_records = records.get("NS", {}).get("records", [])
        if len(ns_records) > 6:
            flags.append({
                "type": "many_ns",
                "severity": "low",
                "description": f"Many NS records ({len(ns_records)})",
                "details": {"ns_count": len(ns_records)},
            })

        # Check for suspicious NS providers (free DNS, etc.)
        suspicious_ns_keywords = [
            "freedns", "noip", "dyndns", "duckdns", "afraid.org",
            "changeip", "dynv6", "ddns", "hopto.org", "serveo.net",
        ]
        for ns in ns_records:
            ns_value = ns.get("value", "").lower()
            for kw in suspicious_ns_keywords:
                if kw in ns_value:
                    flags.append({
                        "type": "suspicious_ns",
                        "severity": "medium",
                        "description": f"Nameserver uses dynamic/free DNS: {ns_value}",
                        "details": {"ns": ns_value},
                    })
                    break

        # CNAME pointing to suspicious domains
        cname_records = records.get("CNAME", {}).get("records", [])
        suspicious_cname_keywords = [
            "github.io", "gitlab.io", "netlify.app", "vercel.app",
            "herokuapp.com", "azurewebsites.net", "cloudfront.net",
            "s3.amazonaws.com", "storage.googleapis.com",
        ]
        for cname in cname_records:
            cname_value = cname.get("value", "").lower()
            for kw in suspicious_cname_keywords:
                if kw in cname_value:
                    flags.append({
                        "type": "hosting_cname",
                        "severity": "low",
                        "description": f"CNAME points to hosting platform: {cname_value}",
                        "details": {"cname": cname_value},
                    })
                    break

        # TXT records with suspicious content
        txt_records = records.get("TXT", {}).get("records", [])
        for txt in txt_records:
            txt_value = txt.get("value", "").lower()
            # SPF all mechanism (allows any sender)
            if "v=spf1" in txt_value and ("+all" in txt_value or "?all" in txt_value):
                flags.append({
                    "type": "spf_permissive",
                    "severity": "medium",
                    "description": "SPF record allows any sender (+all or ?all)",
                    "details": {"txt": txt.get("value", "")[:100]},
                })
            # DMARC none policy
            if "v=dmarc1" in txt_value and "p=none" in txt_value:
                flags.append({
                    "type": "dmarc_none",
                    "severity": "low",
                    "description": "DMARC policy is 'none' (monitoring only)",
                    "details": {"txt": txt.get("value", "")[:100]},
                })

        return flags

    async def _check_batch_impl(self, indicators: List[str], indicator_type: str) -> List[IntelResult]:
        """Batch check DNS records."""
        results = []
        for indicator in indicators:
            result = await self._check_impl(indicator, indicator_type)
            results.append(result)
        return results