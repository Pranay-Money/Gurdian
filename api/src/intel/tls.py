"""
TLS Certificate Adapter for Certificate Age and Analysis
"""
import asyncio
import logging
import ssl
import socket
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

from .base import IntelAdapter, IntelResult, IntelVerdict, IntelSource

logger = logging.getLogger(__name__)


class TLSAdapter(IntelAdapter):
    """
    TLS Certificate adapter for analyzing SSL/TLS certificates.
    Checks: certificate age, validity period, issuer, SAN, key strength, etc.
    """

    def __init__(
        self,
        redis_client,
        timeout: float = 10.0,
        **kwargs,
    ):
        super().__init__(
            source=IntelSource.TLS,
            redis_client=redis_client,
            api_key=None,
            timeout=timeout,
            rate_limit=kwargs.get("rate_limit", 100),
            circuit_breaker_threshold=10,
            **kwargs,
        )
        # Known trusted CAs
        self.trusted_cas = {
            "lets encrypt", "sectigo", "comodo", "digicert", "globalsign",
            "entrust", "godaddy", "google trust services", "amazon",
            "microsoft", "apple", "cloudflare", "zerossl", "buypass",
            "ssl.com", "certum", "actalis", "harica", "telia",
            "swisssign", "quovadis", "camerfirma", "firmaprofesional",
        }

        # Suspicious CA patterns (self-signed, free/cheap CAs often abused)
        self.suspicious_ca_patterns = [
            "self-signed", "self signed", "test", "fake", "dummy",
            "cacert", "startssl", "woosign", "cnnic",
        ]

    def _extract_domain(self, indicator: str, indicator_type: str) -> tuple[str, int]:
        """Extract domain and port from indicator."""
        if indicator_type == "domain":
            return indicator.lower(), 443

        parsed = urlparse(indicator)
        domain = parsed.netloc.lower()
        port = parsed.port or 443

        if ":" in domain:
            domain, port_str = domain.split(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                port = 443

        return domain, port

    async def _get_certificate(self, domain: str, port: int) -> Optional[ssl.Certificate]:
        """Fetch TLS certificate from domain."""
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Connect and get certificate
            loop = asyncio.get_event_loop()
            cert = await loop.run_in_executor(
                None,
                self._fetch_cert_sync,
                domain,
                port,
                context,
            )
            return cert
        except Exception as e:
            logger.debug(f"TLS cert fetch failed for {domain}:{port}: {e}")
            return None

    def _fetch_cert_sync(self, domain: str, port: int, context: ssl.SSLContext) -> ssl.Certificate:
        """Synchronous certificate fetch (runs in executor)."""
        with socket.create_connection((domain, port), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                return ssock.getpeercert(binary_form=False)

    def _parse_certificate(self, cert: Dict[str, Any]) -> Dict[str, Any]:
        """Parse certificate into structured data."""
        # Extract subject
        subject = {}
        for item in cert.get("subject", []):
            for key, value in item:
                subject[key] = value

        # Extract issuer
        issuer = {}
        for item in cert.get("issuer", []):
            for key, value in item:
                issuer[key] = value

        # Extract SAN
        san = []
        for ext in cert.get("subjectAltName", []):
            san.append({"type": ext[0], "value": ext[1]})

        # Validity
        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")

        # Parse dates
        def parse_cert_date(date_str: str) -> Optional[datetime]:
            try:
                # Format: "May 15 12:00:00 2024 GMT"
                return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
            except Exception:
                return None

        nb = parse_cert_date(not_before) if not_before else None
        na = parse_cert_date(not_after) if not_after else None

        # Key info
        key_info = {}
        if "subjectPublicKeyInfo" in cert:
            # This is complex to parse manually, skip for now
            pass

        return {
            "subject": subject,
            "issuer": issuer,
            "san": san,
            "not_before": nb.isoformat() if nb else None,
            "not_after": na.isoformat() if na else None,
            "version": cert.get("version"),
            "serial_number": cert.get("serialNumber"),
            "signature_algorithm": cert.get("signatureAlgorithm"),
        }

    def _analyze_certificate(self, cert_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze certificate for suspicious patterns."""
        flags = []
        now = datetime.utcnow()

        # Certificate age
        not_before_str = cert_data.get("not_before")
        if not_before_str:
            try:
                not_before = datetime.fromisoformat(not_before_str.replace("Z", "+00:00")).replace(tzinfo=None)
                cert_age_days = (now - not_before).days

                if cert_age_days < 1:
                    flags.append({
                        "type": "cert_very_new",
                        "severity": "high",
                        "description": f"Certificate issued less than 1 day ago ({cert_age_days} days)",
                        "details": {"cert_age_days": cert_age_days},
                    })
                elif cert_age_days < 7:
                    flags.append({
                        "type": "cert_new",
                        "severity": "medium",
                        "description": f"Certificate issued {cert_age_days} days ago",
                        "details": {"cert_age_days": cert_age_days},
                    })
                elif cert_age_days < 30:
                    flags.append({
                        "type": "cert_recent",
                        "severity": "low",
                        "description": f"Certificate issued {cert_age_days} days ago",
                        "details": {"cert_age_days": cert_age_days},
                    })
            except Exception:
                pass

        # Certificate expiry
        not_after_str = cert_data.get("not_after")
        if not_after_str:
            try:
                not_after = datetime.fromisoformat(not_after_str.replace("Z", "+00:00")).replace(tzinfo=None)
                days_until_expiry = (not_after - now).days

                if days_until_expiry < 0:
                    flags.append({
                        "type": "cert_expired",
                        "severity": "high",
                        "description": f"Certificate expired {abs(days_until_expiry)} days ago",
                        "details": {"days_until_expiry": days_until_expiry},
                    })
                elif days_until_expiry < 7:
                    flags.append({
                        "type": "cert_expiring_soon",
                        "severity": "medium",
                        "description": f"Certificate expires in {days_until_expiry} days",
                        "details": {"days_until_expiry": days_until_expiry},
                    })
                elif days_until_expiry < 30:
                    flags.append({
                        "type": "cert_expiring",
                        "severity": "low",
                        "description": f"Certificate expires in {days_until_expiry} days",
                        "details": {"days_until_expiry": days_until_expiry},
                    })
            except Exception:
                pass

        # Validity period (long-lived certs can be suspicious)
        if not_before_str and not_after_str:
            try:
                nb = datetime.fromisoformat(not_before_str.replace("Z", "+00:00")).replace(tzinfo=None)
                na = datetime.fromisoformat(not_after_str.replace("Z", "+00:00")).replace(tzinfo=None)
                validity_days = (na - nb).days

                if validity_days > 398:  # > 13 months (max allowed by CA/Browser Forum)
                    flags.append({
                        "type": "cert_long_validity",
                        "severity": "medium",
                        "description": f"Certificate validity period is {validity_days} days (exceeds 398-day max)",
                        "details": {"validity_days": validity_days},
                    })
                elif validity_days < 30:
                    flags.append({
                        "type": "cert_short_validity",
                        "severity": "low",
                        "description": f"Certificate validity period is only {validity_days} days",
                        "details": {"validity_days": validity_days},
                    })
            except Exception:
                pass

        # Self-signed certificate
        issuer = cert_data.get("issuer", {})
        subject = cert_data.get("subject", {})
        issuer_cn = issuer.get("commonName", "").lower()
        subject_cn = subject.get("commonName", "").lower()

        if issuer_cn and subject_cn and issuer_cn == subject_cn:
            flags.append({
                "type": "self_signed",
                "severity": "high",
                "description": "Self-signed certificate (issuer == subject)",
                "details": {"issuer": issuer_cn, "subject": subject_cn},
            })

        # Suspicious issuer
        issuer_org = issuer.get("organizationName", "").lower()
        for pattern in self.suspicious_ca_patterns:
            if pattern in issuer_org or pattern in issuer_cn:
                flags.append({
                    "type": "suspicious_ca",
                    "severity": "medium",
                    "description": f"Certificate from suspicious CA: {issuer_org or issuer_cn}",
                    "details": {"issuer_org": issuer_org, "issuer_cn": issuer_cn},
                })
                break

        # Check for trusted CA
        is_trusted = False
        for trusted in self.trusted_cas:
            if trusted in issuer_org or trusted in issuer_cn:
                is_trusted = True
                break

        if not is_trusted and issuer_org:
            flags.append({
                "type": "untrusted_ca",
                "severity": "low",
                "description": f"Certificate from less common CA: {issuer_org}",
                "details": {"issuer_org": issuer_org},
            })

        # SAN analysis
        san = cert_data.get("san", [])
        domains_in_san = [s["value"] for s in san if s["type"] == "DNS"]
        if len(domains_in_san) > 50:
            flags.append({
                "type": "many_san",
                "severity": "medium",
                "description": f"Certificate has {len(domains_in_san)} SAN entries",
                "details": {"san_count": len(domains_in_san)},
            })

        # Wildcard certificate
        for d in domains_in_san:
            if d.startswith("*."):
                flags.append({
                    "type": "wildcard_cert",
                    "severity": "low",
                    "description": f"Wildcard certificate for {d}",
                    "details": {"domain": d},
                })
                break

        # Signature algorithm
        sig_alg = cert_data.get("signature_algorithm", "").lower()
        weak_algos = ["sha1", "md5", "sha224"]
        for weak in weak_algos:
            if weak in sig_alg:
                flags.append({
                    "type": "weak_signature",
                    "severity": "high",
                    "description": f"Weak signature algorithm: {sig_alg}",
                    "details": {"algorithm": sig_alg},
                })
                break

        return flags

    async def _check_impl(self, indicator: str, indicator_type: str) -> IntelResult:
        """Analyze TLS certificate for a domain."""
        if indicator_type not in ("domain", "url"):
            return IntelResult(
                source=self.source,
                verdict=IntelVerdict.UNKNOWN,
                confidence=0,
                details={"error": f"Unsupported indicator type: {indicator_type}"},
                note="intel_unavailable: unsupported indicator type",
            )

        domain, port = self._extract_domain(indicator, indicator_type)

        # Fetch certificate
        cert = await self._get_certificate(domain, port)
        if not cert:
            return IntelResult(
                source=self.source,
                verdict=IntelVerdict.UNKNOWN,
                confidence=0,
                details={"error": "Failed to fetch certificate", "domain": domain, "port": port},
                note="intel_unavailable: failed to fetch TLS certificate",
            )

        # Parse certificate
        cert_data = self._parse_certificate(cert)

        # Analyze
        flags = self._analyze_certificate(cert_data)

        # Determine verdict
        high_flags = [f for f in flags if f["severity"] == "high"]
        medium_flags = [f for f in flags if f["severity"] == "medium"]

        if high_flags:
            verdict = IntelVerdict.SUSPICIOUS
            confidence = 80
        elif medium_flags:
            verdict = IntelVerdict.SUSPICIOUS
            confidence = 60
        else:
            verdict = IntelVerdict.CLEAN
            confidence = 75

        return IntelResult(
            source=self.source,
            verdict=verdict,
            confidence=confidence,
            details={
                "domain": domain,
                "port": port,
                "certificate": cert_data,
                "flags": flags,
            },
            note=f"TLS analysis: {len(flags)} flags ({len(high_flags)} high, {len(medium_flags)} medium)" if flags else "Certificate appears valid",
        )

    async def _check_batch_impl(self, indicators: List[str], indicator_type: str) -> List[IntelResult]:
        """Batch check TLS certificates."""
        # Limit concurrency to avoid overwhelming
        semaphore = asyncio.Semaphore(5)

        async def check_one(ind: str) -> IntelResult:
            async with semaphore:
                return await self._check_impl(ind, indicator_type)

        tasks = [check_one(ind) for ind in indicators]
        return await asyncio.gather(*tasks)