"""
URL Analysis Engine
Extracts and analyzes URLs from text using tldextract.
Features: scheme, host, registrable domain, TLD reputation, subdomain depth,
length, digits, hyphens, entropy, IP host, punycode/IDN homoglyphs, '@' trick,
shorteners, suspicious path keywords, port, encoded chars.
Optional deep mode: follow redirects safely (HEAD, max 5 hops, SSRF-protected).
"""
import re
import math
import tldextract
import ipaddress
from urllib.parse import urlparse, urljoin
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
import yaml

# Configure tldextract to use bundled snapshot only (no network at runtime)
_tld_extract = tldextract.TLDExtract(
    fallback_to_snapshot=True,
    cache_fetch_timeout=0,  # Don't wait for network fetch
    suffix_list_urls=(),    # Disable network URLs
)

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False


@dataclass
class URLSignal:
    key: str
    category: str
    label: str
    points: int
    reason: str
    evidence: str


@dataclass
class URLAnalysis:
    url: str
    scheme: str
    host: str
    registrable_domain: str
    tld: str
    subdomain: str
    subdomain_depth: int
    path: str
    query: str
    port: Optional[int]
    is_ip_host: bool
    is_punycode: bool
    is_shortener: bool
    length: int
    digit_count: int
    hyphen_count: int
    entropy: float
    tld_reputation: int
    suspicious_path_keywords: List[str]
    has_at_trick: bool
    encoded_char_ratio: float
    redirects: List[str] = field(default_factory=list)
    final_url: Optional[str] = None


class URLEngine:
    def __init__(self, config_dir: Optional[Path] = None):
        self.config_dir = config_dir or Path(__file__).parent / "config"
        self.tld_reputation = self._load_tld_reputation()
        self.shortener_domains = self._load_shortener_domains()
        self.suspicious_path_keywords = self._load_suspicious_path_keywords()

    def _load_tld_reputation(self) -> Dict[str, int]:
        path = self.config_dir / "tld_reputation.yaml"
        if not path.exists():
            return {}
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            return data.get("tld_reputation", {})

    def _load_shortener_domains(self) -> Set[str]:
        return {
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
            "adf.ly", "shorte.st", "cutt.ly", "rebrand.ly", "short.io", "s.id",
            "v.gd", "tr.im", "urlzs.com", "tiny.cc", "lnkd.in", "db.tt", "qr.ae",
            "rb.gy", "bl.ink", "shorturl.at", "tiny.one", "u.to", "x.co",
            "git.io", "fur.ly", "clck.ru", "qr.net", "1url.com", "tweez.me",
            "v.gd", "tr.im", "link.zip.net", "url4.eu", "twit.ac", "su.pr",
            "twurl.nl", "snipurl.com", "short.to", "budurl.com", "ping.fm",
            "post.ly", "just.as", "bkite.com", "snipr.com", "fic.kr", "loopt.us",
            "doiop.com", "short.ie", "kl.am", "wp.me", "rubyurl.com", "om.ly",
            "to.ly", "bit.do", "t.co", "lnkd.in", "db.tt", "qr.ae", "adf.ly"
        }

    def _load_suspicious_path_keywords(self) -> List[str]:
        return [
            "login", "signin", "verify", "update", "confirm", "secure", "account",
            "password", "credential", "bank", "paypal", "apple", "microsoft",
            "google", "amazon", "facebook", "instagram", "twitter", "linkedin",
            "netflix", "steam", "dropbox", "onedrive", "icloud", "webmail",
            "urgent", "suspended", "limited", "expired", "verify", "confirm",
            "click", "download", "free", "gift", "winner", "prize", "bonus",
            "crypto", "bitcoin", "wallet", "investment", "trading",
            "admin", "panel", "dashboard", "portal", "service", "support", "help",
            "install", "update", "patch", "fix", "security", "alert",
            "reset", "recover", "unlock", "restore", "activate", "validate",
            "redirect"
        ]

    def extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text."""
        url_pattern = r'https?://[^\s<>\"\']+'
        urls = re.findall(url_pattern, text)
        urls = [u.rstrip('.,;!?)') for u in urls]
        # Also catch URLs without scheme
        bare_pattern = r'(?:^|\s)(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?'
        bare_urls = re.findall(bare_pattern, text)
        for u in bare_urls:
            u = u.strip().rstrip('.,;!?)')
            if u and not any(u in url for url in urls):
                urls.append("http://" + u)
        return list(dict.fromkeys(urls))  # Deduplicate preserving order

    def calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of string."""
        if not s:
            return 0.0
        prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(s)]
        return -sum(p * math.log2(p) for p in prob)

    def is_private_ip(self, ip_str: str) -> bool:
        """Check if IP is private/loopback/link-local (SSRF protection)."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
        except ValueError:
            return False

    def analyze_url(self, url: str) -> URLAnalysis:
        """Analyze a single URL."""
        parsed = urlparse(url)
        extracted = _tld_extract(url)

        host = parsed.netloc
        if ":" in host:
            host, port_str = host.split(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                port = None
        else:
            port = parsed.port

        # Check if host is IP
        is_ip_host = False
        try:
            ipaddress.ip_address(host)
            is_ip_host = True
        except ValueError:
            pass

        # Punycode/IDN detection
        is_punycode = "xn--" in host.lower()

        # Shortener detection
        is_shortener = host.lower() in self.shortener_domains

        # Subdomain depth
        subdomain = extracted.subdomain
        subdomain_depth = len([s for s in subdomain.split(".") if s]) if subdomain else 0

        # Path and query
        path = parsed.path
        query = parsed.query

        # Suspicious path keywords
        suspicious_path = []
        path_lower = (path + "?" + query).lower()
        for kw in self.suspicious_path_keywords:
            if kw in path_lower:
                suspicious_path.append(kw)

        # @ trick (userinfo in URL)
        has_at_trick = "@" in host or "@" in url.split("://")[-1].split("/")[0]

        # Length, digits, hyphens
        length = len(url)
        digit_count = sum(c.isdigit() for c in url)
        hyphen_count = url.count("-")

        # Entropy of host
        entropy = self.calculate_entropy(host)

        # Encoded character ratio
        encoded_chars = len(re.findall(r'%[0-9a-fA-F]{2}', url))
        encoded_char_ratio = encoded_chars * 3 / length if length > 0 else 0

        # TLD reputation
        tld_rep = self.tld_reputation.get(extracted.suffix.lower(), 0)

        return URLAnalysis(
            url=url,
            scheme=parsed.scheme,
            host=host,
            registrable_domain=f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain,
            tld=extracted.suffix,
            subdomain=subdomain,
            subdomain_depth=subdomain_depth,
            path=path,
            query=query,
            port=port,
            is_ip_host=is_ip_host,
            is_punycode=is_punycode,
            is_shortener=is_shortener,
            length=length,
            digit_count=digit_count,
            hyphen_count=hyphen_count,
            entropy=entropy,
            tld_reputation=tld_rep,
            suspicious_path_keywords=suspicious_path,
            has_at_trick=has_at_trick,
            encoded_char_ratio=encoded_char_ratio
        )

    def analyze(self, text: str, deep: bool = False) -> List[URLSignal]:
        """Analyze all URLs in text and return signals."""
        urls = self.extract_urls(text)
        if not urls:
            return []

        all_signals = []
        for url in urls:
            analysis = self.analyze_url(url)
            signals = self._generate_signals(analysis)
            if deep and HTTPX_AVAILABLE:
                # Deep mode: follow redirects
                redirect_signals = self._follow_redirects(url)
                signals.extend(redirect_signals)
            all_signals.extend(signals)

        return all_signals

    def _generate_signals(self, analysis: URLAnalysis) -> List[URLSignal]:
        """Generate signals from URL analysis."""
        signals = []

        # TLD reputation
        if analysis.tld_reputation < 0:
            signals.append(URLSignal(
                key="suspicious_tld",
                category="structural",
                label=f"Suspicious TLD (.{analysis.tld})",
                points=min(10, abs(analysis.tld_reputation)),
                reason=f"TLD .{analysis.tld} has poor reputation score: {analysis.tld_reputation}",
                evidence=f"TLD: .{analysis.tld} (rep: {analysis.tld_reputation})"
            ))

        # IP host
        if analysis.is_ip_host:
            signals.append(URLSignal(
                key="ip_host",
                category="structural",
                label="IP Address as Host",
                points=15,
                reason="URL uses IP address instead of domain name",
                evidence=f"Host: {analysis.host}"
            ))

        # Punycode/IDN
        if analysis.is_punycode:
            signals.append(URLSignal(
                key="punycode_idn",
                category="structural",
                label="Punycode/IDN Domain",
                points=12,
                reason="Domain uses punycode encoding (possible homograph attack)",
                evidence=f"Host: {analysis.host}"
            ))

        # @ trick
        if analysis.has_at_trick:
            signals.append(URLSignal(
                key="at_trick",
                category="structural",
                label="@ Trick in URL",
                points=10,
                reason="URL contains @ symbol to obscure true destination",
                evidence=f"URL contains @ in host portion"
            ))

        # Shortener
        if analysis.is_shortener:
            signals.append(URLSignal(
                key="url_shortener",
                category="structural",
                label="URL Shortener",
                points=8,
                reason="URL uses a known shortening service",
                evidence=f"Domain: {analysis.host}"
            ))

        # Suspicious path keywords
        if analysis.suspicious_path_keywords:
            for kw in analysis.suspicious_path_keywords[:3]:
                context = (analysis.path + ('?' + analysis.query if analysis.query else '')).strip()
                evidence_text = context[:80] if context else analysis.path[:80]
                signals.append(URLSignal(
                    key="suspicious_path",
                    category="structural",
                    label=f"Suspicious Path Keyword: {kw}",
                    points=7,
                    reason=f"URL path contains suspicious keyword: {kw}",
                    evidence=f"Path: {evidence_text}"
                ))

        # Port anomaly
        if analysis.port and analysis.port not in (80, 443):
            signals.append(URLSignal(
                key="port_anomaly",
                category="structural",
                label=f"Unusual Port: {analysis.port}",
                points=6,
                reason=f"URL uses non-standard port {analysis.port}",
                evidence=f"Port: {analysis.port}"
            ))

        # Encoded chars
        if analysis.encoded_char_ratio > 0.1:
            signals.append(URLSignal(
                key="encoded_chars",
                category="structural",
                label="High Encoded Character Ratio",
                points=5,
                reason=f"{analysis.encoded_char_ratio:.0%} of URL is percent-encoded",
                evidence=f"Encoded ratio: {analysis.encoded_char_ratio:.2f}"
            ))

        # Subdomain depth
        if analysis.subdomain_depth >= 3:
            signals.append(URLSignal(
                key="subdomain_depth",
                category="structural",
                label=f"Deep Subdomain Nesting ({analysis.subdomain_depth})",
                points=min(15, analysis.subdomain_depth * 3),
                reason=f"URL has {analysis.subdomain_depth} subdomain levels",
                evidence=f"Subdomain: {analysis.subdomain}"
            ))

        # High entropy
        if analysis.entropy > 3.5:
            signals.append(URLSignal(
                key="high_entropy",
                category="structural",
                label="High Entropy Hostname",
                points=8,
                reason=f"Hostname entropy is {analysis.entropy:.2f} (appears random)",
                evidence=f"Entropy: {analysis.entropy:.2f}, Host: {analysis.host}"
            ))

        # Long URL
        if analysis.length > 150:
            signals.append(URLSignal(
                key="long_url",
                category="structural",
                label="Unusually Long URL",
                points=3,
                reason=f"URL length is {analysis.length} characters",
                evidence=f"Length: {analysis.length}"
            ))

        # No HTTPS
        if analysis.scheme != "https":
            signals.append(URLSignal(
                key="no_https",
                category="structural",
                label="No HTTPS",
                points=5,
                reason="Connection is not encrypted (HTTP)",
                evidence=f"Scheme: {analysis.scheme}"
            ))

        # Suspicious subdomain / brand-like host segment
        host_text = f"{analysis.subdomain} {analysis.host} {analysis.registrable_domain}".lower()
        brand_terms = ["google", "microsoft", "apple", "amazon", "facebook", "paypal", "bank", "secure", "login", "verify", "netflix", "chase", "hdfc", "sbi", "airtel", "office", "portal", "support", "account", "kyc", "activate"]
        suspicious_brand = False
        official_hosts = {
            host
            for brand in ["google", "microsoft", "apple", "amazon", "facebook", "paypal", "netflix", "chase", "hdfc", "sbi", "airtel"]
            for host in [f"{brand}.com", f"{brand}.org", f"{brand}.net", f"{brand}.co", f"{brand}.co.in", f"{brand}.in"]
        }
        host_names = [piece.lower() for piece in [analysis.subdomain, analysis.host, analysis.registrable_domain] if piece]
        for host_name in host_names:
            if host_name in official_hosts:
                continue
            if any(brand in host_name for brand in brand_terms):
                suspicious_brand = True
                break
        if not suspicious_brand and analysis.subdomain:
            suspicious_fragments = ["secure", "login", "verify", "account", "portal", "support", "kyc", "activate", "update", "confirm", "billing"]
            if analysis.subdomain_depth >= 3 or any(fragment in analysis.subdomain.lower() for fragment in suspicious_fragments):
                suspicious_brand = True
        if suspicious_brand:
            signals.append(URLSignal(
                key="brand_in_subdomain",
                category="structural",
                label="Brand in Subdomain",
                points=8,
                reason="Host or subdomain includes a brand name in a suspicious impersonation pattern",
                evidence=f"Host: {analysis.host}"
            ))
            signals.append(URLSignal(
                key="suspicious_subdomain",
                category="structural",
                label="Brand in Subdomain",
                points=8,
                reason="Host or subdomain includes a brand name in a suspicious impersonation pattern",
                evidence=f"Host: {analysis.host}"
            ))

        return signals

    async def _follow_redirects(self, url: str, max_hops: int = 5) -> List[URLSignal]:
        """Follow redirects safely with SSRF protection."""
        signals = []
        visited = set()
        current_url = url
        hops = 0

        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            while hops < max_hops:
                if current_url in visited:
                    signals.append(URLSignal(
                        key="redirect_loop",
                        category="behavioral",
                        label="Redirect Loop Detected",
                        points=10,
                        reason="Redirect chain contains a loop",
                        evidence=f"Loop at: {current_url}"
                    ))
                    break

                visited.add(current_url)

                try:
                    # SSRF protection: check if host is private IP
                    parsed = urlparse(current_url)
                    host = parsed.netloc.split(":")[0]
                    if self.is_private_ip(host):
                        signals.append(URLSignal(
                            key="ssrf_blocked",
                            category="behavioral",
                            label="SSRF Protection: Private IP Blocked",
                            points=20,
                            reason="Redirect points to private/internal IP address",
                            evidence=f"Blocked host: {host}"
                        ))
                        break

                    resp = await client.head(current_url, headers={"User-Agent": "Guardian/1.0"})
                    hops += 1

                    if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get("location")
                        if location:
                            current_url = urljoin(current_url, location)
                            continue
                    break

                except Exception as e:
                    signals.append(URLSignal(
                        key="redirect_error",
                        category="behavioral",
                        label="Redirect Follow Failed",
                        points=3,
                        reason=f"Failed to follow redirect: {type(e).__name__}",
                        evidence=str(e)[:70]
                    ))
                    break

        if hops > 0:
            signals.append(URLSignal(
                key="redirects_chain",
                category="behavioral",
                label=f"Redirect Chain ({hops} hops)",
                points=min(16, hops * 8),
                reason=f"URL redirects through {hops} intermediate hops",
                evidence=f"Final URL: {current_url}"
            ))

        return signals


# Backward compatibility function
def analyze_urls(text: str, deep: bool = False, config_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Analyze URLs in text and return signals as dicts."""
    engine = URLEngine(config_dir)
    # For sync usage, skip deep mode
    signals = engine.analyze(text, deep=False)
    return [
        {
            "key": s.key,
            "category": s.category,
            "label": s.label,
            "points": s.points,
            "reason": s.reason,
            "evidence": [{"type": "url", "value": s.evidence, "description": s.reason}]
        }
        for s in signals
    ]