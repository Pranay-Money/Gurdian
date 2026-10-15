"""
Impersonation Detection Engine
Detects brand impersonation via:
- Brand in subdomain (typosquat)
- Normalized Levenshtein + leet/homoglyph folding
- Sender display name vs domain mismatch
- Free mailbox claiming organization
- Message names brand but links elsewhere
"""
import re
import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse
import tldextract


@dataclass
class ImpersonationSignal:
    key: str
    category: str
    label: str
    points: int
    reason: str
    evidence: str


class ImpersonationEngine:
    def __init__(self, config_dir: Optional[Path] = None):
        self.config_dir = config_dir or Path(__file__).parent / "config"
        self.brand_domains = self._load_brand_domains()
        self.free_email_providers = self._load_free_email_providers()
        # Build reverse lookup: domain -> brand
        self.domain_to_brand = {}
        for brand, domains in self.brand_domains.get("brands", {}).items():
            for domain in domains:
                self.domain_to_brand[domain.lower()] = brand

        # Homoglyph/leet mapping for normalization
        self.homoglyph_map = {
            '0': 'o', '1': 'i', 'l': 'i', '3': 'e', '4': 'a', '5': 's',
            '6': 'g', '7': 't', '8': 'b', '9': 'g', '@': 'a', '$': 's',
            '!': 'i', '+': 't', '|': 'l', 'vv': 'w', 'vv': 'w',
            # Cyrillic lookalikes
            'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y',
            'х': 'x', 'і': 'i', 'ј': 'j', 'к': 'k', 'м': 'm', 'т': 't',
            'в': 'b', 'н': 'h', 'г': 'g', 'д': 'd', 'з': 'z', 'ф': 'f',
            'я': 'ya', 'ё': 'yo', 'ю': 'yu', 'ъ': '', 'ь': '', 'ы': 'y',
            'э': 'e', 'ш': 'sh', 'щ': 'sch', 'ч': 'ch', 'ц': 'ts', 'ж': 'zh',
            'б': 'b', 'й': 'y', 'л': 'l', 'п': 'p', 'ф': 'f', 'ы': 'y',
        }

    def _load_brand_domains(self) -> Dict[str, Any]:
        path = self.config_dir / "brand_domains.yaml"
        if not path.exists():
            return {"brands": {}, "free_email_providers": []}
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def _load_free_email_providers(self) -> Set[str]:
        return set(self.brand_domains.get("free_email_providers", []))

    def normalize_domain(self, domain: str) -> str:
        """Normalize domain for comparison: lowercase, remove non-alnum, fold homoglyphs/leet."""
        domain = domain.lower()
        # Fold homoglyphs and leet
        normalized = []
        for ch in domain:
            normalized.append(self.homoglyph_map.get(ch, ch))
        return "".join(normalized)

    def _canonical_root(self, domain: str) -> str:
        return re.sub(r"[^a-z0-9]", "", domain.lower())

    def _brand_root(self, domain: str) -> str:
        domain = domain.strip().lower()
        if not domain:
            return ""
        extracted = tldextract.extract(domain)
        root = extracted.domain or domain.split(".")[0]
        return self._canonical_root(self.normalize_domain(root))

    def _matches_brand_root(self, candidate_domain: str, official_domain: str) -> bool:
        candidate = self._brand_root(candidate_domain)
        official_root = self._brand_root(official_domain)
        if len(official_root) <= 2 or len(candidate) <= 2:
            return False
        if not candidate or not official_root:
            return False
        if candidate == official_root:
            return True
        if candidate.startswith(official_root):
            return True
        if official_root in candidate:
            return True
        prefix_hint = official_root[: max(3, len(official_root) - 1)]
        if candidate.startswith(prefix_hint):
            return True
        return self.normalized_similarity(candidate, official_root) >= 0.72

    def _registrable_domain(self, domain: str) -> str:
        parts = domain.lower().split(".")
        if len(parts) <= 2:
            return domain.lower()
        return ".".join(parts[-2:])

    def levenshtein_distance(self, s1: str, s2: str) -> int:
        """Compute Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            s1, s2 = s2, s1
        if len(s2) == 0:
            return len(s1)

        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    def normalized_similarity(self, s1: str, s2: str) -> float:
        """Compute normalized similarity (0-1) after homoglyph/leet folding."""
        n1 = self.normalize_domain(s1)
        n2 = self.normalize_domain(s2)
        if not n1 or not n2:
            return 0.0
        dist = self.levenshtein_distance(n1, n2)
        max_len = max(len(n1), len(n2))
        return 1.0 - (dist / max_len) if max_len > 0 else 0.0

    def extract_brand_from_text(self, text: str) -> List[str]:
        """Extract brand names mentioned in text using word boundaries."""
        brands = []
        text_lower = text.lower()
        for brand in self.domain_to_brand.values():
            pattern = re.compile(rf"(?<![a-z]){re.escape(brand.lower())}(?![a-z])")
            if pattern.search(text_lower):
                brands.append(brand)
        return list(set(brands))

    def analyze(
        self,
        text: str,
        sender: Optional[str],
        urls: List[str]
    ) -> List[ImpersonationSignal]:
        """Analyze for impersonation signals."""
        signals = []

        # 1. Brand in subdomain or base hostname (typosquat detection)
        for url in urls:
            try:
                extracted = tldextract.extract(url)
                subdomain = extracted.subdomain.lower()
                domain = extracted.domain.lower()
                suffix = extracted.suffix.lower()
                full_domain = f"{domain}.{suffix}" if suffix else domain

                sender_domain = None
                if sender:
                    sender_email = None
                    email_match = re.search(r'<([^>]+@[^>]+)>', sender)
                    if email_match:
                        sender_email = email_match.group(1).lower()
                        sender_domain = sender_email.split("@")[-1]
                    else:
                        email_match = re.search(r'[\w\.-]+@([\w\.-]+)', sender.lower())
                        if email_match:
                            sender_domain = email_match.group(1)

                if sender_domain and sender_domain != full_domain and sender_domain not in {domain, f"{domain}.{suffix}"}:
                    if sender_domain in subdomain or sender_domain in domain or sender_domain in full_domain:
                        signals.append(ImpersonationSignal(
                            key="brand_in_subdomain",
                            category="impersonation",
                            label="Sender Domain Embedded in URL Host",
                            points=20,
                            reason=f"URL host embeds the sender domain '{sender_domain}' in a suspicious subdomain or host path",
                            evidence=f"Sender: {sender_domain}, Host: {subdomain or domain}.{suffix or ''}"
                        ))

                decoded_domain = None
                if "xn--" in domain.lower():
                    try:
                        import codecs
                        decoded_domain = codecs.decode(domain.encode("ascii"), "idna")
                    except Exception:
                        decoded_domain = None

                if decoded_domain:
                    host_strings = [domain, decoded_domain]
                    for brand, official_domains in self.brand_domains.get("brands", {}).items():
                        for official in official_domains:
                            official_root = self._brand_root(official)
                            if not official_root or len(official_root) <= 2:
                                continue
                            normalized_host_strings = [self.normalize_domain(value) for value in host_strings if value]
                            if any(official_root in value for value in normalized_host_strings):
                                if self._registrable_domain(official) != self._registrable_domain(full_domain):
                                    signals.append(ImpersonationSignal(
                                        key="brand_in_subdomain",
                                        category="impersonation",
                                        label=f"Brand Root '{official_root}' in Punycode Host",
                                        points=20,
                                        reason=f"Decoded host contains the '{official_root}' brand root but the domain is not official",
                                        evidence=f"Host: {full_domain}, Decoded: {decoded_domain}"
                                    ))
                                    break
                        else:
                            continue
                        break

                seen_brand_roots = set()
                for brand, official_domains in self.brand_domains.get("brands", {}).items():
                    brand_name = brand.lower()
                    is_official = any(
                        full_domain == od.lower() or full_domain.endswith("." + od.lower())
                        for od in official_domains
                    )
                    if is_official:
                        continue

                    if brand_name in subdomain or brand_name in domain:
                        registrable_matches = [
                            od.lower() for od in official_domains
                            if self._registrable_domain(od) == self._registrable_domain(full_domain)
                        ]
                        if not registrable_matches:
                            signals.append(ImpersonationSignal(
                                key="brand_in_subdomain",
                                category="impersonation",
                                label=f"Brand '{brand}' in Domain or Subdomain",
                                points=20,
                                reason=f"Host contains '{brand}' but domain is not official",
                                evidence=f"Host: {full_domain}, Label: {subdomain or domain}"
                            ))

                    for official in official_domains:
                        official_root = self._brand_root(official)
                        if len(official_root) <= 2 or official_root in seen_brand_roots:
                            continue
                        if official_root in subdomain or official_root in domain:
                            registrable_matches = self._registrable_domain(official) == self._registrable_domain(full_domain)
                            if not registrable_matches:
                                seen_brand_roots.add(official_root)
                                signals.append(ImpersonationSignal(
                                    key="brand_in_subdomain",
                                    category="impersonation",
                                    label=f"Brand Root '{official_root}' in Domain or Subdomain",
                                    points=20,
                                    reason=f"Host contains brand root '{official_root}' but domain is not official",
                                    evidence=f"Host: {full_domain}, Label: {subdomain or domain}"
                                ))

                # 2. Typosquatting on registrable domain
                for brand, official_domains in self.brand_domains.get("brands", {}).items():
                    if not domain:
                        continue
                    host_root = self._canonical_root(self.normalize_domain(domain))
                    if not host_root:
                        continue

                    for official in official_domains:
                        official_domain = official.lower()
                        if full_domain == official_domain or full_domain.endswith("." + official_domain):
                            continue
                        normalized_official = self._brand_root(official_domain)
                        if len(normalized_official) <= 2 or not normalized_official:
                            continue
                        if host_root == normalized_official:
                            continue
                        suspicious = (
                            host_root.startswith(normalized_official)
                            or normalized_official in host_root
                            or self._matches_brand_root(domain, official)
                            or self.normalized_similarity(host_root, normalized_official) >= 0.7
                        )
                        if suspicious:
                            signals.append(ImpersonationSignal(
                                key="typosquat",
                                category="impersonation",
                                label=f"Typosquatting: {brand}",
                                points=25,
                                reason=f"Domain '{full_domain}' resembles official '{official_domain}'",
                                evidence=f"Domain: {full_domain} vs {official_domain}"
                            ))
                            break

                # 3. Homoglyph attack detection via punycode/IDN lookalikes
                if "xn--" in domain.lower():
                    decoded_candidate = domain.lower()
                    try:
                        import codecs
                        decoded_candidate = codecs.decode(domain.encode("ascii"), "idna")
                    except Exception:
                        pass
                    for official in self.domain_to_brand.keys():
                        official_domain = official.lower()
                        if official_domain == full_domain:
                            continue
                        if self._matches_brand_root(decoded_candidate, official_domain):
                            signals.append(ImpersonationSignal(
                                key="homoglyph_attack",
                                category="impersonation",
                                label=f"Homoglyph Attack on {self.domain_to_brand[official]}",
                                points=22,
                                reason=f"Domain '{full_domain}' uses a lookalike encoding for '{official_domain}'",
                                evidence=f"Domain: {full_domain} vs {official_domain}"
                            ))
                            break

            except Exception:
                pass

        # 4. Sender display name vs domain mismatch
        if sender:
            sender_lower = sender.lower()
            sender_email = None
            sender_domain = None

            # Extract email from "Name <email@domain.com>" format
            email_match = re.search(r'<([^>]+@[^>]+)>', sender)
            if email_match:
                sender_email = email_match.group(1).lower()
                sender_domain = sender_email.split("@")[-1]
            else:
                # Try to extract domain from plain email
                email_match = re.search(r'[\w\.-]+@([\w\.-]+)', sender_lower)
                if email_match:
                    sender_domain = email_match.group(1)

            if sender_domain:
                # Check if sender domain is free email provider
                if sender_domain in self.free_email_providers:
                    display_name = sender.split("<")[0].strip().strip('"').strip("'")
                    if display_name:
                        for brand in self.domain_to_brand.values():
                            if brand.lower() in display_name.lower():
                                signals.append(ImpersonationSignal(
                                    key="free_mailbox_org_claim",
                                    category="impersonation",
                                    label=f"Free Email Claiming to be {brand}",
                                    points=18,
                                    reason=f"Sender uses free email ({sender_domain}) but display name claims '{brand}'",
                                    evidence=f"From: {display_name} <{sender_email or sender}>"
                                ))

                # Check sender domain mismatch with URLs in message.
                # The sender domain can legitimately be an official brand domain while the
                # message URL is a phishing host; the mismatch check should only skip when
                # both domains are the same brand or the URL is clearly the same host.
                for url in urls:
                    try:
                        extracted = tldextract.extract(url)
                        url_domain = f"{extracted.domain}.{extracted.suffix}".lower()
                        if sender_domain == url_domain:
                            continue

                        sender_official = any(
                            sender_domain == official.lower() or sender_domain.endswith("." + official.lower())
                            for official_domains in self.brand_domains.get("brands", {}).values()
                            for official in official_domains
                        )
                        url_official = any(
                            url_domain == official.lower() or url_domain.endswith("." + official.lower())
                            for official_domains in self.brand_domains.get("brands", {}).values()
                            for official in official_domains
                        )
                        if sender_official and url_official:
                            continue

                        if not (sender_domain.endswith(url_domain) or url_domain.endswith(sender_domain)):
                            signals.append(ImpersonationSignal(
                                key="sender_domain_mismatch",
                                category="impersonation",
                                label="Sender Domain Mismatch",
                                points=15,
                                reason=f"Sender domain ({sender_domain}) differs from URL domain ({url_domain})",
                                evidence=f"Sender: {sender_domain}, URL: {url_domain}"
                            ))
                    except Exception:
                        pass

        # 5. Message names brand but links elsewhere
        mentioned_brands = self.extract_brand_from_text(text)
        for url in urls:
            try:
                extracted = tldextract.extract(url)
                url_domain = f"{extracted.domain}.{extracted.suffix}".lower()
                for brand in mentioned_brands:
                    official_domains = self.brand_domains.get("brands", {}).get(brand, [])
                    is_official = any(
                        url_domain == od.lower() or url_domain.endswith("." + od.lower())
                        for od in official_domains
                    )
                    if not is_official and official_domains:
                        signals.append(ImpersonationSignal(
                            key="brand_mismatch_link",
                            category="impersonation",
                            label=f"Message Mentions {brand} but Links Elsewhere",
                            points=20,
                            reason=f"Text mentions '{brand}' but URL goes to unrelated domain",
                            evidence=f"Brand: {brand}, URL domain: {url_domain}"
                        ))
            except Exception:
                pass

        return signals


# Backward compatibility function
def analyze_impersonation(
    text: str,
    sender: Optional[str],
    urls: List[str],
    config_dir: Optional[Path] = None
) -> List[Dict[str, Any]]:
    """Analyze for impersonation and return signals as dicts."""
    engine = ImpersonationEngine(config_dir)
    signals = engine.analyze(text, sender, urls)
    return [
        {
            "key": s.key,
            "category": s.category,
            "label": s.label,
            "points": s.points,
            "reason": s.reason,
            "evidence": [{"type": "impersonation", "value": s.evidence, "description": s.reason}]
        }
        for s in signals
    ]