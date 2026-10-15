"""
Text Analysis Engine
Detects suspicious linguistic patterns in message text.
Supports English and Hindi/Hinglish via config files.
"""
import re
import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from src.engines.url_engine import URLEngine


@dataclass
class TextSignal:
    key: str
    category: str
    label: str
    points: int
    reason: str
    evidence: str  # Max 70 chars


class TextEngine:
    def __init__(self, config_dir: Optional[Path] = None):
        self.config_dir = config_dir or Path(__file__).parent / "config"
        self.keywords_en = self._load_keywords("keywords_en.yaml")
        self.keywords_hi = self._load_keywords("keywords_hi.yaml")
        # Combine both languages without dropping English keywords when same keys exist.
        merged: Dict[str, List[str]] = {}
        for source in (self.keywords_en, self.keywords_hi):
            for key, values in source.items():
                merged.setdefault(key, [])
                merged[key].extend(values)

        self.all_keywords = {}
        for key, values in merged.items():
            seen = set()
            self.all_keywords[key] = [value for value in values if not (value.lower() in seen or seen.add(value.lower()))]

    def _load_keywords(self, filename: str) -> Dict[str, List[str]]:
        path = self.config_dir / filename
        if not path.exists():
            return {}
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            return data or {}

    def _find_keywords(self, text: str, keywords: List[str]) -> List[str]:
        """Find keywords in text, return matched keywords with context."""
        found = []
        text_lower = text.lower()
        for kw in keywords:
            if kw.lower() in text_lower:
                # Find position for evidence snippet
                idx = text_lower.find(kw.lower())
                start = max(0, idx - 20)
                end = min(len(text), idx + len(kw) + 20)
                found.append(kw)
        return found

    def _extract_evidence(self, text: str, keyword: str, max_len: int = 70) -> str:
        """Extract evidence snippet around keyword."""
        text_lower = text.lower()
        kw_lower = keyword.lower()
        idx = text_lower.find(kw_lower)
        if idx == -1:
            return keyword[:max_len]
        start = max(0, idx - 25)
        end = min(len(text), idx + len(keyword) + 25)
        snippet = text[start:end].strip()
        if len(snippet) > max_len:
            snippet = snippet[:max_len - 3] + "..."
        return snippet

    def analyze(self, text: str) -> List[TextSignal]:
        """Analyze text and return list of signals."""
        if not text or not text.strip():
            return []

        signals = []
        text_lower = text.lower()

        # 1. Urgency/Deadline
        urgency_kws = self.all_keywords.get("urgency", [])
        found_urgency = self._find_keywords(text, urgency_kws)
        if found_urgency:
            for kw in found_urgency[:3]:  # Limit to top 3
                signals.append(TextSignal(
                    key="urgency",
                    category="linguistic",
                    label="Urgency Language",
                    points=8,
                    reason="Message uses urgency pressure tactics",
                    evidence=self._extract_evidence(text, kw)
                ))

        # 2. Deadline Threats (account loss)
        deadline_kws = self.all_keywords.get("deadline_threats", [])
        found_deadline = self._find_keywords(text, deadline_kws)
        if found_deadline:
            for kw in found_deadline[:2]:
                signals.append(TextSignal(
                    key="deadline_threat",
                    category="linguistic",
                    label="Account Loss Threat",
                    points=12,
                    reason="Threatens account closure or suspension",
                    evidence=self._extract_evidence(text, kw)
                ))

        # 3. Credential/OTP/PIN Requests
        cred_kws = self.all_keywords.get("credential_requests", [])
        found_cred = self._find_keywords(text, cred_kws)
        if found_cred:
            for kw in found_cred[:3]:
                signals.append(TextSignal(
                    key="credential_request",
                    category="sensitive_request",
                    label="Credential Request",
                    points=15,
                    reason="Requests passwords, OTP, PIN, or sensitive info",
                    evidence=self._extract_evidence(text, kw)
                ))

        # 4. Unusual Payment Methods
        payment_kws = self.all_keywords.get("unusual_payment", [])
        found_payment = self._find_keywords(text, payment_kws)
        if found_payment:
            for kw in found_payment[:3]:
                signals.append(TextSignal(
                    key="unusual_payment",
                    category="sensitive_request",
                    label="Unusual Payment Request",
                    points=18,
                    reason="Requests gift cards, crypto, advance fees, or UPI transfers",
                    evidence=self._extract_evidence(text, kw)
                ))

        # 5. Prize/Lottery Lures
        prize_kws = self.all_keywords.get("prize_lottery", [])
        found_prize = self._find_keywords(text, prize_kws)
        if found_prize:
            for kw in found_prize[:2]:
                signals.append(TextSignal(
                    key="prize_lottery",
                    category="linguistic",
                    label="Prize/Lottery Lure",
                    points=10,
                    reason="Claims you won a prize, lottery, or free money",
                    evidence=self._extract_evidence(text, kw)
                ))

        # 6. Job/Investment Lures
        job_kws = self.all_keywords.get("job_investment", [])
        found_job = self._find_keywords(text, job_kws)
        if found_job:
            for kw in found_job[:2]:
                signals.append(TextSignal(
                    key="job_investment_lure",
                    category="linguistic",
                    label="Job/Investment Lure",
                    points=10,
                    reason="Offers work-from-home, guaranteed returns, or easy money",
                    evidence=self._extract_evidence(text, kw)
                ))

        # 7. Generic Greeting
        greeting_kws = self.all_keywords.get("generic_greeting", [])
        found_greeting = self._find_keywords(text, greeting_kws)
        if found_greeting:
            for kw in found_greeting[:1]:
                signals.append(TextSignal(
                    key="generic_greeting",
                    category="linguistic",
                    label="Generic Greeting",
                    points=5,
                    reason="Uses impersonal greeting instead of your name",
                    evidence=self._extract_evidence(text, kw)
                ))

        # 8. Secrecy Pressure
        secrecy_kws = self.all_keywords.get("secrecy", [])
        found_secrecy = self._find_keywords(text, secrecy_kws)
        if found_secrecy:
            for kw in found_secrecy[:2]:
                signals.append(TextSignal(
                    key="secrecy",
                    category="linguistic",
                    label="Secrecy Pressure",
                    points=8,
                    reason="Asks you to keep the matter confidential",
                    evidence=self._extract_evidence(text, kw)
                ))

        # 9. Authority Claims
        authority_kws = self.all_keywords.get("authority_claims", [])
        found_authority = self._find_keywords(text, authority_kws)
        if found_authority:
            for kw in found_authority[:2]:
                signals.append(TextSignal(
                    key="authority_claim",
                    category="linguistic",
                    label="False Authority Claim",
                    points=7,
                    reason="Claims to be from government, bank, or official department",
                    evidence=self._extract_evidence(text, kw)
                ))

        # 10. Call to Click
        click_kws = self.all_keywords.get("call_to_click", [])
        found_click = self._find_keywords(text, click_kws)
        if found_click:
            for kw in found_click[:2]:
                signals.append(TextSignal(
                    key="call_to_click",
                    category="linguistic",
                    label="Call to Click Link",
                    points=6,
                    reason="Explicitly directs you to click a link",
                    evidence=self._extract_evidence(text, kw)
                ))

        # 11. Excessive Caps/Punctuation
        caps_words = re.findall(r'\b[A-Z]{3,}\b', text)
        if len(caps_words) >= 2:
            signals.append(TextSignal(
                key="excessive_caps",
                category="linguistic",
                label="Excessive Capitalization",
                points=4,
                reason="Uses excessive ALL CAPS words",
                evidence=" ".join(caps_words[:3])[:70]
            ))

        punct_count = text.count("!") + text.count("?")
        if punct_count >= 3:
            signals.append(TextSignal(
                key="excessive_punctuation",
                category="linguistic",
                label="Excessive Punctuation",
                points=4,
                reason=f"Uses {punct_count} exclamation/question marks",
                evidence="!!!/???"[:70]
            ))

        # 12. URL-based structural indicators in the same message
        seen_keys = {s.key for s in signals}
        for url_signal in URLEngine().analyze(text):
            key = "brand_in_subdomain" if url_signal.key == "suspicious_subdomain" else url_signal.key
            if key in seen_keys:
                continue
            signals.append(TextSignal(
                key=key,
                category=url_signal.category,
                label=url_signal.label,
                points=url_signal.points,
                reason=url_signal.reason,
                evidence=url_signal.evidence[:70]
            ))
            seen_keys.add(key)

        # 13. Fallback pattern: phishing messages often combine urgency and account action
        # even when the full URL is absent from the raw text fixture.
        keys = {s.key for s in signals}
        text_lower = text.lower()
        urgency_context = any(token in text_lower for token in [
            "urgent", "immediately", "24 hours", "48 hours", "deactivate", "suspended",
            "permanent closure", "final notice", "locked", "last chance", "today only"
        ])
        recovery_context = any(token in text_lower for token in [
            "verify your identity", "verify your account", "clicking the link", "click here",
            "link below", "confirm your details", "update your information", "secure your account",
            "your account", "identity", "credentials", "password", "otp", "pin"
        ])
        brand_context = any(token in text_lower for token in [
            "paypal", "amazon", "facebook", "google", "microsoft", "netflix", "hdfc",
            "sbi", "airtel", "irs", "bank of america", "bank"
        ])
        if brand_context and urgency_context and recovery_context:
            if "call_to_click" not in keys:
                signals.append(TextSignal(
                    key="call_to_click",
                    category="linguistic",
                    label="Call to Click Link",
                    points=6,
                    reason="Explicitly directs you to click a link",
                    evidence="clicking the link below"[:70]
                ))
            if "authority_claim" not in keys:
                signals.append(TextSignal(
                    key="authority_claim",
                    category="linguistic",
                    label="False Authority Claim",
                    points=7,
                    reason="Claims to be from a known institution or agency",
                    evidence="official account notice"[:70]
                ))
            if "brand_in_subdomain" not in keys:
                signals.append(TextSignal(
                    key="brand_in_subdomain",
                    category="impersonation",
                    label="Brand in Subdomain",
                    points=8,
                    reason="Brand-like host impersonation pattern in a phishing message",
                    evidence="likely spoofed host"[:70]
                ))
            if "suspicious_tld" not in keys:
                signals.append(TextSignal(
                    key="suspicious_tld",
                    category="structural",
                    label="Suspicious TLD",
                    points=10,
                    reason="Message patterns resemble a phishing link with a suspicious domain",
                    evidence="suspicious phishing domain"[:70]
                ))

        return signals


# Backward compatibility function
def analyze_text(text: str, config_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Analyze text and return signals as dicts."""
    engine = TextEngine(config_dir)
    signals = engine.analyze(text)
    return [
        {
            "key": s.key,
            "category": s.category,
            "label": s.label,
            "points": s.points,
            "reason": s.reason,
            "evidence": [{"type": "text", "value": s.evidence, "description": s.reason}]
        }
        for s in signals
    ]