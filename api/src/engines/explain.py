"""
Explanation Engine
Produces human-readable explanations for analysis results.
Top 3 reasons in one sentence, per-signal reason, recommended action per level.
Plain language, no jargon.
"""
from typing import List, Dict, Any, Optional
from pathlib import Path
from dataclasses import dataclass


@dataclass
class ExplanationResult:
    summary: str  # One sentence with top 3 reasons
    details: List[Dict[str, str]]  # Per-signal explanations
    action_guidance: str  # Recommended action based on level
    level: str
    score: int


class ExplanationEngine:
    def __init__(self, config_dir: Optional[Path] = None):
        self.config_dir = config_dir or Path(__file__).parent / "config"
        self.action_guidance = {
            "Low": "This message appears safe. No action needed.",
            "Medium": "Be cautious. This message has some suspicious signs. Verify independently before clicking links or sharing information.",
            "High": "Do not click links or share information. This message is likely a scam or phishing attempt. Report it and delete.",
            "Critical": "DANGER: This is almost certainly a scam. Do not interact. Block the sender and report immediately."
        }

        # Signal-friendly labels
        self.signal_labels = {
            "urgency": "creates false urgency",
            "deadline_threat": "threatens account closure",
            "credential_request": "asks for passwords or OTP",
            "unusual_payment": "requests gift cards, crypto, or advance fees",
            "prize_lottery": "claims you won a prize",
            "job_investment_lure": "offers easy money or fake jobs",
            "generic_greeting": "uses impersonal greeting",
            "secrecy": "pressures you to keep it secret",
            "authority_claim": "pretends to be official/government",
            "call_to_click": "tells you to click a link",
            "excessive_caps": "uses excessive capitalization",
            "excessive_punctuation": "uses excessive punctuation",
            "suspicious_tld": "uses a suspicious domain extension",
            "ip_host": "uses an IP address instead of a domain name",
            "punycode_idn": "uses lookalike characters in domain",
            "at_trick": "hides the real destination with @ symbol",
            "url_shortener": "uses a URL shortener",
            "suspicious_path": "has suspicious words in the link path",
            "port_anomaly": "uses an unusual port number",
            "encoded_chars": "has heavily encoded URL",
            "subdomain_depth": "has too many subdomains",
            "high_entropy": "domain name looks randomly generated",
            "long_url": "unusually long URL",
            "no_https": "uses insecure HTTP",
            "suspicious_subdomain": "subdomain mimics a known brand",
            "redirects_chain": "redirects through multiple hops",
            "redirect_loop": "redirect loop detected",
            "ssrf_blocked": "redirect blocked (private IP)",
            "brand_in_subdomain": "brand name in subdomain (not official domain)",
            "typosquat": "domain mimics a known brand with small changes",
            "sender_domain_mismatch": "sender email domain doesn't match links",
            "free_mailbox_org_claim": "free email (Gmail, etc.) claiming to be a company",
            "brand_mismatch_link": "message names one brand but links to another",
            "homoglyph_attack": "domain uses lookalike characters",
            "blocklist_hit": "domain is on known blocklist",
            "google_safe_browsing": "flagged by Google Safe Browsing",
            "virustotal_malicious": "flagged by VirusTotal",
            "abuseipdb": "reported on AbuseIPDB",
            "urlhaus": "listed on URLhaus malware database",
            "phishtank": "listed on PhishTank",
        }

    @staticmethod
    def _normalize_evidence(value: Any) -> str:
        """Support evidence coming as a string, a dict, or a list of dicts."""
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            if "value" in value:
                return str(value["value"])
            if "description" in value:
                return str(value["description"])
            return ""
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    normalized = ExplanationEngine._normalize_evidence(item)
                    if normalized:
                        return normalized
            return ""
        return str(value)

    def explain(self, signals: List[Dict[str, Any]], level: str, score: int) -> ExplanationResult:
        """Generate explanation from signals."""
        if not signals:
            return ExplanationResult(
                summary="No suspicious patterns detected.",
                details=[],
                action_guidance=self.action_guidance.get(level, ""),
                level=level,
                score=score
            )

        # Sort signals by points descending
        sorted_signals = sorted(signals, key=lambda s: s.get("points", 0), reverse=True)

        # Top 3 reasons for summary
        top3 = sorted_signals[:3]
        reasons = []
        for s in top3:
            label = self.signal_labels.get(s["key"], s.get("label", s["key"]).lower())
            reasons.append(label)

        if len(reasons) == 1:
            summary = f"This message is suspicious because it {reasons[0]}."
        elif len(reasons) == 2:
            summary = f"This message is suspicious because it {reasons[0]} and {reasons[1]}."
        else:
            summary = f"This message is suspicious because it {reasons[0]}, {reasons[1]}, and {reasons[2]}."

        # Per-signal details
        details = []
        for s in sorted_signals:
            key = s["key"]
            label = self.signal_labels.get(key, s.get("label", key).lower())
            reason = s.get("reason", "")
            evidence = self._normalize_evidence(s.get("evidence"))
            points = s.get("points", 0)

            detail = f"{label} (+{points} pts): {reason}"
            if evidence:
                detail += f" — Example: \"{evidence}\""
            details.append({
                "signal": key,
                "label": s.get("label", key),
                "points": points,
                "explanation": detail
            })

        return ExplanationResult(
            summary=summary,
            details=details,
            action_guidance=self.action_guidance.get(level, ""),
            level=level,
            score=score
        )


# Backward compatibility function
def generate_explanation(
    signals: List[Dict[str, Any]],
    level: str,
    score: int,
    config_dir: Optional[Path] = None
) -> Dict[str, Any]:
    """Generate explanation and return as dict."""
    engine = ExplanationEngine(config_dir)
    result = engine.explain(signals, level, score)
    return {
        "summary": result.summary,
        "details": result.details,
        "action_guidance": result.action_guidance,
        "level": result.level,
        "score": result.score
    }