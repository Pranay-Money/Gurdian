"""
Tests for Explanation Engine
"""
import pytest
from src.engines.explain import ExplanationEngine, generate_explanation


@pytest.fixture
def engine():
    return ExplanationEngine()


class TestExplanationEngine:
    """Test explain engine human-readable explanations."""

    def test_empty_signals(self, engine):
        """Test explanation for no signals."""
        result = engine.explain([], "Low", 5)
        assert result.summary == "No suspicious patterns detected."
        assert result.details == []
        assert "safe" in result.action_guidance.lower()

    def test_single_signal(self, engine):
        """Test explanation with one signal."""
        signals = [
            {"key": "credential_request", "label": "Credential Request",
             "points": 15, "reason": "Requests password", "evidence": "password"}
        ]
        result = engine.explain(signals, "Medium", 35)
        assert "asks for passwords or otp" in result.summary.lower()
        assert len(result.details) == 1
        assert result.details[0]["signal"] == "credential_request"

    def test_two_signals(self, engine):
        """Test explanation with two signals."""
        signals = [
            {"key": "urgency", "label": "Urgency", "points": 8,
             "reason": "Creates urgency", "evidence": "urgent"},
            {"key": "deadline_threat", "label": "Account Loss Threat", "points": 12,
             "reason": "Threatens account closure", "evidence": "account will be closed"}
        ]
        result = engine.explain(signals, "High", 55)
        assert "creates false urgency" in result.summary.lower()
        assert "threatens account closure" in result.summary.lower()
        assert "and" in result.summary.lower()

    def test_three_signals(self, engine):
        """Test explanation with three signals (top 3)."""
        signals = [
            {"key": "credential_request", "label": "Credential Request", "points": 15,
             "reason": "Requests password", "evidence": "password"},
            {"key": "urgency", "label": "Urgency", "points": 8,
             "reason": "Creates urgency", "evidence": "urgent"},
            {"key": "deadline_threat", "label": "Account Loss Threat", "points": 12,
             "reason": "Threatens account closure", "evidence": "account will be closed"},
            {"key": "generic_greeting", "label": "Generic Greeting", "points": 5,
             "reason": "Impersonal greeting", "evidence": "dear customer"}
        ]
        result = engine.explain(signals, "High", 60)
        # Should mention top 3
        assert "asks for passwords or otp" in result.summary.lower()
        assert "creates false urgency" in result.summary.lower()
        assert "threatens account closure" in result.summary.lower()
        # Fourth signal should not be in summary
        assert "impersonal greeting" not in result.summary.lower()
        assert len(result.details) == 4

    def test_signal_details_include_points_and_evidence(self, engine):
        """Test each detail includes points and evidence."""
        signals = [
            {"key": "credential_request", "label": "Credential Request", "points": 15,
             "reason": "Requests password", "evidence": "password"}
        ]
        result = engine.explain(signals, "Medium", 35)
        detail = result.details[0]
        assert detail["points"] == 15
        assert "password" in detail["explanation"]
        assert "+15 pts" in detail["explanation"]

    def test_action_guidance_per_level(self, engine):
        """Test action guidance matches risk level."""
        signals = [{"key": "test", "label": "Test", "points": 10, "reason": "test", "evidence": "test"}]

        low = engine.explain(signals, "Low", 10)
        assert "safe" in low.action_guidance.lower()

        medium = engine.explain(signals, "Medium", 30)
        assert "cautious" in medium.action_guidance.lower()

        high = engine.explain(signals, "High", 55)
        assert "do not click" in high.action_guidance.lower()

        critical = engine.explain(signals, "Critical", 80)
        assert "danger" in critical.action_guidance.lower()

    def test_signal_labels_human_readable(self, engine):
        """Test signal labels are converted to plain language."""
        test_cases = [
            ("credential_request", "asks for passwords or otp"),
            ("unusual_payment", "requests gift cards, crypto, or advance fees"),
            ("prize_lottery", "claims you won a prize"),
            ("job_investment_lure", "offers easy money or fake jobs"),
            ("generic_greeting", "uses impersonal greeting"),
            ("secrecy", "pressures you to keep it secret"),
            ("authority_claim", "pretends to be official/government"),
            ("call_to_click", "tells you to click a link"),
            ("suspicious_tld", "uses a suspicious domain extension"),
            ("ip_host", "uses an ip address instead of a domain name"),
            ("punycode_idn", "uses lookalike characters in domain"),
            ("at_trick", "hides the real destination with @ symbol"),
            ("url_shortener", "uses a url shortener"),
            ("brand_in_subdomain", "brand name in subdomain (not official domain)"),
            ("typosquat", "domain mimics a known brand with small changes"),
            ("sender_domain_mismatch", "sender email domain doesn't match links"),
            ("free_mailbox_org_claim", "free email (gmail, etc.) claiming to be a company"),
            ("brand_mismatch_link", "message names one brand but links to another"),
            ("homoglyph_attack", "domain uses lookalike characters"),
        ]

        for key, expected_phrase in test_cases:
            signals = [{"key": key, "label": key.replace("_", " ").title(),
                        "points": 10, "reason": "test", "evidence": "test"}]
            result = engine.explain(signals, "Medium", 30)
            assert expected_phrase in result.summary.lower(), f"Failed for {key}"

    def test_unknown_signal_fallback(self, engine):
        """Test unknown signal falls back to label."""
        signals = [{"key": "unknown_signal_xyz", "label": "Unknown Signal",
                    "points": 10, "reason": "test", "evidence": "test"}]
        result = engine.explain(signals, "Medium", 30)
        # Should use label as fallback
        assert "unknown signal" in result.summary.lower()

    def test_explanation_includes_all_nonzero_signals(self, engine):
        """Test details include all signals with non-zero points."""
        signals = [
            {"key": "credential_request", "label": "Credential Request", "points": 15,
             "reason": "test", "evidence": "test"},
            {"key": "urgency", "label": "Urgency", "points": 8,
             "reason": "test", "evidence": "test"},
            {"key": "generic_greeting", "label": "Generic Greeting", "points": 5,
             "reason": "test", "evidence": "test"}
        ]
        result = engine.explain(signals, "Medium", 35)
        assert len(result.details) == 3


class TestGenerateExplanationFunction:
    """Test the backward compatibility function."""

    def test_returns_dict_format(self):
        signals = [{"key": "credential_request", "label": "Credential Request",
                    "points": 15, "reason": "test", "evidence": "test"}]
        result = generate_explanation(signals, "Medium", 35)
        assert isinstance(result, dict)
        assert "summary" in result
        assert "details" in result
        assert "action_guidance" in result
        assert "level" in result
        assert "score" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])