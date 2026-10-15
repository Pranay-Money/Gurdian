"""
Tests for Text Engine
"""
import json
import pytest
from pathlib import Path

from src.engines.text_engine import TextEngine, analyze_text


@pytest.fixture
def engine():
    return TextEngine()


@pytest.fixture
def fixtures():
    fixture_path = Path(__file__).parent.parent / "fixtures" / "messages.json"
    with open(fixture_path, encoding="utf-8") as f:
        return json.load(f)["fixtures"]


class TestTextEngine:
    """Test text_engine linguistic pattern detection."""

    def test_urgency_detection(self, engine):
        """Test urgency/deadline keyword detection."""
        text = "URGENT: Act now! Limited time offer expires today."
        signals = engine.analyze(text)
        urgency_signals = [s for s in signals if s.key == "urgency"]
        assert len(urgency_signals) > 0
        assert urgency_signals[0].points == 8

    def test_deadline_threat_detection(self, engine):
        """Test account loss threat detection."""
        text = "Your account will be closed in 24 hours if you don't verify."
        signals = engine.analyze(text)
        deadline_signals = [s for s in signals if s.key == "deadline_threat"]
        assert len(deadline_signals) > 0
        assert deadline_signals[0].points == 12

    def test_credential_request_detection(self, engine):
        """Test password/OTP/PIN request detection."""
        text = "Please provide your password and OTP for verification."
        signals = engine.analyze(text)
        cred_signals = [s for s in signals if s.key == "credential_request"]
        assert len(cred_signals) > 0
        assert cred_signals[0].points == 15

    def test_unusual_payment_detection(self, engine):
        """Test gift card/crypto/advance fee detection."""
        text = "Pay with Google Play gift cards or Bitcoin wallet."
        signals = engine.analyze(text)
        payment_signals = [s for s in signals if s.key == "unusual_payment"]
        assert len(payment_signals) > 0
        assert payment_signals[0].points == 18

    def test_prize_lottery_detection(self, engine):
        """Test prize/lottery lure detection."""
        text = "Congratulations! You won $1,000,000 in our lottery."
        signals = engine.analyze(text)
        prize_signals = [s for s in signals if s.key == "prize_lottery"]
        assert len(prize_signals) > 0
        assert prize_signals[0].points == 10

    def test_job_investment_lure_detection(self, engine):
        """Test job/investment lure detection."""
        text = "Work from home, earn $5000/week guaranteed returns."
        signals = engine.analyze(text)
        job_signals = [s for s in signals if s.key == "job_investment_lure"]
        assert len(job_signals) > 0
        assert job_signals[0].points == 10

    def test_generic_greeting_detection(self, engine):
        """Test generic greeting detection."""
        text = "Dear Customer, your account needs attention."
        signals = engine.analyze(text)
        greeting_signals = [s for s in signals if s.key == "generic_greeting"]
        assert len(greeting_signals) > 0
        assert greeting_signals[0].points == 5

    def test_secrecy_detection(self, engine):
        """Test secrecy pressure detection."""
        text = "Don't tell anyone about this. Keep it confidential."
        signals = engine.analyze(text)
        secrecy_signals = [s for s in signals if s.key == "secrecy"]
        assert len(secrecy_signals) > 0
        assert secrecy_signals[0].points == 8

    def test_authority_claim_detection(self, engine):
        """Test false authority claim detection."""
        text = "This is the FBI. You owe taxes. Pay immediately."
        signals = engine.analyze(text)
        authority_signals = [s for s in signals if s.key == "authority_claim"]
        assert len(authority_signals) > 0
        assert authority_signals[0].points == 7

    def test_call_to_click_detection(self, engine):
        """Test call-to-click detection."""
        text = "Click here to verify your account."
        signals = engine.analyze(text)
        click_signals = [s for s in signals if s.key == "call_to_click"]
        assert len(click_signals) > 0
        assert click_signals[0].points == 6

    def test_excessive_caps_detection(self, engine):
        """Test excessive capitalization detection."""
        text = "URGENT IMMEDIATE ACTION REQUIRED NOW!!!"
        signals = engine.analyze(text)
        caps_signals = [s for s in signals if s.key == "excessive_caps"]
        assert len(caps_signals) > 0
        assert caps_signals[0].points == 4

    def test_excessive_punctuation_detection(self, engine):
        """Test excessive punctuation detection."""
        text = "What??? This is amazing!!!!"
        signals = engine.analyze(text)
        punct_signals = [s for s in signals if s.key == "excessive_punctuation"]
        assert len(punct_signals) > 0
        assert punct_signals[0].points == 4

    def test_hindi_keywords(self, engine):
        """Test Hindi/Hinglish keyword detection."""
        text = "तुरंत करें, आपका खाता बंद हो जाएगा। OTP दें।"
        signals = engine.analyze(text)
        # Should detect urgency, deadline_threat, credential_request
        keys = {s.key for s in signals}
        assert "urgency" in keys
        assert "deadline_threat" in keys
        assert "credential_request" in keys

    def test_mixed_language(self, engine):
        """Test mixed English-Hindi detection."""
        text = "URGENT: आपका account suspend होगा। Verify now!"
        signals = engine.analyze(text)
        keys = {s.key for s in signals}
        assert "urgency" in keys
        assert "deadline_threat" in keys

    def test_empty_text(self, engine):
        """Test empty text returns no signals."""
        signals = engine.analyze("")
        assert signals == []

    def test_evidence_snippet_length(self, engine):
        """Test evidence snippets are truncated to 70 chars."""
        long_text = "A" * 100 + " URGENT " + "B" * 100
        signals = engine.analyze(long_text)
        urgency_signals = [s for s in signals if s.key == "urgency"]
        assert len(urgency_signals) > 0
        assert len(urgency_signals[0].evidence) <= 70

    def test_fixture_001_critical_phishing(self, fixtures, engine):
        """Test fixture 001: PayPal phishing email."""
        f = next(f for f in fixtures if f["id"] == "fixture_001")
        signals = engine.analyze(f["text"])
        keys = {s.key for s in signals}
        expected = set(f["expected_signals"])
        assert expected.issubset(keys), f"Missing: {expected - keys}"

    def test_fixture_002_sms_bank_threat(self, fixtures, engine):
        """Test fixture 002: SMS bank threat."""
        f = next(f for f in fixtures if f["id"] == "fixture_002")
        signals = engine.analyze(f["text"])
        keys = {s.key for s in signals}
        expected = set(f["expected_signals"])
        assert expected.issubset(keys)

    def test_fixture_006_irs_scam(self, fixtures, engine):
        """Test fixture 006: IRS tax scam."""
        f = next(f for f in fixtures if f["id"] == "fixture_006")
        signals = engine.analyze(f["text"])
        keys = {s.key for s in signals}
        expected = set(f["expected_signals"])
        assert expected.issubset(keys)

    def test_fixture_007_legitimate_apple(self, fixtures, engine):
        """Test fixture 007: Legitimate Apple email."""
        f = next(f for f in fixtures if f["id"] == "fixture_007")
        signals = engine.analyze(f["text"])
        # Should have minimal/no signals
        assert len(signals) <= 1

    def test_fixture_012_hindi_prize(self, fixtures, engine):
        """Test fixture 012: Hindi prize scam."""
        f = next(f for f in fixtures if f["id"] == "fixture_012")
        signals = engine.analyze(f["text"])
        keys = {s.key for s in signals}
        expected = set(f["expected_signals"])
        assert expected.issubset(keys)

    def test_fixture_017_hindi_bank(self, fixtures, engine):
        """Test fixture 017: Hindi HDFC bank scam."""
        f = next(f for f in fixtures if f["id"] == "fixture_017")
        signals = engine.analyze(f["text"])
        keys = {s.key for s in signals}
        expected = set(f["expected_signals"])
        assert expected.issubset(keys)

    def test_fixture_032_hindi_sbi(self, fixtures, engine):
        """Test fixture 032: Hindi SBI scam."""
        f = next(f for f in fixtures if f["id"] == "fixture_032")
        signals = engine.analyze(f["text"])
        keys = {s.key for s in signals}
        expected = set(f["expected_signals"])
        assert expected.issubset(keys)

    def test_fixture_039_hindi_airtel(self, fixtures, engine):
        """Test fixture 039: Hindi Airtel scam."""
        f = next(f for f in fixtures if f["id"] == "fixture_039")
        signals = engine.analyze(f["text"])
        keys = {s.key for s in signals}
        expected = set(f["expected_signals"])
        assert expected.issubset(keys)


class TestAnalyzeTextFunction:
    """Test the backward compatibility function."""

    def test_returns_dict_format(self):
        result = analyze_text("URGENT: Click here!")
        assert isinstance(result, list)
        assert len(result) > 0
        assert "key" in result[0]
        assert "category" in result[0]
        assert "label" in result[0]
        assert "points" in result[0]
        assert "reason" in result[0]
        assert "evidence" in result[0]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])