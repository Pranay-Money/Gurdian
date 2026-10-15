"""
Tests for Impersonation Engine
"""
import json
import pytest
from pathlib import Path

from src.engines.impersonation_engine import ImpersonationEngine, analyze_impersonation


@pytest.fixture
def engine():
    return ImpersonationEngine()


@pytest.fixture
def fixtures():
    fixture_path = Path(__file__).parent.parent / "fixtures" / "messages.json"
    with open(fixture_path, encoding="utf-8") as f:
        return json.load(f)["fixtures"]


class TestImpersonationEngine:
    """Test impersonation_engine brand impersonation detection."""

    def test_brand_in_subdomain_typosquat(self, engine):
        """Test brand in subdomain with typosquat detection."""
        signals = engine.analyze(
            text="Verify your PayPal account",
            sender="security@paypal.com",
            urls=["https://paypal-login.malicious-site.com/verify"]
        )
        brand_signals = [s for s in signals if s.key == "brand_in_subdomain"]
        assert len(brand_signals) > 0

    def test_typosquat_detection(self, engine):
        """Test typosquatting detection on registrable domain."""
        signals = engine.analyze(
            text="Update your account",
            sender="noreply@paypal.com",
            urls=["https://paypa1-security-update.com/login"]
        )
        typo_signals = [s for s in signals if s.key == "typosquat"]
        assert len(typo_signals) > 0
        assert typo_signals[0].points == 25

    def test_homoglyph_attack_detection(self, engine):
        """Test homoglyph attack detection."""
        signals = engine.analyze(
            text="Apple ID verification",
            sender="support@apple.com",
            urls=["https://xn--pple-43d.com/verify"]
        )
        homo_signals = [s for s in signals if s.key == "homoglyph_attack"]
        assert len(homo_signals) > 0
        assert homo_signals[0].points == 22

    def test_sender_domain_mismatch(self, engine):
        """Test sender email domain vs URL domain mismatch."""
        signals = engine.analyze(
            text="Your Amazon order",
            sender="noreply@amazon.com",
            urls=["https://fake-amazon-site.xyz/track"]
        )
        mismatch_signals = [s for s in signals if s.key == "sender_domain_mismatch"]
        assert len(mismatch_signals) > 0
        assert mismatch_signals[0].points == 15

    def test_free_mailbox_org_claim(self, engine):
        """Test free email provider claiming to be organization."""
        signals = engine.analyze(
            text="This is Microsoft Security. Your account is compromised.",
            sender="microsoft-security@gmail.com",
            urls=["https://microsoft-verify.tk/login"]
        )
        free_signals = [s for s in signals if s.key == "free_mailbox_org_claim"]
        assert len(free_signals) > 0
        assert free_signals[0].points == 18

    def test_brand_mismatch_link(self, engine):
        """Test message names brand but links elsewhere."""
        signals = engine.analyze(
            text="Your PayPal account needs verification.",
            sender="security@paypal.com",
            urls=["https://unrelated-site.com/verify"]
        )
        mismatch_signals = [s for s in signals if s.key == "brand_mismatch_link"]
        assert len(mismatch_signals) > 0
        assert mismatch_signals[0].points == 20

    def test_legitimate_sender_and_url(self, engine):
        """Test legitimate sender matching URL domain."""
        signals = engine.analyze(
            text="Your GitHub security alert",
            sender="security@github.com",
            urls=["https://github.com/settings/security"]
        )
        # Should not have impersonation signals
        keys = {s.key for s in signals}
        impersonation_keys = {"brand_in_subdomain", "typosquat", "sender_domain_mismatch",
                              "free_mailbox_org_claim", "brand_mismatch_link", "homoglyph_attack"}
        assert not impersonation_keys.intersection(keys)

    def test_fixture_001_paypal_subdomain(self, fixtures, engine):
        """Test fixture 001: PayPal in subdomain."""
        f = next(f for f in fixtures if f["id"] == "fixture_001")
        signals = engine.analyze(f["text"], f["sender"], f["urls"])
        keys = {s.key for s in signals}
        expected = {"brand_in_subdomain", "typosquat", "brand_mismatch_link"}
        assert expected.issubset(keys)

    def test_fixture_003_amazon_subdomain(self, fixtures, engine):
        """Test fixture 003: Amazon in subdomain."""
        f = next(f for f in fixtures if f["id"] == "fixture_003")
        signals = engine.analyze(f["text"], f["sender"], f["urls"])
        keys = {s.key for s in signals}
        expected = {"brand_in_subdomain", "brand_mismatch_link"}
        assert expected.issubset(keys)

    def test_fixture_004_bitly_shortener(self, fixtures, engine):
        """Test fixture 004: Microsoft gift card with bit.ly."""
        f = next(f for f in fixtures if f["id"] == "fixture_004")
        signals = engine.analyze(f["text"], f["sender"], f["urls"])
        keys = {s.key for s in signals}
        # May have brand_mismatch_link since text mentions Microsoft but link is bit.ly
        expected = {"brand_mismatch_link"}
        assert expected.issubset(keys)

    def test_fixture_005_google_jobs(self, fixtures, engine):
        """Test fixture 005: Google jobs scam."""
        f = next(f for f in fixtures if f["id"] == "fixture_005")
        signals = engine.analyze(f["text"], f["sender"], f["urls"])
        keys = {s.key for s in signals}
        expected = {"brand_in_subdomain", "typosquat", "brand_mismatch_link"}
        assert expected.issubset(keys)

    def test_fixture_007_legitimate_apple(self, fixtures, engine):
        """Test fixture 007: Legitimate Apple."""
        f = next(f for f in fixtures if f["id"] == "fixture_007")
        signals = engine.analyze(f["text"], f["sender"], f["urls"])
        keys = {s.key for s in signals}
        impersonation_keys = {"brand_in_subdomain", "typosquat", "sender_domain_mismatch",
                              "free_mailbox_org_claim", "brand_mismatch_link", "homoglyph_attack"}
        assert not impersonation_keys.intersection(keys)

    def test_fixture_016_university_spoof(self, fixtures, engine):
        """Test fixture 016: University subdomain spoof."""
        f = next(f for f in fixtures if f["id"] == "fixture_016")
        signals = engine.analyze(f["text"], f["sender"], f["urls"])
        keys = {s.key for s in signals}
        expected = {"brand_in_subdomain", "sender_domain_mismatch"}
        assert expected.issubset(keys)

    def test_fixture_017_hdfc_hindi(self, fixtures, engine):
        """Test fixture 017: Hindi HDFC scam."""
        f = next(f for f in fixtures if f["id"] == "fixture_017")
        signals = engine.analyze(f["text"], f["sender"], f["urls"])
        keys = {s.key for s in signals}
        expected = {"brand_in_subdomain", "brand_mismatch_link"}
        assert expected.issubset(keys)

    def test_fixture_024_apple_id_ml(self, fixtures, engine):
        """Test fixture 024: Apple ID .ml domain."""
        f = next(f for f in fixtures if f["id"] == "fixture_024")
        signals = engine.analyze(f["text"], f["sender"], f["urls"])
        keys = {s.key for s in signals}
        expected = {"brand_in_subdomain", "typosquat"}
        assert expected.issubset(keys)

    def test_fixture_025_instagram_cf(self, fixtures, engine):
        """Test fixture 025: Instagram .cf domain."""
        f = next(f for f in fixtures if f["id"] == "fixture_025")
        signals = engine.analyze(f["text"], f["sender"], f["urls"])
        keys = {s.key for s in signals}
        expected = {"brand_in_subdomain", "typosquat"}
        assert expected.issubset(keys)

    def test_fixture_026_lottery_scam(self, fixtures, engine):
        """Test fixture 026: UK Lottery scam."""
        f = next(f for f in fixtures if f["id"] == "fixture_026")
        signals = engine.analyze(f["text"], f["sender"], f["urls"])
        keys = {s.key for s in signals}
        expected = {"brand_mismatch_link"}
        assert expected.issubset(keys)

    def test_fixture_028_tcs_careers(self, fixtures, engine):
        """Test fixture 028: TCS careers scam."""
        f = next(f for f in fixtures if f["id"] == "fixture_028")
        signals = engine.analyze(f["text"], f["sender"], f["urls"])
        keys = {s.key for s in signals}
        expected = {"brand_in_subdomain", "brand_mismatch_link"}
        assert expected.issubset(keys)

    def test_fixture_030_punycode_apple(self, fixtures, engine):
        """Test fixture 030: Punycode Apple."""
        f = next(f for f in fixtures if f["id"] == "fixture_030")
        signals = engine.analyze(f["text"], f["sender"], f["urls"])
        keys = {s.key for s in signals}
        expected = {"homoglyph_attack", "brand_in_subdomain"}
        assert expected.issubset(keys)

    def test_fixture_036_icici_tk(self, fixtures, engine):
        """Test fixture 036: ICICI Bank .tk."""
        f = next(f for f in fixtures if f["id"] == "fixture_036")
        signals = engine.analyze(f["text"], f["sender"], f["urls"])
        keys = {s.key for s in signals}
        expected = {"brand_in_subdomain", "typosquat"}
        assert expected.issubset(keys)

    def test_fixture_037_at_trick(self, fixtures, engine):
        """Test fixture 037: @ trick with PayPal."""
        f = next(f for f in fixtures if f["id"] == "fixture_037")
        signals = engine.analyze(f["text"], f["sender"], f["urls"])
        keys = {s.key for s in signals}
        expected = {"brand_in_subdomain"}
        assert expected.issubset(keys)

    def test_fixture_039_airtel_hindi(self, fixtures, engine):
        """Test fixture 039: Hindi Airtel scam."""
        f = next(f for f in fixtures if f["id"] == "fixture_039")
        signals = engine.analyze(f["text"], f["sender"], f["urls"])
        keys = {s.key for s in signals}
        expected = {"brand_in_subdomain", "brand_mismatch_link"}
        assert expected.issubset(keys)

    def test_fixture_042_facebook_ml(self, fixtures, engine):
        """Test fixture 042: Facebook .ml."""
        f = next(f for f in fixtures if f["id"] == "fixture_042")
        signals = engine.analyze(f["text"], f["sender"], f["urls"])
        keys = {s.key for s in signals}
        expected = {"brand_in_subdomain", "typosquat"}
        assert expected.issubset(keys)

    def test_fixture_044_infosys_jobs(self, fixtures, engine):
        """Test fixture 044: Infosys jobs scam."""
        f = next(f for f in fixtures if f["id"] == "fixture_044")
        signals = engine.analyze(f["text"], f["sender"], f["urls"])
        keys = {s.key for s in signals}
        expected = {"brand_in_subdomain", "brand_mismatch_link"}
        assert expected.issubset(keys)

    def test_fixture_045_paytm_hindi(self, fixtures, engine):
        """Test fixture 045: Hindi Paytm scam."""
        f = next(f for f in fixtures if f["id"] == "fixture_045")
        signals = engine.analyze(f["text"], f["sender"], f["urls"])
        keys = {s.key for s in signals}
        expected = {"brand_in_subdomain", "brand_mismatch_link"}
        assert expected.issubset(keys)


class TestAnalyzeImpersonationFunction:
    """Test the backward compatibility function."""

    def test_returns_dict_format(self):
        result = analyze_impersonation(
            "Verify PayPal",
            "security@paypal.com",
            ["https://paypal-login.tk"]
        )
        assert isinstance(result, list)
        if result:
            assert "key" in result[0]
            assert "category" in result[0]
            assert "label" in result[0]
            assert "points" in result[0]
            assert "reason" in result[0]
            assert "evidence" in result[0]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])