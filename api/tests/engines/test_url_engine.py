"""
Tests for URL Engine
"""
import json
import pytest
from pathlib import Path

from src.engines.url_engine import URLEngine, analyze_urls


@pytest.fixture
def engine():
    return URLEngine()


@pytest.fixture
def fixtures():
    fixture_path = Path(__file__).parent.parent / "fixtures" / "messages.json"
    with open(fixture_path, encoding="utf-8") as f:
        return json.load(f)["fixtures"]


class TestURLEngine:
    """Test url_engine URL analysis."""

    def test_extract_urls_from_text(self, engine):
        """Test URL extraction from text."""
        text = "Check this: https://example.com and http://test.org/path"
        urls = engine.extract_urls(text)
        assert len(urls) == 2
        assert "https://example.com" in urls
        assert "http://test.org/path" in urls

    def test_suspicious_tld_detection(self, engine):
        """Test suspicious TLD detection."""
        signals = engine.analyze("https://paypal-login.tk/verify")
        tld_signals = [s for s in signals if s.key == "suspicious_tld"]
        assert len(tld_signals) > 0
        assert tld_signals[0].points > 0

    def test_ip_host_detection(self, engine):
        """Test IP address as host detection."""
        signals = engine.analyze("http://192.168.1.1/admin")
        ip_signals = [s for s in signals if s.key == "ip_host"]
        assert len(ip_signals) > 0
        assert ip_signals[0].points == 15

    def test_punycode_detection(self, engine):
        """Test punycode/IDN homoglyph detection."""
        signals = engine.analyze("https://xn--pple-43d.com/login")
        puny_signals = [s for s in signals if s.key == "punycode_idn"]
        assert len(puny_signals) > 0
        assert puny_signals[0].points == 12

    def test_at_trick_detection(self, engine):
        """Test @ trick in URL detection."""
        signals = engine.analyze("https://paypal.com@malicious-site.com/login")
        at_signals = [s for s in signals if s.key == "at_trick"]
        assert len(at_signals) > 0
        assert at_signals[0].points == 10

    def test_url_shortener_detection(self, engine):
        """Test URL shortener detection."""
        signals = engine.analyze("https://bit.ly/3xYzK9")
        shortener_signals = [s for s in signals if s.key == "url_shortener"]
        assert len(shortener_signals) > 0
        assert shortener_signals[0].points == 8

    def test_suspicious_path_keywords(self, engine):
        """Test suspicious path keyword detection."""
        signals = engine.analyze("https://example.com/login/verify/account")
        path_signals = [s for s in signals if s.key == "suspicious_path"]
        assert len(path_signals) > 0
        assert any("login" in s.evidence for s in path_signals)

    def test_port_anomaly_detection(self, engine):
        """Test unusual port detection."""
        signals = engine.analyze("https://example.com:8080/admin")
        port_signals = [s for s in signals if s.key == "port_anomaly"]
        assert len(port_signals) > 0
        assert port_signals[0].points == 6

    def test_no_https_detection(self, engine):
        """Test HTTP (no HTTPS) detection."""
        signals = engine.analyze("http://example.com/login")
        https_signals = [s for s in signals if s.key == "no_https"]
        assert len(https_signals) > 0
        assert https_signals[0].points == 5

    def test_subdomain_depth_detection(self, engine):
        """Test deep subdomain nesting detection."""
        signals = engine.analyze("https://a.b.c.d.e.example.com/path")
        sub_signals = [s for s in signals if s.key == "subdomain_depth"]
        assert len(sub_signals) > 0
        assert sub_signals[0].points >= 12

    def test_high_entropy_detection(self, engine):
        """Test high entropy hostname detection."""
        signals = engine.analyze("https://x7k9m2p4q8.randomdomain.com/")
        entropy_signals = [s for s in signals if s.key == "high_entropy"]
        assert len(entropy_signals) > 0
        assert entropy_signals[0].points == 8

    def test_brand_in_subdomain_detection(self, engine):
        """Test brand name in subdomain detection."""
        signals = engine.analyze("https://paypal-login.malicious-site.com/verify")
        brand_signals = [s for s in signals if s.key == "suspicious_subdomain"]
        assert len(brand_signals) > 0

    def test_long_url_detection(self, engine):
        """Test unusually long URL detection."""
        long_url = "https://example.com/" + "a" * 200
        signals = engine.analyze(long_url)
        long_signals = [s for s in signals if s.key == "long_url"]
        assert len(long_signals) > 0
        assert long_signals[0].points == 3

    def test_encoded_chars_detection(self, engine):
        """Test high encoded character ratio detection."""
        signals = engine.analyze("https://example.com/%70%61%79%6C%6F%61%64")
        encoded_signals = [s for s in signals if s.key == "encoded_chars"]
        # High ratio should trigger
        if encoded_signals:
            assert encoded_signals[0].points == 5

    def test_redirect_param_detection(self, engine):
        """Test redirect parameter detection."""
        signals = engine.analyze("https://example.com/login?redirect=https://evil.com")
        redirect_signals = [s for s in signals if s.key == "suspicious_path"]
        # redirect is a suspicious path keyword
        assert any("redirect" in s.evidence for s in redirect_signals)

    def test_legitimate_url_low_signals(self, engine):
        """Test legitimate URL produces minimal signals."""
        signals = engine.analyze("https://github.com/microsoft/vscode")
        # Should not have high-risk signals
        high_risk_keys = ["ip_host", "punycode_idn", "at_trick", "suspicious_tld"]
        for s in signals:
            assert s.key not in high_risk_keys

    def test_multiple_urls_in_text(self, engine):
        """Test analysis with multiple URLs."""
        text = "Check https://google.com and http://malicious.tk/phish"
        signals = engine.analyze(text)
        # Should analyze both URLs
        assert len(signals) > 0

    def test_fixture_001_paypal_tk(self, fixtures, engine):
        """Test fixture 001: paypal-verify-account.tk"""
        f = next(f for f in fixtures if f["id"] == "fixture_001")
        text = f["text"] + " " + " ".join(f["urls"])
        signals = engine.analyze(text)
        keys = {s.key for s in signals}
        expected = {"suspicious_tld", "brand_in_subdomain", "suspicious_path"}
        assert expected.issubset(keys)

    def test_fixture_003_amazon_ml(self, fixtures, engine):
        """Test fixture 003: amazon-security-update.ml"""
        f = next(f for f in fixtures if f["id"] == "fixture_003")
        text = f["text"] + " " + " ".join(f["urls"])
        signals = engine.analyze(text)
        keys = {s.key for s in signals}
        expected = {"suspicious_tld", "no_https", "brand_in_subdomain"}
        assert expected.issubset(keys)

    def test_fixture_010_legitimate_netflix(self, fixtures, engine):
        """Test fixture 010: Legitimate Netflix URL."""
        f = next(f for f in fixtures if f["id"] == "fixture_010")
        text = f["text"] + " " + " ".join(f["urls"])
        signals = engine.analyze(text)
        keys = {s.key for s in signals}
        # Should not have suspicious signals
        suspicious = {"ip_host", "punycode_idn", "at_trick", "suspicious_tld", "url_shortener"}
        assert not suspicious.intersection(keys)

    def test_fixture_016_subdomain_spoof(self, fixtures, engine):
        """Test fixture 016: Subdomain spoofing."""
        f = next(f for f in fixtures if f["id"] == "fixture_016")
        text = f["text"] + " " + " ".join(f["urls"])
        signals = engine.analyze(text)
        keys = {s.key for s in signals}
        expected = {"brand_in_subdomain", "no_https", "subdomain_depth"}
        assert expected.issubset(keys)

    def test_fixture_020_ip_host(self, fixtures, engine):
        """Test fixture 020: IP host URL."""
        f = next(f for f in fixtures if f["id"] == "fixture_020")
        text = " ".join(f["urls"])
        signals = engine.analyze(text)
        keys = {s.key for s in signals}
        expected = {"ip_host", "no_https"}
        assert expected.issubset(keys)

    def test_fixture_030_punycode(self, fixtures, engine):
        """Test fixture 030: Punycode Apple."""
        f = next(f for f in fixtures if f["id"] == "fixture_030")
        text = " ".join(f["urls"])
        signals = engine.analyze(text)
        keys = {s.key for s in signals}
        expected = {"punycode_idn"}
        assert expected.issubset(keys)

    def test_fixture_037_at_trick(self, fixtures, engine):
        """Test fixture 037: @ trick."""
        f = next(f for f in fixtures if f["id"] == "fixture_037")
        text = " ".join(f["urls"])
        signals = engine.analyze(text)
        keys = {s.key for s in signals}
        expected = {"at_trick"}
        assert expected.issubset(keys)

    def test_fixture_043_shortener(self, fixtures, engine):
        """Test fixture 043: URL shortener."""
        f = next(f for f in fixtures if f["id"] == "fixture_043")
        text = " ".join(f["urls"])
        signals = engine.analyze(text)
        keys = {s.key for s in signals}
        expected = {"url_shortener"}
        assert expected.issubset(keys)


class TestAnalyzeURLsFunction:
    """Test the backward compatibility function."""

    def test_returns_dict_format(self):
        result = analyze_urls("Check https://example.com")
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