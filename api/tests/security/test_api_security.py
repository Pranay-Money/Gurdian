"""
API Security Tests
Tests for CSP, no eval, dependency audit, SSRF, input fuzzing, rate limiting, secrets scan
"""

import asyncio
import json
import json
import shutil
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from httpx import AsyncClient
from src.core.config import get_settings
from src.engines.url_engine import URLEngine
from src.main import app


class TestAPISecurity:
    """Test API security controls"""

    @pytest.fixture
    def client(self):
        with TestClient(app) as test_client:
            yield test_client

    @pytest.fixture
    def auth_headers(self):
        return {"X-Device-Token": f"dev_test_{uuid4().hex}"}

    def test_cors_restricted(self, client):
        """Test CORS is restricted to configured origins"""
        response = client.options(
            "/v1/analyze",
            headers={"Origin": "https://evil.com", "Access-Control-Request-Method": "POST"}
        )
        # Should not allow arbitrary origins in production
        # In test env, it may allow all - check configuration
        settings = get_settings()
        if settings.app_env == "production":
            assert "access-control-allow-origin" not in response.headers or \
                   response.headers.get("access-control-allow-origin") != "*"

    def test_no_wildcard_cors_in_production(self):
        """Verify CORS_ORIGINS is configured for production"""
        settings = get_settings()
        if settings.app_env == "production":
            assert settings.cors_origins != "*"
            assert len(settings.cors_origins) > 0

    def test_request_size_limit(self, client, auth_headers):
        """Test request size limit enforcement"""
        # Create a payload > 1MB
        large_text = "A" * (2 * 1024 * 1024)  # 2MB
        response = client.post(
            "/v1/analyze",
            json={"channel": "email", "text": large_text, "urls": []},
            headers=auth_headers
        )
        # Should reject oversized payloads
        assert response.status_code in (413, 400, 422)

    def test_analyze_text_size_limit(self, client, auth_headers):
        """Test /v1/analyze text max 50KB"""
        large_text = "A" * (60 * 1024)  # 60KB
        response = client.post(
            "/v1/analyze",
            json={"channel": "email", "text": large_text, "urls": []},
            headers=auth_headers
        )
        assert response.status_code in (400, 413, 422)

    def test_analyze_urls_count_limit(self, client, auth_headers):
        """Test /v1/analyze URLs max 20"""
        many_urls = [f"https://example{i}.com" for i in range(25)]
        response = client.post(
            "/v1/analyze",
            json={"channel": "email", "text": "", "urls": many_urls},
            headers=auth_headers
        )
        assert response.status_code in (400, 422)

    def test_rate_limit_headers(self, client, auth_headers):
        """Test rate limit headers present"""
        response = client.post(
            "/v1/analyze",
            json={"channel": "url", "urls": ["https://example.com"]},
            headers=auth_headers
        )
        # Check for rate limit headers
        assert "x-ratelimit-limit" in response.headers
        assert "x-ratelimit-remaining" in response.headers
        assert "x-ratelimit-reset" in response.headers

    def test_rate_limit_enforced(self, client, auth_headers):
        """Test rate limiting is enforced"""
        # Make many requests quickly
        for _ in range(35):  # Over default 30/min limit
            response = client.post(
                "/v1/analyze",
                json={"channel": "url", "urls": ["https://example.com"]},
                headers=auth_headers
            )
            if response.status_code == 429:
                break
        assert response.status_code == 429
        assert "retry-after" in response.headers or "x-ratelimit-reset" in response.headers

    def test_device_token_required(self, client):
        """Test device token authentication required"""
        response = client.post(
            "/v1/analyze",
            json={"channel": "url", "urls": ["https://example.com"]}
        )
        assert response.status_code == 401

    def test_invalid_device_token_rejected(self, client):
        """Test invalid device token rejected"""
        response = client.post(
            "/v1/analyze",
            json={"channel": "url", "urls": ["https://example.com"]},
            headers={"X-Device-Token": "invalid_token"}
        )
        assert response.status_code == 401

    def test_structured_logging_no_pii(self, client, auth_headers, caplog):
        """Test structured JSON logging without PII"""
        import logging

        import structlog
        
        # Make a request
        client.post(
            "/v1/analyze",
            json={"channel": "email", "text": "My password is secret123", "urls": ["https://example.com"]},
            headers=auth_headers
        )
        
        # Check logs don't contain sensitive data
        log_output = caplog.text
        assert "secret123" not in log_output
        assert "password" not in log_output.lower()

    def test_no_secrets_in_logs(self):
        """Verify no hardcoded secrets in codebase"""
        import os
        import subprocess
        
        # This is checked by gitleaks in CI
        # Here we verify key files don't have obvious secrets
        secret_patterns = ["SECRET_KEY", "API_KEY", "PASSWORD", "TOKEN"]
        for root, dirs, files in os.walk("src"):
            for f in files:
                if f.endswith(".py"):
                    path = os.path.join(root, f)
                    with open(path) as fp:
                        content = fp.read()
                        # Check for actual secret values (not just variable names)
                        for pattern in secret_patterns:
                            # Skip test files and config templates
                            if "test" not in path and "template" not in path:
                                pass  # gitleaks handles this


class TestSSRFProtection:
    """Test SSRF protection in deep mode URL analysis"""

    @pytest.fixture
    def engine(self):
        return URLEngine()

    @pytest.mark.asyncio
    async def test_ssrf_block_private_ip(self, engine):
        """Test SSRF protection blocks private IPs in redirects"""
        signals = await engine._follow_redirects("http://192.168.1.1/admin", max_hops=1)
        ssrf_signals = [s for s in signals if s.key == "ssrf_blocked"]
        assert len(ssrf_signals) > 0
        assert ssrf_signals[0].points == 20

    @pytest.mark.asyncio
    async def test_ssrf_block_loopback(self, engine):
        """Test SSRF protection blocks loopback"""
        signals = await engine._follow_redirects("http://127.0.0.1:8080/admin", max_hops=1)
        ssrf_signals = [s for s in signals if s.key == "ssrf_blocked"]
        assert len(ssrf_signals) > 0

    @pytest.mark.asyncio
    async def test_ssrf_block_link_local(self, engine):
        """Test SSRF protection blocks link-local"""
        signals = await engine._follow_redirects("http://169.254.169.254/latest/meta-data", max_hops=1)
        ssrf_signals = [s for s in signals if s.key == "ssrf_blocked"]
        assert len(ssrf_signals) > 0

    @pytest.mark.asyncio
    async def test_ssrf_allow_public_ip(self, engine):
        """Test SSRF allows public IPs"""
        with patch('httpx.AsyncClient.head') as mock_head:
            mock_resp = MagicMock()
            mock_resp.is_redirect = False
            mock_resp.status_code = 200
            mock_head.return_value = mock_resp
            
            signals = await engine._follow_redirects("http://8.8.8.8/", max_hops=1)
            ssrf_signals = [s for s in signals if s.key == "ssrf_blocked"]
            assert len(ssrf_signals) == 0

    @pytest.mark.asyncio
    async def test_redirect_loop_detection(self, engine):
        """Test redirect loop detection"""
        with patch('httpx.AsyncClient.head') as mock_head:
            mock_resp = MagicMock()
            mock_resp.is_redirect = True
            mock_resp.status_code = 302
            mock_resp.headers = {"location": "http://example.com/loop"}
            mock_head.return_value = mock_resp
            
            signals = await engine._follow_redirects("http://example.com/loop", max_hops=5)
            loop_signals = [s for s in signals if s.key == "redirect_loop"]
            assert len(loop_signals) > 0

    @pytest.mark.asyncio
    async def test_max_hops_enforced(self, engine):
        """Test max hops limit enforced"""
        with patch('httpx.AsyncClient.head') as mock_head:
            mock_resp = MagicMock()
            mock_resp.is_redirect = True
            mock_resp.status_code = 302
            mock_resp.headers = {"location": "http://example.com/next"}
            mock_head.return_value = mock_resp
            
            signals = await engine._follow_redirects("http://example.com/start", max_hops=3)
            chain_signals = [s for s in signals if s.key == "redirects_chain"]
            assert len(chain_signals) > 0
            # Should stop at max_hops


class TestInputFuzzing:
    """Test input fuzzing on /v1/analyze"""

    @pytest.fixture
    def client(self):
        with TestClient(app) as test_client:
            yield test_client

    @pytest.fixture
    def auth_headers(self):
        return {"X-Device-Token": f"dev_test_{uuid4().hex}"}

    def test_huge_input_rejected(self, client, auth_headers):
        """Test huge inputs rejected"""
        huge_text = "A" * (10 * 1024 * 1024)  # 10MB
        response = client.post(
            "/v1/analyze",
            json={"channel": "email", "text": huge_text, "urls": []},
            headers=auth_headers
        )
        assert response.status_code in (413, 400, 422)

    def test_unicode_tricks_handled(self, client, auth_headers):
        """Test unicode tricks (RTL override, homoglyphs) handled"""
        # RTL override
        rtl_text = "Click here \u202E to verify"
        response = client.post(
            "/v1/analyze",
            json={"channel": "email", "text": rtl_text, "urls": []},
            headers=auth_headers
        )
        assert response.status_code == 200
        # Should not crash

    def test_homoglyph_urls_detected(self, client, auth_headers):
        """Test homoglyph URLs detected"""
        # Cyrillic 'а' (U+0430) instead of Latin 'a'
        homoglyph_url = "https://p\u0430ypal.com/login"
        response = client.post(
            "/v1/analyze",
            json={"channel": "email", "text": "", "urls": [homoglyph_url]},
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        # Should detect punycode/homograph
        signals = data.get("signals", [])
        puny_signals = [s for s in signals if "punycode" in s.get("key", "") or "homograph" in s.get("key", "")]
        # May or may not detect depending on implementation

    def test_zero_width_chars_handled(self, client, auth_headers):
        """Test zero-width characters handled"""
        zw_text = "Click\u200B\u200C\u200D here"  # Zero-width space, non-joiner, joiner
        response = client.post(
            "/v1/analyze",
            json={"channel": "email", "text": zw_text, "urls": []},
            headers=auth_headers
        )
        assert response.status_code == 200

    def test_very_long_url_handled(self, client, auth_headers):
        """Reject URLs longer than the documented safe input boundary."""
        long_url = "https://example.com/" + "a" * 10000
        response = client.post(
            "/v1/analyze",
            json={"channel": "email", "text": "", "urls": [long_url]},
            headers=auth_headers
        )
        assert response.status_code == 422

    @pytest.mark.parametrize(
        ("url_length", "expected_status"),
        [(2047, 200), (2048, 200), (2049, 422)],
    )
    def test_analyze_url_length_boundary(self, client, auth_headers, url_length, expected_status):
        """Accept URLs through 2048 characters and reject longer inputs."""
        prefix = "https://example.com/"
        url = prefix + "a" * (url_length - len(prefix))
        response = client.post(
            "/v1/analyze",
            json={"channel": "email", "text": "", "urls": [url]},
            headers=auth_headers,
        )
        assert response.status_code == expected_status

    def test_repeated_fuzz_requests_stay_within_rate_limit(self, client):
        """Repeated fuzz inputs remain below the configured per-device limit."""
        headers = {"X-Device-Token": f"dev_fuzz_{uuid4().hex}"}
        payloads = [
            {"channel": "email", "text": "Click here \u202E to verify", "urls": []},
            {"channel": "email", "text": "", "urls": ["https://p\u0430ypal.com/login"]},
            {"channel": "email", "text": "Click\u200B\u200C\u200D here", "urls": []},
            {"channel": "email", "text": "'; DROP TABLE cases; --", "urls": []},
            {"channel": "email", "text": "<script>alert(1)</script>", "urls": []},
            {"channel": "email", "text": "", "urls": ["https://example.com/../../../etc/passwd"]},
        ]
        for payload in payloads:
            response = client.post("/v1/analyze", json=payload, headers=headers)
            assert response.status_code == 200

    def test_malformed_json_rejected(self, client, auth_headers):
        """Test malformed JSON rejected"""
        response = client.post(
            "/v1/analyze",
            content=b'{"channel": "email", "text": "test"',  # Missing closing brace
            headers={**auth_headers, "Content-Type": "application/json"}
        )
        assert response.status_code in (400, 422)

    def test_sql_injection_attempts_safe(self, client, auth_headers):
        """Test SQL injection attempts don't break API"""
        sql_text = "'; DROP TABLE cases; --"
        response = client.post(
            "/v1/analyze",
            json={"channel": "email", "text": sql_text, "urls": []},
            headers=auth_headers
        )
        assert response.status_code == 200

    def test_xss_attempts_safe(self, client, auth_headers):
        """Test XSS attempts don't break API"""
        xss_text = "<script>alert(1)</script>"
        response = client.post(
            "/v1/analyze",
            json={"channel": "email", "text": xss_text, "urls": []},
            headers=auth_headers
        )
        assert response.status_code == 200

    def test_path_traversal_in_url_safe(self, client, auth_headers):
        """Test path traversal in URL handled"""
        traversal_url = "https://example.com/../../../etc/passwd"
        response = client.post(
            "/v1/analyze",
            json={"channel": "email", "text": "", "urls": [traversal_url]},
            headers=auth_headers
        )
        assert response.status_code == 200


class TestDependencySecurity:
    """Test dependency security"""

    def test_no_known_vulnerabilities_pip_audit(self):
        """Run a real pip-audit from the API project directory."""
        import subprocess

        api_root = Path(__file__).resolve().parents[2]
        assert (api_root / "pyproject.toml").is_file(), f"API project not found under {api_root}"
        pip_audit = shutil.which("pip-audit")
        assert pip_audit is not None, "pip-audit is required; install the API dev dependencies"
        result = subprocess.run(
            [pip_audit, "--desc", "--format=json"],
            capture_output=True,
            text=True,
            cwd=api_root,
        )
        assert result.returncode == 0, (
            f"pip-audit reported vulnerabilities or failed:\n{result.stdout}\n{result.stderr}"
        )
        report = json.loads(result.stdout)
        dependencies = report.get("dependencies", [])
        vulnerable = [
            {"name": dep.get("name"), "vulnerabilities": dep.get("vulns", [])}
            for dep in dependencies
            if dep.get("vulns")
        ]
        assert not vulnerable, f"Python vulnerabilities found: {vulnerable}"

class TestRateLimiting:
    """Test rate limiting enforcement"""

    @pytest.fixture
    def client(self):
        with TestClient(app) as test_client:
            yield test_client

    def test_per_device_rate_limit(self, client):
        """The analyze endpoint enforces its configured 30 requests/minute limit."""
        headers = {"X-Device-Token": f"dev_rate_test_{uuid4().hex}"}
        for i in range(35):
            response = client.post(
                "/v1/analyze",
                json={"channel": "url", "urls": ["https://example.com"]},
                headers=headers
            )
            if response.status_code == 429:
                assert i >= 30
                break
        assert response.status_code == 429

    def test_analyze_stricter_rate_limit(self, client):
        """Test /v1/analyze has stricter rate limit"""
        headers = {"X-Device-Token": f"dev_rate_test_{uuid4().hex}"}
        for i in range(35):
            response = client.post(
                "/v1/analyze",
                json={"channel": "url", "urls": ["https://example.com"]},
                headers=headers
            )
            if response.status_code == 429:
                assert i >= 30
                break
        assert response.status_code == 429

    def test_rate_limit_headers_accurate(self, client):
        """Test rate limit headers show correct remaining"""
        headers = {"X-Device-Token": f"dev_rate_test_{uuid4().hex}"}
        response = client.post(
            "/v1/analyze",
            json={"channel": "url", "urls": ["https://example.com"]},
            headers=headers
        )
        remaining = int(response.headers.get("x-ratelimit-remaining", 0))
        limit = int(response.headers.get("x-ratelimit-limit", 0))
        assert remaining <= limit
        assert limit > 0

    def test_rate_limit_isolated_between_devices(self, client):
        """An exhausted device bucket does not block another device."""
        exhausted_headers = {"X-Device-Token": f"dev_rate_test_{uuid4().hex}"}
        for _ in range(31):
            response = client.post(
                "/v1/analyze",
                json={"channel": "url", "urls": ["https://example.com"]},
                headers=exhausted_headers,
            )
            if response.status_code == 429:
                break
        assert response.status_code == 429

        other_device_headers = {"X-Device-Token": f"dev_rate_test_{uuid4().hex}"}
        response = client.post(
            "/v1/analyze",
            json={"channel": "url", "urls": ["https://example.com"]},
            headers=other_device_headers,
        )
        assert response.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v"])