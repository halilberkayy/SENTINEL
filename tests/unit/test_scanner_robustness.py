"""Robustness regression tests for the scanner's response-reliability gate.

These lock in the fix for false findings produced when the scanner is served a
WAF/bot-challenge or an error page instead of the real application (e.g. a site
behind Vercel/Cloudflare bot protection).
"""

import pytest

from src.core.config import Config
from src.core.http_client import detect_block_reason, response_reliability
from src.modules.base_scanner import BaseScanner
from src.modules.headers_scanner import HeadersScanner


class FakeResp:
    def __init__(self, status: int, headers: dict, url: str):
        self.status = status
        self.headers = headers
        self.url = url

    async def text(self) -> str:
        return ""


class FakeClient:
    def __init__(self, resp: FakeResp):
        self._resp = resp

    async def get(self, url, **kwargs):
        return self._resp

    async def start(self):
        pass

    async def close(self):
        pass


SECURE_HEADERS = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
}


def test_detect_block_reason_distinguishes_challenge_from_normal():
    # Normal responses are never blocks, including a normal Vercel-hosted 200.
    assert detect_block_reason(200, {"server": "nginx"}) is None
    assert detect_block_reason(200, {"server": "Vercel", "x-vercel-id": "fra1::a"}) is None
    assert detect_block_reason(404, {"server": "nginx"}) is None
    assert detect_block_reason(403, {"server": "nginx"}) is None  # plain 403, no challenge marker
    # Real challenges/blocks are detected.
    assert detect_block_reason(403, {"x-vercel-mitigated": "challenge"})
    assert detect_block_reason(403, {"cf-mitigated": "challenge"})
    assert detect_block_reason(429, {}) == "rate limited (HTTP 429)"
    assert detect_block_reason(503, {"cf-ray": "abc"})


def test_response_reliability():
    assert response_reliability(FakeResp(200, {}, "https://x")) == (True, None)
    assert response_reliability(FakeResp(301, {}, "https://x"))[0] is True
    assert response_reliability(FakeResp(500, {}, "https://x"))[0] is False
    ok, reason = response_reliability(FakeResp(403, {"x-vercel-mitigated": "challenge"}, "https://x"))
    assert ok is False and "Vercel" in reason
    assert response_reliability(None) == (False, "no response")


def test_redirect_note():
    assert BaseScanner._redirect_note("https://example.com/", "https://www.example.com/") is not None
    assert BaseScanner._redirect_note("https://example.com/", "https://example.com/x") is None


@pytest.mark.asyncio
async def test_headers_scanner_skips_challenge_page():
    resp = FakeResp(403, {"x-vercel-mitigated": "challenge"}, "https://www.example.com/")
    scanner = HeadersScanner(Config(), FakeClient(resp))
    result = await scanner.scan("https://example.com/")
    assert result["status"] == "Unreliable"
    assert result["vulnerabilities"] == []


@pytest.mark.asyncio
async def test_headers_scanner_flags_missing_headers_on_real_page():
    resp = FakeResp(200, {}, "https://example.com/")
    scanner = HeadersScanner(Config(), FakeClient(resp))
    result = await scanner.scan("https://example.com/")
    titles = [v["title"] for v in result["vulnerabilities"]]
    assert any("Strict-Transport-Security" in t for t in titles)


@pytest.mark.asyncio
async def test_headers_scanner_clean_on_secure_page():
    resp = FakeResp(200, SECURE_HEADERS, "https://example.com/")
    scanner = HeadersScanner(Config(), FakeClient(resp))
    result = await scanner.scan("https://example.com/")
    severities = [v["severity"] for v in result["vulnerabilities"]]
    assert "high" not in severities and "medium" not in severities


@pytest.mark.asyncio
async def test_headers_scanner_marks_cross_host_findings_tentative():
    # Requested apex, served from www: findings describe a different host.
    resp = FakeResp(200, {}, "https://www.example.com/")
    scanner = HeadersScanner(Config(), FakeClient(resp))
    result = await scanner.scan("https://example.com/")
    assert any(v.get("confidence") == "tentative" for v in result["vulnerabilities"])
    assert "redirect" in result["details"].lower()


# ── js_secrets: entropy / placeholder validation ────────────────────────


def test_js_secret_validation_rejects_placeholders_and_low_entropy():
    from src.modules.js_secrets_scanner import _looks_like_secret

    # A real, high-entropy 32-char token for a broad pattern is accepted.
    assert _looks_like_secret("Zx9Qw3Vb7Kp2Lm8Nr4Ts6Yc1Hd5Gf0Jk", broad=True)
    # A low-entropy string that technically matches a broad pattern is rejected.
    assert not _looks_like_secret("ACababababababababababababababab", broad=True)
    # Obvious placeholders are always rejected.
    assert not _looks_like_secret("AKIAIOSFODNN7EXAMPLE", broad=False)
    assert not _looks_like_secret("your_api_key_here_000000000000000", broad=True)


# ── directory: soft-404 / catch-all baseline ────────────────────────────


def test_directory_baseline_suppresses_catch_all():
    from src.modules.directory_scanner import DirectoryScanner

    baseline = {"status": 200, "type": "text/html", "size": 5000}
    same = {"status": 200, "type": "text/html", "size": 5010, "path": "/config"}
    distinct = {"status": 200, "type": "application/json", "size": 120, "path": "/api/keys"}
    assert DirectoryScanner._matches_baseline(same, baseline) is True
    assert DirectoryScanner._matches_baseline(distinct, baseline) is False
    # No catch-all baseline: nothing suppressed.
    assert DirectoryScanner._matches_baseline(same, None) is False


# ── open_redirect: firm vs tentative confidence ─────────────────────────


def test_open_redirect_confidence_levels():
    from src.modules.open_redirect_scanner import OpenRedirectScanner

    scanner = OpenRedirectScanner(Config(), None)
    # 302 to the attacker destination -> confirmed (firm).
    redirect_resp = {"status_code": 302, "headers": {"Location": "https://evil.com"}, "page_content": ""}
    assert scanner._is_redirect_vulnerable(redirect_resp, "https://evil.com") == (True, "firm")
    # Only reflected in a JS sink in the body -> tentative.
    reflected = {"status_code": 200, "headers": {}, "page_content": 'window.location = "https://evil.com"'}
    vulnerable, confidence = scanner._is_redirect_vulnerable(reflected, "https://evil.com")
    assert vulnerable is True and confidence == "tentative"
    # Nothing -> not vulnerable.
    clean = {"status_code": 200, "headers": {}, "page_content": "<html>ok</html>"}
    assert scanner._is_redirect_vulnerable(clean, "https://evil.com") == (False, "")


# ── misconfig: version-leak gated to real responses ─────────────────────


@pytest.mark.asyncio
async def test_misconfig_skips_version_leak_on_challenge():
    from src.modules.security_misconfig_scanner import SecurityMisconfigScanner

    resp = FakeResp(403, {"x-vercel-mitigated": "challenge", "Server": "Vercel"}, "https://x/")
    scanner = SecurityMisconfigScanner(Config(), FakeClient(resp))
    result = await scanner.scan("https://example.com/")
    titles = [v["title"] for v in result["vulnerabilities"]]
    assert "Server Information Leakage" not in titles


@pytest.mark.asyncio
async def test_misconfig_flags_version_leak_on_real_page():
    from src.modules.security_misconfig_scanner import SecurityMisconfigScanner

    resp = FakeResp(200, {"Server": "nginx/1.18.0"}, "https://x/")
    scanner = SecurityMisconfigScanner(Config(), FakeClient(resp))
    result = await scanner.scan("https://example.com/")
    titles = [v["title"] for v in result["vulnerabilities"]]
    assert "Server Information Leakage" in titles
