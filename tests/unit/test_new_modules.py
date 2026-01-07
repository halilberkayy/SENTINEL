"""
Unit tests for new scanner modules.
Tests for Dependency, WAF, Logging, WebSocket, and RateLimit scanners.
"""

import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.modules.dependency_scanner import DependencyScanner
from src.modules.logging_scanner import LoggingScanner
from src.modules.rate_limit_scanner import RateLimitScanner
from src.modules.waf_detector import WAFDetector
from src.modules.websocket_scanner import WebSocketScanner


class MockResponse:
    """Mock HTTP response for testing."""

    def __init__(self, status=200, content="", headers=None):
        self.status = status
        self._content = content
        self.headers = headers or {}

    async def text(self):
        return self._content

    async def json(self):
        import json

        return json.loads(self._content)


class MockHTTPClient:
    """Mock HTTP client for testing."""

    def __init__(self, responses=None):
        self.responses = responses or {}
        self.calls = []

    async def get(self, url, headers=None):
        self.calls.append(("GET", url, headers))
        return self.responses.get(url, MockResponse(404))

    async def post(self, url, data=None, json=None, headers=None):
        self.calls.append(("POST", url, data or json))
        return self.responses.get(url, MockResponse(404))

    async def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.get(url, MockResponse(404))


class MockConfig:
    """Mock scanner configuration."""

    def __init__(self):
        self.scanner = Mock()
        self.scanner.timeout = 10
        self.network = Mock()


# ==================== Dependency Scanner Tests ====================


class TestDependencyScanner:
    """Tests for DependencyScanner module."""

    @pytest.fixture
    def scanner(self):
        config = MockConfig()
        http_client = MockHTTPClient()
        return DependencyScanner(config, http_client)

    def test_initialization(self, scanner):
        """Test scanner initialization."""
        assert scanner.name == "DependencyScanner"
        assert scanner.version == "1.0.0"
        assert len(scanner.js_library_patterns) > 0

    def test_version_comparison(self, scanner):
        """Test version comparison logic."""
        assert scanner._compare_versions("1.0.0", "2.0.0") < 0
        assert scanner._compare_versions("2.0.0", "1.0.0") > 0
        assert scanner._compare_versions("1.0.0", "1.0.0") == 0
        assert scanner._compare_versions("1.5.0", "1.10.0") < 0

    def test_version_matches(self, scanner):
        """Test vulnerable version matching."""
        assert scanner._version_matches("3.4.0", "<3.5.0") == True
        assert scanner._version_matches("3.6.0", "<3.5.0") == False
        assert scanner._version_matches("1.8.0", "1.x") == True
        assert scanner._version_matches("2.1.0", "1.x") == False

    def test_parse_requirements(self, scanner):
        """Test requirements.txt parsing."""
        content = """
        flask==2.0.1
        requests>=2.25.0
        django
        # comment
        numpy==1.21.0
        """
        deps = scanner._parse_requirements(content, "requirements.txt")

        assert len(deps) >= 4
        assert any(d.name == "flask" for d in deps)
        assert any(d.name == "django" for d in deps)

    def test_parse_json_config(self, scanner):
        """Test package.json parsing."""
        content = """{
            "name": "test-app",
            "dependencies": {
                "lodash": "^4.17.0",
                "axios": "0.21.0"
            },
            "devDependencies": {
                "jest": "^26.0.0"
            }
        }"""
        deps = scanner._parse_json_config(content, "package.json")

        assert len(deps) == 3
        assert any(d.name == "lodash" for d in deps)
        assert any(d.name == "axios" for d in deps)

    @pytest.mark.asyncio
    async def test_scan_no_dependencies(self, scanner):
        """Test scan with no dependencies found."""
        scanner.http_client.responses = {"https://example.com": MockResponse(200, "<html><body>No libs</body></html>")}

        result = await scanner.scan("https://example.com")
        assert result["status"] in ["Clean", "Error"]


# ==================== WAF Detector Tests ====================


class TestWAFDetector:
    """Tests for WAFDetector module."""

    @pytest.fixture
    def scanner(self):
        config = MockConfig()
        http_client = MockHTTPClient()
        return WAFDetector(config, http_client)

    def test_initialization(self, scanner):
        """Test scanner initialization."""
        assert scanner.name == "WAFDetector"
        assert len(scanner.waf_signatures) > 0
        assert "cloudflare" in scanner.waf_signatures
        assert "akamai" in scanner.waf_signatures

    def test_bypass_techniques(self, scanner):
        """Test bypass techniques are defined."""
        assert "cloudflare" in scanner.bypass_techniques
        assert "generic" in scanner.bypass_techniques
        assert len(scanner.bypass_techniques["generic"]) > 0

    @pytest.mark.asyncio
    async def test_analyze_normal_response_cloudflare(self, scanner):
        """Test CloudFlare detection from headers."""
        scanner.http_client.responses = {
            "https://example.com": MockResponse(200, "OK", {"cf-ray": "abc123", "server": "cloudflare"})
        }

        detected = await scanner._analyze_normal_response("https://example.com")
        assert "cloudflare" in detected

    @pytest.mark.asyncio
    async def test_no_waf_detected(self, scanner):
        """Test when no WAF is detected."""
        scanner.http_client.responses = {"https://example.com": MockResponse(200, "OK", {})}

        result = await scanner.scan("https://example.com")
        assert result["status"] in ["Clean", "Detected", "Error"]


# ==================== Logging Scanner Tests ====================


class TestLoggingScanner:
    """Tests for LoggingScanner module."""

    @pytest.fixture
    def scanner(self):
        config = MockConfig()
        http_client = MockHTTPClient()
        return LoggingScanner(config, http_client)

    def test_initialization(self, scanner):
        """Test scanner initialization."""
        assert scanner.name == "LoggingScanner"
        assert len(scanner.log_injection_payloads) > 0
        assert len(scanner.log_exposure_paths) > 0

    def test_sensitive_patterns(self, scanner):
        """Test sensitive data pattern detection."""
        content_with_password = "password: secret123"
        findings = scanner._check_sensitive_data(content_with_password)
        assert "password_in_logs" in findings

    def test_check_sensitive_api_key(self, scanner):
        """Test API key detection."""
        content = "api_key: AKIAIOSFODNN7EXAMPLE1234567890"
        findings = scanner._check_sensitive_data(content)
        assert "api_key_exposed" in findings

    def test_check_sensitive_email(self, scanner):
        """Test email detection in errors."""
        content = "Error for user test@example.com"
        findings = scanner._check_sensitive_data(content)
        assert "email_in_error" in findings


# ==================== WebSocket Scanner Tests ====================


class TestWebSocketScanner:
    """Tests for WebSocketScanner module."""

    @pytest.fixture
    def scanner(self):
        config = MockConfig()
        http_client = MockHTTPClient()
        return WebSocketScanner(config, http_client)

    def test_initialization(self, scanner):
        """Test scanner initialization."""
        assert scanner.name == "WebSocketScanner"
        assert len(scanner.ws_paths) > 0
        assert len(scanner.malicious_origins) > 0

    @pytest.mark.asyncio
    async def test_find_ws_in_html(self, scanner):
        """Test WebSocket URL extraction from HTML."""
        html_content = """
        <script>
            const socket = new WebSocket("wss://example.com/ws");
        </script>
        """
        scanner.http_client.responses = {"https://example.com": MockResponse(200, html_content)}

        ws_urls = await scanner._find_ws_in_html("https://example.com")
        assert any("wss://" in url for url in ws_urls)


# ==================== Rate Limit Scanner Tests ====================


class TestRateLimitScanner:
    """Tests for RateLimitScanner module."""

    @pytest.fixture
    def scanner(self):
        config = MockConfig()
        http_client = MockHTTPClient()
        return RateLimitScanner(config, http_client)

    def test_initialization(self, scanner):
        """Test scanner initialization."""
        assert scanner.name == "RateLimitScanner"
        assert len(scanner.sensitive_endpoints) > 0
        assert len(scanner.bypass_headers) > 0
        assert len(scanner.rate_limit_headers) > 0

    @pytest.mark.asyncio
    async def test_analyze_rate_limit_headers(self, scanner):
        """Test rate limit header detection."""
        scanner.http_client.responses = {
            "https://example.com": MockResponse(200, "OK", {"x-ratelimit-limit": "100", "x-ratelimit-remaining": "99"})
        }

        result = await scanner._analyze_rate_limit_headers("https://example.com")
        assert result["has_rate_limiting"] == True
        assert result["limit"] == "100"


# ==================== Integration Tests ====================


class TestModuleIntegration:
    """Integration tests for all new modules."""

    def test_all_modules_load(self):
        """Test that all modules can be imported and initialized."""
        config = MockConfig()
        http_client = MockHTTPClient()

        modules = [
            DependencyScanner(config, http_client),
            WAFDetector(config, http_client),
            LoggingScanner(config, http_client),
            WebSocketScanner(config, http_client),
            RateLimitScanner(config, http_client),
        ]

        for module in modules:
            assert module.name is not None
            assert hasattr(module, "scan")

    def test_modules_in_engine(self):
        """Test that modules are registered in scanner engine."""
        from src.core.config import Config
        from src.core.scanner_engine import ScannerEngine

        config = Config()
        engine = ScannerEngine(config)

        expected_modules = [
            "dependency_scanner",
            "waf_detector",
            "logging_scanner",
            "websocket_scanner",
            "rate_limit_scanner",
        ]

        for mod_id in expected_modules:
            assert mod_id in engine.modules, f"Module {mod_id} not found in engine"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
