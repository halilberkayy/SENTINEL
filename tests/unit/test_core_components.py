"""
Comprehensive unit tests for core scanner components.
Tests for HTTP client, config validation, and scan repository.
"""

import pytest
from unittest.mock import AsyncMock, Mock, patch
from datetime import datetime

from src.core.config import Config, NetworkConfig, ScannerConfig
from src.core.http_client import HTTPClient, RateLimiter
from src.core.scan_repository import InMemoryScanStore
from src.modules.base_scanner import BaseScanner, Vulnerability


class TestNetworkConfig:
    """Tests for network configuration."""
    
    def test_default_values(self):
        """Test default network config values."""
        config = Config()
        assert config.network.timeout == 30
        assert config.network.verify_ssl is True
        assert config.network.rate_limit >= 0
    
    def test_custom_values(self):
        """Test custom network config."""
        config = Config()
        config.network.timeout = 60
        config.network.verify_ssl = False
        
        assert config.network.timeout == 60
        assert config.network.verify_ssl is False


class TestURLValidation:
    """Tests for URL validation logic."""
    
    def test_valid_https_url(self):
        """Test valid HTTPS URL."""
        config = Config()
        assert config.validate_target("https://example.com") is True
    
    def test_valid_http_url(self):
        """Test valid HTTP URL."""
        config = Config()
        assert config.validate_target("http://example.com") is True
    
    def test_url_with_path(self):
        """Test URL with path."""
        config = Config()
        assert config.validate_target("https://example.com/api/v1") is True
    
    def test_url_with_port(self):
        """Test URL with port."""
        config = Config()
        assert config.validate_target("https://example.com:8443") is True
    
    def test_invalid_empty_url(self):
        """Test empty URL."""
        config = Config()
        assert config.validate_target("") is False
    
    def test_invalid_malformed_url(self):
        """Test malformed URL."""
        config = Config()
        assert config.validate_target("not-a-url") is False
    
    def test_invalid_no_protocol(self):
        """Test URL without protocol."""
        config = Config()
        assert config.validate_target("example.com") is False


class TestRateLimiter:
    """Tests for rate limiter."""
    
    @pytest.mark.asyncio
    async def test_rate_limiter_basic(self):
        """Test basic rate limiting."""
        limiter = RateLimiter(requests_per_second=10.0)
        
        # First request should not wait
        import time
        start = time.time()
        await limiter.wait()
        elapsed = time.time() - start
        
        # Should be nearly instant for first request
        assert elapsed < 0.2
    
    @pytest.mark.asyncio
    async def test_rate_limiter_multiple_requests(self):
        """Test rate limiting with multiple requests."""
        limiter = RateLimiter(requests_per_second=100.0)  # High rate for fast test
        
        # Make several requests
        for _ in range(5):
            await limiter.wait()
        
        # All should complete without error


class TestVulnerability:
    """Tests for Vulnerability model."""
    
    def test_vulnerability_creation(self):
        """Test basic vulnerability creation."""
        vuln = Vulnerability(
            title="Test XSS",
            description="Cross-site scripting vulnerability",
            severity="high",
            type="xss",
            evidence={"payload": "<script>alert(1)</script>"}
        )
        
        assert vuln.title == "Test XSS"
        assert vuln.severity == "high"
        assert vuln.type == "xss"
    
    def test_vulnerability_with_cvss(self):
        """Test vulnerability with CVSS score."""
        vuln = Vulnerability(
            title="SQL Injection",
            description="SQL injection found",
            severity="critical",
            type="sqli",
            evidence={},
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )
        
        assert vuln.cvss_score == 9.8
        assert "CVSS:3.1" in vuln.cvss_vector
    
    def test_vulnerability_with_cwe(self):
        """Test vulnerability with CWE ID."""
        vuln = Vulnerability(
            title="Command Injection",
            description="OS command injection",
            severity="critical",
            type="cmdi",
            evidence={},
            cwe_id="CWE-78"
        )
        
        assert vuln.cwe_id == "CWE-78"


class TestInMemoryScanStore:
    """Tests for in-memory scan storage."""
    
    def test_save_and_get(self):
        """Test saving and retrieving scan."""
        store = InMemoryScanStore()
        
        scan_data = {
            "url": "https://example.com",
            "modules": ["xss", "sqli"],
            "results": []
        }
        
        store.save_scan("scan-123", scan_data)
        retrieved = store.get_scan("scan-123")
        
        assert retrieved is not None
        assert retrieved["url"] == "https://example.com"
    
    def test_get_nonexistent(self):
        """Test getting nonexistent scan."""
        store = InMemoryScanStore()
        result = store.get_scan("nonexistent")
        assert result is None
    
    def test_get_recent_scans(self):
        """Test getting recent scans."""
        store = InMemoryScanStore()
        
        # Add multiple scans
        for i in range(5):
            store.save_scan(f"scan-{i}", {"index": i})
        
        recent = store.get_recent_scans(limit=3)
        assert len(recent) == 3
    
    def test_delete_scan(self):
        """Test deleting scan."""
        store = InMemoryScanStore()
        store.save_scan("scan-delete", {"test": True})
        
        assert store.delete_scan("scan-delete") is True
        assert store.get_scan("scan-delete") is None
    
    def test_clear_all(self):
        """Test clearing all scans."""
        store = InMemoryScanStore()
        store.save_scan("scan-1", {})
        store.save_scan("scan-2", {})
        
        store.clear()
        
        assert store.get_scan("scan-1") is None
        assert store.get_scan("scan-2") is None


class TestHTTPClientMocked:
    """Tests for HTTP client with mocking."""
    
    @pytest.fixture
    def mock_network_config(self):
        """Create mock network config."""
        config = Mock()
        config.timeout = 30
        config.verify_ssl = True
        config.rate_limit = 10.0
        config.max_retries = 3
        config.proxy = None
        return config
    
    def test_client_initialization(self, mock_network_config):
        """Test HTTP client initialization."""
        client = HTTPClient(mock_network_config)
        
        assert client.config.timeout == 30
        assert client.stealth_mode is False
    
    def test_enable_stealth_mode(self, mock_network_config):
        """Test enabling stealth mode."""
        client = HTTPClient(mock_network_config)
        client.enable_stealth()
        
        assert client.stealth_mode is True


class TestBaseScannerMocked:
    """Tests for base scanner functionality."""
    
    @pytest.fixture
    def mock_config(self):
        """Create mock config."""
        config = Mock(spec=Config)
        config.network = Mock()
        config.network.timeout = 30
        config.network.verify_ssl = True
        config.network.rate_limit = 1.0
        config.scanner = Mock()
        config.scanner.concurrent_requests = 10
        return config
    
    @pytest.fixture
    def mock_http_client(self):
        """Create mock HTTP client."""
        client = Mock()
        client.get = AsyncMock()
        client.post = AsyncMock()
        return client
    
    def test_create_vulnerability(self, mock_config, mock_http_client):
        """Test vulnerability creation through scanner."""
        
        class TestScanner(BaseScanner):
            async def scan(self, url, progress_callback=None):
                return self._format_result("Test", "Done", [], {})
        
        scanner = TestScanner(mock_config, mock_http_client)
        vuln = scanner._create_vulnerability(
            title="Test",
            description="Test desc",
            severity="medium",
            type="test",
            evidence={}
        )
        
        assert vuln.title == "Test"
        assert vuln.severity == "medium"
    
    def test_format_result(self, mock_config, mock_http_client):
        """Test result formatting."""
        
        class TestScanner(BaseScanner):
            async def scan(self, url, progress_callback=None):
                return self._format_result("Complete", "All checks done", [], None)
        
        scanner = TestScanner(mock_config, mock_http_client)
        result = scanner._format_result("Complete", "Done", [], {})
        
        assert result["status"] == "Complete"
        assert "timestamp" in result
        assert result["risk_level"] == "clean"
    
    def test_get_risk_level_with_vulns(self, mock_config, mock_http_client):
        """Test risk level calculation."""
        
        class TestScanner(BaseScanner):
            async def scan(self, url, progress_callback=None):
                return {}
        
        scanner = TestScanner(mock_config, mock_http_client)
        
        vulns = [
            Vulnerability(title="Test", description="", severity="medium", type="test", evidence={}),
            Vulnerability(title="Test2", description="", severity="high", type="test", evidence={}),
        ]
        
        risk = scanner._get_risk_level(vulns)
        assert risk == "high"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
