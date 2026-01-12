"""
Unit tests for HTTP client with connection pooling.
"""

import pytest
from unittest.mock import AsyncMock, Mock, patch
from src.core.http_client import HTTPClient, RateLimiter
from src.core.config import NetworkConfig


@pytest.fixture
def network_config():
    """Create mock network config."""
    config = Mock(spec=NetworkConfig)
    config.timeout = 30
    config.verify_ssl = True
    config.max_retries = 3
    config.retry_delay = 1.0
    config.max_redirects = 5
    config.user_agent = "Test Agent"
    config.rate_limit = 10.0
    return config


@pytest.fixture
def http_client(network_config):
    """Create HTTP client instance."""
    return HTTPClient(network_config)


class TestRateLimiter:
    """Test rate limiter functionality."""

    @pytest.mark.asyncio
    async def test_rate_limiter_initialization(self):
        """Test rate limiter initializes correctly."""
        limiter = RateLimiter(10.0)
        assert limiter.rate == 10.0
        assert limiter.interval == 0.1

    @pytest.mark.asyncio
    async def test_rate_limiter_wait(self):
        """Test rate limiter enforces delays."""
        limiter = RateLimiter(10.0)
        import time
        start = time.monotonic()
        await limiter.wait()
        await limiter.wait()
        elapsed = time.monotonic() - start
        # Should take at least 0.1 seconds (1/10 rate)
        assert elapsed >= 0.1


class TestHTTPClient:
    """Test HTTP client functionality."""

    def test_client_initialization(self, http_client):
        """Test client initializes with correct settings."""
        assert http_client.session is None
        assert http_client.request_count == 0
        assert http_client.error_count == 0
        assert http_client.stealth_mode is False

    def test_connection_pool_settings(self, http_client):
        """Test connection pool is configured correctly."""
        assert http_client.connector_settings["limit"] == 100
        assert http_client.connector_settings["limit_per_host"] == 30
        assert http_client.connector_settings["ttl_dns_cache"] == 600
        assert http_client.connector_settings["keepalive_timeout"] == 30

    @pytest.mark.asyncio
    async def test_client_start(self, http_client):
        """Test client session starts correctly."""
        await http_client.start()
        assert http_client.session is not None
        await http_client.close()

    @pytest.mark.asyncio
    async def test_client_close(self, http_client):
        """Test client closes cleanly."""
        await http_client.start()
        await http_client.close()
        assert http_client.session is None

    def test_enable_stealth(self, http_client):
        """Test stealth mode activation."""
        assert http_client.stealth_mode is False
        http_client.enable_stealth()
        assert http_client.stealth_mode is True

    @pytest.mark.asyncio
    async def test_context_manager(self, http_client):
        """Test client works as context manager."""
        async with http_client as client:
            assert client.session is not None
        assert http_client.session is None

    @pytest.mark.asyncio
    async def test_get_stats(self, http_client):
        """Test statistics tracking."""
        stats = await http_client.get_stats()
        assert "total_requests" in stats
        assert "error_count" in stats
        assert "success_rate" in stats
        assert stats["total_requests"] == 0
        assert stats["error_count"] == 0
