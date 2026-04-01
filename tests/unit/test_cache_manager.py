"""
Unit tests for Redis cache manager with fallback.
"""

import pytest
from unittest.mock import AsyncMock, Mock, patch
from src.core.cache.redis_cache import CacheManager


@pytest.fixture
def cache_manager():
    """Create cache manager instance."""
    return CacheManager("redis://localhost:6379/0")


class TestCacheManager:
    """Test cache manager functionality."""

    def test_cache_initialization(self, cache_manager):
        """Test cache manager initializes correctly."""
        assert cache_manager.redis_url == "redis://localhost:6379/0"
        assert cache_manager.redis is None

    @pytest.mark.asyncio
    async def test_cache_connect_success(self, cache_manager):
        """Test successful cache connection."""
        mock_conn = AsyncMock()
        mock_conn.ping = AsyncMock(return_value=True)
        with patch("src.core.cache.redis_cache.aioredis.from_url", return_value=mock_conn):
            await cache_manager.connect()
            assert cache_manager.redis is mock_conn

    @pytest.mark.asyncio
    async def test_cache_connect_failure_fallback(self, cache_manager):
        """Test cache connection failure triggers fallback mode."""
        with patch("src.core.cache.redis_cache.aioredis.from_url") as mock_redis:
            mock_redis.side_effect = Exception("Connection failed")
            await cache_manager.connect()
            assert cache_manager.redis is None  # Fallback mode

    @pytest.mark.asyncio
    async def test_get_with_no_connection(self, cache_manager):
        """Test get operation in fallback mode."""
        result = await cache_manager.get("test_key")
        assert result is None

    @pytest.mark.asyncio
    async def test_set_with_no_connection(self, cache_manager):
        """Test set operation in fallback mode."""
        result = await cache_manager.set("test_key", "test_value")
        assert result is False

    @pytest.mark.asyncio
    async def test_ping_with_no_connection(self, cache_manager):
        """Test ping returns False when not connected."""
        result = await cache_manager.ping()
        assert result is False

    @pytest.mark.asyncio
    async def test_cache_operations_with_connection_error(self, cache_manager):
        """Test cache operations handle connection errors gracefully."""
        # Simulate connected state
        cache_manager.redis = Mock()
        cache_manager.redis.get = AsyncMock(side_effect=ConnectionError("Lost connection"))
        
        result = await cache_manager.get("test_key")
        assert result is None
        assert cache_manager.redis is None  # Should disable cache on connection error

    @pytest.mark.asyncio
    async def test_cache_scan_result(self, cache_manager):
        """Test scan result caching."""
        cache_manager.redis = Mock()
        cache_manager.redis.set = AsyncMock(return_value=True)
        
        result = await cache_manager.cache_scan_result("scan_123", {"data": "test"})
        assert result is True

    @pytest.mark.asyncio
    async def test_get_cached_scan_result(self, cache_manager):
        """Test retrieving cached scan result."""
        cache_manager.redis = Mock()
        cache_manager.redis.get = AsyncMock(return_value='{"data": "test"}')
        
        result = await cache_manager.get_cached_scan_result("scan_123")
        assert result == {"data": "test"}
