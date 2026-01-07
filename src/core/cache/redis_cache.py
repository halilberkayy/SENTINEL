"""
Redis-based caching layer for scan results and sessions.
"""

import json
import logging
from typing import Any

from redis import asyncio as aioredis

logger = logging.getLogger(__name__)


class CacheManager:
    """Redis cache manager for the scanner."""

    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        """Initialize Redis connection."""
        self.redis_url = redis_url
        self.redis: aioredis.Redis | None = None

    async def connect(self) -> None:
        """Connect to Redis."""
        self.redis = await aioredis.from_url(
            self.redis_url,
            encoding="utf-8",
            decode_responses=False,  # We'll handle encoding ourselves
            max_connections=50,
        )
        logger.info(f"Connected to Redis: {self.redis_url}")

    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self.redis:
            await self.redis.close()
            logger.info("Disconnected from Redis")

    async def get(self, key: str) -> Any | None:
        """
        Get a value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found
        """
        if not self.redis:
            return None

        try:
            value = await self.redis.get(key)
            if value is None:
                return None

            return json.loads(value)
        except Exception as e:
            logger.error(f"Cache get error for key '{key}': {e}")
            return None

    async def set(self, key: str, value: Any, ttl: int = 3600) -> bool:
        """
        Set a value in cache.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds (default: 1 hour)

        Returns:
            True if successful
        """
        if not self.redis:
            return False

        try:
            serialized = json.dumps(value)
            await self.redis.set(key, serialized, ex=ttl)
            return True
        except Exception as e:
            logger.error(f"Cache set error for key '{key}': {e}")
            return False

    async def delete(self, key: str) -> bool:
        """Delete a key from cache."""
        if not self.redis:
            return False

        try:
            await self.redis.delete(key)
            return True
        except Exception as e:
            logger.error(f"Cache delete error for key '{key}': {e}")
            return False

    async def exists(self, key: str) -> bool:
        """Check if a key exists in cache."""
        if not self.redis:
            return False

        try:
            return await self.redis.exists(key) > 0
        except Exception as e:
            logger.error(f"Cache exists error for key '{key}': {e}")
            return False

    async def invalidate_pattern(self, pattern: str) -> int:
        """
        Invalidate all keys matching a pattern.

        Args:
            pattern: Redis key pattern (e.g., "scan:*")

        Returns:
            Number of keys deleted
        """
        if not self.redis:
            return 0

        try:
            keys = []
            async for key in self.redis.scan_iter(match=pattern):
                keys.append(key)

            if keys:
                return await self.redis.delete(*keys)
            return 0
        except Exception as e:
            logger.error(f"Cache invalidate pattern error for '{pattern}': {e}")
            return 0

    async def get_or_set(self, key: str, factory_func, ttl: int = 3600) -> Any:
        """
        Get from cache or compute and cache if not present.

        Args:
            key: Cache key
            factory_func: Async function to call if cache miss
            ttl: Time to live in seconds

        Returns:
            Cached or computed value
        """
        # Try to get from cache
        value = await self.get(key)
        if value is not None:
            return value

        # Cache miss - compute value
        value = await factory_func()

        # Cache the result
        await self.set(key, value, ttl=ttl)

        return value

    # Scan-specific caching methods

    async def cache_scan_result(self, scan_id: str, result: dict, ttl: int = 86400) -> bool:
        """Cache a scan result (24 hour default TTL)."""
        key = f"scan:result:{scan_id}"
        return await self.set(key, result, ttl=ttl)

    async def get_cached_scan_result(self, scan_id: str) -> dict | None:
        """Get cached scan result."""
        key = f"scan:result:{scan_id}"
        return await self.get(key)

    async def cache_user_session(self, session_id: str, user_data: dict, ttl: int = 3600) -> bool:
        """Cache user session data."""
        key = f"session:{session_id}"
        return await self.set(key, user_data, ttl=ttl)

    async def get_user_session(self, session_id: str) -> dict | None:
        """Get cached user session."""
        key = f"session:{session_id}"
        return await self.get(key)

    async def invalidate_user_session(self, session_id: str) -> bool:
        """Invalidate user session."""
        key = f"session:{session_id}"
        return await self.delete(key)


# Singleton instance
_cache_manager: CacheManager | None = None


async def init_cache(redis_url: str) -> CacheManager:
    """Initialize the global cache manager."""
    global _cache_manager
    _cache_manager = CacheManager(redis_url)
    await _cache_manager.connect()
    return _cache_manager


def get_cache_manager() -> CacheManager:
    """Get the global cache manager instance."""
    if _cache_manager is None:
        raise RuntimeError("Cache not initialized. Call init_cache() first.")
    return _cache_manager
