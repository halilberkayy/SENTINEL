"""
Tests for rate limiting middleware including brute-force protection.
"""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.api.middleware.rate_limit import (
    AUTH_ENDPOINTS,
    AuthBruteForceTracker,
    RateLimitMiddleware,
    TokenBucket,
    get_brute_force_tracker,
)


class TestTokenBucket:
    """Test token bucket algorithm."""

    @pytest.mark.asyncio
    async def test_initial_capacity(self):
        bucket = TokenBucket(capacity=10, refill_rate=1.0)
        assert bucket.capacity == 10
        assert bucket.tokens == 10

    @pytest.mark.asyncio
    async def test_consume_reduces_tokens(self):
        bucket = TokenBucket(capacity=10, refill_rate=1.0)
        result = await bucket.consume(1)
        assert result is True
        assert bucket.tokens < 10

    @pytest.mark.asyncio
    async def test_consume_fails_when_empty(self):
        bucket = TokenBucket(capacity=1, refill_rate=0.001)
        await bucket.consume(1)
        result = await bucket.consume(1)
        assert result is False

    @pytest.mark.asyncio
    async def test_refill_over_time(self):
        bucket = TokenBucket(capacity=10, refill_rate=100.0)  # Very fast refill
        await bucket.consume(5)
        await asyncio.sleep(0.1)
        result = await bucket.consume(1)
        assert result is True

    def test_remaining_property(self):
        bucket = TokenBucket(capacity=10, refill_rate=1.0)
        assert bucket.remaining == 10

    def test_reset_time_when_full(self):
        bucket = TokenBucket(capacity=10, refill_rate=1.0)
        assert bucket.reset_time == 0


class TestAuthBruteForceTracker:
    """Test brute-force protection tracker."""

    @pytest.mark.asyncio
    async def test_no_lockout_below_threshold(self):
        tracker = AuthBruteForceTracker()
        for _ in range(4):  # Below 5 threshold
            await tracker.record_failure("ip1")
        locked, _ = await tracker.is_locked_out("ip1")
        assert not locked

    @pytest.mark.asyncio
    async def test_lockout_at_threshold(self):
        tracker = AuthBruteForceTracker()
        for _ in range(5):
            await tracker.record_failure("ip2")
        locked, retry = await tracker.is_locked_out("ip2")
        assert locked
        assert retry > 0

    @pytest.mark.asyncio
    async def test_progressive_lockout(self):
        tracker = AuthBruteForceTracker()
        # 10 failures should get longer lockout than 5
        for _ in range(10):
            await tracker.record_failure("ip3")
        locked, retry_10 = await tracker.is_locked_out("ip3")
        assert locked
        assert retry_10 >= 300  # 5 minutes

    @pytest.mark.asyncio
    async def test_clear_resets_everything(self):
        tracker = AuthBruteForceTracker()
        for _ in range(10):
            await tracker.record_failure("ip4")
        await tracker.clear("ip4")
        count = await tracker.get_failure_count("ip4")
        assert count == 0
        locked, _ = await tracker.is_locked_out("ip4")
        assert not locked

    @pytest.mark.asyncio
    async def test_separate_clients_tracked_independently(self):
        tracker = AuthBruteForceTracker()
        for _ in range(5):
            await tracker.record_failure("ip5")
        locked_ip5, _ = await tracker.is_locked_out("ip5")
        locked_ip6, _ = await tracker.is_locked_out("ip6")
        assert locked_ip5
        assert not locked_ip6


class TestRateLimitMiddleware:
    """Test rate limit middleware configuration."""

    def test_auth_endpoints_defined(self):
        assert "/api/v1/auth/login" in AUTH_ENDPOINTS
        assert "/api/v1/auth/register" in AUTH_ENDPOINTS

    def test_auth_rate_limit_stricter(self):
        middleware = RateLimitMiddleware(app=MagicMock())
        assert middleware.AUTH_RATE_LIMIT < middleware.requests_per_minute

    def test_is_auth_endpoint(self):
        middleware = RateLimitMiddleware(app=MagicMock())
        assert middleware._is_auth_endpoint("/api/v1/auth/login")
        assert middleware._is_auth_endpoint("/api/v1/auth/register")
        assert not middleware._is_auth_endpoint("/api/v1/scans")
        assert not middleware._is_auth_endpoint("/health")

    def test_get_client_id_from_direct(self):
        middleware = RateLimitMiddleware(app=MagicMock())
        request = MagicMock()
        request.headers = {}
        request.client.host = "192.168.1.1"
        assert middleware._get_client_id(request) == "192.168.1.1"

    def test_get_client_id_from_forwarded(self):
        middleware = RateLimitMiddleware(app=MagicMock())
        request = MagicMock()
        request.headers = {"X-Forwarded-For": "10.0.0.1, 192.168.1.1"}
        with patch.dict("os.environ", {"TRUST_PROXY": "1"}):
            assert middleware._get_client_id(request) == "10.0.0.1"

    def test_separate_buckets_for_auth(self):
        middleware = RateLimitMiddleware(app=MagicMock())
        general_bucket = middleware._get_bucket("client1", is_auth=False)
        auth_bucket = middleware._get_bucket("client1", is_auth=True)
        assert general_bucket.capacity == middleware.requests_per_minute
        assert auth_bucket.capacity == middleware.AUTH_RATE_LIMIT
