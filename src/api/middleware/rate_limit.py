"""
Rate limiting middleware using token bucket algorithm.
"""

import asyncio
import time

from fastapi import HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware


class TokenBucket:
    """Token bucket for rate limiting."""

    def __init__(self, capacity: int, refill_rate: float):
        """
        Initialize token bucket.

        Args:
            capacity: Maximum number of tokens
            refill_rate: Tokens added per second
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_refill = time.time()
        self.lock = asyncio.Lock()

    async def consume(self, tokens: int = 1) -> bool:
        """
        Try to consume tokens.

        Args:
            tokens: Number of tokens to consume

        Returns:
            True if successful
        """
        async with self.lock:
            await self._refill()

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    async def _refill(self):
        """Refill tokens based on time elapsed."""
        now = time.time()
        elapsed = now - self.last_refill

        tokens_to_add = elapsed * self.refill_rate
        self.tokens = min(self.capacity, self.tokens + tokens_to_add)
        self.last_refill = now


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware."""

    def __init__(self, app, requests_per_minute: int = 60):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.buckets: dict[str, TokenBucket] = {}

    def _get_client_id(self, request: Request) -> str:
        """Get client identifier (IP address)."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0]
        return request.client.host if request.client else "unknown"

    def _get_bucket(self, client_id: str) -> TokenBucket:
        """Get or create token bucket for client."""
        if client_id not in self.buckets:
            # Create new bucket: 60 requests per minute = 1 request per second
            self.buckets[client_id] = TokenBucket(
                capacity=self.requests_per_minute, refill_rate=self.requests_per_minute / 60.0
            )
        return self.buckets[client_id]

    async def dispatch(self, request: Request, call_next):
        """Process request with rate limiting."""
        # Skip rate limiting for health checks and metrics
        if request.url.path in ["/health", "/ready", "/metrics"]:
            return await call_next(request)

        client_id = self._get_client_id(request)
        bucket = self._get_bucket(client_id)

        if not await bucket.consume():
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Please try again later.",
                headers={"Retry-After": "60"},
            )

        response = await call_next(request)

        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(self.requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(int(bucket.tokens))

        return response
