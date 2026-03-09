"""
Rate limiting middleware using token bucket algorithm.

Includes enhanced brute-force protection for authentication endpoints
with progressive delays and account lockout.
"""

import asyncio
import logging
import time
from collections import defaultdict

from fastapi import HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

# Auth endpoints that need stricter rate limiting
AUTH_ENDPOINTS = {
    "/api/v1/auth/login",
    "/api/v1/auth/register",
    "/api/v1/auth/token",
    "/api/v1/auth/refresh",
    "/api/v1/auth/reset-password",
}

# Endpoints exempt from rate limiting
EXEMPT_ENDPOINTS = {"/health", "/ready", "/metrics"}


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

    @property
    def remaining(self) -> int:
        """Get remaining tokens (approximate, without lock)."""
        return max(0, int(self.tokens))

    @property
    def reset_time(self) -> int:
        """Seconds until bucket is fully refilled."""
        deficit = self.capacity - self.tokens
        if deficit <= 0:
            return 0
        return int(deficit / self.refill_rate) + 1


class AuthBruteForceTracker:
    """
    Tracks failed authentication attempts per IP and implements progressive penalties.

    Thresholds:
    - 5 failed attempts in 15 min: 30 second delay
    - 10 failed attempts in 15 min: 5 minute lockout
    - 20 failed attempts in 15 min: 30 minute lockout
    """

    WINDOW_SECONDS = 900  # 15 minutes
    THRESHOLDS = [
        (5, 30),      # 5 failures -> 30s delay
        (10, 300),     # 10 failures -> 5min lockout
        (20, 1800),    # 20 failures -> 30min lockout
    ]

    def __init__(self):
        # client_id -> list of failure timestamps
        self._failures: dict[str, list[float]] = defaultdict(list)
        # client_id -> lockout expiry timestamp
        self._lockouts: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def record_failure(self, client_id: str) -> None:
        """Record a failed authentication attempt."""
        async with self._lock:
            now = time.time()
            self._failures[client_id].append(now)
            # Prune old entries
            cutoff = now - self.WINDOW_SECONDS
            self._failures[client_id] = [
                t for t in self._failures[client_id] if t > cutoff
            ]
            # Check thresholds and apply lockout
            failure_count = len(self._failures[client_id])
            for threshold, penalty_seconds in reversed(self.THRESHOLDS):
                if failure_count >= threshold:
                    self._lockouts[client_id] = now + penalty_seconds
                    logger.warning(
                        "Auth brute-force protection activated",
                        extra={
                            "client_id": client_id,
                            "failures": failure_count,
                            "lockout_seconds": penalty_seconds,
                        },
                    )
                    break

    async def is_locked_out(self, client_id: str) -> tuple[bool, int]:
        """
        Check if a client is locked out.

        Returns:
            Tuple of (is_locked, seconds_remaining)
        """
        async with self._lock:
            expiry = self._lockouts.get(client_id, 0)
            now = time.time()
            if now < expiry:
                return True, int(expiry - now) + 1
            # Expired lockout, clean up
            self._lockouts.pop(client_id, None)
            return False, 0

    async def clear(self, client_id: str) -> None:
        """Clear failure history for a client (call on successful login)."""
        async with self._lock:
            self._failures.pop(client_id, None)
            self._lockouts.pop(client_id, None)

    async def get_failure_count(self, client_id: str) -> int:
        """Get current failure count within window."""
        async with self._lock:
            now = time.time()
            cutoff = now - self.WINDOW_SECONDS
            self._failures[client_id] = [
                t for t in self._failures[client_id] if t > cutoff
            ]
            return len(self._failures[client_id])


# Global brute-force tracker singleton
_brute_force_tracker: AuthBruteForceTracker | None = None


def get_brute_force_tracker() -> AuthBruteForceTracker:
    """Get or create the global brute-force tracker."""
    global _brute_force_tracker
    if _brute_force_tracker is None:
        _brute_force_tracker = AuthBruteForceTracker()
    return _brute_force_tracker


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware with enhanced auth endpoint protection.

    General endpoints: 60 requests/minute per IP (configurable).
    Auth endpoints: 10 requests/minute per IP + brute-force tracking.
    """

    # Auth endpoints get stricter limits
    AUTH_RATE_LIMIT = 10  # requests per minute for auth endpoints

    def __init__(self, app, requests_per_minute: int = 60):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.buckets: dict[str, TokenBucket] = {}
        self.auth_buckets: dict[str, TokenBucket] = {}
        self.brute_force = get_brute_force_tracker()

    def _get_client_id(self, request: Request) -> str:
        """Get client identifier (IP address).

        SECURITY: X-Forwarded-For is only trusted when behind a known reverse proxy.
        When directly exposed, attackers can spoof this header to bypass rate limiting.
        Default to request.client.host which is the TCP peer address.
        Set TRUST_PROXY=1 in production behind a reverse proxy.
        """
        import os

        if os.getenv("TRUST_PROXY"):
            forwarded = request.headers.get("X-Forwarded-For")
            if forwarded:
                return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def _get_bucket(self, client_id: str, is_auth: bool = False) -> TokenBucket:
        """Get or create token bucket for client."""
        if is_auth:
            if client_id not in self.auth_buckets:
                self.auth_buckets[client_id] = TokenBucket(
                    capacity=self.AUTH_RATE_LIMIT,
                    refill_rate=self.AUTH_RATE_LIMIT / 60.0,
                )
            return self.auth_buckets[client_id]

        if client_id not in self.buckets:
            self.buckets[client_id] = TokenBucket(
                capacity=self.requests_per_minute,
                refill_rate=self.requests_per_minute / 60.0,
            )
        return self.buckets[client_id]

    def _is_auth_endpoint(self, path: str) -> bool:
        """Check if the request path is an authentication endpoint."""
        return any(path.startswith(ep) for ep in AUTH_ENDPOINTS)

    async def dispatch(self, request: Request, call_next):
        """Process request with rate limiting."""
        path = request.url.path

        # Skip rate limiting for health checks and metrics
        if path in EXEMPT_ENDPOINTS:
            return await call_next(request)

        client_id = self._get_client_id(request)
        is_auth = self._is_auth_endpoint(path)

        # Check brute-force lockout for auth endpoints
        if is_auth:
            is_locked, retry_after = await self.brute_force.is_locked_out(client_id)
            if is_locked:
                logger.warning(
                    "Auth request blocked by brute-force protection",
                    extra={"client_id": client_id, "retry_after": retry_after},
                )
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={
                        "detail": "Too many failed attempts. Account temporarily locked.",
                        "retry_after": retry_after,
                    },
                    headers={
                        "Retry-After": str(retry_after),
                        "X-RateLimit-Limit": str(self.AUTH_RATE_LIMIT),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(int(time.time()) + retry_after),
                    },
                )

        # Apply rate limiting (stricter for auth endpoints)
        bucket = self._get_bucket(client_id, is_auth=is_auth)

        if not await bucket.consume():
            limit = self.AUTH_RATE_LIMIT if is_auth else self.requests_per_minute
            retry_after = bucket.reset_time
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Rate limit exceeded. Please try again later.",
                    "retry_after": retry_after,
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(time.time()) + retry_after),
                },
            )

        # Process the request
        response = await call_next(request)

        # Track failed auth attempts (401 on auth endpoints = failed login)
        if is_auth and response.status_code == status.HTTP_401_UNAUTHORIZED:
            await self.brute_force.record_failure(client_id)
        elif is_auth and response.status_code == 200:
            # Successful auth clears failure history
            await self.brute_force.clear(client_id)

        # Add rate limit headers to all responses
        limit = self.AUTH_RATE_LIMIT if is_auth else self.requests_per_minute
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(bucket.remaining)
        response.headers["X-RateLimit-Reset"] = str(
            int(time.time()) + bucket.reset_time
        )

        return response
