"""
Advanced HTTPClient with connection pooling, rate limiting, and robust retry mechanisms.
"""

import asyncio
import logging
import time
from typing import Any
from urllib.parse import urlparse

import aiohttp

from .config import NetworkConfig

logger = logging.getLogger(__name__)


def host_in_scope(url: str, target_host: str, extra_domains: list[str] | None = None) -> bool:
    """True when url's host is the scan target, or a host under an explicit scope domain."""
    host = urlparse(url).hostname
    if not host or not target_host:
        return False
    host = host.lower().rstrip(".")
    target_host = target_host.lower().rstrip(".")
    if host == target_host:
        return True
    for domain in extra_domains or []:
        domain = domain.lower().strip().lstrip("*").lstrip(".")
        if domain and (host == domain or host.endswith("." + domain)):
            return True
    return False


def detect_block_reason(status: int, headers: Any) -> str | None:
    """Return a human reason when a response is a WAF/bot challenge or hard block.

    Such a response is the protection layer's page, not the real application, so
    analyzing its body or headers yields misleading findings (e.g. "missing HSTS"
    on a challenge page). Callers use this to skip or flag unreliable results.
    """
    h = {str(k).lower(): str(v).lower() for k, v in dict(headers).items()}
    if "x-vercel-mitigated" in h or "x-vercel-challenge-token" in h:
        return "Vercel bot/attack challenge"
    if "cf-mitigated" in h or "x-cf-challenge" in h:
        return "Cloudflare challenge"
    if "x-datadome" in h or "x-datadome-cid" in h:
        return "DataDome challenge"
    if status == 429:
        return "rate limited (HTTP 429)"
    if status == 503 and ("cf-ray" in h or "cloudflare" in h.get("server", "")):
        return "Cloudflare challenge (HTTP 503)"
    return None


def response_reliability(response: Any) -> tuple[bool, str | None]:
    """Return (analyzable, reason) for a response.

    analyzable is False when the response is a WAF/bot challenge, an HTTP error
    status (>= 400), or missing. Content modules use this so they do not emit
    "missing header" / "absent content" findings about an error or challenge page
    that is not the real application.
    """
    if response is None:
        return False, "no response"
    status = getattr(response, "status", 0) or 0
    block = detect_block_reason(status, getattr(response, "headers", {}) or {})
    if block:
        return False, block
    if status >= 400:
        return False, f"HTTP {status}"
    return True, None


class RateLimiter:
    """Rate limiter for HTTP requests using a leaky bucket approach."""

    def __init__(self, requests_per_second: float):
        self.rate = requests_per_second
        self.interval = 1.0 / requests_per_second if requests_per_second > 0 else 0
        self.last_check = time.monotonic()
        self.lock = asyncio.Lock()

    async def wait(self):
        if self.interval <= 0:
            return

        async with self.lock:
            current = time.monotonic()
            elapsed = current - self.last_check
            if elapsed < self.interval:
                await asyncio.sleep(self.interval - elapsed)
            self.last_check = time.monotonic()


class HTTPClient:
    """HTTP client for asynchronous scanning. One session, one rate limit, one scope."""

    def __init__(self, config: NetworkConfig):
        self.config = config
        self.session: aiohttp.ClientSession | None = None
        self.rate_limiter = RateLimiter(config.rate_limit)
        self.request_count = 0
        self.error_count = 0
        self.stealth_mode = False
        self._scope_host: str | None = None
        self._scope_domains: list[str] = []
        self._blocked_hosts: set[str] = set()

        # Enhanced connection pooling with optimizations
        self.connector_settings = {
            "limit": 100,  # Increased total connection pool size
            "limit_per_host": 30,  # Increased per-host connections
            "ttl_dns_cache": 600,  # Longer DNS cache (10 minutes)
            "use_dns_cache": True,
            "enable_cleanup_closed": True,
            "force_close": False,  # Keep connections alive
            "keepalive_timeout": 30,  # Keep connections alive for 30s
            "ssl": self.config.verify_ssl,
        }

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    def bind_scope(self, target_url: str, extra_domains: list[str] | None = None) -> None:
        """Lock later requests to the target host, plus any extra domains the operator named."""
        host = urlparse(target_url).hostname
        if not host:
            raise ValueError(f"Target URL has no host: {target_url}")
        self._scope_host = host.lower().rstrip(".")
        self._scope_domains = list(extra_domains or [])
        self._blocked_hosts.clear()

    def enable_stealth(self):
        """Compatibility flag. Requests are not rewritten."""
        self.stealth_mode = True

    async def start(self):
        """Initialize the async session with optimized settings."""
        if self.session is None:
            connector = aiohttp.TCPConnector(**self.connector_settings)
            timeout = aiohttp.ClientTimeout(total=self.config.timeout)

            # Base headers - will be overridden per request in stealth mode
            headers = {
                "User-Agent": self.config.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Cache-Control": "no-cache",
                "DNT": "1",
            }

            self.session = aiohttp.ClientSession(
                connector=connector, timeout=timeout, headers=headers, raise_for_status=False
            )

    async def close(self):
        """Deep cleanup of connections."""
        if self.session:
            await self.session.close()
            # Grace period for underlying transport cleanup
            await asyncio.sleep(0.2)
            self.session = None

    async def request(self, method: str, url: str, **kwargs) -> aiohttp.ClientResponse | None:
        """
        Make a robust HTTP request with automatic retries, adaptive rate limiting, and evasion.
        """
        if self._scope_host and not host_in_scope(url, self._scope_host, self._scope_domains):
            blocked = urlparse(url).hostname or url
            if blocked not in self._blocked_hosts:
                logger.warning("Refusing off-scope request to %s", blocked)
                self._blocked_hosts.add(blocked)
            return None

        if self.session is None:
            await self.start()

        await self.rate_limiter.wait()

        kwargs.setdefault("allow_redirects", True)
        kwargs.setdefault("max_redirects", self.config.max_redirects)

        for attempt in range(self.config.max_retries + 1):
            try:
                self.request_count += 1
                async with self.session.request(method, url, **kwargs) as response:

                    # [ADAPTIVE THROTTLING] Check for WAF blocks or Rate Limits
                    if response.status in [429, 503]:
                        logger.warning(f"Target is throttling ({response.status}). Engaging cool-down.")
                        await asyncio.sleep(5 * (attempt + 1))  # Progressive cool-down
                        continue  # Retry

                    # We consume the response immediately to keep the connection clean
                    await response.read()
                    return response

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                self.error_count += 1
                logger.warning(
                    f"Request failed [{method} {url}] (Attempt {attempt+1}/{self.config.max_retries+1}): {e}"
                )

                if attempt < self.config.max_retries:
                    # Exponential backoff
                    wait_time = self.config.retry_delay * (2**attempt)
                    await asyncio.sleep(wait_time)
                else:
                    break

        logger.error(f"Request permanently failed for {url} after {self.config.max_retries + 1} attempts.")
        return None

    # Helper methods for cleaner API
    async def get(self, url: str, **kwargs) -> aiohttp.ClientResponse | None:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> aiohttp.ClientResponse | None:
        return await self.request("POST", url, **kwargs)

    async def head(self, url: str, **kwargs) -> aiohttp.ClientResponse | None:
        return await self.request("HEAD", url, **kwargs)

    async def get_stats(self) -> dict[str, Any]:
        """Compile client performance metrics."""
        success_rate = 0.0
        if self.request_count > 0:
            success_rate = ((self.request_count - self.error_count) / self.request_count) * 100

        return {
            "total_requests": self.request_count,
            "error_count": self.error_count,
            "success_rate": round(success_rate, 2),
            "stealth_active": self.stealth_mode,
        }
