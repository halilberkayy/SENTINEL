"""
Advanced HTTPClient with connection pooling, rate limiting, and robust retry mechanisms.
"""

import asyncio
import logging
import time
from typing import Any

import aiohttp

from .config import NetworkConfig

logger = logging.getLogger(__name__)


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


import random


class HTTPClient:
    """Professional HTTP client for asynchronous security scanning."""

    # Red Team Evasion - User Agent Pool
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    ]

    def __init__(self, config: NetworkConfig):
        self.config = config
        self.session: aiohttp.ClientSession | None = None
        self.rate_limiter = RateLimiter(config.rate_limit)
        self.request_count = 0
        self.error_count = 0
        self.stealth_mode = False  # Covering Tracks Mode

        # Enhanced connection pooling
        self.connector_settings = {
            "limit": 50,
            "limit_per_host": 10,
            "ttl_dns_cache": 300,
            "use_dns_cache": True,
            "enable_cleanup_closed": True,
            "ssl": self.config.verify_ssl,
        }

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    def enable_stealth(self):
        """Enable Covering Tracks / Evasion mode."""
        self.stealth_mode = True
        logger.info("[EVASION] Stealth mode engaged: UA Rotation & Header Spoofing active.")

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
        if self.session is None:
            await self.start()

        await self.rate_limiter.wait()

        # Standardize request arguments
        kwargs.setdefault("allow_redirects", True)
        kwargs.setdefault("max_redirects", self.config.max_redirects)

        # [COVERING TRACKS] - Stealth/Evasion Logic
        if self.stealth_mode:
            # Dynamic Headers per request to confuse WAF/Logs
            headers = kwargs.get("headers", {}).copy()
            headers["User-Agent"] = random.choice(self.USER_AGENTS)

            # IP Spoofing Headers
            fake_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            headers.update(
                {
                    "X-Forwarded-For": fake_ip,
                    "X-Originating-IP": fake_ip,
                    "X-Remote-IP": fake_ip,
                    "X-Client-IP": fake_ip,
                }
            )

            # Header Order Randomization (Python 3.7+ dicts preserve order, so we rebuild)
            keys = list(headers.keys())
            random.shuffle(keys)
            randomized_headers = {k: headers[k] for k in keys}
            kwargs["headers"] = randomized_headers

            # Jitter - Randomized delay
            jitter = random.uniform(0.1, 1.5)
            await asyncio.sleep(jitter)

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
