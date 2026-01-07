"""
Subdomain enumeration and analysis module - ENHANCED VERSION
"""

import asyncio
import logging
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class SubdomainScanner(BaseScanner):
    """Professional subdomain enumeration engine with wordlist support."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "SubdomainScanner"
        self.description = "Identifies subdomains and associated risks"
        self.version = "2.0.0"
        self.capabilities = ["DNS Enumeration", "Wordlist-based Discovery", "Concurrent Resolution"]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform subdomain enumeration."""
        logger.info(f"Enumerating subdomains for {url}")
        vulnerabilities = []
        found_subdomains = []

        parsed = urlparse(url)
        domain = parsed.netloc
        if not domain:
            domain = parsed.path.split("/")[0]

        # Extract base domain
        parts = domain.split(".")
        if len(parts) > 2:
            base_domain = ".".join(parts[-2:])
        else:
            base_domain = domain

        try:
            self._update_progress(progress_callback, 10, f"Loading subdomain wordlist for {base_domain}")

            # Load from wordlist file - now using enhanced base_scanner method
            subs = self._load_wordlist("subdomains")[:150]  # Increased limit

            self._update_progress(progress_callback, 20, "Starting concurrent DNS resolution")

            # Use semaphore to limit concurrent DNS queries (prevents overwhelming)
            semaphore = asyncio.Semaphore(30)

            async def check_subdomain(sub):
                async with semaphore:
                    target_sub = f"{sub}.{base_domain}"
                    ip = await self._resolve_dns(target_sub)
                    if ip:
                        return {"subdomain": target_sub, "ip": ip}
                    return None

            # Check all subdomains concurrently for speed
            tasks = [check_subdomain(sub) for sub in subs]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Filter out None and exceptions
            found_subdomains = [r for r in results if r is not None and not isinstance(r, Exception)]

            self._update_progress(progress_callback, 100, "completed")

            if found_subdomains:
                vulnerabilities.append(
                    self._create_vulnerability(
                        title="Subdomains Discovered",
                        description=f"Identified {len(found_subdomains)} active subdomains. This expands the attack surface.",
                        severity="info",
                        type="recon",
                        evidence={
                            "subdomains": found_subdomains[:20],  # Limit evidence size
                            "count": len(found_subdomains),
                            "base_domain": base_domain,
                        },
                        remediation="Maintain an inventory of all public subdomains. Ensure unused subdomains are decommissioned and all active subdomains are properly secured.",
                    )
                )

            status = "Clean"
            return self._format_result(status, f"Identified {len(found_subdomains)} subdomains.", vulnerabilities)

        except Exception as e:
            logger.exception(f"Subdomain scan failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])

    async def _resolve_dns(self, hostname: str) -> str | None:
        """Async DNS resolution with timeout."""
        try:
            loop = asyncio.get_event_loop()
            addr_info = await asyncio.wait_for(
                loop.getaddrinfo(hostname, None), timeout=2.0  # 2 second timeout per DNS query
            )
            return addr_info[0][4][0]
        except asyncio.TimeoutError:
            logger.debug(f"DNS timeout for {hostname}")
            return None
        except Exception as e:
            logger.debug(f"DNS resolution failed for {hostname}: {e}")
            return None
