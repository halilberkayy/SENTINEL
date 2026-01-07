"""
SSE (Server-Sent Events) Scanner - Real-time streaming endpoint security.
"""

import asyncio
import logging
from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin, urlparse

from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class SSEScanner(BaseScanner):
    """Server-Sent Events security scanner."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "SSEScanner"
        self.description = "Server-Sent Events endpoint security analysis"
        self.version = "1.0.0"
        self.capabilities = ["SSE Detection", "Data Leak Analysis", "Auth Check"]

        self.sse_endpoints = [
            "/events",
            "/sse",
            "/stream",
            "/api/events",
            "/api/stream",
            "/realtime",
            "/live",
            "/push",
            "/notifications",
            "/updates",
        ]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Scan for SSE endpoints and vulnerabilities."""
        self._update_progress(progress_callback, 10, "Detecting SSE endpoints")
        vulnerabilities = []
        found_endpoints = []

        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # Check known SSE paths
            for endpoint in self.sse_endpoints:
                test_url = urljoin(base_url, endpoint)
                result = await self._check_sse_endpoint(test_url)

                if result:
                    found_endpoints.append(result)

                    # Check for auth issues
                    if result.get("no_auth"):
                        vulnerabilities.append(
                            self._create_vulnerability(
                                title=f"Unauthenticated SSE Endpoint: {endpoint}",
                                description="SSE endpoint accessible without authentication, may leak real-time data.",
                                severity="high",
                                type="broken_access_control",
                                evidence=result,
                                cwe_id="CWE-306",
                            )
                        )

                    # Check for sensitive data
                    if result.get("sensitive_data"):
                        vulnerabilities.append(
                            self._create_vulnerability(
                                title=f"Sensitive Data in SSE Stream: {endpoint}",
                                description="SSE stream contains potentially sensitive information.",
                                severity="high",
                                type="information_disclosure",
                                evidence=result,
                                cwe_id="CWE-200",
                            )
                        )

            self._update_progress(progress_callback, 100, "completed")

            return self._format_result(
                "Vulnerable" if vulnerabilities else "Clean",
                f"Found {len(found_endpoints)} SSE endpoints",
                vulnerabilities,
                {"endpoints": found_endpoints},
            )

        except Exception as e:
            return self._format_result("Error", str(e), [])

    async def _check_sse_endpoint(self, url: str) -> dict | None:
        """Check if URL is an SSE endpoint."""
        try:
            headers = {"Accept": "text/event-stream"}
            response = await self.http_client.get(url, headers=headers)

            if not response:
                return None

            content_type = response.headers.get("Content-Type", "")

            if "text/event-stream" in content_type or response.status == 200:
                # Try to read some data
                try:
                    data = await asyncio.wait_for(response.text(), timeout=3)
                except asyncio.TimeoutError:
                    data = "[streaming]"

                result = {
                    "url": url,
                    "status": response.status,
                    "content_type": content_type,
                    "sample_data": data[:500] if data else "",
                    "is_sse": "text/event-stream" in content_type,
                }

                # Check if no auth required
                result["no_auth"] = response.status == 200

                # Check for sensitive patterns
                sensitive_patterns = ["password", "token", "secret", "key", "email", "user"]
                if data and any(p in data.lower() for p in sensitive_patterns):
                    result["sensitive_data"] = True

                return result

        except Exception as e:
            logger.debug(f"SSE check failed for {url}: {e}")

        return None
