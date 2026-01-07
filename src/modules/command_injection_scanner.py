"""
Command Injection vulnerability scanner module.
"""

import logging
import re
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse

from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class CommandInjectionScanner(BaseScanner):
    """Professional Command Injection assessment engine."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "CommandInjectionScanner"
        self.description = "OS Command Injection and Template Injection detector"
        self.version = "3.1.0"
        self.capabilities = ["OS Injection", "Time-based Blind Injection", "SSTI Detection"]

        self._init_payloads()
        self._init_patterns()

    def _init_payloads(self):
        # Basic payloads for various platforms
        self.payload_templates = [
            ";id",
            "&id",
            "|id",
            "`id`",
            "$(id)",
            ";whoami",
            "&whoami",
            "|whoami",
            "`whoami`",
            "$(whoami)",
            ";sleep 5",
            "&sleep 5",
            "|sleep 5",
            "`sleep 5`",
            "$(sleep 5)",
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",  # Simple SSTI
        ]

    def _init_patterns(self):
        self.detection_patterns = {
            "linux_id": r"uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)",
            "whoami": r"root|www-data|apache|nginx|[a-z0-9_-]+\\[a-z0-9_-]+",
            "ssti": r"49",
        }

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform command injection assessment."""
        logger.info(f"Analyzing command injection for {url}")
        vulnerabilities = []

        try:
            self._update_progress(progress_callback, 10, "Extracting test points")
            test_points = await self._get_test_points(url)

            if not test_points:
                return self._format_result("Clean", "No injectable parameters found", [])

            total_tests = len(test_points) * len(self.payload_templates)
            processed = 0

            for tp in test_points:
                for payload in self.payload_templates:
                    processed += 1
                    self._update_progress(
                        progress_callback,
                        10 + int((processed / total_tests) * 80),
                        f"Testing {tp['name']} with {payload}",
                    )

                    # Test logic
                    start_time = time.monotonic()
                    test_url = self._inject_payload(tp, payload)
                    response = await self.http_client.get(test_url)
                    duration = time.monotonic() - start_time

                    if not response:
                        continue
                    content = await response.text()

                    # 1. Output-based check
                    for name, pattern in self.detection_patterns.items():
                        if re.search(pattern, content, re.I):
                            vulnerabilities.append(
                                self._create_vulnerability(
                                    title=f"Command Injection Detected: {name.upper()}",
                                    description=f"The application appears to execute shell commands. Output matched pattern: {name}",
                                    severity="critical",
                                    type="cmd_injection",
                                    evidence={"parameter": tp["name"], "payload": payload, "match": name},
                                    cwe_id="CWE-78",
                                    remediation="Use safe APIs that do not involve the shell. Validate and sanitize all user input.",
                                )
                            )
                            break  # Move to next TP

                    # 2. Time-based check
                    if "sleep" in payload and duration >= 4.5:
                        vulnerabilities.append(
                            self._create_vulnerability(
                                title="Blind Command Injection (Time-based)",
                                description="The application response was delayed significantly when a sleep command was injected.",
                                severity="critical",
                                type="blind_cmd_injection",
                                evidence={"parameter": tp["name"], "payload": payload, "delay": duration},
                                cwe_id="CWE-78",
                                remediation="Implement strict input validation and avoid passing user input to system shells.",
                            )
                        )
                        break  # Move to next TP

            self._update_progress(progress_callback, 100, "completed")
            status = "Vulnerable" if vulnerabilities else "Clean"
            return self._format_result(
                status, f"Tested {len(test_points)} parameters. Found {len(vulnerabilities)} issues.", vulnerabilities
            )

        except Exception as e:
            logger.exception(f"Command Injection scan failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])

    async def _get_test_points(self, url: str) -> list[dict[str, Any]]:
        """Identify injectable parameters and form fields."""
        points = []
        parsed = urlparse(url)
        params = parse_qsl(parsed.query)
        for name, _ in params:
            points.append({"name": name, "type": "query", "url": url})

        # Add basic crawl or form detection here if needed
        return points

    def _inject_payload(self, tp: dict[str, Any], payload: str) -> str:
        """Construct the URL with the payload."""
        parsed = urlparse(tp["url"])
        params = dict(parse_qsl(parsed.query))
        params[tp["name"]] = payload
        query = urlencode(params)
        return parsed._replace(query=query).geturl()
