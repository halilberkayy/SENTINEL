"""
Server-Side Includes (SSI) Injection scanner module.
"""

import logging
from collections.abc import Callable
from typing import Any

from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class SSIScanner(BaseScanner):
    """Modern SSI Injection detection engine."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "SSIScanner"
        self.description = "Detects Server-Side Includes (SSI) vulnerabilities"
        self.version = "1.0.0"
        self.capabilities = ["Reflection detection", "Direct manipulation", "Error analysis"]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform SSI scan."""
        logger.info(f"Scanning {url} for SSI Injection")
        vulnerabilities = []

        # Payloads targeting various SSI-enabled backends (Apache/Nginx mod_ssi, etc)
        payloads = [
            '<!--#exec cmd="id"-->',
            '<!--#exec cmd="whoami" -->',
            '<!--#config errmsg="[SSI_INJECTION_SUCCESS]"-->',
            '<!--#echo var="DATE_LOCAL" -->',
            '<!--#include virtual="/etc/passwd" -->',
        ]

        try:
            self._update_progress(progress_callback, 10, "Extracting forms and parameters")
            params = await self._discover_parameters(url)

            total_tasks = len(params) * len(payloads)
            processed = 0

            for param in params:
                for payload in payloads:
                    processed += 1
                    self._update_progress(
                        progress_callback, 10 + int((processed / total_tasks) * 85), f"Testing {param} with SSI payload"
                    )

                    # Test both GET and POST
                    for method in ["GET", "POST"]:
                        result = await self._test_payload(url, param, payload, method)
                        if self._is_vulnerable(result):
                            vulnerabilities.append(
                                self._create_vulnerability(
                                    title="Server-Side Includes (SSI) Injection",
                                    description=f"The application appears to be vulnerable to SSI injection at {param} via {method}.",
                                    severity="critical",
                                    type="injection",
                                    evidence={"param": param, "method": method, "payload": payload},
                                    remediation="Disable Server-Side Includes if not required. If required, sanitize user input to prevent inclusion of SSI directives.",
                                )
                            )
                            break  # Move to next param

            self._update_progress(progress_callback, 100, "completed")

            status = "Vulnerable" if vulnerabilities else "Clean"
            return self._format_result(status, f"Found {len(vulnerabilities)} SSI vulnerabilities.", vulnerabilities)

        except Exception as e:
            logger.exception(f"SSI scan failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])

    def _is_vulnerable(self, response) -> bool:
        """Check for SSI successful execution indicators."""
        if not response or not response.get("page_content"):
            return False

        content = response["page_content"]
        indicators = [
            "uid=",
            "gid=",
            "groups=",  # result of id
            "root:x:",
            "bin:x:",  # result of passwd
            "[SSI_INJECTION_SUCCESS]",
            "1970",
            "2025",
            "GMT",
            "UTC",  # indicators for date/config
        ]
        return any(ind in content for ind in indicators)
