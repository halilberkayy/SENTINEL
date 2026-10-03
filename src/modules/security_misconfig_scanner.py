"""
Security Misconfiguration scanner module.
"""

import logging
from collections.abc import Callable
from typing import Any

from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class SecurityMisconfigScanner(BaseScanner):
    """Engine for identifying general security misconfigurations."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "SecurityMisconfigScanner"
        self.description = "Identifies debug modes, version leaks, and default configurations"
        self.version = "1.0.0"
        self.capabilities = ["Fingerprinting", "Error analysis", "Default path checking"]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform misconfiguration scan."""
        logger.info(f"Scanning {url} for Security Misconfigurations")
        vulnerabilities = []

        checks = [
            {"path": "/.env", "pattern": "DB_PASSWORD", "title": "Exposed Environment File", "severity": "critical"},
            {"path": "/phpinfo.php", "pattern": "PHP Version", "title": "PHPInfo Page Exposed", "severity": "medium"},
            {
                "path": "/server-status",
                "pattern": "Apache Status",
                "title": "Apache Server Status Exposed",
                "severity": "medium",
            },
            {
                "path": "/ssh/id_rsa",
                "pattern": "PRIVATE KEY",
                "title": "Exposed SSH Private Key",
                "severity": "critical",
            },
            {"path": "/.git/config", "pattern": "[core]", "title": "Git Repository Exposed", "severity": "high"},
            {
                "path": "/wp-config.php.bak",
                "pattern": "DB_NAME",
                "title": "Database Config Backup Exposed",
                "severity": "critical",
            },
        ]

        try:
            self._update_progress(progress_callback, 10, "Checking for sensitive files and debug info")

            total_checks = len(checks)
            for idx, check in enumerate(checks):
                self._update_progress(
                    progress_callback, 10 + int((idx / total_checks) * 80), f"Checking {check['path']}"
                )

                target_url = self._build_url(url, check["path"])
                res = await self.http_client.get(target_url)
                res_dict = await self._response_to_dict(res)

                if res_dict.get("status_code") == 200 and check["pattern"] in res_dict.get("page_content", ""):
                    vulnerabilities.append(
                        self._create_vulnerability(
                            title=check["title"],
                            description=f"Sensitive information or debug interface found at {check['path']}.",
                            severity=check["severity"],
                            type="misconfig",
                            evidence={
                                "url": target_url,
                                "snippet": (res_dict.get("page_content", "") or "")[
                                    :500
                                ],  # Capture first 500 chars for analysis
                            },
                            remediation="Remove the sensitive file or restrict access via server configuration.",
                        )
                    )

            # Header fingerprinting for version leaks
            self._update_progress(progress_callback, 95, "Analyzing server headers for version leaks")
            main_resp = await self.http_client.get(url)
            main_resp_dict = await self._response_to_dict(main_resp)
            headers = main_resp_dict.get("headers", {})

            # Check Server and X-Powered-By
            for hname in ["Server", "X-Powered-By", "X-AspNet-Version"]:
                val = headers.get(hname, "")
                if val and any(char.isdigit() for char in val):
                    vulnerabilities.append(
                        self._create_vulnerability(
                            title="Server Information Leakage",
                            description=f"The header '{hname}' leaks software version information: {val}",
                            severity="low",
                            type="info",
                            evidence={"header": hname, "value": val},
                            remediation="Configure the server to hide version information in response headers.",
                        )
                    )

            self._update_progress(progress_callback, 100, "completed")

            status = "Vulnerable" if vulnerabilities else "Clean"
            return self._format_result(status, f"Found {len(vulnerabilities)} misconfigurations.", vulnerabilities)

        except Exception as e:
            logger.exception(f"Security Misconfig scan failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])

    def _build_url(self, base: str, path: str) -> str:
        from urllib.parse import urljoin, urlparse

        parsed = urlparse(base)
        root = f"{parsed.scheme}://{parsed.netloc}"
        return urljoin(root, path)
