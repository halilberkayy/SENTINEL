"""
Advanced Directory and File Discovery module - ENHANCED
"""

import logging
from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin

from .base_scanner import BaseScanner, Vulnerability

logger = logging.getLogger(__name__)


class DirectoryScanner(BaseScanner):
    """High-performance directory brute-forcer with wordlist support."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "DirectoryScanner"
        self.description = "Directory and file enumeration with wordlist support"
        self.version = "3.1.0"
        self.author = "Antigravity AI"
        self.capabilities = [
            "Wordlist-based enumeration",
            "Sensitive file discovery",
            "Concurrent scanning",
            "Response fingerprinting",
        ]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform directory discovery using wordlist."""
        logger.info(f"Starting directory enumeration for {url}")
        vulnerabilities = []
        found_paths = []

        # Ensure URL ends with / for correct joining
        if not url.endswith("/"):
            url += "/"

        try:
            self._update_progress(progress_callback, 5, "Loading directory wordlist")

            # Load from wordlist file - using new base_scanner method
            paths = self._load_wordlist("directories")[:200]  # Limit for reasonable scan time

            total = len(paths)
            self._update_progress(progress_callback, 10, f"Scanning {total} paths")

            # Prepare concurrent tasks
            tasks = []
            for path in paths:
                tasks.append(self._check_path(url, path))

            # Run concurrently with semaphore
            results = await self._concurrent_task_runner(tasks, concurrency_limit=15)

            # Process results
            for res in results:
                if res and isinstance(res, dict):  # Filter out exceptions
                    found_paths.append(res)
                    if self._is_vulnerability(res):
                        vulnerabilities.append(self._create_path_vulnerability(res))

            self._update_progress(progress_callback, 100, "completed")

            status = "Vulnerable" if vulnerabilities else "Clean"
            details = f"Discovered {len(found_paths)} accessible paths, {len(vulnerabilities)} sensitive."
            return self._format_result(
                status, details, vulnerabilities, {"found_paths": found_paths[:50]}
            )  # Limit evidence

        except Exception as e:
            logger.exception(f"Directory scan failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])

    async def _check_path(self, base_url: str, path: str) -> dict | None:
        """Check a single path and return metadata if accessible."""
        target_url = urljoin(base_url, path.lstrip("/"))
        try:
            # Use HEAD first for efficiency
            response = await self.http_client.head(target_url)

            # Fallback to GET if HEAD fails
            if not response or response.status >= 400:
                if response and response.status in [403, 405]:  # Some servers block HEAD
                    response = await self.http_client.get(target_url)
                else:
                    return None

            if response and response.status < 400:
                return {
                    "path": path,
                    "url": str(response.url),
                    "status": response.status,
                    "size": response.content_length or 0,
                    "type": response.headers.get("Content-Type", "unknown"),
                }
        except Exception as e:
            logger.debug(f"Path check failed for {path}: {e}")

        return None

    def _is_vulnerability(self, res: dict) -> bool:
        """Determine if a found path is a security risk."""
        path = res["path"].lower()

        # Critical secrets
        critical_patterns = [".env", ".git", ".svn", ".hg", ".sql", "wp-config", "database"]

        # Sensitive patterns
        sensitive_patterns = ["config", "setup", "install", ".bak", "backup", "old", "phpinfo"]

        # Admin patterns
        admin_patterns = ["admin", "administrator", "manager", "dashboard", "control"]

        # Check criticality
        if any(s in path for s in critical_patterns):
            return True

        # Check other patterns
        if any(s in path for s in sensitive_patterns + admin_patterns):
            return True

        return False

    def _create_path_vulnerability(self, res: dict) -> Vulnerability:
        """Create a vulnerability report for a sensitive path."""
        path = res["path"].lower()

        # Determine severity
        if any(x in path for x in [".env", ".git", ".sql", "database", "wp-config"]):
            severity = "critical"
            cvss = 9.0
        elif any(x in path for x in ["config", "backup", ".bak"]):
            severity = "high"
            cvss = 7.5
        elif any(x in path for x in ["admin", "setup", "install"]):
            severity = "medium"
            cvss = 5.0
        else:
            severity = "low"
            cvss = 3.0

        return self._create_vulnerability(
            title=f"Sensitive Resource Exposed: {res['path']}",
            description=f"A potentially sensitive resource was found at {res['path']} with status {res['status']}. Size: {res['size']} bytes.",
            severity=severity,
            type="information_disclosure",
            evidence=res,
            cwe_id="CWE-200",
            cvss_score=cvss,
            remediation="Restrict access to this path using web server configuration (.htaccess, nginx.conf) or move it outside the web root. Remove if not needed.",
            references=["https://owasp.org/www-community/attacks/Forced_browsing"],
        )
