"""
Robots.txt analysis module for information disclosure and crawl directive evaluation.
"""

import logging
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin

from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class RobotsTxtScanner(BaseScanner):
    """Professional Robots.txt evaluation engine."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "RobotsTxtScanner"
        self.description = "Robots.txt information disclosure and SEO policy analyzer"
        self.version = "3.1.0"
        self.capabilities = ["Policy Analysis", "Sensitive Path Detection", "Sitemap Discovery"]

        self.sensitive_markers = (
            "/admin",
            "/backup",
            ".git",
            ".env",
            ".svn",
            ".hg",
            "phpmyadmin",
            "server-status",
            "wp-admin",
            ".sql",
            ".aws",
            "id_rsa",
            "/dump",
        )

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Fetch and analyze robots.txt."""
        logger.info(f"Analyzing robots.txt for {url}")
        vulnerabilities = []

        try:
            self._update_progress(progress_callback, 30, "Fetching robots.txt")
            robots_url = urljoin(url, "/robots.txt")
            response = await self.http_client.get(robots_url)

            if not response or response.status != 200:
                return self._format_result("Good", "No robots.txt found (Default policy applies)", [])

            content = await response.text()
            if content.lstrip()[:200].lower().startswith(("<!doctype", "<html")):
                return self._format_result("Good", "robots.txt URL returned HTML, not a robots file", [])

            self._update_progress(progress_callback, 50, "Evaluating directives")
            disallows = re.findall(r"^Disallow:\s*(.*)$", content, re.M | re.I)
            candidates = []
            for path in disallows:
                path = path.strip()
                if not path or path in {"/", "*"} or "://" in path:
                    continue
                if any(marker in path.lower() for marker in self.sensitive_markers):
                    candidates.append(path)

            checked = 0
            for path in candidates[:12]:
                checked += 1
                target = urljoin(url, path)
                probed = await self.http_client.get(target)
                if not probed or probed.status != 200:
                    continue
                body = await probed.text()
                if len(body) < 40 or 'type="password"' in body.lower() or 'name="password"' in body.lower():
                    continue
                low = path.lower()
                severity = (
                    "high"
                    if any(marker in low for marker in (".env", ".git", ".svn", ".sql", "id_rsa", ".aws", "backup"))
                    else "low"
                )
                vulnerabilities.append(
                    self._create_vulnerability(
                        title="Robots.txt path is reachable without a login",
                        description=f"{path} is listed in robots.txt and returned HTTP 200 without a password form.",
                        severity=severity,
                        type="info_disclosure",
                        evidence={
                            "robots": robots_url,
                            "path": path,
                            "url": str(probed.url),
                            "status": probed.status,
                            "bytes": len(body),
                        },
                        cwe_id="CWE-200",
                        remediation="Require authentication on the path, or remove it if it should not exist.",
                    )
                )

            self._update_progress(progress_callback, 100, "completed")
            status = "Issues Found" if vulnerabilities else "Clean"
            details = f"{len(disallows)} Disallow directive(s). Probed {checked} sensitive path(s)."
            return self._format_result(status, details, vulnerabilities, {"disallow_count": len(disallows)})

        except Exception as e:
            logger.exception(f"Robots scan failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])
