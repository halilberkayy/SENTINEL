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

        # Keywords that indicate sensitive areas in Disallow directives
        self.sensitive_keywords = [
            "admin",
            "config",
            "backup",
            "setup",
            "test",
            "dev",
            "private",
            "api",
            "tmp",
            "cgi-bin",
            "secret",
            "dashboard",
            "sql",
            "db",
        ]

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
            self._update_progress(progress_callback, 70, "Evaluating directives")

            # Simple parsing
            disallows = re.findall(r"^Disallow:\s*(.*)$", content, re.M | re.I)
            sitemaps = re.findall(r"^Sitemap:\s*(.*)$", content, re.M | re.I)

            # 1. Check for sensitive path disclosure
            for path in disallows:
                path = path.strip()
                if not path or path == "/":
                    continue

                matched = [k for k in self.sensitive_keywords if k in path.lower()]
                if matched:
                    vulnerabilities.append(
                        self._create_vulnerability(
                            title="Sensitive Path Disclosed in Robots.txt",
                            description=f"Directives in robots.txt reveal the existence of potentially sensitive area: '{path}' (Matched: {', '.join(matched)})",
                            severity="medium",
                            type="info_disclosure",
                            evidence={"path": path, "keywords": matched},
                            cwe_id="CWE-200",
                            remediation="Ensure sensitive directories are protected by authentication, not just hidden in robots.txt. Consider removing them from robots.txt if they are not indexed by default.",
                        )
                    )

            # 2. Check for missing sitemaps (Informational)
            if not sitemaps:
                vulnerabilities.append(
                    self._create_vulnerability(
                        title="Missing Sitemap Directive",
                        description="No Sitemap directive found in robots.txt. This may limit search engine discovery.",
                        severity="info",
                        type="seo_optimization",
                        evidence={},
                        cwe_id="CWE-200",
                        remediation="Add 'Sitemap: [url]' to robots.txt to improve SEO.",
                    )
                )

            self._update_progress(progress_callback, 100, "completed")

            status = "Issues Found" if vulnerabilities else "Clean"
            details = f"Analyzed {len(disallows)} Disallow directives. Discovered {len(sitemaps)} sitemaps."
            return self._format_result(status, details, vulnerabilities, {"raw_content": content})

        except Exception as e:
            logger.exception(f"Robots scan failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])
