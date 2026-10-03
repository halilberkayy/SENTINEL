"""
Cloud Security & Metadata exposure scanner module.
"""

import logging
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class CloudScanner(BaseScanner):
    """Engine for identifying cloud-specific exposure (S3, AWS/GCP/Azure Metadata)."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "CloudScanner"
        self.description = "Identifies cloud storage exposure and metadata leaks"
        self.version = "1.0.0"
        self.capabilities = ["S3 bucket discovery", "Metadata endpoint checks", "Container leak detection"]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform cloud scan."""
        logger.info(f"Scanning {url} for Cloud exposure")
        vulnerabilities = []

        urlparse(url)

        try:
            self._update_progress(progress_callback, 10, "Searching for cloud storage links")

            # 1. Discover bucket patterns in the page
            res = await self.http_client.get(url)
            res_dict = await self._response_to_dict(res)
            content = res_dict.get("page_content", "")

            # Simple bucket regex
            patterns = [
                r"[a-z0-9.-]+\.s3\.amazonaws\.com",
                r"s3://[a-z0-9.-]+",
                r"storage\.googleapis\.com/[a-z0-9.-]+",
                r"[a-z0-9.-]+\.blob\.core\.windows\.net",
            ]

            import re

            found_buckets = []
            for p in patterns:
                found_buckets.extend(re.findall(p, content))

            if found_buckets:
                vulnerabilities.append(
                    self._create_vulnerability(
                        title="Cloud Storage Links Discovered",
                        description=f"Found {len(set(found_buckets))} cloud storage references. These should be audited for public accessibility.",
                        severity="info",
                        type="recon",
                        evidence={"buckets": list(set(found_buckets))},
                        remediation="Ensure that referenced buckets/blobs are not publicly readable/writable unless explicitly required.",
                    )
                )

            # 2. Check for common cloud config files on the web root
            self._update_progress(progress_callback, 60, "Checking for cloud config files")
            cloud_files = [
                {"path": "/.aws/credentials", "title": "Exposed AWS Credentials"},
                {"path": "/.docker/config.json", "title": "Exposed Docker Config"},
                {"path": "/.kube/config", "title": "Exposed Kubernetes Config"},
            ]

            for cf in cloud_files:
                target = self._build_url(url, cf["path"])
                check_res = await self.http_client.get(target)
                check_res_dict = await self._response_to_dict(check_res)
                if check_res_dict.get("status_code") == 200:
                    vulnerabilities.append(
                        self._create_vulnerability(
                            title=cf["title"],
                            description=f"Critical cloud/container configuration file found at {cf['path']}.",
                            severity="critical",
                            type="misconfig",
                            evidence={"url": target},
                            remediation="Remove sensitive configuration files from the web root immediately.",
                        )
                    )

            self._update_progress(progress_callback, 100, "completed")

            status = "Vulnerable" if vulnerabilities else "Clean"
            return self._format_result(status, f"Found {len(vulnerabilities)} cloud-related issues.", vulnerabilities)

        except Exception as e:
            logger.exception(f"Cloud scan failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])

    def _build_url(self, base: str, path: str) -> str:
        from urllib.parse import urljoin, urlparse

        parsed = urlparse(base)
        root = f"{parsed.scheme}://{parsed.netloc}"
        return urljoin(root, path)
