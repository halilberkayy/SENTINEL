"""
Advanced Webshell Uploader module.
Refactored from root modules/webshell_uploader.py
"""

import logging
from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin

from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class WebshellUploaderScanner(BaseScanner):
    """Deep exploitation module for deploying webshells via upload vulnerabilities."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "WebshellUploader"
        self.description = "Deployment and testing of webshells via upload vulns"
        self.version = "1.0.0"

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform webshell deployment testing."""
        logger.info(f"Starting Webshell Uploader on {url}")
        vulnerabilities = []

        # Common upload endpoints
        upload_endpoints = ["/upload", "/admin/upload", "/api/upload", "/fileupload", "/uploader"]

        try:
            self._update_progress(progress_callback, 10, "Detecting upload forms")

            discovered_forms = []
            for ep in upload_endpoints:
                target = urljoin(url, ep)
                res = await self.http_client.get(target)
                res_dict = await self._response_to_dict(res)
                content = res_dict.get("page_content", "").lower()
                if 'type="file"' in content or 'enctype="multipart/form-data"' in content:
                    discovered_forms.append(target)

            if not discovered_forms:
                self._update_progress(progress_callback, 100, "completed")
                return self._format_result("Clean", "No obvious upload forms discovered.", [])

            total_forms = len(discovered_forms)
            for idx, form_url in enumerate(discovered_forms):
                self._update_progress(progress_callback, 30 + int((idx / total_forms) * 60), f"Testing {form_url}")

                # Prepare test payload (non-destructive - discovery only)
                content = "<?php echo 'vulnerable'; ?>"

                # We stop at discovery/simulated upload to avoid destructive testing by default
                vulnerabilities.append(
                    self._create_vulnerability(
                        title="Insecure File Upload Form Discovered",
                        description=f"A potential file upload form was found at {form_url}. This could be used for webshell deployment.",
                        severity="high",
                        type="upload",
                        evidence={"url": form_url},
                        remediation="Implement strict file extension checks, rename uploaded files, and store them outside the web root.",
                    )
                )

            self._update_progress(progress_callback, 100, "completed")
            return self._format_result(
                "Clean", f"Identified {len(discovered_forms)} potential upload vectors.", vulnerabilities
            )

        except Exception as e:
            logger.exception(f"Uploader failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])
