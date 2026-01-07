"""
Webshell detection module - ENHANCED with signature-based detection
"""

import logging
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin, urlparse

from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class WebshellScanner(BaseScanner):
    """Enhanced webshell detection using signature-based analysis."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "WebshellScanner"
        self.description = "Detects webshells and backdoors using pattern matching"
        self.version = "2.0.0"
        self.capabilities = ["Signature Detection", "Pattern Matching", "File Analysis"]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Scan for webshells using signature database."""
        logger.info(f"Scanning for webshells on {url}")
        vulnerabilities = []

        try:
            self._update_progress(progress_callback, 10, "Loading webshell signatures")

            # Load signatures from file
            signatures = self._load_webshell_signatures()

            # Get common upload/shell paths
            webshell_paths = self._load_wordlist("webshells") if hasattr(self, "_load_wordlist") else []

            # Add common webshell locations
            common_paths = [
                "/uploads/",
                "/upload/",
                "/files/",
                "/media/",
                "/assets/",
                "/tmp/",
                "/temp/",
                "/cache/",
                "/images/",
                "/img/",
                "/content/",
                "/data/",
            ]

            total_checks = len(signatures) + len(webshell_paths)
            checked = 0

            # 1. Check for known webshell filenames
            self._update_progress(progress_callback, 20, "Checking known webshell paths")

            for sig in signatures[:50]:  # Limit to top 50 signatures
                checked += 1
                progress = 20 + int((checked / total_checks) * 60)
                self._update_progress(progress_callback, progress, f"Checking {sig['filename']}")

                # Try in root and common upload directories
                for base_path in ["", *common_paths]:
                    test_url = self._build_url(url, f"{base_path}{sig['filename']}")

                    try:
                        response = await self.http_client.get(test_url)
                        if response and response.status == 200:
                            content = await response.text()

                            # Check for signature pattern in content
                            if re.search(sig["pattern"], content, re.IGNORECASE):
                                vulnerabilities.append(
                                    self._create_vulnerability(
                                        title=f"Webshell Detected: {sig['filename']}",
                                        description=f"Potential webshell found at {test_url}. Pattern match: {sig['pattern'][:50]}",
                                        severity=sig["severity"],
                                        type="backdoor",
                                        evidence={
                                            "url": test_url,
                                            "filename": sig["filename"],
                                            "pattern": sig["pattern"][:100],
                                            "matched_content": content[:200],
                                        },
                                        cwe_id="CWE-94",
                                        remediation="Remove the webshell file immediately. Investigate how it was uploaded and patch the vulnerability. Review server logs for suspicious activity.",
                                    )
                                )
                                break  # Don't check other paths for same signature
                    except Exception as e:
                        logger.debug(f"Error checking {test_url}: {e}")
                        continue

            # 2. Content-based detection on accessible PHP/ASP files
            self._update_progress(progress_callback, 85, "Analyzing accessible script files")

            suspicious_patterns = [
                (r"eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)", "critical", "Eval with user input"),
                (r"base64_decode\s*\(\s*\$_(GET|POST)", "high", "Base64 decode user input"),
                (r"system\s*\(\s*\$_(GET|POST)", "critical", "System execution"),
                (r"exec\s*\(\s*\$_(GET|POST)", "critical", "Exec with user input"),
                (r"shell_exec\s*\(\s*\$_(GET|POST)", "critical", "Shell exec"),
                (r"passthru\s*\(\s*\$", "critical", "Passthru function"),
                (r"assert\s*\(\s*\$_(GET|POST)", "high", "Assert with user input"),
                (r"preg_replace.*\/e", "high", "Deprecated preg_replace /e modifier"),
                (r"ProcessStartInfo|Process\.Start", "critical", "ASP.NET process execution"),
                (r"Runtime\.getRuntime\(\)\.exec", "critical", "Java runtime exec"),
            ]

            # Check main page for suspicious patterns
            try:
                main_response = await self.http_client.get(url)
                if main_response and main_response.status == 200:
                    main_content = await main_response.text()

                    for pattern, severity, desc in suspicious_patterns:
                        if re.search(pattern, main_content, re.IGNORECASE):
                            vulnerabilities.append(
                                self._create_vulnerability(
                                    title="Suspicious Code Pattern Detected",
                                    description=f"Found potentially malicious pattern: {desc}",
                                    severity=severity,
                                    type="code_injection",
                                    evidence={"url": url, "pattern": pattern, "description": desc},
                                    cwe_id="CWE-94",
                                    remediation="Review the code for backdoors or webshells. This pattern is commonly used in malicious scripts.",
                                )
                            )
            except Exception as e:
                logger.debug(f"Content analysis failed: {e}")

            self._update_progress(progress_callback, 100, "completed")

            status = "Vulnerable" if vulnerabilities else "Clean"
            return self._format_result(
                status, f"Found {len(vulnerabilities)} potential webshells/backdoors.", vulnerabilities
            )

        except Exception as e:
            logger.exception(f"Webshell scan failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])

    def _build_url(self, base: str, path: str) -> str:
        """Build full URL from base and path."""
        parsed = urlparse(base)
        root = f"{parsed.scheme}://{parsed.netloc}"
        return urljoin(root, path)
