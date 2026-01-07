"""
HTTP Security Headers analysis module.
"""

import logging
from collections.abc import Callable
from typing import Any

from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class HeadersScanner(BaseScanner):
    """Professional Security Headers assessment engine."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "HeadersScanner"
        self.description = "Security Headers and Cookie analysis engine"
        self.version = "3.1.0"
        self.capabilities = ["Header Analysis", "Cookie Security", "CSP Evaluation"]

        # Security header definitions
        self.headers_to_check = {
            "Strict-Transport-Security": (
                "high",
                "Ensures HTTPS-only communication.",
                "max-age=31536000; includeSubDomains",
            ),
            "Content-Security-Policy": ("high", "Protects against XSS and injection attacks.", "default-src 'self';"),
            "X-Frame-Options": ("medium", "Prevents clickjacking attacks.", "DENY or SAMEORIGIN"),
            "X-Content-Type-Options": ("low", "Prevents MIME-sniffing.", "nosniff"),
            "Referrer-Policy": ("low", "Controls referrer information leakage.", "strict-origin-when-cross-origin"),
            "Permissions-Policy": (
                "low",
                "Controls browser feature usage (camera, geolocation, etc).",
                "geolocation=()",
            ),
            "Cross-Origin-Embedder-Policy": (
                "medium",
                "Prevents non-safe cross-origin resources from being embedded.",
                "require-corp",
            ),
            "Cross-Origin-Opener-Policy": ("medium", "Prevents cross-origin window interactions.", "same-origin"),
        }

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform security headers and cookie analysis."""
        logger.info(f"Analyzing headers for {url}")
        vulnerabilities = []

        try:
            self._update_progress(progress_callback, 20, "Fetching target headers")
            response = await self.http_client.get(url)
            if not response:
                return self._format_result("Error", "Target unreachable", [])

            headers = {k.lower(): v for k, v in response.headers.items()}

            # 1. Analyze Security Headers
            self._update_progress(progress_callback, 50, "Evaluating security headers")
            for h_name, (sev, desc, rec) in self.headers_to_check.items():
                if h_name.lower() not in headers:
                    vulnerabilities.append(
                        self._create_vulnerability(
                            title=f"Missing Security Header: {h_name}",
                            description=f"{desc} This header is missing.",
                            severity=sev,
                            type="missing_header",
                            evidence={"header": h_name},
                            cwe_id="CWE-693",
                            remediation=f"Implement the {h_name} header. Suggested value: {rec}",
                        )
                    )

            # 2. Analyze Cookies
            self._update_progress(progress_callback, 80, "Checking cookie security flags")
            set_cookies = [v for k, v in response.headers.items() if k.lower() == "set-cookie"]
            for cookie in set_cookies:
                c_low = cookie.lower()
                c_name = cookie.split("=")[0]

                flags_missing = []
                if "secure" not in c_low:
                    flags_missing.append("Secure")
                if "httponly" not in c_low:
                    flags_missing.append("HttpOnly")
                if "samesite" not in c_low:
                    flags_missing.append("SameSite")

                if flags_missing:
                    vulnerabilities.append(
                        self._create_vulnerability(
                            title=f"Insecure Cookie Flags: {c_name}",
                            description=f"Cookie '{c_name}' is missing security flags: {', '.join(flags_missing)}",
                            severity="medium",
                            type="insecure_cookie",
                            evidence={"cookie": cookie, "missing": flags_missing},
                            cwe_id="CWE-614",
                            remediation="Ensure all sensitive cookies have Secure, HttpOnly, and SameSite attributes.",
                        )
                    )

            self._update_progress(progress_callback, 100, "completed")

            status = "Vulnerable" if vulnerabilities else "Secure"
            details = f"Analyzed {len(self.headers_to_check)} security headers and {len(set_cookies)} cookies. Found {len(vulnerabilities)} issues."
            return self._format_result(status, details, vulnerabilities)

        except Exception as e:
            logger.exception(f"Headers scan failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])
