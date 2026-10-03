"""
Cross-Site Request Forgery (CSRF) vulnerability scanner module.
"""

import logging
from collections.abc import Callable
from typing import Any

from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class CsrfScanner(BaseScanner):
    """Professional CSRF assessment engine."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "CsrfScanner"
        self.description = "Cross-Site Request Forgery detector"
        self.version = "1.0.0"
        self.capabilities = ["Anti-CSRF Token Analysis", "SameSite Cookie Check", "CORS policy analysis"]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform CSRF assessment."""
        logger.info(f"Analyzing CSRF for {url}")
        vulnerabilities = []

        try:
            self._update_progress(progress_callback, 10, "Fetching page to analyze forms")
            response = await self.http_client.get(url)
            if not response:
                return self._format_result("Error", "Target unreachable", [])

            html = await response.text()
            soup = await self._parse_html(html)

            # 1. Analyze Forms for CSRF tokens
            self._update_progress(progress_callback, 40, "Analyzing forms")
            forms = soup.find_all("form")
            for form in forms:
                if form.get("method", "get").lower() == "post":
                    has_token = self._check_form_for_token(form)
                    if not has_token:
                        vulnerabilities.append(
                            self._create_vulnerability(
                                title="Missing Anti-CSRF Token",
                                description=f"A POST form found at {url} does not appear to contain a CSRF protection token.",
                                severity="medium",
                                type="csrf",
                                evidence={"form_action": form.get("action")},
                                cwe_id="CWE-352",
                                remediation="Implement unique, non-predictable CSRF tokens for all state-changing requests.",
                            )
                        )

            # 2. Analyze Cookies for SameSite attribute
            self._update_progress(progress_callback, 70, "Analyzing cookies")
            cookies = response.cookies
            for name, cookie in cookies.items():
                samesite = cookie.get("samesite", "").lower()
                if not samesite or samesite == "none":
                    vulnerabilities.append(
                        self._create_vulnerability(
                            title="Insecure Cookie (SameSite)",
                            description=f"Cookie '{name}' is missing the SameSite attribute or set to 'None', facilitating CSRF.",
                            severity="low",
                            type="insecure_cookie",
                            evidence={"cookie_name": name, "samesite": samesite},
                            cwe_id="CWE-1275",
                            remediation="Set SameSite=Lax or SameSite=Strict for all sensitive cookies.",
                        )
                    )

            self._update_progress(progress_callback, 100, "completed")
            status = "Vulnerable" if vulnerabilities else "Clean"
            return self._format_result(
                status, f"Analyzed {len(forms)} forms and {len(cookies)} cookies.", vulnerabilities
            )

        except Exception as e:
            logger.exception(f"CSRF scan failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])

    def _check_form_for_token(self, form) -> bool:
        """Check if form has a potential CSRF token."""
        token_names = ["csrf", "token", "xsrf", "crumb", "authenticity_token"]
        inputs = form.find_all("input")
        for inp in inputs:
            name = (inp.get("name") or "").lower()
            if any(t in name for t in token_names):
                return True
        return False
