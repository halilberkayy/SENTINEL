"""
Security.txt analysis module for RFC 9116 compliance.
"""

import logging
import re
from collections.abc import Callable
from datetime import datetime
from typing import Any
from urllib.parse import urljoin

from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class SecurityTxtScanner(BaseScanner):
    """Professional Security.txt (RFC 9116) evaluation engine."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "SecurityTxtScanner"
        self.description = "RFC 9116 security contact policy analyzer"
        self.version = "3.1.0"
        self.capabilities = ["Compliance Audit", "Contact Validation", "Expiration Check"]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Fetch and analyze security.txt."""
        logger.info(f"Analyzing security.txt for {url}")
        vulnerabilities = []

        locations = ["/.well-known/security.txt", "/security.txt"]
        security_txt_found = False
        content = ""
        found_url = ""

        try:
            self._update_progress(progress_callback, 20, "Searching for security.txt")
            for loc in locations:
                target_url = urljoin(url, loc)
                response = await self.http_client.get(target_url)
                if response and response.status == 200:
                    content = await response.text()
                    found_url = str(response.url)
                    security_txt_found = True
                    break

            if not security_txt_found:
                vulnerabilities.append(
                    self._create_vulnerability(
                        title="Missing security.txt File",
                        description="No security.txt file found. This prevents researchers from safely reporting vulnerabilities.",
                        severity="info",
                        type="missing_policy",
                        evidence={},
                        cwe_id="CWE-200",
                        remediation="Implement a security.txt file at /.well-known/security.txt as per RFC 9116.",
                        references=["https://securitytxt.org/"],
                    )
                )
            else:
                self._update_progress(progress_callback, 60, "Evaluating compliance")
                # 1. Check for Contact (Required)
                if "Contact:" not in content:
                    vulnerabilities.append(
                        self._create_vulnerability(
                            title="Non-compliant security.txt: Missing Contact",
                            description="RFC 9116 requires at least one 'Contact:' directive.",
                            severity="medium",
                            type="compliance_issue",
                            evidence={"url": found_url},
                            cwe_id="CWE-200",
                            remediation="Add a Contact: directive with an email or security page URL.",
                        )
                    )

                # 2. Check for Expires (Required by RFC 9116)
                expires_match = re.search(r"Expires:\s*(.*)", content, re.I)
                if not expires_match:
                    vulnerabilities.append(
                        self._create_vulnerability(
                            title="Non-compliant security.txt: Missing Expires",
                            description="RFC 9116 requires an 'Expires:' directive.",
                            severity="low",
                            type="compliance_issue",
                            evidence={"url": found_url},
                            cwe_id="CWE-200",
                            remediation="Add an Expires: directive with an ISO 8601 date.",
                        )
                    )
                else:
                    exp_str = expires_match.group(1).strip()
                    try:
                        # Basic ISO 8601 check
                        exp_date = datetime.fromisoformat(exp_str.replace("Z", "+00:00"))
                        if exp_date < datetime.now(exp_date.tzinfo):
                            vulnerabilities.append(
                                self._create_vulnerability(
                                    title="Expired security.txt Policy",
                                    description=f"The security policy expired on {exp_str}.",
                                    severity="medium",
                                    type="outdated_policy",
                                    evidence={"url": found_url, "expires": exp_str},
                                    cwe_id="CWE-200",
                                    remediation="Update the Expires directive in your security.txt file.",
                                )
                            )
                    except Exception:
                        vulnerabilities.append(
                            self._create_vulnerability(
                                title="Invalid Expires Format",
                                description=f"The Expires value '{exp_str}' is not a valid ISO 8601 date.",
                                severity="low",
                                type="compliance_issue",
                                evidence={"url": found_url, "expires": exp_str},
                                cwe_id="CWE-200",
                                remediation="Use the full ISO 8601 format (e.g., 2025-12-31T23:59:59Z).",
                            )
                        )

            self._update_progress(progress_callback, 100, "completed")

            status = "Issues Found" if vulnerabilities else "Compliant"
            return self._format_result(
                status, f"Found {len(vulnerabilities)} policy issues.", vulnerabilities, {"url": found_url}
            )

        except Exception as e:
            logger.exception(f"Security.txt scan failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])
