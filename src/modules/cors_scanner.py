"""
CORS Misconfiguration scanner module - Advanced Implementation.
"""

import logging
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from .base_scanner import BaseScanner, Vulnerability

logger = logging.getLogger(__name__)


class CORSScanner(BaseScanner):
    """Advanced CORS misconfiguration detection engine."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "CORSScanner"
        self.description = "Advanced CORS analyzer with preflight, subdomain bypass and credentials testing"
        self.version = "2.0.0"
        self.capabilities = [
            "Origin Reflection Testing",
            "Wildcard with Credentials",
            "Null Origin Attack",
            "Subdomain Takeover Bypass",
            "Preflight Request Analysis",
            "Protocol Downgrade Detection",
        ]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform comprehensive CORS security scan."""
        logger.info(f"Scanning {url} for CORS misconfiguration")
        vulnerabilities = []
        parsed = urlparse(url)
        target_domain = parsed.netloc

        # Generate test origins
        test_origins = self._generate_test_origins(target_domain, url)

        try:
            self._update_progress(progress_callback, 10, "Testing default CORS headers")

            # 1. Check default response
            resp = await self.http_client.get(url)
            resp_dict = await self._response_to_dict(resp)
            default_headers = resp_dict.get("headers", {})
            default_acao = default_headers.get("Access-Control-Allow-Origin", "")
            default_acac = default_headers.get("Access-Control-Allow-Credentials", "")

            # Wildcard with Credentials - Most severe
            if default_acao == "*" and default_acac.lower() == "true":
                vulnerabilities.append(
                    self._create_vulnerability(
                        title="Critical CORS: Wildcard with Credentials",
                        description="Server allows ALL origins (*) with credentials enabled. Any website can make authenticated cross-origin requests.",
                        severity="critical",
                        type="cors_wildcard_credentials",
                        evidence={"acao": default_acao, "acac": default_acac},
                        cwe_id="CWE-942",
                        remediation="Never use wildcard (*) with Allow-Credentials. Specify explicit trusted domains.",
                    )
                )

            # 2. Test Preflight (OPTIONS) request
            self._update_progress(progress_callback, 20, "Testing preflight requests")
            preflight_vulns = await self._test_preflight(url, target_domain)
            vulnerabilities.extend(preflight_vulns)

            # 3. Test each origin variant
            total_origins = len(test_origins)
            for idx, (origin, origin_type) in enumerate(test_origins):
                progress = 30 + int((idx / total_origins) * 60)
                self._update_progress(progress_callback, progress, f"Testing: {origin_type}")

                vulns = await self._test_origin(url, origin, origin_type)
                vulnerabilities.extend(vulns)

            self._update_progress(progress_callback, 100, "completed")

            status = "Vulnerable" if vulnerabilities else "Secure"
            details = f"Tested {len(test_origins)} origin variants. Found {len(vulnerabilities)} CORS issues."
            return self._format_result(status, details, vulnerabilities)

        except Exception as e:
            logger.exception(f"CORS scan failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])

    def _generate_test_origins(self, target_domain: str, url: str) -> list[tuple]:
        """Generate various malicious origin variants."""
        urlparse(url)
        base_domain = target_domain.split(":")[0]  # Remove port

        origins = [
            # Direct malicious origins
            ("https://evil-attacker.com", "External Domain"),
            ("https://attacker.com", "External Domain 2"),
            # Null origin (sandbox, data: URI, file:)
            ("null", "Null Origin"),
            # Subdomain takeover variants
            (f"https://evil.{base_domain}", "Subdomain Prefix"),
            (f"https://{base_domain}.evil.com", "Subdomain Suffix"),
            (f"https://not{base_domain}", "Domain Concatenation"),
            # Protocol downgrade
            (f"http://{base_domain}", "HTTP Downgrade"),
            # Special character bypass attempts
            (f"https://{base_domain}%60.evil.com", "Backtick Bypass"),
            (f"https://{base_domain}_.evil.com", "Underscore Bypass"),
            (f"https://{base_domain}!.evil.com", "Special Char Bypass"),
            # Case variation
            (f"https://{base_domain.upper()}", "Case Variation"),
            # Trailing dot
            (f"https://{base_domain}.", "Trailing Dot"),
            # Port variation
            (f"https://{base_domain}:443", "Explicit Port"),
            (f"https://{base_domain}:8443", "Alternative Port"),
        ]

        return origins

    async def _test_preflight(self, url: str, target_domain: str) -> list[Vulnerability]:
        """Test preflight (OPTIONS) request handling."""
        findings = []

        try:
            # Send OPTIONS request with custom headers
            custom_headers = {
                "Origin": "https://evil-attacker.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "X-Custom-Header, Authorization",
            }

            resp = await self.http_client.request("OPTIONS", url, headers=custom_headers)
            resp_dict = await self._response_to_dict(resp)
            headers = resp_dict.get("headers", {})

            acao = headers.get("Access-Control-Allow-Origin", "")
            acam = headers.get("Access-Control-Allow-Methods", "")
            acah = headers.get("Access-Control-Allow-Headers", "")
            headers.get("Access-Control-Allow-Credentials", "")

            # Check if arbitrary origin is reflected in preflight
            if acao == "https://evil-attacker.com":
                findings.append(
                    self._create_vulnerability(
                        title="CORS Preflight Origin Reflection",
                        description="Preflight response reflects arbitrary origins, allowing cross-origin requests from any website.",
                        severity="high",
                        type="cors_preflight_reflection",
                        evidence={"origin": acao, "methods": acam, "headers": acah},
                        cwe_id="CWE-942",
                        remediation="Validate Origin header against a whitelist before returning CORS headers.",
                    )
                )

            # Check for overly permissive methods
            dangerous_methods = ["PUT", "DELETE", "PATCH"]
            if acam:
                allowed_dangerous = [m for m in dangerous_methods if m in acam.upper()]
                if "*" in acam or len(allowed_dangerous) >= 2:
                    findings.append(
                        self._create_vulnerability(
                            title="Overly Permissive CORS Methods",
                            description=f"Server allows potentially dangerous HTTP methods: {acam}",
                            severity="medium",
                            type="cors_dangerous_methods",
                            evidence={"allowed_methods": acam},
                            cwe_id="CWE-942",
                            remediation="Restrict allowed methods to only those required (GET, POST).",
                        )
                    )

            # Check for wildcard headers
            if acah and "*" in acah:
                findings.append(
                    self._create_vulnerability(
                        title="Wildcard CORS Headers",
                        description="Server allows any custom headers in cross-origin requests.",
                        severity="low",
                        type="cors_wildcard_headers",
                        evidence={"allowed_headers": acah},
                        cwe_id="CWE-942",
                        remediation="Specify only required headers instead of using wildcard.",
                    )
                )

        except Exception as e:
            logger.debug(f"Preflight test error: {e}")

        return findings

    async def _test_origin(self, url: str, origin: str, origin_type: str) -> list[Vulnerability]:
        """Test a specific origin for CORS misconfiguration."""
        findings = []

        try:
            custom_headers = {"Origin": origin}
            resp = await self.http_client.get(url, headers=custom_headers)
            resp_dict = await self._response_to_dict(resp)
            headers = resp_dict.get("headers", {})

            acao = headers.get("Access-Control-Allow-Origin", "")
            acac = headers.get("Access-Control-Allow-Credentials", "")

            # Origin reflection
            if acao == origin:
                severity = "high" if origin == "null" else "medium"

                if acac.lower() == "true":
                    severity = "critical" if origin == "null" else "high"
                    findings.append(
                        self._create_vulnerability(
                            title=f"CORS Origin Reflection with Credentials ({origin_type})",
                            description=f"Server reflects origin '{origin}' with credentials enabled. Authenticated cross-origin requests are possible.",
                            severity=severity,
                            type="cors_reflection_credentials",
                            evidence={"origin": origin, "type": origin_type, "acao": acao, "acac": acac},
                            cwe_id="CWE-942",
                            remediation="Implement strict origin validation. Never reflect untrusted origins with credentials.",
                        )
                    )
                else:
                    findings.append(
                        self._create_vulnerability(
                            title=f"CORS Origin Reflection ({origin_type})",
                            description=f"Server reflects origin '{origin}'. Cross-origin requests are possible without cookies.",
                            severity=severity,
                            type="cors_reflection",
                            evidence={"origin": origin, "type": origin_type, "acao": acao},
                            cwe_id="CWE-942",
                            remediation="Validate Origin header against a strict whitelist of trusted domains.",
                        )
                    )

            # Check for regex/pattern bypass (partial match)
            elif origin in acao or (acao and acao != "*" and len(acao) > 0):
                # Domain appears to be using some kind of pattern matching
                if "evil" in origin.lower() and acao not in ["", "*"]:
                    findings.append(
                        self._create_vulnerability(
                            title=f"Potential CORS Bypass ({origin_type})",
                            description=f"Tested origin '{origin}' returned ACAO: '{acao}'. May indicate weak origin validation.",
                            severity="low",
                            type="cors_potential_bypass",
                            evidence={"tested_origin": origin, "acao": acao},
                            cwe_id="CWE-942",
                            remediation="Review CORS origin validation logic for bypass vulnerabilities.",
                        )
                    )

        except Exception as e:
            logger.debug(f"Origin test error for {origin}: {e}")

        return findings
