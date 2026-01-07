"""
Broken Access Control scanner - ENHANCED with real IDOR testing
"""

import asyncio
import logging
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from .base_scanner import BaseScanner, Vulnerability

logger = logging.getLogger(__name__)


class BrokenAccessControlScanner(BaseScanner):
    """Enhanced Access Control testing with IDOR and privilege escalation detection."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "BrokenAccessControlScanner"
        self.description = "Identifies IDOR, admin bypass, and access control flaws"
        self.version = "2.0.0"
        self.capabilities = ["IDOR Testing", "Admin Path Discovery", "Privilege Escalation Detection"]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform comprehensive access control scan."""
        logger.info(f"Scanning {url} for Broken Access Control")
        vulnerabilities = []

        try:
            # 1. Admin Interface Discovery
            self._update_progress(progress_callback, 10, "Checking for exposed administrative interfaces")
            admin_vulns = await self._test_admin_interfaces(url)
            vulnerabilities.extend(admin_vulns)

            # 2. IDOR Testing
            self._update_progress(progress_callback, 40, "Testing for IDOR vulnerabilities")
            idor_vulns = await self._test_idor(url)
            vulnerabilities.extend(idor_vulns)

            # 3. HTTP Method Override Testing
            self._update_progress(progress_callback, 70, "Testing HTTP method override bypass")
            method_vulns = await self._test_method_override(url)
            vulnerabilities.extend(method_vulns)

            # 4. Path Traversal in Access Control
            self._update_progress(progress_callback, 85, "Testing path traversal bypass")
            path_vulns = await self._test_path_traversal(url)
            vulnerabilities.extend(path_vulns)

            self._update_progress(progress_callback, 100, "completed")

            status = "Vulnerable" if any(v.severity in ["critical", "high"] for v in vulnerabilities) else "Clean"
            return self._format_result(
                status, f"Identified {len(vulnerabilities)} access control issues.", vulnerabilities
            )

        except Exception as e:
            logger.exception(f"Access Control scan failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])

    async def _test_admin_interfaces(self, url: str) -> list[Vulnerability]:
        """Test for exposed administrative interfaces."""
        vulns = []
        admin_paths = [
            "/admin",
            "/administrator",
            "/wp-admin",
            "/dashboard",
            "/admin-panel",
            "/control-panel",
            "/cpanel",
            "/admin.php",
            "/administrator.php",
            "/admin/login",
            "/admin/dashboard",
            "/management",
            "/manager",
            "/admin-console",
            "/console",
            "/api/admin",
            "/api/v1/admin",
            "/backend",
            "/backend/admin",
        ]

        for path in admin_paths:
            try:
                target = self._build_url(url, path)
                res = await self.http_client.get(target)
                res_dict = await self._response_to_dict(res)

                status = res_dict.get("status_code", 0)
                content = res_dict.get("page_content", "").lower()

                # Check if page exists and looks like admin panel
                if status == 200:
                    admin_indicators = [
                        "login",
                        "password",
                        "administrator",
                        "admin panel",
                        "dashboard",
                        "control panel",
                        "username",
                        "sign in",
                    ]

                    if any(indicator in content for indicator in admin_indicators):
                        # Check if it's really unprotected (not asking for auth)
                        auth_indicators = ["401", "unauthorized", "forbidden", "403"]
                        if not any(ind in str(status) or ind in content for ind in auth_indicators):
                            vulns.append(
                                self._create_vulnerability(
                                    title="Exposed Administrative Interface",
                                    description=f"An administrative interface is accessible at {path} without proper authentication.",
                                    severity="high",
                                    type="access_control",
                                    evidence={
                                        "url": target,
                                        "status": status,
                                        "indicators": [ind for ind in admin_indicators if ind in content][:3],
                                    },
                                    cwe_id="CWE-284",
                                    remediation="Implement strong authentication for all administrative interfaces. Use IP whitelisting and multi-factor authentication.",
                                )
                            )
            except Exception as e:
                logger.debug(f"Admin check failed for {path}: {e}")
                continue

        return vulns

    async def _test_idor(self, url: str) -> list[Vulnerability]:
        """Test for Insecure Direct Object Reference vulnerabilities."""
        vulns = []

        # Parse URL to find ID parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Common ID parameter names
        id_params = [
            "id",
            "user_id",
            "uid",
            "account",
            "userid",
            "user",
            "order",
            "orderid",
            "order_id",
            "document",
            "doc_id",
            "file",
            "file_id",
            "item",
            "item_id",
            "product_id",
        ]

        # Find potential ID parameters in URL
        suspicious_params = [p for p in params.keys() if any(id_p in p.lower() for id_p in id_params)]

        if not suspicious_params:
            # Try to discover parameters from the page
            try:
                main_response = await self.http_client.get(url)
                main_dict = await self._response_to_dict(main_response)
                content = main_dict.get("page_content", "")

                # Look for /api/users/123 style endpoints
                api_pattern = r"/api/[\w-]+/(\d+)"
                matches = re.findall(api_pattern, content)
                if matches:
                    # Found potential IDOR endpoints
                    vulns.append(
                        self._create_vulnerability(
                            title="Potential IDOR Endpoint Discovered",
                            description="Found API endpoints with numeric IDs that may be vulnerable to IDOR attacks.",
                            severity="info",
                            type="access_control",
                            evidence={"pattern": api_pattern, "examples": matches[:5]},
                            cwe_id="CWE-639",
                            remediation="Implement proper authorization checks. Verify that the authenticated user has permission to access the requested resource.",
                        )
                    )
            except (asyncio.TimeoutError, Exception) as e:
                logger.debug(f"IDOR discovery failed: {e}")

        # Test IDOR by parameter manipulation
        for param in suspicious_params:
            try:
                original_value = params[param][0]

                # Skip if not numeric
                if not original_value.isdigit():
                    continue

                # Get baseline response
                baseline_response = await self.http_client.get(url)
                baseline_dict = await self._response_to_dict(baseline_response)
                baseline_status = baseline_dict.get("status_code", 0)
                baseline_length = len(baseline_dict.get("page_content", ""))

                # Try different IDs
                test_values = [str(int(original_value) + 1), str(int(original_value) - 1), "1", "999999"]

                for test_value in test_values:
                    # Build test URL
                    test_params = params.copy()
                    test_params[param] = [test_value]

                    new_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(
                        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
                    )

                    test_response = await self.http_client.get(test_url)
                    test_dict = await self._response_to_dict(test_response)
                    test_status = test_dict.get("status_code", 0)
                    test_length = len(test_dict.get("page_content", ""))

                    # Check if we got data (potential IDOR)
                    if test_status == 200 and test_status == baseline_status:
                        # Different content length suggests different data
                        if abs(test_length - baseline_length) > 50:
                            vulns.append(
                                self._create_vulnerability(
                                    title=f"Potential IDOR in Parameter '{param}'",
                                    description=f"Parameter '{param}' appears to allow unauthorized access to different objects. Changing value from {original_value} to {test_value} returned different data.",
                                    severity="high",
                                    type="access_control",
                                    evidence={
                                        "parameter": param,
                                        "original_value": original_value,
                                        "test_value": test_value,
                                        "original_url": url,
                                        "test_url": test_url,
                                        "baseline_length": baseline_length,
                                        "test_length": test_length,
                                    },
                                    cwe_id="CWE-639",
                                    remediation="Implement authorization checks for all object references. Verify the user has permission to access the specific resource.",
                                )
                            )
                            break  # One finding per parameter is enough

            except Exception as e:
                logger.debug(f"IDOR test failed for {param}: {e}")
                continue

        return vulns

    async def _test_method_override(self, url: str) -> list[Vulnerability]:
        """Test HTTP method override bypass techniques."""
        vulns = []

        override_headers = [
            {"X-HTTP-Method-Override": "PUT"},
            {"X-HTTP-Method-Override": "DELETE"},
            {"X-HTTP-Method-Override": "PATCH"},
            {"X-Method-Override": "PUT"},
            {"X-Original-HTTP-Method": "PUT"},
        ]

        try:
            # Get baseline GET request
            baseline = await self.http_client.get(url)
            baseline_dict = await self._response_to_dict(baseline)
            baseline_status = baseline_dict.get("status_code", 0)

            for headers in override_headers:
                test_response = await self.http_client.get(url, headers=headers)
                test_dict = await self._response_to_dict(test_response)
                test_status = test_dict.get("status_code", 0)

                # If adding header changed status code, it might be a bypass
                if test_status != baseline_status:
                    vulns.append(
                        self._create_vulnerability(
                            title="HTTP Method Override Bypass",
                            description="Server responds differently when HTTP method override headers are used. This may allow bypassing access controls.",
                            severity="medium",
                            type="access_control",
                            evidence={
                                "url": url,
                                "header": headers,
                                "baseline_status": baseline_status,
                                "test_status": test_status,
                            },
                            cwe_id="CWE-749",
                            remediation="Disable HTTP method override if not needed. If required, implement proper authorization checks regardless of the HTTP method.",
                        )
                    )
                    break
        except Exception as e:
            logger.debug(f"Method override test failed: {e}")

        return vulns

    async def _test_path_traversal(self, url: str) -> list[Vulnerability]:
        """Test path traversal to bypass access controls."""
        vulns = []

        traversal_payloads = [
            "../admin",
            "..\\admin",
            "....//admin",
            ".;/admin",
            "%2e%2e/admin",
            "..%252fadmin",
        ]

        for payload in traversal_payloads:
            try:
                test_url = self._build_url(url, payload)
                response = await self.http_client.get(test_url)
                res_dict = await self._response_to_dict(response)

                if res_dict.get("status_code") == 200:
                    content = res_dict.get("page_content", "").lower()
                    if "admin" in content or "dashboard" in content:
                        vulns.append(
                            self._create_vulnerability(
                                title="Path Traversal Access Control Bypass",
                                description=f"Path traversal payload '{payload}' bypassed access controls.",
                                severity="high",
                                type="path_traversal",
                                evidence={"url": test_url, "payload": payload},
                                cwe_id="CWE-22",
                                remediation="Properly sanitize and validate all path inputs. Use canonical path resolution.",
                            )
                        )
                        break
            except (asyncio.TimeoutError, Exception) as e:
                logger.debug(f"Path traversal test failed: {e}")
                continue

        return vulns

    def _build_url(self, base: str, path: str) -> str:
        """Build full URL from base and path."""
        from urllib.parse import urljoin, urlparse

        parsed = urlparse(base)
        root = f"{parsed.scheme}://{parsed.netloc}"
        return urljoin(root, path)
