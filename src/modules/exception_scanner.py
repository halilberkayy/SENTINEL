"""
Exception Handling Scanner - OWASP A10:2025 Mishandling of Exceptional Conditions
Detects improper error handling, information disclosure, and fail-open scenarios.
"""

import asyncio
import re
from typing import Any
from urllib.parse import urljoin

from .base_scanner import BaseScanner


class ExceptionScanner(BaseScanner):
    """
    Scanner for detecting mishandling of exceptional conditions.

    Covers OWASP A10:2025:
    - CWE-209: Generation of Error Message Containing Sensitive Information
    - CWE-234: Failure to Handle Missing Parameter
    - CWE-274: Improper Handling of Insufficient Privileges
    - CWE-476: NULL Pointer Dereference
    - CWE-636: Not Failing Securely ('Failing Open')
    """

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "Exception Handling Scanner"
        self.description = "Detects improper error handling and exceptional condition vulnerabilities"

        # Sensitive information patterns in error messages
        self.sensitive_patterns = {
            "stack_trace": [
                r"at\s+[\w\.]+\s*\([^)]+:\d+\)",  # Java/C# stack trace
                r'File\s+"[^"]+",\s+line\s+\d+',  # Python stack trace
                r"#\d+\s+[\w\\\/\.]+\(\d+\)",  # PHP stack trace
                r"at\s+\w+\s+\([^)]+\.js:\d+:\d+\)",  # Node.js stack trace
                r"goroutine\s+\d+\s+\[",  # Go stack trace
                r"panic:\s+",  # Go panic
                r"Traceback\s+\(most recent call last\)",  # Python traceback
            ],
            "database_info": [
                r"mysql_\w+\(\)",
                r"pg_\w+\(\)",
                r"ORA-\d{5}",  # Oracle error
                r"SQL\s+Server\s+Native\s+Client",
                r"SQLSTATE\[\w+\]",
                r"sqlite3?\.",
                r"MongoDB\s+server\s+version",
                r"redis\.\w+Error",
            ],
            "path_disclosure": [
                r"[A-Z]:\\[\w\\]+\.\w+",  # Windows paths
                r"/(?:var|home|usr|etc|opt)/[\w/]+\.\w+",  # Unix paths
                r"/www/[\w/]+",
                r"DocumentRoot",
                r"DOCUMENT_ROOT",
            ],
            "server_info": [
                r"Apache/[\d\.]+",
                r"nginx/[\d\.]+",
                r"PHP/[\d\.]+",
                r"Python/[\d\.]+",
                r"Node\.js\s+v[\d\.]+",
                r"ASP\.NET\s+Version",
                r"X-Powered-By:\s*[\w/\.]+",
            ],
            "credentials": [
                r'password\s*[=:]\s*[\'"]?[\w@#$%^&*]+',
                r'api[_-]?key\s*[=:]\s*[\'"]?[\w-]+',
                r'secret\s*[=:]\s*[\'"]?[\w-]+',
                r'token\s*[=:]\s*[\'"]?[\w\.-]+',
                r"jdbc:[\w:]+//[\w\.]+:\d+",  # JDBC connection strings
            ],
            "debug_info": [
                r"DEBUG\s*=\s*True",
                r"development\s+mode",
                r"debug\s+mode\s+enabled",
                r"var_dump\(",
                r"print_r\(",
                r"console\.log\(",
                r"System\.out\.println",
            ],
        }

        # Error triggering payloads
        self.error_payloads = {
            "missing_params": [
                "",
                "null",
                "undefined",
                "None",
                "{{}}",
            ],
            "type_confusion": [
                "[]",
                "{}",
                "NaN",
                "Infinity",
                "-Infinity",
                "0x0",
                "1e999",
            ],
            "overflow": [
                "9" * 100,
                "-" + "9" * 100,
                "A" * 10000,
                str(2**63),
                str(-(2**63)),
            ],
            "format_string": [
                "%s%s%s%s%s",
                "%n%n%n%n",
                "%x%x%x%x",
                "{0}{1}{2}",
                "${jndi:ldap://test}",
            ],
            "null_injection": [
                "\x00",
                "%00",
                "\\0",
                "\u0000",
            ],
            "special_chars": [
                "\n\r\t",
                "<!--",
                "-->",
                "<??>",
                "<![CDATA[]]>",
            ],
        }

        # HTTP methods for testing
        self.test_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]

        # Error status codes to analyze
        self.error_codes = [400, 401, 403, 404, 405, 500, 501, 502, 503]

    async def scan(self, url: str, progress_callback=None) -> dict[str, Any]:
        """Main scan method for exception handling vulnerabilities."""
        self.vulnerabilities = []

        try:
            if progress_callback:
                progress_callback(self.name, "starting", 0)

            # 1. Test error message information disclosure
            await self._test_error_disclosure(url)
            if progress_callback:
                progress_callback(self.name, "error_disclosure", 20)

            # 2. Test missing parameter handling
            await self._test_missing_params(url)
            if progress_callback:
                progress_callback(self.name, "missing_params", 40)

            # 3. Test fail-open scenarios
            await self._test_fail_open(url)
            if progress_callback:
                progress_callback(self.name, "fail_open", 60)

            # 4. Test resource exhaustion handling
            await self._test_resource_exhaustion(url)
            if progress_callback:
                progress_callback(self.name, "resource_exhaustion", 80)

            # 5. Test exception handler bypass
            await self._test_exception_bypass(url)
            if progress_callback:
                progress_callback(self.name, "completed", 100)

            return {
                "status": "Completed",
                "details": f"Found {len(self.vulnerabilities)} exception handling issues",
                "vulnerabilities": self.vulnerabilities,
                "risk_level": self._calculate_risk_level(),
            }

        except Exception as e:
            return {
                "status": "Error",
                "details": str(e),
                "vulnerabilities": self.vulnerabilities,
                "risk_level": "unknown",
            }

    async def _test_error_disclosure(self, url: str):
        """Test for sensitive information disclosure in error messages."""

        # Test various error-triggering requests
        test_cases = [
            # Non-existent paths
            (urljoin(url, "/nonexistent_path_12345"), "GET", None),
            (urljoin(url, "/api/v999/test"), "GET", None),
            (urljoin(url, "/.git/config"), "GET", None),
            # Malformed requests
            (url, "GET", {"id": "'; DROP TABLE--"}),
            (url, "GET", {"page": "-1"}),
            (url, "GET", {"id": "0"}),
            (url, "POST", {"data": "{"}),  # Invalid JSON
        ]

        for test_url, method, params in test_cases:
            try:
                if method == "GET":
                    response = await self.http_client.get(test_url, params=params)
                else:
                    response = await self.http_client.post(test_url, data=params)

                if response:
                    content = response.text if hasattr(response, "text") else str(response.content)
                    await self._analyze_error_response(test_url, content, response.status_code)

            except Exception as e:
                logger.debug(f"Error testing exception handling for {test_url}: {e}")

    async def _analyze_error_response(self, url: str, content: str, status_code: int):
        """Analyze error response for sensitive information."""

        for category, patterns in self.sensitive_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    severity = self._get_disclosure_severity(category)
                    self.vulnerabilities.append(
                        {
                            "type": "information_disclosure",
                            "severity": severity,
                            "title": f'Sensitive {category.replace("_", " ").title()} in Error Response',
                            "description": f"Error response contains sensitive {category} information",
                            "url": url,
                            "status_code": status_code,
                            "evidence": matches[:3],  # First 3 matches
                            "cwe": "CWE-209",
                            "owasp": "A10:2025 Mishandling of Exceptional Conditions",
                            "remediation": "Implement custom error pages that do not reveal technical details. "
                            "Log detailed errors server-side only.",
                        }
                    )
                    break  # One finding per category

    def _get_disclosure_severity(self, category: str) -> str:
        """Get severity based on disclosure category."""
        severity_map = {
            "credentials": "critical",
            "database_info": "high",
            "stack_trace": "medium",
            "path_disclosure": "medium",
            "server_info": "low",
            "debug_info": "medium",
        }
        return severity_map.get(category, "info")

    async def _test_missing_params(self, url: str):
        """Test how application handles missing required parameters."""

        # Common API endpoints to test
        endpoints = ["/api/user", "/api/login", "/api/search", "/api/data", "/login", "/register", "/search"]

        for endpoint in endpoints:
            test_url = urljoin(url, endpoint)

            # Test with completely empty request
            try:
                response = await self.http_client.post(test_url, json={})
                if response and response.status_code in [200, 500]:
                    content = response.text if hasattr(response, "text") else ""

                    # Check for improper handling
                    if response.status_code == 500:
                        self.vulnerabilities.append(
                            {
                                "type": "missing_param_handling",
                                "severity": "medium",
                                "title": "Improper Missing Parameter Handling",
                                "description": "Server returns 500 error when required parameters are missing",
                                "url": test_url,
                                "cwe": "CWE-234",
                                "owasp": "A10:2025 Mishandling of Exceptional Conditions",
                                "remediation": "Validate all required parameters and return appropriate 400 errors",
                            }
                        )

                    # Check if null/empty values are processed
                    if "null" in content.lower() or "undefined" in content.lower():
                        self.vulnerabilities.append(
                            {
                                "type": "null_value_exposure",
                                "severity": "low",
                                "title": "Null/Undefined Value Exposure",
                                "description": "Application exposes internal null/undefined handling in response",
                                "url": test_url,
                                "cwe": "CWE-476",
                                "owasp": "A10:2025 Mishandling of Exceptional Conditions",
                                "remediation": "Handle null values properly without exposing internal details",
                            }
                        )

            except Exception as e:
                logger.debug(f"Error testing input validation for {url}: {e}")

    async def _test_fail_open(self, url: str):
        """Test for fail-open scenarios."""

        # Test authentication bypass via error conditions
        auth_endpoints = ["/api/admin", "/admin", "/dashboard", "/api/protected", "/api/user/profile"]

        for endpoint in auth_endpoints:
            test_url = urljoin(url, endpoint)

            # Test with malformed auth headers
            malformed_headers = [
                {"Authorization": ""},
                {"Authorization": "Bearer "},
                {"Authorization": "Bearer null"},
                {"Authorization": "Bearer undefined"},
                {"Authorization": "Bearer " + "A" * 1000},
                {"Authorization": "InvalidScheme token"},
                {"X-API-Key": ""},
                {"Cookie": "session=; invalid"},
            ]

            for headers in malformed_headers:
                try:
                    response = await self.http_client.get(test_url, headers=headers)

                    if response and response.status_code == 200:
                        self.vulnerabilities.append(
                            {
                                "type": "fail_open",
                                "severity": "critical",
                                "title": "Authentication Bypass via Fail-Open",
                                "description": "Application grants access when authentication fails or is malformed",
                                "url": test_url,
                                "headers": headers,
                                "cwe": "CWE-636",
                                "owasp": "A10:2025 Mishandling of Exceptional Conditions",
                                "remediation": "Implement fail-closed authentication. "
                                "Deny access when authentication cannot be verified.",
                            }
                        )
                        break

                except Exception as e:
                    logger.debug(f"Error testing fail-open scenario for {endpoint}: {e}")

    async def _test_resource_exhaustion(self, url: str):
        """Test for resource exhaustion handling."""

        # Test with large payloads
        large_payloads = [
            {"data": "A" * 100000},  # 100KB string
            {"array": list(range(10000))},  # Large array
            {"nested": {"level" + str(i): {} for i in range(100)}},  # Deep nesting
        ]

        for payload in large_payloads:
            try:
                response = await self.http_client.post(url, json=payload, timeout=10)

                # If server doesn't limit, it might be vulnerable
                if response and response.status_code != 413:  # Not "Payload Too Large"
                    content = response.text if hasattr(response, "text") else ""

                    if "memory" in content.lower() or "heap" in content.lower():
                        self.vulnerabilities.append(
                            {
                                "type": "resource_exhaustion",
                                "severity": "high",
                                "title": "Resource Exhaustion Vulnerability",
                                "description": "Application reveals memory issues when processing large payloads",
                                "url": url,
                                "cwe": "CWE-400",
                                "owasp": "A10:2025 Mishandling of Exceptional Conditions",
                                "remediation": "Implement request size limits and validate input sizes",
                            }
                        )
                        break

            except asyncio.TimeoutError:
                # Timeout might indicate resource issues
                self.vulnerabilities.append(
                    {
                        "type": "potential_dos",
                        "severity": "medium",
                        "title": "Potential DoS via Large Payload",
                        "description": "Application times out when processing large payloads",
                        "url": url,
                        "cwe": "CWE-400",
                        "owasp": "A10:2025 Mishandling of Exceptional Conditions",
                        "remediation": "Implement request size limits and timeout handling",
                    }
                )
                break
            except Exception as e:
                logger.debug(f"Error testing resource exhaustion for {url}: {e}")

    async def _test_exception_bypass(self, url: str):
        """Test for exception handler bypass."""

        # Content-Type manipulation
        content_types = [
            "application/json",
            "application/xml",
            "text/html",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "invalid/type",
            "",
        ]

        for content_type in content_types:
            try:
                headers = {"Content-Type": content_type} if content_type else {}
                response = await self.http_client.post(url, data='{"test": "data"}', headers=headers)

                if response and response.status_code == 500:
                    content = response.text if hasattr(response, "text") else ""

                    # Check for unhandled exception indicators
                    for pattern in self.sensitive_patterns["stack_trace"]:
                        if re.search(pattern, content):
                            self.vulnerabilities.append(
                                {
                                    "type": "unhandled_exception",
                                    "severity": "medium",
                                    "title": "Unhandled Exception with Content-Type Manipulation",
                                    "description": f'Invalid Content-Type "{content_type}" causes unhandled exception',
                                    "url": url,
                                    "content_type": content_type,
                                    "cwe": "CWE-755",
                                    "owasp": "A10:2025 Mishandling of Exceptional Conditions",
                                    "remediation": "Implement proper Content-Type validation and error handling",
                                }
                            )
                            break

            except Exception as e:
                logger.debug(f"Error testing content-type manipulation for {url}: {e}")

        # Test HTTP method handling
        for method in ["TRACE", "CONNECT", "INVALID"]:
            try:
                response = await self.http_client.request(method, url)

                if response and response.status_code == 500:
                    self.vulnerabilities.append(
                        {
                            "type": "method_exception",
                            "severity": "low",
                            "title": "Improper HTTP Method Exception Handling",
                            "description": f'HTTP method "{method}" causes server error',
                            "url": url,
                            "method": method,
                            "cwe": "CWE-749",
                            "owasp": "A10:2025 Mishandling of Exceptional Conditions",
                            "remediation": "Return 405 Method Not Allowed instead of 500 errors",
                        }
                    )

            except Exception as e:
                logger.debug(f"Error testing HTTP method handling for {url}: {e}")

    def _calculate_risk_level(self) -> str:
        """Calculate overall risk level based on findings."""
        if not self.vulnerabilities:
            return "info"

        severities = [v.get("severity", "info") for v in self.vulnerabilities]

        if "critical" in severities:
            return "critical"
        elif "high" in severities:
            return "high"
        elif "medium" in severities:
            return "medium"
        elif "low" in severities:
            return "low"
        return "info"
