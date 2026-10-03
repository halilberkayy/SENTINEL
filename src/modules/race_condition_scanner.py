"""
Race Condition Scanner module - Advanced Implementation.
"""

import asyncio
import logging
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin

from .base_scanner import BaseScanner, Vulnerability

logger = logging.getLogger(__name__)


class RaceConditionScanner(BaseScanner):
    """Advanced Race Condition vulnerability detection engine."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "RaceConditionScanner"
        self.description = "Detects TOCTOU, double-spend, and parallel request vulnerabilities"
        self.version = "1.0.0"
        self.capabilities = [
            "Parallel Request Testing",
            "TOCTOU Detection",
            "Double-Spend Analysis",
            "File Upload Race",
            "Session Race Condition",
            "Last-Write-Wins Detection",
        ]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform race condition vulnerability scan."""
        logger.info(f"Scanning {url} for race condition vulnerabilities")
        vulnerabilities = []

        try:
            self._update_progress(progress_callback, 10, "Extracting forms and endpoints")

            response = await self.http_client.get(url)
            if not response:
                return self._format_result("Error", "Target unreachable", [])

            html = await response.text()
            soup = await self._parse_html(html)

            # 1. Find state-changing endpoints
            self._update_progress(progress_callback, 25, "Identifying state-changing operations")
            endpoints = self._find_state_changing_endpoints(soup, url)

            # 2. Test parallel requests
            self._update_progress(progress_callback, 40, "Testing parallel requests")
            parallel_vulns = await self._test_parallel_requests(endpoints)
            vulnerabilities.extend(parallel_vulns)

            # 3. Test for response timing differences
            self._update_progress(progress_callback, 60, "Analyzing response timing")
            timing_vulns = await self._test_timing_differences(url)
            vulnerabilities.extend(timing_vulns)

            # 4. Check for lock-free data structures
            self._update_progress(progress_callback, 80, "Checking synchronization issues")
            sync_vulns = await self._check_synchronization_issues(url)
            vulnerabilities.extend(sync_vulns)

            self._update_progress(progress_callback, 100, "completed")

            status = "Vulnerable" if vulnerabilities else "Secure"
            details = f"Tested {len(endpoints)} endpoints. Found {len(vulnerabilities)} race condition issues."
            return self._format_result(status, details, vulnerabilities)

        except Exception as e:
            logger.exception(f"Race condition scan failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])

    def _find_state_changing_endpoints(self, soup, url: str) -> list[dict[str, Any]]:
        """Find forms and endpoints that change state."""
        endpoints = []

        # Find POST forms
        forms = soup.find_all("form", method=lambda x: x and x.lower() == "post")
        for form in forms:
            action = form.get("action", "")
            form_url = urljoin(url, action) if action else url

            # Extract form fields
            fields = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                value = inp.get("value", "")
                if name:
                    fields[name] = value

            # Identify sensitive operations
            form_text = str(form).lower()
            operation_type = "unknown"

            if any(x in form_text for x in ["password", "passwd"]):
                operation_type = "password_change"
            elif any(x in form_text for x in ["transfer", "send", "pay", "amount"]):
                operation_type = "financial"
            elif any(x in form_text for x in ["delete", "remove"]):
                operation_type = "delete"
            elif any(x in form_text for x in ["add", "create", "register"]):
                operation_type = "create"
            elif any(x in form_text for x in ["coupon", "discount", "promo"]):
                operation_type = "coupon"
            elif any(x in form_text for x in ["vote", "like", "rate"]):
                operation_type = "voting"

            endpoints.append({"url": form_url, "method": "POST", "fields": fields, "type": operation_type})

        return endpoints[:10]  # Limit endpoints

    async def _test_parallel_requests(self, endpoints: list[dict[str, Any]]) -> list[Vulnerability]:
        """Test endpoints with parallel requests."""
        findings = []

        for endpoint in endpoints:
            if endpoint["type"] in ["financial", "coupon", "voting", "create"]:
                try:
                    # Send multiple requests in parallel
                    num_requests = 10
                    tasks = []

                    for _ in range(num_requests):
                        task = self.http_client.post(endpoint["url"], data=endpoint["fields"])
                        tasks.append(task)

                    # Execute all requests simultaneously
                    start_time = time.time()
                    responses = await asyncio.gather(*tasks, return_exceptions=True)
                    elapsed = time.time() - start_time

                    # Analyze responses
                    success_count = sum(
                        1
                        for r in responses
                        if r and not isinstance(r, Exception) and hasattr(r, "status") and r.status < 400
                    )

                    # If multiple requests succeeded with similar timing, potential race condition
                    if success_count > 1 and elapsed < 2.0:
                        severity = "high" if endpoint["type"] == "financial" else "medium"

                        findings.append(
                            self._create_vulnerability(
                                title=f"Potential Race Condition: {endpoint['type'].replace('_', ' ').title()}",
                                description=f"Parallel requests to {endpoint['url']} were processed simultaneously. {success_count}/{num_requests} succeeded in {elapsed:.2f}s.",
                                severity=severity,
                                type=f"race_condition_{endpoint['type']}",
                                evidence={
                                    "url": endpoint["url"],
                                    "operation": endpoint["type"],
                                    "success_count": success_count,
                                    "total_requests": num_requests,
                                    "elapsed_time": elapsed,
                                },
                                cwe_id="CWE-362",
                                remediation="Implement proper locking mechanisms. Use database transactions with appropriate isolation levels. Add mutex/semaphore for critical sections.",
                            )
                        )

                except Exception as e:
                    logger.debug(f"Parallel request test error: {e}")

        return findings

    async def _test_timing_differences(self, url: str) -> list[Vulnerability]:
        """Test for timing-based race conditions."""
        findings = []

        try:
            # Send requests with slight delays
            times = []

            for _i in range(5):
                start = time.time()
                await self.http_client.get(url)
                elapsed = time.time() - start
                times.append(elapsed)
                await asyncio.sleep(0.1)

            # Check for significant timing variations
            avg_time = sum(times) / len(times)
            variance = sum((t - avg_time) ** 2 for t in times) / len(times)

            if variance > 0.5:  # High variance indicates potential issues
                findings.append(
                    self._create_vulnerability(
                        title="High Response Time Variance",
                        description=f"Significant timing variance detected ({variance:.2f}s²). This may indicate concurrent processing issues.",
                        severity="info",
                        type="timing_variance",
                        evidence={"average_time": avg_time, "variance": variance, "samples": times},
                        cwe_id="CWE-362",
                        remediation="Investigate why response times vary significantly. May indicate shared resource contention.",
                    )
                )

        except Exception as e:
            logger.debug(f"Timing test error: {e}")

        return findings

    async def _check_synchronization_issues(self, url: str) -> list[Vulnerability]:
        """Check for synchronization-related issues."""
        findings = []

        try:
            # Send multiple requests rapidly
            rapid_tasks = []
            for _ in range(20):
                rapid_tasks.append(self.http_client.get(url))

            responses = await asyncio.gather(*rapid_tasks, return_exceptions=True)

            # Check for inconsistent responses
            response_bodies = []
            for r in responses:
                if r and not isinstance(r, Exception) and hasattr(r, "text"):
                    try:
                        body = await r.text()
                        response_bodies.append(len(body))
                    except Exception as e:
                        logger.debug(f"Error reading response body: {e}")

            if response_bodies:
                unique_sizes = len(set(response_bodies))

                if unique_sizes > 3:  # Multiple different response sizes
                    findings.append(
                        self._create_vulnerability(
                            title="Inconsistent Response Under Load",
                            description=f"Detected {unique_sizes} different response sizes under concurrent load. May indicate race condition or caching issues.",
                            severity="low",
                            type="inconsistent_response",
                            evidence={
                                "unique_response_sizes": unique_sizes,
                                "sample_sizes": list(set(response_bodies))[:5],
                            },
                            cwe_id="CWE-362",
                            remediation="Review caching and session handling logic for thread-safety.",
                        )
                    )

        except Exception as e:
            logger.debug(f"Synchronization check error: {e}")

        return findings
