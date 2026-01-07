"""
Rate Limiting and DoS Vulnerability Scanner
Detects missing or misconfigured rate limiting protections.
"""

import asyncio
import logging
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin

from .base_scanner import BaseScanner, Vulnerability

logger = logging.getLogger(__name__)


class RateLimitScanner(BaseScanner):
    """
    Rate limiting and resource exhaustion assessment module.

    Capabilities:
    - Rate limit detection and bypass testing
    - Missing rate limit identification
    - Resource exhaustion testing (careful!)
    - Brute force protection testing
    - API rate limit analysis
    """

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "RateLimitScanner"
        self.description = "Detects rate limiting vulnerabilities and DoS risks"
        self.version = "1.0.0"

        # Endpoints typically requiring rate limiting
        self.sensitive_endpoints = [
            "/login",
            "/api/login",
            "/auth",
            "/api/auth",
            "/signin",
            "/register",
            "/signup",
            "/api/register",
            "/forgot-password",
            "/reset-password",
            "/api/password/reset",
            "/api/token",
            "/oauth/token",
            "/api/v1/auth",
            "/api/v1/login",
            "/2fa",
            "/verify",
            "/otp",
            "/sms/send",
            "/email/send",
        ]

        # Rate limit bypass techniques
        self.bypass_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-For": "10.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Original-Forwarded-For": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"True-Client-IP": "127.0.0.1"},
            {"CF-Connecting-IP": "127.0.0.1"},
            {"X-Cluster-Client-IP": "127.0.0.1"},
            {"X-Remote-Addr": "127.0.0.1"},
        ]

        # Rate limit indicators
        self.rate_limit_headers = [
            "x-ratelimit-limit",
            "x-ratelimit-remaining",
            "x-ratelimit-reset",
            "x-rate-limit-limit",
            "x-rate-limit-remaining",
            "retry-after",
            "ratelimit-limit",
            "ratelimit-remaining",
            "x-ratelimit-requests-limit",
            "x-ratelimit-requests-remaining",
        ]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform rate limiting security scan."""
        logger.info(f"Starting rate limit scan on {url}")
        vulnerabilities = []

        try:
            self._update_progress(progress_callback, 10, "Detecting rate limit headers")

            # 1. Analyze rate limit headers on main endpoint
            header_analysis = await self._analyze_rate_limit_headers(url)

            self._update_progress(progress_callback, 30, "Testing sensitive endpoints")

            # 2. Check sensitive endpoints for rate limiting
            sensitive_vulns = await self._check_sensitive_endpoints(url)
            vulnerabilities.extend(sensitive_vulns)

            self._update_progress(progress_callback, 55, "Testing bypass techniques")

            # 3. Test rate limit bypass techniques
            bypass_vulns = await self._test_bypass_techniques(url)
            vulnerabilities.extend(bypass_vulns)

            self._update_progress(progress_callback, 80, "Checking API endpoints")

            # 4. Check for API endpoint rate limits
            api_vulns = await self._check_api_rate_limits(url)
            vulnerabilities.extend(api_vulns)

            self._update_progress(progress_callback, 100, "completed")

            status = "Vulnerable" if vulnerabilities else "Clean"
            details = f"Found {len(vulnerabilities)} rate limiting issues"

            if header_analysis.get("has_rate_limiting"):
                details += f". Rate limits detected: {header_analysis.get('limit', 'unknown')}"

            return self._format_result(status, details, vulnerabilities)

        except Exception as e:
            logger.exception(f"Rate limit scan failed: {e}")
            return self._format_result("Error", f"Scan failed: {e}", [])

    async def _analyze_rate_limit_headers(self, url: str) -> dict[str, Any]:
        """Analyze rate limit headers in response."""
        result = {"has_rate_limiting": False, "headers_found": [], "limit": None, "remaining": None}

        try:
            response = await self.http_client.get(url)
            if not response:
                return result

            headers = dict(response.headers) if response.headers else {}

            for header in self.rate_limit_headers:
                for response_header, value in headers.items():
                    if header.lower() == response_header.lower():
                        result["has_rate_limiting"] = True
                        result["headers_found"].append({header: value})

                        if "limit" in header.lower() and "remaining" not in header.lower():
                            result["limit"] = value
                        elif "remaining" in header.lower():
                            result["remaining"] = value

        except Exception as e:
            logger.debug(f"Rate limit header analysis failed: {e}")

        return result

    async def _check_sensitive_endpoints(self, url: str) -> list[Vulnerability]:
        """Check sensitive endpoints for rate limiting."""
        vulnerabilities = []

        for endpoint in self.sensitive_endpoints[:10]:  # Limit to avoid abuse
            try:
                test_url = urljoin(url, endpoint)

                # Send burst of requests
                responses = []
                for _i in range(5):  # Small burst to detect
                    response = await self.http_client.get(test_url)
                    if response:
                        responses.append(response.status)
                    await asyncio.sleep(0.1)

                if not responses:
                    continue

                # Check if all requests succeeded (no rate limiting)
                if all(status not in [429, 503] for status in responses):
                    # Check for rate limit headers in response
                    response = await self.http_client.get(test_url)

                    if response:
                        has_rate_headers = any(
                            header.lower() in [h.lower() for h in dict(response.headers).keys()]
                            for header in self.rate_limit_headers
                        )

                        if not has_rate_headers and response.status != 404:
                            vulnerabilities.append(
                                self._create_vulnerability(
                                    title="Missing Rate Limiting on Sensitive Endpoint",
                                    description=f"The endpoint {endpoint} lacks rate limiting protection. This could allow brute force or credential stuffing attacks.",
                                    severity="medium",
                                    type="missing_rate_limit",
                                    evidence={"endpoint": endpoint, "url": test_url, "response_codes": responses},
                                    cwe_id="CWE-307",
                                    remediation=f"Implement rate limiting on {endpoint}. Consider limiting by IP, user session, or API key.",
                                )
                            )

            except Exception as e:
                logger.debug(f"Sensitive endpoint check failed for {endpoint}: {e}")

        return vulnerabilities

    async def _test_bypass_techniques(self, url: str) -> list[Vulnerability]:
        """Test rate limit bypass techniques."""
        vulnerabilities = []

        # First check if rate limiting exists
        initial_headers = await self._analyze_rate_limit_headers(url)

        if not initial_headers.get("has_rate_limiting"):
            return vulnerabilities  # No rate limiting to bypass

        # Test bypass headers
        for bypass_header in self.bypass_headers[:5]:
            try:
                # Send requests with bypass header
                success_count = 0

                for _i in range(3):
                    response = await self.http_client.get(url, headers=bypass_header)

                    if response and response.status not in [429, 503]:
                        success_count += 1

                    await asyncio.sleep(0.1)

                if success_count == 3:
                    # All requests succeeded despite rate limiting
                    header_name = list(bypass_header.keys())[0]

                    vulnerabilities.append(
                        self._create_vulnerability(
                            title="Rate Limit Bypass via Header Manipulation",
                            description=f"Rate limiting can be bypassed using the {header_name} header. Attackers can rotate IP values to avoid rate limits.",
                            severity="medium",
                            type="rate_limit_bypass",
                            evidence={"bypass_header": bypass_header, "url": url},
                            cwe_id="CWE-770",
                            remediation=f"Do not trust {header_name} header for rate limiting. Use actual client IP from the connection.",
                        )
                    )
                    break

            except Exception as e:
                logger.debug(f"Bypass test failed: {e}")

        return vulnerabilities

    async def _check_api_rate_limits(self, url: str) -> list[Vulnerability]:
        """Check API endpoints for rate limits."""
        vulnerabilities = []

        api_paths = [
            "/api",
            "/api/v1",
            "/api/v2",
            "/graphql",
            "/rest",
        ]

        for path in api_paths:
            try:
                test_url = urljoin(url, path)

                # Quick burst test
                time.time()
                response_times = []

                for _i in range(3):
                    req_start = time.time()
                    response = await self.http_client.get(test_url)
                    req_end = time.time()

                    if response:
                        response_times.append(req_end - req_start)

                    await asyncio.sleep(0.05)

                # Check if responses are consistent (no throttling)
                if len(response_times) >= 3:
                    avg_time = sum(response_times) / len(response_times)
                    time_variance = max(response_times) - min(response_times)

                    # If time variance is low and no rate limiting detected
                    if time_variance < 0.5:
                        response = await self.http_client.get(test_url)

                        if response and response.status not in [404, 429]:
                            has_rate_headers = any(
                                header.lower() in [h.lower() for h in dict(response.headers).keys()]
                                for header in self.rate_limit_headers
                            )

                            if not has_rate_headers:
                                vulnerabilities.append(
                                    self._create_vulnerability(
                                        title="API Endpoint Without Rate Limiting",
                                        description=f"The API endpoint at {path} does not appear to have rate limiting. This could lead to API abuse or DoS attacks.",
                                        severity="low",
                                        type="api_no_rate_limit",
                                        evidence={
                                            "endpoint": path,
                                            "url": test_url,
                                            "avg_response_time": f"{avg_time:.3f}s",
                                        },
                                        cwe_id="CWE-799",
                                        remediation="Implement API rate limiting based on API key, user identity, or IP address.",
                                    )
                                )

            except Exception as e:
                logger.debug(f"API rate limit check failed for {path}: {e}")

        return vulnerabilities
