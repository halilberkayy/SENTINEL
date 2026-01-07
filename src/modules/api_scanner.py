"""
Advanced API security assessment module.
"""

import logging
from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin, urlparse

from .base_scanner import BaseScanner, Vulnerability

logger = logging.getLogger(__name__)


class ApiScanner(BaseScanner):
    """Professional API security module for REST and GraphQL."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "ApiScanner"
        self.description = "Advanced API Security Assessment"
        self.version = "1.0.0"
        self.capabilities = ["GraphQL Introspection", "Swagger Discovery", "Auth Bypass", "Insecure Methods"]

        self.common_paths = [
            "/api",
            "/api/v1",
            "/api/v2",
            "/graphql",
            "/swagger.json",
            "/openapi.json",
            "/v1/users",
            "/api/debug",
        ]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform API security scan."""
        logger.info(f"Scanning API for {url}")
        vulnerabilities = []
        discovered_endpoints = []

        try:
            self._update_progress(progress_callback, 10, "Discovering API surface")

            # 1. Endpoint Discovery
            tasks = [self._check_endpoint(url, path) for path in self.common_paths]
            endpoints = await self._concurrent_task_runner(tasks, concurrency_limit=10)
            discovered_endpoints = [e for e in endpoints if e]

            if not discovered_endpoints:
                return self._format_result("Clean", "No obvious API endpoints found", [])

            # 2. Vulnerability Testing
            self._update_progress(progress_callback, 50, "Testing for API vulnerabilities")

            for endpoint in discovered_endpoints:
                # a) Test GraphQL Introspection
                if "graphql" in endpoint["path"].lower():
                    vuln = await self._test_graphql_introspection(endpoint["url"])
                    if vuln:
                        vulnerabilities.append(vuln)

                # b) Test Insecure Methods
                methods_vuln = await self._test_methods(endpoint["url"])
                if methods_vuln:
                    vulnerabilities.append(methods_vuln)

                # c) Test Auth Bypass on protected endpoints
                if endpoint["status"] in [401, 403]:
                    auth_vuln = await self._test_auth_bypass(endpoint["url"])
                    if auth_vuln:
                        vulnerabilities.append(auth_vuln)

            self._update_progress(progress_callback, 100, "completed")
            status = "Vulnerable" if vulnerabilities else "Clean"
            return self._format_result(
                status, f"Found {len(discovered_endpoints)} endpoints, {len(vulnerabilities)} issues.", vulnerabilities
            )

        except Exception as e:
            logger.exception(f"API scan failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])

    async def _check_endpoint(self, base_url: str, path: str) -> dict | None:
        target = urljoin(base_url, path)
        try:
            response = await self.http_client.get(target)
            if response and response.status < 500:
                return {"path": path, "url": target, "status": response.status}
        except Exception as e:
            logger.debug(f"Endpoint check failed for {target}: {e}")
        return None

    async def _test_graphql_introspection(self, url: str) -> Vulnerability | None:
        query = {"query": "{ __schema { types { name } } }"}
        try:
            response = await self.http_client.post(url, json=query)
            if response and response.status == 200:
                content = await response.json()
                if "data" in content and "__schema" in content["data"]:
                    return self._create_vulnerability(
                        title="GraphQL Introspection Enabled",
                        description="The GraphQL API permits introspection, allowing full schema discovery.",
                        severity="medium",
                        type="api_info",
                        evidence={"url": url},
                        cwe_id="CWE-200",
                        remediation="Disable introspection in production environments.",
                    )
        except Exception as e:
            logger.debug(f"GraphQL introspection test failed for {url}: {e}")
        return None

    async def _test_methods(self, url: str) -> Vulnerability | None:
        dangerous_methods = ["PUT", "DELETE", "PATCH"]
        found = []
        for method in dangerous_methods:
            try:
                response = await self.http_client.request(method, url)
                if response and response.status not in [404, 405]:
                    found.append(method)
            except Exception as e:
                logger.debug(f"Method test {method} failed for {url}: {e}")

        if found:
            return self._create_vulnerability(
                title="Insecure HTTP Methods Enabled",
                description=f"Dangerous HTTP methods {found} are enabled on this API endpoint.",
                severity="low",
                type="api_misconfig",
                evidence={"url": url, "methods": found},
                cwe_id="CWE-16",
                remediation="Only allow necessary HTTP methods (GET, POST).",
            )
        return None

    async def _test_auth_bypass(self, url: str) -> Vulnerability | None:
        headers_to_try = [
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Original-URL": urlparse(url).path},
            {"X-Rewrite-URL": urlparse(url).path},
        ]
        for headers in headers_to_try:
            try:
                response = await self.http_client.get(url, headers=headers)
                if response and response.status == 200:
                    return self._create_vulnerability(
                        title="API Authentication Bypass",
                        description="Authentication can be bypassed using custom headers.",
                        severity="high",
                        type="api_auth",
                        evidence={"url": url, "bypass_header": headers},
                        cwe_id="CWE-287",
                        remediation="Ensure the backend correctly validates authentication and does not trust client-supplied override headers.",
                    )
            except Exception as e:
                logger.debug(f"Auth bypass test failed for {url} with headers {headers}: {e}")
        return None
