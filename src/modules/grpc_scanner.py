"""
gRPC Security Scanner Module
Detects security vulnerabilities in gRPC services.
"""

import asyncio
import logging
from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin

from .base_scanner import BaseScanner, Vulnerability

logger = logging.getLogger(__name__)


class GRPCScanner(BaseScanner):
    """
    gRPC security assessment module.

    Capabilities:
    - gRPC endpoint discovery
    - Reflection API abuse detection
    - Authentication bypass testing
    - Proto file exposure
    - gRPC-Web security testing
    """

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "GRPCScanner"
        self.description = "Detects gRPC security vulnerabilities"
        self.version = "1.0.0"

        # Common gRPC paths
        self.grpc_paths = [
            "/grpc",
            "/grpc/",
            "/grpc-web",
            "/grpc.health.v1.Health/Check",
            "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
            "/api/grpc",
            "/rpc",
        ]

        # gRPC-Web content types
        self.grpc_content_types = [
            "application/grpc",
            "application/grpc+proto",
            "application/grpc-web",
            "application/grpc-web+proto",
            "application/grpc-web-text",
        ]

        # Proto file paths
        self.proto_paths = [
            "/proto/",
            "/protos/",
            "/.proto/",
            "/api.proto",
            "/service.proto",
            "/grpc.proto",
            "/schema.proto",
        ]

        # Reflection methods
        self.reflection_methods = [
            "ServerReflectionInfo",
            "ListServices",
            "FileByFilename",
            "FileContainingSymbol",
        ]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform gRPC security scan."""
        logger.info(f"Starting gRPC scan on {url}")
        vulnerabilities = []
        grpc_endpoints = []

        try:
            self._update_progress(progress_callback, 10, "Discovering gRPC endpoints")

            # 1. Discover gRPC endpoints
            endpoints = await self._discover_grpc_endpoints(url)
            grpc_endpoints = endpoints

            self._update_progress(progress_callback, 30, "Testing reflection API")

            # 2. Test for reflection API exposure
            if grpc_endpoints:
                reflection_vulns = await self._test_reflection_api(url, grpc_endpoints)
                vulnerabilities.extend(reflection_vulns)

            self._update_progress(progress_callback, 50, "Checking proto file exposure")

            # 3. Check for exposed proto files
            proto_vulns = await self._check_proto_exposure(url)
            vulnerabilities.extend(proto_vulns)

            self._update_progress(progress_callback, 70, "Testing gRPC-Web security")

            # 4. Test gRPC-Web specific vulnerabilities
            grpc_web_vulns = await self._test_grpc_web(url)
            vulnerabilities.extend(grpc_web_vulns)

            self._update_progress(progress_callback, 90, "Checking authentication")

            # 5. Test authentication requirements
            auth_vulns = await self._test_authentication(url, grpc_endpoints)
            vulnerabilities.extend(auth_vulns)

            self._update_progress(progress_callback, 100, "completed")

            status = "Vulnerable" if vulnerabilities else "Clean"
            details = f"Found {len(grpc_endpoints)} gRPC endpoints, {len(vulnerabilities)} issues"

            return self._format_result(status, details, vulnerabilities)

        except Exception as e:
            logger.exception(f"gRPC scan failed: {e}")
            return self._format_result("Error", f"Scan failed: {e}", [])

    async def _discover_grpc_endpoints(self, url: str) -> list[str]:
        """Discover gRPC endpoints."""
        discovered = []

        for path in self.grpc_paths:
            try:
                test_url = urljoin(url, path)

                # Test with gRPC headers
                headers = {
                    "Content-Type": "application/grpc-web+proto",
                    "X-Grpc-Web": "1",
                    "Accept": "application/grpc-web-text+proto",
                }

                response = await self.http_client.post(test_url, headers=headers, data=b"")

                if response:
                    content_type = response.headers.get("content-type", "").lower()

                    # Check for gRPC indicators
                    if (
                        response.status in [200, 400, 415]
                        or any(ct in content_type for ct in self.grpc_content_types)
                        or "grpc-status" in [h.lower() for h in response.headers.keys()]
                    ):
                        discovered.append(test_url)

            except Exception as e:
                logger.debug(f"gRPC discovery failed for {path}: {e}")

        return discovered

    async def _test_reflection_api(self, url: str, endpoints: list[str]) -> list[Vulnerability]:
        """Test for gRPC reflection API exposure."""
        vulnerabilities = []

        # Common reflection endpoints
        reflection_paths = [
            "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
            "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
        ]

        for path in reflection_paths:
            try:
                test_url = urljoin(url, path)

                headers = {
                    "Content-Type": "application/grpc-web+proto",
                    "X-Grpc-Web": "1",
                }

                # Reflection request payload (simplified)
                payload = b"\x00\x00\x00\x00\x02\n\x00"  # ListServices request

                response = await self.http_client.post(test_url, headers=headers, data=payload)

                if response and response.status in [200, 204]:
                    content = await response.text()

                    # Check if reflection returned service info
                    if content and len(content) > 10:
                        vulnerabilities.append(
                            self._create_vulnerability(
                                title="gRPC Reflection API Exposed",
                                description="The gRPC Reflection API is publicly accessible. This allows attackers to discover all available gRPC services, methods, and message types without authentication.",
                                severity="high",
                                type="grpc_reflection",
                                evidence={"url": test_url, "response_length": len(content)},
                                cwe_id="CWE-200",
                                remediation="Disable gRPC reflection in production or restrict access to authenticated clients only.",
                            )
                        )
                        break

            except Exception as e:
                logger.debug(f"Reflection test failed: {e}")

        return vulnerabilities

    async def _check_proto_exposure(self, url: str) -> list[Vulnerability]:
        """Check for exposed proto files."""
        vulnerabilities = []

        for path in self.proto_paths:
            try:
                test_url = urljoin(url, path)
                response = await self.http_client.get(test_url)

                if response and response.status == 200:
                    content = await response.text()

                    # Check for proto file content
                    proto_indicators = ['syntax = "proto', "message ", "service ", "rpc ", "package "]

                    if any(indicator in content for indicator in proto_indicators):
                        vulnerabilities.append(
                            self._create_vulnerability(
                                title=f"Proto File Exposed: {path}",
                                description="Protocol Buffer definition files are publicly accessible. These files reveal the API structure, message types, and service definitions.",
                                severity="medium",
                                type="proto_exposure",
                                evidence={"url": test_url, "content_preview": content[:300]},
                                cwe_id="CWE-200",
                                remediation="Remove proto files from the web root or restrict access.",
                            )
                        )

            except Exception as e:
                logger.debug(f"Proto check failed for {path}: {e}")

        return vulnerabilities

    async def _test_grpc_web(self, url: str) -> list[Vulnerability]:
        """Test gRPC-Web specific vulnerabilities."""
        vulnerabilities = []

        # Check for CORS misconfiguration on gRPC-Web endpoints
        grpc_web_paths = ["/grpc-web", "/grpc", "/api/grpc"]

        for path in grpc_web_paths:
            try:
                test_url = urljoin(url, path)

                # Test with malicious origin
                headers = {
                    "Origin": "https://evil.com",
                    "Content-Type": "application/grpc-web+proto",
                }

                response = await self.http_client.options(test_url, headers=headers)

                if response:
                    acao = response.headers.get("Access-Control-Allow-Origin", "")

                    if acao == "*" or "evil.com" in acao:
                        vulnerabilities.append(
                            self._create_vulnerability(
                                title="gRPC-Web CORS Misconfiguration",
                                description="The gRPC-Web endpoint has overly permissive CORS settings, allowing cross-origin requests from any domain.",
                                severity="medium",
                                type="grpc_cors",
                                evidence={"url": test_url, "acao_header": acao},
                                cwe_id="CWE-942",
                                remediation="Configure strict CORS policy to allow only trusted origins.",
                            )
                        )
                        break

            except Exception as e:
                logger.debug(f"gRPC-Web test failed: {e}")

        return vulnerabilities

    async def _test_authentication(self, url: str, endpoints: list[str]) -> list[Vulnerability]:
        """Test authentication requirements on gRPC endpoints."""
        vulnerabilities = []

        for endpoint in endpoints[:3]:  # Limit testing
            try:
                headers = {
                    "Content-Type": "application/grpc-web+proto",
                    "X-Grpc-Web": "1",
                }

                # Try without authentication
                response = await self.http_client.post(endpoint, headers=headers, data=b"\x00\x00\x00\x00\x00")

                if response and response.status == 200:
                    grpc_status = response.headers.get("grpc-status", "")

                    # Status 0 = OK, no auth required
                    if grpc_status == "0" or grpc_status == "":
                        vulnerabilities.append(
                            self._create_vulnerability(
                                title="gRPC Endpoint Without Authentication",
                                description=f"The gRPC endpoint at {endpoint} is accessible without authentication.",
                                severity="medium",
                                type="grpc_no_auth",
                                evidence={"endpoint": endpoint, "grpc_status": grpc_status},
                                cwe_id="CWE-306",
                                remediation="Implement proper authentication for gRPC services using JWT tokens, mTLS, or API keys.",
                            )
                        )

            except Exception as e:
                logger.debug(f"Auth test failed for {endpoint}: {e}")

        return vulnerabilities

    async def _concurrent_task_runner(self, tasks, concurrency_limit=5):
        """Run tasks concurrently with limit."""
        semaphore = asyncio.Semaphore(concurrency_limit)

        async def limited_task(task):
            async with semaphore:
                return await task

        return await asyncio.gather(*[limited_task(t) for t in tasks], return_exceptions=True)
