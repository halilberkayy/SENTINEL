"""
Mobile API Security Scanner Module
Detects mobile-specific API security vulnerabilities.
"""

import logging
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin

from .base_scanner import BaseScanner, Vulnerability

logger = logging.getLogger(__name__)


class MobileAPIScanner(BaseScanner):
    """
    Mobile API security assessment module.

    Capabilities:
    - Mobile-specific header testing
    - Certificate pinning bypass detection
    - Root/Jailbreak detection bypass
    - Mobile authentication vulnerabilities
    - Deep link security testing
    - API versioning issues
    """

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "MobileAPIScanner"
        self.description = "Detects mobile API security vulnerabilities"
        self.version = "1.0.0"

        # Mobile user agents
        self.mobile_user_agents = {
            "ios": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
            "android": "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36",
            "ios_app": "MyApp/1.0 CFNetwork/1399 Darwin/22.1.0",
            "android_app": "okhttp/4.10.0",
        }

        # Mobile-specific headers
        self.mobile_headers = {
            "X-Device-Id": "test-device-id-12345",
            "X-App-Version": "1.0.0",
            "X-Platform": "iOS",
            "X-Device-Model": "iPhone14,2",
            "X-OS-Version": "16.0",
            "X-Bundle-Id": "com.test.app",
            "X-Install-Id": "install-uuid-12345",
        }

        # Common mobile API paths
        self.mobile_api_paths = [
            "/api/mobile/",
            "/mobile/api/",
            "/v1/mobile/",
            "/api/app/",
            "/app/api/",
            "/api/v1/device/",
            "/api/v1/auth/mobile",
            "/api/register-device",
            "/api/push-token",
        ]

        # Deep link schemes to test
        self.deeplink_patterns = [
            "myapp://",
            "app://",
            "intent://",
        ]

        # Root/Jailbreak bypass headers
        self.bypass_headers = [
            {"X-Jailbreak": "false"},
            {"X-Rooted": "false"},
            {"X-Device-Integrity": "true"},
            {"X-Safetynet-Attestation": "valid"},
            {"X-App-Attest": "verified"},
        ]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform mobile API security scan."""
        logger.info(f"Starting mobile API scan on {url}")
        vulnerabilities = []
        mobile_endpoints = []

        try:
            self._update_progress(progress_callback, 10, "Discovering mobile endpoints")

            # 1. Discover mobile API endpoints
            endpoints = await self._discover_mobile_endpoints(url)
            mobile_endpoints = endpoints

            self._update_progress(progress_callback, 25, "Testing mobile headers")

            # 2. Test mobile-specific header vulnerabilities
            header_vulns = await self._test_mobile_headers(url)
            vulnerabilities.extend(header_vulns)

            self._update_progress(progress_callback, 40, "Testing device ID vulnerabilities")

            # 3. Test device ID manipulation
            device_vulns = await self._test_device_id_manipulation(url)
            vulnerabilities.extend(device_vulns)

            self._update_progress(progress_callback, 55, "Testing root/jailbreak bypass")

            # 4. Test root/jailbreak detection bypass
            bypass_vulns = await self._test_root_jailbreak_bypass(url)
            vulnerabilities.extend(bypass_vulns)

            self._update_progress(progress_callback, 70, "Testing API versioning")

            # 5. Test API versioning issues
            version_vulns = await self._test_api_versioning(url)
            vulnerabilities.extend(version_vulns)

            self._update_progress(progress_callback, 85, "Checking deep links")

            # 6. Check for deep link vulnerabilities
            deeplink_vulns = await self._test_deep_links(url)
            vulnerabilities.extend(deeplink_vulns)

            self._update_progress(progress_callback, 100, "completed")

            status = "Vulnerable" if vulnerabilities else "Clean"
            details = f"Found {len(mobile_endpoints)} mobile endpoints, {len(vulnerabilities)} issues"

            return self._format_result(status, details, vulnerabilities)

        except Exception as e:
            logger.exception(f"Mobile API scan failed: {e}")
            return self._format_result("Error", f"Scan failed: {e}", [])

    async def _discover_mobile_endpoints(self, url: str) -> list[str]:
        """Discover mobile API endpoints."""
        discovered = []

        for path in self.mobile_api_paths:
            try:
                test_url = urljoin(url, path)

                headers = {"User-Agent": self.mobile_user_agents["ios_app"], **self.mobile_headers}

                response = await self.http_client.get(test_url, headers=headers)

                if response and response.status in [200, 401, 403]:
                    discovered.append(test_url)

            except Exception as e:
                logger.debug(f"Mobile endpoint discovery failed for {path}: {e}")

        return discovered

    async def _test_mobile_headers(self, url: str) -> list[Vulnerability]:
        """Test for mobile-specific header vulnerabilities."""
        vulnerabilities = []

        # Test if mobile headers affect response
        test_endpoints = [url, urljoin(url, "/api/"), urljoin(url, "/api/v1/")]

        for endpoint in test_endpoints:
            try:
                # Request without mobile headers
                response_normal = await self.http_client.get(endpoint)

                # Request with mobile headers
                mobile_headers = {"User-Agent": self.mobile_user_agents["android_app"], **self.mobile_headers}
                response_mobile = await self.http_client.get(endpoint, headers=mobile_headers)

                if response_normal and response_mobile:
                    # Check if mobile request gets different/more permissive response
                    if response_mobile.status == 200 and response_normal.status in [401, 403]:
                        vulnerabilities.append(
                            self._create_vulnerability(
                                title="Mobile User-Agent Bypasses Authentication",
                                description="The API returns different responses based on mobile User-Agent headers, potentially bypassing security controls.",
                                severity="high",
                                type="mobile_ua_bypass",
                                evidence={
                                    "endpoint": endpoint,
                                    "normal_status": response_normal.status,
                                    "mobile_status": response_mobile.status,
                                },
                                cwe_id="CWE-290",
                                remediation="Do not rely on User-Agent for security decisions. Implement proper authentication for all clients.",
                            )
                        )

            except Exception as e:
                logger.debug(f"Mobile header test failed: {e}")

        return vulnerabilities

    async def _test_device_id_manipulation(self, url: str) -> list[Vulnerability]:
        """Test for device ID manipulation vulnerabilities."""
        vulnerabilities = []

        # Test endpoints that might use device ID
        endpoints = [
            urljoin(url, "/api/device/info"),
            urljoin(url, "/api/user/devices"),
            urljoin(url, "/api/v1/device"),
        ]

        device_ids_to_test = [
            "admin-device",
            "00000000-0000-0000-0000-000000000000",
            "../../../etc/passwd",
            "'; DROP TABLE devices;--",
        ]

        for endpoint in endpoints:
            for device_id in device_ids_to_test:
                try:
                    headers = {
                        "X-Device-Id": device_id,
                        "User-Agent": self.mobile_user_agents["android"],
                    }

                    response = await self.http_client.get(endpoint, headers=headers)

                    if response and response.status == 200:
                        content = await response.text()

                        # Check for signs of injection or privilege escalation
                        if "admin" in content.lower() or "root" in content.lower() or "error" in content.lower():
                            vulnerabilities.append(
                                self._create_vulnerability(
                                    title="Device ID Manipulation Vulnerability",
                                    description="The API may be vulnerable to device ID manipulation, potentially allowing access to other users' data.",
                                    severity="high",
                                    type="device_id_manipulation",
                                    evidence={"endpoint": endpoint, "malicious_device_id": device_id},
                                    cwe_id="CWE-639",
                                    remediation="Validate and sanitize device IDs. Use cryptographically secure device identifiers.",
                                )
                            )
                            return vulnerabilities  # Found, stop testing

                except Exception as e:
                    logger.debug(f"Device ID test failed: {e}")

        return vulnerabilities

    async def _test_root_jailbreak_bypass(self, url: str) -> list[Vulnerability]:
        """Test for root/jailbreak detection bypass."""
        vulnerabilities = []

        # Check if the app has root/jailbreak detection
        test_url = urljoin(url, "/api/v1/auth/login")

        for bypass_header in self.bypass_headers:
            try:
                headers = {"User-Agent": self.mobile_user_agents["android_app"], **bypass_header, **self.mobile_headers}

                # Test login endpoint
                response = await self.http_client.post(
                    test_url, headers=headers, json={"username": "test", "password": "test"}
                )

                if response:
                    content = await response.text()

                    # Check if response indicates rooted device check
                    if any(term in content.lower() for term in ["rooted", "jailbreak", "integrity", "tampered"]):
                        # Check if our bypass header worked
                        if response.status != 403:
                            vulnerabilities.append(
                                self._create_vulnerability(
                                    title="Root/Jailbreak Detection Can Be Bypassed",
                                    description="The application's root/jailbreak detection can be bypassed by manipulating HTTP headers.",
                                    severity="medium",
                                    type="root_detection_bypass",
                                    evidence={"endpoint": test_url, "bypass_header": bypass_header},
                                    cwe_id="CWE-919",
                                    remediation="Implement server-side device attestation (SafetyNet/App Attest). Do not rely solely on client-provided headers.",
                                )
                            )
                            break

            except Exception as e:
                logger.debug(f"Root bypass test failed: {e}")

        return vulnerabilities

    async def _test_api_versioning(self, url: str) -> list[Vulnerability]:
        """Test for API versioning issues."""
        vulnerabilities = []

        # Check for deprecated/old API versions that might have vulnerabilities
        api_versions = ["v1", "v2", "v3", "v0", "beta", "alpha", "dev", "test"]

        for version in api_versions:
            try:
                test_url = urljoin(url, f"/api/{version}/")
                response = await self.http_client.get(test_url)

                if response and response.status == 200:
                    content = await response.text()

                    # Check for deprecated version indicators
                    if any(term in content.lower() for term in ["deprecated", "legacy", "old", "beta", "test"]):
                        vulnerabilities.append(
                            self._create_vulnerability(
                                title=f"Deprecated API Version Accessible: {version}",
                                description=f"The deprecated API version '{version}' is still accessible. Old API versions may contain unpatched vulnerabilities.",
                                severity="low",
                                type="deprecated_api",
                                evidence={"url": test_url, "version": version},
                                cwe_id="CWE-477",
                                remediation=f"Disable or remove the deprecated API version {version}.",
                            )
                        )

            except Exception as e:
                logger.debug(f"API version test failed for {version}: {e}")

        return vulnerabilities

    async def _test_deep_links(self, url: str) -> list[Vulnerability]:
        """Test for deep link security issues."""
        vulnerabilities = []

        # Check if the web app exposes deep link schemes
        try:
            response = await self.http_client.get(url)

            if response and response.status == 200:
                content = await response.text()

                # Look for deep link patterns in HTML
                for scheme in self.deeplink_patterns:
                    pattern = rf'{scheme}[^\s"\'<>]+'
                    matches = re.findall(pattern, content, re.IGNORECASE)

                    if matches:
                        vulnerabilities.append(
                            self._create_vulnerability(
                                title="Deep Link Scheme Exposed",
                                description="Deep link schemes are exposed in the web content. This may allow attackers to craft malicious deep links.",
                                severity="low",
                                type="deeplink_exposed",
                                evidence={"scheme": scheme, "examples": matches[:3]},
                                cwe_id="CWE-939",
                                remediation="Validate deep link parameters. Implement intent filters with appropriate verification.",
                            )
                        )

        except Exception as e:
            logger.debug(f"Deep link test failed: {e}")

        return vulnerabilities
