"""
WebSocket Security Scanner Module
Detects WebSocket vulnerabilities and security issues.
"""

import logging
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin, urlparse

from .base_scanner import BaseScanner, Vulnerability

logger = logging.getLogger(__name__)


class WebSocketScanner(BaseScanner):
    """
    WebSocket security assessment module.

    Capabilities:
    - WebSocket endpoint discovery
    - Cross-Site WebSocket Hijacking (CSWSH)
    - Authentication bypass testing
    - Message injection testing
    - Origin validation testing
    """

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "WebSocketScanner"
        self.description = "Detects WebSocket security vulnerabilities"
        self.version = "1.0.0"

        # Common WebSocket paths
        self.ws_paths = [
            "/ws",
            "/ws/",
            "/websocket",
            "/websocket/",
            "/socket",
            "/socket.io/",
            "/sockjs/",
            "/hub",
            "/signalr",
            "/signalr/hubs",
            "/realtime",
            "/live",
            "/stream",
            "/feed",
            "/notifications",
            "/chat",
            "/api/ws",
            "/api/websocket",
            "/cable",  # ActionCable (Rails)
            "/graphql",  # GraphQL subscriptions
        ]

        # Malicious origins for CSWSH testing
        self.malicious_origins = ["https://evil.com", "https://attacker.com", "http://localhost", "null", ""]

        # Message injection payloads
        self.injection_payloads = [
            '{"type":"auth","token":"malicious"}',
            '{"action":"admin","cmd":"getUsers"}',
            "<script>alert(1)</script>",
            '{"__proto__":{"polluted":true}}',
            '{"constructor":{"prototype":{"polluted":true}}}',
        ]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform WebSocket security scan."""
        logger.info(f"Starting WebSocket scan on {url}")
        vulnerabilities = []
        discovered_endpoints = []

        try:
            self._update_progress(progress_callback, 10, "Discovering WebSocket endpoints")

            # 1. Discover WebSocket endpoints
            endpoints = await self._discover_ws_endpoints(url)
            discovered_endpoints = endpoints

            self._update_progress(progress_callback, 40, "Testing for CSWSH")

            # 2. Check for WebSocket references in HTML
            html_endpoints = await self._find_ws_in_html(url)
            for ep in html_endpoints:
                if ep not in discovered_endpoints:
                    discovered_endpoints.append(ep)

            # 3. Test for Cross-Site WebSocket Hijacking
            if discovered_endpoints:
                cswsh_vulns = await self._test_cswsh(url, discovered_endpoints)
                vulnerabilities.extend(cswsh_vulns)

            self._update_progress(progress_callback, 70, "Checking upgrade headers")

            # 4. Test WebSocket upgrade headers
            upgrade_vulns = await self._test_upgrade_security(url, discovered_endpoints)
            vulnerabilities.extend(upgrade_vulns)

            self._update_progress(progress_callback, 90, "Analyzing findings")

            # 5. Check for Socket.IO specific issues
            socketio_vulns = await self._check_socketio(url)
            vulnerabilities.extend(socketio_vulns)

            self._update_progress(progress_callback, 100, "completed")

            status = "Vulnerable" if vulnerabilities else "Clean"
            details = f"Found {len(discovered_endpoints)} WebSocket endpoints, {len(vulnerabilities)} issues"

            return self._format_result(status, details, vulnerabilities)

        except Exception as e:
            logger.exception(f"WebSocket scan failed: {e}")
            return self._format_result("Error", f"Scan failed: {e}", [])

    async def _discover_ws_endpoints(self, url: str) -> list[str]:
        """Discover WebSocket endpoints."""
        discovered = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in self.ws_paths:
            try:
                test_url = urljoin(base, path)
                response = await self.http_client.get(test_url)

                if response:
                    # Check for WebSocket-related responses
                    response.headers.get("content-type", "").lower()
                    upgrade = response.headers.get("upgrade", "").lower()

                    # 101 Switching Protocols or specific responses
                    if response.status in [101, 200, 400]:
                        content = await response.text()

                        # Check for WebSocket indicators
                        if (
                            "websocket" in content.lower()
                            or "socket.io" in content.lower()
                            or "upgrade" in upgrade
                            or response.status == 101
                        ):

                            ws_url = test_url.replace("http://", "ws://").replace("https://", "wss://")
                            discovered.append(ws_url)

            except Exception as e:
                logger.debug(f"WS discovery failed for {path}: {e}")

        return discovered

    async def _find_ws_in_html(self, url: str) -> list[str]:
        """Find WebSocket URLs in HTML/JavaScript."""
        ws_urls = []

        try:
            response = await self.http_client.get(url)
            if not response or response.status != 200:
                return ws_urls

            content = await response.text()

            # Find WebSocket URLs in content
            patterns = [
                r'wss?://[^\s"\'\)>]+',
                r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']',
                r'io\s*\(\s*["\']([^"\']+)["\']',
                r'socket\.connect\s*\(\s*["\']([^"\']+)["\']',
            ]

            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if match.startswith("ws://") or match.startswith("wss://"):
                        ws_urls.append(match)
                    elif match.startswith("/"):
                        parsed = urlparse(url)
                        ws_url = f"{'wss' if parsed.scheme == 'https' else 'ws'}://{parsed.netloc}{match}"
                        ws_urls.append(ws_url)

        except Exception as e:
            logger.debug(f"HTML WS search failed: {e}")

        return list(set(ws_urls))

    async def _test_cswsh(self, url: str, ws_endpoints: list[str]) -> list[Vulnerability]:
        """Test for Cross-Site WebSocket Hijacking."""
        vulnerabilities = []
        urlparse(url)

        for ws_url in ws_endpoints[:3]:  # Limit testing
            for malicious_origin in self.malicious_origins[:3]:
                try:
                    # Convert WS URL to HTTP for testing
                    http_url = ws_url.replace("wss://", "https://").replace("ws://", "http://")

                    # Test with WebSocket upgrade request and malicious origin
                    headers = {
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                        "Sec-WebSocket-Version": "13",
                        "Origin": malicious_origin,
                    }

                    response = await self.http_client.get(http_url, headers=headers)

                    if response:
                        # Check if the server accepts the malicious origin
                        if response.status in [101, 200]:
                            # Check Access-Control headers
                            acao = response.headers.get("Access-Control-Allow-Origin", "")

                            if malicious_origin in acao or acao == "*":
                                vulnerabilities.append(
                                    self._create_vulnerability(
                                        title="Cross-Site WebSocket Hijacking (CSWSH)",
                                        description=f"The WebSocket endpoint at {ws_url} accepts connections from arbitrary origins, making it vulnerable to CSWSH attacks.",
                                        severity="high",
                                        type="websocket_cswsh",
                                        evidence={
                                            "endpoint": ws_url,
                                            "malicious_origin": malicious_origin,
                                            "acao_header": acao,
                                        },
                                        cwe_id="CWE-346",
                                        remediation="Implement strict Origin header validation. Only accept WebSocket connections from trusted origins.",
                                    )
                                )
                                break

                except Exception as e:
                    logger.debug(f"CSWSH test failed: {e}")

        return vulnerabilities

    async def _test_upgrade_security(self, url: str, ws_endpoints: list[str]) -> list[Vulnerability]:
        """Test WebSocket upgrade security."""
        vulnerabilities = []

        for ws_url in ws_endpoints[:3]:
            try:
                http_url = ws_url.replace("wss://", "https://").replace("ws://", "http://")

                # Test without proper WebSocket headers
                response = await self.http_client.get(http_url)

                if response and response.status == 101:
                    vulnerabilities.append(
                        self._create_vulnerability(
                            title="WebSocket Upgrade Without Proper Handshake",
                            description=f"The WebSocket endpoint at {ws_url} may accept connections without proper handshake validation.",
                            severity="medium",
                            type="ws_handshake_bypass",
                            evidence={"endpoint": ws_url},
                            cwe_id="CWE-287",
                            remediation="Ensure proper WebSocket handshake validation. Verify Sec-WebSocket-Key and other required headers.",
                        )
                    )

            except Exception as e:
                logger.debug(f"Upgrade security test failed: {e}")

        return vulnerabilities

    async def _check_socketio(self, url: str) -> list[Vulnerability]:
        """Check for Socket.IO specific security issues."""
        vulnerabilities = []
        urlparse(url)

        socketio_paths = [
            "/socket.io/",
            "/socket.io/?EIO=4&transport=polling",
            "/socket.io/?EIO=3&transport=polling",
        ]

        for path in socketio_paths:
            try:
                test_url = urljoin(url, path)
                response = await self.http_client.get(test_url)

                if response and response.status == 200:
                    content = await response.text()

                    # Check for Socket.IO response
                    if "sid" in content or "socket.io" in content.lower():
                        # Socket.IO is present

                        # Check for CORS misconfiguration
                        cors_test = await self.http_client.get(test_url, headers={"Origin": "https://evil.com"})

                        if cors_test:
                            acao = cors_test.headers.get("Access-Control-Allow-Origin", "")
                            if acao == "*" or "evil.com" in acao:
                                vulnerabilities.append(
                                    self._create_vulnerability(
                                        title="Socket.IO CORS Misconfiguration",
                                        description="Socket.IO endpoint has overly permissive CORS settings, potentially allowing cross-origin attacks.",
                                        severity="medium",
                                        type="socketio_cors",
                                        evidence={"endpoint": test_url, "acao_header": acao},
                                        cwe_id="CWE-942",
                                        remediation="Configure Socket.IO to only accept connections from trusted origins.",
                                    )
                                )
                        break

            except Exception as e:
                logger.debug(f"Socket.IO check failed: {e}")

        return vulnerabilities
