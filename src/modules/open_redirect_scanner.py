"""
Open Redirect scanner module - Advanced Implementation.
"""

import logging
from collections.abc import Callable
from typing import Any

from .base_scanner import BaseScanner, Vulnerability

logger = logging.getLogger(__name__)


class OpenRedirectScanner(BaseScanner):
    """Advanced Open Redirect vulnerability detection engine."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "OpenRedirectScanner"
        self.description = "Advanced unvalidated redirect detector with WAF bypass techniques"
        self.version = "2.0.0"
        self.capabilities = [
            "WAF Bypass Payloads",
            "Protocol Handler Testing",
            "JavaScript Redirect Detection",
            "Meta Refresh Analysis",
            "Encoding Bypass Techniques",
            "Parameter Discovery",
        ]

        # Common redirect parameter names
        self.redirect_params = [
            "url",
            "redirect",
            "next",
            "dest",
            "destination",
            "redir",
            "redirect_uri",
            "redirect_url",
            "return",
            "returnTo",
            "return_url",
            "return_to",
            "out",
            "view",
            "to",
            "uri",
            "path",
            "continue",
            "go",
            "goto",
            "target",
            "link",
            "forward",
            "forward_url",
            "callback",
            "fallback",
            "checkout_url",
        ]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform comprehensive open redirect scan."""
        logger.info(f"Scanning {url} for Open Redirect vulnerabilities")
        vulnerabilities = []

        # Generate comprehensive payloads
        payloads = self._generate_payloads()

        try:
            self._update_progress(progress_callback, 10, "Discovering redirect parameters")
            discovered_params = await self._discover_parameters(url)

            # Merge with known redirect params
            all_params = list(set(discovered_params + self.redirect_params))

            # Prioritize known redirect params
            priority_params = [p for p in all_params if p.lower() in [rp.lower() for rp in self.redirect_params]]
            other_params = [p for p in all_params if p not in priority_params]
            target_params = priority_params[:10] + other_params[:5]  # Limit total params

            total_tests = len(target_params) * len(payloads)
            processed = 0

            for param in target_params:
                for payload_info in payloads:
                    payload = payload_info["payload"]
                    technique = payload_info["technique"]

                    processed += 1
                    if processed % 10 == 0:  # Update less frequently
                        progress = 15 + int((processed / total_tests) * 75)
                        self._update_progress(progress_callback, progress, f"Testing {param}")

                    # Test GET
                    vulns = await self._test_redirect(url, param, payload, technique, "GET")
                    if vulns:
                        vulnerabilities.extend(vulns)
                        break  # Move to next param after finding vuln

                    # Test POST for important params
                    if param.lower() in ["redirect", "redirect_url", "return_url", "next"]:
                        vulns = await self._test_redirect(url, param, payload, technique, "POST")
                        if vulns:
                            vulnerabilities.extend(vulns)
                            break

            # Check for meta refresh and JS redirects in page
            self._update_progress(progress_callback, 92, "Checking embedded redirects")
            embedded_vulns = await self._check_embedded_redirects(url)
            vulnerabilities.extend(embedded_vulns)

            self._update_progress(progress_callback, 100, "completed")

            status = "Vulnerable" if vulnerabilities else "Secure"
            details = f"Tested {len(target_params)} parameters with {len(payloads)} payloads. Found {len(vulnerabilities)} issues."
            return self._format_result(status, details, vulnerabilities)

        except Exception as e:
            logger.exception(f"Open Redirect scan failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])

    def _generate_payloads(self) -> list[dict[str, str]]:
        """Generate comprehensive redirect payloads with bypass techniques."""
        payloads = [
            # Basic payloads
            {"payload": "https://evil.com", "technique": "Direct URL"},
            {"payload": "http://evil.com", "technique": "HTTP URL"},
            {"payload": "//evil.com", "technique": "Protocol-relative"},
            # Backslash/slash confusion
            {"payload": "/\\evil.com", "technique": "Backslash bypass"},
            {"payload": "\\/evil.com", "technique": "Reverse backslash"},
            {"payload": "///evil.com", "technique": "Triple slash"},
            {"payload": "\\\\evil.com", "technique": "Double backslash"},
            # @ symbol bypass
            {"payload": "https://trusted.com@evil.com", "technique": "@ symbol auth bypass"},
            {"payload": "https://evil.com?trusted.com", "technique": "Query confusion"},
            {"payload": "https://evil.com#trusted.com", "technique": "Fragment confusion"},
            # Protocol handlers
            {"payload": "javascript:alert(document.domain)", "technique": "JavaScript protocol"},
            {"payload": "data:text/html,<script>alert(1)</script>", "technique": "Data URI"},
            {"payload": "vbscript:alert(1)", "technique": "VBScript protocol"},
            # Encoding bypasses
            {"payload": "https:%2f%2fevil.com", "technique": "Single URL encode"},
            {"payload": "https:%252f%252fevil.com", "technique": "Double URL encode"},
            {"payload": "%68%74%74%70%73%3a%2f%2fevil.com", "technique": "Full URL encode"},
            {"payload": "//evil%E3%80%82com", "technique": "Unicode dot"},
            {"payload": "//evil。com", "technique": "Fullwidth dot"},
            # Whitespace tricks
            {"payload": " //evil.com", "technique": "Leading space"},
            {"payload": "\t//evil.com", "technique": "Leading tab"},
            {"payload": "\n//evil.com", "technique": "Newline prefix"},
            {"payload": "//evil.com%00", "technique": "Null byte suffix"},
            {"payload": "//evil.com%20", "technique": "Trailing space"},
            # Case variations
            {"payload": "HTTPS://EVIL.COM", "technique": "Uppercase"},
            {"payload": "HtTpS://EvIl.CoM", "technique": "Mixed case"},
            # IPv4/IPv6
            {"payload": "https://0x7f000001", "technique": "Hex IP"},
            {"payload": "https://2130706433", "technique": "Decimal IP"},
            {"payload": "https://[::1]", "technique": "IPv6 localhost"},
            # CRLF injection
            {"payload": "//evil.com%0d%0aSet-Cookie:test=1", "technique": "CRLF injection"},
            # Subdomain tricks
            {"payload": "//evil.com.trusted.com", "technique": "Subdomain suffix"},
            {"payload": "//trusted.com.evil.com", "technique": "Subdomain prefix"},
        ]

        return payloads

    async def _test_redirect(
        self, url: str, param: str, payload: str, technique: str, method: str
    ) -> list[Vulnerability]:
        """Test a specific redirect payload."""
        findings = []

        try:
            response = await self._test_payload(url, param, payload, method, follow_redirects=False)

            if self._is_redirect_vulnerable(response, payload):
                severity = "high" if "javascript" in payload.lower() else "medium"

                findings.append(
                    self._create_vulnerability(
                        title=f"Open Redirect Vulnerability ({technique})",
                        description=f"Parameter '{param}' allows unvalidated redirects. Technique: {technique}",
                        severity=severity,
                        type="open_redirect",
                        evidence={
                            "param": param,
                            "payload": payload,
                            "technique": technique,
                            "method": method,
                            "location": response.get("headers", {}).get("Location", ""),
                        },
                        cwe_id="CWE-601",
                        remediation="Implement strict URL validation. Use allowlists for redirect destinations. Avoid using user input in redirect URLs.",
                    )
                )

        except Exception as e:
            logger.debug(f"Redirect test error: {e}")

        return findings

    def _is_redirect_vulnerable(self, response: dict, payload: str) -> bool:
        """Determine if response indicates successful redirect."""
        if not response:
            return False

        status = response.get("status_code", 0)
        location = response.get("headers", {}).get("Location", "")
        content = response.get("page_content", "").lower()

        # Normalize payload for comparison
        payload_lower = payload.lower().replace("%2f", "/").replace("%3a", ":")

        # Check Location header for 3xx redirects
        if 300 <= status < 400:
            # Direct match or partial match
            if payload_lower in location.lower():
                return True
            if "evil" in location.lower():
                return True
            # Protocol-relative check
            if payload.startswith("//") and location.startswith("//"):
                if "evil" in location.lower():
                    return True

        # Check for meta refresh redirect
        if f"url={payload_lower}" in content or f"url='{payload_lower}'" in content:
            return True

        # Check for JavaScript redirect
        js_patterns = [
            f'window.location = "{payload_lower}"',
            f"window.location = '{payload_lower}'",
            f'location.href = "{payload_lower}"',
            f"location.href = '{payload_lower}'",
            f'location.replace("{payload_lower}")',
            f"location.replace('{payload_lower}')",
        ]

        for pattern in js_patterns:
            if pattern in content:
                return True

        return False

    async def _check_embedded_redirects(self, url: str) -> list[Vulnerability]:
        """Check for embedded redirect mechanisms in the page."""
        findings = []

        try:
            response = await self.http_client.get(url)
            if not response:
                return findings

            html = await response.text()
            soup = await self._parse_html(html)

            # Check meta refresh tags
            meta_refresh = soup.find_all("meta", attrs={"http-equiv": lambda x: x and x.lower() == "refresh"})
            for meta in meta_refresh:
                content = meta.get("content", "")
                if "url=" in content.lower():
                    # Extract redirect URL
                    parts = content.lower().split("url=")
                    if len(parts) > 1:
                        redirect_url = parts[1].strip().strip("'\"")
                        if redirect_url.startswith("http") or redirect_url.startswith("//"):
                            findings.append(
                                self._create_vulnerability(
                                    title="Meta Refresh Redirect Detected",
                                    description=f"Page contains meta refresh redirect to: {redirect_url[:100]}",
                                    severity="info",
                                    type="meta_redirect",
                                    evidence={"meta_content": content},
                                    cwe_id="CWE-601",
                                    remediation="Review meta refresh redirects for security implications.",
                                )
                            )

            # Check for JS-based redirects that might be controllable
            scripts = soup.find_all("script")
            for script in scripts:
                script_content = script.string or ""

                # Look for dynamic redirect patterns
                dangerous_patterns = [
                    "location.href = document.location",
                    "window.location = window.location",
                    "location.href = location.search",
                    "location = new URLSearchParams",
                    "window.open(document.",
                ]

                for pattern in dangerous_patterns:
                    if pattern in script_content.lower():
                        findings.append(
                            self._create_vulnerability(
                                title="Potential DOM-based Open Redirect",
                                description="JavaScript code may allow DOM-based open redirect.",
                                severity="medium",
                                type="dom_redirect",
                                evidence={"pattern": pattern},
                                cwe_id="CWE-601",
                                remediation="Avoid using URL parameters directly in JavaScript redirects. Validate all redirect destinations.",
                            )
                        )
                        break

        except Exception as e:
            logger.debug(f"Embedded redirect check error: {e}")

        return findings
