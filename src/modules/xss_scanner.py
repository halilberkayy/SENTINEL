"""
XSS Scanner - ENHANCED with DOM XSS detection
"""

import logging
import re
from collections.abc import Callable
from typing import Any

from .base_scanner import BaseScanner, Vulnerability

logger = logging.getLogger(__name__)


class XSSScanner(BaseScanner):
    """Enhanced XSS scanner with DOM XSS and reflected XSS detection."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "XSSScanner"
        self.description = "Detects XSS vulnerabilities including DOM-based"
        self.version = "2.0.0"
        self.capabilities = ["Reflected XSS", "DOM XSS", "Stored XSS Detection", "WAF Evasion"]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform comprehensive XSS scan."""
        logger.info(f"Initiating XSS scan for {url}")
        vulnerabilities = []

        # Enhanced XSS payloads with evasion
        base_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            '<iframe src="javascript:alert(1)">',
            "<body onload=alert(1)>",
            "<input autofocus onfocus=alert(1)>",
            "<select autofocus onfocus=alert(1)>",
            "<textarea autofocus onfocus=alert(1)>",
            "<keygen autofocus onfocus=alert(1)>",
            '<video><source onerror="alert(1)">',
            "<audio src=x onerror=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<marquee onstart=alert(1)>",
        ]

        try:
            self._update_progress(progress_callback, 10, "Discovering parameters")
            params = await self._discover_parameters(url)

            if not params:
                params = ["q", "search", "query", "keyword", "term"]

            total_tests = len(params) * len(base_payloads[:5])  # Limit for speed
            tested = 0

            # Test reflected XSS
            for param in params:
                for base_payload in base_payloads[:5]:
                    tested += 1
                    progress = 20 + int((tested / total_tests) * 50)
                    self._update_progress(progress_callback, progress, f"Testing {param}")

                    # Generate evasion variants
                    payloads = self._generate_payload_variants(base_payload, max_variants=2)

                    for payload in payloads:
                        # Test GET
                        result = await self._test_payload(url, param, payload, "GET")
                        if self._is_xss_vulnerable(result, payload):
                            vulnerabilities.append(
                                self._create_vulnerability(
                                    title=f"Reflected XSS in Parameter '{param}'",
                                    description=f"The application reflects unescaped user input. Payload: {payload[:50]}",
                                    severity="high",
                                    type="xss",
                                    evidence={
                                        "parameter": param,
                                        "payload": payload,
                                        "method": "GET",
                                        "reflected_content": result.get("page_content", "")[:200],
                                    },
                                    cwe_id="CWE-79",
                                    remediation="Encode all user input before rendering. Use Content-Security-Policy headers.",
                                )
                            )
                            break  # Found XSS, move to next param

            # Test DOM XSS patterns
            self._update_progress(progress_callback, 75, "Analyzing DOM XSS patterns")
            dom_vulns = await self._test_dom_xss(url)
            vulnerabilities.extend(dom_vulns)

            self._update_progress(progress_callback, 100, "completed")

            status = "Vulnerable" if vulnerabilities else "Clean"
            return self._format_result(status, f"Found {len(vulnerabilities)} XSS vulnerabilities.", vulnerabilities)

        except Exception as e:
            logger.exception(f"XSS scan failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])

    def _is_xss_vulnerable(self, response: dict, payload: str) -> bool:
        """Check if response contains unescaped XSS payload."""
        content = response.get("page_content", "")

        # Check for exact payload reflection (unescaped)
        if payload in content:
            return True

        # Check for partial payload that could execute
        dangerous_patterns = [
            r"<script[^>]*>.*alert",
            r'onerror\s*=\s*["\']?alert',
            r'onload\s*=\s*["\']?alert',
            r"javascript:\s*alert",
            r"<svg[^>]*onload",
            r"<img[^>]*onerror",
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True

        return False

    async def _test_dom_xss(self, url: str) -> list[Vulnerability]:
        """Test for DOM-based XSS vulnerabilities."""
        vulns = []

        try:
            response = await self.http_client.get(url)
            if not response:
                return vulns

            content = await response.text()

            # Dangerous DOM sinks
            dom_sinks = [
                r"document\.write\s*\(\s*[^)]*location",
                r"document\.writeln\s*\(\s*[^)]*location",
                r"\.innerHTML\s*=\s*[^;]*location",
                r"\.outerHTML\s*=\s*[^;]*location",
                r"eval\s*\(\s*[^)]*location",
                r"setTimeout\s*\(\s*[^)]*location",
                r"setInterval\s*\(\s*[^)]*location",
                r"Function\s*\(\s*[^)]*location",
                r"\.html\s*\(\s*[^)]*location",  # jQuery
                r"\$\([^)]*\)\.append\s*\([^)]*location",
            ]

            # Dangerous sources
            dom_sources = [
                "location.hash",
                "location.search",
                "location.href",
                "document.URL",
                "document.documentURI",
                "document.referrer",
                "window.name",
            ]

            # Check for dangerous patterns
            for sink_pattern in dom_sinks:
                matches = re.findall(sink_pattern, content, re.IGNORECASE | re.MULTILINE)
                if matches:
                    # Check if any dangerous source is used
                    for source in dom_sources:
                        if source in content:
                            vulns.append(
                                self._create_vulnerability(
                                    title="Potential DOM-based XSS",
                                    description=f"Dangerous DOM sink pattern found: {sink_pattern[:50]}. Used with source: {source}",
                                    severity="medium",
                                    type="dom_xss",
                                    evidence={
                                        "url": url,
                                        "sink_pattern": sink_pattern[:100],
                                        "source": source,
                                        "code_snippet": matches[0][:150] if matches else "",
                                    },
                                    cwe_id="CWE-79",
                                    remediation="Sanitize and validate all data from DOM sources before using in sinks. Use textContent instead of innerHTML.",
                                )
                            )
                            break
                    if vulns:  # Found vulnerability, don't need to check more sinks
                        break

            # Check for dangerous eval patterns
            if "eval(" in content or "Function(" in content:
                vulns.append(
                    self._create_vulnerability(
                        title="Dangerous JavaScript Patterns",
                        description="Use of eval() or Function() constructor detected. These can lead to code injection.",
                        severity="info",
                        type="code_pattern",
                        evidence={"url": url},
                        cwe_id="CWE-95",
                        remediation="AvoidAvoid using eval() and Function(). Use safer alternatives like JSON.parse().",
                    )
                )

        except Exception as e:
            logger.debug(f"DOM XSS test failed: {e}")

        return vulns
