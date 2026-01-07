"""
WAF (Web Application Firewall) Detection and Bypass Module
Detects WAF presence and suggests bypass techniques.
"""

import asyncio
import logging
from collections.abc import Callable
from typing import Any

from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class WAFDetector(BaseScanner):
    """
    Advanced WAF detection and fingerprinting module.

    Capabilities:
    - Detect major WAF vendors (CloudFlare, Akamai, AWS WAF, etc.)
    - Fingerprint WAF by response patterns
    - Test common bypass techniques
    - Provide evasion recommendations
    """

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "WAFDetector"
        self.description = "Detects Web Application Firewalls and suggests bypass techniques"
        self.version = "1.0.0"

        # WAF signatures
        self.waf_signatures = {
            "cloudflare": {
                "headers": ["cf-ray", "cf-cache-status", "__cfduid", "cf-request-id"],
                "cookies": ["__cfduid", "__cf_bm"],
                "body_patterns": ["cloudflare", "attention required", "cf-error-details"],
                "status_codes": [403, 503],
                "server": ["cloudflare"],
            },
            "akamai": {
                "headers": ["akamai-grn", "x-akamai-session-info", "x-akamai-ssl-client-sid"],
                "cookies": ["akamai"],
                "body_patterns": ["access denied", "akamai", "reference #"],
                "status_codes": [403],
                "server": ["akamaighost", "akamai"],
            },
            "aws_waf": {
                "headers": ["x-amzn-requestid", "x-amz-cf-id", "x-amz-apigw-id"],
                "cookies": ["AWSALB", "AWSALBCORS"],
                "body_patterns": ["request blocked", "aws waf"],
                "status_codes": [403],
                "server": ["awselb", "amazon"],
            },
            "imperva": {
                "headers": ["x-iinfo", "x-cdn"],
                "cookies": ["incap_ses", "visid_incap", "_incapsula"],
                "body_patterns": ["incapsula", "incident id", "_incapsula"],
                "status_codes": [403],
                "server": ["incapsula"],
            },
            "sucuri": {
                "headers": ["x-sucuri-id", "x-sucuri-cache"],
                "cookies": ["sucuri"],
                "body_patterns": ["sucuri", "access denied", "sucuri firewall"],
                "status_codes": [403],
                "server": ["sucuri"],
            },
            "f5_bigip": {
                "headers": ["x-wa-info"],
                "cookies": ["ts", "bigipserver", "f5_cspm"],
                "body_patterns": ["the requested url was rejected"],
                "status_codes": [403],
                "server": ["bigip", "f5"],
            },
            "modsecurity": {
                "headers": ["mod_security", "modsec"],
                "cookies": [],
                "body_patterns": ["mod_security", "modsecurity", "not acceptable", "method not implemented"],
                "status_codes": [403, 406, 501],
                "server": ["mod_security", "modsec"],
            },
            "barracuda": {
                "headers": ["barra_counter_session"],
                "cookies": ["barra_counter_session", "BNI__BARRACUDA_LB_COOKIE"],
                "body_patterns": ["barracuda", "access denied"],
                "status_codes": [403],
                "server": ["barracuda"],
            },
            "fortinet": {
                "headers": [],
                "cookies": ["FORTIWAFSID"],
                "body_patterns": ["fortigate", "fortiweb", "fortigate application control"],
                "status_codes": [403],
                "server": ["fortigate", "fortiweb"],
            },
            "radware": {
                "headers": ["x-sl-compstate"],
                "cookies": [],
                "body_patterns": ["radware", "unauthorized activity"],
                "status_codes": [403],
                "server": ["radware"],
            },
            "wallarm": {
                "headers": ["x-wallarm-waf-check"],
                "cookies": [],
                "body_patterns": ["wallarm", "ngx_http_wallarm_module"],
                "status_codes": [403],
                "server": ["wallarm"],
            },
            "citrix_netscaler": {
                "headers": ["cneonction", "nncontection"],
                "cookies": ["citrix_ns_id", "ns_af", "ns_s"],
                "body_patterns": ["citrix", "netscaler"],
                "status_codes": [403],
                "server": ["netscaler"],
            },
        }

        # Trigger payloads to provoke WAF responses
        self.trigger_payloads = [
            "<script>alert('XSS')</script>",
            "' OR '1'='1",
            "../../../etc/passwd",
            "; cat /etc/passwd",
            "{{7*7}}",
            "${7*7}",
            "<?php phpinfo(); ?>",
            "<img src=x onerror=alert(1)>",
            "UNION SELECT * FROM users--",
        ]

        # Bypass techniques per WAF
        self.bypass_techniques = {
            "cloudflare": [
                "Unicode encoding",
                "Mixed case obfuscation",
                "Comment insertion",
                "Chunked transfer encoding",
                "HTTP parameter pollution",
                "Protocol-level attacks",
            ],
            "akamai": [
                "URL encoding variations",
                "Header case manipulation",
                "Double URL encoding",
                "Null byte injection",
                "Whitespace manipulation",
            ],
            "aws_waf": [
                "Request smuggling",
                "Path normalization bypass",
                "Encoding variations",
                "Size limits exploitation",
            ],
            "modsecurity": [
                "Comment insertion (/**/)",
                "Case variation",
                "String concatenation",
                "Charset encoding",
                "Null bytes",
            ],
            "generic": [
                "URL encoding",
                "Double encoding",
                "Unicode normalization",
                "Case manipulation",
                "Comment insertion",
                "Whitespace variations",
                "HTTP parameter pollution",
                "Request line manipulation",
            ],
        }

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform WAF detection scan."""
        logger.info(f"Starting WAF detection on {url}")
        vulnerabilities = []
        detected_wafs = []

        try:
            self._update_progress(progress_callback, 10, "Checking normal response")

            # 1. Analyze normal response for WAF signatures
            normal_detection = await self._analyze_normal_response(url)
            if normal_detection:
                detected_wafs.extend(normal_detection)

            self._update_progress(progress_callback, 40, "Sending trigger payloads")

            # 2. Send trigger payloads to provoke WAF
            triggered_detection = await self._trigger_waf_response(url)
            if triggered_detection:
                for waf in triggered_detection:
                    if waf not in detected_wafs:
                        detected_wafs.append(waf)

            self._update_progress(progress_callback, 70, "Analyzing WAF behavior")

            # 3. Test basic bypass techniques
            if detected_wafs:
                bypass_results = await self._test_basic_bypasses(url, detected_wafs)

                # Create vulnerability report
                for waf in detected_wafs:
                    techniques = self.bypass_techniques.get(waf, self.bypass_techniques["generic"])

                    vulnerabilities.append(
                        self._create_vulnerability(
                            title=f"WAF Detected: {waf.upper()}",
                            description=f"Web Application Firewall detected: {waf.upper()}. This may affect scanning accuracy and require bypass techniques.",
                            severity="info",
                            type="waf_detection",
                            evidence={
                                "waf_name": waf,
                                "detection_method": "signature_matching",
                                "bypass_techniques": techniques,
                                "bypass_test_results": bypass_results.get(waf, {}),
                            },
                            cwe_id="CWE-693",
                            remediation="Consider the detected WAF when interpreting scan results. Some vulnerabilities may be blocked by the WAF.",
                        )
                    )

            self._update_progress(progress_callback, 100, "completed")

            if detected_wafs:
                status = "Detected"
                details = f"WAF detected: {', '.join(detected_wafs).upper()}"
            else:
                status = "Clean"
                details = "No WAF detected"

            return self._format_result(status, details, vulnerabilities)

        except Exception as e:
            logger.exception(f"WAF detection failed: {e}")
            return self._format_result("Error", f"Scan failed: {e}", [])

    async def _analyze_normal_response(self, url: str) -> list[str]:
        """Analyze normal response for WAF signatures."""
        detected = []

        try:
            response = await self.http_client.get(url)
            if not response:
                return detected

            headers = dict(response.headers) if response.headers else {}
            cookies = headers.get("set-cookie", "")
            server = headers.get("server", "").lower()

            for waf_name, signatures in self.waf_signatures.items():
                score = 0

                # Check headers
                for sig_header in signatures["headers"]:
                    if sig_header.lower() in [h.lower() for h in headers.keys()]:
                        score += 2

                # Check cookies
                for sig_cookie in signatures["cookies"]:
                    if sig_cookie.lower() in cookies.lower():
                        score += 2

                # Check server header
                for sig_server in signatures["server"]:
                    if sig_server.lower() in server:
                        score += 3

                if score >= 2:
                    detected.append(waf_name)

        except Exception as e:
            logger.debug(f"Normal response analysis failed: {e}")

        return detected

    async def _trigger_waf_response(self, url: str) -> list[str]:
        """Send trigger payloads to provoke WAF response."""
        detected = []

        for payload in self.trigger_payloads[:5]:  # Limit to avoid blocking
            try:
                # Try payload in URL parameter
                test_url = f"{url}?test={payload}"
                response = await self.http_client.get(test_url)

                if response:
                    waf = await self._analyze_blocked_response(response)
                    if waf and waf not in detected:
                        detected.append(waf)

                # Small delay to avoid rate limiting
                await asyncio.sleep(0.5)

            except Exception as e:
                logger.debug(f"Trigger payload failed: {e}")

        return detected

    async def _analyze_blocked_response(self, response) -> str | None:
        """Analyze response to identify WAF from block page."""
        try:
            content = await response.text()
            content_lower = content.lower()
            headers = dict(response.headers) if response.headers else {}

            for waf_name, signatures in self.waf_signatures.items():
                # Check if status code matches
                if response.status in signatures["status_codes"]:
                    # Check body patterns
                    for pattern in signatures["body_patterns"]:
                        if pattern.lower() in content_lower:
                            return waf_name

                    # Check headers in blocked response
                    for sig_header in signatures["headers"]:
                        if sig_header.lower() in [h.lower() for h in headers.keys()]:
                            return waf_name

        except Exception as e:
            logger.debug(f"Blocked response analysis failed: {e}")

        return None

    async def _test_basic_bypasses(self, url: str, detected_wafs: list[str]) -> dict[str, dict]:
        """Test basic bypass techniques."""
        results = {}

        bypass_tests = [
            ("url_encoding", "<script>alert(1)</script>", "%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
            ("double_encoding", "<script>", "%253Cscript%253E"),
            ("unicode", "<script>", "\\u003cscript\\u003e"),
            ("case_variation", "<SCRIPT>alert(1)</SCRIPT>", "<ScRiPt>alert(1)</ScRiPt>"),
            ("comment_insertion", "SELECT * FROM", "SEL/**/ECT/**/*/**/FROM"),
            ("null_byte", "<script>", "<script%00>"),
        ]

        for waf in detected_wafs:
            results[waf] = {}

            for bypass_name, _original, bypassed in bypass_tests[:3]:  # Limit tests
                try:
                    # Test bypassed version
                    test_url = f"{url}?test={bypassed}"
                    response = await self.http_client.get(test_url)

                    if response:
                        blocked = response.status in [403, 406, 429]
                        results[waf][bypass_name] = {"blocked": blocked, "status_code": response.status}

                    await asyncio.sleep(0.3)

                except Exception as e:
                    results[waf][bypass_name] = {"error": str(e)}

        return results
