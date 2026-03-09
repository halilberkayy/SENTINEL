"""
IDS/IPS Evasion Assessment Module - Security Controls Bypass Testing

WARNING: This module is designed for AUTHORIZED penetration testing and security
assessments ONLY. Unauthorized use against systems you do not own or have explicit
written permission to test is ILLEGAL and UNETHICAL. Always obtain proper authorization
before conducting any security assessment.

This module tests the target's IDS/IPS and WAF effectiveness by attempting
various evasion techniques including payload encoding, request smuggling,
chunked transfer encoding, and WAF bypass methods.
"""

import asyncio
import base64
import logging
import random
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import quote, urlparse

from .base_scanner import BaseScanner, Vulnerability

logger = logging.getLogger(__name__)


# Payload encoding techniques
ENCODING_TECHNIQUES = {
    "base64": lambda p: base64.b64encode(p.encode()).decode(),
    "hex": lambda p: "".join(f"%{ord(c):02x}" for c in p),
    "unicode": lambda p: "".join(f"\\u{ord(c):04x}" for c in p),
    "double_url": lambda p: quote(quote(p)),
    "html_entity": lambda p: "".join(f"&#{ord(c)};" for c in p),
    "octal": lambda p: "".join(f"\\{ord(c):03o}" for c in p),
}

# Test payloads for WAF detection (benign but trigger WAF rules)
WAF_TEST_PAYLOADS = [
    "<script>alert(1)</script>",
    "' OR 1=1--",
    "../../../etc/passwd",
    "{{7*7}}",
    "${jndi:ldap://test}",
    "; ls -la",
    "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
]

# Known WAF signatures
WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "__cfduid"],
        "server": ["cloudflare"],
        "status_codes": [403, 503],
        "body_patterns": ["Attention Required!", "cloudflare", "cf-error"],
    },
    "AWS WAF": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id"],
        "body_patterns": ["Request blocked", "AWS WAF"],
    },
    "ModSecurity": {
        "headers": ["mod_security", "modsecurity"],
        "server": ["mod_security"],
        "body_patterns": ["ModSecurity", "NOYB"],
    },
    "Akamai": {
        "headers": ["akamai-grn", "x-akamai-session-info"],
        "server": ["akamaighost"],
        "body_patterns": ["Access Denied", "akamai"],
    },
    "Imperva/Incapsula": {
        "headers": ["x-iinfo", "x-cdn"],
        "body_patterns": ["incapsula", "imperva", "visid_incap"],
    },
    "F5 BIG-IP": {
        "headers": ["x-cnection", "x-wa-info"],
        "server": ["bigip", "f5"],
        "body_patterns": ["BIG-IP", "The requested URL was rejected"],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "server": ["sucuri"],
        "body_patterns": ["sucuri", "access denied - sucuri"],
    },
}

# Request smuggling test patterns
SMUGGLING_PATTERNS = [
    {
        "name": "CL-TE",
        "description": "Content-Length / Transfer-Encoding desync",
        "headers": {
            "Content-Length": "0",
            "Transfer-Encoding": "chunked",
        },
    },
    {
        "name": "TE-CL",
        "description": "Transfer-Encoding / Content-Length desync",
        "headers": {
            "Transfer-Encoding": "chunked",
            "Content-Length": "5",
        },
    },
    {
        "name": "TE-TE",
        "description": "Transfer-Encoding obfuscation",
        "headers": {
            "Transfer-Encoding": "chunked",
            "Transfer-encoding": "identity",
        },
    },
]


class EvasionScanner(BaseScanner):
    """
    IDS/IPS Evasion Assessment Scanner.

    AUTHORIZED USE ONLY: This module assesses the effectiveness of security
    controls (WAF, IDS, IPS) by testing various evasion techniques. It helps
    identify gaps in security monitoring and filtering.

    Features:
    - Payload encoding variation testing
    - HTTP request smuggling detection
    - Chunked transfer encoding evasion
    - Case variation and null byte injection
    - WAF fingerprinting and bypass assessment
    - Slow-rate attack simulation
    - Fragment-based evasion
    """

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "EvasionScanner"
        self.description = "IDS/IPS evasion assessment - tests security control effectiveness"
        self.version = "1.0.0"
        self.capabilities = [
            "Payload Encoding Testing",
            "Request Smuggling Detection",
            "Chunked Encoding Evasion",
            "WAF Fingerprinting",
            "WAF Bypass Assessment",
            "Slow-Rate Attack Simulation",
            "Fragment-Based Evasion",
        ]
        self.max_requests = 80
        self.slow_rate_connections = 5
        self.slow_rate_interval = 5  # seconds

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform IDS/IPS evasion assessment."""
        logger.info(f"Starting Evasion assessment for {url}")
        vulnerabilities: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "waf_fingerprint": {},
            "encoding_bypass": {},
            "request_smuggling": {},
            "slow_rate": {},
            "fragment_evasion": {},
        }

        try:
            # Phase 1: WAF Fingerprinting (20%)
            self._update_progress(progress_callback, 10, "Fingerprinting WAF")
            waf_vulns, waf_evidence = await self._fingerprint_waf(url)
            vulnerabilities.extend(waf_vulns)
            evidence["waf_fingerprint"] = waf_evidence

            # Phase 2: Encoding Bypass Testing (40%)
            self._update_progress(progress_callback, 25, "Testing encoding bypass")
            enc_vulns, enc_evidence = await self._test_encoding_bypass(url)
            vulnerabilities.extend(enc_vulns)
            evidence["encoding_bypass"] = enc_evidence

            # Phase 3: Request Smuggling (55%)
            self._update_progress(progress_callback, 40, "Testing request smuggling")
            smug_vulns, smug_evidence = await self._test_request_smuggling(url)
            vulnerabilities.extend(smug_vulns)
            evidence["request_smuggling"] = smug_evidence

            # Phase 4: Case/Null Byte Evasion (70%)
            self._update_progress(progress_callback, 55, "Testing case/null byte evasion")
            case_vulns, case_evidence = await self._test_case_null_evasion(url)
            vulnerabilities.extend(case_vulns)
            evidence["case_null_evasion"] = case_evidence

            # Phase 5: Slow-Rate Assessment (85%)
            self._update_progress(progress_callback, 70, "Testing slow-rate resilience")
            slow_vulns, slow_evidence = await self._test_slow_rate(url)
            vulnerabilities.extend(slow_vulns)
            evidence["slow_rate"] = slow_evidence

            # Phase 6: Fragment Evasion (100%)
            self._update_progress(progress_callback, 85, "Testing fragment evasion")
            frag_vulns, frag_evidence = await self._test_fragment_evasion(url)
            vulnerabilities.extend(frag_vulns)
            evidence["fragment_evasion"] = frag_evidence

            self._update_progress(progress_callback, 100, "completed")

        except Exception as e:
            logger.error(f"Evasion assessment error: {e}")
            return self._format_result(
                "Error", f"Assessment failed: {str(e)}", vulnerabilities, evidence
            )

        waf_name = waf_evidence.get("detected_waf", "none")
        details = (
            f"Evasion assessment completed. "
            f"Found {len(vulnerabilities)} bypass(es). "
            f"WAF detected: {waf_name}, "
            f"Encoding bypasses: {enc_evidence.get('bypasses_found', 0)}, "
            f"Smuggling vulnerable: {smug_evidence.get('vulnerable', False)}"
        )

        return self._format_result("Completed", details, vulnerabilities, evidence)

    async def _fingerprint_waf(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Fingerprint the WAF protecting the target."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "detected_waf": "none",
            "confidence": "low",
            "indicators": [],
        }

        try:
            # Normal request for baseline
            response = await self.http_client.get(url)
            if not response:
                return vulns, evidence

            headers = {k.lower(): v.lower() for k, v in response.headers.items()}
            server = headers.get("server", "")

            # Check each WAF signature
            for waf_name, signatures in WAF_SIGNATURES.items():
                score = 0

                # Check headers
                for sig_header in signatures.get("headers", []):
                    if sig_header.lower() in headers:
                        score += 30
                        evidence["indicators"].append({"type": "header", "name": sig_header, "waf": waf_name})

                # Check server header
                for srv_sig in signatures.get("server", []):
                    if srv_sig in server:
                        score += 40
                        evidence["indicators"].append({"type": "server", "value": server, "waf": waf_name})

                if score >= 30:
                    evidence["detected_waf"] = waf_name
                    evidence["confidence"] = "high" if score >= 60 else "medium"
                    break

            # Send malicious payload to trigger WAF response
            test_payload = "<script>alert(1)</script>"
            test_url = f"{url}?test={quote(test_payload)}"
            try:
                waf_resp = await self.http_client.get(test_url)
                if waf_resp:
                    waf_status = waf_resp.status
                    if waf_status in [403, 406, 429, 503]:
                        evidence["waf_blocks_xss"] = True
                        if evidence["detected_waf"] == "none":
                            evidence["detected_waf"] = "unknown_waf"

                        try:
                            waf_body = await waf_resp.text()
                            for waf_name, sigs in WAF_SIGNATURES.items():
                                for pattern in sigs.get("body_patterns", []):
                                    if pattern.lower() in waf_body.lower():
                                        evidence["detected_waf"] = waf_name
                                        evidence["confidence"] = "high"
                                        break
                        except Exception:
                            pass
                    else:
                        evidence["waf_blocks_xss"] = False
            except Exception:
                pass

            if evidence["detected_waf"] == "none":
                vulns.append(self._create_vulnerability(
                    title="No WAF Detected",
                    description=(
                        "No Web Application Firewall was detected protecting the target. "
                        "The application may be directly exposed to attack payloads."
                    ),
                    severity="medium",
                    type="evasion_no_waf",
                    evidence=evidence,
                    cwe_id="CWE-693",
                    remediation="Deploy a WAF (e.g., Cloudflare, AWS WAF, ModSecurity) to filter malicious requests.",
                ))

        except Exception as e:
            logger.debug(f"WAF fingerprinting error: {e}")
            evidence["error"] = str(e)

        return vulns, evidence

    async def _test_encoding_bypass(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Test payload encoding techniques for WAF bypass."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "bypasses_found": 0,
            "techniques_tested": [],
            "successful_encodings": [],
        }

        try:
            base_payload = "<script>alert(1)</script>"

            # First check if the base payload is blocked
            params = await self._discover_parameters(url)
            test_param = params[0] if params else "q"

            base_result = await self._test_payload(url, test_param, base_payload)
            base_blocked = base_result["status_code"] in [403, 406, 429, 503]

            if not base_blocked:
                evidence["note"] = "Base payload not blocked, encoding bypass not applicable"
                return vulns, evidence

            # Test each encoding technique
            for enc_name, enc_func in ENCODING_TECHNIQUES.items():
                encoded = enc_func(base_payload)
                result = await self._test_payload(url, test_param, encoded)

                technique_result = {
                    "encoding": enc_name,
                    "blocked": result["status_code"] in [403, 406, 429, 503],
                    "status": result["status_code"],
                }
                evidence["techniques_tested"].append(technique_result)

                if not technique_result["blocked"] and result["status_code"] == 200:
                    evidence["bypasses_found"] += 1
                    evidence["successful_encodings"].append(enc_name)

                await asyncio.sleep(0.5)

            if evidence["bypasses_found"] > 0:
                vulns.append(self._create_vulnerability(
                    title=f"WAF Bypass via Encoding ({evidence['bypasses_found']} methods)",
                    description=(
                        f"The WAF can be bypassed using {evidence['bypasses_found']} encoding "
                        f"technique(s): {', '.join(evidence['successful_encodings'])}. "
                        "Encoded payloads pass through the WAF undetected."
                    ),
                    severity="high",
                    type="evasion_encoding_bypass",
                    evidence={
                        "bypasses": evidence["successful_encodings"],
                        "total_tested": len(evidence["techniques_tested"]),
                    },
                    cwe_id="CWE-693",
                    remediation="Update WAF rules to decode and inspect encoded payloads. Enable recursive decoding.",
                ))

        except Exception as e:
            logger.debug(f"Encoding bypass test error: {e}")

        return vulns, evidence

    async def _test_request_smuggling(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Test for HTTP request smuggling vulnerabilities."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "vulnerable": False,
            "patterns_tested": [],
        }

        try:
            for pattern in SMUGGLING_PATTERNS:
                try:
                    # Send request with conflicting headers
                    response = await self.http_client.post(
                        url,
                        headers=pattern["headers"],
                        data="0\r\n\r\n",
                    )

                    result = {
                        "pattern": pattern["name"],
                        "description": pattern["description"],
                        "status": response.status if response else 0,
                        "suspicious": False,
                    }

                    if response:
                        # Check for desync indicators
                        if response.status in [400, 500]:
                            result["suspicious"] = True
                            result["indicator"] = "server_error_on_conflicting_headers"

                        # Check for timeout or connection reset (strong indicator)
                        content_length = response.headers.get("Content-Length", "")
                        transfer_encoding = response.headers.get("Transfer-Encoding", "")
                        if content_length and transfer_encoding:
                            result["suspicious"] = True
                            result["indicator"] = "both_cl_and_te_in_response"

                    evidence["patterns_tested"].append(result)

                    if result["suspicious"]:
                        evidence["vulnerable"] = True

                except asyncio.TimeoutError:
                    evidence["patterns_tested"].append({
                        "pattern": pattern["name"],
                        "status": "timeout",
                        "suspicious": True,
                        "indicator": "connection_timeout",
                    })
                    evidence["vulnerable"] = True
                except Exception:
                    pass

            if evidence["vulnerable"]:
                vulns.append(self._create_vulnerability(
                    title="Potential HTTP Request Smuggling",
                    description=(
                        "The server shows signs of HTTP request smuggling vulnerability "
                        "when processing conflicting Content-Length and Transfer-Encoding headers."
                    ),
                    severity="critical",
                    type="evasion_request_smuggling",
                    evidence=evidence,
                    cwe_id="CWE-444",
                    remediation=(
                        "Normalize HTTP parsing. Reject ambiguous requests with both "
                        "Content-Length and Transfer-Encoding. Use HTTP/2 end-to-end."
                    ),
                ))

        except Exception as e:
            logger.debug(f"Request smuggling test error: {e}")

        return vulns, evidence

    async def _test_case_null_evasion(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Test case variation and null byte evasion techniques."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {"techniques_tested": [], "bypasses": []}

        try:
            params = await self._discover_parameters(url)
            test_param = params[0] if params else "q"

            # Case variation tests
            case_payloads = [
                ("<ScRiPt>alert(1)</ScRiPt>", "mixed_case"),
                ("<SCRIPT>alert(1)</SCRIPT>", "upper_case"),
                ("<scr\x00ipt>alert(1)</scr\x00ipt>", "null_byte"),
                ("<img/src=x onerror=alert(1)>", "tag_slash"),
                ("<img\tsrc=x\tonerror=alert(1)>", "tab_separator"),
            ]

            for payload, technique in case_payloads:
                result = await self._test_payload(url, test_param, payload)
                blocked = result["status_code"] in [403, 406, 429, 503]

                test_result = {
                    "technique": technique,
                    "blocked": blocked,
                    "status": result["status_code"],
                }
                evidence["techniques_tested"].append(test_result)

                if not blocked and result["status_code"] == 200:
                    evidence["bypasses"].append(technique)

                await asyncio.sleep(0.3)

            if evidence["bypasses"]:
                vulns.append(self._create_vulnerability(
                    title=f"WAF Bypass via Case/Encoding Tricks ({len(evidence['bypasses'])})",
                    description=(
                        f"Security controls can be bypassed using: {', '.join(evidence['bypasses'])}. "
                        "These techniques evade pattern-based filtering."
                    ),
                    severity="medium",
                    type="evasion_case_null_bypass",
                    evidence={"bypasses": evidence["bypasses"]},
                    cwe_id="CWE-693",
                    remediation="Normalize input (lowercase, remove null bytes) before WAF inspection.",
                ))

        except Exception as e:
            logger.debug(f"Case/null evasion test error: {e}")

        return vulns, evidence

    async def _test_slow_rate(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Test resilience to slow-rate attacks (Slowloris-style)."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "connections_held": 0,
            "vulnerable": False,
        }

        try:
            # Simulate slow-rate by sending partial requests
            # We use the HTTP client with very small chunks and delays
            start = time.monotonic()
            successful_connections = 0

            for _ in range(self.slow_rate_connections):
                try:
                    # Send request with very slow body
                    headers = {
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Content-Length": "1000",
                    }
                    # Just check if server accepts slow connections
                    resp = await asyncio.wait_for(
                        self.http_client.post(url, headers=headers, data="x" * 10),
                        timeout=5.0,
                    )
                    if resp:
                        successful_connections += 1
                except asyncio.TimeoutError:
                    successful_connections += 1  # Connection was held open
                except Exception:
                    pass

            elapsed = time.monotonic() - start
            evidence["connections_held"] = successful_connections
            evidence["test_duration_seconds"] = round(elapsed, 2)

            # If all connections were held without rejection, likely vulnerable
            if successful_connections >= self.slow_rate_connections:
                evidence["vulnerable"] = True
                vulns.append(self._create_vulnerability(
                    title="Potential Slow-Rate Attack Vulnerability",
                    description=(
                        f"The server held {successful_connections} slow connections open "
                        "without dropping them. This may indicate vulnerability to "
                        "Slowloris-style denial-of-service attacks."
                    ),
                    severity="medium",
                    type="evasion_slow_rate",
                    evidence=evidence,
                    cwe_id="CWE-400",
                    remediation=(
                        "Configure connection timeouts, limit connections per IP, "
                        "and use a reverse proxy with slow-client protection."
                    ),
                ))

        except Exception as e:
            logger.debug(f"Slow-rate test error: {e}")

        return vulns, evidence

    async def _test_fragment_evasion(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Test fragment-based evasion techniques."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {"techniques_tested": [], "bypasses": []}

        try:
            params = await self._discover_parameters(url)
            test_param = params[0] if params else "q"

            # Fragment-based payloads
            fragment_payloads = [
                ("java%0ascript:alert(1)", "newline_in_protocol"),
                ("<svg/onload=alert(1)>", "slash_separator"),
                ("<a href='ja\tvascript:alert(1)'>", "tab_in_protocol"),
                ("%3Cscript%3Ealert(1)%3C/script%3E", "full_url_encode"),
                ("<iframe src=jav&#x09;ascript:alert(1)>", "html_entity_tab"),
            ]

            for payload, technique in fragment_payloads:
                result = await self._test_payload(url, test_param, payload)
                blocked = result["status_code"] in [403, 406, 429, 503]

                evidence["techniques_tested"].append({
                    "technique": technique,
                    "blocked": blocked,
                    "status": result["status_code"],
                })

                if not blocked and result["status_code"] == 200:
                    # Check if payload appears in response (reflected)
                    if payload in result.get("page_content", ""):
                        evidence["bypasses"].append(technique)

                await asyncio.sleep(0.3)

        except Exception as e:
            logger.debug(f"Fragment evasion test error: {e}")

        return vulns, evidence
