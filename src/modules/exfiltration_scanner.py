"""
Data Exfiltration Assessment Module - Data Loss Prevention Testing

WARNING: This module is designed for AUTHORIZED penetration testing and security
assessments ONLY. Unauthorized use against systems you do not own or have explicit
written permission to test is ILLEGAL and UNETHICAL. Always obtain proper authorization
before conducting any security assessment.

This module performs ASSESSMENT ONLY - it tests if data exfiltration paths exist
but does NOT actually exfiltrate any data. It identifies DNS tunneling risks,
covert channels, large data exposure endpoints, DLP bypass paths, steganography
indicators, and WebSocket data channels.
"""

import asyncio
import base64
import logging
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from .base_scanner import BaseScanner, Vulnerability

logger = logging.getLogger(__name__)


# DNS tunneling indicators
DNS_TUNNEL_INDICATORS = {
    "long_subdomain_threshold": 40,  # chars
    "high_entropy_threshold": 3.8,
    "suspicious_record_types": ["TXT", "CNAME", "MX", "NULL"],
}

# Common data exposure endpoints
DATA_EXPOSURE_ENDPOINTS = [
    "/api/export", "/api/download", "/api/dump", "/api/backup",
    "/export", "/download", "/dump", "/backup",
    "/api/v1/export", "/api/v1/download",
    "/data/export", "/reports/download",
    "/admin/export", "/admin/backup",
    "/db/dump", "/database/export",
    "/.env", "/config.json", "/settings.json",
    "/debug/vars", "/actuator/env",
]

# Covert channel indicators
COVERT_CHANNEL_INDICATORS = {
    "timing_based": ["X-Response-Time", "Server-Timing"],
    "header_based": ["X-Custom", "X-Data", "X-Debug"],
    "cookie_based_max_size": 4096,
}


class ExfiltrationScanner(BaseScanner):
    """
    Data Exfiltration Assessment Scanner.

    AUTHORIZED USE ONLY: This module assesses the target's resistance
    to data exfiltration. It identifies potential exfiltration channels
    WITHOUT actually exfiltrating data.

    Features:
    - DNS tunneling detection and risk assessment
    - HTTP/HTTPS covert channel assessment
    - Large data exposure endpoint identification
    - DLP bypass path testing
    - Steganography detection in served content
    - WebSocket data channel assessment
    """

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "ExfiltrationScanner"
        self.description = "Data exfiltration path assessment (detection only)"
        self.version = "1.0.0"
        self.capabilities = [
            "DNS Tunneling Assessment",
            "Covert Channel Detection",
            "Data Exposure Endpoint Scanning",
            "DLP Bypass Testing",
            "Steganography Detection",
            "WebSocket Channel Assessment",
        ]
        self.max_requests = 60

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform data exfiltration assessment."""
        logger.info(f"Starting Exfiltration assessment for {url}")
        vulnerabilities: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "dns_tunneling": {},
            "covert_channels": {},
            "data_exposure": {},
            "dlp_bypass": {},
            "steganography": {},
            "websocket_channels": {},
        }

        try:
            # Phase 1: DNS Tunneling Assessment (20%)
            self._update_progress(progress_callback, 10, "Assessing DNS tunneling risks")
            dns_vulns, dns_evidence = await self._assess_dns_tunneling(url)
            vulnerabilities.extend(dns_vulns)
            evidence["dns_tunneling"] = dns_evidence

            # Phase 2: Covert Channel Assessment (35%)
            self._update_progress(progress_callback, 25, "Assessing covert channels")
            cov_vulns, cov_evidence = await self._assess_covert_channels(url)
            vulnerabilities.extend(cov_vulns)
            evidence["covert_channels"] = cov_evidence

            # Phase 3: Data Exposure Endpoints (55%)
            self._update_progress(progress_callback, 40, "Scanning data exposure endpoints")
            exp_vulns, exp_evidence = await self._scan_data_exposure(url)
            vulnerabilities.extend(exp_vulns)
            evidence["data_exposure"] = exp_evidence

            # Phase 4: DLP Bypass Assessment (70%)
            self._update_progress(progress_callback, 55, "Assessing DLP bypass paths")
            dlp_vulns, dlp_evidence = await self._assess_dlp_bypass(url)
            vulnerabilities.extend(dlp_vulns)
            evidence["dlp_bypass"] = dlp_evidence

            # Phase 5: Steganography Detection (85%)
            self._update_progress(progress_callback, 70, "Detecting steganography")
            steg_vulns, steg_evidence = await self._detect_steganography(url)
            vulnerabilities.extend(steg_vulns)
            evidence["steganography"] = steg_evidence

            # Phase 6: WebSocket Channel Assessment (100%)
            self._update_progress(progress_callback, 85, "Assessing WebSocket channels")
            ws_vulns, ws_evidence = await self._assess_websocket_channels(url)
            vulnerabilities.extend(ws_vulns)
            evidence["websocket_channels"] = ws_evidence

            self._update_progress(progress_callback, 100, "completed")

        except Exception as e:
            logger.error(f"Exfiltration assessment error: {e}")
            return self._format_result(
                "Error", f"Assessment failed: {str(e)}", vulnerabilities, evidence
            )

        details = (
            f"Exfiltration assessment completed (ASSESSMENT ONLY). "
            f"Found {len(vulnerabilities)} potential exfil path(s). "
            f"Data endpoints: {exp_evidence.get('exposed_count', 0)}, "
            f"Covert channels: {len(cov_evidence.get('channels_found', []))}"
        )

        return self._format_result("Completed", details, vulnerabilities, evidence)

    async def _assess_dns_tunneling(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Assess DNS tunneling risks."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "dns_security": "unknown",
            "tunneling_risk": "unknown",
        }

        try:
            parsed = urlparse(url)
            domain = parsed.hostname
            if not domain:
                return vulns, evidence

            evidence["target_domain"] = domain

            # Check if the target has DNS monitoring capabilities
            # by looking for indicators in security headers and configurations
            response = await self.http_client.get(url)
            if response:
                headers = {k.lower(): v for k, v in response.headers.items()}

                # Check for content security policy (CSP) which may restrict DNS
                csp = headers.get("content-security-policy", "")
                evidence["csp_present"] = bool(csp)

                # Check for DNS-related security headers
                evidence["dns_prefetch_control"] = headers.get("x-dns-prefetch-control", "not set")

            # Test DNS resolution characteristics
            try:
                # Use DoH to check for unusually long TXT records (tunneling indicator)
                doh_url = f"https://dns.google/resolve?name={domain}&type=TXT"
                resp = await self.http_client.get(doh_url)
                if resp and resp.status == 200:
                    import json
                    data = json.loads(await resp.text())
                    answers = data.get("Answer", [])

                    long_records = []
                    for ans in answers:
                        txt_data = ans.get("data", "")
                        if len(txt_data) > 200:
                            long_records.append({
                                "length": len(txt_data),
                                "preview": txt_data[:50] + "...",
                            })

                    evidence["long_txt_records"] = long_records
                    if long_records:
                        evidence["tunneling_risk"] = "elevated"
            except Exception:
                pass

            # Check if DNS exfiltration is possible by analyzing outbound DNS config
            evidence["tunneling_risk"] = evidence.get("tunneling_risk", "standard")

            if evidence["tunneling_risk"] == "elevated":
                vulns.append(self._create_vulnerability(
                    title="DNS Tunneling Risk - Long TXT Records",
                    description=(
                        "Unusually long DNS TXT records were detected for the target domain. "
                        "This pattern can indicate DNS tunneling for data exfiltration."
                    ),
                    severity="medium",
                    type="exfil_dns_tunneling",
                    evidence={"long_records": evidence.get("long_txt_records", [])},
                    cwe_id="CWE-200",
                    remediation="Monitor DNS query patterns. Implement DNS query length limits and filtering.",
                ))

        except Exception as e:
            logger.debug(f"DNS tunneling assessment error: {e}")

        return vulns, evidence

    async def _assess_covert_channels(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Assess HTTP covert channel possibilities."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {"channels_found": []}

        try:
            response = await self.http_client.get(url)
            if not response:
                return vulns, evidence

            headers = dict(response.headers)

            # Check for timing-based covert channels
            for timing_header in COVERT_CHANNEL_INDICATORS["timing_based"]:
                if timing_header in headers:
                    evidence["channels_found"].append({
                        "type": "timing",
                        "header": timing_header,
                        "value": headers[timing_header],
                        "description": "Server timing information can be used for covert signaling",
                    })

            # Check for large cookies (potential data channel)
            set_cookie = headers.get("Set-Cookie", "")
            if len(set_cookie) > COVERT_CHANNEL_INDICATORS["cookie_based_max_size"]:
                evidence["channels_found"].append({
                    "type": "cookie",
                    "size": len(set_cookie),
                    "description": "Unusually large cookie could carry exfiltrated data",
                })

            # Check for custom headers that could carry data
            custom_headers = {k: v for k, v in headers.items() if k.startswith("X-")}
            for header, value in custom_headers.items():
                if len(value) > 200:
                    evidence["channels_found"].append({
                        "type": "custom_header",
                        "header": header,
                        "value_length": len(value),
                        "description": "Large custom header could be a data channel",
                    })

            # Check CORS that allows data reading from any origin
            cors_origin = headers.get("Access-Control-Allow-Origin", "")
            if cors_origin == "*":
                evidence["channels_found"].append({
                    "type": "cors_wildcard",
                    "description": "Wildcard CORS enables cross-origin data reading",
                    "risk": "high",
                })

            if evidence["channels_found"]:
                vulns.append(self._create_vulnerability(
                    title=f"Potential Covert Channels ({len(evidence['channels_found'])})",
                    description=(
                        "Potential covert data channels were identified that could be "
                        "used for stealthy data exfiltration."
                    ),
                    severity="medium",
                    type="exfil_covert_channel",
                    evidence={"channels": evidence["channels_found"][:10]},
                    cwe_id="CWE-200",
                    remediation="Monitor HTTP headers for anomalies. Restrict custom headers and cookie sizes.",
                ))

        except Exception as e:
            logger.debug(f"Covert channel assessment error: {e}")

        return vulns, evidence

    async def _scan_data_exposure(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Scan for exposed data endpoints."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "exposed_count": 0,
            "endpoints": [],
        }

        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            for endpoint in DATA_EXPOSURE_ENDPOINTS:
                try:
                    resp = await self.http_client.get(f"{base_url}{endpoint}")
                    if resp and resp.status == 200:
                        content_type = resp.headers.get("Content-Type", "")
                        content_length = resp.headers.get("Content-Length", "0")

                        try:
                            size = int(content_length)
                        except ValueError:
                            size = 0

                        endpoint_info = {
                            "path": endpoint,
                            "status": resp.status,
                            "content_type": content_type[:50],
                            "size_bytes": size,
                        }

                        # Check if it contains actual data
                        if any(t in content_type for t in [
                            "json", "csv", "xml", "sql", "text/plain",
                            "octet-stream", "zip", "gzip",
                        ]):
                            endpoint_info["data_type"] = "structured_data"
                            evidence["exposed_count"] += 1
                        elif size > 10000:
                            endpoint_info["data_type"] = "large_response"
                            evidence["exposed_count"] += 1

                        evidence["endpoints"].append(endpoint_info)

                except Exception:
                    pass

            if evidence["exposed_count"] > 0:
                vulns.append(self._create_vulnerability(
                    title=f"Data Export Endpoints Exposed ({evidence['exposed_count']})",
                    description=(
                        f"Found {evidence['exposed_count']} accessible data export/download "
                        "endpoints. These could be used for bulk data exfiltration."
                    ),
                    severity="high",
                    type="exfil_data_exposure",
                    evidence={"endpoints": evidence["endpoints"][:10]},
                    cwe_id="CWE-200",
                    remediation="Require authentication for all data export endpoints. Implement access logging.",
                ))

        except Exception as e:
            logger.debug(f"Data exposure scan error: {e}")

        return vulns, evidence

    async def _assess_dlp_bypass(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Assess Data Loss Prevention bypass paths."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "bypass_paths": [],
            "dlp_indicators": False,
        }

        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # Check for upload endpoints (could be used for data staging)
            upload_paths = [
                "/upload", "/api/upload", "/file/upload",
                "/import", "/api/import", "/api/v1/upload",
            ]

            for path in upload_paths:
                try:
                    # Check if upload endpoint exists (OPTIONS or GET)
                    resp = await self.http_client.get(f"{base_url}{path}")
                    if resp and resp.status not in [404, 405]:
                        evidence["bypass_paths"].append({
                            "type": "upload_endpoint",
                            "path": path,
                            "status": resp.status,
                            "description": "Upload endpoint could stage data for exfiltration",
                        })
                except Exception:
                    pass

            # Check for base64 encoding acceptance (DLP bypass technique)
            response = await self.http_client.get(url)
            if response:
                try:
                    html = await response.text()
                    # Check for file upload forms
                    if 'type="file"' in html or "enctype" in html:
                        evidence["bypass_paths"].append({
                            "type": "file_upload_form",
                            "description": "File upload form could encode and upload sensitive data",
                        })

                    # Check for base64 content in page
                    b64_pattern = re.compile(r'data:[\w/+-]+;base64,[A-Za-z0-9+/=]{100,}')
                    b64_matches = b64_pattern.findall(html)
                    if b64_matches:
                        evidence["bypass_paths"].append({
                            "type": "base64_data",
                            "count": len(b64_matches),
                            "description": "Base64 encoded data present - DLP may not inspect",
                        })
                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"DLP bypass assessment error: {e}")

        return vulns, evidence

    async def _detect_steganography(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Detect potential steganography in served images."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "images_analyzed": 0,
            "suspicious_images": [],
        }

        try:
            response = await self.http_client.get(url)
            if not response or response.status != 200:
                return vulns, evidence

            html = ""
            try:
                html = await response.text()
            except Exception:
                return vulns, evidence

            # Find image URLs
            img_pattern = re.compile(r'<img[^>]+src=["\']([^"\']+)["\']', re.I)
            img_urls = img_pattern.findall(html)

            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            for img_url in img_urls[:10]:  # Limit analysis
                if not img_url.startswith("http"):
                    img_url = f"{base_url}{img_url}" if img_url.startswith("/") else f"{base_url}/{img_url}"

                try:
                    img_resp = await self.http_client.get(img_url)
                    if img_resp and img_resp.status == 200:
                        evidence["images_analyzed"] += 1

                        content_type = img_resp.headers.get("Content-Type", "")
                        content_length = img_resp.headers.get("Content-Length", "0")

                        try:
                            size = int(content_length)
                        except ValueError:
                            size = 0

                        # Check for suspicious indicators
                        suspicious = False
                        reasons = []

                        # Unusually large image for its type
                        if "png" in content_type and size > 5_000_000:
                            suspicious = True
                            reasons.append("unusually_large_png")
                        elif "jpeg" in content_type and size > 10_000_000:
                            suspicious = True
                            reasons.append("unusually_large_jpeg")

                        # Check for appended data after image EOF
                        try:
                            body = await img_resp.read()
                            if b"png" in content_type.encode():
                                # PNG ends with IEND chunk
                                iend_pos = body.find(b"IEND")
                                if iend_pos > 0 and iend_pos + 12 < len(body):
                                    trailing = len(body) - (iend_pos + 12)
                                    if trailing > 100:
                                        suspicious = True
                                        reasons.append(f"trailing_data_{trailing}_bytes")
                        except Exception:
                            pass

                        if suspicious:
                            evidence["suspicious_images"].append({
                                "url": img_url[:100],
                                "size": size,
                                "content_type": content_type,
                                "reasons": reasons,
                            })

                except Exception:
                    pass

            if evidence["suspicious_images"]:
                vulns.append(self._create_vulnerability(
                    title=f"Suspicious Image Content ({len(evidence['suspicious_images'])})",
                    description=(
                        "Images with potential steganographic content were detected. "
                        "This could indicate hidden data channels in image files."
                    ),
                    severity="low",
                    type="exfil_steganography",
                    evidence={"suspicious": evidence["suspicious_images"][:5]},
                    cwe_id="CWE-200",
                    remediation="Implement image re-encoding on upload. Monitor for unusual image sizes.",
                ))

        except Exception as e:
            logger.debug(f"Steganography detection error: {e}")

        return vulns, evidence

    async def _assess_websocket_channels(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Assess WebSocket-based data channels."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "websocket_endpoints": [],
            "unprotected": False,
        }

        try:
            response = await self.http_client.get(url)
            if not response or response.status != 200:
                return vulns, evidence

            html = ""
            try:
                html = await response.text()
            except Exception:
                return vulns, evidence

            # Find WebSocket URLs
            ws_pattern = re.compile(r'wss?://[^\s"\'<>]+')
            ws_urls = ws_pattern.findall(html)

            # Also check for WebSocket initialization code
            ws_init_patterns = [
                re.compile(r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']'),
                re.compile(r'WebSocket\s*\(\s*["\']([^"\']+)["\']'),
            ]

            for pattern in ws_init_patterns:
                matches = pattern.findall(html)
                ws_urls.extend(matches)

            for ws_url in set(ws_urls):
                endpoint_info = {
                    "url": ws_url[:200],
                    "protocol": "wss" if ws_url.startswith("wss") else "ws",
                }

                # Check if WS endpoint requires auth
                if "token" not in ws_url.lower() and "auth" not in ws_url.lower():
                    endpoint_info["auth_required"] = "unlikely"
                    evidence["unprotected"] = True
                else:
                    endpoint_info["auth_required"] = "likely"

                evidence["websocket_endpoints"].append(endpoint_info)

            if evidence["unprotected"]:
                vulns.append(self._create_vulnerability(
                    title="Unprotected WebSocket Channels",
                    description=(
                        "WebSocket endpoints were found without apparent authentication. "
                        "These could serve as covert data exfiltration channels."
                    ),
                    severity="medium",
                    type="exfil_websocket_channel",
                    evidence={"endpoints": evidence["websocket_endpoints"][:10]},
                    cwe_id="CWE-306",
                    remediation="Require authentication for all WebSocket connections. Monitor WS traffic.",
                ))

        except Exception as e:
            logger.debug(f"WebSocket channel assessment error: {e}")

        return vulns, evidence
