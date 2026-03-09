"""
C2 (Command & Control) Detection Module - Defensive C2 Indicator Scanner

WARNING: This module is designed for AUTHORIZED penetration testing and security
assessments ONLY. Unauthorized use against systems you do not own or have explicit
written permission to test is ILLEGAL and UNETHICAL. Always obtain proper authorization
before conducting any security assessment.

This is a DEFENSIVE module that detects Command & Control indicators on the target.
It does NOT operate a C2 server. It identifies signs that a target may already be
compromised by detecting beacon patterns, suspicious connections, DGA domains,
and known C2 framework fingerprints.
"""

import asyncio
import hashlib
import logging
import math
import re
import struct
from collections import Counter
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from .base_scanner import BaseScanner, Vulnerability

logger = logging.getLogger(__name__)


# Known C2 framework indicators
COBALT_STRIKE_INDICATORS = {
    "default_ports": [50050, 443, 8443, 8080],
    "beacon_paths": [
        "/pixel.gif", "/submit.php", "/visit.js", "/load",
        "/__utm.gif", "/ga.js", "/updates.rss", "/fwlink",
        "/cm", "/cx", "/updates", "/activity",
    ],
    "headers": {
        "Content-Type": ["application/octet-stream"],
        "Cache-Control": ["no-cache"],
    },
    "malleable_indicators": [
        "MZRE",  # PE header in response
        "MZAR",  # Alternative PE header
    ],
}

SLIVER_INDICATORS = {
    "default_ports": [31337, 8888, 443],
    "paths": ["/login", "/api/v1/session", "/connect"],
    "tls_patterns": ["sliver", "bishopfox"],
}

MYTHIC_INDICATORS = {
    "default_ports": [7443, 443],
    "paths": ["/api/v1.4/agent_message", "/api/v1.4/crypto"],
    "headers": {"Mythic": True, "Server": "Mythic"},
}

# Known JA3 hashes for C2 frameworks
KNOWN_C2_JA3_HASHES = {
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike (default)",
    "a0e9f5d64349fb13191bc781f81f42e1": "Cobalt Strike (modified)",
    "51c64c77e60f3980eea90869b68c58a8": "Metasploit Meterpreter",
    "4d7a28d6f2263ed61de88ca66eb2e820": "PoshC2",
    "e7d705a3286e19ea42f587b344ee6865": "Covenant",
    "6734f37431670b3ab4292b8f60f29984": "Sliver",
    "3b5074b1b5d032e5620f69f9f700ff0e": "Empire",
    "a353c5d2f8cdb6f4a4bae4bf66e19f76": "Brute Ratel C4",
}

# DGA (Domain Generation Algorithm) characteristics
DGA_INDICATORS = {
    "high_entropy_threshold": 3.5,
    "suspicious_tlds": [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz"],
    "max_label_length": 20,
    "consonant_cluster_threshold": 4,
}


class C2DetectionScanner(BaseScanner):
    """
    C2 (Command & Control) Detection Scanner - Defensive.

    AUTHORIZED USE ONLY: This module detects indicators of Command & Control
    infrastructure on the target. It is PURELY DEFENSIVE - it identifies signs
    that a target may be compromised, NOT to establish C2 channels.

    Detection capabilities:
    - Cobalt Strike beacon detection
    - Sliver implant detection
    - Mythic agent detection
    - DGA (Domain Generation Algorithm) domain detection
    - Malleable C2 profile detection
    - JA3/JA3S TLS fingerprint matching
    - Suspicious outbound connection indicators
    """

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "C2DetectionScanner"
        self.description = "Defensive C2 indicator detection - identifies compromised systems"
        self.version = "1.0.0"
        self.capabilities = [
            "Cobalt Strike Detection",
            "Sliver Detection",
            "Mythic Detection",
            "DGA Domain Detection",
            "Malleable C2 Profile Detection",
            "JA3/JA3S Fingerprint Matching",
        ]
        self.max_requests = 80

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform C2 detection scan on the target."""
        logger.info(f"Starting C2 detection scan for {url}")
        vulnerabilities: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "cobalt_strike": {},
            "sliver": {},
            "mythic": {},
            "dga_domains": [],
            "malleable_c2": {},
            "ja3_analysis": {},
            "suspicious_connections": [],
        }

        try:
            # Phase 1: Cobalt Strike Beacon Detection (20%)
            self._update_progress(progress_callback, 10, "Scanning for Cobalt Strike indicators")
            cs_vulns, cs_evidence = await self._detect_cobalt_strike(url)
            vulnerabilities.extend(cs_vulns)
            evidence["cobalt_strike"] = cs_evidence

            # Phase 2: Sliver/Mythic Detection (35%)
            self._update_progress(progress_callback, 25, "Scanning for Sliver/Mythic indicators")
            sl_vulns, sl_evidence = await self._detect_sliver(url)
            vulnerabilities.extend(sl_vulns)
            evidence["sliver"] = sl_evidence

            my_vulns, my_evidence = await self._detect_mythic(url)
            vulnerabilities.extend(my_vulns)
            evidence["mythic"] = my_evidence

            # Phase 3: DGA Domain Detection (50%)
            self._update_progress(progress_callback, 40, "Analyzing for DGA patterns")
            dga_vulns, dga_evidence = await self._detect_dga_domains(url)
            vulnerabilities.extend(dga_vulns)
            evidence["dga_domains"] = dga_evidence

            # Phase 4: Malleable C2 Profile Detection (70%)
            self._update_progress(progress_callback, 55, "Checking for malleable C2 profiles")
            mc2_vulns, mc2_evidence = await self._detect_malleable_c2(url)
            vulnerabilities.extend(mc2_vulns)
            evidence["malleable_c2"] = mc2_evidence

            # Phase 5: JA3/JA3S Analysis (85%)
            self._update_progress(progress_callback, 70, "Analyzing TLS fingerprints")
            ja3_vulns, ja3_evidence = await self._analyze_ja3_fingerprints(url)
            vulnerabilities.extend(ja3_vulns)
            evidence["ja3_analysis"] = ja3_evidence

            # Phase 6: Suspicious Connection Analysis (100%)
            self._update_progress(progress_callback, 85, "Analyzing suspicious connections")
            conn_vulns, conn_evidence = await self._analyze_suspicious_connections(url)
            vulnerabilities.extend(conn_vulns)
            evidence["suspicious_connections"] = conn_evidence

            self._update_progress(progress_callback, 100, "completed")

        except Exception as e:
            logger.error(f"C2 detection scan error: {e}")
            return self._format_result(
                "Error", f"Scan failed: {str(e)}", vulnerabilities, evidence
            )

        details = (
            f"C2 detection scan completed. "
            f"Found {len(vulnerabilities)} C2 indicator(s). "
            f"CS beacons: {cs_evidence.get('beacons_found', 0)}, "
            f"DGA domains: {len(evidence.get('dga_domains', []))}, "
            f"Suspicious connections: {len(evidence.get('suspicious_connections', []))}"
        )

        return self._format_result("Completed", details, vulnerabilities, evidence)

    async def _detect_cobalt_strike(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Detect Cobalt Strike beacon indicators."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {"beacons_found": 0, "indicators": []}

        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # Check known beacon paths
            for path in COBALT_STRIKE_INDICATORS["beacon_paths"]:
                try:
                    resp = await self.http_client.get(f"{base_url}{path}")
                    if resp and resp.status == 200:
                        content_type = resp.headers.get("Content-Type", "")
                        content_length = resp.headers.get("Content-Length", "0")

                        # Check for suspicious response patterns
                        suspicious = False
                        reasons = []

                        # Cobalt Strike beacons often have specific content types
                        if "octet-stream" in content_type:
                            suspicious = True
                            reasons.append("binary content-type")

                        # Check response body for PE header indicators
                        try:
                            body = await resp.read()
                            if body[:2] in [b"MZ", b"TV"]:
                                suspicious = True
                                reasons.append("PE header detected")
                            # Check for XOR-encoded beacon config
                            if len(body) > 0 and len(body) < 500000:
                                # Look for beacon config magic bytes
                                for indicator in COBALT_STRIKE_INDICATORS["malleable_indicators"]:
                                    if indicator.encode() in body:
                                        suspicious = True
                                        reasons.append(f"malleable indicator: {indicator}")
                        except Exception:
                            pass

                        if suspicious:
                            evidence["beacons_found"] += 1
                            evidence["indicators"].append({
                                "path": path,
                                "content_type": content_type,
                                "reasons": reasons,
                            })
                except Exception:
                    pass

            # Check for default Cobalt Strike 404 response (unique pattern)
            try:
                resp = await self.http_client.get(f"{base_url}/aaa_random_cs_check_{id(self)}")
                if resp:
                    body = ""
                    try:
                        body = await resp.text()
                    except Exception:
                        pass
                    # CS default 404 is very short/empty
                    if resp.status == 404 and len(body.strip()) == 0:
                        evidence["indicators"].append({
                            "type": "empty_404",
                            "description": "Empty 404 response (common CS default)",
                        })
            except Exception:
                pass

            if evidence["beacons_found"] > 0:
                vulns.append(self._create_vulnerability(
                    title=f"Cobalt Strike Indicators Detected ({evidence['beacons_found']})",
                    description=(
                        "Cobalt Strike beacon indicators were detected on the target. "
                        "This may indicate an active compromise or red team operation."
                    ),
                    severity="critical",
                    type="c2_cobalt_strike",
                    evidence=evidence,
                    cwe_id="CWE-506",
                    remediation="Investigate immediately. Isolate affected systems and perform incident response.",
                ))

        except Exception as e:
            logger.debug(f"Cobalt Strike detection error: {e}")
            evidence["error"] = str(e)

        return vulns, evidence

    async def _detect_sliver(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Detect Sliver C2 framework indicators."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {"indicators": [], "detected": False}

        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            for path in SLIVER_INDICATORS["paths"]:
                try:
                    resp = await self.http_client.get(f"{base_url}{path}")
                    if resp:
                        headers = {k.lower(): v for k, v in resp.headers.items()}
                        server = headers.get("server", "").lower()

                        for pattern in SLIVER_INDICATORS["tls_patterns"]:
                            if pattern in server:
                                evidence["indicators"].append({
                                    "path": path,
                                    "indicator": f"Server header contains '{pattern}'",
                                })
                                evidence["detected"] = True
                except Exception:
                    pass

            if evidence["detected"]:
                vulns.append(self._create_vulnerability(
                    title="Sliver C2 Indicators Detected",
                    description="Sliver C2 framework indicators were found on the target.",
                    severity="critical",
                    type="c2_sliver",
                    evidence=evidence,
                    cwe_id="CWE-506",
                    remediation="Investigate immediately. Perform incident response procedures.",
                ))

        except Exception as e:
            logger.debug(f"Sliver detection error: {e}")

        return vulns, evidence

    async def _detect_mythic(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Detect Mythic C2 framework indicators."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {"indicators": [], "detected": False}

        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            for path in MYTHIC_INDICATORS["paths"]:
                try:
                    resp = await self.http_client.get(f"{base_url}{path}")
                    if resp:
                        headers = {k.lower(): v for k, v in resp.headers.items()}

                        if "mythic" in headers.get("server", "").lower():
                            evidence["indicators"].append({
                                "path": path,
                                "indicator": "Mythic server header",
                            })
                            evidence["detected"] = True

                        # Check for Mythic-specific response patterns
                        if resp.status == 200:
                            try:
                                body = await resp.text()
                                if "agent_message" in body or "mythic" in body.lower():
                                    evidence["indicators"].append({
                                        "path": path,
                                        "indicator": "Mythic API response pattern",
                                    })
                            except Exception:
                                pass
                except Exception:
                    pass

            if evidence["detected"]:
                vulns.append(self._create_vulnerability(
                    title="Mythic C2 Indicators Detected",
                    description="Mythic C2 framework indicators were found on the target.",
                    severity="critical",
                    type="c2_mythic",
                    evidence=evidence,
                    cwe_id="CWE-506",
                    remediation="Investigate immediately. Perform incident response procedures.",
                ))

        except Exception as e:
            logger.debug(f"Mythic detection error: {e}")

        return vulns, evidence

    async def _detect_dga_domains(self, url: str) -> tuple[list[Vulnerability], list]:
        """Detect Domain Generation Algorithm (DGA) patterns."""
        vulns: list[Vulnerability] = []
        dga_domains: list[dict] = []

        try:
            response = await self.http_client.get(url)
            if not response:
                return vulns, dga_domains

            html = ""
            try:
                html = await response.text()
            except Exception:
                return vulns, dga_domains

            # Extract all domains from the page
            domain_pattern = re.compile(
                r'(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
                r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})'
            )
            domains = set(domain_pattern.findall(html))

            for domain in domains:
                score = self._calculate_dga_score(domain)
                if score > 0.7:
                    dga_domains.append({
                        "domain": domain,
                        "dga_score": round(score, 3),
                        "entropy": round(self._shannon_entropy(domain.split(".")[0]), 3),
                    })

            if dga_domains:
                vulns.append(self._create_vulnerability(
                    title=f"Potential DGA Domains Detected ({len(dga_domains)})",
                    description=(
                        "Domains with characteristics matching Domain Generation Algorithms (DGA) "
                        "were found in the target's content. These may indicate C2 communication."
                    ),
                    severity="high",
                    type="c2_dga_domains",
                    evidence={"dga_domains": dga_domains[:20]},
                    cwe_id="CWE-506",
                    remediation="Investigate identified domains. Block suspicious domains and monitor DNS traffic.",
                ))

        except Exception as e:
            logger.debug(f"DGA detection error: {e}")

        return vulns, dga_domains

    def _calculate_dga_score(self, domain: str) -> float:
        """Calculate likelihood that a domain is DGA-generated."""
        if not domain:
            return 0.0

        label = domain.split(".")[0].lower()
        score = 0.0
        factors = 0

        # Factor 1: Shannon entropy
        entropy = self._shannon_entropy(label)
        if entropy > DGA_INDICATORS["high_entropy_threshold"]:
            score += 0.3
        factors += 1

        # Factor 2: Label length
        if len(label) > DGA_INDICATORS["max_label_length"]:
            score += 0.2
        factors += 1

        # Factor 3: Consonant clusters
        consonant_runs = re.findall(r'[bcdfghjklmnpqrstvwxyz]{4,}', label)
        if consonant_runs:
            score += 0.2
        factors += 1

        # Factor 4: Digit ratio
        digit_ratio = sum(1 for c in label if c.isdigit()) / max(len(label), 1)
        if digit_ratio > 0.3:
            score += 0.15
        factors += 1

        # Factor 5: Suspicious TLD
        tld = "." + domain.split(".")[-1]
        if tld in DGA_INDICATORS["suspicious_tlds"]:
            score += 0.15
        factors += 1

        return min(score, 1.0)

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0
        freq = Counter(s)
        length = len(s)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )

    async def _detect_malleable_c2(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Detect malleable C2 profile indicators."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {"indicators": [], "detected": False}

        try:
            response = await self.http_client.get(url)
            if not response:
                return vulns, evidence

            headers = dict(response.headers)

            # Check for unusual header combinations typical of malleable C2
            suspicious_combos = [
                # CS default malleable profile often has these
                ("Content-Type", "application/octet-stream"),
                ("Content-Type", "image/gif"),
            ]

            for header, value in suspicious_combos:
                if headers.get(header) == value:
                    # Verify with body content check
                    try:
                        body = await response.read()
                        if body and value == "image/gif" and not body.startswith(b"GIF"):
                            evidence["indicators"].append({
                                "type": "content_type_mismatch",
                                "header_value": value,
                                "actual_content": "not_gif",
                            })
                    except Exception:
                        pass

            # Check for cookie-based C2 indicators
            set_cookie = headers.get("Set-Cookie", "")
            if set_cookie:
                # Unusually long cookie values may contain encoded C2 data
                cookie_values = re.findall(r'=([^;]+)', set_cookie)
                for val in cookie_values:
                    if len(val) > 200:  # Suspiciously long cookie
                        evidence["indicators"].append({
                            "type": "long_cookie",
                            "length": len(val),
                            "description": "Unusually long cookie value (possible C2 data channel)",
                        })

        except Exception as e:
            logger.debug(f"Malleable C2 detection error: {e}")

        return vulns, evidence

    async def _analyze_ja3_fingerprints(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Analyze TLS fingerprints against known C2 patterns."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "tls_info": {},
            "known_c2_match": False,
        }

        try:
            parsed = urlparse(url)
            if parsed.scheme != "https":
                evidence["tls_info"] = {"note": "HTTP only, no TLS fingerprint available"}
                return vulns, evidence

            # We can't compute JA3 directly from Python without raw TLS access,
            # but we can check server-side indicators
            response = await self.http_client.get(url)
            if response:
                headers = {k.lower(): v for k, v in response.headers.items()}
                evidence["tls_info"] = {
                    "server": headers.get("server", "unknown"),
                    "strict_transport": "strict-transport-security" in headers,
                    "tls_version": "TLS (exact version requires packet capture)",
                }

                # Note: Full JA3/JA3S analysis requires packet-level access
                evidence["note"] = (
                    "Full JA3/JA3S fingerprint analysis requires packet capture tools. "
                    "This assessment checks for server-side C2 indicators only."
                )

        except Exception as e:
            logger.debug(f"JA3 analysis error: {e}")
            evidence["error"] = str(e)

        return vulns, evidence

    async def _analyze_suspicious_connections(self, url: str) -> tuple[list[Vulnerability], list]:
        """Analyze for suspicious connection patterns."""
        vulns: list[Vulnerability] = []
        suspicious: list[dict] = []

        try:
            response = await self.http_client.get(url)
            if not response:
                return vulns, suspicious

            html = ""
            try:
                html = await response.text()
            except Exception:
                return vulns, suspicious

            # Look for external resources that could be C2 callbacks
            ext_resource_pattern = re.compile(
                r'(?:src|href|action|data-url)\s*=\s*["\']'
                r'(https?://[^"\']+)["\']'
            )
            external_urls = ext_resource_pattern.findall(html)

            parsed_target = urlparse(url)
            target_domain = parsed_target.netloc

            for ext_url in set(external_urls):
                try:
                    ext_parsed = urlparse(ext_url)
                    ext_domain = ext_parsed.netloc

                    if ext_domain and ext_domain != target_domain:
                        # Check for suspicious characteristics
                        dga_score = self._calculate_dga_score(ext_domain)
                        if dga_score > 0.5:
                            suspicious.append({
                                "url": ext_url[:200],
                                "domain": ext_domain,
                                "dga_score": round(dga_score, 3),
                                "reason": "High DGA score",
                            })

                        # Check for IP-based URLs (common in C2)
                        ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
                        if ip_pattern.match(ext_domain.split(":")[0]):
                            suspicious.append({
                                "url": ext_url[:200],
                                "domain": ext_domain,
                                "reason": "Direct IP address connection",
                            })

                        # Check for non-standard ports
                        if ":" in ext_domain:
                            port = ext_domain.split(":")[-1]
                            try:
                                port_num = int(port)
                                if port_num not in [80, 443, 8080, 8443]:
                                    suspicious.append({
                                        "url": ext_url[:200],
                                        "domain": ext_domain,
                                        "port": port_num,
                                        "reason": "Non-standard port",
                                    })
                            except ValueError:
                                pass
                except Exception:
                    pass

            if suspicious:
                vulns.append(self._create_vulnerability(
                    title=f"Suspicious External Connections ({len(suspicious)})",
                    description=(
                        "Suspicious external connections were identified that may indicate "
                        "C2 communication channels or compromised resources."
                    ),
                    severity="high",
                    type="c2_suspicious_connections",
                    evidence={"connections": suspicious[:20]},
                    cwe_id="CWE-506",
                    remediation="Investigate external connections. Verify all external resources are legitimate.",
                ))

        except Exception as e:
            logger.debug(f"Suspicious connection analysis error: {e}")

        return vulns, suspicious
