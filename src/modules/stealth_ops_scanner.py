"""
Stealth/OPSEC Scanner Module - Operational Security Assessment

WARNING: This module is designed for AUTHORIZED penetration testing and security
assessments ONLY. Unauthorized use against systems you do not own or have explicit
written permission to test is ILLEGAL and UNETHICAL. Always obtain proper authorization
before conducting any security assessment.

This module assesses the target's ability to detect and respond to stealthy
reconnaissance techniques, including proxy chain rotation, user-agent rotation,
request timing analysis, and traffic pattern obfuscation.
"""

import asyncio
import hashlib
import logging
import random
import re
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from .base_scanner import BaseScanner, Vulnerability

logger = logging.getLogger(__name__)


# Realistic browser fingerprints for User-Agent rotation
BROWSER_FINGERPRINTS = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    # Chrome on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Firefox on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Safari on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    # Chrome on Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Firefox on Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Mobile Chrome
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    # Mobile Safari
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
]

# Known DoH (DNS-over-HTTPS) providers
DOH_PROVIDERS = [
    "https://dns.google/dns-query",
    "https://cloudflare-dns.com/dns-query",
    "https://dns.quad9.net/dns-query",
    "https://doh.opendns.com/dns-query",
]

# Common proxy detection indicators
PROXY_DETECTION_HEADERS = [
    "X-Forwarded-For",
    "X-Real-IP",
    "Via",
    "Forwarded",
    "X-Proxy-ID",
    "X-BlueCoat-Via",
    "X-Forwarded-Proto",
    "X-Forwarded-Host",
]

# TLS fingerprint characteristics (JA3-like patterns)
KNOWN_TLS_FINGERPRINTS = {
    "chrome_120": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53",
    "firefox_121": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49172-49171-156-157-47-53",
    "safari_17": "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47",
    "curl_default": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53",
}


class StealthOpsScanner(BaseScanner):
    """
    Operational Security (OPSEC) Assessment Scanner.

    AUTHORIZED USE ONLY: This module assesses the target's detection capabilities
    against common stealth techniques used in penetration testing. It evaluates
    proxy detection, user-agent analysis, timing-based detection, and traffic
    pattern recognition.

    This module does NOT perform actual attacks. It tests whether the target
    can detect various evasion techniques that an attacker might use.
    """

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "StealthOpsScanner"
        self.description = "Operational security assessment - tests target detection capabilities"
        self.version = "1.0.0"
        self.capabilities = [
            "Proxy Detection Assessment",
            "User-Agent Analysis",
            "Timing Jitter Analysis",
            "TLS Fingerprint Assessment",
            "DNS-over-HTTPS Testing",
            "Traffic Pattern Obfuscation",
        ]
        # Safety limits
        self.max_requests = 50
        self.min_jitter_ms = 100
        self.max_jitter_ms = 3000

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform stealth/OPSEC assessment on the target."""
        logger.info(f"Starting Stealth/OPSEC assessment for {url}")
        vulnerabilities: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "proxy_detection": {},
            "ua_rotation": {},
            "timing_analysis": {},
            "tls_fingerprints": {},
            "doh_assessment": {},
            "traffic_patterns": {},
        }

        try:
            # Phase 1: Proxy Detection Assessment (20%)
            self._update_progress(progress_callback, 10, "Assessing proxy detection capabilities")
            proxy_vulns, proxy_evidence = await self._assess_proxy_detection(url)
            vulnerabilities.extend(proxy_vulns)
            evidence["proxy_detection"] = proxy_evidence

            # Phase 2: User-Agent Rotation Analysis (40%)
            self._update_progress(progress_callback, 25, "Testing user-agent rotation detection")
            ua_vulns, ua_evidence = await self._assess_ua_rotation(url)
            vulnerabilities.extend(ua_vulns)
            evidence["ua_rotation"] = ua_evidence

            # Phase 3: Request Timing Jitter Analysis (55%)
            self._update_progress(progress_callback, 40, "Analyzing timing-based detection")
            timing_vulns, timing_evidence = await self._assess_timing_detection(url)
            vulnerabilities.extend(timing_vulns)
            evidence["timing_analysis"] = timing_evidence

            # Phase 4: TLS Fingerprint Assessment (70%)
            self._update_progress(progress_callback, 55, "Assessing TLS fingerprint detection")
            tls_vulns, tls_evidence = await self._assess_tls_fingerprinting(url)
            vulnerabilities.extend(tls_vulns)
            evidence["tls_fingerprints"] = tls_evidence

            # Phase 5: DNS-over-HTTPS Assessment (85%)
            self._update_progress(progress_callback, 70, "Testing DNS-over-HTTPS capabilities")
            doh_vulns, doh_evidence = await self._assess_doh_capabilities(url)
            vulnerabilities.extend(doh_vulns)
            evidence["doh_assessment"] = doh_evidence

            # Phase 6: Traffic Pattern Obfuscation (100%)
            self._update_progress(progress_callback, 85, "Analyzing traffic pattern detection")
            traffic_vulns, traffic_evidence = await self._assess_traffic_patterns(url)
            vulnerabilities.extend(traffic_vulns)
            evidence["traffic_patterns"] = traffic_evidence

            self._update_progress(progress_callback, 100, "completed")

        except Exception as e:
            logger.error(f"Stealth/OPSEC assessment error: {e}")
            return self._format_result(
                "Error", f"Assessment failed: {str(e)}", vulnerabilities, evidence
            )

        details = (
            f"Stealth/OPSEC assessment completed. "
            f"Found {len(vulnerabilities)} detection gap(s). "
            f"Proxy detection: {proxy_evidence.get('detection_level', 'unknown')}, "
            f"UA tracking: {ua_evidence.get('tracking_detected', 'unknown')}, "
            f"Timing analysis: {timing_evidence.get('timing_detection', 'unknown')}"
        )

        return self._format_result("Completed", details, vulnerabilities, evidence)

    async def _assess_proxy_detection(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Assess target's ability to detect proxy usage."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {"headers_tested": [], "detection_level": "unknown"}

        try:
            # Test 1: Send request with proxy-related headers
            proxy_headers_found = []
            response = await self.http_client.get(url)
            if response:
                resp_headers = {k.lower(): v for k, v in response.headers.items()}

                # Check if target echoes back proxy headers
                for header in PROXY_DETECTION_HEADERS:
                    if header.lower() in resp_headers:
                        proxy_headers_found.append(header)

                evidence["headers_tested"] = PROXY_DETECTION_HEADERS
                evidence["headers_echoed"] = proxy_headers_found

                # Test 2: Send requests with fake proxy headers to see if blocked
                fake_proxy_headers = {
                    "X-Forwarded-For": "127.0.0.1",
                    "X-Real-IP": "10.0.0.1",
                    "Via": "1.1 proxy.example.com",
                }
                proxy_response = await self.http_client.get(url, headers=fake_proxy_headers)

                if proxy_response and proxy_response.status == response.status:
                    evidence["detection_level"] = "none"
                    vulns.append(self._create_vulnerability(
                        title="No Proxy Detection Mechanism",
                        description=(
                            "The target does not detect or block requests with proxy-related headers. "
                            "An attacker could use proxy chains to anonymize their traffic without detection."
                        ),
                        severity="medium",
                        type="stealth_proxy_detection",
                        evidence={
                            "tested_headers": list(fake_proxy_headers.keys()),
                            "response_status": proxy_response.status,
                            "blocked": False,
                        },
                        cwe_id="CWE-778",
                        remediation="Implement proxy detection by analyzing X-Forwarded-For chains and request anomalies.",
                    ))
                elif proxy_response and proxy_response.status in [403, 429]:
                    evidence["detection_level"] = "active"
                else:
                    evidence["detection_level"] = "partial"

                # Test 3: Check for IP reputation / geolocation headers
                geo_headers = ["X-Country", "X-Geo", "CF-IPCountry", "X-Client-Geo"]
                geo_found = [h for h in geo_headers if h.lower() in resp_headers]
                evidence["geo_headers"] = geo_found

        except Exception as e:
            logger.debug(f"Proxy detection assessment error: {e}")
            evidence["error"] = str(e)

        return vulns, evidence

    async def _assess_ua_rotation(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Assess target's response to different user agents."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "agents_tested": 0,
            "tracking_detected": "unknown",
            "consistent_responses": True,
        }

        try:
            responses = []
            sample_uas = random.sample(BROWSER_FINGERPRINTS, min(5, len(BROWSER_FINGERPRINTS)))

            for ua in sample_uas:
                await asyncio.sleep(random.uniform(0.1, 0.5))  # Jitter
                headers = {"User-Agent": ua}
                response = await self.http_client.get(url, headers=headers)
                if response:
                    responses.append({
                        "ua": ua[:50],
                        "status": response.status,
                        "content_length": response.headers.get("Content-Length", "unknown"),
                        "set_cookie": "Set-Cookie" in response.headers,
                    })

            evidence["agents_tested"] = len(responses)

            if responses:
                # Check if all responses are consistent (no UA-based blocking)
                statuses = set(r["status"] for r in responses)
                if len(statuses) == 1 and 200 in statuses:
                    evidence["tracking_detected"] = "none"
                    vulns.append(self._create_vulnerability(
                        title="No User-Agent Based Detection",
                        description=(
                            "The target responds identically to various user agents, including "
                            "rapid rotation between different browser fingerprints. This allows "
                            "an attacker to evade user-agent based tracking."
                        ),
                        severity="low",
                        type="stealth_ua_detection",
                        evidence={
                            "agents_tested": len(responses),
                            "all_same_status": True,
                        },
                        cwe_id="CWE-778",
                        remediation="Implement user-agent consistency tracking to detect rapid UA switching.",
                    ))
                elif len(statuses) > 1:
                    evidence["tracking_detected"] = "partial"
                    evidence["varied_statuses"] = list(statuses)

                # Check cookie-based tracking
                cookie_responses = [r for r in responses if r["set_cookie"]]
                evidence["cookie_tracking"] = len(cookie_responses) > 0

        except Exception as e:
            logger.debug(f"UA rotation assessment error: {e}")
            evidence["error"] = str(e)

        return vulns, evidence

    async def _assess_timing_detection(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Assess target's ability to detect timing-based anomalies."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "timing_detection": "unknown",
            "response_times": [],
        }

        try:
            # Send requests with varying timing to detect rate limiting or anomaly detection
            response_times = []

            # Burst: 5 rapid requests
            for _ in range(5):
                start = time.monotonic()
                response = await self.http_client.get(url)
                elapsed = time.monotonic() - start
                status = response.status if response else 0
                response_times.append({"delay_ms": 0, "response_time_ms": round(elapsed * 1000, 2), "status": status})

            # Check if any burst requests were rate-limited
            burst_statuses = [r["status"] for r in response_times]
            rate_limited = any(s == 429 for s in burst_statuses)

            # Jittered: 3 requests with random delays
            for _ in range(3):
                jitter = random.uniform(self.min_jitter_ms, self.max_jitter_ms) / 1000
                await asyncio.sleep(jitter)
                start = time.monotonic()
                response = await self.http_client.get(url)
                elapsed = time.monotonic() - start
                status = response.status if response else 0
                response_times.append({
                    "delay_ms": round(jitter * 1000, 2),
                    "response_time_ms": round(elapsed * 1000, 2),
                    "status": status,
                })

            evidence["response_times"] = response_times

            if not rate_limited:
                evidence["timing_detection"] = "none"
                vulns.append(self._create_vulnerability(
                    title="No Rate Limiting on Rapid Requests",
                    description=(
                        "The target does not implement rate limiting for rapid sequential requests. "
                        "An attacker could perform high-speed scanning without detection or throttling."
                    ),
                    severity="medium",
                    type="stealth_timing_detection",
                    evidence={
                        "burst_requests": 5,
                        "all_successful": all(s == 200 for s in burst_statuses),
                        "rate_limited": False,
                    },
                    cwe_id="CWE-770",
                    remediation="Implement rate limiting and request timing anomaly detection.",
                ))
            else:
                evidence["timing_detection"] = "active"

        except Exception as e:
            logger.debug(f"Timing detection assessment error: {e}")
            evidence["error"] = str(e)

        return vulns, evidence

    async def _assess_tls_fingerprinting(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Assess TLS fingerprint detection capabilities."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "tls_version": "unknown",
            "fingerprint_detection": "unknown",
        }

        try:
            parsed = urlparse(url)
            is_https = parsed.scheme == "https"
            evidence["is_https"] = is_https

            if is_https:
                # Test with default TLS settings
                response = await self.http_client.get(url)
                if response:
                    # Check for TLS-related response headers
                    headers = {k.lower(): v for k, v in response.headers.items()}

                    # Look for JA3 fingerprint blocking indicators
                    tls_indicators = {
                        "strict-transport-security": headers.get("strict-transport-security", ""),
                        "expect-ct": headers.get("expect-ct", ""),
                    }
                    evidence["tls_headers"] = tls_indicators
                    evidence["fingerprint_detection"] = "none"

                    if not tls_indicators.get("strict-transport-security"):
                        vulns.append(self._create_vulnerability(
                            title="Missing HSTS - TLS Downgrade Possible",
                            description=(
                                "The target does not enforce HSTS, making it vulnerable to "
                                "TLS downgrade attacks. An attacker could intercept traffic "
                                "by forcing HTTP connections."
                            ),
                            severity="medium",
                            type="stealth_tls_downgrade",
                            evidence={"hsts_header": False},
                            cwe_id="CWE-319",
                            remediation="Enable HSTS with a minimum max-age of 31536000 seconds.",
                        ))
            else:
                evidence["tls_assessment"] = "skipped_http_only"
                vulns.append(self._create_vulnerability(
                    title="No TLS Encryption",
                    description=(
                        "The target uses plain HTTP without TLS encryption. "
                        "All traffic is visible to network observers, making stealth irrelevant."
                    ),
                    severity="high",
                    type="stealth_no_tls",
                    evidence={"scheme": parsed.scheme},
                    cwe_id="CWE-319",
                    remediation="Enable TLS/HTTPS for all connections.",
                ))

        except Exception as e:
            logger.debug(f"TLS fingerprint assessment error: {e}")
            evidence["error"] = str(e)

        return vulns, evidence

    async def _assess_doh_capabilities(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Assess DNS-over-HTTPS availability and DNS security."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "doh_providers_tested": [],
            "dns_security": "unknown",
        }

        try:
            parsed = urlparse(url)
            domain = parsed.hostname

            if not domain:
                evidence["dns_security"] = "skipped_no_domain"
                return vulns, evidence

            # Check if target domain has DNSSEC
            evidence["target_domain"] = domain

            # Test DoH resolution availability
            doh_results = []
            for provider in DOH_PROVIDERS[:2]:  # Test 2 providers
                try:
                    doh_url = f"{provider}?name={domain}&type=A"
                    headers = {"Accept": "application/dns-json"}
                    response = await self.http_client.get(doh_url, headers=headers)
                    if response and response.status == 200:
                        doh_results.append({
                            "provider": provider,
                            "status": "available",
                        })
                    else:
                        doh_results.append({
                            "provider": provider,
                            "status": "unavailable",
                        })
                except Exception:
                    doh_results.append({"provider": provider, "status": "error"})

            evidence["doh_providers_tested"] = doh_results
            evidence["doh_available"] = any(r["status"] == "available" for r in doh_results)

            # Check for DNS rebinding protection
            localhost_headers = {"Host": "localhost"}
            try:
                response = await self.http_client.get(url, headers=localhost_headers)
                if response and response.status == 200:
                    vulns.append(self._create_vulnerability(
                        title="DNS Rebinding Vulnerability",
                        description=(
                            "The target accepts requests with a 'Host: localhost' header, "
                            "indicating potential DNS rebinding vulnerability."
                        ),
                        severity="medium",
                        type="stealth_dns_rebinding",
                        evidence={"host_header": "localhost", "response_status": response.status},
                        cwe_id="CWE-350",
                        remediation="Validate Host headers and reject requests with unexpected values.",
                    ))
            except Exception:
                pass

        except Exception as e:
            logger.debug(f"DoH assessment error: {e}")
            evidence["error"] = str(e)

        return vulns, evidence

    async def _assess_traffic_patterns(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Assess target's ability to detect anomalous traffic patterns."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "pattern_detection": "unknown",
            "sequential_access": {},
        }

        try:
            # Simulate normal browsing pattern: access main page, then linked resources
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # Fetch main page
            response = await self.http_client.get(url)
            if not response or response.status != 200:
                evidence["pattern_detection"] = "skipped"
                return vulns, evidence

            # Extract some links to simulate browsing
            try:
                html = await response.text()
                link_pattern = re.compile(r'href=["\']([^"\']+)["\']')
                links = link_pattern.findall(html)
                internal_links = [
                    l for l in links
                    if l.startswith("/") or l.startswith(base_url)
                ][:5]
            except Exception:
                internal_links = []

            # Access pages with realistic browsing timing
            browsing_results = []
            for link in internal_links[:3]:
                full_url = link if link.startswith("http") else f"{base_url}{link}"
                await asyncio.sleep(random.uniform(0.5, 2.0))  # Human-like delay
                try:
                    resp = await self.http_client.get(full_url)
                    browsing_results.append({
                        "url": full_url[:80],
                        "status": resp.status if resp else 0,
                    })
                except Exception:
                    pass

            evidence["sequential_access"] = {
                "pages_visited": len(browsing_results),
                "results": browsing_results,
            }

            # Now test rapid sequential access (scanner-like pattern)
            rapid_results = []
            for link in internal_links[:3]:
                full_url = link if link.startswith("http") else f"{base_url}{link}"
                try:
                    resp = await self.http_client.get(full_url)
                    rapid_results.append({
                        "url": full_url[:80],
                        "status": resp.status if resp else 0,
                    })
                except Exception:
                    pass

            # Compare: did rapid access trigger any blocking?
            rapid_blocked = any(r["status"] in [403, 429, 503] for r in rapid_results)
            normal_blocked = any(r["status"] in [403, 429, 503] for r in browsing_results)

            if not rapid_blocked and not normal_blocked:
                evidence["pattern_detection"] = "none"
                vulns.append(self._create_vulnerability(
                    title="No Traffic Pattern Anomaly Detection",
                    description=(
                        "The target does not distinguish between normal browsing patterns "
                        "and rapid automated scanning. An attacker could perform automated "
                        "reconnaissance without triggering security alerts."
                    ),
                    severity="low",
                    type="stealth_traffic_pattern",
                    evidence={
                        "normal_browsing_blocked": normal_blocked,
                        "rapid_scanning_blocked": rapid_blocked,
                    },
                    cwe_id="CWE-778",
                    remediation="Implement behavioral analysis to detect automated scanning patterns.",
                ))
            elif rapid_blocked and not normal_blocked:
                evidence["pattern_detection"] = "active"
            else:
                evidence["pattern_detection"] = "partial"

        except Exception as e:
            logger.debug(f"Traffic pattern assessment error: {e}")
            evidence["error"] = str(e)

        return vulns, evidence
