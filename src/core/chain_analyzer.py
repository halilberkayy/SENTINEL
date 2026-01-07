"""
Vulnerability Chaining Logic Module.
This module links multiple low-severity findings into high-risk attack chains.
"""

import logging
import re
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ChainResult:
    """Represents a discovered attack chain."""

    title: str
    risk_level: str  # critical, high, medium, low
    description: str
    steps: list[str]
    evidence: list[dict[str, Any]]
    remediation: str


class ChainAnalyzer:
    """
    Analyzes scan results to find vulnerability chains.
    Concept: Findings A + Finding B = Critical Impact C
    """

    def __init__(self):
        self.chains: list[ChainResult] = []

    def analyze(self, scan_results: list[Any]) -> list[ChainResult]:
        """
        Main entry point for chain analysis.
        scan_results: List of ScanResult objects from ScannerEngine.
        """
        self.chains = []

        # Flatten vulnerabilities for easier searching
        all_vulns = []
        for res in scan_results:
            if hasattr(res, "vulnerabilities"):
                all_vulns.extend(res.vulnerabilities)
            elif isinstance(res, dict) and "vulnerabilities" in res:
                all_vulns.extend(res["vulnerabilities"])

        # 1. Check for "Config Leak -> Credential Compromise" Chain
        self._check_config_credential_chain(all_vulns)

        # 2. Check for "SSRF -> Cloud/Internal Access" Chain
        self._check_ssrf_chain(all_vulns)

        # 3. Check for "XSS -> Session Hijacking" Chain
        self._check_xss_session_hijacking_chain(all_vulns)

        logger.info(f"Chain Analyzer completed. Found {len(self.chains)} chains.")
        return self.chains

    def _check_config_credential_chain(self, vulnerabilities: list[dict[str, Any]]):
        """
        Scenario:
        1. A sensitive file is exposed (e.g., .env, .git/config, wp-config.php.bak).
        2. The content of that file contains actual credentials (API Key, DB Password).
        """

        # Filter for sensitive file exposures
        sensitive_files = [
            v
            for v in vulnerabilities
            if v.get("type") == "misconfig" and ("Environment" in v.get("title", "") or "Config" in v.get("title", ""))
        ]

        if not sensitive_files:
            return

        # Regex patterns for high-value secrets
        # Examples: standard AWS keys, generic connection strings, private keys
        secret_patterns = {
            "AWS Access Key": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
            "Private Key": r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE\s+KEY",
            "Database Password": r'(?i)(password|passwd|pwd|secret)\s*[:=]\s*[\'"]?([a-zA-Z0-9@#$%^&*!]{8,})[\'"]?',
            "Generic API Key": r'(?i)(api[_-]?key|access[_-]?token|secret[_-]?key)\s*[:=]\s*[\'"]?([a-zA-Z0-9\-_]{16,})[\'"]?',
        }

        for vuln in sensitive_files:
            evidence = vuln.get("evidence", {})
            # We need the actual content or snippet.
            # Note: The SecurityMisconfigScanner needs to be updated to include 'snippet' or 'content_sample' in evidence.
            # Assuming 'link' or 'url' is present, we rely on the scanner having already grabbed content.
            # Ideally, the scanner should pass the snippet. For now, let's assume 'snippet' might be added.

            content_snippet = evidence.get("snippet", "") or evidence.get("response_body", "")

            if not content_snippet:
                continue

            found_secrets = []
            for name, pattern in secret_patterns.items():
                if re.search(pattern, content_snippet):
                    found_secrets.append(name)

            if found_secrets:
                # BINGO! We have a chain.
                chain = ChainResult(
                    title="Critical Credential Leak via Config Exposure",
                    risk_level="critical",
                    description=(
                        f"A sensitive configuration file was found ({vuln['evidence'].get('url', 'unknown')}) "
                        f"AND it contains high-value secrets: {', '.join(found_secrets)}. "
                        "This allows an attacker to directly compromise cloud infrastructure or databases."
                    ),
                    steps=[
                        f"Scanner identified exposed file: {vuln.get('title')}",
                        f"Regex analysis confirmed presence of {', '.join(found_secrets)} in the file content.",
                    ],
                    evidence=[
                        {"step": "File Discovery", "data": vuln["evidence"]},
                        {"step": "Secret Extraction", "data": {"found_secrets": found_secrets}},
                    ],
                    remediation="Revoke the exposed credentials IMMEDIATELY. Remove the file or restrict access. Rotate all keys.",
                )
                self.chains.append(chain)

    def _check_ssrf_chain(self, vulnerabilities: list[dict[str, Any]]):
        """
        Scenario:
        1. SSRF Detected (Critical).
        2. Evidence points to Cloud Metadata (AWS/GCP) or Internal Services (Redis/Admin).
        """
        ssrf_vulns = [v for v in vulnerabilities if v.get("type") == "ssrf"]

        for vuln in ssrf_vulns:
            evidence = vuln.get("evidence", {})
            match_type = evidence.get("match", "").lower()
            payload = evidence.get("payload", "")

            if not match_type:
                continue

            if match_type in ["aws", "google", "azure"]:
                # Chain: SSRF -> Cloud Compromise
                chain = ChainResult(
                    title=f"Cloud Infrastructure Takeover via SSRF ({match_type.upper()})",
                    risk_level="critical",
                    description=(
                        f"An SSRF vulnerability ({vuln['evidence'].get('parameter', 'param')}) allows access to "
                        f"Cloud Metadata services ({payload}). "
                        "An attacker can extract temporary credentials (STS/IAM) and take full control of the cloud environment."
                    ),
                    steps=[
                        f"Scanner identified SSRF in parameter: {evidence.get('parameter')}",
                        f"Payload successfully accessed sensitive metadata endpoint: {payload}",
                        f"Response matched known cloud provider pattern: {match_type}",
                    ],
                    evidence=[
                        {"step": "SSRF Vector", "data": evidence},
                        {"step": "Impact", "data": f"Direct access to {match_type.upper()} IAM roles/keys"},
                    ],
                    remediation="Block access to 169.254.169.254 at the firewall/network level. Use IMDSv2 (AWS) which requires token headers.",
                )
                self.chains.append(chain)

            elif match_type in ["redis", "internal"]:
                # Chain: SSRF -> Internal Network Scan
                chain = ChainResult(
                    title="Internal Network Reconnaissance & Service Access via SSRF",
                    risk_level="high",
                    description=(
                        f"SSRF allows the attacker to reach internal services (like Redis or Admin panels) "
                        f"that should not be accessible from the internet. Payload: {payload}"
                    ),
                    steps=[
                        "Scanner bypassed external firewalls via SSRF.",
                        f"Internal service responded to the request: {match_type}",
                    ],
                    evidence=[{"step": "Internal Access", "data": evidence}],
                    remediation="Enforce strict allow-listing for outgoing requests. Isolate the application in a DMZ.",
                )
                self.chains.append(chain)

    def _check_xss_session_hijacking_chain(self, vulnerabilities: list[dict[str, Any]]):
        """
        Scenario:
        1. XSS Detected (High).
        2. Cookies are missing 'HttpOnly' flag or 'Secure' flag.
        Result: Easy Session Hijacking.
        """
        xss_vulns = [v for v in vulnerabilities if v.get("type") in ["xss", "dom_xss"]]
        cookie_vulns = [v for v in vulnerabilities if v.get("type") == "insecure_cookie"]

        if not xss_vulns or not cookie_vulns:
            return

        # Check if we have missing HttpOnly specifically
        http_only_missing = False
        vulnerable_cookies = []
        for cv in cookie_vulns:
            missing = cv.get("evidence", {}).get("missing", [])
            if "HttpOnly" in missing:
                http_only_missing = True
                cookie_name = cv.get("title", "").split(": ")[-1]
                vulnerable_cookies.append(cookie_name)

        if http_only_missing:
            # We take the first XSS as the vector
            xss_vector = xss_vulns[0]

            chain = ChainResult(
                title="Account Takeover via XSS & Insecure Cookies",
                risk_level="critical",
                description=(
                    "An XSS vulnerability was found that can be chained with insecure cookie configurations "
                    f"to steal user sessions. The cookies ({', '.join(vulnerable_cookies)}) lack the 'HttpOnly' flag, "
                    "allowing JavaScript (via XSS) to read them directly."
                ),
                steps=[
                    f"Attacker exploits XSS in: {xss_vector.get('evidence', {}).get('parameter', 'parameter')}",
                    "Malicious script reads document.cookie (possible due to missing HttpOnly flag).",
                    f"Attacker exfiltrates session tokens: {', '.join(vulnerable_cookies)}",
                ],
                evidence=[
                    {"step": "XSS Vector", "data": xss_vector.get("evidence")},
                    {"step": "Insecure Cookie", "data": {"vulnerable_cookies": vulnerable_cookies}},
                ],
                remediation="Set the 'HttpOnly' flag on all session cookies to prevent JavaScript access. Fix the XSS vulnerability.",
            )
            self.chains.append(chain)

    def _format_chain_as_vulnerability(self, chain: ChainResult) -> dict[str, Any]:
        """Converts a ChainResult to the standard vulnerability dict format for reporting."""
        return {
            "title": f"[CHAIN] {chain.title}",
            "severity": chain.risk_level,
            "description": chain.description,
            "remediation": chain.remediation,
            "evidence": chain.evidence,
            "type": "attack_chain",
        }
