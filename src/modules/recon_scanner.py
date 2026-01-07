from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from ..core.config import Config
from ..core.http_client import HTTPClient
from ..modules.base_scanner import BaseScanner


class ReconScanner(BaseScanner):
    """
    Advanced Reconnaissance Module for Tech Stack Fingerprinting,
    WAF Detection, and Security Header Analysis.
    Covers Phase 1 (Reconnaissance) and 3 (Misconfiguration) of the Red Team checklist.
    """

    def __init__(self, config: Config, http_client: HTTPClient):
        super().__init__(config, http_client)
        self.name = "ReconScanner"
        self.description = "Performs passive reconnaissance, fingerprints technology stack, detects WAFs, and analyzes security headers."

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Run the reconnaissance scan."""
        self._update_progress(progress_callback, 0, "Starting Recon")
        vulnerabilities = []
        evidence = {}

        try:
            # 1. Main Baseline Request
            self._update_progress(progress_callback, 20, "Analyzing Headers")
            response = await self.http_client.get(url, ssl=False)

            if response:
                headers = response.headers
                content = await response.text()

                # Tech Fingerprinting
                self._update_progress(progress_callback, 40, "Fingerprinting Tech")
                vs = self._fingerprint_technologies(headers, content)
                vulnerabilities.extend(vs)

                # Security Header Analysis
                self._update_progress(progress_callback, 60, "Checking Headers")
                vs = self._analyze_security_headers(headers)
                vulnerabilities.extend(vs)

                # WAF Detection (Basic Heuristics) - using helper from BaseScanner
                self._update_progress(progress_callback, 80, "Detecting WAF")
                waf_name = await self._detect_waf(response)
                if waf_name:
                    vulnerabilities.append(
                        self._create_vulnerability(
                            title=f"WAF Detected: {waf_name}",
                            description=f"A Web Application Firewall ({waf_name}) is protecting the target.",
                            severity="Info",
                            type="WAF",
                            evidence={"waf_name": waf_name},
                            remediation="WAF presence confirmed. Evasion techniques (Stealth Mode) required.",
                        )
                    )

                # SSL/TLS Security Check
                vs = self._check_ssl_tls(url)
                vulnerabilities.extend(vs)

        except Exception as e:
            logger.debug(f"[{self.name}] Reconnaissance analysis failed: {e}")

        self._update_progress(progress_callback, 100, "Completed")

        return self._format_result(
            status="Completed",
            details=f"Recon completed. Found {len(vulnerabilities)} insights.",
            vulnerabilities=vulnerabilities,
            evidence=evidence,
        )

    def _fingerprint_technologies(self, headers: Any, content: str) -> list[Any]:
        """Identify server software, frameworks, and CMS."""
        technologies = []
        vulns = []

        # Header-based detection
        if "Server" in headers:
            technologies.append(f"Server: {headers['Server']}")
        if "X-Powered-By" in headers:
            technologies.append(f"Powered By: {headers['X-Powered-By']}")
        if "X-AspNet-Version" in headers:
            technologies.append("Framework: ASP.NET")
        if "X-Generator" in headers:
            technologies.append(f"Generator: {headers['X-Generator']}")

        # Cookie-based detection
        cookies = str(headers.get("Set-Cookie", ""))
        if "PHPSESSID" in cookies:
            technologies.append("Language: PHP")
        if "JSESSIONID" in cookies:
            technologies.append("Platform: Java")
        if "csrftoken" in cookies and "django" in content.lower():
            technologies.append("Framework: Django")
        if "laravel_session" in cookies:
            technologies.append("Framework: Laravel")

        # Content-based detection
        if "wp-content" in content:
            technologies.append("CMS: WordPress")
        if "Drupal" in content or "drupal.js" in content:
            technologies.append("CMS: Drupal")
        if "Joomla" in content:
            technologies.append("CMS: Joomla")

        if technologies:
            vulns.append(
                self._create_vulnerability(
                    title="Technology Stack Discovered",
                    description=f"Identified the following technologies: {', '.join(technologies)}",
                    severity="Info",
                    type="Fingerprinting",
                    evidence={"technologies": technologies},
                    remediation="Information only. Ensure identified software versions are patched.",
                )
            )
        return vulns

    def _analyze_security_headers(self, headers: Any) -> list[Any]:
        """Check for missing security headers."""
        vulns = []
        missing_headers = []

        security_headers = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP",
            "X-Frame-Options": "Clickjacking Protection",
            "X-Content-Type-Options": "MIME Sniffing Protection",
        }

        for header, description in security_headers.items():
            keys = [k.lower() for k in headers.keys()]
            if header.lower() not in keys:
                missing_headers.append(f"{header} ({description})")

        if missing_headers:
            vulns.append(
                self._create_vulnerability(
                    title="Missing Security Headers",
                    description=f"The server is missing critical security headers: {', '.join(missing_headers)}",
                    severity="Low",
                    type="Misconfiguration",
                    evidence={"missing_headers": missing_headers},
                    remediation="Configure the web server to send these headers.",
                )
            )
        return vulns

    def _check_ssl_tls(self, url: str) -> list[Any]:
        """Check SSL configuration (Basic)."""
        vulns = []
        parsed = urlparse(url)
        if parsed.scheme != "https":
            vulns.append(
                self._create_vulnerability(
                    title="Insecure Transport (HTTP)",
                    description="Target is communicating over unencrypted HTTP. Data is vulnerable to interception (MiTM).",
                    severity="Medium",
                    type="Encryption",
                    evidence={"scheme": "http"},
                    remediation="Enforce HTTPS with a valid certificate and HSTS.",
                )
            )
        return vulns
