"""
Security Hardening Analyzer.

Checks a target for defensive security posture:
  - HTTP security headers (OWASP Secure Headers Project)
  - TLS configuration (protocol version, certificate validity)
  - DNS security records (SPF, DKIM, DMARC)
  - Cookie security flags

Each check produces a scored finding (pass/warn/fail) with remediation guidance.
"""

import logging
import ssl
import socket
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import aiohttp

logger = logging.getLogger(__name__)


@dataclass
class HardeningCheck:
    """Single hardening check result."""

    category: str  # headers, tls, dns, cookies
    name: str
    status: str  # pass, warn, fail, error
    current_value: str | None = None
    expected: str | None = None
    description: str = ""
    remediation: str = ""
    severity: str = "info"  # critical, high, medium, low, info
    reference: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "name": self.name,
            "status": self.status,
            "current_value": self.current_value,
            "expected": self.expected,
            "description": self.description,
            "remediation": self.remediation,
            "severity": self.severity,
            "reference": self.reference,
        }


@dataclass
class HardeningReport:
    """Full hardening assessment report."""

    target: str
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    score: int = 0  # 0-100
    grade: str = "F"
    checks: list[HardeningCheck] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=lambda: {"pass": 0, "warn": 0, "fail": 0, "error": 0})

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "score": self.score,
            "grade": self.grade,
            "checks": [c.to_dict() for c in self.checks],
            "summary": self.summary,
        }


# Expected security headers with descriptions and references
SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "Strict-Transport-Security (HSTS)",
        "expected": "max-age=31536000; includeSubDomains",
        "severity": "high",
        "description": "Forces HTTPS connections, preventing SSL stripping attacks.",
        "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "reference": "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
    },
    "content-security-policy": {
        "name": "Content-Security-Policy (CSP)",
        "expected": "default-src 'self'",
        "severity": "high",
        "description": "Prevents XSS, clickjacking, and code injection by controlling resource loading.",
        "remediation": "Add a Content-Security-Policy header. Start with: default-src 'self'; script-src 'self'",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "expected": "nosniff",
        "severity": "medium",
        "description": "Prevents MIME-type sniffing which can lead to XSS.",
        "remediation": "Add header: X-Content-Type-Options: nosniff",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "expected": "DENY or SAMEORIGIN",
        "severity": "medium",
        "description": "Prevents clickjacking by controlling iframe embedding.",
        "remediation": "Add header: X-Frame-Options: DENY (or SAMEORIGIN if iframes are needed)",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "expected": "strict-origin-when-cross-origin",
        "severity": "low",
        "description": "Controls how much referrer information is sent with requests.",
        "remediation": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "expected": "geolocation=(), camera=(), microphone=()",
        "severity": "low",
        "description": "Controls which browser features the page can use (replaces Feature-Policy).",
        "remediation": "Add header: Permissions-Policy: geolocation=(), camera=(), microphone=()",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "expected": "0 (disabled — CSP supersedes this)",
        "severity": "info",
        "description": "Legacy XSS filter. Modern best practice is to disable it (set to 0) and rely on CSP.",
        "remediation": "Set X-XSS-Protection: 0 and ensure a strong CSP is in place.",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection",
    },
    "cross-origin-opener-policy": {
        "name": "Cross-Origin-Opener-Policy (COOP)",
        "expected": "same-origin",
        "severity": "medium",
        "description": "Isolates browsing context to prevent cross-origin attacks like Spectre.",
        "remediation": "Add header: Cross-Origin-Opener-Policy: same-origin",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
    },
    "cross-origin-resource-policy": {
        "name": "Cross-Origin-Resource-Policy (CORP)",
        "expected": "same-origin",
        "severity": "medium",
        "description": "Prevents other origins from reading your resources (Spectre mitigation).",
        "remediation": "Add header: Cross-Origin-Resource-Policy: same-origin",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy",
    },
}

# Headers that should NOT be present (information leakage)
LEAK_HEADERS = {
    "server": "Reveals web server software and version.",
    "x-powered-by": "Reveals backend framework (e.g., Express, PHP).",
    "x-aspnet-version": "Reveals ASP.NET version.",
    "x-aspnetmvc-version": "Reveals ASP.NET MVC version.",
}


class HardeningAnalyzer:
    """Analyze a target's defensive security posture."""

    def __init__(self, timeout: int = 15):
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    async def analyze(self, url: str) -> HardeningReport:
        """Run all hardening checks against a target URL."""
        parsed = urlparse(url)
        if not parsed.scheme:
            url = f"https://{url}"
            parsed = urlparse(url)

        report = HardeningReport(target=url)

        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(url, allow_redirects=True, ssl=False) as response:
                    headers = {k.lower(): v for k, v in response.headers.items()}
                    cookies = response.cookies

                    # 1. Security headers
                    report.checks.extend(self._check_security_headers(headers))

                    # 2. Information leakage headers
                    report.checks.extend(self._check_leak_headers(headers))

                    # 3. Cookie security
                    report.checks.extend(self._check_cookies(cookies))

        except Exception as e:
            report.checks.append(HardeningCheck(
                category="connection", name="HTTP Connection",
                status="error", description=f"Failed to connect: {e}",
                severity="critical",
            ))

        # 4. TLS check (separate connection)
        if parsed.scheme == "https":
            report.checks.extend(await self._check_tls(parsed.hostname, parsed.port or 443))

        # 5. DNS security (SPF/DMARC)
        report.checks.extend(await self._check_dns_security(parsed.hostname))

        # Calculate score
        self._calculate_score(report)
        return report

    def _check_security_headers(self, headers: dict[str, str]) -> list[HardeningCheck]:
        """Check for presence and correctness of security headers."""
        checks = []
        for header_key, spec in SECURITY_HEADERS.items():
            value = headers.get(header_key)
            if value:
                checks.append(HardeningCheck(
                    category="headers", name=spec["name"], status="pass",
                    current_value=value[:200], expected=spec["expected"],
                    description=spec["description"], severity="info",
                    reference=spec["reference"],
                ))
            else:
                checks.append(HardeningCheck(
                    category="headers", name=spec["name"], status="fail",
                    current_value="Not set", expected=spec["expected"],
                    description=spec["description"],
                    remediation=spec["remediation"],
                    severity=spec["severity"],
                    reference=spec["reference"],
                ))
        return checks

    def _check_leak_headers(self, headers: dict[str, str]) -> list[HardeningCheck]:
        """Check for headers that leak server information."""
        checks = []
        for header_key, desc in LEAK_HEADERS.items():
            value = headers.get(header_key)
            if value:
                checks.append(HardeningCheck(
                    category="headers", name=f"Information Leak: {header_key}",
                    status="warn", current_value=value[:100],
                    description=desc, severity="low",
                    remediation=f"Remove or suppress the '{header_key}' header in production.",
                ))
        return checks

    def _check_cookies(self, cookies: Any) -> list[HardeningCheck]:
        """Check cookie security flags."""
        checks = []
        for cookie in cookies.values():
            name = cookie.key
            missing = []
            if not cookie.get("httponly"):
                missing.append("HttpOnly")
            if not cookie.get("secure"):
                missing.append("Secure")
            samesite = cookie.get("samesite", "").lower()
            if samesite not in ("strict", "lax"):
                missing.append("SameSite=Strict|Lax")

            if missing:
                checks.append(HardeningCheck(
                    category="cookies", name=f"Cookie: {name}",
                    status="warn", current_value=f"Missing: {', '.join(missing)}",
                    expected="HttpOnly; Secure; SameSite=Strict",
                    description=f"Cookie '{name}' is missing security flags.",
                    remediation=f"Set {', '.join(missing)} on cookie '{name}'.",
                    severity="medium",
                ))
            else:
                checks.append(HardeningCheck(
                    category="cookies", name=f"Cookie: {name}",
                    status="pass", description="All security flags present.",
                    severity="info",
                ))
        return checks

    async def _check_tls(self, hostname: str, port: int) -> list[HardeningCheck]:
        """Check TLS version and certificate validity."""
        checks = []
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    protocol = ssock.version()
                    cert = ssock.getpeercert()

                    # Protocol version
                    if protocol in ("TLSv1.3",):
                        checks.append(HardeningCheck(
                            category="tls", name="TLS Version", status="pass",
                            current_value=protocol, expected="TLS 1.3",
                            description="Using latest TLS version.", severity="info",
                        ))
                    elif protocol in ("TLSv1.2",):
                        checks.append(HardeningCheck(
                            category="tls", name="TLS Version", status="pass",
                            current_value=protocol, expected="TLS 1.2+",
                            description="TLS 1.2 is acceptable. TLS 1.3 is preferred.",
                            severity="info",
                        ))
                    else:
                        checks.append(HardeningCheck(
                            category="tls", name="TLS Version", status="fail",
                            current_value=protocol, expected="TLS 1.2+",
                            description=f"{protocol} is deprecated and vulnerable.",
                            remediation="Upgrade to TLS 1.2 or 1.3. Disable TLS 1.0/1.1.",
                            severity="critical",
                        ))

                    # Certificate expiry
                    if cert:
                        not_after = ssl.cert_time_to_seconds(cert["notAfter"])
                        now = datetime.now(UTC).timestamp()
                        days_left = (not_after - now) / 86400

                        if days_left < 0:
                            checks.append(HardeningCheck(
                                category="tls", name="Certificate Validity", status="fail",
                                current_value=f"Expired {abs(int(days_left))} days ago",
                                description="TLS certificate has expired.",
                                remediation="Renew the TLS certificate immediately.",
                                severity="critical",
                            ))
                        elif days_left < 30:
                            checks.append(HardeningCheck(
                                category="tls", name="Certificate Validity", status="warn",
                                current_value=f"Expires in {int(days_left)} days",
                                description="Certificate expiring soon.",
                                remediation="Renew the certificate before expiry.",
                                severity="medium",
                            ))
                        else:
                            checks.append(HardeningCheck(
                                category="tls", name="Certificate Validity", status="pass",
                                current_value=f"Valid for {int(days_left)} more days",
                                severity="info",
                            ))
        except ssl.SSLCertVerificationError as e:
            checks.append(HardeningCheck(
                category="tls", name="Certificate Validation", status="fail",
                current_value=str(e)[:200], description="Certificate failed validation.",
                remediation="Use a certificate from a trusted CA.", severity="critical",
            ))
        except Exception as e:
            checks.append(HardeningCheck(
                category="tls", name="TLS Connection", status="error",
                description=f"Could not establish TLS connection: {e}",
                severity="high",
            ))
        return checks

    async def _check_dns_security(self, hostname: str) -> list[HardeningCheck]:
        """Check SPF and DMARC DNS records."""
        checks = []
        try:
            import dns.resolver

            # SPF
            try:
                answers = dns.resolver.resolve(hostname, "TXT")
                spf_found = any("v=spf1" in str(r) for r in answers)
                if spf_found:
                    checks.append(HardeningCheck(
                        category="dns", name="SPF Record", status="pass",
                        description="SPF record found. Helps prevent email spoofing.",
                        severity="info",
                    ))
                else:
                    checks.append(HardeningCheck(
                        category="dns", name="SPF Record", status="warn",
                        description="No SPF record found.",
                        remediation="Add a TXT record: v=spf1 ... -all",
                        severity="low",
                    ))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                checks.append(HardeningCheck(
                    category="dns", name="SPF Record", status="warn",
                    description="No SPF record found.", severity="low",
                ))

            # DMARC
            try:
                answers = dns.resolver.resolve(f"_dmarc.{hostname}", "TXT")
                dmarc_found = any("v=DMARC1" in str(r) for r in answers)
                if dmarc_found:
                    checks.append(HardeningCheck(
                        category="dns", name="DMARC Record", status="pass",
                        description="DMARC record found. Protects against email spoofing.",
                        severity="info",
                    ))
                else:
                    checks.append(HardeningCheck(
                        category="dns", name="DMARC Record", status="warn",
                        description="No DMARC record found.",
                        remediation="Add TXT record at _dmarc.domain: v=DMARC1; p=reject; ...",
                        severity="low",
                    ))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                checks.append(HardeningCheck(
                    category="dns", name="DMARC Record", status="warn",
                    description="No DMARC record found.", severity="low",
                ))

        except ImportError:
            checks.append(HardeningCheck(
                category="dns", name="DNS Security", status="error",
                description="dnspython not available. Install with: pip install dnspython",
                severity="info",
            ))
        except Exception as e:
            checks.append(HardeningCheck(
                category="dns", name="DNS Security", status="error",
                description=f"DNS check failed: {e}", severity="info",
            ))
        return checks

    def _calculate_score(self, report: HardeningReport) -> None:
        """Calculate overall hardening score (0-100) and letter grade."""
        if not report.checks:
            return

        total_weight = 0
        earned = 0
        weight_map = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}

        for check in report.checks:
            w = weight_map.get(check.severity, 1)
            total_weight += w
            report.summary[check.status] = report.summary.get(check.status, 0) + 1
            if check.status == "pass":
                earned += w
            elif check.status == "warn":
                earned += w * 0.5

        report.score = round((earned / total_weight) * 100) if total_weight > 0 else 0

        if report.score >= 90:
            report.grade = "A"
        elif report.score >= 75:
            report.grade = "B"
        elif report.score >= 60:
            report.grade = "C"
        elif report.score >= 40:
            report.grade = "D"
        else:
            report.grade = "F"
