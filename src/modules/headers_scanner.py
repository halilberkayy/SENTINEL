"""Response header and cookie checks.

Missing headers are scored by the control they replace. A header that is
present is read, not only counted.
"""

import logging
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from ..core.http_client import response_reliability
from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)

_SESSION_COOKIE_MARKERS = ("session", "sid", "token", "auth", "jwt", "sess")


def _directive(header_value: str, name: str) -> str | None:
    for part in header_value.split(";"):
        piece = part.strip()
        if piece.lower().split(" ", 1)[0] == name:
            return piece
    return None


def _hsts_max_age(value: str) -> int | None:
    for part in value.split(";"):
        piece = part.strip()
        if piece.lower().startswith("max-age="):
            raw = piece.split("=", 1)[1].strip().strip('"')
            try:
                return int(raw)
            except ValueError:
                return None
    return None


def _script_policy(csp: str) -> str | None:
    script = _directive(csp, "script-src")
    if script:
        return script
    return _directive(csp, "default-src")


class HeadersScanner(BaseScanner):
    """Checks transport, framing, content-type, and cookie flags on one response."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "HeadersScanner"
        self.description = "Security headers and cookie flags"
        self.version = "4.0.0"
        self.capabilities = ["Header Analysis", "Cookie Security"]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        logger.info("Analyzing headers for %s", url)
        vulnerabilities = []

        try:
            self._update_progress(progress_callback, 20, "Fetching target headers")
            response = await self.http_client.get(url)
            if not response:
                return self._format_result("Error", "Target unreachable", [])

            final_url = str(response.url or url)
            analyzable, reason = response_reliability(response)
            if not analyzable:
                return self._format_result(
                    "Unreliable",
                    f"Did not assess security headers: target returned {reason} at {final_url}. "
                    "Header findings on an error or challenge page would be misleading.",
                    [],
                )

            redirect_note = self._redirect_note(url, final_url)
            headers = {k.lower(): v for k, v in response.headers.items()}
            scheme = urlparse(final_url).scheme
            self._update_progress(progress_callback, 50, "Evaluating security headers")
            header_vulns = self._header_findings(headers, scheme, final_url)
            if redirect_note:
                # Findings are about the redirected host, not the requested one.
                for v in header_vulns:
                    v.confidence = "tentative"
            vulnerabilities.extend(header_vulns)

            self._update_progress(progress_callback, 80, "Checking cookie security flags")
            set_cookies = [v for k, v in response.headers.items() if k.lower() == "set-cookie"]
            vulnerabilities.extend(self._cookie_findings(set_cookies, scheme))

            self._update_progress(progress_callback, 100, "completed")
            status = "Vulnerable" if any(v.severity != "info" for v in vulnerabilities) else "Secure"
            details = f"Checked headers and {len(set_cookies)} Set-Cookie value(s). {len(vulnerabilities)} issue(s)."
            if redirect_note:
                details = f"{details} {redirect_note}"
            return self._format_result(status, details, vulnerabilities)

        except Exception as e:
            logger.exception("Headers scan failed: %s", e)
            return self._format_result("Error", f"Internal error: {e}", [])

    def _header_findings(self, headers: dict[str, str], scheme: str, final_url: str) -> list:
        findings = []
        csp = headers.get("content-security-policy", "")
        framing = _directive(csp, "frame-ancestors") if csp else None

        if scheme == "https":
            hsts = headers.get("strict-transport-security")
            if not hsts:
                findings.append(
                    self._create_vulnerability(
                        title="Missing Strict-Transport-Security",
                        description="HTTPS response has no HSTS header, so the browser will not pin this host to HTTPS.",
                        severity="high",
                        type="missing_header",
                        evidence={"url": final_url, "header": "Strict-Transport-Security"},
                        cwe_id="CWE-319",
                        remediation="Send Strict-Transport-Security: max-age=31536000; includeSubDomains on HTTPS responses.",
                    )
                )
            else:
                max_age = _hsts_max_age(hsts)
                if max_age is None or max_age < 15552000:
                    findings.append(
                        self._create_vulnerability(
                            title="HSTS max-age is missing or short",
                            description="HSTS is present, but max-age is absent or under 180 days.",
                            severity="low",
                            type="missing_header",
                            evidence={"url": final_url, "value": hsts, "max_age": max_age},
                            cwe_id="CWE-319",
                            remediation="Use max-age of at least 15552000. Add includeSubDomains only after every subdomain serves HTTPS.",
                        )
                    )

        if not csp:
            findings.append(
                self._create_vulnerability(
                    title="Missing Content-Security-Policy",
                    description="No Content-Security-Policy header on this response.",
                    severity="medium",
                    type="missing_header",
                    evidence={"url": final_url, "header": "Content-Security-Policy"},
                    cwe_id="CWE-693",
                    remediation="Send a Content-Security-Policy. Start from default-src 'self' and add sources you actually use.",
                )
            )
        else:
            script = _script_policy(csp)
            if (
                script
                and "'unsafe-inline'" in script.lower()
                and not any(token in script.lower() for token in ("nonce-", "sha256-", "sha384-", "sha512-"))
            ):
                findings.append(
                    self._create_vulnerability(
                        title="Content-Security-Policy allows unsafe-inline scripts",
                        description="script-src or default-src includes 'unsafe-inline' and no nonce or hash.",
                        severity="medium",
                        type="missing_header",
                        evidence={"url": final_url, "directive": script},
                        cwe_id="CWE-693",
                        remediation="Replace 'unsafe-inline' with a nonce or hash. Do not keep both.",
                    )
                )

        if not framing and "x-frame-options" not in headers:
            findings.append(
                self._create_vulnerability(
                    title="No clickjacking control",
                    description="Neither Content-Security-Policy frame-ancestors nor X-Frame-Options is set.",
                    severity="medium",
                    type="missing_header",
                    evidence={"url": final_url},
                    cwe_id="CWE-1021",
                    remediation="Set Content-Security-Policy: frame-ancestors 'none', or X-Frame-Options: DENY.",
                )
            )

        xcto = headers.get("x-content-type-options")
        if xcto is None:
            findings.append(
                self._create_vulnerability(
                    title="Missing X-Content-Type-Options",
                    description="Response does not set X-Content-Type-Options.",
                    severity="low",
                    type="missing_header",
                    evidence={"url": final_url, "header": "X-Content-Type-Options"},
                    cwe_id="CWE-693",
                    remediation="Send X-Content-Type-Options: nosniff.",
                )
            )
        elif xcto.strip().lower() != "nosniff":
            findings.append(
                self._create_vulnerability(
                    title="X-Content-Type-Options is not nosniff",
                    description="The header is present but the value is not nosniff.",
                    severity="low",
                    type="missing_header",
                    evidence={"url": final_url, "value": xcto},
                    cwe_id="CWE-693",
                    remediation="Set the value to nosniff.",
                )
            )

        if "referrer-policy" not in headers:
            findings.append(
                self._create_vulnerability(
                    title="Missing Referrer-Policy",
                    description="Response does not set Referrer-Policy.",
                    severity="info",
                    type="missing_header",
                    evidence={"url": final_url, "header": "Referrer-Policy"},
                    cwe_id="CWE-693",
                    remediation="Send Referrer-Policy: strict-origin-when-cross-origin, or a stricter value.",
                )
            )

        return findings

    def _cookie_findings(self, set_cookies: list[str], scheme: str) -> list:
        findings = []
        for cookie in set_cookies:
            name = cookie.split("=", 1)[0].strip()
            lowered = cookie.lower()
            session_like = any(marker in name.lower() for marker in _SESSION_COOKIE_MARKERS)
            missing = []
            if scheme == "https" and "secure" not in lowered:
                missing.append("Secure")
            if session_like and "httponly" not in lowered:
                missing.append("HttpOnly")
            if "samesite" not in lowered:
                missing.append("SameSite")
            if "samesite=none" in lowered and "secure" not in lowered:
                if "Secure" not in missing:
                    missing.append("Secure")

            if not missing:
                continue

            severity = "medium" if session_like or "samesite=none" in lowered else "low"
            findings.append(
                self._create_vulnerability(
                    title=f"Cookie {name} is missing {', '.join(missing)}",
                    description=f"Set-Cookie for {name} does not include: {', '.join(missing)}.",
                    severity=severity,
                    type="insecure_cookie",
                    evidence={"cookie_name": name, "missing": missing},
                    cwe_id="CWE-614",
                    remediation="Set Secure on HTTPS cookies, HttpOnly on session cookies, and an explicit SameSite.",
                )
            )
        return findings
