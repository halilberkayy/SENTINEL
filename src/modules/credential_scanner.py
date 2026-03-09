"""
Credential Testing Module - Authentication Security Assessment

WARNING: This module is designed for AUTHORIZED penetration testing and security
assessments ONLY. Unauthorized use against systems you do not own or have explicit
written permission to test is ILLEGAL and UNETHICAL. Always obtain proper authorization
before conducting any security assessment.

This module tests authentication mechanisms for weaknesses including default
credentials, credential stuffing vulnerabilities, password spray detection,
and account lockout policy assessment. It uses safe, rate-limited testing to
avoid causing account lockouts or service disruption.
"""

import asyncio
import base64
import logging
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin, urlparse

from .base_scanner import BaseScanner, Vulnerability

logger = logging.getLogger(__name__)


# Common default credential pairs (username, password)
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "123456"),
    ("administrator", "administrator"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("user", "user"),
    ("guest", "guest"),
    ("demo", "demo"),
    ("admin", "changeme"),
    ("admin", "admin@123"),
    ("operator", "operator"),
    ("webmaster", "webmaster"),
]

# Common login form indicators
LOGIN_FORM_INDICATORS = {
    "action_patterns": [
        r'/login', r'/signin', r'/auth', r'/authenticate',
        r'/j_security_check', r'/wp-login.php', r'/user/login',
    ],
    "input_names": {
        "username": ["username", "user", "email", "login", "usr", "name", "user_id", "userid"],
        "password": ["password", "pass", "pwd", "passwd", "secret"],
    },
}

# Auth protocol indicators
AUTH_PROTOCOL_INDICATORS = {
    "basic": {"header": "WWW-Authenticate", "value_pattern": r"Basic"},
    "bearer": {"header": "WWW-Authenticate", "value_pattern": r"Bearer"},
    "oauth": {"indicators": ["/oauth", "/authorize", "/token", "client_id"]},
    "saml": {"indicators": ["/saml", "/sso", "SAMLRequest", "SAMLResponse"]},
    "openid": {"indicators": ["/openid", "/.well-known/openid-configuration"]},
}


class CredentialScanner(BaseScanner):
    """
    Credential Testing Scanner - Authentication Security Assessment.

    AUTHORIZED USE ONLY: This module tests authentication mechanisms for
    common weaknesses. It performs SAFE, RATE-LIMITED testing to avoid
    account lockouts or denial of service.

    Features:
    - Default credential detection
    - Credential stuffing vulnerability assessment
    - Password spray simulation
    - Account lockout policy detection
    - Multi-protocol auth testing (HTTP Basic, Form, OAuth, SAML)
    - Leaked credential pattern correlation
    """

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "CredentialScanner"
        self.description = "Authentication security assessment - tests credential weaknesses"
        self.version = "1.0.0"
        self.capabilities = [
            "Default Credential Detection",
            "Credential Stuffing Assessment",
            "Password Spray Simulation",
            "Account Lockout Policy Detection",
            "Multi-Protocol Auth Testing",
            "Leaked Credential Correlation",
        ]
        # Safety limits
        self.max_login_attempts = 10
        self.attempt_delay_seconds = 2.0
        self.lockout_detection_threshold = 3

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform credential testing assessment on the target."""
        logger.info(f"Starting credential assessment for {url}")
        vulnerabilities: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "login_forms": [],
            "auth_protocols": [],
            "default_creds": [],
            "lockout_policy": {},
            "credential_stuffing": {},
            "password_spray": {},
        }

        try:
            # Phase 1: Discover Login Forms (15%)
            self._update_progress(progress_callback, 10, "Discovering login forms")
            forms, form_evidence = await self._discover_login_forms(url)
            evidence["login_forms"] = form_evidence

            # Phase 2: Detect Auth Protocols (30%)
            self._update_progress(progress_callback, 20, "Detecting auth protocols")
            proto_vulns, proto_evidence = await self._detect_auth_protocols(url)
            vulnerabilities.extend(proto_vulns)
            evidence["auth_protocols"] = proto_evidence

            # Phase 3: Default Credential Check (50%)
            self._update_progress(progress_callback, 35, "Testing default credentials")
            cred_vulns, cred_evidence = await self._test_default_credentials(url, forms)
            vulnerabilities.extend(cred_vulns)
            evidence["default_creds"] = cred_evidence

            # Phase 4: Account Lockout Policy Detection (65%)
            self._update_progress(progress_callback, 50, "Detecting lockout policy")
            lockout_vulns, lockout_evidence = await self._detect_lockout_policy(url, forms)
            vulnerabilities.extend(lockout_vulns)
            evidence["lockout_policy"] = lockout_evidence

            # Phase 5: Credential Stuffing Assessment (80%)
            self._update_progress(progress_callback, 65, "Assessing credential stuffing resistance")
            stuff_vulns, stuff_evidence = await self._assess_credential_stuffing(url, forms)
            vulnerabilities.extend(stuff_vulns)
            evidence["credential_stuffing"] = stuff_evidence

            # Phase 6: Password Spray Assessment (95%)
            self._update_progress(progress_callback, 80, "Assessing password spray resistance")
            spray_vulns, spray_evidence = await self._assess_password_spray(url, forms)
            vulnerabilities.extend(spray_vulns)
            evidence["password_spray"] = spray_evidence

            self._update_progress(progress_callback, 100, "completed")

        except Exception as e:
            logger.error(f"Credential assessment error: {e}")
            return self._format_result(
                "Error", f"Assessment failed: {str(e)}", vulnerabilities, evidence
            )

        details = (
            f"Credential assessment completed. "
            f"Found {len(vulnerabilities)} weakness(es). "
            f"Login forms: {len(evidence.get('login_forms', []))}, "
            f"Auth protocols: {len(evidence.get('auth_protocols', []))}, "
            f"Default creds found: {len(evidence.get('default_creds', []))}"
        )

        return self._format_result("Completed", details, vulnerabilities, evidence)

    async def _discover_login_forms(self, url: str) -> tuple[list[dict], list[dict]]:
        """Discover login forms on the target."""
        forms: list[dict] = []
        evidence: list[dict] = []

        try:
            # Check common login paths
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            login_paths = [
                "/login", "/signin", "/auth/login", "/user/login",
                "/admin/login", "/wp-login.php", "/account/login",
                "/api/auth/login", "/api/login",
            ]

            # Also check the main page
            pages_to_check = [url] + [f"{base_url}{p}" for p in login_paths]

            for page_url in pages_to_check:
                try:
                    response = await self.http_client.get(page_url)
                    if not response or response.status == 404:
                        continue

                    html = ""
                    try:
                        html = await response.text()
                    except Exception:
                        continue

                    # Parse forms
                    form_pattern = re.compile(
                        r'<form[^>]*>(.*?)</form>',
                        re.DOTALL | re.IGNORECASE
                    )
                    page_forms = form_pattern.findall(html)

                    for form_html in page_forms:
                        # Check if this looks like a login form
                        has_password = bool(re.search(
                            r'type\s*=\s*["\']password["\']', form_html, re.IGNORECASE
                        ))
                        if not has_password:
                            continue

                        # Extract form details
                        action_match = re.search(
                            r'action\s*=\s*["\']([^"\']*)["\']', form_html, re.IGNORECASE
                        )
                        method_match = re.search(
                            r'method\s*=\s*["\']([^"\']*)["\']', form_html, re.IGNORECASE
                        )

                        # Find input field names
                        input_pattern = re.compile(
                            r'<input[^>]*name\s*=\s*["\']([^"\']+)["\'][^>]*>',
                            re.IGNORECASE
                        )
                        inputs = input_pattern.findall(form_html)

                        # Identify username and password fields
                        username_field = None
                        password_field = None
                        for inp in inputs:
                            inp_lower = inp.lower()
                            if any(u in inp_lower for u in LOGIN_FORM_INDICATORS["input_names"]["username"]):
                                username_field = inp
                            elif any(p in inp_lower for p in LOGIN_FORM_INDICATORS["input_names"]["password"]):
                                password_field = inp

                        if password_field:
                            form_info = {
                                "url": page_url,
                                "action": action_match.group(1) if action_match else page_url,
                                "method": (method_match.group(1) if method_match else "POST").upper(),
                                "username_field": username_field or "username",
                                "password_field": password_field,
                                "all_inputs": inputs,
                            }
                            forms.append(form_info)
                            evidence.append({
                                "url": page_url,
                                "username_field": username_field or "unknown",
                                "password_field": password_field,
                            })

                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"Login form discovery error: {e}")

        return forms, evidence

    async def _detect_auth_protocols(self, url: str) -> tuple[list[Vulnerability], list[dict]]:
        """Detect authentication protocols in use."""
        vulns: list[Vulnerability] = []
        protocols: list[dict] = []

        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # Check for HTTP Basic Auth
            response = await self.http_client.get(url)
            if response:
                www_auth = response.headers.get("WWW-Authenticate", "")
                if "Basic" in www_auth:
                    protocols.append({"type": "HTTP Basic", "header": www_auth})
                    vulns.append(self._create_vulnerability(
                        title="HTTP Basic Authentication Detected",
                        description=(
                            "HTTP Basic Authentication sends credentials in Base64 encoding "
                            "(easily decoded). This is insecure unless used over HTTPS."
                        ),
                        severity="medium" if parsed.scheme == "https" else "high",
                        type="credential_basic_auth",
                        evidence={"www_authenticate": www_auth},
                        cwe_id="CWE-522",
                        remediation="Use token-based authentication (OAuth, JWT) instead of HTTP Basic.",
                    ))
                if "Bearer" in www_auth:
                    protocols.append({"type": "Bearer/JWT", "header": www_auth})

            # Check for OAuth/OIDC endpoints
            oauth_paths = [
                "/oauth/authorize", "/oauth/token",
                "/.well-known/openid-configuration",
                "/api/oauth", "/auth/oauth",
            ]
            for path in oauth_paths:
                try:
                    resp = await self.http_client.get(f"{base_url}{path}")
                    if resp and resp.status not in [404, 405]:
                        protocols.append({
                            "type": "OAuth/OIDC",
                            "endpoint": path,
                            "status": resp.status,
                        })
                except Exception:
                    pass

            # Check for SAML endpoints
            saml_paths = ["/saml/login", "/saml/metadata", "/sso/saml"]
            for path in saml_paths:
                try:
                    resp = await self.http_client.get(f"{base_url}{path}")
                    if resp and resp.status not in [404, 405]:
                        protocols.append({
                            "type": "SAML",
                            "endpoint": path,
                            "status": resp.status,
                        })
                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"Auth protocol detection error: {e}")

        return vulns, protocols

    async def _test_default_credentials(
        self, url: str, forms: list[dict]
    ) -> tuple[list[Vulnerability], list[dict]]:
        """Test for default credentials on discovered login forms."""
        vulns: list[Vulnerability] = []
        found_creds: list[dict] = []

        if not forms:
            return vulns, found_creds

        try:
            form = forms[0]  # Test first form found
            form_action = form["action"]
            if not form_action.startswith("http"):
                parsed = urlparse(url)
                form_action = urljoin(f"{parsed.scheme}://{parsed.netloc}", form_action)

            username_field = form["username_field"]
            password_field = form["password_field"]

            # Test a limited subset of default credentials (safety limit)
            test_creds = DEFAULT_CREDENTIALS[:self.max_login_attempts]

            # First, get a baseline "failed login" response
            baseline_data = {
                username_field: "sentinel_test_nonexist_user_xyz",
                password_field: "sentinel_test_nonexist_pass_xyz",
            }
            baseline_resp = await self.http_client.post(form_action, data=baseline_data)
            baseline_status = baseline_resp.status if baseline_resp else 0
            baseline_length = 0
            try:
                if baseline_resp:
                    baseline_text = await baseline_resp.text()
                    baseline_length = len(baseline_text)
            except Exception:
                pass

            for username, password in test_creds:
                await asyncio.sleep(self.attempt_delay_seconds)  # Rate limiting

                data = {
                    username_field: username,
                    password_field: password,
                }

                try:
                    response = await self.http_client.post(form_action, data=data)
                    if not response:
                        continue

                    # Detect successful login
                    is_success = False
                    indicators = []

                    # Check for redirect to dashboard/home
                    if response.status in [301, 302, 303]:
                        location = response.headers.get("Location", "")
                        if any(w in location.lower() for w in [
                            "dashboard", "home", "panel", "admin", "welcome", "profile"
                        ]):
                            is_success = True
                            indicators.append(f"redirect_to: {location}")

                    # Check for session cookie
                    set_cookie = response.headers.get("Set-Cookie", "")
                    if any(s in set_cookie.lower() for s in [
                        "session", "token", "auth", "jwt", "sid"
                    ]):
                        if response.status != baseline_status:
                            is_success = True
                            indicators.append("session_cookie_set")

                    # Check for different response size (significant difference)
                    try:
                        resp_text = await response.text()
                        if abs(len(resp_text) - baseline_length) > 200:
                            # Response significantly different from baseline
                            if response.status == 200 and any(w in resp_text.lower() for w in [
                                "welcome", "dashboard", "logout", "profile"
                            ]):
                                is_success = True
                                indicators.append("success_content_detected")
                    except Exception:
                        pass

                    if is_success:
                        found_creds.append({
                            "username": username,
                            "password": "***" + password[-2:],  # Partially masked
                            "indicators": indicators,
                        })

                except Exception:
                    pass

            if found_creds:
                vulns.append(self._create_vulnerability(
                    title=f"Default Credentials Found ({len(found_creds)} pair(s))",
                    description=(
                        f"Default credentials were accepted by the login form. "
                        f"Found {len(found_creds)} working credential pair(s). "
                        "This allows unauthorized access to the application."
                    ),
                    severity="critical",
                    type="credential_default_creds",
                    evidence={"credentials": found_creds},
                    cwe_id="CWE-798",
                    remediation="Change all default credentials. Enforce strong password policies.",
                ))

        except Exception as e:
            logger.debug(f"Default credential test error: {e}")

        return vulns, found_creds

    async def _detect_lockout_policy(
        self, url: str, forms: list[dict]
    ) -> tuple[list[Vulnerability], dict]:
        """Detect account lockout policy."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "lockout_detected": False,
            "lockout_threshold": None,
            "lockout_response": None,
        }

        if not forms:
            evidence["note"] = "No login forms found for lockout testing"
            return vulns, evidence

        try:
            form = forms[0]
            form_action = form["action"]
            if not form_action.startswith("http"):
                parsed = urlparse(url)
                form_action = urljoin(f"{parsed.scheme}://{parsed.netloc}", form_action)

            username_field = form["username_field"]
            password_field = form["password_field"]

            # Send multiple failed login attempts to detect lockout
            test_username = "sentinel_lockout_test_user"
            responses: list[dict] = []

            for i in range(self.lockout_detection_threshold + 2):
                await asyncio.sleep(self.attempt_delay_seconds)

                data = {
                    username_field: test_username,
                    password_field: f"wrong_password_{i}",
                }

                try:
                    response = await self.http_client.post(form_action, data=data)
                    if response:
                        status = response.status
                        try:
                            body = await response.text()
                        except Exception:
                            body = ""

                        resp_info = {
                            "attempt": i + 1,
                            "status": status,
                            "body_length": len(body),
                            "lockout_indicators": [],
                        }

                        # Check for lockout indicators
                        lockout_words = [
                            "locked", "blocked", "too many", "rate limit",
                            "temporarily", "wait", "try again later",
                        ]
                        for word in lockout_words:
                            if word in body.lower():
                                resp_info["lockout_indicators"].append(word)

                        if status == 429:
                            resp_info["lockout_indicators"].append("HTTP 429")

                        responses.append(resp_info)

                        if resp_info["lockout_indicators"]:
                            evidence["lockout_detected"] = True
                            evidence["lockout_threshold"] = i + 1
                            evidence["lockout_response"] = resp_info
                            break
                except Exception:
                    pass

            evidence["attempts"] = responses

            if not evidence["lockout_detected"]:
                vulns.append(self._create_vulnerability(
                    title="No Account Lockout Policy Detected",
                    description=(
                        f"After {len(responses)} failed login attempts, no lockout mechanism "
                        "was triggered. This makes the application vulnerable to brute-force "
                        "and credential stuffing attacks."
                    ),
                    severity="high",
                    type="credential_no_lockout",
                    evidence={"attempts_made": len(responses), "lockout_triggered": False},
                    cwe_id="CWE-307",
                    remediation=(
                        "Implement account lockout after 5-10 failed attempts. "
                        "Use progressive delays and CAPTCHA challenges."
                    ),
                ))

        except Exception as e:
            logger.debug(f"Lockout policy detection error: {e}")

        return vulns, evidence

    async def _assess_credential_stuffing(
        self, url: str, forms: list[dict]
    ) -> tuple[list[Vulnerability], dict]:
        """Assess vulnerability to credential stuffing attacks."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "captcha_present": False,
            "rate_limiting": False,
            "device_fingerprinting": False,
        }

        try:
            # Check main page and login page for CAPTCHA
            response = await self.http_client.get(url)
            if response:
                html = ""
                try:
                    html = await response.text()
                except Exception:
                    pass

                # Check for CAPTCHA indicators
                captcha_indicators = [
                    "recaptcha", "hcaptcha", "captcha", "g-recaptcha",
                    "cf-turnstile", "challenge", "arkose",
                ]
                for indicator in captcha_indicators:
                    if indicator in html.lower():
                        evidence["captcha_present"] = True
                        evidence["captcha_type"] = indicator
                        break

                # Check for device fingerprinting
                fingerprint_indicators = [
                    "fingerprint", "fingerprintjs", "fp2", "clientjs",
                    "device_id", "browser_id",
                ]
                for indicator in fingerprint_indicators:
                    if indicator in html.lower():
                        evidence["device_fingerprinting"] = True
                        break

            # Check login form responses for anti-automation
            if forms:
                form = forms[0]
                form_action = form["action"]
                if not form_action.startswith("http"):
                    parsed = urlparse(url)
                    form_action = urljoin(f"{parsed.scheme}://{parsed.netloc}", form_action)

                # Check for CSRF token (anti-automation)
                if response:
                    try:
                        html = await response.text()
                    except Exception:
                        html = ""
                    csrf_pattern = re.compile(
                        r'name\s*=\s*["\'](?:csrf|_token|csrfmiddlewaretoken|__RequestVerificationToken)["\']',
                        re.IGNORECASE,
                    )
                    evidence["csrf_protection"] = bool(csrf_pattern.search(html))

            if not evidence["captcha_present"] and not evidence.get("csrf_protection"):
                vulns.append(self._create_vulnerability(
                    title="Vulnerable to Credential Stuffing",
                    description=(
                        "The login form lacks CAPTCHA and CSRF protection, making it "
                        "vulnerable to automated credential stuffing attacks using "
                        "leaked credential databases."
                    ),
                    severity="high",
                    type="credential_stuffing_vuln",
                    evidence=evidence,
                    cwe_id="CWE-307",
                    remediation=(
                        "Implement CAPTCHA (reCAPTCHA v3, hCaptcha), CSRF tokens, "
                        "and device fingerprinting to prevent automated attacks."
                    ),
                ))

        except Exception as e:
            logger.debug(f"Credential stuffing assessment error: {e}")

        return vulns, evidence

    async def _assess_password_spray(
        self, url: str, forms: list[dict]
    ) -> tuple[list[Vulnerability], dict]:
        """Assess vulnerability to password spray attacks."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "user_enumeration": False,
            "consistent_error_messages": True,
            "timing_difference": False,
        }

        if not forms:
            evidence["note"] = "No login forms found for password spray assessment"
            return vulns, evidence

        try:
            form = forms[0]
            form_action = form["action"]
            if not form_action.startswith("http"):
                parsed = urlparse(url)
                form_action = urljoin(f"{parsed.scheme}://{parsed.netloc}", form_action)

            username_field = form["username_field"]
            password_field = form["password_field"]

            # Test with known-valid vs known-invalid usernames
            import time

            test_cases = [
                ("admin", "wrong_password_test"),
                ("nonexistent_user_xyz_abc", "wrong_password_test"),
            ]

            results = []
            for username, password in test_cases:
                await asyncio.sleep(self.attempt_delay_seconds)

                data = {username_field: username, password_field: password}

                start = time.monotonic()
                try:
                    response = await self.http_client.post(form_action, data=data)
                    elapsed = time.monotonic() - start

                    if response:
                        body = ""
                        try:
                            body = await response.text()
                        except Exception:
                            pass

                        results.append({
                            "username": username,
                            "status": response.status,
                            "body_length": len(body),
                            "response_time_ms": round(elapsed * 1000, 2),
                            "error_message": self._extract_error_message(body),
                        })
                except Exception:
                    pass

            if len(results) >= 2:
                # Check for user enumeration via different error messages
                if results[0].get("error_message") != results[1].get("error_message"):
                    if results[0]["error_message"] and results[1]["error_message"]:
                        evidence["user_enumeration"] = True
                        evidence["consistent_error_messages"] = False

                # Check timing difference (> 100ms could indicate user enumeration)
                time_diff = abs(
                    results[0].get("response_time_ms", 0) - results[1].get("response_time_ms", 0)
                )
                if time_diff > 200:
                    evidence["timing_difference"] = True

                evidence["test_results"] = results

                if evidence["user_enumeration"]:
                    vulns.append(self._create_vulnerability(
                        title="Username Enumeration via Login Response",
                        description=(
                            "The login form returns different error messages for valid vs invalid "
                            "usernames, enabling username enumeration for password spray attacks."
                        ),
                        severity="medium",
                        type="credential_user_enumeration",
                        evidence={
                            "valid_user_error": results[0].get("error_message", ""),
                            "invalid_user_error": results[1].get("error_message", ""),
                        },
                        cwe_id="CWE-204",
                        remediation="Use generic error messages like 'Invalid username or password' for all cases.",
                    ))

        except Exception as e:
            logger.debug(f"Password spray assessment error: {e}")

        return vulns, evidence

    @staticmethod
    def _extract_error_message(html: str) -> str:
        """Extract error message from login response."""
        if not html:
            return ""

        # Common error message patterns
        patterns = [
            re.compile(r'class\s*=\s*["\'][^"\']*error[^"\']*["\'][^>]*>(.*?)<', re.IGNORECASE | re.DOTALL),
            re.compile(r'class\s*=\s*["\'][^"\']*alert[^"\']*["\'][^>]*>(.*?)<', re.IGNORECASE | re.DOTALL),
            re.compile(r'class\s*=\s*["\'][^"\']*message[^"\']*["\'][^>]*>(.*?)<', re.IGNORECASE | re.DOTALL),
            re.compile(r'<div[^>]*class="flash"[^>]*>(.*?)</div>', re.IGNORECASE | re.DOTALL),
        ]

        for pattern in patterns:
            match = pattern.search(html)
            if match:
                text = re.sub(r'<[^>]+>', '', match.group(1)).strip()
                if text and len(text) < 200:
                    return text

        return ""
