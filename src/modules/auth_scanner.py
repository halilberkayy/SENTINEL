"""
Authentication and Authorization vulnerability scanner module - Advanced Implementation.
"""

import asyncio
import logging
from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin

from .base_scanner import BaseScanner, Vulnerability

logger = logging.getLogger(__name__)


class AuthScanner(BaseScanner):
    """Advanced authentication security assessment engine."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "AuthScanner"
        self.description = "Advanced authentication analyzer with credential testing and brute force detection"
        self.version = "2.0.0"
        self.capabilities = [
            "Default Credential Testing",
            "Account Enumeration Detection",
            "Rate Limiting Analysis",
            "Password Policy Evaluation",
            "Session Security Audit",
            "Multi-Factor Detection",
        ]

        # Common default credentials
        self.default_credentials = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("admin", "admin123"),
            ("root", "root"),
            ("root", "toor"),
            ("test", "test"),
            ("user", "user"),
            ("guest", "guest"),
            ("demo", "demo"),
            ("administrator", "administrator"),
            ("admin", ""),
            ("", ""),
        ]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform comprehensive authentication security scan."""
        logger.info(f"Analyzing authentication security for {url}")
        vulnerabilities = []

        try:
            self._update_progress(progress_callback, 10, "Detecting login forms")
            response = await self.http_client.get(url)
            if not response:
                return self._format_result("Error", "Target unreachable", [])

            html = await response.text()
            soup = await self._parse_html(html)

            # 1. Detect and analyze login forms
            forms = soup.find_all("form")
            login_forms = [f for f in forms if self._is_login_form(f)]

            if login_forms:
                self._update_progress(progress_callback, 20, "Analyzing login form security")
                for form in login_forms:
                    form_vulns = await self._analyze_login_form(form, url, soup)
                    vulnerabilities.extend(form_vulns)

            # 2. Test default credentials
            self._update_progress(progress_callback, 40, "Testing default credentials")
            if login_forms:
                cred_vulns = await self._test_default_credentials(login_forms[0], url)
                vulnerabilities.extend(cred_vulns)

            # 3. Check for account enumeration
            self._update_progress(progress_callback, 60, "Checking account enumeration")
            if login_forms:
                enum_vulns = await self._check_account_enumeration(login_forms[0], url)
                vulnerabilities.extend(enum_vulns)

            # 4. Test rate limiting
            self._update_progress(progress_callback, 75, "Testing rate limiting")
            if login_forms:
                rate_vulns = await self._test_rate_limiting(login_forms[0], url)
                vulnerabilities.extend(rate_vulns)

            # 5. Analyze session/cookie security
            self._update_progress(progress_callback, 90, "Auditing session security")
            session_vulns = self._analyze_session_security(response)
            vulnerabilities.extend(session_vulns)

            self._update_progress(progress_callback, 100, "completed")

            status = "Vulnerable" if vulnerabilities else "Secure"
            details = f"Analyzed {len(login_forms)} login form(s). Found {len(vulnerabilities)} authentication issues."
            return self._format_result(status, details, vulnerabilities)

        except Exception as e:
            logger.exception(f"Auth scan failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])

    def _is_login_form(self, form) -> bool:
        """Enhanced login form detection."""
        indicators = ["login", "signin", "sign-in", "auth", "session"]
        text = str(form).lower()
        inputs = form.find_all("input")

        has_password = any(i.get("type") == "password" for i in inputs)
        has_username = any(
            i.get("type") in ["text", "email"]
            and any(
                ind in (i.get("name", "") + i.get("id", "")).lower()
                for ind in ["user", "email", "login", "name", "account"]
            )
            for i in inputs
        )
        has_indicator = any(ind in text for ind in indicators)

        return has_password and (has_username or has_indicator)

    async def _analyze_login_form(self, form, url: str, soup) -> list[Vulnerability]:
        """Analyze login form for security issues."""
        findings = []

        # Check for HTTPS
        action = form.get("action", "")
        form_url = urljoin(url, action) if action else url

        if form_url.startswith("http://"):
            findings.append(
                self._create_vulnerability(
                    title="Login Form Submits Over HTTP",
                    description="Credentials are transmitted over unencrypted HTTP connection.",
                    severity="critical",
                    type="auth_http",
                    evidence={"form_action": form_url},
                    cwe_id="CWE-319",
                    remediation="Use HTTPS for all authentication endpoints.",
                )
            )

        # Check for autocomplete on password
        password_inputs = form.find_all("input", {"type": "password"})
        for pwd_input in password_inputs:
            if pwd_input.get("autocomplete", "").lower() not in ["off", "new-password", "current-password"]:
                findings.append(
                    self._create_vulnerability(
                        title="Password Autocomplete Enabled",
                        description="Password field allows browser autocomplete, which may expose credentials.",
                        severity="low",
                        type="auth_autocomplete",
                        evidence={"input_name": pwd_input.get("name")},
                        cwe_id="CWE-522",
                        remediation="Set autocomplete='off' or 'new-password' on password fields.",
                    )
                )

        # Check for CSRF protection
        csrf_indicators = ["csrf", "token", "xsrf", "authenticity"]
        hidden_inputs = form.find_all("input", {"type": "hidden"})
        has_csrf = any(
            any(ind in (h.get("name", "") + h.get("id", "")).lower() for ind in csrf_indicators) for h in hidden_inputs
        )

        if not has_csrf:
            findings.append(
                self._create_vulnerability(
                    title="Login Form Missing CSRF Protection",
                    description="Login form does not appear to have CSRF token protection.",
                    severity="medium",
                    type="auth_no_csrf",
                    evidence={"form_action": form_url},
                    cwe_id="CWE-352",
                    remediation="Implement CSRF tokens for login forms to prevent login CSRF attacks.",
                )
            )

        return findings

    async def _test_default_credentials(self, form, url: str) -> list[Vulnerability]:
        """Test for default credentials."""
        findings = []

        action = form.get("action", "")
        form_url = urljoin(url, action) if action else url

        # Get field names
        inputs = form.find_all("input")
        username_field = None
        password_field = None

        for inp in inputs:
            inp_type = inp.get("type", "text").lower()
            inp_name = inp.get("name", "")

            if inp_type == "password":
                password_field = inp_name
            elif inp_type in ["text", "email"]:
                if any(x in inp_name.lower() for x in ["user", "email", "login", "name"]):
                    username_field = inp_name

        if not username_field or not password_field:
            return findings

        # Test limited number of credentials
        tested = 0
        for username, password in self.default_credentials[:5]:  # Limit tests
            try:
                data = {username_field: username, password_field: password}
                resp = await self.http_client.post(form_url, data=data)

                if resp:
                    resp_text = await resp.text()
                    resp_url = str(resp.url)

                    # Success indicators
                    success_indicators = [
                        "dashboard" in resp_url.lower(),
                        "welcome" in resp_text.lower(),
                        "logout" in resp_text.lower(),
                        "profile" in resp_text.lower(),
                        resp.status == 302 and "login" not in resp_url.lower(),
                    ]

                    # Failure indicators
                    failure_indicators = [
                        "invalid" in resp_text.lower(),
                        "incorrect" in resp_text.lower(),
                        "failed" in resp_text.lower(),
                        "error" in resp_text.lower(),
                    ]

                    if any(success_indicators) and not any(failure_indicators):
                        findings.append(
                            self._create_vulnerability(
                                title="Default Credentials Accepted",
                                description=f"Login successful with default credentials: {username}:{password}",
                                severity="critical",
                                type="auth_default_creds",
                                evidence={"username": username, "password": "***"},
                                cwe_id="CWE-521",
                                remediation="Change all default credentials immediately. Implement password complexity requirements.",
                            )
                        )
                        break  # Stop after finding valid credentials

                tested += 1
                await asyncio.sleep(0.5)  # Rate limit ourselves

            except Exception as e:
                logger.debug(f"Credential test error: {e}")

        return findings

    async def _check_account_enumeration(self, form, url: str) -> list[Vulnerability]:
        """Check for account enumeration vulnerability."""
        findings = []

        action = form.get("action", "")
        form_url = urljoin(url, action) if action else url

        inputs = form.find_all("input")
        username_field = None
        password_field = None

        for inp in inputs:
            if inp.get("type") == "password":
                password_field = inp.get("name", "")
            elif inp.get("type") in ["text", "email"]:
                username_field = inp.get("name", "")

        if not username_field or not password_field:
            return findings

        try:
            # Test with likely non-existent user
            fake_user_data = {username_field: "nonexistent_user_12345", password_field: "wrongpassword"}
            resp1 = await self.http_client.post(form_url, data=fake_user_data)

            # Test with common username but wrong password
            real_user_data = {username_field: "admin", password_field: "definitelywrongpassword123"}
            resp2 = await self.http_client.post(form_url, data=real_user_data)

            if resp1 and resp2:
                text1 = await resp1.text()
                await resp2.text()

                # Look for different error messages
                error_patterns = [
                    ("user not found", "invalid password"),
                    ("username does not exist", "wrong password"),
                    ("no account", "incorrect password"),
                    ("user does not exist", "invalid credentials"),
                ]

                for not_found_msg, wrong_pwd_msg in error_patterns:
                    if not_found_msg in text1.lower() and wrong_pwd_msg not in text1.lower():
                        findings.append(
                            self._create_vulnerability(
                                title="Username Enumeration Possible",
                                description="Different error messages for invalid username vs invalid password allow attackers to enumerate valid usernames.",
                                severity="medium",
                                type="auth_enumeration",
                                evidence={"response_snippet": text1[:200]},
                                cwe_id="CWE-203",
                                remediation="Use generic error messages like 'Invalid username or password' for all login failures.",
                            )
                        )
                        break

        except Exception as e:
            logger.debug(f"Enumeration check error: {e}")

        return findings

    async def _test_rate_limiting(self, form, url: str) -> list[Vulnerability]:
        """Test for rate limiting on login attempts."""
        findings = []

        action = form.get("action", "")
        form_url = urljoin(url, action) if action else url

        inputs = form.find_all("input")
        username_field = next((i.get("name") for i in inputs if i.get("type") in ["text", "email"]), None)
        password_field = next((i.get("name") for i in inputs if i.get("type") == "password"), None)

        if not username_field or not password_field:
            return findings

        try:
            # Make rapid login attempts
            blocked = False
            attempts = 0

            for i in range(10):
                data = {username_field: "admin", password_field: f"wrongpass{i}"}
                resp = await self.http_client.post(form_url, data=data)

                if resp:
                    if resp.status == 429:  # Too Many Requests
                        blocked = True
                        break

                    text = await resp.text()
                    if any(x in text.lower() for x in ["rate limit", "too many", "blocked", "locked", "wait"]):
                        blocked = True
                        break

                attempts += 1
                await asyncio.sleep(0.1)  # Very quick succession

            if not blocked and attempts >= 10:
                findings.append(
                    self._create_vulnerability(
                        title="No Rate Limiting on Login",
                        description=f"Made {attempts} rapid login attempts without being blocked. Brute force attacks possible.",
                        severity="high",
                        type="auth_no_rate_limit",
                        evidence={"attempts_made": attempts},
                        cwe_id="CWE-307",
                        remediation="Implement rate limiting, account lockout, or CAPTCHA after failed attempts.",
                    )
                )

        except Exception as e:
            logger.debug(f"Rate limit test error: {e}")

        return findings

    def _analyze_session_security(self, response) -> list[Vulnerability]:
        """Analyze session and cookie security."""
        findings = []

        if not hasattr(response, "cookies"):
            return findings

        session_cookie_names = [
            "session",
            "sessionid",
            "sess",
            "sid",
            "auth",
            "token",
            "jwt",
            "phpsessid",
            "jsessionid",
        ]

        for name, cookie in response.cookies.items():
            is_session_cookie = any(s in name.lower() for s in session_cookie_names)

            if is_session_cookie:
                # Check Secure flag
                if not cookie.get("secure"):
                    findings.append(
                        self._create_vulnerability(
                            title=f"Session Cookie Missing Secure Flag: {name}",
                            description="Session cookie can be transmitted over unencrypted HTTP connections.",
                            severity="medium",
                            type="auth_cookie_secure",
                            evidence={"cookie": name},
                            cwe_id="CWE-614",
                            remediation="Set Secure flag on all session cookies.",
                        )
                    )

                # Check HttpOnly flag
                if not cookie.get("httponly"):
                    findings.append(
                        self._create_vulnerability(
                            title=f"Session Cookie Missing HttpOnly: {name}",
                            description="Session cookie accessible to JavaScript, vulnerable to XSS-based session theft.",
                            severity="medium",
                            type="auth_cookie_httponly",
                            evidence={"cookie": name},
                            cwe_id="CWE-1004",
                            remediation="Set HttpOnly flag on session cookies.",
                        )
                    )

                # Check SameSite
                samesite = cookie.get("samesite", "").lower()
                if not samesite or samesite == "none":
                    findings.append(
                        self._create_vulnerability(
                            title=f"Session Cookie Weak SameSite: {name}",
                            description="Session cookie missing or has weak SameSite attribute, vulnerable to CSRF.",
                            severity="low",
                            type="auth_cookie_samesite",
                            evidence={"cookie": name, "samesite": samesite or "not set"},
                            cwe_id="CWE-1275",
                            remediation="Set SameSite=Lax or SameSite=Strict on session cookies.",
                        )
                    )

        return findings
