"""
LDAP/Active Directory Assessment Module - Directory Service Security Scanner

WARNING: This module is designed for AUTHORIZED penetration testing and security
assessments ONLY. Unauthorized use against systems you do not own or have explicit
written permission to test is ILLEGAL and UNETHICAL. Always obtain proper authorization
before conducting any security assessment.

This module tests for LDAP injection vulnerabilities, anonymous bind access,
Active Directory enumeration exposure, Kerberoasting and AS-REP roasting
vulnerabilities, password policy weaknesses, and Group Policy exposure.
"""

import asyncio
import logging
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin, urlparse

from .base_scanner import BaseScanner, Vulnerability

logger = logging.getLogger(__name__)


# LDAP injection payloads (safe, detection-only)
LDAP_INJECTION_PAYLOADS = [
    "*",
    "*)(&",
    "*)(|(&",
    "*()|&'",
    "admin*",
    "admin)(&)",
    "admin)(|(password=*))",
    ")(cn=*))(|(cn=*",
    "*)(uid=*))(|(uid=*",
    "\\00",
    "*(|(mail=*))",
    "*(|(objectclass=*))",
]

# Common LDAP-related web endpoints
LDAP_WEB_ENDPOINTS = [
    "/ldap", "/ldaplogin", "/auth/ldap", "/api/ldap",
    "/adfs", "/adfs/ls", "/sso", "/sso/login",
    "/api/v1/ldap/config", "/admin/ldap",
]

# AD-specific indicators
AD_INDICATORS = {
    "headers": [
        "X-MS-Server-Fqdn",
        "X-MS-AuthType",
        "X-FORMS_BASED_AUTH_REQUIRED",
        "X-MS-InvokeApp",
    ],
    "paths": [
        "/adfs/services/trust",
        "/adfs/ls/idpinitiatedsignon",
        "/EWS/Exchange.asmx",
        "/OWA",
        "/owa/auth/logon.aspx",
        "/autodiscover/autodiscover.xml",
        "/remote/login",
    ],
    "content_patterns": [
        r"Active Directory",
        r"LDAP",
        r"domain\\",
        r"@[\w]+\.local",
        r"DC=[\w]+",
        r"CN=[\w]+",
        r"OU=[\w]+",
    ],
}

# Kerberos-related indicators
KERBEROS_INDICATORS = {
    "spn_patterns": [
        r"HTTP/[\w\.]+",
        r"MSSQLSvc/[\w\.]+",
        r"CIFS/[\w\.]+",
        r"LDAP/[\w\.]+",
    ],
    "auth_headers": [
        "WWW-Authenticate: Negotiate",
        "WWW-Authenticate: NTLM",
    ],
}


class LDAPADScanner(BaseScanner):
    """
    LDAP/Active Directory Assessment Scanner.

    AUTHORIZED USE ONLY: This module assesses directory service security
    including LDAP injection testing, anonymous access detection, AD
    enumeration exposure, and Kerberos-related vulnerabilities.

    Features:
    - LDAP injection testing via web interfaces
    - Anonymous bind detection
    - AD enumeration via LDAP-exposed web services
    - Kerberoasting vulnerability indicators
    - AS-REP roasting indicators
    - Password policy extraction
    - Group Policy exposure detection
    """

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "LDAPADScanner"
        self.description = "LDAP/Active Directory security assessment"
        self.version = "1.0.0"
        self.capabilities = [
            "LDAP Injection Testing",
            "Anonymous Bind Detection",
            "AD Enumeration Assessment",
            "Kerberoasting Detection",
            "AS-REP Roasting Detection",
            "Password Policy Extraction",
            "Group Policy Enumeration",
        ]
        self.max_requests = 80

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform LDAP/AD security assessment on the target."""
        logger.info(f"Starting LDAP/AD assessment for {url}")
        vulnerabilities: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "ldap_injection": {},
            "anonymous_bind": {},
            "ad_enumeration": {},
            "kerberoasting": {},
            "asrep_roasting": {},
            "password_policy": {},
            "group_policy": {},
        }

        try:
            # Phase 1: Detect LDAP/AD Presence (15%)
            self._update_progress(progress_callback, 10, "Detecting LDAP/AD presence")
            ad_detected, ad_evidence = await self._detect_ad_presence(url)

            # Phase 2: LDAP Injection Testing (35%)
            self._update_progress(progress_callback, 25, "Testing LDAP injection")
            ldap_vulns, ldap_evidence = await self._test_ldap_injection(url)
            vulnerabilities.extend(ldap_vulns)
            evidence["ldap_injection"] = ldap_evidence

            # Phase 3: Anonymous Bind Detection (50%)
            self._update_progress(progress_callback, 40, "Testing anonymous bind access")
            anon_vulns, anon_evidence = await self._detect_anonymous_bind(url)
            vulnerabilities.extend(anon_vulns)
            evidence["anonymous_bind"] = anon_evidence

            # Phase 4: AD Enumeration (65%)
            self._update_progress(progress_callback, 55, "Checking AD enumeration exposure")
            enum_vulns, enum_evidence = await self._check_ad_enumeration(url, ad_evidence)
            vulnerabilities.extend(enum_vulns)
            evidence["ad_enumeration"] = enum_evidence

            # Phase 5: Kerberos Assessment (80%)
            self._update_progress(progress_callback, 70, "Assessing Kerberos vulnerabilities")
            kerb_vulns, kerb_evidence = await self._assess_kerberos(url)
            vulnerabilities.extend(kerb_vulns)
            evidence["kerberoasting"] = kerb_evidence

            # Phase 6: Password Policy (90%)
            self._update_progress(progress_callback, 82, "Extracting password policy")
            pw_vulns, pw_evidence = await self._extract_password_policy(url)
            vulnerabilities.extend(pw_vulns)
            evidence["password_policy"] = pw_evidence

            # Phase 7: Group Policy (100%)
            self._update_progress(progress_callback, 92, "Checking Group Policy exposure")
            gp_vulns, gp_evidence = await self._check_group_policy(url)
            vulnerabilities.extend(gp_vulns)
            evidence["group_policy"] = gp_evidence

            self._update_progress(progress_callback, 100, "completed")

        except Exception as e:
            logger.error(f"LDAP/AD assessment error: {e}")
            return self._format_result(
                "Error", f"Assessment failed: {str(e)}", vulnerabilities, evidence
            )

        details = (
            f"LDAP/AD assessment completed. "
            f"Found {len(vulnerabilities)} issue(s). "
            f"AD detected: {ad_detected}, "
            f"LDAP injection: {ldap_evidence.get('vulnerable', False)}, "
            f"Anonymous bind: {anon_evidence.get('accessible', False)}"
        )

        return self._format_result("Completed", details, vulnerabilities, evidence)

    async def _detect_ad_presence(self, url: str) -> tuple[bool, dict]:
        """Detect Active Directory / LDAP service presence."""
        evidence: dict[str, Any] = {"detected": False, "indicators": []}

        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # Check for AD-specific headers
            response = await self.http_client.get(url)
            if response:
                headers = dict(response.headers)
                for ad_header in AD_INDICATORS["headers"]:
                    if ad_header in headers:
                        evidence["detected"] = True
                        evidence["indicators"].append({
                            "type": "header",
                            "name": ad_header,
                            "value": headers[ad_header],
                        })

                # Check for Negotiate/NTLM auth
                www_auth = headers.get("WWW-Authenticate", "")
                if "Negotiate" in www_auth or "NTLM" in www_auth:
                    evidence["detected"] = True
                    evidence["indicators"].append({
                        "type": "auth",
                        "method": www_auth,
                    })

            # Check AD-specific paths
            for path in AD_INDICATORS["paths"][:5]:
                try:
                    resp = await self.http_client.get(f"{base_url}{path}")
                    if resp and resp.status not in [404]:
                        evidence["detected"] = True
                        evidence["indicators"].append({
                            "type": "endpoint",
                            "path": path,
                            "status": resp.status,
                        })
                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"AD presence detection error: {e}")

        return evidence["detected"], evidence

    async def _test_ldap_injection(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Test for LDAP injection vulnerabilities via web interfaces."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "vulnerable": False,
            "tested_params": [],
            "injection_points": [],
        }

        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # Find potential LDAP-connected forms/endpoints
            search_params = ["username", "user", "uid", "cn", "search", "query", "filter", "name"]
            params = await self._discover_parameters(url)
            ldap_params = [p for p in params if p.lower() in search_params] or search_params[:4]

            evidence["tested_params"] = ldap_params

            for param in ldap_params:
                for payload in LDAP_INJECTION_PAYLOADS[:6]:
                    try:
                        result = await self._test_payload(url, param, payload)

                        if result["status_code"] == 200:
                            content = result.get("page_content", "")

                            # Check for LDAP error messages in response
                            ldap_errors = [
                                "ldap_search", "ldap_bind", "LDAP error",
                                "Invalid DN syntax", "Bad search filter",
                                "javax.naming", "LDAPException",
                                "ldap_err", "LDAP_OPERATIONS_ERROR",
                                "invalid attribute description",
                            ]

                            for error in ldap_errors:
                                if error.lower() in content.lower():
                                    evidence["vulnerable"] = True
                                    evidence["injection_points"].append({
                                        "parameter": param,
                                        "payload": payload,
                                        "error_indicator": error,
                                    })
                                    break

                            # Check if wildcard returned more data (different response size)
                            if payload == "*" and len(content) > 1000:
                                evidence["injection_points"].append({
                                    "parameter": param,
                                    "payload": payload,
                                    "indicator": "wildcard_expansion",
                                    "response_size": len(content),
                                })

                    except Exception:
                        pass

            if evidence["vulnerable"]:
                vulns.append(self._create_vulnerability(
                    title="LDAP Injection Vulnerability",
                    description=(
                        "LDAP injection vulnerabilities were detected. An attacker could "
                        "modify LDAP queries to bypass authentication, enumerate directory "
                        "objects, or extract sensitive information."
                    ),
                    severity="critical",
                    type="ldap_injection",
                    evidence={"injection_points": evidence["injection_points"][:5]},
                    cwe_id="CWE-90",
                    remediation=(
                        "Use parameterized LDAP queries. Validate and sanitize all user input "
                        "used in LDAP filters. Apply least-privilege LDAP bind accounts."
                    ),
                ))

        except Exception as e:
            logger.debug(f"LDAP injection test error: {e}")

        return vulns, evidence

    async def _detect_anonymous_bind(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Detect if LDAP anonymous bind is accessible via web interface."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {"accessible": False, "endpoints_tested": []}

        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            for endpoint in LDAP_WEB_ENDPOINTS:
                try:
                    resp = await self.http_client.get(f"{base_url}{endpoint}")
                    endpoint_info = {
                        "path": endpoint,
                        "status": resp.status if resp else 0,
                    }

                    if resp and resp.status == 200:
                        try:
                            body = await resp.text()
                            # Check for LDAP data leakage without auth
                            ldap_data_indicators = [
                                "objectClass", "distinguishedName", "sAMAccountName",
                                "userPrincipalName", "memberOf", "cn=",
                            ]
                            for indicator in ldap_data_indicators:
                                if indicator in body:
                                    evidence["accessible"] = True
                                    endpoint_info["data_leaked"] = True
                                    endpoint_info["indicator"] = indicator
                                    break
                        except Exception:
                            pass

                    evidence["endpoints_tested"].append(endpoint_info)

                except Exception:
                    pass

            if evidence["accessible"]:
                vulns.append(self._create_vulnerability(
                    title="LDAP Anonymous Access Detected",
                    description=(
                        "LDAP directory data is accessible without authentication via web endpoints. "
                        "This allows attackers to enumerate users, groups, and organizational structure."
                    ),
                    severity="high",
                    type="ldap_anonymous_bind",
                    evidence=evidence,
                    cwe_id="CWE-287",
                    remediation="Disable anonymous LDAP binds. Require authentication for all directory queries.",
                ))

        except Exception as e:
            logger.debug(f"Anonymous bind detection error: {e}")

        return vulns, evidence

    async def _check_ad_enumeration(self, url: str, ad_evidence: dict) -> tuple[list[Vulnerability], dict]:
        """Check for AD enumeration exposure."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "users_exposed": False,
            "groups_exposed": False,
            "ous_exposed": False,
        }

        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # Check for user enumeration endpoints
            user_enum_paths = [
                "/api/users", "/api/v1/users", "/api/directory/users",
                "/users", "/people", "/employees", "/staff",
            ]

            for path in user_enum_paths:
                try:
                    resp = await self.http_client.get(f"{base_url}{path}")
                    if resp and resp.status == 200:
                        try:
                            body = await resp.text()
                            # Check for user data indicators
                            if any(w in body.lower() for w in [
                                "username", "email", "displayname", "samaccountname",
                                "userprincipalname", '"users"', '"employees"',
                            ]):
                                evidence["users_exposed"] = True
                                evidence["user_endpoint"] = path
                        except Exception:
                            pass
                except Exception:
                    pass

            # Check for exposed metadata that reveals AD structure
            response = await self.http_client.get(url)
            if response:
                try:
                    html = await response.text()
                    for pattern_str in AD_INDICATORS["content_patterns"]:
                        pattern = re.compile(pattern_str, re.IGNORECASE)
                        matches = pattern.findall(html)
                        if matches:
                            evidence["ad_patterns_found"] = matches[:5]
                except Exception:
                    pass

            if evidence["users_exposed"]:
                vulns.append(self._create_vulnerability(
                    title="Active Directory User Enumeration Exposed",
                    description=(
                        "User directory information is accessible via web endpoints. "
                        "This allows attackers to enumerate valid usernames for attacks."
                    ),
                    severity="high",
                    type="ldap_user_enumeration",
                    evidence=evidence,
                    cwe_id="CWE-200",
                    remediation="Restrict directory listing endpoints. Require authentication for user queries.",
                ))

        except Exception as e:
            logger.debug(f"AD enumeration check error: {e}")

        return vulns, evidence

    async def _assess_kerberos(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Assess Kerberos-related vulnerabilities (Kerberoasting, AS-REP roasting)."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "negotiate_auth": False,
            "spn_exposure": False,
            "kerberoasting_risk": "unknown",
        }

        try:
            response = await self.http_client.get(url)
            if not response:
                return vulns, evidence

            headers = dict(response.headers)
            www_auth = headers.get("WWW-Authenticate", "")

            if "Negotiate" in www_auth:
                evidence["negotiate_auth"] = True

                vulns.append(self._create_vulnerability(
                    title="Kerberos/Negotiate Authentication Exposed",
                    description=(
                        "The target uses Kerberos/Negotiate authentication. If service accounts "
                        "use weak passwords with SPNs, they may be vulnerable to Kerberoasting "
                        "(offline password cracking of service ticket hashes)."
                    ),
                    severity="medium",
                    type="ldap_kerberos_exposed",
                    evidence={"www_authenticate": www_auth},
                    cwe_id="CWE-916",
                    remediation=(
                        "Use strong passwords (25+ characters) for service accounts with SPNs. "
                        "Monitor for Kerberoasting attacks. Use AES encryption for Kerberos."
                    ),
                ))

            # Check for SPN exposure in page content
            try:
                html = await response.text()
                for spn_pattern in KERBEROS_INDICATORS["spn_patterns"]:
                    matches = re.findall(spn_pattern, html)
                    if matches:
                        evidence["spn_exposure"] = True
                        evidence["spns_found"] = matches[:5]
            except Exception:
                pass

        except Exception as e:
            logger.debug(f"Kerberos assessment error: {e}")

        return vulns, evidence

    async def _extract_password_policy(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Extract and assess password policy information."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {"policy_found": False, "policy": {}}

        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # Check for password policy endpoints
            policy_paths = [
                "/api/password-policy", "/api/v1/password-policy",
                "/api/auth/policy", "/password-requirements",
                "/signup", "/register", "/create-account",
            ]

            for path in policy_paths:
                try:
                    resp = await self.http_client.get(f"{base_url}{path}")
                    if resp and resp.status == 200:
                        try:
                            body = await resp.text()
                            # Look for password requirements
                            policy_patterns = {
                                "min_length": re.compile(r'(?:minimum|min)\s*(?:length|characters?)\s*[:=]\s*(\d+)', re.I),
                                "max_length": re.compile(r'(?:maximum|max)\s*(?:length|characters?)\s*[:=]\s*(\d+)', re.I),
                                "uppercase": re.compile(r'(?:uppercase|capital)\s*(?:letter|character)', re.I),
                                "lowercase": re.compile(r'(?:lowercase)\s*(?:letter|character)', re.I),
                                "digits": re.compile(r'(?:digit|number)', re.I),
                                "special": re.compile(r'(?:special|symbol)\s*(?:character)', re.I),
                            }

                            for key, pattern in policy_patterns.items():
                                match = pattern.search(body)
                                if match:
                                    evidence["policy_found"] = True
                                    evidence["policy"][key] = match.group(0) if not match.groups() else match.group(1)
                        except Exception:
                            pass
                except Exception:
                    pass

            # Check for weak password policy indicators
            if evidence["policy_found"]:
                min_len = evidence["policy"].get("min_length")
                if min_len and int(min_len) < 8:
                    vulns.append(self._create_vulnerability(
                        title="Weak Password Policy Detected",
                        description=(
                            f"The password policy allows passwords as short as {min_len} characters. "
                            "This makes accounts vulnerable to brute-force attacks."
                        ),
                        severity="medium",
                        type="ldap_weak_password_policy",
                        evidence=evidence["policy"],
                        cwe_id="CWE-521",
                        remediation="Enforce minimum 12-character passwords with complexity requirements.",
                    ))

        except Exception as e:
            logger.debug(f"Password policy extraction error: {e}")

        return vulns, evidence

    async def _check_group_policy(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Check for Group Policy exposure."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {"gpo_exposed": False, "sysvol_accessible": False}

        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # Check for SYSVOL/NETLOGON share exposure via web
            gp_paths = [
                "/sysvol", "/netlogon", "/SYSVOL", "/NETLOGON",
                "/gpo", "/group-policy", "/policies",
            ]

            for path in gp_paths:
                try:
                    resp = await self.http_client.get(f"{base_url}{path}")
                    if resp and resp.status == 200:
                        try:
                            body = await resp.text()
                            # Look for GPO indicators
                            gpo_indicators = [
                                "Groups.xml", "ScheduledTasks.xml",
                                "Registry.pol", "GptTmpl.inf",
                                "cpassword", "Policy",
                            ]
                            for indicator in gpo_indicators:
                                if indicator in body:
                                    evidence["gpo_exposed"] = True
                                    evidence["exposed_path"] = path
                                    evidence["indicator"] = indicator
                                    break
                        except Exception:
                            pass
                except Exception:
                    pass

            if evidence["gpo_exposed"]:
                vulns.append(self._create_vulnerability(
                    title="Group Policy Objects Exposed",
                    description=(
                        "Group Policy configuration files are accessible via web. "
                        "This may expose sensitive configuration including credentials "
                        "(cpassword in Groups.xml), scheduled tasks, and security settings."
                    ),
                    severity="critical",
                    type="ldap_gpo_exposure",
                    evidence=evidence,
                    cwe_id="CWE-200",
                    remediation=(
                        "Restrict SYSVOL/NETLOGON share access. Remove GPP credentials. "
                        "Use LAPS for local admin password management."
                    ),
                ))

        except Exception as e:
            logger.debug(f"Group Policy check error: {e}")

        return vulns, evidence
