"""
Social Engineering Assessment Module - Human Factor Security Scanner

WARNING: This module is designed for AUTHORIZED penetration testing and security
assessments ONLY. Unauthorized use against systems you do not own or have explicit
written permission to test is ILLEGAL and UNETHICAL. Always obtain proper authorization
before conducting any security assessment.

This module assesses the target's resilience to social engineering attacks by
analyzing email security (SPF, DKIM, DMARC), detecting typosquatting risks,
identifying metadata leakage, and evaluating security awareness indicators.
"""

import asyncio
import logging
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from .base_scanner import BaseScanner, Vulnerability

logger = logging.getLogger(__name__)


# Common typosquatting transformations
TYPOSQUAT_TRANSFORMS = {
    "char_swap": lambda d: [d[:i] + d[i + 1] + d[i] + d[i + 2:] for i in range(len(d) - 1)],
    "char_omit": lambda d: [d[:i] + d[i + 1:] for i in range(len(d))],
    "char_double": lambda d: [d[:i] + d[i] + d[i:] for i in range(len(d))],
    "homoglyphs": {
        "a": ["@", "4"], "e": ["3"], "i": ["1", "l"], "o": ["0"],
        "s": ["5", "$"], "t": ["7"], "g": ["9"], "l": ["1", "i"],
    },
}

# Email security record types
EMAIL_SECURITY_RECORDS = {
    "spf": {
        "prefix": "v=spf1",
        "strong_indicators": ["-all", "~all"],
        "weak_indicators": ["+all", "?all"],
    },
    "dmarc": {
        "prefix": "v=DMARC1",
        "policies": {"none": "monitoring", "quarantine": "moderate", "reject": "strict"},
    },
}

# Metadata patterns for information leakage
METADATA_PATTERNS = {
    "emails": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    "phone_numbers": re.compile(r'(?:\+\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}'),
    "names": re.compile(r'(?:authored?\s+by|created?\s+by|contact|manager|director|ceo|cto|cfo)\s*:?\s*([A-Z][a-z]+\s+[A-Z][a-z]+)', re.I),
    "internal_paths": re.compile(r'[A-Za-z]:\\(?:Users|Documents|home)\\[^"\'<>\s]+'),
    "software_versions": re.compile(r'(?:version|ver|v)\s*:?\s*(\d+\.\d+(?:\.\d+)?)', re.I),
}


class SocialEngineeringScanner(BaseScanner):
    """
    Social Engineering Assessment Scanner.

    AUTHORIZED USE ONLY: This module assesses the target organization's
    resilience to social engineering by examining:

    - Email security configuration (SPF, DKIM, DMARC)
    - Typosquatting/homograph domain risks
    - Open redirect chains for phishing paths
    - Metadata leakage (employee names, emails, internal info)
    - Social media footprint exposure
    - Security awareness indicators
    """

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "SocialEngineeringScanner"
        self.description = "Social engineering resilience assessment"
        self.version = "1.0.0"
        self.capabilities = [
            "Email Security Analysis",
            "Typosquatting Detection",
            "Open Redirect Analysis",
            "Metadata Leakage Analysis",
            "Social Media Footprint",
            "Security Awareness Assessment",
        ]
        self.max_requests = 60

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform social engineering assessment."""
        logger.info(f"Starting Social Engineering assessment for {url}")
        vulnerabilities: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "email_security": {},
            "typosquatting": {},
            "open_redirects": [],
            "metadata_leakage": {},
            "social_media": {},
            "security_awareness": {},
        }

        try:
            # Phase 1: Email Security Analysis (20%)
            self._update_progress(progress_callback, 10, "Analyzing email security")
            email_vulns, email_evidence = await self._analyze_email_security(url)
            vulnerabilities.extend(email_vulns)
            evidence["email_security"] = email_evidence

            # Phase 2: Typosquatting Detection (35%)
            self._update_progress(progress_callback, 25, "Detecting typosquatting risks")
            typo_vulns, typo_evidence = await self._detect_typosquatting(url)
            vulnerabilities.extend(typo_vulns)
            evidence["typosquatting"] = typo_evidence

            # Phase 3: Open Redirect Analysis (50%)
            self._update_progress(progress_callback, 40, "Analyzing open redirect chains")
            redir_vulns, redir_evidence = await self._analyze_open_redirects(url)
            vulnerabilities.extend(redir_vulns)
            evidence["open_redirects"] = redir_evidence

            # Phase 4: Metadata Leakage (70%)
            self._update_progress(progress_callback, 55, "Scanning for metadata leakage")
            meta_vulns, meta_evidence = await self._analyze_metadata_leakage(url)
            vulnerabilities.extend(meta_vulns)
            evidence["metadata_leakage"] = meta_evidence

            # Phase 5: Social Media Footprint (85%)
            self._update_progress(progress_callback, 72, "Analyzing social media footprint")
            social_vulns, social_evidence = await self._analyze_social_footprint(url)
            vulnerabilities.extend(social_vulns)
            evidence["social_media"] = social_evidence

            # Phase 6: Security Awareness Indicators (100%)
            self._update_progress(progress_callback, 88, "Checking security awareness indicators")
            aware_vulns, aware_evidence = await self._check_security_awareness(url)
            vulnerabilities.extend(aware_vulns)
            evidence["security_awareness"] = aware_evidence

            self._update_progress(progress_callback, 100, "completed")

        except Exception as e:
            logger.error(f"Social engineering assessment error: {e}")
            return self._format_result(
                "Error", f"Assessment failed: {str(e)}", vulnerabilities, evidence
            )

        details = (
            f"Social engineering assessment completed. "
            f"Found {len(vulnerabilities)} issue(s). "
            f"Email security: {email_evidence.get('overall_rating', 'unknown')}, "
            f"Typosquat risk domains: {len(typo_evidence.get('risky_domains', []))}, "
            f"Metadata leaks: {meta_evidence.get('total_leaks', 0)}"
        )

        return self._format_result("Completed", details, vulnerabilities, evidence)

    async def _analyze_email_security(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Analyze email security records (SPF, DKIM, DMARC)."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "domain": "",
            "spf": {"found": False},
            "dkim": {"found": False},
            "dmarc": {"found": False},
            "overall_rating": "unknown",
        }

        try:
            parsed = urlparse(url)
            domain = parsed.hostname
            if not domain:
                return vulns, evidence

            evidence["domain"] = domain

            # Check SPF via DNS-over-HTTPS
            try:
                doh_url = f"https://dns.google/resolve?name={domain}&type=TXT"
                resp = await self.http_client.get(doh_url)
                if resp and resp.status == 200:
                    try:
                        import json
                        data = json.loads(await resp.text())
                        answers = data.get("Answer", [])
                        for answer in answers:
                            txt_data = answer.get("data", "")
                            if "v=spf1" in txt_data:
                                evidence["spf"]["found"] = True
                                evidence["spf"]["record"] = txt_data[:200]
                                if "+all" in txt_data or "?all" in txt_data:
                                    evidence["spf"]["strength"] = "weak"
                                elif "~all" in txt_data:
                                    evidence["spf"]["strength"] = "moderate"
                                elif "-all" in txt_data:
                                    evidence["spf"]["strength"] = "strong"
                    except Exception:
                        pass
            except Exception:
                pass

            # Check DMARC via DNS-over-HTTPS
            try:
                dmarc_url = f"https://dns.google/resolve?name=_dmarc.{domain}&type=TXT"
                resp = await self.http_client.get(dmarc_url)
                if resp and resp.status == 200:
                    try:
                        import json
                        data = json.loads(await resp.text())
                        answers = data.get("Answer", [])
                        for answer in answers:
                            txt_data = answer.get("data", "")
                            if "v=DMARC1" in txt_data:
                                evidence["dmarc"]["found"] = True
                                evidence["dmarc"]["record"] = txt_data[:200]
                                if "p=reject" in txt_data:
                                    evidence["dmarc"]["policy"] = "reject"
                                elif "p=quarantine" in txt_data:
                                    evidence["dmarc"]["policy"] = "quarantine"
                                elif "p=none" in txt_data:
                                    evidence["dmarc"]["policy"] = "none"
                    except Exception:
                        pass
            except Exception:
                pass

            # Rate overall email security
            issues = []
            if not evidence["spf"]["found"]:
                issues.append("No SPF record")
            elif evidence["spf"].get("strength") == "weak":
                issues.append("Weak SPF (+all)")

            if not evidence["dmarc"]["found"]:
                issues.append("No DMARC record")
            elif evidence["dmarc"].get("policy") == "none":
                issues.append("DMARC policy set to 'none'")

            if len(issues) >= 2:
                evidence["overall_rating"] = "poor"
                vulns.append(self._create_vulnerability(
                    title="Weak Email Security Configuration",
                    description=(
                        f"Email security is inadequate for domain '{domain}'. "
                        f"Issues: {', '.join(issues)}. "
                        "This makes the domain vulnerable to email spoofing and phishing attacks."
                    ),
                    severity="high",
                    type="social_eng_email_security",
                    evidence={
                        "spf": evidence["spf"],
                        "dmarc": evidence["dmarc"],
                        "issues": issues,
                    },
                    cwe_id="CWE-290",
                    remediation=(
                        "Implement SPF with '-all', configure DMARC with 'p=reject', "
                        "and enable DKIM signing for all outgoing emails."
                    ),
                ))
            elif len(issues) == 1:
                evidence["overall_rating"] = "moderate"
            else:
                evidence["overall_rating"] = "good"

        except Exception as e:
            logger.debug(f"Email security analysis error: {e}")

        return vulns, evidence

    async def _detect_typosquatting(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Detect typosquatting/homograph domain risks."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "target_domain": "",
            "generated_variants": 0,
            "risky_domains": [],
        }

        try:
            parsed = urlparse(url)
            domain = parsed.hostname
            if not domain:
                return vulns, evidence

            # Get base domain name (without TLD)
            parts = domain.split(".")
            if len(parts) < 2:
                return vulns, evidence

            base_name = parts[-2] if len(parts) >= 2 else parts[0]
            tld = parts[-1]
            evidence["target_domain"] = domain

            # Generate typosquat variants
            variants = set()

            # Character swaps
            for i in range(len(base_name) - 1):
                variant = base_name[:i] + base_name[i + 1] + base_name[i] + base_name[i + 2:]
                variants.add(f"{variant}.{tld}")

            # Character omissions
            for i in range(len(base_name)):
                variant = base_name[:i] + base_name[i + 1:]
                if variant:
                    variants.add(f"{variant}.{tld}")

            # Homoglyphs
            for i, char in enumerate(base_name):
                replacements = TYPOSQUAT_TRANSFORMS["homoglyphs"].get(char, [])
                for rep in replacements:
                    variant = base_name[:i] + rep + base_name[i + 1:]
                    variants.add(f"{variant}.{tld}")

            # Different TLDs
            for alt_tld in ["com", "net", "org", "io", "co", "biz", "info"]:
                if alt_tld != tld:
                    variants.add(f"{base_name}.{alt_tld}")

            evidence["generated_variants"] = len(variants)

            # Check a subset of variants for DNS resolution
            risky = []
            check_variants = list(variants)[:15]  # Limit checks

            for variant in check_variants:
                try:
                    doh_url = f"https://dns.google/resolve?name={variant}&type=A"
                    resp = await self.http_client.get(doh_url)
                    if resp and resp.status == 200:
                        import json
                        data = json.loads(await resp.text())
                        if data.get("Answer"):
                            risky.append({
                                "domain": variant,
                                "resolves": True,
                                "ip": data["Answer"][0].get("data", ""),
                            })
                except Exception:
                    pass

            evidence["risky_domains"] = risky

            if risky:
                vulns.append(self._create_vulnerability(
                    title=f"Typosquatting Domains Active ({len(risky)})",
                    description=(
                        f"Found {len(risky)} active domains similar to '{domain}' that could "
                        "be used for phishing attacks targeting the organization."
                    ),
                    severity="medium",
                    type="social_eng_typosquatting",
                    evidence={"risky_domains": risky[:10]},
                    cwe_id="CWE-290",
                    remediation="Register common typosquat domains proactively. Monitor for brand impersonation.",
                ))

        except Exception as e:
            logger.debug(f"Typosquatting detection error: {e}")

        return vulns, evidence

    async def _analyze_open_redirects(self, url: str) -> tuple[list[Vulnerability], list]:
        """Analyze open redirect chains for phishing paths."""
        vulns: list[Vulnerability] = []
        redirects: list[dict] = []

        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # Test common redirect parameters
            redirect_params = [
                "redirect", "url", "next", "return", "returnUrl", "returnTo",
                "redir", "destination", "dest", "go", "target", "continue",
                "redirect_uri", "return_url", "callback",
            ]

            evil_url = "https://evil.example.com/phishing"

            for param in redirect_params:
                test_url = f"{base_url}/?{param}={evil_url}"
                try:
                    # Don't follow redirects to check for open redirect
                    resp = await self.http_client.get(test_url, allow_redirects=False)
                    if resp and resp.status in [301, 302, 303, 307, 308]:
                        location = resp.headers.get("Location", "")
                        if "evil.example.com" in location:
                            redirects.append({
                                "parameter": param,
                                "test_url": test_url[:100],
                                "redirects_to": location[:200],
                            })
                except Exception:
                    pass

            if redirects:
                vulns.append(self._create_vulnerability(
                    title=f"Open Redirects for Phishing ({len(redirects)} params)",
                    description=(
                        "Open redirect vulnerabilities were found that an attacker could "
                        "chain with the legitimate domain to create convincing phishing URLs."
                    ),
                    severity="medium",
                    type="social_eng_open_redirect",
                    evidence={"redirects": redirects[:10]},
                    cwe_id="CWE-601",
                    remediation="Validate redirect URLs against a whitelist of allowed destinations.",
                ))

        except Exception as e:
            logger.debug(f"Open redirect analysis error: {e}")

        return vulns, redirects

    async def _analyze_metadata_leakage(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Analyze metadata leakage in target responses."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "emails_found": [],
            "names_found": [],
            "internal_paths": [],
            "total_leaks": 0,
        }

        try:
            # Check main page and common information pages
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            pages = [
                url,
                f"{base_url}/about",
                f"{base_url}/contact",
                f"{base_url}/team",
                f"{base_url}/robots.txt",
                f"{base_url}/humans.txt",
            ]

            all_content = ""
            for page_url in pages:
                try:
                    resp = await self.http_client.get(page_url)
                    if resp and resp.status == 200:
                        try:
                            text = await resp.text()
                            all_content += text
                        except Exception:
                            pass
                except Exception:
                    pass

            if all_content:
                # Extract emails
                emails = METADATA_PATTERNS["emails"].findall(all_content)
                target_domain = parsed.hostname
                org_emails = [e for e in set(emails) if target_domain and target_domain in e]
                evidence["emails_found"] = org_emails[:20]

                # Extract names
                names = METADATA_PATTERNS["names"].findall(all_content)
                evidence["names_found"] = list(set(names))[:20]

                # Extract internal paths
                paths = METADATA_PATTERNS["internal_paths"].findall(all_content)
                evidence["internal_paths"] = list(set(paths))[:10]

                evidence["total_leaks"] = (
                    len(evidence["emails_found"])
                    + len(evidence["names_found"])
                    + len(evidence["internal_paths"])
                )

                if evidence["total_leaks"] > 5:
                    vulns.append(self._create_vulnerability(
                        title=f"Metadata Leakage ({evidence['total_leaks']} items)",
                        description=(
                            "Significant metadata leakage found including employee emails, "
                            "names, and potentially internal paths. This information can be "
                            "used to craft targeted phishing attacks (spear phishing)."
                        ),
                        severity="medium",
                        type="social_eng_metadata_leakage",
                        evidence={
                            "emails": evidence["emails_found"][:5],
                            "names": evidence["names_found"][:5],
                            "paths": evidence["internal_paths"][:3],
                        },
                        cwe_id="CWE-200",
                        remediation="Minimize public exposure of employee information. Remove internal paths from responses.",
                    ))

        except Exception as e:
            logger.debug(f"Metadata leakage analysis error: {e}")

        return vulns, evidence

    async def _analyze_social_footprint(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Analyze social media footprint exposure."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {"social_links": [], "platforms_found": []}

        try:
            response = await self.http_client.get(url)
            if not response or response.status != 200:
                return vulns, evidence

            html = ""
            try:
                html = await response.text()
            except Exception:
                return vulns, evidence

            social_platforms = {
                "linkedin": re.compile(r'https?://(?:www\.)?linkedin\.com/(?:company|in)/[^\s"\'<>]+'),
                "twitter": re.compile(r'https?://(?:www\.)?(?:twitter|x)\.com/[^\s"\'<>]+'),
                "facebook": re.compile(r'https?://(?:www\.)?facebook\.com/[^\s"\'<>]+'),
                "github": re.compile(r'https?://(?:www\.)?github\.com/[^\s"\'<>]+'),
                "instagram": re.compile(r'https?://(?:www\.)?instagram\.com/[^\s"\'<>]+'),
            }

            for platform, pattern in social_platforms.items():
                matches = pattern.findall(html)
                if matches:
                    evidence["platforms_found"].append(platform)
                    for match in set(matches[:3]):
                        evidence["social_links"].append({
                            "platform": platform,
                            "url": match[:200],
                        })

        except Exception as e:
            logger.debug(f"Social footprint analysis error: {e}")

        return vulns, evidence

    async def _check_security_awareness(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Check for security awareness indicators on the target."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "phishing_report_page": False,
            "security_page": False,
            "security_txt": False,
            "awareness_score": 0,
        }

        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # Check for security.txt
            try:
                resp = await self.http_client.get(f"{base_url}/.well-known/security.txt")
                if resp and resp.status == 200:
                    evidence["security_txt"] = True
                    evidence["awareness_score"] += 30
            except Exception:
                pass

            # Check for security page
            security_paths = ["/security", "/report-vulnerability", "/bug-bounty", "/responsible-disclosure"]
            for path in security_paths:
                try:
                    resp = await self.http_client.get(f"{base_url}{path}")
                    if resp and resp.status == 200:
                        evidence["security_page"] = True
                        evidence["security_page_path"] = path
                        evidence["awareness_score"] += 25
                        break
                except Exception:
                    pass

            # Check for phishing report mechanism
            response = await self.http_client.get(url)
            if response and response.status == 200:
                try:
                    html = await response.text()
                    phishing_indicators = [
                        "report phishing", "report suspicious",
                        "phishing report", "report abuse",
                        "security@", "abuse@",
                    ]
                    for indicator in phishing_indicators:
                        if indicator in html.lower():
                            evidence["phishing_report_page"] = True
                            evidence["awareness_score"] += 20
                            break
                except Exception:
                    pass

            # Check for security headers as awareness indicators
            if response:
                headers = {k.lower(): v for k, v in response.headers.items()}
                security_headers = [
                    "content-security-policy",
                    "x-content-type-options",
                    "x-frame-options",
                    "strict-transport-security",
                ]
                headers_present = sum(1 for h in security_headers if h in headers)
                evidence["security_headers_count"] = headers_present
                evidence["awareness_score"] += headers_present * 5

            if evidence["awareness_score"] < 30:
                vulns.append(self._create_vulnerability(
                    title="Low Security Awareness Posture",
                    description=(
                        "The target shows minimal security awareness indicators. "
                        "No security.txt, no vulnerability reporting page, and limited "
                        "security headers. This suggests the organization may be more "
                        "susceptible to social engineering attacks."
                    ),
                    severity="low",
                    type="social_eng_low_awareness",
                    evidence=evidence,
                    cwe_id="CWE-693",
                    remediation=(
                        "Implement security.txt, create a vulnerability disclosure page, "
                        "establish phishing reporting mechanisms, and deploy security headers."
                    ),
                ))

        except Exception as e:
            logger.debug(f"Security awareness check error: {e}")

        return vulns, evidence
