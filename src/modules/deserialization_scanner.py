"""
Deserialization Scanner module - Advanced Implementation.
"""

import base64
import logging
import re
from collections.abc import Callable
from typing import Any

from .base_scanner import BaseScanner, Vulnerability

logger = logging.getLogger(__name__)


class DeserializationScanner(BaseScanner):
    """Advanced Insecure Deserialization vulnerability detection engine."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "DeserializationScanner"
        self.description = "Detects insecure deserialization in Java, Python, PHP, .NET, and Ruby"
        self.version = "1.0.0"
        self.capabilities = [
            "Java Serialization Detection",
            "PHP Object Injection",
            "Python Pickle Detection",
            ".NET ViewState Analysis",
            "Ruby Marshal Detection",
            "Gadget Chain Identification",
        ]

        # Serialization signatures
        self.signatures = {
            "java": {
                "magic": [b"\xac\xed", "rO0", "H4sI"],
                "patterns": ["java.", "org.apache", "javax.", "serialVersionUID"],
                "description": "Java ObjectInputStream",
            },
            "php": {
                "magic": ["O:", "a:", "s:", "C:"],
                "patterns": ["__wakeup", "__destruct", "__toString", "POP chain"],
                "description": "PHP unserialize()",
            },
            "python": {
                "magic": [b"\x80\x03", b"\x80\x04", b"\x80\x05", "gASV"],
                "patterns": ["__reduce__", "pickle", "cPickle"],
                "description": "Python pickle.loads()",
            },
            "dotnet": {
                "magic": ["__VIEWSTATE", "AAEAAAD", "AAEAAAD/////"],
                "patterns": ["System.", "Microsoft.", "BinaryFormatter", "SoapFormatter"],
                "description": ".NET BinaryFormatter",
            },
            "ruby": {
                "magic": [b"\x04\x08", "BAh"],
                "patterns": ["Marshal.load", "YAML.load"],
                "description": "Ruby Marshal/YAML",
            },
        }

        # Common vulnerable parameters
        self.target_params = [
            "data",
            "object",
            "session",
            "state",
            "viewstate",
            "__VIEWSTATE",
            "payload",
            "item",
            "token",
            "cache",
            "input",
            "content",
            "message",
            "blob",
            "serialized",
            "encoded",
            "base64",
        ]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform comprehensive deserialization vulnerability scan."""
        logger.info(f"Scanning {url} for deserialization vulnerabilities")
        vulnerabilities = []

        try:
            self._update_progress(progress_callback, 10, "Fetching target response")

            response = await self.http_client.get(url)
            if not response:
                return self._format_result("Error", "Target unreachable", [])

            html = await response.text()
            headers = dict(response.headers)

            # 1. Scan for serialization indicators in response
            self._update_progress(progress_callback, 25, "Scanning for serialization patterns")
            pattern_vulns = self._detect_serialization_patterns(html, headers)
            vulnerabilities.extend(pattern_vulns)

            # 2. Analyze ViewState (.NET)
            self._update_progress(progress_callback, 40, "Analyzing ViewState")
            viewstate_vulns = await self._analyze_viewstate(html, url)
            vulnerabilities.extend(viewstate_vulns)

            # 3. Check cookies for serialized data
            self._update_progress(progress_callback, 55, "Checking cookies")
            cookie_vulns = self._check_cookies_for_serialization(response)
            vulnerabilities.extend(cookie_vulns)

            # 4. Test parameters for deserialization
            self._update_progress(progress_callback, 70, "Testing parameters")
            param_vulns = await self._test_deserialization_params(url)
            vulnerabilities.extend(param_vulns)

            # 5. Check for known gadget chains
            self._update_progress(progress_callback, 90, "Identifying gadget chains")
            gadget_vulns = self._identify_gadget_chains(html)
            vulnerabilities.extend(gadget_vulns)

            self._update_progress(progress_callback, 100, "completed")

            status = "Vulnerable" if vulnerabilities else "Secure"
            details = f"Found {len(vulnerabilities)} potential deserialization issues."
            return self._format_result(status, details, vulnerabilities)

        except Exception as e:
            logger.exception(f"Deserialization scan failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])

    def _detect_serialization_patterns(self, content: str, headers: dict) -> list[Vulnerability]:
        """Detect serialization signatures in response."""
        findings = []

        for lang, sig in self.signatures.items():
            # Check magic bytes (as strings for content)
            for magic in sig["magic"]:
                magic_str = magic if isinstance(magic, str) else magic.decode("latin-1", errors="ignore")
                if magic_str in content:
                    findings.append(
                        self._create_vulnerability(
                            title=f"Serialization Signature Detected: {lang.upper()}",
                            description=f"Found {sig['description']} signature in response. This may indicate serialized data is transmitted.",
                            severity="medium",
                            type=f"deserialization_{lang}",
                            evidence={"signature": magic_str[:20], "language": lang},
                            cwe_id="CWE-502",
                            remediation=f"Avoid {sig['description']} for untrusted data. Use safe alternatives like JSON.",
                        )
                    )
                    break

            # Check patterns
            for pattern in sig["patterns"]:
                if pattern.lower() in content.lower():
                    findings.append(
                        self._create_vulnerability(
                            title=f"Deserialization Pattern: {lang.upper()}",
                            description=f"Found {pattern} pattern suggesting {sig['description']} usage.",
                            severity="low",
                            type=f"deserialization_pattern_{lang}",
                            evidence={"pattern": pattern, "language": lang},
                            cwe_id="CWE-502",
                            remediation="Review deserialization usage and implement secure patterns.",
                        )
                    )
                    break

        return findings

    async def _analyze_viewstate(self, html: str, url: str) -> list[Vulnerability]:
        """Analyze .NET ViewState for vulnerabilities."""
        findings = []

        # Find ViewState
        viewstate_match = re.search(r'name="__VIEWSTATE"[^>]*value="([^"]+)"', html)
        if not viewstate_match:
            return findings

        viewstate = viewstate_match.group(1)

        try:
            # Try to decode
            decoded = base64.b64decode(viewstate)

            # Check for MAC (Message Authentication Code)
            # MAC-protected ViewState typically has a longer signature at the end
            if len(decoded) < 20:
                findings.append(
                    self._create_vulnerability(
                        title="Weak ViewState Detected",
                        description="ViewState appears unprotected or weakly protected.",
                        severity="medium",
                        type="viewstate_weak",
                        evidence={"viewstate_length": len(viewstate)},
                        cwe_id="CWE-502",
                        remediation="Enable ViewState MAC validation and encryption.",
                    )
                )

            # Check for common serialization markers
            decoded_str = decoded.decode("latin-1", errors="ignore")
            if "System." in decoded_str or "Type" in decoded_str:
                findings.append(
                    self._create_vulnerability(
                        title="ViewState Contains .NET Object Data",
                        description="ViewState contains serialized .NET objects which could be vulnerable to deserialization attacks.",
                        severity="high",
                        type="viewstate_object",
                        evidence={"preview": decoded_str[:100]},
                        cwe_id="CWE-502",
                        remediation="Ensure ViewState is encrypted and MAC protected. Consider using ViewStateUserKey.",
                    )
                )

        except Exception as e:
            logger.debug(f"ViewState decode error: {e}")

        return findings

    def _check_cookies_for_serialization(self, response) -> list[Vulnerability]:
        """Check cookies for serialized data."""
        findings = []

        if not hasattr(response, "cookies"):
            return findings

        for name, cookie in response.cookies.items():
            value = str(cookie)

            # Check for Base64-encoded serialized data
            if len(value) > 50 and self._is_likely_serialized(value):
                findings.append(
                    self._create_vulnerability(
                        title=f"Potentially Serialized Cookie: {name}",
                        description=f"Cookie '{name}' appears to contain serialized object data.",
                        severity="medium",
                        type="cookie_serialization",
                        evidence={"cookie_name": name, "preview": value[:50]},
                        cwe_id="CWE-502",
                        remediation="Avoid storing serialized objects in cookies. Use signed tokens or server-side sessions.",
                    )
                )

        return findings

    def _is_likely_serialized(self, value: str) -> bool:
        """Check if value looks like serialized data."""
        # Check for common serialization markers
        markers = ["rO0", "O:", "a:", "gASV", "AAEAAAD", "BAh"]
        return any(m in value for m in markers)

    async def _test_deserialization_params(self, url: str) -> list[Vulnerability]:
        """Test parameters for deserialization vulnerabilities."""
        findings = []

        # Test with malformed serialized data
        test_payloads = [
            ('O:8:"stdClass":0:{}', "php"),
            ("rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==", "java"),
            ("gASVDAAAAAAAAACMBHRlc3SJAAAA", "python"),
        ]

        for param in self.target_params[:5]:
            for payload, lang in test_payloads:
                try:
                    response = await self._test_payload(url, param, payload, "POST")

                    if response:
                        content = response.get("page_content", "").lower()

                        # Check for error messages indicating processing
                        error_indicators = [
                            "unserialize",
                            "deserialize",
                            "invalid stream",
                            "class not found",
                            "objectinputstream",
                            "pickle",
                            "marshal",
                            "yaml",
                            "unexpected end",
                        ]

                        for indicator in error_indicators:
                            if indicator in content:
                                findings.append(
                                    self._create_vulnerability(
                                        title=f"Deserialization Processing Detected: {param}",
                                        description=f"Parameter '{param}' appears to process {lang} serialized data.",
                                        severity="high",
                                        type=f"deserialization_param_{lang}",
                                        evidence={"param": param, "indicator": indicator},
                                        cwe_id="CWE-502",
                                        remediation="Never deserialize untrusted user input.",
                                    )
                                )
                                return findings  # Found one, stop

                except Exception as e:
                    logger.debug(f"Param test error: {e}")

        return findings

    def _identify_gadget_chains(self, content: str) -> list[Vulnerability]:
        """Identify potential gadget chain classes."""
        findings = []

        # Known gadget chain classes
        gadget_classes = {
            "java": [
                "org.apache.commons.collections",
                "org.apache.xalan",
                "com.sun.org.apache.xalan",
                "org.springframework",
                "com.mchange.v2.c3p0",
                "org.hibernate",
            ],
            "php": ["Monolog", "Guzzle", "Symfony", "Laravel", "phpggc", "Doctrine"],
            "python": ["yaml.load", "pickle.loads", "marshal.loads", "jsonpickle", "shelve"],
        }

        for lang, classes in gadget_classes.items():
            for class_name in classes:
                if class_name.lower() in content.lower():
                    findings.append(
                        self._create_vulnerability(
                            title=f"Potential Gadget Chain: {class_name}",
                            description=f"Found reference to {class_name} which is commonly used in {lang} deserialization exploits.",
                            severity="info",
                            type="gadget_chain",
                            evidence={"class": class_name, "language": lang},
                            cwe_id="CWE-502",
                            remediation="Audit usage of this library and ensure safe deserialization practices.",
                        )
                    )

        return findings
