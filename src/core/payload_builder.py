"""
Payload Builder with encoder/obfuscator chains.
Extends the existing PayloadManager and TamperEngine with systematic encoding capabilities.
"""

import base64
import html
import logging
import random
import urllib.parse
from typing import Any

logger = logging.getLogger(__name__)


class PayloadBuilder:
    """
    Build payloads with chained encoders/obfuscators.
    Encoders are applied sequentially in the order specified.
    """

    ENCODERS = {
        "base64": "Standard base64 encoding",
        "hex": "Hex encoding (\\x41 format)",
        "url_encode": "Standard URL encoding",
        "double_url_encode": "Double URL encoding",
        "html_entities": "HTML entity encoding (&#x41; format)",
        "unicode": "Unicode encoding (\\u0041 format)",
        "utf7": "UTF-7 encoding",
        "random_case": "Randomize character case",
    }

    def build(self, payload: str, encoders: list[str]) -> str:
        """Apply a chain of encoders to a payload."""
        result = payload
        for encoder in encoders:
            encoder_fn = getattr(self, f"_encode_{encoder}", None)
            if encoder_fn is None:
                logger.warning(f"Unknown encoder: {encoder}, skipping")
                continue
            result = encoder_fn(result)
        return result

    @staticmethod
    def _encode_base64(payload: str) -> str:
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def _encode_hex(payload: str) -> str:
        return "".join(f"\\x{ord(c):02x}" for c in payload)

    @staticmethod
    def _encode_url_encode(payload: str) -> str:
        return urllib.parse.quote(payload, safe="")

    @staticmethod
    def _encode_double_url_encode(payload: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")

    @staticmethod
    def _encode_html_entities(payload: str) -> str:
        return "".join(f"&#x{ord(c):x};" for c in payload)

    @staticmethod
    def _encode_unicode(payload: str) -> str:
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    @staticmethod
    def _encode_utf7(payload: str) -> str:
        try:
            return payload.encode("utf-7").decode("ascii")
        except (UnicodeDecodeError, UnicodeEncodeError):
            return payload

    @staticmethod
    def _encode_random_case(payload: str) -> str:
        return "".join(
            c.upper() if random.random() > 0.5 else c.lower() for c in payload
        )

    def get_encoders(self) -> list[dict[str, str]]:
        """List available encoders with descriptions."""
        return [{"name": k, "description": v} for k, v in self.ENCODERS.items()]
