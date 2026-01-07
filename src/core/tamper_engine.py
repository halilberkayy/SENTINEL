"""
Tamper Engine for Advanced WAF Evasion and Payload Obfuscation.
Part of the Red Team capabilities.
"""

import random
import urllib.parse
from collections.abc import Callable


class TamperEngine:
    """
    Engine to apply various obfuscation techniques to payloads.
    Used to bypass WAFs and filters.
    """

    @staticmethod
    def random_case(payload: str) -> str:
        """
        Randomizes character case.
        Example: SELECT -> SeLeCT
        """
        return "".join(choice.lower() if random.random() > 0.5 else choice.upper() for choice in payload)

    @staticmethod
    def url_encode(payload: str) -> str:
        """
        Standard URL encoding.
        """
        return urllib.parse.quote(payload)

    @staticmethod
    def double_url_encode(payload: str) -> str:
        """
        Double URL encoding.
        """
        return urllib.parse.quote(urllib.parse.quote(payload))

    @staticmethod
    def space_to_comment(payload: str) -> str:
        """
        Replaces spaces with inline SQL comments.
        Example: SELECT 1 -> SELECT/**/1
        """
        return payload.replace(" ", "/**/")

    @staticmethod
    def space_to_plus(payload: str) -> str:
        """
        Replaces spaces with plus signs.
        """
        return payload.replace(" ", "+")

    @staticmethod
    def null_byte_injection(payload: str) -> str:
        """
        Appends a null byte to the payload.
        """
        return f"{payload}%00"

    @staticmethod
    def between_operator(payload: str) -> str:
        """
        Replaces > or < with BETWEEN logic if applicable.
        (Simple heuristic replacement)
        """
        if ">" in payload:
            return payload.replace(">", " NOT BETWEEN 0 AND ")
        if "=" in payload:
            return payload.replace("=", " LIKE ")
        return payload

    @staticmethod
    def comment_garbage(payload: str) -> str:
        """
        Injects random garbage comments.
        Example: UNION SELECT -> UNION/*!50000SELECT*/
        """
        return payload.replace("SELECT", "/*!50000SELECT*/").replace("UNION", "/*!50000UNION*/")

    @staticmethod
    def get_techniques() -> list[Callable]:
        """Returns a list of all available tamper functions."""
        return [
            TamperEngine.random_case,
            TamperEngine.space_to_comment,
            TamperEngine.comment_garbage,
            TamperEngine.double_url_encode,
            # Add more selective ones manually if needed
        ]

    def tamper(self, payload: str, level: str = "standard") -> list[str]:
        """
        Generates multiple tampered versions of a single payload.
        """
        tampered = set()

        # Always include original
        tampered.add(payload)

        # Standard: Random Case, Space to Comment
        if level in ["standard", "aggressive"]:
            tampered.add(self.random_case(payload))
            tampered.add(self.space_to_comment(payload))

        # Aggressive: Garbage comments, Double Encoding, Null Byte
        if level == "aggressive":
            tampered.add(self.comment_garbage(payload))
            tampered.add(self.double_url_encode(payload))
            tampered.add(self.null_byte_injection(payload))

            # Combined techniques (e.g., Random Case + Space to Comment)
            mixed = self.space_to_comment(self.random_case(payload))
            tampered.add(mixed)

        return list(tampered)
