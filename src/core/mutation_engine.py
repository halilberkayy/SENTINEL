"""
Payload Mutation Engine for WAF bypass and evasion testing.
Extends the existing TamperEngine with additional mutation techniques
and systematic variation generation.
"""

import logging
import random
from typing import Any

from .tamper_engine import TamperEngine

logger = logging.getLogger(__name__)


class MutationEngine:
    """
    Generate payload mutations using various evasion techniques.
    Builds on existing TamperEngine methods and adds new ones.
    """

    MUTATIONS = {
        # Existing (from TamperEngine)
        "random_case": "Randomize character casing",
        "url_encode": "Standard URL encoding",
        "double_url_encode": "Double URL encoding",
        "space_to_comment": "Replace spaces with SQL comments /**/",
        "space_to_plus": "Replace spaces with plus signs",
        "null_byte_injection": "Append null byte (%00)",
        "between_operator": "Replace operators with BETWEEN/LIKE",
        "comment_garbage": "Inject version-specific MySQL comments",
        # New mutations
        "concat_split": "Split strings with concatenation operators",
        "char_encoding": "Replace characters with CHAR() functions",
        "whitespace_variation": "Use tabs, newlines, carriage returns instead of spaces",
        "case_swap": "Swap keyword casing patterns (alternating)",
    }

    def __init__(self) -> None:
        self._tamper = TamperEngine()

    def mutate(self, payload: str, mutations: list[str], count: int = 10) -> list[dict[str, Any]]:
        """
        Generate multiple payload mutations.

        Args:
            payload: Original payload string
            mutations: List of mutation technique names to apply
            count: Number of unique mutations to generate

        Returns:
            List of {"payload": str, "applied": list[str]} dicts
        """
        results = []
        seen = set()

        for _ in range(count * 3):  # Over-generate to account for duplicates
            if len(results) >= count:
                break

            # Apply a random subset of requested mutations
            num_to_apply = random.randint(1, len(mutations))
            selected = random.sample(mutations, num_to_apply)

            mutated = payload
            applied = []
            for mutation in selected:
                mutated = self._apply_mutation(mutated, mutation)
                applied.append(mutation)

            if mutated not in seen and mutated != payload:
                seen.add(mutated)
                results.append({"payload": mutated, "applied": applied})

        # If we still need more, apply all mutations at once
        if len(results) < count:
            mutated = payload
            for mutation in mutations:
                mutated = self._apply_mutation(mutated, mutation)
            if mutated not in seen:
                results.append({"payload": mutated, "applied": mutations})

        return results[:count]

    def _apply_mutation(self, payload: str, mutation: str) -> str:
        """Apply a single mutation technique."""
        # Existing TamperEngine methods
        tamper_map = {
            "random_case": self._tamper.random_case,
            "url_encode": self._tamper.url_encode,
            "double_url_encode": self._tamper.double_url_encode,
            "space_to_comment": self._tamper.space_to_comment,
            "space_to_plus": self._tamper.space_to_plus,
            "null_byte_injection": self._tamper.null_byte_injection,
            "between_operator": self._tamper.between_operator,
            "comment_garbage": self._tamper.comment_garbage,
        }

        # New mutation methods
        new_map = {
            "concat_split": self._concat_split,
            "char_encoding": self._char_encoding,
            "whitespace_variation": self._whitespace_variation,
            "case_swap": self._case_swap,
        }

        fn = tamper_map.get(mutation) or new_map.get(mutation)
        if fn is None:
            logger.warning(f"Unknown mutation: {mutation}, returning payload unchanged")
            return payload
        return fn(payload)

    @staticmethod
    def _concat_split(payload: str) -> str:
        """Split string literals with concatenation."""
        # For SQL: 'admin' -> 'adm'+'in'
        # For JS: "alert" -> "al"+"ert"
        if "'" in payload:
            parts = payload.split("'")
            result_parts = []
            for i, part in enumerate(parts):
                if i % 2 == 1 and len(part) > 2:  # Inside quotes
                    mid = len(part) // 2
                    result_parts.append(f"'{part[:mid]}'||'{part[mid:]}'")
                else:
                    result_parts.append(f"'{part}'" if i % 2 == 1 else part)
            return "".join(result_parts)
        return payload

    @staticmethod
    def _char_encoding(payload: str) -> str:
        """Replace some characters with CHAR() function calls."""
        # Replace a few random characters with CHAR() equivalents
        chars_to_replace = random.sample(
            range(len(payload)), min(3, len(payload))
        )
        result = list(payload)
        for idx in chars_to_replace:
            c = payload[idx]
            if c.isalpha():
                result[idx] = f"CHAR({ord(c)})"
        return "".join(result)

    @staticmethod
    def _whitespace_variation(payload: str) -> str:
        """Replace spaces with various whitespace characters."""
        whitespace_chars = ["\t", "\n", "\r\n", "\x0b", "\x0c"]
        result = ""
        for c in payload:
            if c == " ":
                result += random.choice(whitespace_chars)
            else:
                result += c
        return result

    @staticmethod
    def _case_swap(payload: str) -> str:
        """Alternating case pattern for keywords."""
        result = ""
        upper = True
        for c in payload:
            if c.isalpha():
                result += c.upper() if upper else c.lower()
                upper = not upper
            else:
                result += c
        return result

    def get_mutations(self) -> list[dict[str, str]]:
        """List available mutation techniques with descriptions."""
        return [{"name": k, "description": v} for k, v in self.MUTATIONS.items()]
