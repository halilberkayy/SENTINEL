"""
Wordlist Builder - Target-based custom wordlist generation.
Similar to CeWL but integrated into SENTINEL.
"""

import logging
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class WordlistBuilder(BaseScanner):
    """Custom wordlist generation from target content."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "WordlistBuilder"
        self.description = "Target-based wordlist generation"
        self.version = "1.0.0"
        self.capabilities = ["Content Extraction", "Word Generation", "Custom Wordlists"]

        self.min_word_length = 4
        self.max_word_length = 20
        self.common_words = {
            "the",
            "and",
            "for",
            "are",
            "but",
            "not",
            "you",
            "all",
            "can",
            "had",
            "her",
            "was",
            "one",
            "our",
            "out",
        }

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Generate wordlist from target."""
        self._update_progress(progress_callback, 10, "Fetching content")

        try:
            words = set()
            emails = set()
            usernames = set()

            # Fetch main page
            response = await self.http_client.get(url)
            if response and response.status == 200:
                content = await response.text()

                # Extract words
                text_words = re.findall(r"\b[a-zA-Z]{%d,%d}\b" % (self.min_word_length, self.max_word_length), content)
                words.update(w.lower() for w in text_words if w.lower() not in self.common_words)

                # Extract emails
                emails.update(re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", content))

                # Extract usernames from emails
                for email in emails:
                    usernames.add(email.split("@")[0])

            self._update_progress(progress_callback, 50, f"Extracted {len(words)} words")

            # Generate variations
            variations = self._generate_variations(words)

            # Combine all
            final_wordlist = list(words | variations | usernames)
            final_wordlist.sort()

            # Save wordlist
            output_path = Path("output/wordlists")
            output_path.mkdir(parents=True, exist_ok=True)

            parsed = urlparse(url)
            filename = f"{parsed.hostname}_wordlist.txt"
            filepath = output_path / filename

            filepath.write_text("\n".join(final_wordlist))

            self._update_progress(progress_callback, 100, "completed")

            return self._format_result(
                "Completed",
                f"Generated {len(final_wordlist)} words",
                [],
                evidence={
                    "wordlist_path": str(filepath),
                    "total_words": len(final_wordlist),
                    "emails_found": list(emails)[:10],
                    "sample": final_wordlist[:20],
                },
            )

        except Exception as e:
            return self._format_result("Error", str(e), [])

    def _generate_variations(self, words: set) -> set:
        """Generate password variations."""
        variations = set()

        common_suffixes = ["123", "!", "1", "2024", "2025", "@", "#", "1!"]

        for word in list(words)[:100]:  # Limit base words
            # Capitalize
            variations.add(word.capitalize())
            variations.add(word.upper())

            # Add suffixes
            for suffix in common_suffixes:
                variations.add(word + suffix)
                variations.add(word.capitalize() + suffix)

            # Leet speak basic
            leet = word.replace("a", "4").replace("e", "3").replace("i", "1").replace("o", "0")
            if leet != word:
                variations.add(leet)

        return variations
