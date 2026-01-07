"""
Payload Manager & Attack Guide Module.
Responsible for loading, categorizing, and guiding the user on how to use specific attack payloads.
"""

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class PayloadManager:
    """Manages the attack payload library and provides usage guidance."""

    def __init__(self, library_path: str = "src/data/payloads/attack_library.json"):
        self.library_path = library_path
        self.payloads = self._load_library()

    def _load_library(self) -> list[dict[str, Any]]:
        """Loads the payload database from JSON."""
        try:
            path = Path(self.library_path)
            if not path.exists():
                logger.warning(f"Payload library not found at {path}. using empty list.")
                return []

            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load payload library: {e}")
            return []

    def get_payloads_by_category(self, category: str) -> list[dict[str, Any]]:
        """Returns all payloads matching a category (e.g., XSS, SQLi)."""
        return [p for p in self.payloads if p.get("category", "").lower() == category.lower()]

    def get_attack_guide(self, payload_id: str) -> dict[str, str] | None:
        """Returns detailed manual for a specific payload execution."""
        for p in self.payloads:
            if p.get("id") == payload_id:
                return {
                    "Title": p["name"],
                    "Risk": p["risk"],
                    "Payload": p["payload"],
                    "Target Params": ", ".join(p.get("target_parameters", [])),
                    "Execution Guide": p.get("usage_guide", "No guide available."),
                    "Evasion Tips": ", ".join(p.get("evasion_techniques", [])),
                }
        return None

    def suggest_payloads_for_url(self, url: str) -> list[dict[str, Any]]:
        """Smartly suggests payloads based on URL parameters."""
        suggestions = []
        # Simple heuristic: matches common param names
        for p in self.payloads:
            for target in p.get("target_parameters", []):
                if f"{target}=" in url:
                    suggestions.append(p)
                    break
        return suggestions
