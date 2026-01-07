import sys
from unittest.mock import MagicMock

# Mock dependencies
sys.modules["aiohttp"] = MagicMock()
sys.modules["aiohttp.ClientSession"] = MagicMock()

import os
import unittest

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from src.reporting.smart_summary import SmartSummaryGenerator


class TestSmartSummaryGenerator(unittest.TestCase):

    def test_no_chains(self):
        generator = SmartSummaryGenerator()
        result = generator.generate_executive_narrative([])

        self.assertEqual(result["title"], "Security Posture Summary")
        self.assertIn("resilient", result["narrative"])

    def test_critical_chain_cloud(self):
        generator = SmartSummaryGenerator()
        chains = [
            {
                "title": "Cloud Infrastructure Takeover via SSRF",
                "description": "Allows full control of cloud.",
                "severity": "critical",
            }
        ]

        result = generator.generate_executive_narrative(chains)

        self.assertIn("CRITICAL SECURITY ALERT", result["narrative"])
        self.assertIn("Complete loss of cloud environment control", result["narrative"])
        self.assertIn("$100,000", result["narrative"])
        self.assertIn("IMMEDIATE ACTION REQUIRED", result["title"])

    def test_multiple_chains(self):
        generator = SmartSummaryGenerator()
        chains = [
            {"title": "Cloud Infrastructure Takeover", "severity": "critical"},
            {"title": "Account Takeover via XSS", "severity": "critical"},
        ]

        result = generator.generate_executive_narrative(chains)

        # Check if both risks are mentioned
        self.assertIn("Complete loss of cloud environment control", result["narrative"])
        self.assertIn("Compromise of user accounts", result["narrative"])
        self.assertIn("2 Verifyable Attack Paths Detected", result["narrative"])


if __name__ == "__main__":
    unittest.main()
