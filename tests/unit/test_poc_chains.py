import sys
from unittest.mock import MagicMock

# Mock dependencies
sys.modules["aiohttp"] = MagicMock()
sys.modules["aiohttp.ClientSession"] = MagicMock()

import os
import unittest

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from src.reporting.poc_generator import PoCGenerator


class TestPoCGenerator(unittest.TestCase):

    def test_cloud_takeover_poc(self):
        generator = PoCGenerator()
        vuln = {
            "title": "Cloud Infrastructure Takeover via SSRF",
            "type": "chain:cloud",
            "severity": "critical",
            "evidence": {"url": "http://example.com", "parameter": "url", "payload": "http://169.254.169.254"},
        }

        poc = generator.generate_poc(vuln)

        self.assertIn("verify_cloud_ssrf", poc["python"])
        self.assertIn("http://169.254.169.254", poc["python"])
        self.assertIn("instance-id", poc["python"])

    def test_account_takeover_poc(self):
        generator = PoCGenerator()
        vuln = {
            "title": "Account Takeover via XSS",
            "type": "chain:account takeover",
            "severity": "critical",
            "evidence": {
                "url": "http://example.com",
                "parameter": "q",
                "payload": "<script>alert(1)</script>",
                "data": {"vulnerable_cookies": ["session_id", "auth_token"]},
            },
        }

        poc = generator.generate_poc(vuln)

        self.assertIn("CookieStealer", poc["python"])
        self.assertIn("session_id", poc["python"])
        self.assertIn("PORT = 8888", poc["python"])

    def test_config_leak_poc(self):
        generator = PoCGenerator()
        vuln = {
            "title": "Critical Credential Leak",
            "type": "chain:config",
            "severity": "critical",
            "evidence": {
                "url": "http://example.com/.env",
            },
        }

        poc = generator.generate_poc(vuln)

        self.assertIn("verify_leak", poc["python"])
        self.assertIn(".env", poc["python"] or "http://example.com/.env")
        self.assertIn("aws sts", poc["python"])


if __name__ == "__main__":
    unittest.main()
