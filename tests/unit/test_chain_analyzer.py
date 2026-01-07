import sys
from unittest.mock import MagicMock

# Mock missing dependencies to allow testing logic in isolation
sys.modules["aiohttp"] = MagicMock()
sys.modules["aiohttp.ClientSession"] = MagicMock()

# Add project root to path
import os

# Now we can import our modules
import unittest

# We need to make sure we can import from src without triggering the whole app initialization if possible
# But src/__init__.py imports ScannerEngine which imports HTTPClient -> aiohttp.
# By mocking aiohttp above, the import should proceed.


sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from src.core.chain_analyzer import ChainAnalyzer


class TestChainAnalyzer(unittest.TestCase):

    def test_config_credential_chain(self):
        """Test detection of Config File -> Credential Leak chain."""
        analyzer = ChainAnalyzer()

        # Mock vulnerability data
        mock_vulns = [
            {
                "title": "Exposed Environment File",
                "description": "Found .env file",
                "severity": "critical",
                "type": "misconfig",
                "evidence": {
                    "url": "http://example.com/.env",
                    "snippet": "DB_HOST=localhost\nAWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\nDEBUG=true",
                },
            }
        ]

        mock_results = [{"vulnerabilities": mock_vulns}]

        chains = analyzer.analyze(mock_results)

        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0].risk_level, "critical")
        self.assertTrue("Cloud Infrastructure" in chains[0].description or "Credential Leak" in chains[0].title)
        self.assertTrue("AWS Access Key" in chains[0].description)

    def test_ssrf_cloud_chain(self):
        """Test detection of SSRF -> Cloud Metadata chain."""
        analyzer = ChainAnalyzer()

        mock_vulns = [
            {
                "title": "Potential SSRF Detected (AWS)",
                "severity": "critical",
                "type": "ssrf",
                "evidence": {"parameter": "url", "payload": "http://169.254.169.254", "match": "aws"},
            }
        ]

        mock_results = [{"vulnerabilities": mock_vulns}]

        chains = analyzer.analyze(mock_results)

        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0].risk_level, "critical")
        self.assertIn("Cloud Infrastructure Takeover", chains[0].title)
        self.assertIn("AWS", chains[0].title)

    def test_xss_session_hijacking_chain(self):
        """Test detection of XSS -> Session Hijacking chain."""
        analyzer = ChainAnalyzer()

        mock_vulns = [
            {
                "title": "Reflected XSS in Parameter q",
                "severity": "high",
                "type": "xss",
                "evidence": {"parameter": "q", "payload": "<script>alert(1)</script>"},
            },
            {
                "title": "Insecure Cookie Flags: session_id",
                "severity": "medium",
                "type": "insecure_cookie",
                "evidence": {"cookie": "session_id=123", "missing": ["HttpOnly", "Secure"]},
            },
        ]

        mock_results = [{"vulnerabilities": mock_vulns}]

        chains = analyzer.analyze(mock_results)

        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0].risk_level, "critical")
        self.assertIn("Account Takeover", chains[0].title)
        self.assertIn("Insecure Cookie", chains[0].title)

    def test_no_chain(self):
        """Test that unrelated vulnerabilities do not trigger a chain."""
        analyzer = ChainAnalyzer()

        mock_vulns = [
            {
                "title": "XSS Found",
                "severity": "high",
                "type": "xss",
                "evidence": {"payload": "<script>alert(1)</script>"},
            }
        ]

        mock_results = [{"vulnerabilities": mock_vulns}]

        chains = analyzer.analyze(mock_results)

        self.assertEqual(len(chains), 0)


if __name__ == "__main__":
    unittest.main()
