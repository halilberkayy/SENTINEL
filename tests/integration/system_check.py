# System Check Imports
import sys
import unittest
from pathlib import Path

# Add src to pythonpath correctly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from src.core.config import Config
from src.core.scanner_engine import ScannerEngine

# Import all modules explicitly to verify they load
from src.modules.recon_scanner import ReconScanner
from src.reporting.poc_generator import PoCGenerator


class TestSystemIntegration(unittest.TestCase):
    """
    Validation Test Suite to confirm all components are integrated and loadable.
    This does NOT perform actual network attacks (safe for CI/Test),
    but verifies the engine can assemble the Red Team arsenal independently.
    """

    def setUp(self):
        self.config = Config()
        # Enable all aggressive features for testing validation
        self.config.scanner.enable_waf_bypass = True
        self.engine = ScannerEngine(self.config)

    def test_module_registry(self):
        """Verify all critical Red Team modules are registered in the engine."""
        expected_modules = [
            "recon_scanner",
            "xss_scanner",
            "sqli_scanner",
            "lfi_scanner",
            "ssrf_scanner",
            "cmd_injection",
            "misconfig",
            "xxe_scanner",
            "ssti_scanner",
            "deserialization",
            "graphql_scanner",
            "jwt_scanner",
            "api_scanner",
            "auth_scanner",
            "cors_scanner",
            "csrf_scanner",
            "open_redirect",
            "proto_pollution",
            "subdomain_scanner",
            "webshell_scanner",
            "robots_scanner",
            "ssi_scanner",
            "js_secrets_scanner",
            "port_scanner",
        ]

        registered_modules = list(self.engine.modules.keys())
        print(f"\n[SYSTEM CHECK] Active Modules: {len(registered_modules)}")

        for mod in expected_modules:
            self.assertIn(mod, registered_modules, f"Critical module '{mod}' is missing from the engine!")
            print(f"  [+] Module '{mod}' .... OK")

    def test_recon_scanner_integration(self):
        """Verify the new ReconScanner is correctly instantiated."""
        recon = self.engine.modules.get("recon_scanner")
        self.assertIsInstance(recon, ReconScanner)
        self.assertTrue(hasattr(recon, "scan"), "ReconScanner missing 'scan' method")
        print("  [+] ReconScanner Integration .... OK")

    def test_nuclei_template_generation(self):
        """Verify Nuclei PoC generation works."""
        generator = PoCGenerator()

        mock_vuln = {
            "title": "Test SQLi",
            "type": "sqli",
            "severity": "critical",
            "evidence": {"url": "http://target.com/vuln.php", "parameter": "id", "payload": "' OR 1=1 --"},
        }

        # Access the private method for testing or use the public interface if exposed
        # Since _generate_nuclei_template is internal, we use the public generate_poc
        pocs = generator.generate_poc(mock_vuln)

        self.assertIn("nuclei", pocs, "Nuclei template missing from PoC outputs")
        self.assertIn("id: sentinel-generated", pocs["nuclei"], "Invalid Nuclei template structure")
        self.assertIn("matchers:", pocs["nuclei"], "Nuclei template missing matchers")

        print("  [+] Nuclei Generator .... OK")

    def test_legacy_poc_formats(self):
        """Verify Python/Curl/Burp formats still work."""
        generator = PoCGenerator()
        mock_vuln = {"title": "Test XSS", "type": "xss", "evidence": {"url": "http://x.com", "payload": "<script>"}}
        pocs = generator.generate_poc(mock_vuln)

        self.assertIn("python", pocs)
        self.assertIn("curl", pocs)
        self.assertIn("burp_request", pocs)
        print("  [+] Legacy PoC Formats .... OK")


if __name__ == "__main__":
    print("=" * 60)
    print("SENTINEL :: SYSTEM INTEGRATION DIAGNOSTIC")
    print("=" * 60)
    unittest.main()
