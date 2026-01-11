"""
Basic tests for the vulnerability scanner.
"""

from unittest.mock import AsyncMock, Mock

import pytest

from src.core.config import Config
from src.core.scanner_engine import ScannerEngine
from src.modules.sqli_scanner import SQLIScanner
from src.modules.xss_scanner import XSSScanner


@pytest.fixture
def mock_config():
    """Create a mock configuration."""
    config = Mock(spec=Config)

    # Mock network config
    network_config = Mock()
    network_config.timeout = 30
    network_config.verify_ssl = True
    network_config.rate_limit = 1.0
    config.network = network_config

    # Mock scanner config
    scanner_config = Mock()
    scanner_config.concurrent_requests = 10
    scanner_config.max_payloads_per_module = 100
    config.scanner = scanner_config

    # Mock other configs
    output_config = Mock()
    output_config.report_dir = "output/reports"
    config.output = output_config

    logging_config = Mock()
    logging_config.level = "INFO"
    config.logging = logging_config

    security_config = Mock()
    security_config.require_consent = True
    config.security = security_config

    config.validate_target.return_value = True
    return config


@pytest.fixture
def mock_http_client():
    """Create a mock HTTP client."""
    client = Mock()
    client.get = AsyncMock()
    client.post = AsyncMock()
    client.head = AsyncMock()
    client.get_stats.return_value = {"total_requests": 0, "error_count": 0, "success_rate": 100.0}
    return client


def test_config_initialization():
    """Test configuration initialization."""
    config = Config()
    assert config.network.timeout == 30
    assert config.network.verify_ssl is True
    assert config.scanner.concurrent_requests == 10


def test_xss_scanner_initialization(mock_config, mock_http_client):
    """Test XSS scanner initialization."""
    scanner = XSSScanner(mock_config, mock_http_client)
    assert scanner.name == "XSSScanner"
    assert "XSS" in scanner.description  # Check if XSS is mentioned in description
    assert len(scanner.capabilities) > 0


def test_sqli_scanner_initialization(mock_config, mock_http_client):
    """Test SQL injection scanner initialization."""
    scanner = SQLIScanner(mock_config, mock_http_client)
    assert scanner.name == "SQLIScanner"
    assert "SQL" in scanner.description  # Check if SQL is mentioned in description
    assert len(scanner.capabilities) > 0


def test_url_validation():
    """Test URL validation."""
    config = Config()

    # Valid URLs
    assert config.validate_target("https://example.com") is True
    assert config.validate_target("http://test.com/path") is True

    # Invalid URLs
    assert config.validate_target("not-a-url") is False
    assert config.validate_target("") is False
    assert config.validate_target("invalid") is False


def test_payload_database():
    """Test payload database loading."""
    from src.payloads.sqli_payloads import SQLIPayloads
    from src.payloads.xss_payloads import XSSPayloads

    xss_payloads = XSSPayloads()
    sqli_payloads = SQLIPayloads()

    assert xss_payloads.get_payload_count() > 0
    assert sqli_payloads.get_payload_count() > 0

    # Test getting payloads by severity (updated API)
    high_xss = xss_payloads.get_payloads_by_severity("high")
    assert len(high_xss) > 0

    # Test getting all payloads for SQLi
    all_sqli = sqli_payloads.get_all_payloads()
    assert len(all_sqli) > 0


def test_wordlist_loading():
    """Test wordlist loading."""
    from src.payloads.wordlists import Wordlists

    wordlists = Wordlists()
    # Test getting directories
    dirs = wordlists.get_directories(limit=10)
    assert len(dirs) > 0

    # Test getting subdomains
    subs = wordlists.get_subdomains(limit=10)
    assert len(subs) > 0


@pytest.mark.asyncio
async def test_scanner_engine_initialization(mock_config):
    """Test scanner engine initialization."""
    engine = ScannerEngine(mock_config)
    assert len(engine.modules) > 0
    assert "xss_scanner" in engine.modules
    assert "sqli_scanner" in engine.modules


def test_vulnerability_creation():
    """Test vulnerability object creation."""
    from src.modules.base_scanner import Vulnerability

    vuln = Vulnerability(
        title="Test Vulnerability",
        description="Test description",
        severity="high",
        type="test",
        evidence={"test": "data"},
        cwe_id="CWE-79",
        cvss_score=7.5,
    )

    assert vuln.title == "Test Vulnerability"
    assert vuln.severity == "high"
    assert vuln.cwe_id == "CWE-79"
    assert vuln.cvss_score == 7.5


def test_base_scanner_methods(mock_config, mock_http_client):
    """Test base scanner methods."""
    from src.modules.base_scanner import BaseScanner

    class TestScanner(BaseScanner):
        async def scan(self, url, progress_callback=None):
            return self._format_result("Test", "Test scan", [], {})

    scanner = TestScanner(mock_config, mock_http_client)

    # Test vulnerability creation
    vuln = scanner._create_vulnerability(title="Test", description="Test", severity="high", type="test", evidence={})
    assert vuln.title == "Test"
    assert vuln.severity == "high"

    # Test result formatting
    result = scanner._format_result("Completed", "Test completed", [], {})
    assert result["status"] == "Completed"
    assert "risk_level" in result


def test_reporting_system():
    """Test the reporting system."""
    from src.reporting.formatters import HTMLFormatter, JSONFormatter, TXTFormatter
    from src.reporting.templates import ReportTemplateManager

    # Test data
    test_scan_data = {
        "url": "https://example.com",
        "timestamp": "2025-01-01 12:00:00",
        "scan_type": "Test Scan",
        "modules": ["xss", "sqli"],
        "results": [
            {
                "module": "XSS Scanner",
                "status": "Completed",
                "details": "Found 2 XSS vulnerabilities",
                "vulnerabilities": [
                    {
                        "title": "Reflected XSS",
                        "severity": "High",
                        "type": "XSS",
                        "description": "Reflected XSS vulnerability found",
                        "evidence": {"payload": "<script>alert(1)</script>"},
                        "cwe_id": "CWE-79",
                        "cvss_score": 7.5,
                        "remediation": "Implement input validation",
                    }
                ],
                "scan_time": 5.2,
                "risk_level": "High",
            }
        ],
    }

    # Test formatters
    json_formatter = JSONFormatter()
    txt_formatter = TXTFormatter()
    html_formatter = HTMLFormatter()

    json_report = json_formatter.format_report(test_scan_data)
    txt_report = txt_formatter.format_report(test_scan_data)
    html_report = html_formatter.format_report(test_scan_data)

    # Check that reports contain expected content
    assert "scan_info" in json_report or "example.com" in json_report  # JSON contains target info
    assert "SCAN SUMMARY" in txt_report or "Summary" in txt_report.upper()
    assert "<!DOCTYPE html>" in html_report or "<html" in html_report.lower()

    # Test templates
    template_manager = ReportTemplateManager()

    executive_report = template_manager.generate_report("executive", test_scan_data)
    technical_report = template_manager.generate_report("technical", test_scan_data)
    remediation_report = template_manager.generate_report("remediation", test_scan_data)

    assert "Executive Security Assessment Summary" in executive_report
    assert "Technical Security Assessment Report" in technical_report
    assert "Vulnerability Remediation Guide" in remediation_report

    # Test all reports generation
    all_reports = template_manager.generate_all_reports(test_scan_data)
    assert "executive" in all_reports
    assert "technical" in all_reports
    assert "remediation" in all_reports


if __name__ == "__main__":
    pytest.main([__file__])
