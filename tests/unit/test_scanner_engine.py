"""
Tests for the ScannerEngine with lazy module loading.
"""

import asyncio
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from src.core.scanner_engine import MODULE_REGISTRY, ScanResult, ScannerEngine, _load_module_class


class TestScanResult:
    """Test ScanResult dataclass."""

    def test_defaults(self):
        result = ScanResult(module_name="test", status="ok", details="details")
        assert result.module_name == "test"
        assert isinstance(result.vulnerabilities, list)
        assert isinstance(result.evidence, dict)
        assert isinstance(result.timestamp, datetime)
        assert result.duration == 0.0
        assert result.risk_level == "unknown"

    def test_evidence_is_dict(self):
        """Regression test: evidence must be dict, not list."""
        result = ScanResult(module_name="test", status="ok", details="test")
        assert isinstance(result.evidence, dict)
        # Verify it's mutable as a dict
        result.evidence["key"] = "value"
        assert result.evidence["key"] == "value"

    def test_custom_values(self):
        result = ScanResult(
            module_name="xss",
            status="Vulnerable",
            details="Found XSS",
            vulnerabilities=[{"title": "XSS", "severity": "high"}],
            evidence={"url": "http://test.com"},
            risk_level="high",
            duration=1.5,
        )
        assert result.risk_level == "high"
        assert len(result.vulnerabilities) == 1
        assert result.duration == 1.5


class TestModuleRegistry:
    """Test lazy module loading registry."""

    def test_registry_has_all_modules(self):
        """Verify all 57 modules are registered."""
        assert len(MODULE_REGISTRY) >= 55  # At least 55 modules

    def test_registry_contains_core_modules(self):
        core_modules = [
            "xss_scanner", "sqli_scanner", "ssrf_scanner",
            "jwt_scanner", "cors_scanner", "auth_scanner",
        ]
        for mod in core_modules:
            assert mod in MODULE_REGISTRY, f"Missing core module: {mod}"

    def test_registry_entries_have_correct_format(self):
        for module_id, (module_path, class_name) in MODULE_REGISTRY.items():
            assert module_path.startswith("src.modules."), f"Invalid path for {module_id}: {module_path}"
            assert class_name[0].isupper(), f"Class name should be CamelCase: {class_name}"

    def test_load_module_class_unknown(self):
        """Verify unknown module raises ScannerException."""
        from src.core.exceptions import ScannerException
        with pytest.raises(ScannerException):
            _load_module_class("nonexistent_module")


class TestScannerEngine:
    """Test ScannerEngine initialization and methods."""

    def _create_engine(self):
        config = MagicMock()
        config.scanner.enable_waf_bypass = False
        config.scanner.concurrent_requests = 5
        config.network = MagicMock()
        with patch("src.core.scanner_engine.HTTPClient"):
            with patch("src.core.scanner_engine.ReportTemplateManager"):
                return ScannerEngine(config)

    def test_engine_init_no_eager_loading(self):
        """Verify engine initializes without loading any modules."""
        engine = self._create_engine()
        assert len(engine._module_cache) == 0  # No modules loaded yet

    def test_get_module_lazy_loads(self):
        """Verify get_module loads module on first access."""
        engine = self._create_engine()
        # Mock the import to avoid actual module loading
        with patch("src.core.scanner_engine._load_module_class") as mock_load:
            mock_class = MagicMock()
            mock_load.return_value = mock_class

            module = engine.get_module("xss_scanner")
            mock_load.assert_called_once_with("xss_scanner")
            assert "xss_scanner" in engine._module_cache

    def test_get_module_caches(self):
        """Verify second call returns cached instance."""
        engine = self._create_engine()
        with patch("src.core.scanner_engine._load_module_class") as mock_load:
            mock_class = MagicMock()
            mock_load.return_value = mock_class

            module1 = engine.get_module("xss_scanner")
            module2 = engine.get_module("xss_scanner")
            mock_load.assert_called_once()  # Only loaded once

    def test_get_available_module_ids(self):
        engine = self._create_engine()
        ids = engine.get_available_module_ids()
        assert len(ids) >= 47
        assert "xss_scanner" in ids

    def test_get_module_count(self):
        engine = self._create_engine()
        assert engine.get_module_count() >= 47

    def test_get_scan_summary_empty(self):
        engine = self._create_engine()
        summary = engine.get_scan_summary()
        assert summary["total_modules"] == 0
        assert summary["total_vulnerabilities"] == 0
        assert summary["status"] == "running"

    def test_get_scan_summary_with_results(self):
        engine = self._create_engine()
        engine.start_time = datetime.now()
        engine.end_time = datetime.now()
        engine.results = [
            ScanResult(
                module_name="xss",
                status="Vulnerable",
                details="Found XSS",
                vulnerabilities=[
                    {"title": "XSS", "severity": "high"},
                    {"title": "XSS2", "severity": "critical"},
                ],
            ),
            ScanResult(
                module_name="sqli",
                status="Clean",
                details="No issues",
            ),
        ]
        summary = engine.get_scan_summary()
        assert summary["total_modules"] == 2
        assert summary["total_vulnerabilities"] == 2
        assert summary["vulnerability_counts"]["high"] == 1
        assert summary["vulnerability_counts"]["critical"] == 1
        assert summary["status"] == "completed"

    @pytest.mark.asyncio
    async def test_diagnostic_check(self):
        engine = self._create_engine()
        health = await engine.diagnostic_check()
        assert health["status"] in ("healthy", "degraded")
        assert "modules_registered" in health["stats"]
        assert health["stats"]["modules_registered"] >= 47
        assert health["stats"]["modules_loaded"] == 0  # Lazy, none loaded
