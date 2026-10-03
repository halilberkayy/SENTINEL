"""
Unit tests for advanced scanner modules.
Tests for gRPC, Mobile API, Recursive Scanner, and Distributed Scanner.
"""

import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.core.distributed_scanner import DistributedScanner, JobQueue, JobStatus, ScanJob, WorkerManager, WorkerStatus
from src.modules.grpc_scanner import GRPCScanner
from src.modules.mobile_api_scanner import MobileAPIScanner
from src.modules.recursive_scanner import RecursiveScanner


class MockResponse:
    """Mock HTTP response for testing."""

    def __init__(self, status=200, content="", headers=None):
        self.status = status
        self._content = content
        self.headers = headers or {}

    async def text(self):
        return self._content

    async def json(self):
        import json

        return json.loads(self._content)


class MockHTTPClient:
    """Mock HTTP client for testing."""

    def __init__(self, responses=None):
        self.responses = responses or {}
        self.calls = []

    async def get(self, url, headers=None):
        self.calls.append(("GET", url, headers))
        return self.responses.get(url, MockResponse(404))

    async def post(self, url, data=None, json=None, headers=None):
        self.calls.append(("POST", url, data or json))
        return self.responses.get(url, MockResponse(404))

    async def options(self, url, headers=None):
        self.calls.append(("OPTIONS", url, headers))
        return self.responses.get(url, MockResponse(404))


class MockConfig:
    """Mock scanner configuration."""

    def __init__(self):
        self.scanner = Mock()
        self.scanner.timeout = 10
        self.network = Mock()


# ==================== gRPC Scanner Tests ====================


class TestGRPCScanner:
    """Tests for GRPCScanner module."""

    @pytest.fixture
    def scanner(self):
        config = MockConfig()
        http_client = MockHTTPClient()
        return GRPCScanner(config, http_client)

    def test_initialization(self, scanner):
        """Test scanner initialization."""
        assert scanner.name == "GRPCScanner"
        assert scanner.version == "1.0.0"
        assert len(scanner.grpc_paths) > 0
        assert len(scanner.proto_paths) > 0

    def test_grpc_content_types(self, scanner):
        """Test gRPC content types are defined."""
        assert "application/grpc" in scanner.grpc_content_types
        assert "application/grpc-web" in scanner.grpc_content_types

    @pytest.mark.asyncio
    async def test_scan_returns_result(self, scanner):
        """Test scan method returns valid result."""
        scanner.http_client.responses = {"https://example.com": MockResponse(200, "OK")}

        result = await scanner.scan("https://example.com")
        assert result is not None
        assert "status" in result


# ==================== Mobile API Scanner Tests ====================


class TestMobileAPIScanner:
    """Tests for MobileAPIScanner module."""

    @pytest.fixture
    def scanner(self):
        config = MockConfig()
        http_client = MockHTTPClient()
        return MobileAPIScanner(config, http_client)

    def test_initialization(self, scanner):
        """Test scanner initialization."""
        assert scanner.name == "MobileAPIScanner"
        assert scanner.version == "1.0.0"
        assert len(scanner.mobile_user_agents) > 0
        assert len(scanner.mobile_headers) > 0

    def test_mobile_user_agents(self, scanner):
        """Test mobile user agents are defined."""
        assert "ios" in scanner.mobile_user_agents
        assert "android" in scanner.mobile_user_agents
        assert "iPhone" in scanner.mobile_user_agents["ios"]

    def test_bypass_headers(self, scanner):
        """Test root/jailbreak bypass headers."""
        assert len(scanner.bypass_headers) > 0
        # Check for common bypass headers
        headers_list = [list(h.keys())[0] for h in scanner.bypass_headers]
        assert any("Jailbreak" in h or "Rooted" in h for h in headers_list)

    @pytest.mark.asyncio
    async def test_scan_returns_result(self, scanner):
        """Test scan method returns valid result."""
        result = await scanner.scan("https://example.com")
        assert result is not None
        assert "status" in result


# ==================== Recursive Scanner Tests ====================


class TestRecursiveScanner:
    """Tests for RecursiveScanner module."""

    @pytest.fixture
    def scanner_with_config(self):
        config = MockConfig()
        http_client = MockHTTPClient()
        return RecursiveScanner(config=config, http_client=http_client)

    @pytest.fixture
    def scanner_with_url(self):
        return RecursiveScanner(base_url="https://example.com", max_depth=2)

    def test_initialization_with_config(self, scanner_with_config):
        """Test scanner initialization with config."""
        assert scanner_with_config.name == "RecursiveScanner"
        assert scanner_with_config.config is not None
        assert scanner_with_config.http_client is not None

    def test_initialization_with_url(self, scanner_with_url):
        """Test scanner initialization with URL."""
        assert scanner_with_url.base_url == "https://example.com"
        assert scanner_with_url.max_depth == 2

    def test_default_values(self, scanner_with_config):
        """Test default configuration values."""
        assert scanner_with_config.max_depth == 3
        assert scanner_with_config.max_pages == 100
        assert scanner_with_config.delay == 0.5


# ==================== Distributed Scanner Tests ====================


class TestJobQueue:
    """Tests for JobQueue."""

    @pytest.fixture
    def queue(self):
        return JobQueue()

    @pytest.mark.asyncio
    async def test_add_job(self, queue):
        """Test adding a job to queue."""
        job = ScanJob(id="test-1", target_url="https://example.com", modules=["xss_scanner"], status=JobStatus.PENDING)

        job_id = await queue.add_job(job)
        assert job_id == "test-1"
        assert job.status == JobStatus.QUEUED

    @pytest.mark.asyncio
    async def test_get_next_job(self, queue):
        """Test getting next job from queue."""
        job = ScanJob(id="test-2", target_url="https://example.com", modules=["sqli_scanner"], status=JobStatus.PENDING)

        await queue.add_job(job)
        next_job = await queue.get_next_job()

        assert next_job is not None
        assert next_job.id == "test-2"
        assert next_job.status == JobStatus.RUNNING

    @pytest.mark.asyncio
    async def test_complete_job(self, queue):
        """Test completing a job."""
        job = ScanJob(id="test-3", target_url="https://example.com", modules=[], status=JobStatus.PENDING)

        await queue.add_job(job)
        await queue.get_next_job()
        await queue.complete_job("test-3", {"vulnerabilities": []})

        status = queue.get_job_status("test-3")
        assert status["status"] == JobStatus.COMPLETED.value


class TestWorkerManager:
    """Tests for WorkerManager."""

    @pytest.fixture
    def manager(self):
        return WorkerManager()

    @pytest.mark.asyncio
    async def test_register_worker(self, manager):
        """Test worker registration."""
        worker = await manager.register_worker(
            worker_id="worker-1", name="Test Worker", capabilities=["xss_scanner", "sqli_scanner"]
        )

        assert worker.id == "worker-1"
        assert worker.status == WorkerStatus.IDLE
        assert len(worker.capabilities) == 2

    @pytest.mark.asyncio
    async def test_get_available_worker(self, manager):
        """Test getting available worker."""
        await manager.register_worker("w1", "Worker 1", ["scanner"])

        worker = await manager.get_available_worker()
        assert worker is not None
        assert worker.id == "w1"

    @pytest.mark.asyncio
    async def test_assign_job(self, manager):
        """Test assigning job to worker."""
        await manager.register_worker("w2", "Worker 2", [])
        await manager.assign_job("w2", "job-123")

        workers = manager.get_all_workers()
        worker = next(w for w in workers if w["id"] == "w2")

        assert worker["status"] == WorkerStatus.BUSY.value
        assert worker["current_job_id"] == "job-123"


class TestDistributedScanner:
    """Tests for DistributedScanner."""

    @pytest.fixture
    def scanner(self):
        return DistributedScanner()

    @pytest.mark.asyncio
    async def test_submit_scan(self, scanner):
        """Test submitting a scan job."""
        job_id = await scanner.submit_scan(target_url="https://example.com", modules=["xss_scanner"])

        assert job_id is not None
        status = await scanner.get_job_status(job_id)
        assert status is not None

    @pytest.mark.asyncio
    async def test_register_worker(self, scanner):
        """Test registering a worker."""
        worker_id = await scanner.register_worker(name="Test Worker", capabilities=["scanner"])

        assert worker_id is not None

    def test_get_queue_stats(self, scanner):
        """Test getting queue statistics."""
        stats = scanner.get_queue_stats()

        assert "total_jobs" in stats
        assert "total_workers" in stats
        assert "pending_jobs" in stats


# ==================== Integration Tests ====================


class TestAdvancedModulesIntegration:
    """Integration tests for advanced modules."""

    def test_all_modules_load(self):
        """Test that all modules can be imported and initialized."""
        config = MockConfig()
        http_client = MockHTTPClient()

        modules = [
            GRPCScanner(config, http_client),
            MobileAPIScanner(config, http_client),
            RecursiveScanner(config=config, http_client=http_client),
        ]

        for module in modules:
            assert module.name is not None

    def test_modules_in_engine(self):
        """Test that modules are registered in scanner engine."""
        from src.core.config import Config
        from src.core.scanner_engine import ScannerEngine

        config = Config()
        engine = ScannerEngine(config)

        expected_modules = ["grpc_scanner", "mobile_api_scanner", "recursive_scanner"]

        for mod_id in expected_modules:
            assert mod_id in engine.modules, f"Module {mod_id} not found in engine"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
