"""
Distributed Scanning Module
Enables distributed vulnerability scanning across multiple workers.
"""

import asyncio
import logging
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class JobStatus(Enum):
    """Scan job status."""

    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class WorkerStatus(Enum):
    """Worker status."""

    IDLE = "idle"
    BUSY = "busy"
    OFFLINE = "offline"
    ERROR = "error"


@dataclass
class ScanJob:
    """Represents a distributed scan job."""

    id: str
    target_url: str
    modules: list[str]
    status: JobStatus
    priority: int = 1
    created_at: str = ""
    started_at: str = ""
    completed_at: str = ""
    worker_id: str = ""
    results: dict = None
    error: str = ""
    progress: int = 0

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()
        if self.results is None:
            self.results = {}

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class Worker:
    """Represents a scan worker."""

    id: str
    name: str
    status: WorkerStatus
    capabilities: list[str]
    current_job_id: str = ""
    last_heartbeat: str = ""
    jobs_completed: int = 0
    address: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


class JobQueue:
    """In-memory job queue for distributed scanning."""

    def __init__(self):
        self.jobs: dict[str, ScanJob] = {}
        self.pending_queue: asyncio.Queue = asyncio.Queue()
        self.results: dict[str, dict] = {}
        self._lock = asyncio.Lock()

    async def add_job(self, job: ScanJob) -> str:
        """Add a job to the queue."""
        async with self._lock:
            self.jobs[job.id] = job
            await self.pending_queue.put(job.id)
            job.status = JobStatus.QUEUED
            logger.info(f"Job {job.id} added to queue")
            return job.id

    async def get_next_job(self) -> ScanJob | None:
        """Get the next pending job."""
        try:
            job_id = await asyncio.wait_for(self.pending_queue.get(), timeout=1.0)
            async with self._lock:
                job = self.jobs.get(job_id)
                if job and job.status == JobStatus.QUEUED:
                    job.status = JobStatus.RUNNING
                    job.started_at = datetime.utcnow().isoformat()
                    return job
        except asyncio.TimeoutError:
            pass
        return None

    async def complete_job(self, job_id: str, results: dict):
        """Mark a job as completed."""
        async with self._lock:
            if job_id in self.jobs:
                job = self.jobs[job_id]
                job.status = JobStatus.COMPLETED
                job.completed_at = datetime.utcnow().isoformat()
                job.results = results
                job.progress = 100
                self.results[job_id] = results
                logger.info(f"Job {job_id} completed")

    async def fail_job(self, job_id: str, error: str):
        """Mark a job as failed."""
        async with self._lock:
            if job_id in self.jobs:
                job = self.jobs[job_id]
                job.status = JobStatus.FAILED
                job.completed_at = datetime.utcnow().isoformat()
                job.error = error
                logger.error(f"Job {job_id} failed: {error}")

    def get_job_status(self, job_id: str) -> dict | None:
        """Get job status."""
        if job_id in self.jobs:
            return self.jobs[job_id].to_dict()
        return None

    def get_all_jobs(self) -> list[dict]:
        """Get all jobs."""
        return [job.to_dict() for job in self.jobs.values()]


class WorkerManager:
    """Manages distributed workers."""

    def __init__(self):
        self.workers: dict[str, Worker] = {}
        self._lock = asyncio.Lock()
        self.heartbeat_timeout = 60  # seconds

    async def register_worker(self, worker_id: str, name: str, capabilities: list[str], address: str = "") -> Worker:
        """Register a new worker."""
        async with self._lock:
            worker = Worker(
                id=worker_id,
                name=name,
                status=WorkerStatus.IDLE,
                capabilities=capabilities,
                address=address,
                last_heartbeat=datetime.utcnow().isoformat(),
            )
            self.workers[worker_id] = worker
            logger.info(f"Worker {worker_id} registered")
            return worker

    async def update_heartbeat(self, worker_id: str):
        """Update worker heartbeat."""
        async with self._lock:
            if worker_id in self.workers:
                worker = self.workers[worker_id]
                worker.last_heartbeat = datetime.utcnow().isoformat()
                if worker.status == WorkerStatus.OFFLINE:
                    worker.status = WorkerStatus.IDLE

    async def assign_job(self, worker_id: str, job_id: str):
        """Assign a job to a worker."""
        async with self._lock:
            if worker_id in self.workers:
                worker = self.workers[worker_id]
                worker.status = WorkerStatus.BUSY
                worker.current_job_id = job_id

    async def complete_job(self, worker_id: str):
        """Mark worker as having completed its job."""
        async with self._lock:
            if worker_id in self.workers:
                worker = self.workers[worker_id]
                worker.status = WorkerStatus.IDLE
                worker.current_job_id = ""
                worker.jobs_completed += 1

    async def get_available_worker(self, required_capabilities: list[str] = None) -> Worker | None:
        """Get an available worker with required capabilities."""
        async with self._lock:
            for worker in self.workers.values():
                if worker.status == WorkerStatus.IDLE:
                    if required_capabilities:
                        if all(cap in worker.capabilities for cap in required_capabilities):
                            return worker
                    else:
                        return worker
        return None

    def get_all_workers(self) -> list[dict]:
        """Get all workers."""
        return [w.to_dict() for w in self.workers.values()]

    async def check_dead_workers(self):
        """Check for dead workers."""
        async with self._lock:
            now = datetime.utcnow()
            for worker in self.workers.values():
                if worker.last_heartbeat:
                    last_beat = datetime.fromisoformat(worker.last_heartbeat)
                    if (now - last_beat).total_seconds() > self.heartbeat_timeout:
                        worker.status = WorkerStatus.OFFLINE
                        logger.warning(f"Worker {worker.id} marked as offline")


class DistributedScanner:
    """
    Distributed scanning coordinator.

    Manages job distribution across multiple workers for
    large-scale vulnerability scanning.
    """

    def __init__(self, config=None, scanner_engine=None):
        self.config = config
        self.scanner_engine = scanner_engine
        self.job_queue = JobQueue()
        self.worker_manager = WorkerManager()
        self.running = False
        self._coordinator_task = None

    async def start(self):
        """Start the distributed scanner coordinator."""
        self.running = True
        self._coordinator_task = asyncio.create_task(self._coordinator_loop())
        logger.info("Distributed scanner coordinator started")

    async def stop(self):
        """Stop the distributed scanner coordinator."""
        self.running = False
        if self._coordinator_task:
            self._coordinator_task.cancel()
            try:
                await self._coordinator_task
            except asyncio.CancelledError:
                pass
        logger.info("Distributed scanner coordinator stopped")

    async def _coordinator_loop(self):
        """Main coordinator loop."""
        while self.running:
            try:
                # Check for dead workers
                await self.worker_manager.check_dead_workers()

                # Try to assign pending jobs to available workers
                job = await self.job_queue.get_next_job()
                if job:
                    worker = await self.worker_manager.get_available_worker()
                    if worker:
                        await self._dispatch_job(worker, job)
                    else:
                        # No worker available, requeue
                        job.status = JobStatus.QUEUED
                        await self.job_queue.pending_queue.put(job.id)

                await asyncio.sleep(0.5)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception(f"Coordinator error: {e}")
                await asyncio.sleep(1)

    async def _dispatch_job(self, worker: Worker, job: ScanJob):
        """Dispatch a job to a worker."""
        await self.worker_manager.assign_job(worker.id, job.id)
        job.worker_id = worker.id

        logger.info(f"Dispatching job {job.id} to worker {worker.id}")

        # If running locally, execute the scan
        if not worker.address:
            asyncio.create_task(self._execute_local_job(worker, job))
        else:
            # Send to remote worker (would use HTTP/gRPC in production)
            asyncio.create_task(self._send_to_remote_worker(worker, job))

    async def _execute_local_job(self, worker: Worker, job: ScanJob):
        """Execute a job locally."""
        try:
            if self.scanner_engine:
                # Run actual scan
                results = await self.scanner_engine.scan(job.target_url, modules=job.modules)
                await self.job_queue.complete_job(job.id, results)
            else:
                # Simulated scan for testing
                await asyncio.sleep(2)
                results = {"status": "completed", "target": job.target_url, "vulnerabilities": [], "scan_time": 2.0}
                await self.job_queue.complete_job(job.id, results)

        except Exception as e:
            await self.job_queue.fail_job(job.id, str(e))
        finally:
            await self.worker_manager.complete_job(worker.id)

    async def _send_to_remote_worker(self, worker: Worker, job: ScanJob):
        """Send job to remote worker."""
        # In production, this would make HTTP/gRPC call to remote worker
        # For now, simulate remote execution
        try:
            await asyncio.sleep(3)  # Simulated remote execution
            results = {"status": "completed", "target": job.target_url, "worker": worker.id, "vulnerabilities": []}
            await self.job_queue.complete_job(job.id, results)
        except Exception as e:
            await self.job_queue.fail_job(job.id, str(e))
        finally:
            await self.worker_manager.complete_job(worker.id)

    # Public API

    async def submit_scan(self, target_url: str, modules: list[str], priority: int = 1) -> str:
        """Submit a new scan job."""
        job = ScanJob(
            id=str(uuid.uuid4()), target_url=target_url, modules=modules, status=JobStatus.PENDING, priority=priority
        )
        return await self.job_queue.add_job(job)

    async def get_job_status(self, job_id: str) -> dict | None:
        """Get status of a job."""
        return self.job_queue.get_job_status(job_id)

    async def get_job_results(self, job_id: str) -> dict | None:
        """Get results of a completed job."""
        return self.job_queue.results.get(job_id)

    async def cancel_job(self, job_id: str) -> bool:
        """Cancel a pending job."""
        status = self.job_queue.get_job_status(job_id)
        if status and status["status"] in [JobStatus.PENDING.value, JobStatus.QUEUED.value]:
            async with self.job_queue._lock:
                self.job_queue.jobs[job_id].status = JobStatus.CANCELLED
            return True
        return False

    async def register_worker(self, name: str, capabilities: list[str], address: str = "") -> str:
        """Register a new worker."""
        worker_id = str(uuid.uuid4())
        await self.worker_manager.register_worker(worker_id, name, capabilities, address)
        return worker_id

    def get_queue_stats(self) -> dict:
        """Get queue statistics."""
        jobs = self.job_queue.jobs.values()
        workers = self.worker_manager.workers.values()

        return {
            "total_jobs": len(jobs),
            "pending_jobs": sum(1 for j in jobs if j.status == JobStatus.PENDING),
            "queued_jobs": sum(1 for j in jobs if j.status == JobStatus.QUEUED),
            "running_jobs": sum(1 for j in jobs if j.status == JobStatus.RUNNING),
            "completed_jobs": sum(1 for j in jobs if j.status == JobStatus.COMPLETED),
            "failed_jobs": sum(1 for j in jobs if j.status == JobStatus.FAILED),
            "total_workers": len(workers),
            "idle_workers": sum(1 for w in workers if w.status == WorkerStatus.IDLE),
            "busy_workers": sum(1 for w in workers if w.status == WorkerStatus.BUSY),
            "offline_workers": sum(1 for w in workers if w.status == WorkerStatus.OFFLINE),
        }


# Convenience functions for standalone usage


async def create_distributed_scanner(config=None, scanner_engine=None) -> DistributedScanner:
    """Create and start a distributed scanner."""
    scanner = DistributedScanner(config, scanner_engine)
    await scanner.start()
    return scanner


async def run_distributed_scan(targets: list[str], modules: list[str], num_workers: int = 4) -> dict[str, Any]:
    """
    Run a distributed scan across multiple targets.

    Args:
        targets: List of target URLs
        modules: List of modules to run
        num_workers: Number of local workers

    Returns:
        Aggregated results from all scans
    """
    scanner = DistributedScanner()
    await scanner.start()

    # Register workers
    for i in range(num_workers):
        await scanner.register_worker(name=f"worker-{i}", capabilities=modules)

    # Submit all jobs
    job_ids = []
    for target in targets:
        job_id = await scanner.submit_scan(target, modules)
        job_ids.append(job_id)

    # Wait for all jobs to complete
    all_results = {}
    while True:
        all_done = True
        for job_id in job_ids:
            status = await scanner.get_job_status(job_id)
            if status:
                if status["status"] in [JobStatus.PENDING.value, JobStatus.QUEUED.value, JobStatus.RUNNING.value]:
                    all_done = False
                elif status["status"] == JobStatus.COMPLETED.value:
                    results = await scanner.get_job_results(job_id)
                    all_results[status["target_url"]] = results

        if all_done:
            break
        await asyncio.sleep(0.5)

    await scanner.stop()

    return {"total_targets": len(targets), "successful_scans": len(all_results), "results": all_results}
