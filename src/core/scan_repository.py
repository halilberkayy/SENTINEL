"""
Repository layer for scan results persistence.
Provides database operations for scan jobs and vulnerabilities.
"""

import json
import logging
from datetime import datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import select, update, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from .database.models import ScanJob, ScanStatus, Severity, Vulnerability

logger = logging.getLogger(__name__)


class ScanRepository:
    """Repository for scan-related database operations."""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def create_scan_job(
        self,
        target_url: str,
        modules: list[str],
        user_id: str = "anonymous"
    ) -> ScanJob:
        """Create a new scan job record."""
        scan_job = ScanJob(
            id=str(uuid4()),
            target_url=target_url,
            modules=modules,
            user_id=user_id,
            status=ScanStatus.PENDING,
        )
        self.session.add(scan_job)
        await self.session.flush()
        logger.info(f"Created scan job: {scan_job.id}")
        return scan_job
    
    async def update_scan_status(
        self,
        scan_id: str,
        status: ScanStatus,
        error_message: str | None = None
    ) -> None:
        """Update scan job status."""
        update_data = {"status": status}
        
        if status == ScanStatus.RUNNING:
            update_data["started_at"] = datetime.utcnow()
        elif status in [ScanStatus.COMPLETED, ScanStatus.FAILED]:
            update_data["completed_at"] = datetime.utcnow()
        
        if error_message:
            update_data["error_message"] = error_message
        
        stmt = update(ScanJob).where(ScanJob.id == scan_id).values(**update_data)
        await self.session.execute(stmt)
        await self.session.flush()
    
    async def save_vulnerabilities(
        self,
        scan_id: str,
        results: list[dict[str, Any]]
    ) -> int:
        """Save vulnerability findings from scan results."""
        total_vulns = 0
        
        for result in results:
            module_name = result.get("module_name", "unknown")
            vulnerabilities = result.get("vulnerabilities", [])
            
            for vuln_data in vulnerabilities:
                severity_str = vuln_data.get("severity", "info").lower()
                try:
                    severity = Severity(severity_str)
                except ValueError:
                    severity = Severity.INFO
                
                vuln = Vulnerability(
                    id=str(uuid4()),
                    scan_job_id=scan_id,
                    title=vuln_data.get("title", "Unknown Vulnerability"),
                    description=vuln_data.get("description", ""),
                    type=vuln_data.get("type", "unknown"),
                    severity=severity,
                    cvss_score=vuln_data.get("cvss_score"),
                    cwe_id=vuln_data.get("cwe_id"),
                    evidence=vuln_data.get("evidence", {}),
                    remediation=vuln_data.get("remediation"),
                    references=vuln_data.get("references", []),
                    module_name=module_name,
                )
                self.session.add(vuln)
                total_vulns += 1
        
        # Update total vulnerability count
        stmt = update(ScanJob).where(ScanJob.id == scan_id).values(
            total_vulnerabilities=total_vulns
        )
        await self.session.execute(stmt)
        await self.session.flush()
        
        logger.info(f"Saved {total_vulns} vulnerabilities for scan {scan_id}")
        return total_vulns
    
    async def get_scan_by_id(self, scan_id: str) -> ScanJob | None:
        """Get scan job by ID with vulnerabilities."""
        stmt = (
            select(ScanJob)
            .options(selectinload(ScanJob.vulnerabilities))
            .where(ScanJob.id == scan_id)
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def get_recent_scans(
        self,
        user_id: str | None = None,
        limit: int = 50
    ) -> list[ScanJob]:
        """Get recent scan jobs."""
        stmt = select(ScanJob).order_by(desc(ScanJob.created_at)).limit(limit)
        
        if user_id:
            stmt = stmt.where(ScanJob.user_id == user_id)
        
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
    
    async def get_scan_results_as_dict(self, scan_id: str) -> dict[str, Any] | None:
        """Get scan results in dictionary format for API responses."""
        scan = await self.get_scan_by_id(scan_id)
        if not scan:
            return None
        
        return {
            "scan_id": scan.id,
            "target_url": scan.target_url,
            "status": scan.status.value,
            "modules": scan.modules,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "total_vulnerabilities": scan.total_vulnerabilities,
            "duration_seconds": scan.duration_seconds,
            "vulnerabilities": [
                {
                    "id": v.id,
                    "title": v.title,
                    "description": v.description,
                    "type": v.type,
                    "severity": v.severity.value,
                    "cvss_score": v.cvss_score,
                    "cwe_id": v.cwe_id,
                    "evidence": v.evidence,
                    "remediation": v.remediation,
                    "references": v.references,
                    "module_name": v.module_name,
                }
                for v in scan.vulnerabilities
            ]
        }
    
    async def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan job and its vulnerabilities."""
        scan = await self.get_scan_by_id(scan_id)
        if not scan:
            return False
        
        await self.session.delete(scan)
        await self.session.flush()
        logger.info(f"Deleted scan job: {scan_id}")
        return True


class InMemoryScanStore:
    """
    In-memory fallback store for when database is not available.
    Used by web_app.py when running standalone.
    """
    
    def __init__(self):
        self._scans: dict[str, dict[str, Any]] = {}
    
    def save_scan(self, scan_id: str, data: dict[str, Any]) -> None:
        """Save scan data."""
        self._scans[scan_id] = {
            **data,
            "saved_at": datetime.utcnow().isoformat(),
        }
    
    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        """Get scan data."""
        return self._scans.get(scan_id)
    
    def get_recent_scans(self, limit: int = 50) -> list[dict[str, Any]]:
        """Get recent scans."""
        scans = list(self._scans.values())
        scans.sort(key=lambda x: x.get("saved_at", ""), reverse=True)
        return scans[:limit]
    
    def delete_scan(self, scan_id: str) -> bool:
        """Delete scan data."""
        if scan_id in self._scans:
            del self._scans[scan_id]
            return True
        return False
    
    def clear(self) -> None:
        """Clear all scans."""
        self._scans.clear()


# Global in-memory store for standalone mode
_memory_store: InMemoryScanStore | None = None


def get_memory_store() -> InMemoryScanStore:
    """Get global in-memory store."""
    global _memory_store
    if _memory_store is None:
        _memory_store = InMemoryScanStore()
    return _memory_store
