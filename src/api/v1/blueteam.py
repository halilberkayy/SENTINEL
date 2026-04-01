"""
Blue Team API endpoints — IOC lookup, hardening analysis, incident tracking.
"""

import os

import structlog
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from src.blueteam.hardening import HardeningAnalyzer
from src.blueteam.incident_tracker import IncidentTracker
from src.blueteam.ioc_checker import IOCChecker

logger = structlog.get_logger()

router = APIRouter(prefix="/blueteam", tags=["Blue Team"])

# Singletons
_ioc_checker: IOCChecker | None = None
_hardening: HardeningAnalyzer | None = None
_incidents: IncidentTracker | None = None


def get_ioc_checker() -> IOCChecker:
    global _ioc_checker
    if _ioc_checker is None:
        _ioc_checker = IOCChecker(
            abuseipdb_key=os.getenv("ABUSEIPDB_API_KEY"),
            otx_key=os.getenv("OTX_API_KEY"),
        )
    return _ioc_checker


def get_hardening() -> HardeningAnalyzer:
    global _hardening
    if _hardening is None:
        _hardening = HardeningAnalyzer()
    return _hardening


def get_incident_tracker() -> IncidentTracker:
    global _incidents
    if _incidents is None:
        _incidents = IncidentTracker()
    return _incidents


# ── Request / Response Models ─────────────────────────────────────


class IOCRequest(BaseModel):
    indicator: str = Field(..., min_length=1, max_length=500, description="IP, domain, or file hash to check")


class HardeningRequest(BaseModel):
    url: str = Field(..., min_length=5, max_length=2048)


class IncidentCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    description: str = ""
    severity: str = "medium"
    category: str = "vulnerability"
    source: str = ""
    scan_id: str | None = None
    finding_index: int | None = None
    ioc_indicators: list[str] = []
    tags: list[str] = []


class IncidentStatusUpdate(BaseModel):
    status: str = Field(..., description="New status: investigating, contained, resolved, closed, open")
    note: str = ""


class IncidentNote(BaseModel):
    note: str = Field(..., min_length=1, max_length=2000)
    user: str = "analyst"


# ── IOC Endpoints ──────────────────────────────────────────────────


@router.post("/ioc/check")
async def check_ioc(req: IOCRequest):
    """Check an indicator (IP/domain/hash) against threat intelligence sources."""
    checker = get_ioc_checker()
    result = await checker.check(req.indicator.strip())
    return result.to_dict()


@router.post("/ioc/check/bulk")
async def check_ioc_bulk(indicators: list[str]):
    """Check multiple indicators at once. Max 50 per request."""
    if len(indicators) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 indicators per request")

    checker = get_ioc_checker()
    results = []
    for ind in indicators:
        result = await checker.check(ind.strip())
        results.append(result.to_dict())
    return {"results": results, "total": len(results)}


# ── Hardening Endpoints ────────────────────────────────────────────


@router.post("/hardening/analyze")
async def analyze_hardening(req: HardeningRequest):
    """Analyze a target's security hardening (headers, TLS, DNS, cookies)."""
    analyzer = get_hardening()
    report = await analyzer.analyze(req.url)
    return report.to_dict()


# ── Incident Endpoints ─────────────────────────────────────────────


@router.post("/incidents", status_code=status.HTTP_201_CREATED)
async def create_incident(req: IncidentCreate):
    """Create a new security incident."""
    tracker = get_incident_tracker()
    incident = tracker.create(
        title=req.title,
        description=req.description,
        severity=req.severity,
        category=req.category,
        source=req.source,
        scan_id=req.scan_id,
        finding_index=req.finding_index,
        ioc_indicators=req.ioc_indicators,
        tags=req.tags,
    )
    return incident.to_dict()


@router.get("/incidents")
async def list_incidents(status_filter: str | None = None, severity: str | None = None):
    """List all incidents with optional filters."""
    tracker = get_incident_tracker()
    incidents = tracker.list_all(status=status_filter, severity=severity)
    return {"incidents": [i.to_dict() for i in incidents], "total": len(incidents)}


@router.get("/incidents/stats")
async def incident_stats():
    """Get incident statistics."""
    return get_incident_tracker().get_stats()


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: str):
    """Get a specific incident with full timeline."""
    incident = get_incident_tracker().get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident.to_dict()


@router.patch("/incidents/{incident_id}/status")
async def update_incident_status(incident_id: str, req: IncidentStatusUpdate):
    """Update incident status (with transition validation)."""
    incident = get_incident_tracker().update_status(incident_id, req.status, note=req.note)
    if not incident:
        raise HTTPException(status_code=400, detail="Invalid status transition or incident not found")
    return incident.to_dict()


@router.post("/incidents/{incident_id}/notes")
async def add_incident_note(incident_id: str, req: IncidentNote):
    """Add a note to an incident timeline."""
    incident = get_incident_tracker().add_note(incident_id, req.note, req.user)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident.to_dict()


@router.delete("/incidents/{incident_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_incident(incident_id: str):
    """Delete an incident."""
    if not get_incident_tracker().delete(incident_id):
        raise HTTPException(status_code=404, detail="Incident not found")
