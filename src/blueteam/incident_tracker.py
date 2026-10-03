"""
Incident Tracker — Lightweight incident lifecycle management.

Tracks security incidents from detection through resolution:
  open → investigating → contained → resolved → closed

Stores incidents in-memory with localStorage persistence on the frontend.
For production, incidents should be stored in the database.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)


@dataclass
class IncidentEvent:
    """A single event in an incident timeline."""

    timestamp: str
    action: str  # created, status_changed, note_added, assigned, escalated
    user: str = "system"
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"timestamp": self.timestamp, "action": self.action, "user": self.user, "detail": self.detail}


@dataclass
class Incident:
    """A tracked security incident."""

    id: str = field(default_factory=lambda: str(uuid4())[:8])
    title: str = ""
    description: str = ""
    severity: str = "medium"  # critical, high, medium, low
    status: str = "open"  # open, investigating, contained, resolved, closed
    category: str = "vulnerability"  # vulnerability, malware, phishing, unauthorized_access, data_leak, other
    source: str = ""  # scan finding, IOC hit, manual report
    assignee: str | None = None
    related_scan_id: str | None = None
    related_finding_index: int | None = None
    ioc_indicators: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    timeline: list[IncidentEvent] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "category": self.category,
            "source": self.source,
            "assignee": self.assignee,
            "related_scan_id": self.related_scan_id,
            "related_finding_index": self.related_finding_index,
            "ioc_indicators": self.ioc_indicators,
            "tags": self.tags,
            "timeline": [e.to_dict() for e in self.timeline],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


VALID_STATUSES = ("open", "investigating", "contained", "resolved", "closed")
VALID_CATEGORIES = ("vulnerability", "malware", "phishing", "unauthorized_access", "data_leak", "other")

# Allowed status transitions
STATUS_TRANSITIONS = {
    "open": ("investigating", "closed"),
    "investigating": ("contained", "resolved", "open"),
    "contained": ("resolved", "investigating"),
    "resolved": ("closed", "investigating"),
    "closed": ("open",),  # reopen
}


_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _incident_from_dict(raw: dict[str, Any]) -> Incident:
    timeline = [
        IncidentEvent(
            timestamp=event.get("timestamp", ""),
            action=event.get("action", ""),
            user=event.get("user", "system"),
            detail=event.get("detail", ""),
        )
        for event in raw.get("timeline") or []
        if isinstance(event, dict)
    ]
    now = datetime.now(UTC).isoformat()
    return Incident(
        id=str(raw.get("id") or "")[:8] or str(uuid4())[:8],
        title=str(raw.get("title") or ""),
        description=str(raw.get("description") or ""),
        severity=str(raw.get("severity") or "medium"),
        status=str(raw.get("status") or "open"),
        category=str(raw.get("category") or "vulnerability"),
        source=str(raw.get("source") or ""),
        assignee=raw.get("assignee"),
        related_scan_id=raw.get("related_scan_id"),
        related_finding_index=raw.get("related_finding_index"),
        ioc_indicators=list(raw.get("ioc_indicators") or []),
        tags=list(raw.get("tags") or []),
        timeline=timeline,
        created_at=str(raw.get("created_at") or now),
        updated_at=str(raw.get("updated_at") or now),
    )


class IncidentTracker:
    """Incident lifecycle. Records are stored in a JSON file so they survive a restart."""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else Path("output/incidents.json")
        self._incidents: dict[str, Incident] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.warning("Incident file %s could not be read. Starting empty.", self.path)
            return
        if not isinstance(raw, list):
            return
        for item in raw:
            if isinstance(item, dict) and item.get("id"):
                incident = _incident_from_dict(item)
                self._incidents[incident.id] = incident

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = [incident.to_dict() for incident in self._incidents.values()]
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def create(
        self,
        title: str,
        description: str = "",
        severity: str = "medium",
        category: str = "vulnerability",
        source: str = "",
        scan_id: str | None = None,
        finding_index: int | None = None,
        ioc_indicators: list[str] | None = None,
        tags: list[str] | None = None,
    ) -> Incident:
        """Create a new incident."""
        incident = Incident(
            title=title,
            description=description,
            severity=severity if severity in ("critical", "high", "medium", "low") else "medium",
            category=category if category in VALID_CATEGORIES else "other",
            source=source,
            related_scan_id=scan_id,
            related_finding_index=finding_index,
            ioc_indicators=ioc_indicators or [],
            tags=tags or [],
        )
        incident.timeline.append(
            IncidentEvent(
                timestamp=incident.created_at,
                action="created",
                detail=f"Incident created: {title}",
            )
        )
        self._incidents[incident.id] = incident
        self._save()
        logger.info("Incident created: %s", incident.id)
        return incident

    def open_from_findings(
        self,
        findings: list[dict[str, Any]],
        scan_id: str | None = None,
        min_severity: str = "high",
    ) -> list[Incident]:
        """Open one incident per finding at or above min_severity. Skips titles already opened for this scan."""
        floor = _SEVERITY_RANK.get(min_severity, _SEVERITY_RANK["high"])
        existing = {(incident.related_scan_id, incident.title) for incident in self._incidents.values()}
        opened: list[Incident] = []
        for index, finding in enumerate(findings):
            if not isinstance(finding, dict):
                continue
            severity = str(finding.get("severity") or "info").lower()
            if _SEVERITY_RANK.get(severity, 0) < floor:
                continue
            title = str(finding.get("title") or "Finding")[:200]
            if (scan_id, title) in existing:
                continue
            incident = self.create(
                title=title,
                description=str(finding.get("description") or "")[:2000],
                severity=severity,
                source="red_team_scan",
                scan_id=scan_id,
                finding_index=index,
                tags=["red-team"],
            )
            existing.add((scan_id, title))
            opened.append(incident)
        return opened

    def get(self, incident_id: str) -> Incident | None:
        return self._incidents.get(incident_id)

    def list_all(self, status: str | None = None, severity: str | None = None) -> list[Incident]:
        """List incidents with optional filters."""
        result = list(self._incidents.values())
        if status:
            result = [i for i in result if i.status == status]
        if severity:
            result = [i for i in result if i.severity == severity]
        return sorted(result, key=lambda i: i.created_at, reverse=True)

    def update_status(self, incident_id: str, new_status: str, user: str = "system", note: str = "") -> Incident | None:
        """Transition an incident to a new status."""
        incident = self._incidents.get(incident_id)
        if not incident:
            return None

        allowed = STATUS_TRANSITIONS.get(incident.status, ())
        if new_status not in allowed:
            logger.warning(f"Invalid transition: {incident.status} → {new_status} (allowed: {allowed})")
            return None

        old_status = incident.status
        incident.status = new_status
        incident.updated_at = datetime.now(UTC).isoformat()
        incident.timeline.append(
            IncidentEvent(
                timestamp=incident.updated_at,
                action="status_changed",
                user=user,
                detail=f"{old_status} → {new_status}" + (f": {note}" if note else ""),
            )
        )
        self._save()
        logger.info("Incident %s: %s -> %s", incident_id, old_status, new_status)
        return incident

    def add_note(self, incident_id: str, note: str, user: str = "analyst") -> Incident | None:
        """Add a note to an incident timeline."""
        incident = self._incidents.get(incident_id)
        if not incident:
            return None

        incident.updated_at = datetime.now(UTC).isoformat()
        incident.timeline.append(
            IncidentEvent(
                timestamp=incident.updated_at,
                action="note_added",
                user=user,
                detail=note,
            )
        )
        self._save()
        return incident

    def assign(self, incident_id: str, assignee: str) -> Incident | None:
        """Assign an incident to a team member."""
        incident = self._incidents.get(incident_id)
        if not incident:
            return None

        incident.assignee = assignee
        incident.updated_at = datetime.now(UTC).isoformat()
        incident.timeline.append(
            IncidentEvent(
                timestamp=incident.updated_at,
                action="assigned",
                detail=f"Assigned to {assignee}",
            )
        )
        self._save()
        return incident

    def delete(self, incident_id: str) -> bool:
        if incident_id in self._incidents:
            del self._incidents[incident_id]
            self._save()
            return True
        return False

    def get_stats(self) -> dict[str, Any]:
        """Get incident statistics."""
        incidents = list(self._incidents.values())
        by_status = {}
        by_severity = {}
        for i in incidents:
            by_status[i.status] = by_status.get(i.status, 0) + 1
            by_severity[i.severity] = by_severity.get(i.severity, 0) + 1

        return {
            "total": len(incidents),
            "by_status": by_status,
            "by_severity": by_severity,
            "open_count": by_status.get("open", 0) + by_status.get("investigating", 0),
        }
