"""Incident tracker persistence and red-to-blue handoff."""

from src.blueteam.incident_tracker import IncidentTracker


def test_incidents_survive_a_new_tracker(tmp_path):
    path = tmp_path / "incidents.json"
    first = IncidentTracker(path)
    created = first.create(title="Missing HSTS", severity="high", source="red_team_scan", scan_id="scan-1")

    second = IncidentTracker(path)
    loaded = second.get(created.id)
    assert loaded is not None
    assert loaded.title == "Missing HSTS"
    assert loaded.status == "open"


def test_handoff_keeps_high_and_skips_duplicates(tmp_path):
    tracker = IncidentTracker(tmp_path / "incidents.json")
    findings = [
        {"title": "Missing HSTS", "description": "no header", "severity": "high"},
        {"title": "Missing Referrer-Policy", "description": "optional", "severity": "info"},
        {"title": "Cookie missing HttpOnly", "description": "session", "severity": "critical"},
    ]
    opened = tracker.open_from_findings(findings, scan_id="scan-9")
    assert [item.title for item in opened] == ["Missing HSTS", "Cookie missing HttpOnly"]

    again = tracker.open_from_findings(findings, scan_id="scan-9")
    assert again == []
    assert tracker.get_stats()["total"] == 2


def test_status_transition_is_rejected_when_illegal(tmp_path):
    tracker = IncidentTracker(tmp_path / "incidents.json")
    incident = tracker.create(title="IOC hit", severity="high")
    assert tracker.update_status(incident.id, "resolved") is None
    assert tracker.get(incident.id).status == "open"
    moved = tracker.update_status(incident.id, "investigating")
    assert moved is not None
    assert moved.status == "investigating"
