"""Scan, verify, and report steps for one engagement.

Scan records exposed services. Verify runs registered check modules and keeps
the evidence. Neither step extracts data, uploads a file, or hides the client.
"""

import os
from pathlib import Path
from urllib.parse import urlparse

from src.core.discovery import discover_services, service_findings, target_host
from src.core.engagements import EngagementStore, host_in_domains


class AssessmentError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


def _public_url(url: str) -> str:
    from src.core.config import Config

    candidate = url.strip()
    if not candidate.startswith(("http://", "https://")):
        candidate = "https://" + candidate
    host = target_host(candidate)
    parsed = urlparse(candidate)
    if parsed.hostname != host:
        raise AssessmentError("Target must be an http(s) URL.")
    if not Config().validate_target(candidate):
        raise AssessmentError("Target is not an allowed public http(s) URL.")
    return candidate


def _require_in_scope(engagement: dict, url: str) -> str:
    candidate = url.strip()
    if not candidate.startswith(("http://", "https://")):
        candidate = "https://" + candidate
    host = target_host(candidate)
    if not host_in_domains(host, engagement.get("allowed_domains") or []):
        raise AssessmentError(f"{host} is outside this engagement's scope.")
    return _public_url(candidate)


def _store(store: EngagementStore | None) -> EngagementStore:
    return store or EngagementStore()


def _get(store: EngagementStore, engagement_id: str) -> dict:
    engagement = store.get(engagement_id)
    if engagement is None:
        raise AssessmentError("Engagement not found.", 404)
    return engagement


async def run_scan(engagement_id: str, url: str, store: EngagementStore | None = None) -> dict:
    store = _store(store)
    engagement = _get(store, engagement_id)
    target = _require_in_scope(engagement, url)
    discovered = await discover_services(target_host(target))
    findings = service_findings(target, discovered["services"])
    store.add_services(engagement_id, target, discovered["services"])
    added = store.add_findings(engagement_id, findings)
    store.add_note(engagement_id, f"Scan {target}: {discovered['detail']}")
    if discovered["status"] == "ok":
        store.set_phase(engagement_id, "scanned")
    return {
        "status": discovered["status"],
        "detail": discovered["detail"],
        "services": discovered["services"],
        "findings_added": len(added),
        "engagement": store.summary(store.get(engagement_id)),
    }


def findings_from_module_results(results, target: str) -> list[dict]:
    collected = []
    for result in results:
        for vuln in getattr(result, "vulnerabilities", []) or []:
            if not isinstance(vuln, dict):
                continue
            collected.append(
                {
                    "title": vuln.get("title") or "Finding",
                    "description": vuln.get("description") or "",
                    "severity": vuln.get("severity") or "info",
                    "module": getattr(result, "module_name", "") or vuln.get("module_name") or "",
                    "target": target,
                    "remediation": vuln.get("remediation") or "",
                    "evidence": vuln.get("evidence") if isinstance(vuln.get("evidence"), dict) else {},
                }
            )
    return collected


async def run_verify(
    engagement_id: str,
    url: str,
    modules: list[str] | None = None,
    store: EngagementStore | None = None,
) -> dict:
    from src.api.v1.blueteam import get_incident_tracker
    from src.core.config import Config
    from src.core.scan_templates import BOUNTY_MODULES
    from src.core.scanner_engine import MODULE_REGISTRY, ScannerEngine

    store = _store(store)
    engagement = _get(store, engagement_id)
    target = _require_in_scope(engagement, url)
    selected = [item.strip() for item in (modules or list(BOUNTY_MODULES)) if item and item.strip()]
    unknown = [item for item in selected if item not in MODULE_REGISTRY]
    if unknown:
        raise AssessmentError("Unknown module: " + ", ".join(unknown))
    if not selected:
        raise AssessmentError("No modules selected.")

    engine = ScannerEngine(Config())
    results = await engine.scan_target(target, selected)
    findings = findings_from_module_results(results, target)
    added = store.add_findings(engagement_id, findings)
    store.set_phase(engagement_id, "verified")
    store.add_note(engagement_id, f"Verify {target}: {len(added)} new findings.")

    handoff = []
    for finding in added:
        description = finding["description"]
        if finding.get("remediation"):
            description = f"{description}\n\nFix: {finding['remediation']}"
        if finding.get("evidence"):
            description = f"{description}\n\nEvidence: {finding['evidence']}"
        handoff.append(
            {
                "title": finding["title"],
                "description": description[:2000],
                "severity": finding["severity"],
            }
        )
    opened = get_incident_tracker().open_from_findings(handoff, scan_id=engagement_id, min_severity="high")
    return {
        "status": "ok",
        "findings_added": len(added),
        "incidents_opened": len(opened),
        "engagement": store.summary(store.get(engagement_id)),
    }


def write_report(engagement_id: str, store: EngagementStore | None = None) -> dict:
    store = _store(store)
    _get(store, engagement_id)
    store.set_phase(engagement_id, "reported")
    text = store.markdown(engagement_id)
    report_dir = Path(os.getenv("SENTINEL_REPORT_DIR", "output/reports"))
    report_dir.mkdir(parents=True, exist_ok=True)
    path = report_dir / f"{engagement_id}.md"
    path.write_text(text, encoding="utf-8")
    return {"markdown": text, "path": str(path), "engagement": store.summary(store.get(engagement_id))}
