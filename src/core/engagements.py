"""Local engagement records for an authorized assessment.

An engagement is the operator's scope plus what the scan and verify steps
actually observed. It is a JSON file, not a kill-chain tracker.
"""

import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)

PHASES = ("draft", "scanned", "verified", "reported")
_SAFE_EVIDENCE_KEYS = ("status", "url", "port", "protocol", "service", "product", "version", "header", "bytes")


def engagement_file() -> Path:
    override = os.getenv("SENTINEL_ENGAGEMENT_FILE")
    return Path(override) if override else Path("output/engagements.json")


def normalize_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".").lstrip("*").lstrip(".")
    if not domain or any(char in domain for char in " /\\@:"):
        raise ValueError(f"Not a domain: {value}")
    return domain


def host_in_domains(host: str, domains: list[str]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == domain or host.endswith("." + domain) for domain in domains)


def evidence_line(evidence: Any) -> str:
    """Keep a short observed fact. Drop bodies, payloads, and scripts."""
    if not isinstance(evidence, dict):
        return ""
    kept = {key: evidence[key] for key in _SAFE_EVIDENCE_KEYS if evidence.get(key) not in (None, "")}
    if not kept:
        return ""
    return json.dumps(kept, default=str)[:300]


class EngagementStore:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else engagement_file()
        self._items: dict[str, dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.warning("Engagement file %s could not be read. Starting empty.", self.path)
            return
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, dict) and item.get("id"):
                    self._items[item["id"]] = item

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = list(self._items.values())
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def create(self, name: str, domains: list[str], description: str = "", objectives: list[str] | None = None) -> dict:
        cleaned = []
        for domain in domains:
            normalized = normalize_domain(str(domain))
            if normalized not in cleaned:
                cleaned.append(normalized)
        if not name.strip() or not cleaned:
            raise ValueError("Name and at least one domain are required.")
        if len(cleaned) > 50:
            raise ValueError("At most 50 domains.")
        now = datetime.now(UTC).isoformat()
        engagement = {
            "id": uuid4().hex[:8],
            "name": name.strip()[:200],
            "description": description.strip()[:2000],
            "objectives": [str(item).strip()[:200] for item in (objectives or []) if str(item).strip()][:20],
            "allowed_domains": cleaned,
            "phase": "draft",
            "services": [],
            "findings": [],
            "notes": [],
            "created_at": now,
            "updated_at": now,
        }
        self._items[engagement["id"]] = engagement
        self._save()
        return engagement

    def get(self, engagement_id: str) -> dict | None:
        return self._items.get(engagement_id)

    def list_all(self) -> list[dict]:
        return sorted(self._items.values(), key=lambda item: item["created_at"], reverse=True)

    def summary(self, engagement: dict) -> dict:
        findings = engagement.get("findings") or []
        targets = {item.get("target") for item in findings + (engagement.get("services") or []) if item.get("target")}
        return {
            "id": engagement["id"],
            "name": engagement["name"],
            "description": engagement.get("description") or "",
            "phase": engagement.get("phase") or "draft",
            "status": "completed" if engagement.get("phase") == "reported" else "active",
            "allowed_domains": engagement.get("allowed_domains") or [],
            "targets_count": len(targets),
            "findings_count": len(findings),
            "critical_findings": sum(1 for item in findings if item.get("severity") == "critical"),
            "services_count": len(engagement.get("services") or []),
            "created_at": engagement.get("created_at"),
        }

    def add_note(self, engagement_id: str, note: str) -> None:
        engagement = self._require(engagement_id)
        engagement["notes"].append({"at": datetime.now(UTC).isoformat(), "note": note[:500]})
        engagement["notes"] = engagement["notes"][-30:]
        engagement["updated_at"] = datetime.now(UTC).isoformat()
        self._save()

    def set_phase(self, engagement_id: str, phase: str) -> dict:
        if phase not in PHASES:
            raise ValueError(f"Unknown phase: {phase}")
        engagement = self._require(engagement_id)
        engagement["phase"] = phase
        engagement["updated_at"] = datetime.now(UTC).isoformat()
        self._save()
        return engagement

    def add_services(self, engagement_id: str, target: str, services: list[dict]) -> int:
        engagement = self._require(engagement_id)
        known = {(item.get("target"), item.get("port"), item.get("protocol")) for item in engagement["services"]}
        added = 0
        for service in services:
            key = (target, service.get("port"), service.get("protocol"))
            if key in known:
                continue
            known.add(key)
            engagement["services"].append(
                {
                    "target": target,
                    "port": service.get("port"),
                    "protocol": service.get("protocol") or "tcp",
                    "service": str(service.get("service") or "")[:80],
                    "product": str(service.get("product") or "")[:80],
                    "version": str(service.get("version") or "")[:80],
                }
            )
            added += 1
        engagement["services"] = engagement["services"][-300:]
        engagement["updated_at"] = datetime.now(UTC).isoformat()
        self._save()
        return added

    def add_findings(self, engagement_id: str, findings: list[dict]) -> list[dict]:
        engagement = self._require(engagement_id)
        known = {(item.get("target"), item.get("title"), item.get("module")) for item in engagement["findings"]}
        added = []
        for finding in findings:
            title = str(finding.get("title") or "Finding")[:200]
            target = str(finding.get("target") or "")[:500]
            module = str(finding.get("module") or "")[:80]
            key = (target, title, module)
            if key in known:
                continue
            known.add(key)
            record = {
                "title": title,
                "description": str(finding.get("description") or "")[:2000],
                "severity": str(finding.get("severity") or "info").lower(),
                "module": module,
                "target": target,
                "remediation": str(finding.get("remediation") or "")[:1000],
                "evidence": evidence_line(finding.get("evidence")),
            }
            if record["severity"] not in {"critical", "high", "medium", "low", "info"}:
                record["severity"] = "info"
            engagement["findings"].append(record)
            added.append(record)
        engagement["findings"] = engagement["findings"][-500:]
        engagement["updated_at"] = datetime.now(UTC).isoformat()
        self._save()
        return added

    def markdown(self, engagement_id: str) -> str:
        engagement = self._require(engagement_id)
        lines = [
            f"# {engagement['name']}",
            "",
            engagement.get("description") or "Authorized assessment.",
            "",
            f"Phase: {engagement.get('phase')}",
            f"Scope: {', '.join(engagement.get('allowed_domains') or [])}",
            "",
            "## Services",
            "",
        ]
        services = engagement.get("services") or []
        if not services:
            lines.append("No services recorded.")
        else:
            for service in services:
                banner = " ".join(part for part in (service.get("product"), service.get("version")) if part)
                lines.append(
                    f"- {service.get('target')} {service.get('protocol')}/{service.get('port')} "
                    f"{service.get('service')}" + (f" ({banner})" if banner else "")
                )
        lines.extend(["", "## Findings", ""])
        findings = engagement.get("findings") or []
        if not findings:
            lines.append("No findings recorded.")
        else:
            for finding in findings:
                lines.append(f"### {finding['severity'].upper()}: {finding['title']}")
                lines.append("")
                lines.append(f"Target: {finding.get('target') or '(none)'}")
                lines.append(f"Module: {finding.get('module') or '(none)'}")
                if finding.get("description"):
                    lines.append("")
                    lines.append(finding["description"])
                if finding.get("evidence"):
                    lines.append("")
                    lines.append(f"Evidence: {finding['evidence']}")
                if finding.get("remediation"):
                    lines.append("")
                    lines.append(f"Fix: {finding['remediation']}")
                lines.append("")
        if engagement.get("notes"):
            lines.extend(["## Notes", ""])
            for note in engagement["notes"]:
                lines.append(f"- {note.get('at')}: {note.get('note')}")
        lines.append("")
        return "\n".join(lines)

    def _require(self, engagement_id: str) -> dict:
        engagement = self._items.get(engagement_id)
        if engagement is None:
            raise KeyError(engagement_id)
        return engagement
