"""Alerting: turn the serious things a scan finds into alerts that leave the tool.

A finding sitting in a report is passive. An alert is pushed: to a webhook (Slack,
Discord, a SIEM, anything that takes JSON) and to the Blue Team incident tracker,
so a privilege-escalation hole or a known CVE is acted on, not just logged.

Only high-confidence findings alert. A ``tentative`` finding stays in the report
but does not page anyone, so alerts do not cry wolf.
"""

import os
from dataclasses import asdict, dataclass
from typing import Any

import aiohttp
import structlog

logger = structlog.get_logger()

ALERT_WEBHOOK_ENV = "SENTINEL_ALERT_WEBHOOK"

# Finding type/title markers that mean a privilege-escalation class issue, which
# alerts regardless of the severity the module assigned it.
_PRIVESC_MARKERS = (
    "privilege escalation",
    "privilege-escalation",
    "privesc",
    "idor",
    "broken access",
    "insecure direct object",
    "authorization bypass",
    "auth bypass",
    "authentication bypass",
    "cross-tenant",
)


@dataclass
class Alert:
    severity: str
    category: str  # "critical" | "privilege-escalation" | "cve"
    title: str
    target: str
    module: str = ""
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _as_vuln_dicts(result: Any) -> tuple[str, list[dict]]:
    module = getattr(result, "module_name", None)
    vulns = getattr(result, "vulnerabilities", None)
    if module is None and isinstance(result, dict):
        module = result.get("module_name", "")
        vulns = result.get("vulnerabilities", [])
    out = []
    for v in vulns or []:
        if isinstance(v, dict):
            out.append(v)
        else:
            out.append(
                {
                    "title": getattr(v, "title", ""),
                    "type": getattr(v, "type", ""),
                    "severity": getattr(v, "severity", ""),
                    "evidence": getattr(v, "evidence", {}),
                    "confidence": getattr(v, "confidence", "firm"),
                }
            )
    return module or "", out


def classify_alerts(results: Any, target: str) -> list[Alert]:
    """Pick the alert-worthy findings: known CVEs, privilege-escalation issues, and
    anything critical. Tentative-confidence findings are skipped so alerts stay trustworthy."""
    alerts: list[Alert] = []
    for result in results:
        module, vulns = _as_vuln_dicts(result)
        for v in vulns:
            if str(v.get("confidence", "firm")) != "firm":
                continue  # uncertain finding: in the report, but not an alert
            severity = str(v.get("severity", "")).lower()
            text = f"{v.get('title', '')} {v.get('type', '')}".lower()
            evidence_text = str(v.get("evidence", "")).lower()

            if "cve-" in text or "cve-" in evidence_text or v.get("type") == "cve":
                category = "cve"
            elif any(marker in text for marker in _PRIVESC_MARKERS):
                category = "privilege-escalation"
            elif severity == "critical":
                category = "critical"
            else:
                continue

            alerts.append(
                Alert(
                    severity=severity or "high",
                    category=category,
                    title=str(v.get("title", "Security finding")),
                    target=target,
                    module=module,
                )
            )
    return alerts


async def _post_webhook(url: str, alerts: list[Alert]) -> str:
    payload = {"source": "SENTINEL", "alert_count": len(alerts), "alerts": [a.to_dict() for a in alerts]}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                return f"sent ({resp.status})"
    except Exception as exc:  # network / timeout / bad URL: never break the scan
        logger.warning("Alert webhook failed", error=str(exc))
        return "failed"


def _open_incidents(alerts: list[Alert], scan_id: str | None) -> int:
    from src.blueteam.incident_tracker import IncidentTracker

    tracker = IncidentTracker()
    opened = 0
    for alert in alerts:
        try:
            tracker.create(
                title=f"[{alert.category}] {alert.title}",
                description=f"Alert from scan of {alert.target} (module: {alert.module}).",
                severity=alert.severity,
                category="vulnerability",
                source="alerting",
                scan_id=scan_id,
                tags=[alert.category],
            )
            opened += 1
        except Exception as exc:
            logger.warning("Failed to open incident for alert", error=str(exc))
    return opened


async def dispatch_alerts(alerts: list[Alert], scan_id: str | None = None) -> dict[str, Any]:
    """Send alerts to the webhook (if configured) and open a Blue Team incident for
    each. Always safe to call; failures are logged, not raised."""
    if not alerts:
        return {"alerts": 0, "webhook": "no alerts", "incidents": 0}

    webhook_url = os.getenv(ALERT_WEBHOOK_ENV)
    webhook_status = await _post_webhook(webhook_url, alerts) if webhook_url else "not configured"
    incidents = _open_incidents(alerts, scan_id)
    return {"alerts": len(alerts), "webhook": webhook_status, "incidents": incidents}
