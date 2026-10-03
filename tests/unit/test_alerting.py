"""Tests for the alerting engine: which findings alert, and dispatch behavior."""

import pytest

from src.core.alerting import ALERT_WEBHOOK_ENV, Alert, classify_alerts, dispatch_alerts


def _result(module, vulns):
    return {"module_name": module, "vulnerabilities": vulns}


def test_classify_alerts_selects_only_serious_firm_findings():
    results = [
        _result(
            "x",
            [
                {"title": "SQLi", "type": "sqli", "severity": "critical", "confidence": "firm"},
                {"title": "Missing header", "type": "missing_header", "severity": "low", "confidence": "firm"},
                {"title": "IDOR on /users", "type": "broken_access", "severity": "medium", "confidence": "firm"},
                {
                    "title": "Vulnerable jquery",
                    "type": "vulnerable_component",
                    "severity": "high",
                    "evidence": {"cve": "CVE-2020-11022"},
                    "confidence": "firm",
                },
                {"title": "Tentative critical", "type": "x", "severity": "critical", "confidence": "tentative"},
            ],
        )
    ]
    alerts = classify_alerts(results, "https://target")
    # low -> skipped, tentative -> skipped; the rest classify by category.
    assert sorted(a.category for a in alerts) == ["critical", "cve", "privilege-escalation"]


@pytest.mark.asyncio
async def test_dispatch_no_alerts_is_noop():
    summary = await dispatch_alerts([], scan_id="s")
    assert summary["alerts"] == 0


@pytest.mark.asyncio
async def test_dispatch_opens_incidents_without_webhook(monkeypatch):
    import src.core.alerting as al

    monkeypatch.delenv(ALERT_WEBHOOK_ENV, raising=False)
    monkeypatch.setattr(al, "_open_incidents", lambda alerts, scan_id: len(alerts))
    summary = await al.dispatch_alerts([Alert("critical", "critical", "x", "target")], scan_id="s")
    assert summary == {"alerts": 1, "webhook": "not configured", "incidents": 1}
