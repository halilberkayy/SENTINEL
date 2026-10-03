"""Tests for auto-orchestration: signal extraction, follow-up planning, and the
engine's chaining loop that turns discoveries into follow-on scans."""

import pytest

from src.core.config import Config
from src.core.orchestration import extract_signals, plan_followups
from src.core.scanner_engine import ScannerEngine, ScanResult


def test_extract_signals_from_results():
    results = [
        {"module_name": "graphql_scanner", "details": "Found /graphql endpoint", "vulnerabilities": []},
        {
            "module_name": "recon",
            "details": "",
            "vulnerabilities": [{"title": "Exposed Token", "type": "jwt", "evidence": {"snippet": "eyJhbGciOi"}}],
        },
    ]
    signals = extract_signals(results)
    assert "graphql" in signals
    assert "jwt" in signals
    assert "aws" not in signals


def test_plan_followups_filters_dedups_and_skips_unregistered():
    registry = {m: object() for m in ["graphql_scanner", "jwt_scanner", "rate_limit_scanner"]}
    followups = plan_followups({"api", "graphql"}, already_run={"graphql_scanner"}, registry=registry)
    assert "graphql_scanner" not in followups  # already ran
    assert "jwt_scanner" in followups and "rate_limit_scanner" in followups
    assert "broken_access_control_scanner" not in followups  # not in this registry
    assert len(followups) == len(set(followups))  # deduped


class _FakeHTTP:
    async def start(self):
        pass

    async def close(self):
        pass

    def bind_scope(self, url, domains):
        pass

    async def get(self, url, **kwargs):
        class R:
            status = 200
            headers: dict = {}
            url = "https://example.com/"

        return R()


@pytest.mark.asyncio
async def test_engine_auto_chaining_triggers_followups(monkeypatch):
    eng = ScannerEngine(Config())
    eng.http_client = _FakeHTTP()
    monkeypatch.setattr(eng.config, "validate_target", lambda u: True)
    # Don't really import/instantiate triggered module classes.
    monkeypatch.setattr(eng, "_instantiate_module", lambda mid: object())

    async def fake_run_module(module_id, url, progress_callback):
        # The seed recon surfaces a JWT signal; that should trigger jwt_scanner.
        vulns = []
        if module_id == "recon_scanner":
            vulns = [{"title": "JWT in response", "type": "jwt", "evidence": {"snippet": "eyJhbGciOi"}}]
        return ScanResult(module_name=module_id, status="Completed", details="", vulnerabilities=vulns)

    monkeypatch.setattr(eng, "_run_module", fake_run_module)

    results = await eng.scan_target("https://example.com/", module_names=["recon_scanner"], auto=True)
    ran = {r.module_name for r in results}
    assert "recon_scanner" in ran
    assert "jwt_scanner" in ran  # chained in from the jwt signal
