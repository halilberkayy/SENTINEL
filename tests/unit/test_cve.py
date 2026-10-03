"""Tests for OSV-based CVE enrichment (dependency extraction + alert mapping)."""

import pytest

from src.core.cve import cve_alerts_from_results, extract_dependencies


def test_extract_dependencies_dedups_and_ignores_non_deps():
    results = [
        {
            "module_name": "dep",
            "vulnerabilities": [
                {"title": "x", "evidence": {"library": "jquery", "version": "1.8.0", "ecosystem": "npm"}},
                {"title": "y", "evidence": {"library": "jquery", "version": "1.8.0", "ecosystem": "npm"}},  # dup
                {"title": "z", "evidence": {"name": "lodash", "version": "4.17.0", "ecosystem": "npm"}},
                {"title": "not-a-dep", "evidence": {"url": "https://x"}},
            ],
        }
    ]
    deps = extract_dependencies(results)
    assert sorted(d["name"] for d in deps) == ["jquery", "lodash"]


@pytest.mark.asyncio
async def test_cve_alerts_from_results(monkeypatch):
    import src.core.cve as cve

    results = [
        {
            "module_name": "dep",
            "vulnerabilities": [
                {"title": "x", "evidence": {"library": "jquery", "version": "1.8.0", "ecosystem": "npm"}},
            ],
        }
    ]

    async def fake_query(packages):
        return [["GHSA-xxxx", "CVE-2020-11022"]]

    monkeypatch.setattr(cve, "query_osv", fake_query)
    alerts = await cve.cve_alerts_from_results(results, "https://target")
    assert len(alerts) == 1
    assert alerts[0].category == "cve"
    assert "jquery" in alerts[0].title


@pytest.mark.asyncio
async def test_cve_alerts_empty_without_dependencies():
    out = await cve_alerts_from_results([{"module_name": "x", "vulnerabilities": []}], "target")
    assert out == []
