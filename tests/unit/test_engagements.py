"""Engagement scope, service discovery, and the scan/verify/report record."""

import pytest

from src.core.discovery import NMAP_DISCOVERY_ARGS, discover_services, services_from_nmap_xml, target_host
from src.core.engagements import EngagementStore, evidence_line, host_in_domains, normalize_domain

SAMPLE_XML = """<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.25"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_discovery_command_is_version_detection_only():
    assert "-sV" in NMAP_DISCOVERY_ARGS
    assert "--script" not in NMAP_DISCOVERY_ARGS
    assert "-sS" not in NMAP_DISCOVERY_ARGS
    assert "-A" not in NMAP_DISCOVERY_ARGS
    assert "-O" not in NMAP_DISCOVERY_ARGS


def test_open_services_are_parsed_and_closed_ports_are_not():
    services = services_from_nmap_xml(SAMPLE_XML)
    assert services == [{"port": 443, "protocol": "tcp", "service": "https", "product": "nginx", "version": "1.25"}]


def test_bad_nmap_xml_is_rejected():
    with pytest.raises(ValueError):
        services_from_nmap_xml("not xml")


def test_host_must_be_plain():
    assert target_host("https://example.com/path") == "example.com"
    with pytest.raises(ValueError):
        target_host("https://-example.com")
    with pytest.raises(ValueError):
        target_host("file:///etc/passwd")


def test_scope_matches_subdomains_not_lookalikes():
    domains = [normalize_domain("*.example.com")]
    assert domains == ["example.com"]
    assert host_in_domains("www.example.com", domains)
    assert not host_in_domains("example.com.evil.net", domains)
    assert not host_in_domains("notexample.com", domains)


def test_evidence_line_drops_payloads():
    assert "secret" not in evidence_line({"payload": "secret", "port": 443, "service": "https"})
    assert "443" in evidence_line({"payload": "secret", "port": 443, "service": "https"})


def test_engagement_persists_and_dedupes_findings(tmp_path):
    path = tmp_path / "engagements.json"
    store = EngagementStore(path)
    engagement = store.create("Example", ["example.com"], "authorized")
    store.add_findings(
        engagement["id"],
        [
            {"title": "Missing HSTS", "severity": "high", "module": "headers", "target": "https://example.com"},
            {"title": "Missing HSTS", "severity": "high", "module": "headers", "target": "https://example.com"},
        ],
    )
    reloaded = EngagementStore(path)
    saved = reloaded.get(engagement["id"])
    assert saved is not None
    assert len(saved["findings"]) == 1
    text = reloaded.markdown(engagement["id"])
    assert "Missing HSTS" in text
    assert "poc" not in text.lower()


@pytest.mark.asyncio
async def test_missing_nmap_is_a_skip(monkeypatch):
    class Runner:
        def __init__(self, timeout=0):
            pass

        def check_tool_available(self, name):
            return None

    monkeypatch.setattr("src.utils.command_runner.ExternalCommandRunner", Runner)
    result = await discover_services("example.com")
    assert result["status"] == "skipped"
    assert result["services"] == []


def test_api_rejects_out_of_scope_before_scanning(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_ENGAGEMENT_FILE", str(tmp_path / "engagements.json"))
    monkeypatch.setenv("SENTINEL_REPORT_DIR", str(tmp_path / "reports"))
    from fastapi.testclient import TestClient

    from src.web.app import app

    client = TestClient(app)
    created = client.post(
        "/api/v1/engagements",
        json={"name": "Example", "allowed_domains": ["*.example.com"], "description": "test"},
    )
    assert created.status_code == 201
    engagement_id = created.json()["id"]
    assert created.json()["allowed_domains"] == ["example.com"]

    denied = client.post(
        f"/api/v1/engagements/{engagement_id}/scan",
        json={"url": "https://evil.example/admin"},
    )
    assert denied.status_code == 400
    assert "scope" in denied.json()["detail"]

    report = client.get(f"/api/v1/engagements/{engagement_id}/report")
    assert report.status_code == 200
    assert "No services recorded." in report.json()["markdown"]
    assert "Phase: reported" in report.json()["markdown"]
    assert (tmp_path / "reports" / f"{engagement_id}.md").exists()
