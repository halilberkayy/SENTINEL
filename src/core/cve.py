"""CVE enrichment via OSV.dev.

Libraries a scan detected (name, version, ecosystem) are checked against OSV's
free, key-less vulnerability database. Matches become CVE alerts. Network or API
failures degrade gracefully: no CVEs are added and the scan is unaffected.
"""

from typing import Any

import aiohttp
import structlog

from src.core.alerting import Alert

logger = structlog.get_logger()

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

# Module ecosystem labels -> the names OSV expects.
_ECOSYSTEM_MAP = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "composer": "Packagist",
    "go": "Go",
    "rubygems": "RubyGems",
    "nuget": "NuGet",
}


def extract_dependencies(results: Any) -> list[dict]:
    """Pull {ecosystem, name, version} from findings that carry them (the
    dependency and supply-chain modules put these in evidence). De-duplicated."""
    deps: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for result in results:
        vulns = getattr(result, "vulnerabilities", None)
        if vulns is None and isinstance(result, dict):
            vulns = result.get("vulnerabilities", [])
        for v in vulns or []:
            evidence = v.get("evidence", {}) if isinstance(v, dict) else getattr(v, "evidence", {})
            if not isinstance(evidence, dict):
                continue
            name = evidence.get("library") or evidence.get("name")
            version = evidence.get("version")
            ecosystem = evidence.get("ecosystem")
            if name and version and ecosystem:
                key = (str(ecosystem).lower(), str(name).lower(), str(version))
                if key not in seen:
                    seen.add(key)
                    deps.append({"ecosystem": str(ecosystem), "name": str(name), "version": str(version)})
    return deps


async def query_osv(packages: list[dict]) -> list[list[str]]:
    """Return, per package (same order), the list of OSV vulnerability ids. Empty
    lists on any failure, so callers never have to handle exceptions."""
    if not packages:
        return []
    queries = []
    for pkg in packages:
        ecosystem = _ECOSYSTEM_MAP.get(str(pkg["ecosystem"]).lower(), pkg["ecosystem"])
        queries.append({"version": pkg["version"], "package": {"ecosystem": ecosystem, "name": pkg["name"]}})
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                OSV_BATCH_URL, json={"queries": queries}, timeout=aiohttp.ClientTimeout(total=15)
            ) as resp:
                if resp.status != 200:
                    logger.warning("OSV query returned non-200", status=resp.status)
                    return [[] for _ in packages]
                data = await resp.json()
    except Exception as exc:
        logger.warning("OSV query failed", error=str(exc))
        return [[] for _ in packages]

    results = data.get("results", []) or []
    out: list[list[str]] = []
    for i in range(len(packages)):
        entry = results[i] if i < len(results) else {}
        vulns = entry.get("vulns") or []
        out.append([v.get("id") for v in vulns if v.get("id")])
    return out


async def cve_alerts_from_results(results: Any, target: str) -> list[Alert]:
    """Detect libraries in the results, check OSV, and return one CVE alert per
    vulnerable package. Returns [] when nothing is found or OSV is unreachable."""
    deps = extract_dependencies(results)
    if not deps:
        return []
    vuln_lists = await query_osv(deps)
    alerts: list[Alert] = []
    for dep, ids in zip(deps, vuln_lists, strict=False):
        if not ids:
            continue
        alerts.append(
            Alert(
                severity="high",
                category="cve",
                title=f"{dep['name']} {dep['version']}: {', '.join(ids[:5])}",
                target=target,
                module="osv",
                detail=f"{len(ids)} advisory(ies) via OSV",
            )
        )
    return alerts
