"""Service discovery for an authorized engagement.

The command is fixed: version detection on the top 100 TCP ports.
No script scan, no SYN stealth flags, no OS fingerprint, no full-port sweep.
"""

import logging
import re
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

NMAP_DISCOVERY_ARGS = ("-sV", "-T4", "--top-ports", "100", "-oX", "-")
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


def target_host(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Target must be an http(s) URL.")
    host = parsed.hostname.lower().rstrip(".")
    if not _HOST_RE.fullmatch(host) or host.startswith("-") or ".." in host:
        raise ValueError("Target host is not a plain hostname or IPv4 address.")
    return host


def _attr(text: str, name: str) -> str:
    found = re.search(rf'\b{name}="([^"]*)"', text)
    return found.group(1) if found else ""


def services_from_nmap_xml(xml_text: str) -> list[dict]:
    """Read open ports from nmap XML without an XML entity parser."""
    if "<nmaprun" not in xml_text:
        raise ValueError("Nmap did not return XML.")
    services = []
    for match in re.finditer(r"<port\b([^>]*)>(.*?)</port>", xml_text, re.DOTALL):
        attrs, body = match.group(1), match.group(2)
        if not re.search(r'<state\b[^>]*\bstate="open"', body):
            continue
        service_tag = re.search(r"<service\b([^>]*)/?>", body)
        service_attrs = service_tag.group(1) if service_tag else ""
        services.append(
            {
                "port": int(_attr(attrs, "portid") or 0),
                "protocol": _attr(attrs, "protocol") or "tcp",
                "service": _attr(service_attrs, "name"),
                "product": _attr(service_attrs, "product"),
                "version": _attr(service_attrs, "version"),
            }
        )
    return services


def service_findings(target: str, services: list[dict]) -> list[dict]:
    findings = []
    for service in services:
        name = service.get("service") or "unknown"
        banner = " ".join(part for part in (service.get("product"), service.get("version")) if part)
        findings.append(
            {
                "title": f"Open {name} on {service.get('protocol')}/{service.get('port')}",
                "description": "Service detected. An open port is not by itself a vulnerability.",
                "severity": "info",
                "module": "nmap",
                "target": target,
                "remediation": "Close the port if the service is not required, and keep the software current.",
                "evidence": {
                    "port": service.get("port"),
                    "protocol": service.get("protocol"),
                    "service": name,
                    "product": service.get("product") or "",
                    "version": service.get("version") or "",
                    "url": target,
                },
            }
        )
        if banner:
            findings[-1]["description"] += f" Banner: {banner}."
    return findings


async def discover_services(host: str) -> dict:
    """Run the fixed nmap command. A missing binary is a skip, not a failure of the engagement."""
    from src.utils.command_runner import ExternalCommandRunner

    if not _HOST_RE.fullmatch(host):
        raise ValueError("Refusing to pass this host to nmap.")
    runner = ExternalCommandRunner(timeout=180)
    if not runner.check_tool_available("nmap"):
        return {"status": "skipped", "services": [], "detail": "Nmap is not installed."}

    args = [*NMAP_DISCOVERY_ARGS, host]
    result = await runner.run_tool("nmap", args)
    if not result.success:
        detail = (result.stderr or "Nmap failed.").strip().splitlines()
        return {"status": "error", "services": [], "detail": (detail[-1] if detail else "Nmap failed.")[:300]}
    try:
        services = services_from_nmap_xml(result.stdout)
    except ValueError as exc:
        logger.warning("Nmap XML parse failed: %s", exc)
        return {"status": "error", "services": [], "detail": "Nmap output was not usable."}
    return {"status": "ok", "services": services, "detail": f"{len(services)} open services."}
