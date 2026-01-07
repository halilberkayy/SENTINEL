"""
Nmap Integration Module - Professional network scanning via nmap.
Provides service detection, OS fingerprinting, and vulnerability scanning.
"""

import logging
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class NmapScanner(BaseScanner):
    """
    Advanced Nmap integration for network reconnaissance.
    Requires nmap to be installed on the system.
    """

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "NmapScanner"
        self.description = "Network scanning and service detection via Nmap"
        self.version = "1.0.0"
        self.author = "SENTINEL Team"
        self.capabilities = [
            "Port Scanning",
            "Service Detection",
            "OS Fingerprinting",
            "Script Scanning (NSE)",
            "Vulnerability Detection",
        ]

        # Scan profiles
        self.scan_profiles = {
            "quick": "-sV -T4 --top-ports 100",
            "standard": "-sV -sC -T4 --top-ports 1000",
            "comprehensive": "-sV -sC -O -T4 -p-",
            "stealth": "-sS -T2 -f --data-length 24",
            "vuln": "-sV --script vuln -T4",
            "aggressive": "-A -T4 -p-",
        }

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Execute Nmap scan against target."""
        from ..utils.command_runner import ExternalCommandRunner

        parsed = urlparse(url)
        hostname = parsed.hostname or urlparse(f"http://{url}").hostname

        if not hostname:
            return self._format_result("Error", "Invalid hostname", [])

        runner = ExternalCommandRunner(timeout=600)  # 10 min timeout for nmap

        # Check if nmap is available
        if not runner.check_tool_available("nmap"):
            return self._format_result(
                "Skipped",
                "Nmap is not installed. Install with: brew install nmap (macOS) or apt install nmap (Linux)",
                [],
            )

        logger.info(f"Starting Nmap scan on {hostname}")
        self._update_progress(progress_callback, 10, "Initializing Nmap scan")

        vulnerabilities = []
        scan_results = {}

        try:
            # Phase 1: Quick service detection
            self._update_progress(progress_callback, 20, "Running service detection")

            quick_args = ["-sV", "-T4", "--top-ports", "100", "-oX", "-", hostname]  # XML output to stdout

            result = await runner.run_tool("nmap", quick_args)

            if not result.success:
                if not result.tool_available:
                    return self._format_result("Skipped", "Nmap not available", [])
                return self._format_result("Error", f"Nmap failed: {result.stderr}", [])

            # Parse nmap output
            scan_results = self._parse_nmap_output(result.stdout)

            self._update_progress(progress_callback, 50, f"Found {len(scan_results.get('ports', []))} open ports")

            # Phase 2: Vulnerability scripts on discovered services
            open_ports = scan_results.get("ports", [])

            if open_ports:
                self._update_progress(progress_callback, 60, "Running vulnerability scripts")

                port_list = ",".join([str(p["port"]) for p in open_ports[:20]])  # Limit to 20 ports

                vuln_args = ["-sV", "--script", "vuln,auth,default", "-p", port_list, "-oX", "-", hostname]

                vuln_result = await runner.run_tool("nmap", vuln_args, timeout=300)

                if vuln_result.success:
                    vuln_findings = self._parse_nse_vulnerabilities(vuln_result.stdout)
                    vulnerabilities.extend(vuln_findings)

            # Generate vulnerabilities from open services
            for port_info in open_ports:
                vuln = self._analyze_service(port_info)
                if vuln:
                    vulnerabilities.append(vuln)

            self._update_progress(progress_callback, 100, "completed")

            status = "Vulnerable" if any(v.severity in ["critical", "high"] for v in vulnerabilities) else "Clean"
            if vulnerabilities and status == "Clean":
                status = "Info"

            return self._format_result(
                status,
                f"Scanned {hostname}: {len(open_ports)} open ports, {len(vulnerabilities)} findings",
                vulnerabilities,
                evidence={
                    "hostname": hostname,
                    "ports": open_ports,
                    "os_detection": scan_results.get("os", "Unknown"),
                    "scan_info": scan_results.get("info", {}),
                },
            )

        except Exception as e:
            logger.exception(f"Nmap scan failed: {e}")
            return self._format_result("Error", f"Scan error: {e}", [])

    def _parse_nmap_output(self, xml_output: str) -> dict[str, Any]:
        """Parse nmap XML output."""
        import re

        results = {"ports": [], "os": "Unknown", "info": {}}

        # Parse ports (simple regex for XML)
        port_pattern = r'<port protocol="(\w+)" portid="(\d+)".*?<state state="(\w+)".*?<service name="([^"]*)"(?:.*?product="([^"]*)")?(?:.*?version="([^"]*)")?'

        for match in re.finditer(port_pattern, xml_output, re.DOTALL):
            protocol, port, state, service, product, version = match.groups()

            if state == "open":
                results["ports"].append(
                    {
                        "port": int(port),
                        "protocol": protocol,
                        "service": service or "unknown",
                        "product": product or "",
                        "version": version or "",
                        "state": state,
                    }
                )

        # Parse OS detection
        os_match = re.search(r'<osmatch name="([^"]+)"', xml_output)
        if os_match:
            results["os"] = os_match.group(1)

        # Parse host info
        hostname_match = re.search(r'<hostname name="([^"]+)"', xml_output)
        if hostname_match:
            results["info"]["hostname"] = hostname_match.group(1)

        return results

    def _parse_nse_vulnerabilities(self, xml_output: str) -> list:
        """Parse NSE script output for vulnerabilities."""
        vulnerabilities = []

        # Parse script output
        script_pattern = r'<script id="([^"]+)".*?output="([^"]*)"'

        vuln_scripts = ["http-vuln-", "ssl-", "smb-vuln-", "rdp-vuln-", "ftp-vuln-", "ssh-", "mysql-vuln-", "ms-sql-"]

        for match in re.finditer(script_pattern, xml_output, re.DOTALL):
            script_id, output = match.groups()

            # Check if it's a vulnerability script
            if any(v in script_id for v in vuln_scripts):
                if "VULNERABLE" in output.upper() or "vulnerable" in output.lower():
                    severity = self._determine_script_severity(script_id)

                    vulnerabilities.append(
                        self._create_vulnerability(
                            title=f"Nmap NSE: {script_id}",
                            description=output[:500] if output else f"Vulnerability detected by {script_id}",
                            severity=severity,
                            type="nmap_nse_finding",
                            evidence={"script": script_id, "output": output[:1000]},
                            cwe_id="CWE-200",
                            remediation="Review the specific vulnerability and apply vendor patches.",
                        )
                    )

        return vulnerabilities

    def _determine_script_severity(self, script_id: str) -> str:
        """Determine severity based on NSE script type."""
        critical_patterns = ["ms17-010", "eternalblue", "heartbleed", "shellshock"]
        high_patterns = ["vuln", "rce", "sqli", "auth-bypass"]
        medium_patterns = ["ssl", "tls", "weak", "deprecated"]

        script_lower = script_id.lower()

        if any(p in script_lower for p in critical_patterns):
            return "critical"
        elif any(p in script_lower for p in high_patterns):
            return "high"
        elif any(p in script_lower for p in medium_patterns):
            return "medium"
        return "low"

    def _analyze_service(self, port_info: dict) -> Any:
        """Analyze a service for security implications."""
        port = port_info["port"]
        service = port_info["service"].lower()
        product = port_info.get("product", "").lower()
        version = port_info.get("version", "")

        # High-risk services
        high_risk = {
            "telnet": ("Telnet Exposed", "Unencrypted remote access protocol", "high"),
            "ftp": ("FTP Service Exposed", "File transfer may be unencrypted", "medium"),
            "rsh": ("RSH Service Exposed", "Insecure remote shell", "critical"),
            "rlogin": ("Rlogin Exposed", "Insecure remote login", "critical"),
            "vnc": ("VNC Exposed", "Remote desktop service exposed", "high"),
            "rdp": ("RDP Exposed", "Windows Remote Desktop exposed", "high"),
            "ms-wbt-server": ("RDP Exposed", "Windows Remote Desktop exposed", "high"),
        }

        # Database services
        db_services = {
            "mysql": ("MySQL Exposed", "Database service exposed to network", "high"),
            "postgresql": ("PostgreSQL Exposed", "Database service exposed", "high"),
            "mongodb": ("MongoDB Exposed", "NoSQL database exposed", "high"),
            "redis": ("Redis Exposed", "In-memory store exposed", "high"),
            "elasticsearch": ("Elasticsearch Exposed", "Search engine exposed", "high"),
            "memcached": ("Memcached Exposed", "Cache service exposed", "medium"),
            "ms-sql-s": ("MSSQL Exposed", "Microsoft SQL Server exposed", "high"),
        }

        # Check high risk
        if service in high_risk:
            title, desc, severity = high_risk[service]
            return self._create_vulnerability(
                title=f"{title} (Port {port})",
                description=f"{desc}. Product: {product} {version}".strip(),
                severity=severity,
                type="exposed_service",
                evidence=port_info,
                cwe_id="CWE-284",
                remediation="Restrict access via firewall, use VPN, or disable if not needed.",
            )

        # Check databases
        if service in db_services:
            title, desc, severity = db_services[service]
            return self._create_vulnerability(
                title=f"{title} (Port {port})",
                description=f"{desc}. Product: {product} {version}".strip(),
                severity=severity,
                type="exposed_database",
                evidence=port_info,
                cwe_id="CWE-284",
                remediation="Database should not be directly exposed. Use firewall rules and require authentication.",
            )

        # Check for outdated versions (simple heuristic)
        if version and self._is_outdated_version(product, version):
            return self._create_vulnerability(
                title=f"Potentially Outdated: {product} {version}",
                description=f"Service {service} on port {port} may be running an outdated version.",
                severity="medium",
                type="outdated_software",
                evidence=port_info,
                cwe_id="CWE-1104",
                remediation="Update to the latest stable version.",
            )

        return None

    def _is_outdated_version(self, product: str, version: str) -> bool:
        """Simple heuristic to detect potentially outdated versions."""
        # This is a simplified check - in production, use a CVE database
        old_indicators = ["1.0", "2.0", "3.0", "4.0", "5.0", "5.5", "5.6", "5.7"]

        for indicator in old_indicators:
            if version.startswith(indicator):
                return True
        return False
