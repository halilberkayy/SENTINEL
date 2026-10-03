"""
Port Scanner module for discovering open services.
Non-intrusive async port scanner for common services.
"""

import asyncio
import logging
import socket
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class PortScanner(BaseScanner):
    """
    Async Port Scanner for service discovery.
    Scans top common ports to identify running services.
    """

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "PortScanner"
        self.description = "Scans for open ports and services"
        self.version = "1.0.0"
        self.capabilities = ["Service Discovery", "Banner Grabbing", "Common Ports"]

        # Common ports to scan
        self.common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            111: "RPC",
            135: "RPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8000: "HTTP-Alt",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt",
            9200: "Elasticsearch",
            27017: "MongoDB",
        }

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform port scan."""
        parsed = urlparse(url)
        hostname = parsed.hostname or urlparse(f"http://{url}").hostname

        if not hostname:
            return self._format_result("Error", "Invalid hostname", [])

        logger.info(f"Scanning ports for {hostname}")

        open_ports = []
        vulnerabilities = []

        try:
            self._update_progress(progress_callback, 10, f"Resolving {hostname}")
            # Verify host is resolvable
            try:
                await asyncio.get_event_loop().run_in_executor(None, socket.gethostbyname, hostname)
            except socket.gaierror:
                return self._format_result("Error", f"Could not resolve hostname: {hostname}", [])

            total_ports = len(self.common_ports)
            batch_size = 10  # Scan in small batches to be polite
            ports_list = list(self.common_ports.items())

            for i in range(0, total_ports, batch_size):
                batch = ports_list[i : i + batch_size]
                progress = 20 + int((i / total_ports) * 70)
                self._update_progress(progress_callback, progress, f"Scanning ports {batch[0][0]}-{batch[-1][0]}")

                tasks = [self._check_port(hostname, port, service) for port, service in batch]
                results = await asyncio.gather(*tasks)

                for result in results:
                    if result:
                        open_ports.append(result)

            # Create vulnerabilities for risky services
            for port_info in open_ports:
                port = port_info["port"]
                service = port_info["service"]

                severity = "info"
                desc = f"Port {port} ({service}) is open."

                # Flag risky services
                risky_ports = {
                    21: "Unencrypted FTP found. Ensure anonymous access is disabled.",
                    23: "Telnet service found. This protocol is unencrypted and insecure.",
                    3389: "RDP exposed to the internet. Potential brute-force target.",
                    3306: "MySQL database exposed. Ensure strict firewall rules.",
                    5432: "PostgreSQL database exposed. Ensure strict firewall rules.",
                    6379: "Redis exposed. Check for unauthenticated access.",
                    27017: "MongoDB exposed. Check for unauthenticated access.",
                }

                if port in risky_ports:
                    severity = "medium" if port not in [23] else "high"
                    vulnerabilities.append(
                        self._create_vulnerability(
                            title=f"Open Port: {service} ({port})",
                            description=risky_ports[port],
                            severity=severity,
                            type="open_port",
                            evidence={"port": port, "service": service},
                            cwe_id="CWE-284",
                            remediation="Restrict access to this port via firewall rules (whitelist IPs) or use VPN.",
                        )
                    )
                else:
                    # Informational finding for other ports
                    vulnerabilities.append(
                        self._create_vulnerability(
                            title=f"Open Service: {service}",
                            description=desc,
                            severity="info",
                            type="open_port",
                            evidence={"port": port, "service": service},
                            cwe_id="CWE-200",
                            remediation="Ensure this service is intended to be public.",
                        )
                    )

            self._update_progress(progress_callback, 100, "completed")

            status = "Vulnerable" if any(v.severity in ["high", "medium"] for v in vulnerabilities) else "Clean"
            if not vulnerabilities and open_ports:
                status = "Info"

            return self._format_result(status, f"Found {len(open_ports)} open ports.", vulnerabilities)

        except Exception as e:
            logger.exception(f"Port scan failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])

    async def _check_port(self, host: str, port: int, service: str) -> dict | None:
        """Check a single port."""
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=1.0)
            writer.close()
            await writer.wait_closed()
            return {"port": port, "service": service}
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None
        except Exception:
            return None
