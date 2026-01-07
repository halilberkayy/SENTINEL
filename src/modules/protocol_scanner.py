"""
STDIO/Protocol Scanner - Multi-protocol scanning capabilities.
Supports HTTP, HTTPS, and raw TCP analysis.
"""

import asyncio
import logging
import ssl
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class ProtocolScanner(BaseScanner):
    """Multi-protocol security scanner with STDIO support."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "ProtocolScanner"
        self.description = "Multi-protocol security analysis (HTTP/HTTPS/TCP)"
        self.version = "1.0.0"
        self.capabilities = ["Protocol Detection", "SSL/TLS Analysis", "Banner Grabbing"]

        self.protocol_ports = {
            "http": [80, 8080, 8000, 8888],
            "https": [443, 8443],
            "ftp": [21],
            "ssh": [22],
            "telnet": [23],
            "smtp": [25, 587],
            "mysql": [3306],
            "redis": [6379],
            "mongodb": [27017],
        }

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform multi-protocol scan."""
        self._update_progress(progress_callback, 10, "Analyzing protocols")
        vulnerabilities = []
        findings = []

        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or url

            # SSL/TLS Analysis
            if parsed.scheme == "https" or parsed.port == 443:
                ssl_issues = await self._analyze_ssl(hostname, parsed.port or 443)
                findings.extend(ssl_issues)

                for issue in ssl_issues:
                    if issue.get("severity") in ["high", "critical"]:
                        vulnerabilities.append(
                            self._create_vulnerability(
                                title=issue["title"],
                                description=issue["description"],
                                severity=issue["severity"],
                                type="ssl_tls_vulnerability",
                                evidence=issue,
                                cwe_id="CWE-295",
                            )
                        )

            # Banner grabbing on common ports
            self._update_progress(progress_callback, 50, "Grabbing service banners")
            banners = await self._grab_banners(hostname)
            findings.extend(banners)

            for banner in banners:
                if banner.get("vulnerable"):
                    vulnerabilities.append(
                        self._create_vulnerability(
                            title=f"Vulnerable Service: {banner['service']}",
                            description=banner.get("issue", "Potential security issue detected"),
                            severity=banner.get("severity", "medium"),
                            type="vulnerable_service",
                            evidence=banner,
                            cwe_id="CWE-200",
                        )
                    )

            self._update_progress(progress_callback, 100, "completed")

            return self._format_result(
                "Vulnerable" if vulnerabilities else "Clean",
                f"Analyzed {len(findings)} protocol findings",
                vulnerabilities,
                {"findings": findings},
            )

        except Exception as e:
            return self._format_result("Error", str(e), [])

    async def _analyze_ssl(self, hostname: str, port: int = 443) -> list[dict]:
        """Analyze SSL/TLS configuration."""
        issues = []

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(asyncio.open_connection(hostname, port, ssl=context), timeout=10)

            ssl_obj = writer.get_extra_info("ssl_object")

            if ssl_obj:
                version = ssl_obj.version()
                cipher = ssl_obj.cipher()

                # Check for weak protocols
                weak_protocols = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"]
                if version in weak_protocols:
                    issues.append(
                        {
                            "title": f"Weak TLS Version: {version}",
                            "description": f"Server supports outdated {version}",
                            "severity": "high" if "SSL" in version else "medium",
                            "type": "weak_tls",
                        }
                    )

                # Check cipher strength
                if cipher and cipher[2] < 128:
                    issues.append(
                        {
                            "title": "Weak Cipher Suite",
                            "description": f"Cipher {cipher[0]} uses only {cipher[2]} bits",
                            "severity": "medium",
                            "type": "weak_cipher",
                        }
                    )

            writer.close()
            await writer.wait_closed()

        except Exception as e:
            logger.debug(f"SSL analysis failed: {e}")

        return issues

    async def _grab_banners(self, hostname: str) -> list[dict]:
        """Grab service banners from common ports."""
        banners = []

        ports_to_check = [21, 22, 25, 80, 110, 143, 443, 3306, 6379]

        for port in ports_to_check:
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(hostname, port), timeout=3)

                banner = await asyncio.wait_for(reader.read(1024), timeout=2)
                banner_text = banner.decode("utf-8", errors="replace").strip()

                result = {
                    "port": port,
                    "banner": banner_text[:200],
                    "service": self._identify_service(port, banner_text),
                }

                # Check for vulnerable versions
                if self._is_vulnerable_banner(banner_text):
                    result["vulnerable"] = True
                    result["severity"] = "high"
                    result["issue"] = "Potentially vulnerable version detected"

                banners.append(result)

                writer.close()
                await writer.wait_closed()

            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                continue

        return banners

    def _identify_service(self, port: int, banner: str) -> str:
        """Identify service from port and banner."""
        service_map = {
            21: "FTP",
            22: "SSH",
            25: "SMTP",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            3306: "MySQL",
            6379: "Redis",
        }
        return service_map.get(port, "Unknown")

    def _is_vulnerable_banner(self, banner: str) -> bool:
        """Check if banner indicates vulnerable version."""
        vulnerable_patterns = [
            "OpenSSH 7.",
            "OpenSSH 6.",
            "OpenSSH 5.",
            "ProFTPD 1.3.3",
            "vsftpd 2.3.4",
            "Apache/2.2",
            "nginx/1.1",
            "nginx/1.0",
        ]
        return any(p in banner for p in vulnerable_patterns)
