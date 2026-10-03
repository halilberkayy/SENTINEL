"""
Nikto Integration Module - Web server vulnerability scanner.
"""

import logging
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class NiktoScanner(BaseScanner):
    """Nikto web server scanner integration."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "NiktoScanner"
        self.description = "Web server vulnerability scanning via Nikto"
        self.version = "1.0.0"
        self.capabilities = ["Server Misconfiguration", "Outdated Software", "Dangerous Files"]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Execute Nikto scan."""
        from ..utils.command_runner import StreamingCommandRunner

        parsed = urlparse(url)
        if not parsed.scheme:
            url = f"http://{url}"

        runner = StreamingCommandRunner(timeout=600)

        if not runner.check_tool_available("nikto"):
            return self._format_result("Skipped", "Nikto not installed", [])

        self._update_progress(progress_callback, 10, "Starting Nikto")
        vulnerabilities = []

        try:
            args = ["-h", url, "-Format", "csv", "-nointeractive", "-Tuning", "x6789abc"]
            if parsed.scheme == "https":
                args.append("-ssl")

            output_lines = []

            async def handler(line, is_err):
                if not is_err:
                    output_lines.append(line)

            await runner.run_streaming(["nikto"] + args, handler)

            for line in output_lines:
                if line.startswith("+") and not any(x in line.lower() for x in ["target", "start", "end", "host"]):
                    severity = "high" if "CVE" in line else "medium"
                    vulnerabilities.append(
                        self._create_vulnerability(
                            title=f"Nikto: {line[:60]}",
                            description=line,
                            severity=severity,
                            type="nikto_finding",
                            evidence={"raw": line},
                            cwe_id="CWE-200",
                        )
                    )

            self._update_progress(progress_callback, 100, "completed")
            status = "Vulnerable" if vulnerabilities else "Clean"
            return self._format_result(status, f"Found {len(vulnerabilities)} issues", vulnerabilities)

        except Exception as e:
            return self._format_result("Error", str(e), [])
