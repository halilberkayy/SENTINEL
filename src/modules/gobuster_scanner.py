"""
Gobuster Integration Module - High-speed directory/file brute-forcing.
Alternative to dirb/dirbuster with Go-based performance.
"""

import logging
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class GobusterScanner(BaseScanner):
    """
    Gobuster integration for high-performance directory enumeration.
    Supports dir, dns, vhost, and fuzz modes.
    """

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "GobusterScanner"
        self.description = "High-speed directory and DNS enumeration via Gobuster"
        self.version = "1.0.0"
        self.author = "SENTINEL Team"
        self.capabilities = [
            "Directory Brute-forcing",
            "DNS Subdomain Enumeration",
            "Virtual Host Discovery",
            "File Extension Fuzzing",
            "Custom Wordlist Support",
        ]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Execute Gobuster directory scan."""
        from ..utils.command_runner import StreamingCommandRunner

        parsed = urlparse(url)
        if not parsed.scheme:
            url = f"http://{url}"
            parsed = urlparse(url)

        base_url = f"{parsed.scheme}://{parsed.netloc}"

        runner = StreamingCommandRunner(timeout=300)

        # Check availability
        if not runner.check_tool_available("gobuster"):
            # Fallback to dirb
            if runner.check_tool_available("dirb"):
                return await self._run_dirb_fallback(url, progress_callback)
            return self._format_result(
                "Skipped", "Gobuster not installed. Install: go install github.com/OJ/gobuster/v3@latest", []
            )

        logger.info(f"Starting Gobuster scan on {base_url}")
        self._update_progress(progress_callback, 10, "Initializing Gobuster")

        vulnerabilities = []
        found_paths = []

        try:
            # Find wordlist
            wordlist = self._find_wordlist()
            if not wordlist:
                return self._format_result("Error", "No wordlist found for directory enumeration", [])

            self._update_progress(progress_callback, 20, "Running directory enumeration")

            # Build gobuster command
            args = [
                "dir",
                "-u",
                base_url,
                "-w",
                wordlist,
                "-t",
                "20",  # 20 threads
                "-q",  # Quiet mode
                "--no-error",
                "-o",
                "-",  # Output to stdout
                "--timeout",
                "10s",
                "-s",
                "200,201,202,203,204,301,302,307,308,401,403,405",  # Status codes
            ]

            # Add extensions for file discovery
            args.extend(["-x", "php,asp,aspx,jsp,html,js,txt,xml,json,bak,old,sql,zip,tar,gz"])

            discovered = []

            async def output_handler(line: str, is_stderr: bool):
                if not is_stderr and line.strip():
                    discovered.append(line)
                    # Update progress periodically
                    if len(discovered) % 10 == 0:
                        self._update_progress(
                            progress_callback, min(20 + len(discovered), 90), f"Found {len(discovered)} paths"
                        )

            await runner.run_streaming(["gobuster"] + args, output_handler)

            # Parse results
            for line in discovered:
                parsed_result = self._parse_gobuster_line(line, base_url)
                if parsed_result:
                    found_paths.append(parsed_result)

                    # Check if sensitive
                    vuln = self._check_sensitive_path(parsed_result)
                    if vuln:
                        vulnerabilities.append(vuln)

            self._update_progress(progress_callback, 100, "completed")

            status = "Vulnerable" if vulnerabilities else "Clean"
            if found_paths and not vulnerabilities:
                status = "Info"

            return self._format_result(
                status,
                f"Discovered {len(found_paths)} accessible paths, {len(vulnerabilities)} sensitive",
                vulnerabilities,
                evidence={"found_paths": found_paths[:100], "total_found": len(found_paths)},
            )

        except Exception as e:
            logger.exception(f"Gobuster scan failed: {e}")
            return self._format_result("Error", f"Scan error: {e}", [])

    async def _run_dirb_fallback(self, url: str, progress_callback: Callable | None) -> dict[str, Any]:
        """Fallback to dirb if gobuster is not available."""
        from ..utils.command_runner import ExternalCommandRunner

        runner = ExternalCommandRunner(timeout=300)

        self._update_progress(progress_callback, 10, "Using dirb as fallback")

        wordlist = self._find_wordlist()
        if not wordlist:
            return self._format_result("Error", "No wordlist found", [])

        args = [url, wordlist, "-S", "-w"]  # Silent, warning only

        result = await runner.run_tool("dirb", args)

        if not result.success:
            return self._format_result("Error", f"Dirb failed: {result.stderr}", [])

        # Parse dirb output
        found_paths = []
        vulnerabilities = []

        for line in result.stdout.split("\n"):
            if "+ http" in line or "==> DIRECTORY:" in line:
                url_match = re.search(r"(https?://[^\s]+)", line)
                if url_match:
                    path_url = url_match.group(1)
                    status = 200  # Default
                    status_match = re.search(r"\(CODE:(\d+)\)", line)
                    if status_match:
                        status = int(status_match.group(1))

                    found_paths.append({"url": path_url, "status": status, "is_directory": "==> DIRECTORY:" in line})

        for path in found_paths:
            vuln = self._check_sensitive_path(path)
            if vuln:
                vulnerabilities.append(vuln)

        self._update_progress(progress_callback, 100, "completed")

        return self._format_result(
            "Vulnerable" if vulnerabilities else "Info" if found_paths else "Clean",
            f"Dirb found {len(found_paths)} paths",
            vulnerabilities,
            evidence={"found_paths": found_paths},
        )

    def _find_wordlist(self) -> str | None:
        """Find a suitable wordlist for directory enumeration."""
        wordlist_paths = [
            # Project wordlists
            Path("wordlists/directories.txt"),
            Path("wordlists/web-content-modern.txt"),
            # Common system locations
            Path("/usr/share/wordlists/dirb/common.txt"),
            Path("/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"),
            Path("/usr/share/seclists/Discovery/Web-Content/common.txt"),
            Path("/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt"),
            Path("/opt/SecLists/Discovery/Web-Content/common.txt"),
            # Homebrew location (macOS)
            Path("/opt/homebrew/share/dirb/wordlists/common.txt"),
        ]

        for path in wordlist_paths:
            if path.exists():
                logger.debug(f"Using wordlist: {path}")
                return str(path)

        return None

    def _parse_gobuster_line(self, line: str, base_url: str) -> dict | None:
        """Parse a gobuster output line."""
        # Format: /path (Status: 200) [Size: 1234]
        match = re.match(r"(/\S*)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]", line.strip())

        if match:
            path, status, size = match.groups()
            return {"path": path, "url": f"{base_url.rstrip('/')}{path}", "status": int(status), "size": int(size)}

        # Alternative format without size
        match = re.match(r"(/\S*)\s+\(Status:\s*(\d+)\)", line.strip())
        if match:
            path, status = match.groups()
            return {"path": path, "url": f"{base_url.rstrip('/')}{path}", "status": int(status), "size": 0}

        return None

    def _check_sensitive_path(self, path_info: dict) -> Any:
        """Check if discovered path is sensitive."""
        path = path_info.get("path", path_info.get("url", "")).lower()

        # Critical findings
        critical_patterns = {
            ".git": "Git repository exposed - source code leak",
            ".svn": "SVN repository exposed - source code leak",
            ".env": "Environment file exposed - credentials leak",
            "wp-config": "WordPress config exposed",
            ".sql": "SQL dump exposed",
            "database": "Database file/directory exposed",
            "backup": "Backup files exposed",
            ".bak": "Backup file exposed",
            "debug": "Debug endpoint exposed",
            "phpinfo": "PHP info page exposed",
            "adminer": "Database admin tool exposed",
            "phpmyadmin": "PHPMyAdmin exposed",
        }

        # High severity
        high_patterns = {
            "admin": "Admin panel discovered",
            "manager": "Management interface discovered",
            "console": "Console/admin endpoint",
            "api/swagger": "API documentation exposed",
            "graphql": "GraphQL endpoint exposed",
            ".htpasswd": "Password file exposed",
            ".htaccess": "Apache config exposed",
            "web.config": "IIS config exposed",
        }

        # Medium severity
        medium_patterns = {
            "config": "Configuration file/directory",
            "setup": "Setup/installation page",
            "install": "Installation page",
            "test": "Test endpoint",
            "dev": "Development endpoint",
            "staging": "Staging environment",
            "api": "API endpoint discovered",
        }

        for pattern, desc in critical_patterns.items():
            if pattern in path:
                return self._create_vulnerability(
                    title=f"Critical: {desc}",
                    description=f"Sensitive resource found at {path_info.get('url', path)}",
                    severity="critical",
                    type="sensitive_exposure",
                    evidence=path_info,
                    cwe_id="CWE-200",
                    cvss_score=9.0,
                    remediation="Remove or restrict access immediately.",
                )

        for pattern, desc in high_patterns.items():
            if pattern in path:
                return self._create_vulnerability(
                    title=f"High: {desc}",
                    description=f"Potentially sensitive resource at {path_info.get('url', path)}",
                    severity="high",
                    type="sensitive_exposure",
                    evidence=path_info,
                    cwe_id="CWE-200",
                    cvss_score=7.5,
                    remediation="Restrict access with authentication or firewall rules.",
                )

        for pattern, desc in medium_patterns.items():
            if pattern in path:
                return self._create_vulnerability(
                    title=f"Medium: {desc}",
                    description=f"Resource discovered at {path_info.get('url', path)}",
                    severity="medium",
                    type="information_disclosure",
                    evidence=path_info,
                    cwe_id="CWE-200",
                    cvss_score=5.0,
                    remediation="Review if this resource should be publicly accessible.",
                )

        return None
