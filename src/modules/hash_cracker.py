"""
John the Ripper & Hashcat Integration - Password cracking and hash analysis.
"""

import logging
import re
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class HashCracker(BaseScanner):
    """Password hash cracking via John the Ripper or Hashcat."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "HashCracker"
        self.description = "Password cracking and hash analysis"
        self.version = "1.0.0"
        self.capabilities = ["Hash Identification", "Dictionary Attack", "Hash Cracking"]

        self.hash_patterns = {
            "md5": (r"^[a-f0-9]{32}$", "Raw-MD5"),
            "sha1": (r"^[a-f0-9]{40}$", "Raw-SHA1"),
            "sha256": (r"^[a-f0-9]{64}$", "Raw-SHA256"),
            "sha512": (r"^[a-f0-9]{128}$", "Raw-SHA512"),
            "bcrypt": (r"^\$2[aby]?\$\d+\$[./A-Za-z0-9]{53}$", "bcrypt"),
            "mysql": (r"^\*[A-F0-9]{40}$", "mysql-sha1"),
            "ntlm": (r"^[A-Fa-f0-9]{32}$", "NT"),
        }

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Analyze URL for exposed hashes."""
        self._update_progress(progress_callback, 10, "Checking for exposed hashes")
        vulnerabilities = []
        found_hashes = []

        try:
            response = await self.http_client.get(url)
            if not response or response.status != 200:
                return self._format_result("Clean", "No content to analyze", [])

            content = await response.text()

            # Find hashes in content
            for hash_type, (pattern, john_format) in self.hash_patterns.items():
                matches = re.findall(pattern, content, re.MULTILINE | re.IGNORECASE)
                for match in matches[:10]:  # Limit
                    found_hashes.append({"hash": match, "type": hash_type, "format": john_format})

            if found_hashes:
                vulnerabilities.append(
                    self._create_vulnerability(
                        title=f"Exposed Password Hashes ({len(found_hashes)} found)",
                        description=f"Found {len(found_hashes)} potential password hashes in page content.",
                        severity="critical",
                        type="credential_exposure",
                        evidence={"hashes": found_hashes[:5]},
                        cwe_id="CWE-312",
                        remediation="Remove password hashes from public content immediately.",
                    )
                )

            self._update_progress(progress_callback, 100, "completed")
            return self._format_result(
                "Vulnerable" if vulnerabilities else "Clean",
                f"Found {len(found_hashes)} hashes",
                vulnerabilities,
                {"found_hashes": len(found_hashes)},
            )

        except Exception as e:
            return self._format_result("Error", str(e), [])

    async def crack_hashes(self, hashes: list[str], wordlist: str = None) -> dict[str, Any]:
        """Attempt to crack provided hashes using JtR."""
        from ..utils.command_runner import ExternalCommandRunner

        runner = ExternalCommandRunner(timeout=300)

        if not runner.check_tool_available("john"):
            return {"error": "John the Ripper not installed"}

        # Write hashes to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            for h in hashes:
                f.write(h + "\n")
            hash_file = f.name

        wordlist = wordlist or self._find_wordlist()
        args = [hash_file]
        if wordlist:
            args.extend(["--wordlist=" + wordlist])

        result = await runner.run_tool("john", args)

        # Get cracked passwords
        show_result = await runner.run_tool("john", ["--show", hash_file])

        Path(hash_file).unlink(missing_ok=True)

        return {"success": result.success, "cracked": show_result.stdout, "duration": result.duration}

    def _find_wordlist(self) -> str | None:
        """Find password wordlist."""
        paths = [
            Path("wordlists/passwords.txt"),
            Path("/usr/share/wordlists/rockyou.txt"),
            Path("/usr/share/john/password.lst"),
        ]
        for p in paths:
            if p.exists():
                return str(p)
        return None
