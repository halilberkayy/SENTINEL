"""
Base scanner architecture with shared utilities and high-concurrency support.
"""

import asyncio
import concurrent.futures
import logging
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import parse_qs, urlparse

from ..core.config import Config
from ..core.http_client import HTTPClient

logger = logging.getLogger(__name__)


@dataclass
class Vulnerability:
    """Rich vulnerability model following industry standards with CVSS and PoC support."""

    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    type: str
    evidence: dict[str, Any]
    cwe_id: str | None = None
    cvss_score: float = 0.0
    cvss_vector: str | None = None  # CVSS:3.1/AV:N/AC:L/...
    cvss_details: dict[str, Any] | None = None  # Full CVSS breakdown
    poc_available: bool = False
    poc_script: str | None = None  # Python PoC script
    poc_curl: str | None = None  # cURL command
    exploit_difficulty: str = "Medium"  # Easy, Medium, Hard
    remediation: str | None = None
    references: list[str] = field(default_factory=list)

    def __post_init__(self):
        """Auto-calculate CVSS if not provided"""
        if self.cvss_score == 0.0 and self.type:
            self._auto_calculate_cvss()

    def _auto_calculate_cvss(self):
        """Automatically calculate CVSS based on vulnerability type"""
        try:
            from ..core.cvss import get_cvss_for_vulnerability, get_cwe_for_vulnerability

            result = get_cvss_for_vulnerability(self.type)
            if result:
                self.cvss_score = result.score
                self.cvss_vector = result.vector_string
                self.cvss_details = result.to_dict()

                # Set severity based on CVSS score
                self.severity = result.severity.lower()

                # Set exploit difficulty based on attack complexity
                if result.vector.attack_complexity == "L":
                    self.exploit_difficulty = "Easy"
                else:
                    self.exploit_difficulty = "Hard"

            # Auto-fill CWE if not provided
            if not self.cwe_id:
                cwe = get_cwe_for_vulnerability(self.type)
                if cwe:
                    self.cwe_id = cwe

        except ImportError:
            pass  # CVSS module not available
        except Exception:
            pass  # Silently fail for CVSS auto-calculation


class BaseScanner(ABC):
    """Abstract foundation for all security modules."""

    def __init__(self, config: Config, http_client: HTTPClient):
        self.config = config
        self.http_client = http_client
        self.name = self.__class__.__name__
        self.description = "Base vulnerability scanner"
        self.version = "1.0.0"
        self.author = "CodeMaster AI"
        self.capabilities: list[str] = []

        # Isolated thread pool for CPU-bound tasks (HTML parsing, regex)
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)

        # WAF Evasion techniques enabled by default
        self.evasion_enabled = True

    @abstractmethod
    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform a targeted scan. Must return a standardized results dict."""
        raise NotImplementedError("Scanner subclass must implement scan() method")

    async def _concurrent_task_runner(self, tasks: list[Awaitable], concurrency_limit: int = 10) -> list[Any]:
        """Utility to run a large set of async tasks with limited concurrency."""
        semaphore = asyncio.Semaphore(concurrency_limit)

        async def sem_task(task):
            async with semaphore:
                return await task

        return await asyncio.gather(*[sem_task(t) for t in tasks], return_exceptions=True)

    def _create_vulnerability(self, **kwargs) -> Vulnerability:
        """Factory method for Vulnerability objects."""
        return Vulnerability(**kwargs)

    def _update_progress(self, callback: Callable | None, progress: int, status: str = "running"):
        if callback:
            try:
                callback(self.name, status, progress)
            except Exception as e:
                logger.warning(f"Progress update failed: {e}")

    async def _parse_html(self, html: str):
        """Parse HTML in a thread pool to avoid blocking the event loop."""
        from bs4 import BeautifulSoup

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, lambda: BeautifulSoup(html, "lxml"))

    def _get_risk_level(self, vulnerabilities: list[Vulnerability]) -> str:
        if not vulnerabilities:
            return "clean"

        weights = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        max_v = max(vulnerabilities, key=lambda x: weights.get(x.severity.lower(), 0))
        return max_v.severity.lower()

    def _format_result(
        self, status: str, details: str, vulnerabilities: list[Vulnerability], evidence: dict | None = None
    ) -> dict[str, Any]:
        return {
            "status": status,
            "details": details,
            "vulnerabilities": [v.__dict__ for v in vulnerabilities],
            "evidence": evidence or {},
            "risk_level": self._get_risk_level(vulnerabilities),
            "timestamp": datetime.now().isoformat(),
        }

    async def _detect_waf(self, response: Any) -> str | None:
        """Signature-based WAF detection."""
        if not response:
            return None

        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        server = headers.get("server", "")

        waf_map = {
            "Cloudflare": ["cloudflare", "cf-ray", "__cfduid"],
            "Akamai": ["akamai", "aka-debug"],
            "sucuri": ["sucuri", "x-sucuri-id"],
            "ModSecurity": ["mod_security", 'no-cache="set-cookie"'],
            "F5 BigIP": ["bigip", "f5"],
            "AWS WAF": ["awswaf", "x-amz-cf-id"],
        }

        for name, sigs in waf_map.items():
            if any(s in server or s in str(headers) for s in sigs):
                return name
        return None

    async def _response_to_dict(self, response: Any) -> dict[str, Any]:
        """Convert ClientResponse to dict format."""
        if not response:
            return {"status_code": 0, "page_content": "", "headers": {}}

        try:
            content = await response.text()
        except (UnicodeDecodeError, Exception):
            content = ""

        return {"status_code": response.status, "page_content": content, "headers": dict(response.headers)}

    async def _discover_parameters(self, url: str) -> list[str]:
        """Discover form and query parameters from URL and page."""
        params = []

        try:
            # Extract query parameters from URL
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            params.extend(query_params.keys())

            # Fetch page and extract form parameters
            response = await self.http_client.get(url)
            if response and response.status == 200:
                html = await response.text()
                soup = await self._parse_html(html)

                # Find all input fields
                for input_tag in soup.find_all(["input", "textarea", "select"]):
                    name = input_tag.get("name")
                    if name:
                        params.append(name)

                # Common URL parameters if none found
                if not params:
                    params = ["id", "url", "redirect", "page", "file", "path", "q", "search"]

        except Exception as e:
            logger.debug(f"Parameter discovery failed: {e}")
            # Fallback to common parameters
            params = ["id", "url", "redirect", "page", "file", "path", "q", "search"]

        return list(set(params))

    async def _test_payload(self, url: str, param: str, payload: str, method: str = "GET", **kwargs) -> dict[str, Any]:
        """Test a payload on a specific parameter."""
        try:
            if method.upper() == "GET":
                # Add payload to URL parameter
                parsed = urlparse(url)
                separator = "&" if parsed.query else "?"
                test_url = f"{url}{separator}{param}={payload}"
                response = await self.http_client.get(test_url, **kwargs)
            else:  # POST
                data = {param: payload}
                response = await self.http_client.post(url, data=data, **kwargs)

            return await self._response_to_dict(response)

        except Exception as e:
            logger.debug(f"Payload test failed: {e}")
            return {"status_code": 0, "page_content": "", "headers": {}}

    # === WAF Evasion Techniques ===

    def _apply_evasion(self, payload: str, technique: str = "random") -> str:
        """Apply WAF evasion technique to payload."""
        import random
        import urllib.parse

        if not self.evasion_enabled:
            return payload

        techniques = {
            "url_encode": lambda p: urllib.parse.quote(p),
            "double_encode": lambda p: urllib.parse.quote(urllib.parse.quote(p)),
            "unicode": lambda p: "".join(f"\\u{ord(c):04x}" if ord(c) > 127 else c for c in p),
            "hex": lambda p: "".join(f"%{ord(c):02x}" for c in p),
            "mixed_case": lambda p: "".join(random.choice([c.upper(), c.lower()]) if c.isalpha() else c for c in p),
            "null_byte": lambda p: p.replace(" ", "%00"),
            "comment_inject": lambda p: p.replace(" ", "/**/"),
            "tab_space": lambda p: p.replace(" ", "\t"),
        }

        if technique == "random":
            technique = random.choice(list(techniques.keys()))

        return techniques.get(technique, lambda p: p)(payload)

    def _generate_payload_variants(self, payload: str, max_variants: int = 3) -> list[str]:
        """Generate multiple evasion variants of a payload."""
        variants = [payload]  # Always include original

        if self.evasion_enabled:
            techniques = ["url_encode", "mixed_case", "double_encode", "comment_inject"]
            import random

            selected = random.sample(techniques, min(max_variants - 1, len(techniques)))
            for tech in selected:
                variants.append(self._apply_evasion(payload, tech))

        return variants

    # === Wordlist Management ===

    def _load_wordlist(self, wordlist_name: str, prefer_modern: bool = True) -> list[str]:
        """Load wordlist from file with modern fallback support."""
        import os

        # Mapping for wordlist names to filenames
        # Supports both legacy and modern naming conventions
        wordlist_mapping = {
            "directories": ["directories.txt", "web-content-modern.txt"],
            "subdomains": ["subdomains.txt", "subdomains-modern.txt"],
            "api_endpoints": ["api-endpoints.txt", "api-endpoints-modern.txt"],
            "api-endpoints": ["api-endpoints.txt", "api-endpoints-modern.txt"],
            "xss": ["xss-payloads.txt", "xss-payloads-modern.txt"],
            "xss_payloads": ["xss-payloads.txt", "xss-payloads-modern.txt"],
            "xss-payloads": ["xss-payloads.txt", "xss-payloads-modern.txt"],
            "sqli": ["sqli-payloads.txt", "sqli-payloads-modern.txt"],
            "sqli_payloads": ["sqli-payloads.txt", "sqli-payloads-modern.txt"],
            "sqli-payloads": ["sqli-payloads.txt", "sqli-payloads-modern.txt"],
            "backup": ["backup-files.txt", "backup-files-modern.txt"],
            "backup_files": ["backup-files.txt", "backup-files-modern.txt"],
            "backup-files": ["backup-files.txt", "backup-files-modern.txt"],
            "passwords": ["passwords.txt"],
            "user_agents": ["user-agents.txt"],
            "user-agents": ["user-agents.txt"],
            "security_headers": ["security-headers.txt"],
            "security-headers": ["security-headers.txt"],
            "webshells": ["webshell_signatures.txt"],
            "webshell_signatures": ["webshell_signatures.txt"],
        }

        # Get possible filenames for this wordlist
        filenames = wordlist_mapping.get(wordlist_name, [f"{wordlist_name}.txt"])

        # If prefer_modern, try modern version first
        if prefer_modern:
            filenames = sorted(filenames, key=lambda x: "-modern" in x, reverse=True)

        # Base wordlists directory
        base_dirs = [
            "wordlists",
            "../wordlists",
            "../../wordlists",
            os.path.join(os.path.dirname(__file__), "..", "..", "wordlists"),
        ]

        # Try all combinations
        for base_dir in base_dirs:
            for filename in filenames:
                path = os.path.join(base_dir, filename)
                try:
                    if os.path.exists(path):
                        with open(path, encoding="utf-8") as f:
                            # Filter out comments and empty lines
                            lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                            if lines:
                                logger.debug(f"Loaded wordlist from {path} ({len(lines)} entries)")
                                return lines
                except Exception as e:
                    logger.debug(f"Failed to load wordlist from {path}: {e}")
                    continue

        logger.warning(f"Wordlist '{wordlist_name}' not found, using fallback")
        return self._get_fallback_wordlist(wordlist_name)

    def _get_fallback_wordlist(self, wordlist_name: str) -> list[str]:
        """Return minimal fallback wordlist when file not found."""
        fallbacks = {
            "directories": ["admin", "api", "backup", "config", "test", "dev", "uploads", ".git", ".env", "wp-admin"],
            "subdomains": ["www", "mail", "ftp", "admin", "api", "dev", "stage", "test", "cdn", "app"],
            "webshells": ["shell.php", "c99.php", "r57.php", "backdoor.php", "cmd.php"],
            "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"],
            "sqli": ["' OR '1'='1", "' OR 1=1--", "'; DROP TABLE users--"],
            "passwords": ["admin", "password", "123456", "admin123", "root"],
        }
        return fallbacks.get(wordlist_name, [])

    def _load_webshell_signatures(self) -> list[dict[str, str]]:
        """Load webshell signature patterns."""
        import os

        signatures = []
        sig_file = os.path.join(os.path.dirname(__file__), "..", "..", "wordlists", "webshell_signatures.txt")

        try:
            if os.path.exists(sig_file):
                with open(sig_file, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            parts = line.split("|")
                            if len(parts) >= 3:
                                signatures.append({"filename": parts[0], "pattern": parts[1], "severity": parts[2]})
        except Exception as e:
            logger.debug(f"Failed to load webshell signatures: {e}")

        # Fallback signatures
        if not signatures:
            signatures = [
                {"filename": "shell.php", "pattern": "eval\\(\\$_POST", "severity": "critical"},
                {"filename": "c99.php", "pattern": "c99shell", "severity": "critical"},
                {"filename": "backdoor.php", "pattern": "passthru.*system", "severity": "critical"},
            ]

        return signatures
