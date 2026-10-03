"""
JavaScript Secrets Scanner module.
Scans JavaScript files for hardcoded secrets, API keys, and sensitive tokens.
"""

import logging
import math
import re
from collections import Counter
from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin

from ..core.http_client import response_reliability
from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)

# Strings that mark a match as a placeholder/example, not a real secret.
_PLACEHOLDER_MARKERS = (
    "example",
    "xxxx",
    "0000",
    "1234",
    "abcd",
    "placeholder",
    "your_",
    "yourkey",
    "changeme",
    "change_me",
    "dummy",
    "sample",
    "redacted",
    "<",
    ">",
    "{{",
    "}}",
    "null",
    "none",
    "undefined",
    "foobar",
)


def _shannon_entropy(value: str) -> float:
    """Shannon entropy (bits per char). Real secrets are high-entropy; minified
    JS identifiers that match a broad pattern are usually not."""
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_like_secret(value: str, broad: bool) -> bool:
    """Reject obvious placeholders, and for broad patterns also reject low-entropy
    matches that are almost certainly identifiers rather than credentials."""
    low = value.lower()
    if any(marker in low for marker in _PLACEHOLDER_MARKERS):
        return False
    return not (broad and _shannon_entropy(value) < 3.5)


class JSSecretsScanner(BaseScanner):
    """
    Scans client-side JavaScript for exposed secrets and API keys.
    Uses a comprehensive regex library to detect cloud credentials,
    SaaS tokens, and other sensitive data.
    """

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "JSSecretsScanner"
        self.description = "Detects hardcoded API keys and secrets in JavaScript files"
        self.version = "1.0.0"
        self.capabilities = ["Secret Detection", "API Key Mining", "Entropy Analysis"]

        # Regex patterns for various secrets
        self.signatures = [
            {
                "name": "AWS Access Key ID",
                "pattern": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
                "severity": "critical",
            },
            {
                "name": "AWS Secret Access Key",
                "pattern": r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]",
                "severity": "critical",
            },
            {"name": "Google API Key", "pattern": r"AIza[0-9A-Za-z_-]{35}", "severity": "high"},
            {"name": "Firebase URL", "pattern": r"https://[a-z0-9-]+\.firebaseio\.com", "severity": "medium"},
            {"name": "Stripe Publishable Key", "pattern": r"pk_live_[0-9a-zA-Z]{24,34}", "severity": "medium"},
            {"name": "Stripe Secret Key", "pattern": r"sk_live_[0-9a-zA-Z]{24,34}", "severity": "critical"},
            {"name": "Slack Token", "pattern": r"xox[baprs]-[0-9a-zA-Z]{10,48}", "severity": "high"},
            {"name": "GitHub Personal Access Token", "pattern": r"ghp_[0-9a-zA-Z]{36}", "severity": "critical"},
            {"name": "Generic Private Key", "pattern": r"-----BEGIN PRIVATE KEY-----", "severity": "critical"},
            {"name": "Twilio Account SID", "pattern": r"AC[a-zA-Z0-9_\-]{32}", "severity": "medium", "broad": True},
            {"name": "Twilio API Key", "pattern": r"SK[a-zA-Z0-9_\-]{32}", "severity": "high", "broad": True},
            {"name": "Mailgun API Key", "pattern": r"key-[0-9a-zA-Z]{32}", "severity": "high", "broad": True},
            {
                "name": "Algolia Admin Key",
                "pattern": r"(?i)(algolia|algolia_key).{0,20}['\"][a-z0-9]{32}['\"]",
                "severity": "high",
            },
            {
                "name": "Heroku API Key",
                "pattern": r"(?i)heroku.{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                "severity": "high",
            },
        ]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform JS secrets scan."""
        logger.info(f"Scanning {url} for JS secrets")
        vulnerabilities = []
        seen: set[tuple[str, str]] = set()

        try:
            self._update_progress(progress_callback, 10, "Fetching main page")
            response = await self.http_client.get(url)
            if not response:
                return self._format_result("Error", "Target unreachable", [])

            analyzable, reason = response_reliability(response)
            if not analyzable:
                return self._format_result(
                    "Unreliable",
                    f"Did not scan for secrets: target returned {reason}. "
                    "An error or challenge page is not the application's JavaScript.",
                    [],
                )

            html = await response.text()
            soup = await self._parse_html(html)

            # Extract script sources
            scripts = []

            # Inline scripts
            for script in soup.find_all("script"):
                if script.string:
                    scripts.append({"url": url, "content": script.string, "type": "inline"})
                elif script.get("src"):
                    src = script.get("src")
                    full_url = urljoin(url, src)
                    scripts.append({"url": full_url, "content": None, "type": "external"})

            total_scripts = len(scripts)
            processed = 0

            self._update_progress(progress_callback, 20, f"Found {total_scripts} scripts to analyze")

            for script in scripts:
                processed += 1
                progress = 20 + int((processed / total_scripts) * 75) if total_scripts > 0 else 95

                content = script["content"]
                script_url = script["url"]

                # Fetch external script content
                if script["type"] == "external":
                    self._update_progress(progress_callback, progress, f"Fetching {script_url.split('/')[-1]}")
                    try:
                        resp = await self.http_client.get(script_url)
                        if resp and resp.status == 200:
                            content = await resp.text()
                        else:
                            continue
                    except Exception as e:
                        logger.debug(f"Failed to fetch script {script_url}: {e}")
                        continue

                if not content:
                    continue

                # Scan content against signatures
                for sig in self.signatures:
                    broad = sig.get("broad", False)
                    for match in re.finditer(sig["pattern"], content):
                        secret = match.group(0)
                        # Drop placeholders and low-entropy broad-pattern matches.
                        if not _looks_like_secret(secret, broad):
                            continue
                        dedup_key = (sig["name"], secret)
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)

                        redacted = secret if len(secret) <= 8 else f"{secret[:4]}...{secret[-4:]}"
                        vulnerabilities.append(
                            self._create_vulnerability(
                                title=f"Exposed {sig['name']}",
                                description=f"Found a potential {sig['name']} in JavaScript code.",
                                severity=sig["severity"],
                                type="info_leak",
                                evidence={
                                    "file": script_url,
                                    "match_type": sig["name"],
                                    "snippet": redacted,
                                    "location": f"Index: {match.start()}",
                                },
                                cwe_id="CWE-798",
                                remediation="Remove hardcoded credentials from client-side code. Use environment variables and backend proxies.",
                                # Broad patterns match identifiers too; flag for human confirmation.
                                confidence="tentative" if broad else "firm",
                            )
                        )

            self._update_progress(progress_callback, 100, "completed")

            status = "Vulnerable" if vulnerabilities else "Clean"
            return self._format_result(
                status, f"Scanned {total_scripts} scripts. Found {len(vulnerabilities)} secrets.", vulnerabilities
            )

        except Exception as e:
            logger.exception(f"JS Secrets scan failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])
