"""
Advanced SQL Injection detection module with concurrent probing and DB fingerprinting.
"""

import asyncio
import logging
import re
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import quote, urljoin, urlparse

from ..core.tamper_engine import TamperEngine
from ..payloads.sqli_payloads import SQLIPayloads
from .base_scanner import BaseScanner, Vulnerability

logger = logging.getLogger(__name__)


class SQLIScanner(BaseScanner):
    """Professional SQL Injection assessment engine."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "SQLIScanner"
        self.description = "Advanced SQL Injection detection engine"
        self.version = "3.2.0"
        self.capabilities = [
            "Error-based SQLi",
            "Time-based Blind SQLi",
            "Boolean-based Blind SQLi",
            "DB Fingerprinting",
            "NoSQL Injection",
            "WAF Evasion",
        ]
        self.payloads = SQLIPayloads()
        self.tamper_engine = TamperEngine()

        # SQL & NoSQL Error Patterns
        self.error_patterns = {
            "MySQL": [r"SQL syntax.*?MySQL", r"Warning.*?mysql_", r"valid MySQL result"],
            "PostgreSQL": [r"PostgreSQL.*?ERROR", r"Warning.*?pg_", r"valid PostgreSQL result"],
            "MSSQL": [
                r"Driver.*? SQL Server",
                r"OLE DB Provider.*? SQL Server",
                r"Unclosed quotation mark after the character string",
            ],
            "Oracle": [r"ORA-[0-9]{5}", r"Oracle Error", r"Oracle.*?Driver"],
            "SQLite": [r"sqlite3.*?Error", r"SQLite error", r"unrecognized token:"],
            "MongoDB": [r"MongoDB.*?Error", r"MongoError", r"is not defined", r"ReferenceError"],
        }

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform multi-vector SQLi assessment."""
        logger.info(f"Starting SQLi scan for {url}")
        vulnerabilities = []

        try:
            # 1. Resource Discovery
            self._update_progress(progress_callback, 10, "Analyzing target surface")
            response = await self.http_client.get(url)
            if not response:
                return self._format_result("Error", "Target unreachable", [])

            html = await response.text()
            soup = await self._parse_html(html)

            # 2. Extract Test Points
            params = self._extract_params(url)
            forms = self._extract_forms(soup, url)

            # 3. Concurrent Testing
            self._update_progress(progress_callback, 30, "Executing SQLi probes")
            tasks = []

            # Test Parameters
            for p_name in params:
                tasks.append(self._test_param_sqli(url, p_name, params))

            # Test Forms
            for form in forms:
                tasks.append(self._test_form_sqli(form))

            if tasks:
                results = await self._concurrent_task_runner(tasks, concurrency_limit=5)
                for r in results:
                    if isinstance(r, list):
                        vulnerabilities.extend(r)

            self._update_progress(progress_callback, 100, "completed")

            status = "Vulnerable" if vulnerabilities else "Clean"
            details = f"Scanned {len(params)} parameters and {len(forms)} forms. Found {len(vulnerabilities)} vulnerabilities."
            return self._format_result(status, details, vulnerabilities)

        except Exception as e:
            logger.exception(f"SQLi scan failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])

    def _extract_params(self, url: str) -> dict:
        from urllib.parse import parse_qs

        query = urlparse(url).query
        return {k: v[0] for k, v in parse_qs(query).items()}

    def _extract_forms(self, soup, base_url: str) -> list[dict]:
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            inputs = []
            for tag in form.find_all(["input", "textarea", "select"]):
                if tag.get("name"):
                    inputs.append({"name": tag.get("name"), "type": tag.get("type", "text")})
            forms.append({"action": urljoin(base_url, action), "method": method, "inputs": inputs})
        return forms

    async def _test_param_sqli(self, url: str, target_param: str, all_params: dict) -> list[Vulnerability]:
        """Test a URL parameter for various SQLi techniques."""
        vulns = []
        # Get a mix of error-based and time-based payloads
        # Get a mix of error-based, time-based, and NoSQL payloads
        base_probes = [p.payload for p in self.payloads.get_all_payloads()[:30]]

        # Add basic NoSQL Payloads
        base_probes.extend(['{"$ne": null}', '{"$gt": ""}', "';return true;'", "';sleep(5000);'"])

        # Apply Tampering if Stealth Mode is on
        probes = []
        if self.config.scanner.enable_waf_bypass:
            for p in base_probes:
                # Use aggressive tampering for maximum evasion
                probes.extend(self.tamper_engine.tamper(p, level="aggressive"))
            # Deduplicate
            probes = list(set(probes))
        else:
            probes = base_probes

        for payload in probes:
            test_params = all_params.copy()
            test_params[target_param] = payload
            encoded_query = "&".join([f"{k}={quote(v)}" for k, v in test_params.items()])
            test_url = f"{url.split('?')[0]}?{encoded_query}"

            start_time = time.monotonic()
            try:
                response = await self.http_client.get(test_url)
                duration = time.monotonic() - start_time

                if response:
                    content = await response.text()

                    # 1. Error-based Check
                    for db, patterns in self.error_patterns.items():
                        if any(re.search(p, content, re.I) for p in patterns):
                            vulns.append(
                                self._create_vulnerability(
                                    title=f"Error-based SQL Injection ({db})",
                                    description=f"Database error disclosed in {target_param} parameter.",
                                    severity="high",
                                    type="sqli",
                                    evidence={"url": test_url, "db": db, "payload": payload},
                                    cwe_id="CWE-89",
                                    cvss_score=8.5,
                                    remediation="Use prepared statements with parameterized queries.",
                                )
                            )
                            return vulns  # Stop testing this param if high-confidence found

                    # 2. Time-based Check (heuristic: > 5s delay)
                    if duration > 5.0 and (
                        "SLEEP" in payload.upper() or "WAITFOR" in payload.upper() or "pg_sleep" in payload
                    ):
                        vulns.append(
                            self._create_vulnerability(
                                title="Time-based Blind SQL Injection",
                                description=f"Significant delay ({duration:.2f}s) detected with payload: {payload}",
                                severity="high",
                                type="sqli_blind",
                                evidence={"url": test_url, "delay": duration, "payload": payload},
                                cwe_id="CWE-89",
                                cvss_score=7.5,
                                remediation="Implement robust input validation and use parameterized queries.",
                            )
                        )
                        return vulns
            except (asyncio.TimeoutError, Exception) as e:
                logger.debug(f"SQLi test failed for {target_param}: {e}")
                continue
        return vulns

    async def _test_form_sqli(self, form: dict) -> list[Vulnerability]:
        """Test form fields for SQL injection."""
        vulns = []
        base_probes = [p.payload for p in self.payloads.get_all_payloads()[:20]]

        # Apply Tampering if Stealth Mode is on
        probes = []
        if self.config.scanner.enable_waf_bypass:
            for p in base_probes:
                probes.extend(
                    self.tamper_engine.tamper(p, level="standard")
                )  # Less aggressive for forms to avoid locking
            probes = list(set(probes))
        else:
            probes = base_probes

        for payload in probes:
            data = {inp["name"]: payload for inp in form["inputs"] if inp["type"] in ["text", "search", "password"]}
            if not data:
                continue

            try:
                start_time = time.monotonic()
                if form["method"] == "post":
                    response = await self.http_client.post(form["action"], data=data)
                else:
                    response = await self.http_client.get(form["action"], params=data)
                duration = time.monotonic() - start_time

                if response:
                    content = await response.text()
                    # Error-based
                    for db, patterns in self.error_patterns.items():
                        if any(re.search(p, content, re.I) for p in patterns):
                            vulns.append(
                                self._create_vulnerability(
                                    title=f"Error-based SQL Injection via Form ({db})",
                                    description=f"Database error disclosure at {form['action']}",
                                    severity="high",
                                    type="sqli",
                                    evidence={"action": form["action"], "db": db, "payload": payload},
                                    cwe_id="CWE-89",
                                    remediation="Switch to parameterized queries for all database interactions.",
                                )
                            )
                            return vulns

                    # Time-based
                    if duration > 5.0 and ("SLEEP" in payload.upper() or "WAITFOR" in payload.upper()):
                        vulns.append(
                            self._create_vulnerability(
                                title="Time-based Blind SQL Injection via Form",
                                description=f"Time delay detected during form submission to {form['action']}",
                                severity="high",
                                type="sqli_blind",
                                evidence={"action": form["action"], "delay": duration, "payload": payload},
                                cwe_id="CWE-89",
                                remediation="Ensure all database inputs are parameterized.",
                            )
                        )
                        return vulns
            except (asyncio.TimeoutError, Exception) as e:
                logger.debug(f"Form SQLi test failed: {e}")
                continue
        return vulns
