"""
Prototype Pollution scanner - ENHANCED with behavioral analysis
"""

import json
import logging
from collections.abc import Callable
from typing import Any

from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class ProtoPollutionScanner(BaseScanner):
    """Enhanced Prototype Pollution detection with behavioral testing."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "ProtoPollutionScanner"
        self.description = "Detects Prototype Pollution in JavaScript with behavioral analysis"
        self.version = "2.0.0"
        self.capabilities = ["Behavioral Testing", "Response Analysis", "Object Pollution Detection"]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform enhanced Prototype Pollution scan."""
        logger.info(f"Scanning {url} for Prototype Pollution")
        vulnerabilities = []

        # Test payloads with behavioral indicators
        test_cases = [
            {
                "payload": "__proto__[testprop]=polluted",
                "check_response": lambda r: "testprop" in r or "polluted" in r,
                "type": "query_param",
            },
            {
                "payload": "constructor[prototype][testprop]=polluted",
                "check_response": lambda r: "testprop" in r or "polluted" in r,
                "type": "query_param",
            },
            {
                "payload": '{"__proto__":{"testprop":"polluted"}}',
                "check_response": lambda r: "testprop" in r or "polluted" in r,
                "type": "json_body",
            },
            {
                "payload": "__proto__.isAdmin=true",
                "check_response": lambda r: "isAdmin" in r or "admin" in r.lower(),
                "type": "query_param",
            },
        ]

        try:
            self._update_progress(progress_callback, 10, "Starting prototype pollution tests")

            # Baseline request to compare behavior
            self._update_progress(progress_callback, 20, "Getting baseline response")
            baseline_response = await self.http_client.get(url)
            baseline_dict = await self._response_to_dict(baseline_response) if baseline_response else {}
            baseline_content = baseline_dict.get("page_content", "")
            baseline_dict.get("headers", {})

            len(test_cases) * 2  # Query + POST for each
            tested = 0

            for idx, test_case in enumerate(test_cases):
                progress = 30 + int((idx / len(test_cases)) * 60)
                self._update_progress(progress_callback, progress, f"Testing pollution vector {idx + 1}")

                payload = test_case["payload"]

                # Test 1: Query parameter pollution
                if test_case["type"] == "query_param":
                    test_url = f"{url}{'&' if '?' in url else '?'}{payload}"
                    polluted_response = await self.http_client.get(test_url)
                    polluted_dict = await self._response_to_dict(polluted_response)

                    # Analyze response differences
                    if self._detect_pollution_behavior(baseline_dict, polluted_dict, test_case):
                        vulnerabilities.append(
                            self._create_vulnerability(
                                title="Prototype Pollution via Query Parameter",
                                description=f"Application appears vulnerable to prototype pollution. Payload '{payload}' caused behavioral changes indicating object pollution.",
                                severity="high",
                                type="injection",
                                evidence={
                                    "url": test_url,
                                    "payload": payload,
                                    "baseline_response": baseline_content[:200],
                                    "polluted_response": polluted_dict.get("page_content", "")[:200],
                                },
                                cwe_id="CWE-1321",
                                remediation="Use Map objects instead of plain objects for user-controlled keys. Freeze Object.prototype. Validate and sanitize all user inputs. Use Object.create(null) for objects storing user data.",
                            )
                        )

                # Test 2: JSON body pollution
                elif test_case["type"] == "json_body":
                    try:
                        json_payload = json.loads(payload)
                        polluted_response = await self.http_client.post(
                            url, json=json_payload, headers={"Content-Type": "application/json"}
                        )
                        polluted_dict = await self._response_to_dict(polluted_response)

                        if self._detect_pollution_behavior(baseline_dict, polluted_dict, test_case):
                            vulnerabilities.append(
                                self._create_vulnerability(
                                    title="Prototype Pollution via JSON Body",
                                    description="Application merges JSON input unsafely, allowing prototype pollution.",
                                    severity="high",
                                    type="injection",
                                    evidence={
                                        "url": url,
                                        "method": "POST",
                                        "payload": payload,
                                        "baseline_response": baseline_content[:200],
                                        "polluted_response": polluted_dict.get("page_content", "")[:200],
                                    },
                                    cwe_id="CWE-1321",
                                    remediation="Implement safe JSON merge operations. Use libraries like lodash with secure defaults. Filter __proto__, constructor, and prototype keys.",
                                )
                            )
                    except json.JSONDecodeError:
                        logger.debug(f"Response not JSON, skipping proto pollution check for {endpoint}")

                tested += 1

            # Test for common vulnerable patterns in code
            self._update_progress(progress_callback, 95, "Analyzing code patterns")
            if baseline_content:
                vulnerable_patterns = [
                    r"Object\.assign\s*\(\s*{}\s*,",
                    r"merge\s*\(",
                    r"\$\.extend\s*\(",
                    r"\.\.\..*{",  # Spread operator with objects
                ]

                for pattern in vulnerable_patterns:
                    import re

                    if re.search(pattern, baseline_content):
                        vulnerabilities.append(
                            self._create_vulnerability(
                                title="Potentially Vulnerable Object Merge Pattern",
                                description=f"Detected pattern that may be vulnerable to prototype pollution: {pattern}",
                                severity="info",
                                type="code_pattern",
                                evidence={"url": url, "pattern": pattern},
                                cwe_id="CWE-1321",
                                remediation="Review object merging operations to ensure they don't allow __proto__ pollution.",
                            )
                        )
                        break  # One warning is enough

            self._update_progress(progress_callback, 100, "completed")

            status = "Vulnerable" if any(v.severity in ["critical", "high"] for v in vulnerabilities) else "Clean"
            return self._format_result(
                status, f"Completed pollution tests. Found {len(vulnerabilities)} issues.", vulnerabilities
            )

        except Exception as e:
            logger.exception(f"Proto Pollution scan failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])

    def _detect_pollution_behavior(self, baseline: dict, polluted: dict, test_case: dict) -> bool:
        """Detect if pollution occurred based on response differences."""
        baseline_content = baseline.get("page_content", "").lower()
        polluted_content = polluted.get("page_content", "").lower()

        # Check if test property appeared in response
        if test_case["check_response"](polluted_content) and not test_case["check_response"](baseline_content):
            return True

        # Check for new keys in JSON responses
        try:
            if "application/json" in polluted.get("headers", {}).get("Content-Type", ""):
                baseline_json = json.loads(baseline_content) if baseline_content else {}
                polluted_json = json.loads(polluted_content) if polluted_content else {}

                # Look for new keys that weren't in baseline
                if isinstance(polluted_json, dict):
                    new_keys = set(polluted_json.keys()) - set(
                        baseline_json.keys() if isinstance(baseline_json, dict) else []
                    )
                    if new_keys and any(key in ["testprop", "polluted", "isAdmin"] for key in new_keys):
                        return True
        except Exception as e:
            logger.debug(f"Error comparing JSON responses for pollution detection: {e}")

        # Check for behavioral changes (status code, response length)
        baseline_status = baseline.get("status_code", 0)
        polluted_status = polluted.get("status_code", 0)

        # If status changed from error to success, might indicate pollution
        if baseline_status >= 400 and polluted_status == 200:
            return True

        # Significant response length change
        if abs(len(polluted_content) - len(baseline_content)) > 100:
            # But only if polluted response contains test terms
            if "testprop" in polluted_content or "polluted" in polluted_content:
                return True

        return False
