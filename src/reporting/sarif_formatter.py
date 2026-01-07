"""
SARIF (Static Analysis Results Interchange Format) Formatter

Generates SARIF 2.1.0 compliant output for integration with:
- GitHub Code Scanning
- GitLab SAST
- Azure DevOps
- Other CI/CD security tools

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

import hashlib
import json
from datetime import datetime
from typing import Any
from urllib.parse import urlparse


class SARIFFormatter:
    """
    SARIF 2.1.0 formatter for CI/CD integration.

    Produces output compatible with GitHub Security, GitLab SAST,
    and other security scanning integrations.
    """

    SARIF_VERSION = "2.1.0"
    SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
    TOOL_NAME = "Web Vulnerability Scanner"
    TOOL_VERSION = "6.0.0"
    INFORMATION_URI = "https://github.com/halilberkayy/SENTINEL"

    # SARIF severity mapping
    SEVERITY_MAP = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }

    # SARIF level to score mapping for sorting
    LEVEL_SCORES = {
        "error": 3,
        "warning": 2,
        "note": 1,
        "none": 0,
    }

    def format_report(self, scan_data: dict[str, Any]) -> str:
        """
        Format scan data as SARIF 2.1.0 JSON.

        Args:
            scan_data: Scan results from scanner engine

        Returns:
            SARIF JSON string
        """
        sarif_report = {
            "$schema": self.SCHEMA_URI,
            "version": self.SARIF_VERSION,
            "runs": [self._generate_run(scan_data)],
        }

        return json.dumps(sarif_report, indent=2)

    def _generate_run(self, scan_data: dict[str, Any]) -> dict[str, Any]:
        """Generate a SARIF run object"""
        results = scan_data.get("results", [])
        target_url = scan_data.get("url", "unknown")

        # Collect all vulnerabilities
        all_vulns = []
        for result in results:
            vulns = result.get("vulnerabilities", [])
            for vuln in vulns:
                vuln["_module"] = result.get("module", "Unknown")
                all_vulns.append(vuln)

        # Generate rules from vulnerabilities
        rules = self._generate_rules(all_vulns)

        return {
            "tool": {
                "driver": {
                    "name": self.TOOL_NAME,
                    "version": self.TOOL_VERSION,
                    "informationUri": self.INFORMATION_URI,
                    "rules": rules,
                    "notifications": [],
                    "properties": {"scanType": "DAST", "targetUrl": target_url},
                }
            },
            "invocations": [self._generate_invocation(scan_data)],
            "results": self._generate_results(all_vulns, target_url),
            "artifacts": [self._generate_artifact(target_url)],
            "automationDetails": {
                "id": f"web-vulnerability-scan/{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                "guid": self._generate_guid(f"{target_url}-{datetime.now().isoformat()}"),
            },
        }

    def _generate_rules(self, vulnerabilities: list[dict]) -> list[dict]:
        """Generate SARIF rules from vulnerabilities"""
        rules = {}

        for vuln in vulnerabilities:
            rule_id = self._get_rule_id(vuln)

            if rule_id not in rules:
                severity = vuln.get("severity", "medium").lower()
                vuln_type = vuln.get("type", "unknown")
                cwe_id = vuln.get("cwe_id", "")
                cvss_score = vuln.get("cvss_score", 0.0)

                rules[rule_id] = {
                    "id": rule_id,
                    "name": vuln_type.replace("_", " ").title(),
                    "shortDescription": {"text": vuln.get("title", vuln_type)},
                    "fullDescription": {"text": vuln.get("description", f"Vulnerability of type {vuln_type}")},
                    "defaultConfiguration": {"level": self.SEVERITY_MAP.get(severity, "warning")},
                    "helpUri": self._get_reference_uri(vuln),
                    "help": {
                        "text": vuln.get("remediation", "No remediation guidance available"),
                        "markdown": self._generate_help_markdown(vuln),
                    },
                    "properties": {
                        "tags": self._get_tags(vuln),
                        "precision": "high",
                        "security-severity": str(cvss_score) if cvss_score else self._severity_to_score(severity),
                    },
                }

                # Add CWE relationship if available
                if cwe_id:
                    rules[rule_id]["relationships"] = [
                        {
                            "target": {
                                "id": cwe_id,
                                "guid": self._generate_guid(cwe_id),
                                "toolComponent": {"name": "CWE", "guid": self._generate_guid("CWE")},
                            },
                            "kinds": ["superset"],
                        }
                    ]

        return list(rules.values())

    def _generate_results(self, vulnerabilities: list[dict], target_url: str) -> list[dict]:
        """Generate SARIF results from vulnerabilities"""
        results = []

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "medium").lower()
            evidence = vuln.get("evidence", {})

            result = {
                "ruleId": self._get_rule_id(vuln),
                "ruleIndex": 0,  # Will be updated
                "level": self.SEVERITY_MAP.get(severity, "warning"),
                "message": {
                    "text": vuln.get("description", vuln.get("title", "Vulnerability detected")),
                    "markdown": self._generate_message_markdown(vuln),
                },
                "locations": [self._generate_location(vuln, target_url)],
                "fingerprints": {
                    "primaryLocationLineHash": self._generate_fingerprint(vuln),
                },
                "partialFingerprints": {"primaryLocationLineHash": self._generate_fingerprint(vuln)[:16]},
                "properties": {
                    "vulnerability_type": vuln.get("type", "unknown"),
                    "module": vuln.get("_module", "Unknown"),
                    "cvss_score": vuln.get("cvss_score", 0.0),
                    "cvss_vector": vuln.get("cvss_vector", ""),
                    "cwe_id": vuln.get("cwe_id", ""),
                    "evidence": evidence,
                },
            }

            # Add fixes if remediation is available
            if vuln.get("remediation"):
                result["fixes"] = [{"description": {"text": vuln.get("remediation")}}]

            # Add code flows for attack evidence
            if evidence.get("payload"):
                result["codeFlows"] = [self._generate_code_flow(vuln, target_url)]

            results.append(result)

        return results

    def _generate_invocation(self, scan_data: dict[str, Any]) -> dict:
        """Generate SARIF invocation object"""
        return {
            "executionSuccessful": True,
            "startTimeUtc": scan_data.get("timestamp", datetime.now().isoformat()),
            "endTimeUtc": datetime.now().isoformat(),
            "workingDirectory": {"uri": "file:///"},
            "properties": {"target_url": scan_data.get("url", ""), "modules_executed": scan_data.get("modules", [])},
        }

    def _generate_artifact(self, target_url: str) -> dict:
        """Generate SARIF artifact for target URL"""
        parsed = urlparse(target_url)

        return {
            "location": {"uri": target_url, "uriBaseId": "%SRCROOT%"},
            "sourceLanguage": "html",
            "properties": {"host": parsed.netloc, "scheme": parsed.scheme, "path": parsed.path or "/"},
        }

    def _generate_location(self, vuln: dict, target_url: str) -> dict:
        """Generate SARIF location for vulnerability"""
        evidence = vuln.get("evidence", {})
        vuln_url = evidence.get("url", target_url)
        parameter = evidence.get("parameter", "")

        return {
            "physicalLocation": {
                "artifactLocation": {"uri": vuln_url, "uriBaseId": "%SRCROOT%"},
                "region": {
                    "startLine": 1,
                    "startColumn": 1,
                    "snippet": {"text": evidence.get("payload", "")[:200] if evidence.get("payload") else ""},
                },
            },
            "logicalLocations": [
                {
                    "name": parameter or "request",
                    "kind": "parameter",
                    "fullyQualifiedName": f"{vuln_url}?{parameter}" if parameter else vuln_url,
                }
            ],
        }

    def _generate_code_flow(self, vuln: dict, target_url: str) -> dict:
        """Generate code flow for attack visualization"""
        evidence = vuln.get("evidence", {})

        return {
            "threadFlows": [
                {
                    "locations": [
                        {
                            "location": {
                                "message": {"text": "User input received"},
                                "physicalLocation": {"artifactLocation": {"uri": target_url}},
                            },
                            "importance": "essential",
                        },
                        {
                            "location": {
                                "message": {"text": f"Payload injected: {evidence.get('payload', '')[:50]}"},
                                "physicalLocation": {"artifactLocation": {"uri": evidence.get("url", target_url)}},
                            },
                            "importance": "essential",
                        },
                        {
                            "location": {
                                "message": {"text": "Vulnerability triggered"},
                                "physicalLocation": {"artifactLocation": {"uri": evidence.get("url", target_url)}},
                            },
                            "importance": "essential",
                        },
                    ]
                }
            ]
        }

    def _generate_help_markdown(self, vuln: dict) -> str:
        """Generate markdown help content for rule"""
        title = vuln.get("title", "Vulnerability")
        description = vuln.get("description", "")
        remediation = vuln.get("remediation", "")
        cvss_score = vuln.get("cvss_score", 0.0)
        cvss_vector = vuln.get("cvss_vector", "")
        cwe_id = vuln.get("cwe_id", "")
        references = vuln.get("references", [])

        md = f"# {title}\n\n"
        md += f"{description}\n\n"

        if cvss_score:
            md += f"## CVSS Score: {cvss_score}\n"
            if cvss_vector:
                md += f"Vector: `{cvss_vector}`\n\n"

        if cwe_id:
            md += f"## CWE\n[{cwe_id}](https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html)\n\n"

        if remediation:
            md += f"## Remediation\n{remediation}\n\n"

        if references:
            md += "## References\n"
            for ref in references:
                md += f"- {ref}\n"

        return md

    def _generate_message_markdown(self, vuln: dict) -> str:
        """Generate markdown message for result"""
        evidence = vuln.get("evidence", {})

        md = f"**{vuln.get('title', 'Vulnerability Detected')}**\n\n"
        md += f"{vuln.get('description', '')}\n\n"

        if evidence.get("parameter"):
            md += f"- **Parameter:** `{evidence['parameter']}`\n"
        if evidence.get("payload"):
            md += f"- **Payload:** `{evidence['payload'][:100]}`\n"
        if evidence.get("url"):
            md += f"- **URL:** {evidence['url']}\n"

        return md

    def _get_rule_id(self, vuln: dict) -> str:
        """Generate unique rule ID for vulnerability type"""
        vuln_type = vuln.get("type", "unknown").lower().replace(" ", "_")
        cwe = vuln.get("cwe_id", "")

        if cwe:
            return f"WVS-{cwe}"

        return f"WVS-{vuln_type.upper()}"

    def _get_tags(self, vuln: dict) -> list[str]:
        """Get tags for vulnerability"""
        tags = ["security", "dast", "web"]

        vuln_type = vuln.get("type", "").lower()
        severity = vuln.get("severity", "").lower()

        if severity in ["critical", "high"]:
            tags.append("critical")

        # OWASP Top 10 mapping
        owasp_map = {
            "sql_injection": "A03:2021-Injection",
            "xss": "A03:2021-Injection",
            "command_injection": "A03:2021-Injection",
            "xxe": "A05:2021-Security-Misconfiguration",
            "ssrf": "A10:2021-SSRF",
            "broken_auth": "A07:2021-Identification-and-Authentication-Failures",
            "idor": "A01:2021-Broken-Access-Control",
            "csrf": "A01:2021-Broken-Access-Control",
        }

        for key, owasp in owasp_map.items():
            if key in vuln_type:
                tags.append(owasp)
                break

        return tags

    def _get_reference_uri(self, vuln: dict) -> str:
        """Get first reference URI or default"""
        references = vuln.get("references", [])
        cwe = vuln.get("cwe_id", "")

        if references:
            return references[0]

        if cwe:
            cwe_num = cwe.replace("CWE-", "")
            return f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"

        return "https://owasp.org/www-community/vulnerabilities/"

    def _severity_to_score(self, severity: str) -> str:
        """Convert severity to numeric score string"""
        scores = {
            "critical": "9.5",
            "high": "7.5",
            "medium": "5.0",
            "low": "2.5",
            "info": "0.0",
        }
        return scores.get(severity.lower(), "5.0")

    def _generate_fingerprint(self, vuln: dict) -> str:
        """Generate unique fingerprint for vulnerability"""
        evidence = vuln.get("evidence", {})
        unique_string = f"{vuln.get('type', '')}-{evidence.get('url', '')}-{evidence.get('parameter', '')}"
        return hashlib.sha256(unique_string.encode()).hexdigest()

    def _generate_guid(self, value: str) -> str:
        """Generate GUID from string"""
        h = hashlib.md5(value.encode(), usedforsecurity=False).hexdigest()
        return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


# Convenience function
def format_as_sarif(scan_data: dict[str, Any]) -> str:
    """
    Format scan data as SARIF.

    Args:
        scan_data: Scan results from scanner

    Returns:
        SARIF JSON string
    """
    formatter = SARIFFormatter()
    return formatter.format_report(scan_data)
