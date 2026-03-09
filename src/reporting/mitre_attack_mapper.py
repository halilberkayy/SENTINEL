"""
MITRE ATT&CK Mapping and Reporting Module

Maps vulnerability scan findings to MITRE ATT&CK tactics and techniques,
generates ATT&CK Navigator layer JSON files, technique coverage heatmaps,
and kill chain visualizations.

This is a REPORTING module that integrates with the existing report formatters.
It does NOT extend BaseScanner - it processes scan results post-scan.
"""

import json
import logging
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


# MITRE ATT&CK Enterprise Tactics (v14)
TACTICS = {
    "TA0043": {"name": "Reconnaissance", "shortname": "reconnaissance"},
    "TA0042": {"name": "Resource Development", "shortname": "resource-development"},
    "TA0001": {"name": "Initial Access", "shortname": "initial-access"},
    "TA0002": {"name": "Execution", "shortname": "execution"},
    "TA0003": {"name": "Persistence", "shortname": "persistence"},
    "TA0004": {"name": "Privilege Escalation", "shortname": "privilege-escalation"},
    "TA0005": {"name": "Defense Evasion", "shortname": "defense-evasion"},
    "TA0006": {"name": "Credential Access", "shortname": "credential-access"},
    "TA0007": {"name": "Discovery", "shortname": "discovery"},
    "TA0008": {"name": "Lateral Movement", "shortname": "lateral-movement"},
    "TA0009": {"name": "Collection", "shortname": "collection"},
    "TA0011": {"name": "Command and Control", "shortname": "command-and-control"},
    "TA0010": {"name": "Exfiltration", "shortname": "exfiltration"},
    "TA0040": {"name": "Impact", "shortname": "impact"},
}

# Vulnerability type -> MITRE ATT&CK technique mapping
VULN_TO_TECHNIQUE: dict[str, list[dict[str, str]]] = {
    # XSS variants
    "xss": [
        {"id": "T1189", "name": "Drive-by Compromise", "tactic": "TA0001"},
        {"id": "T1059.007", "name": "JavaScript", "tactic": "TA0002"},
    ],
    "dom_xss": [
        {"id": "T1189", "name": "Drive-by Compromise", "tactic": "TA0001"},
        {"id": "T1059.007", "name": "JavaScript", "tactic": "TA0002"},
    ],
    # SQL Injection
    "sqli": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "TA0001"},
        {"id": "T1505.001", "name": "SQL Stored Procedures", "tactic": "TA0003"},
    ],
    "sql_injection": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "TA0001"},
    ],
    # Command Injection
    "command_injection": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "TA0001"},
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "TA0002"},
    ],
    # SSRF
    "ssrf": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "TA0001"},
        {"id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "TA0006"},
    ],
    # XXE
    "xxe": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "TA0001"},
        {"id": "T1005", "name": "Data from Local System", "tactic": "TA0009"},
    ],
    # LFI/RFI
    "lfi": [
        {"id": "T1005", "name": "Data from Local System", "tactic": "TA0009"},
        {"id": "T1083", "name": "File and Directory Discovery", "tactic": "TA0007"},
    ],
    "rfi": [
        {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "TA0011"},
    ],
    # Authentication
    "auth_bypass": [
        {"id": "T1078", "name": "Valid Accounts", "tactic": "TA0001"},
        {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "TA0004"},
    ],
    "credential_default_creds": [
        {"id": "T1078.001", "name": "Default Accounts", "tactic": "TA0001"},
        {"id": "T1110", "name": "Brute Force", "tactic": "TA0006"},
    ],
    "credential_no_lockout": [
        {"id": "T1110", "name": "Brute Force", "tactic": "TA0006"},
        {"id": "T1110.001", "name": "Password Guessing", "tactic": "TA0006"},
    ],
    "credential_stuffing_vuln": [
        {"id": "T1110.004", "name": "Credential Stuffing", "tactic": "TA0006"},
    ],
    "credential_user_enumeration": [
        {"id": "T1589.001", "name": "Credentials", "tactic": "TA0043"},
    ],
    "credential_basic_auth": [
        {"id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "TA0006"},
    ],
    # CORS
    "cors": [
        {"id": "T1189", "name": "Drive-by Compromise", "tactic": "TA0001"},
    ],
    # CSRF
    "csrf": [
        {"id": "T1189", "name": "Drive-by Compromise", "tactic": "TA0001"},
    ],
    # Open Redirect
    "open_redirect": [
        {"id": "T1566.002", "name": "Spearphishing Link", "tactic": "TA0001"},
    ],
    "social_eng_open_redirect": [
        {"id": "T1566.002", "name": "Spearphishing Link", "tactic": "TA0001"},
    ],
    # JWT
    "jwt": [
        {"id": "T1078", "name": "Valid Accounts", "tactic": "TA0001"},
        {"id": "T1550.001", "name": "Application Access Token", "tactic": "TA0008"},
    ],
    # Deserialization
    "deserialization": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "TA0001"},
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "TA0002"},
    ],
    # SSTI
    "ssti": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "TA0001"},
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "TA0002"},
    ],
    # LDAP
    "ldap_injection": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "TA0001"},
        {"id": "T1087.002", "name": "Domain Account", "tactic": "TA0007"},
    ],
    "ldap_anonymous_bind": [
        {"id": "T1087.002", "name": "Domain Account", "tactic": "TA0007"},
    ],
    "ldap_kerberos_exposed": [
        {"id": "T1558.003", "name": "Kerberoasting", "tactic": "TA0006"},
    ],
    "ldap_gpo_exposure": [
        {"id": "T1615", "name": "Group Policy Discovery", "tactic": "TA0007"},
        {"id": "T1484.001", "name": "Group Policy Modification", "tactic": "TA0005"},
    ],
    # C2 Detection
    "c2_cobalt_strike": [
        {"id": "T1071.001", "name": "Web Protocols", "tactic": "TA0011"},
        {"id": "T1573", "name": "Encrypted Channel", "tactic": "TA0011"},
    ],
    "c2_sliver": [
        {"id": "T1071.001", "name": "Web Protocols", "tactic": "TA0011"},
    ],
    "c2_mythic": [
        {"id": "T1071.001", "name": "Web Protocols", "tactic": "TA0011"},
    ],
    "c2_dga_domains": [
        {"id": "T1568.002", "name": "Domain Generation Algorithms", "tactic": "TA0011"},
    ],
    "c2_suspicious_connections": [
        {"id": "T1071", "name": "Application Layer Protocol", "tactic": "TA0011"},
    ],
    # Stealth/OPSEC
    "stealth_proxy_detection": [
        {"id": "T1090", "name": "Proxy", "tactic": "TA0011"},
    ],
    "stealth_no_tls": [
        {"id": "T1040", "name": "Network Sniffing", "tactic": "TA0006"},
    ],
    "stealth_tls_downgrade": [
        {"id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "TA0006"},
    ],
    # Post-Exploitation
    "post_exploit_info_disclosure": [
        {"id": "T1016", "name": "System Network Configuration Discovery", "tactic": "TA0007"},
    ],
    "post_exploit_pivot_points": [
        {"id": "T1021", "name": "Remote Services", "tactic": "TA0008"},
        {"id": "T1570", "name": "Lateral Tool Transfer", "tactic": "TA0008"},
    ],
    "post_exploit_priv_esc": [
        {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "TA0004"},
    ],
    "post_exploit_cors_exfil": [
        {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "TA0010"},
    ],
    # Social Engineering
    "social_eng_email_security": [
        {"id": "T1566.002", "name": "Spearphishing Link", "tactic": "TA0001"},
        {"id": "T1586.002", "name": "Email Accounts", "tactic": "TA0042"},
    ],
    "social_eng_typosquatting": [
        {"id": "T1583.001", "name": "Domains", "tactic": "TA0042"},
        {"id": "T1566", "name": "Phishing", "tactic": "TA0001"},
    ],
    "social_eng_metadata_leakage": [
        {"id": "T1589", "name": "Gather Victim Identity Information", "tactic": "TA0043"},
        {"id": "T1591", "name": "Gather Victim Org Information", "tactic": "TA0043"},
    ],
    # Evasion
    "evasion_request_smuggling": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "TA0001"},
        {"id": "T1036", "name": "Masquerading", "tactic": "TA0005"},
    ],
    "evasion_waf_bypass": [
        {"id": "T1562.001", "name": "Disable or Modify Tools", "tactic": "TA0005"},
    ],
    "evasion_encoding_bypass": [
        {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "TA0005"},
    ],
    # Exfiltration
    "exfil_dns_tunneling": [
        {"id": "T1048.001", "name": "Exfiltration Over Symmetric Encrypted Non-C2 Protocol", "tactic": "TA0010"},
        {"id": "T1071.004", "name": "DNS", "tactic": "TA0011"},
    ],
    "exfil_covert_channel": [
        {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "TA0010"},
    ],
    "exfil_data_exposure": [
        {"id": "T1530", "name": "Data from Cloud Storage", "tactic": "TA0009"},
    ],
    # Persistence
    "persistence_webshell": [
        {"id": "T1505.003", "name": "Web Shell", "tactic": "TA0003"},
    ],
    "persistence_scheduled_task": [
        {"id": "T1053", "name": "Scheduled Task/Job", "tactic": "TA0003"},
    ],
    "persistence_service": [
        {"id": "T1543", "name": "Create or Modify System Process", "tactic": "TA0003"},
    ],
    "persistence_backdoor": [
        {"id": "T1505", "name": "Server Software Component", "tactic": "TA0003"},
    ],
    # Infrastructure
    "misconfig": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "TA0001"},
    ],
    "webshell": [
        {"id": "T1505.003", "name": "Web Shell", "tactic": "TA0003"},
    ],
    "supply_chain": [
        {"id": "T1195", "name": "Supply Chain Compromise", "tactic": "TA0001"},
    ],
}

# Severity to ATT&CK Navigator color mapping
SEVERITY_COLORS = {
    "critical": "#ff0000",
    "high": "#ff6600",
    "medium": "#ffcc00",
    "low": "#99cc00",
    "info": "#66b2ff",
}

# Kill Chain phases mapping
KILL_CHAIN_PHASES = [
    {"phase": "Reconnaissance", "tactics": ["TA0043"]},
    {"phase": "Weaponization", "tactics": ["TA0042"]},
    {"phase": "Delivery", "tactics": ["TA0001"]},
    {"phase": "Exploitation", "tactics": ["TA0002"]},
    {"phase": "Installation", "tactics": ["TA0003"]},
    {"phase": "Command & Control", "tactics": ["TA0011"]},
    {"phase": "Actions on Objectives", "tactics": ["TA0004", "TA0005", "TA0006", "TA0007", "TA0008", "TA0009", "TA0010", "TA0040"]},
]


class MITREAttackMapper:
    """
    Maps scan findings to MITRE ATT&CK framework and generates reports.

    This module processes scan results and produces:
    - ATT&CK technique mappings for each finding
    - Navigator layer JSON for ATT&CK Navigator visualization
    - Technique coverage heatmaps
    - Kill chain visualization data
    """

    def __init__(self):
        self.mappings: list[dict[str, Any]] = []
        self.technique_hits: Counter = Counter()
        self.tactic_hits: Counter = Counter()

    def map_findings(self, scan_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Map scan findings to MITRE ATT&CK techniques.

        Args:
            scan_results: List of scan result dicts (from ScanResult.__dict__)

        Returns:
            List of mapped findings with ATT&CK references.
        """
        self.mappings = []
        self.technique_hits = Counter()
        self.tactic_hits = Counter()

        for result in scan_results:
            vulnerabilities = result.get("vulnerabilities", [])
            module_name = result.get("module_name", "unknown")

            for vuln in vulnerabilities:
                vuln_type = vuln.get("type", "").lower()
                severity = vuln.get("severity", "info").lower()
                title = vuln.get("title", "Unknown Vulnerability")

                # Look up techniques for this vulnerability type
                techniques = self._lookup_techniques(vuln_type)

                if techniques:
                    mapping = {
                        "finding": title,
                        "vulnerability_type": vuln_type,
                        "severity": severity,
                        "module": module_name,
                        "techniques": techniques,
                        "tactics": list(set(t["tactic"] for t in techniques)),
                    }
                    self.mappings.append(mapping)

                    # Count hits
                    for tech in techniques:
                        self.technique_hits[tech["id"]] += 1
                        self.tactic_hits[tech["tactic"]] += 1

        return self.mappings

    def _lookup_techniques(self, vuln_type: str) -> list[dict[str, str]]:
        """Look up MITRE ATT&CK techniques for a vulnerability type."""
        # Direct match
        if vuln_type in VULN_TO_TECHNIQUE:
            return VULN_TO_TECHNIQUE[vuln_type]

        # Partial match
        for key, techniques in VULN_TO_TECHNIQUE.items():
            if key in vuln_type or vuln_type in key:
                return techniques

        # Fallback: generic initial access for unknown vulns
        return [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "TA0001"}]

    def generate_navigator_layer(
        self,
        name: str = "SENTINEL Scan Results",
        description: str = "Auto-generated from SENTINEL vulnerability scan",
    ) -> dict[str, Any]:
        """
        Generate ATT&CK Navigator layer JSON.

        This JSON can be imported into MITRE ATT&CK Navigator
        (https://mitre-attack.github.io/attack-navigator/) for visualization.
        """
        techniques = []
        technique_details: dict[str, dict] = {}

        for mapping in self.mappings:
            severity = mapping["severity"]
            for tech in mapping["techniques"]:
                tech_id = tech["id"]

                if tech_id not in technique_details:
                    technique_details[tech_id] = {
                        "techniqueID": tech_id,
                        "tactic": TACTICS.get(tech["tactic"], {}).get("shortname", ""),
                        "color": SEVERITY_COLORS.get(severity, "#66b2ff"),
                        "comment": "",
                        "enabled": True,
                        "metadata": [],
                        "links": [],
                        "showSubtechniques": "." in tech_id,
                        "score": 0,
                    }

                # Update score (higher severity = higher score)
                severity_scores = {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 10}
                new_score = severity_scores.get(severity, 10)
                if new_score > technique_details[tech_id]["score"]:
                    technique_details[tech_id]["score"] = new_score
                    technique_details[tech_id]["color"] = SEVERITY_COLORS.get(severity, "#66b2ff")

                # Add finding as metadata
                technique_details[tech_id]["comment"] += f"- {mapping['finding']}\n"
                technique_details[tech_id]["metadata"].append({
                    "name": "finding",
                    "value": mapping["finding"],
                })

        techniques = list(technique_details.values())

        layer = {
            "name": name,
            "versions": {
                "attack": "14",
                "navigator": "4.9.1",
                "layer": "4.5",
            },
            "domain": "enterprise-attack",
            "description": description,
            "filters": {
                "platforms": ["Linux", "macOS", "Windows", "Network", "Cloud", "Containers"],
            },
            "sorting": 3,  # Sort by score descending
            "layout": {
                "layout": "side",
                "aggregateFunction": "max",
                "showID": True,
                "showName": True,
                "showAggregateScores": True,
                "countUnscored": False,
            },
            "hideDisabled": False,
            "techniques": techniques,
            "gradient": {
                "colors": ["#66b2ff", "#99cc00", "#ffcc00", "#ff6600", "#ff0000"],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [
                {"label": "Critical", "color": "#ff0000"},
                {"label": "High", "color": "#ff6600"},
                {"label": "Medium", "color": "#ffcc00"},
                {"label": "Low", "color": "#99cc00"},
                {"label": "Info", "color": "#66b2ff"},
            ],
            "metadata": [
                {"name": "generated_by", "value": "SENTINEL Security Scanner"},
                {"name": "generated_at", "value": datetime.now().isoformat()},
                {"name": "total_findings", "value": str(len(self.mappings))},
            ],
            "links": [],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False,
            "selectVisibleTechniques": False,
        }

        return layer

    def generate_heatmap(self) -> dict[str, Any]:
        """Generate technique coverage heatmap data."""
        heatmap: dict[str, Any] = {
            "generated_at": datetime.now().isoformat(),
            "total_techniques_mapped": len(self.technique_hits),
            "total_tactics_covered": len(self.tactic_hits),
            "tactics_coverage": {},
            "top_techniques": [],
        }

        # Tactic coverage
        for tactic_id, info in TACTICS.items():
            count = self.tactic_hits.get(tactic_id, 0)
            heatmap["tactics_coverage"][info["name"]] = {
                "id": tactic_id,
                "hit_count": count,
                "intensity": min(count / 5, 1.0) if count > 0 else 0,  # Normalize 0-1
            }

        # Top techniques
        heatmap["top_techniques"] = [
            {
                "id": tech_id,
                "name": self._get_technique_name(tech_id),
                "hit_count": count,
            }
            for tech_id, count in self.technique_hits.most_common(20)
        ]

        return heatmap

    def generate_kill_chain(self) -> dict[str, Any]:
        """Generate kill chain visualization data."""
        kill_chain: dict[str, Any] = {
            "generated_at": datetime.now().isoformat(),
            "phases": [],
            "attack_paths": [],
        }

        for phase_info in KILL_CHAIN_PHASES:
            phase_name = phase_info["phase"]
            phase_tactics = phase_info["tactics"]

            findings = []
            for mapping in self.mappings:
                for tactic in mapping["tactics"]:
                    if tactic in phase_tactics:
                        findings.append({
                            "finding": mapping["finding"],
                            "severity": mapping["severity"],
                            "techniques": [t["id"] for t in mapping["techniques"]],
                        })
                        break

            kill_chain["phases"].append({
                "name": phase_name,
                "findings_count": len(findings),
                "findings": findings[:10],  # Limit per phase
                "covered": len(findings) > 0,
            })

        # Calculate coverage
        covered = sum(1 for p in kill_chain["phases"] if p["covered"])
        kill_chain["coverage_percentage"] = round(covered / len(KILL_CHAIN_PHASES) * 100, 1)

        return kill_chain

    def _get_technique_name(self, technique_id: str) -> str:
        """Get technique name from ID."""
        for techniques in VULN_TO_TECHNIQUE.values():
            for tech in techniques:
                if tech["id"] == technique_id:
                    return tech["name"]
        return technique_id

    def generate_full_report(self, scan_results: list[dict[str, Any]], target_url: str = "") -> dict[str, Any]:
        """
        Generate a complete MITRE ATT&CK report from scan results.

        Args:
            scan_results: List of scan result dictionaries
            target_url: The scanned target URL

        Returns:
            Complete report with mappings, navigator layer, heatmap, and kill chain.
        """
        self.map_findings(scan_results)

        return {
            "report_type": "mitre_attack",
            "generated_at": datetime.now().isoformat(),
            "target": target_url,
            "summary": {
                "total_findings_mapped": len(self.mappings),
                "unique_techniques": len(self.technique_hits),
                "tactics_covered": len(self.tactic_hits),
                "top_tactic": (
                    TACTICS.get(self.tactic_hits.most_common(1)[0][0], {}).get("name", "N/A")
                    if self.tactic_hits
                    else "N/A"
                ),
            },
            "mappings": self.mappings,
            "navigator_layer": self.generate_navigator_layer(
                name=f"SENTINEL - {target_url}",
                description=f"Vulnerability scan results for {target_url}",
            ),
            "heatmap": self.generate_heatmap(),
            "kill_chain": self.generate_kill_chain(),
        }

    def export_navigator_json(self, output_path: str, scan_results: list[dict[str, Any]] | None = None) -> str:
        """
        Export ATT&CK Navigator layer as JSON file.

        Args:
            output_path: Path to save the JSON file
            scan_results: Optional - if provided, will map findings first

        Returns:
            Path to the generated file
        """
        if scan_results:
            self.map_findings(scan_results)

        layer = self.generate_navigator_layer()

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(layer, f, indent=2, default=str)

        logger.info(f"ATT&CK Navigator layer exported to {output_path}")
        return output_path

    def format_markdown_report(self) -> str:
        """Generate a Markdown-formatted MITRE ATT&CK report."""
        lines = [
            "# MITRE ATT&CK Mapping Report",
            f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"\n## Summary",
            f"\n- **Total Findings Mapped**: {len(self.mappings)}",
            f"- **Unique Techniques**: {len(self.technique_hits)}",
            f"- **Tactics Covered**: {len(self.tactic_hits)} / {len(TACTICS)}",
            "\n## Tactic Coverage\n",
            "| Tactic | Findings |",
            "|--------|----------|",
        ]

        for tactic_id, info in TACTICS.items():
            count = self.tactic_hits.get(tactic_id, 0)
            indicator = "***" if count > 3 else "**" if count > 0 else ""
            lines.append(f"| {info['name']} | {count} {indicator}|")

        lines.extend([
            "\n## Top Techniques\n",
            "| Technique ID | Name | Occurrences |",
            "|-------------|------|-------------|",
        ])

        for tech_id, count in self.technique_hits.most_common(15):
            name = self._get_technique_name(tech_id)
            lines.append(f"| {tech_id} | {name} | {count} |")

        lines.extend([
            "\n## Kill Chain Coverage\n",
        ])

        kill_chain = self.generate_kill_chain()
        for phase in kill_chain["phases"]:
            status = "[X]" if phase["covered"] else "[ ]"
            lines.append(f"- {status} **{phase['name']}**: {phase['findings_count']} finding(s)")

        lines.append(f"\n**Kill Chain Coverage**: {kill_chain['coverage_percentage']}%")

        lines.extend([
            "\n## Detailed Mappings\n",
        ])

        for mapping in self.mappings:
            techniques_str = ", ".join(f"{t['id']} ({t['name']})" for t in mapping["techniques"])
            lines.append(f"### {mapping['finding']}")
            lines.append(f"- **Severity**: {mapping['severity']}")
            lines.append(f"- **Module**: {mapping['module']}")
            lines.append(f"- **Techniques**: {techniques_str}")
            lines.append("")

        return "\n".join(lines)
