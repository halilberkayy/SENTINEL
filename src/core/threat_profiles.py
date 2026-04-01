"""
Threat Actor Profile Library and TTP Matching Engine.
Maps findings to known APT groups via MITRE ATT&CK technique correlation.

Updated for ATT&CK v18 (October 2025):
  - 216 Techniques, 475 Sub-Techniques
  - New: T1059.013 (Container CLI/API), T1680 (Local Storage Discovery),
         T1213.006 (Databases), T1651 (Cloud Admin Command)
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)


# Built-in threat actor profiles with MITRE ATT&CK TTPs
BUILTIN_PROFILES: list[dict[str, Any]] = [
    {
        "name": "APT28",
        "aliases": ["Fancy Bear", "Sofacy", "Pawn Storm", "Sednit", "STRONTIUM"],
        "description": "Russian state-sponsored threat group attributed to GRU Unit 26165. Active since at least 2004, targeting government, military, and security organizations worldwide.",
        "country_origin": "Russia",
        "motivation": "espionage",
        "target_sectors": ["government", "military", "defense", "media", "political"],
        "active_since": "2004",
        "ttps": {
            "tactics": {
                "TA0043": ["T1598", "T1589"],
                "TA0001": ["T1566.001", "T1190", "T1133"],
                "TA0002": ["T1059.001", "T1059.005", "T1204.001"],
                "TA0003": ["T1547.001", "T1053.005"],
                "TA0004": ["T1068", "T1055"],
                "TA0005": ["T1027", "T1070.004", "T1112"],
                "TA0006": ["T1110", "T1056.001", "T1003"],
                "TA0007": ["T1082", "T1083"],
                "TA0008": ["T1021.002"],
                "TA0010": ["T1041", "T1048"],
                "TA0011": ["T1071.001", "T1573"],
            }
        },
        "tools": ["X-Agent", "X-Tunnel", "Seduploader", "Zebrocy", "Mimikatz"],
        "iocs": {},
        "references": [
            "https://attack.mitre.org/groups/G0007/",
            "https://www.fireeye.com/content/dam/fireeye-www/solutions/pdfs/st-apt28.pdf",
        ],
    },
    {
        "name": "APT29",
        "aliases": ["Cozy Bear", "The Dukes", "NOBELIUM", "Midnight Blizzard"],
        "description": "Russian state-sponsored threat group attributed to SVR. Known for sophisticated supply chain attacks and long-term espionage campaigns.",
        "country_origin": "Russia",
        "motivation": "espionage",
        "target_sectors": ["government", "technology", "think_tanks", "healthcare"],
        "active_since": "2008",
        "ttps": {
            "tactics": {
                "TA0043": ["T1598", "T1593"],
                "TA0001": ["T1195.002", "T1566.001", "T1190"],
                "TA0002": ["T1059.001", "T1059.003"],
                "TA0003": ["T1547.001", "T1053.005", "T1505.003"],
                "TA0005": ["T1027", "T1140", "T1070.006"],
                "TA0006": ["T1003", "T1558"],
                "TA0007": ["T1087", "T1069"],
                "TA0008": ["T1021.002", "T1550.001"],
                "TA0009": ["T1114"],
                "TA0010": ["T1041"],
                "TA0011": ["T1071.001", "T1102"],
            }
        },
        "tools": ["SUNBURST", "TEARDROP", "EnvyScout", "BoomBox", "Cobalt Strike"],
        "iocs": {},
        "references": ["https://attack.mitre.org/groups/G0016/"],
    },
    {
        "name": "APT41",
        "aliases": ["Winnti", "Barium", "Wicked Panda", "Double Dragon"],
        "description": "Chinese state-sponsored threat group that conducts both espionage and financially motivated operations. Unique dual-mission group.",
        "country_origin": "China",
        "motivation": "espionage",
        "target_sectors": ["technology", "healthcare", "gaming", "telecommunications", "finance"],
        "active_since": "2012",
        "ttps": {
            "tactics": {
                "TA0001": ["T1190", "T1195.002", "T1566.001"],
                "TA0002": ["T1059.001", "T1059.003", "T1059.006"],
                "TA0003": ["T1547.001", "T1543.003", "T1505.003"],
                "TA0005": ["T1027", "T1055", "T1036"],
                "TA0006": ["T1003", "T1552.001"],
                "TA0008": ["T1021.001", "T1021.002"],
                "TA0010": ["T1041", "T1567"],
                "TA0011": ["T1071.001", "T1095"],
            }
        },
        "tools": ["ShadowPad", "Winnti", "PlugX", "Cobalt Strike", "Acunetix"],
        "iocs": {},
        "references": ["https://attack.mitre.org/groups/G0096/"],
    },
    {
        "name": "Lazarus Group",
        "aliases": ["Hidden Cobra", "Zinc", "Diamond Sleet", "Labyrinth Chollima"],
        "description": "North Korean state-sponsored threat group responsible for major financial theft and destructive attacks, including the Sony Pictures hack and WannaCry.",
        "country_origin": "North Korea",
        "motivation": "financial",
        "target_sectors": ["finance", "cryptocurrency", "defense", "entertainment", "technology"],
        "active_since": "2009",
        "ttps": {
            "tactics": {
                "TA0001": ["T1566.001", "T1566.002", "T1190", "T1189"],
                "TA0002": ["T1059.001", "T1059.003", "T1059.005"],
                "TA0003": ["T1547.001", "T1053.005"],
                "TA0005": ["T1027", "T1070", "T1140"],
                "TA0006": ["T1003", "T1056.001"],
                "TA0040": ["T1486", "T1561.002"],
                "TA0011": ["T1071.001", "T1573"],
            }
        },
        "tools": ["HOPLIGHT", "ELECTRICFISH", "AppleJeus", "DTrack"],
        "iocs": {},
        "references": ["https://attack.mitre.org/groups/G0032/"],
    },
    {
        "name": "FIN7",
        "aliases": ["Carbanak Group", "Navigator Group", "Sangria Tempest"],
        "description": "Financially motivated threat group targeting the restaurant, hospitality, and retail sectors primarily in the US. Known for sophisticated phishing and POS malware.",
        "country_origin": "Unknown",
        "motivation": "financial",
        "target_sectors": ["retail", "hospitality", "restaurant", "finance"],
        "active_since": "2013",
        "ttps": {
            "tactics": {
                "TA0001": ["T1566.001", "T1566.002"],
                "TA0002": ["T1059.001", "T1059.003", "T1059.005"],
                "TA0003": ["T1547.001", "T1053.005"],
                "TA0005": ["T1027", "T1036", "T1055"],
                "TA0006": ["T1056.001"],
                "TA0009": ["T1005", "T1113"],
                "TA0010": ["T1041"],
                "TA0011": ["T1071.001", "T1105"],
            }
        },
        "tools": ["Carbanak", "GRIFFON", "HALFBAKED", "Cobalt Strike"],
        "iocs": {},
        "references": ["https://attack.mitre.org/groups/G0046/"],
    },
    {
        "name": "Turla",
        "aliases": ["Snake", "Venomous Bear", "Waterbug", "Secret Blizzard"],
        "description": "Russian state-sponsored threat group attributed to FSB. Known for highly sophisticated operations and satellite-based C2 infrastructure.",
        "country_origin": "Russia",
        "motivation": "espionage",
        "target_sectors": ["government", "military", "education", "research"],
        "active_since": "1996",
        "ttps": {
            "tactics": {
                "TA0043": ["T1595", "T1590"],
                "TA0001": ["T1189", "T1566.001", "T1190"],
                "TA0002": ["T1059.001", "T1059.003"],
                "TA0003": ["T1547.001", "T1543.003"],
                "TA0005": ["T1027", "T1014", "T1036"],
                "TA0006": ["T1003", "T1552.001"],
                "TA0007": ["T1046", "T1082"],
                "TA0010": ["T1041", "T1029"],
                "TA0011": ["T1071.001", "T1071.004", "T1102"],
            }
        },
        "tools": ["Snake", "Carbon", "Kazuar", "LightNeuron", "Gazer"],
        "iocs": {},
        "references": ["https://attack.mitre.org/groups/G0010/"],
    },
    {
        "name": "OceanLotus",
        "aliases": ["APT32", "Canvas Cyclone", "SeaLotus"],
        "description": "Vietnamese state-sponsored threat group targeting private sector organizations in Southeast Asia, particularly in manufacturing, media, and banking.",
        "country_origin": "Vietnam",
        "motivation": "espionage",
        "target_sectors": ["manufacturing", "media", "banking", "technology"],
        "active_since": "2012",
        "ttps": {
            "tactics": {
                "TA0001": ["T1566.001", "T1189", "T1195.002"],
                "TA0002": ["T1059.001", "T1059.003", "T1059.005"],
                "TA0003": ["T1547.001", "T1053.005"],
                "TA0005": ["T1027", "T1036", "T1070.006"],
                "TA0006": ["T1003"],
                "TA0010": ["T1041"],
                "TA0011": ["T1071.001", "T1573"],
            }
        },
        "tools": ["Denis", "Kerrdown", "METALJACK", "Cobalt Strike"],
        "iocs": {},
        "references": ["https://attack.mitre.org/groups/G0050/"],
    },
    {
        "name": "Sandworm",
        "aliases": ["Voodoo Bear", "IRIDIUM", "Seashell Blizzard", "Telebots"],
        "description": "Russian state-sponsored threat group attributed to GRU Unit 74455. Known for destructive attacks including NotPetya and attacks on Ukrainian infrastructure.",
        "country_origin": "Russia",
        "motivation": "destruction",
        "target_sectors": ["energy", "government", "finance", "transportation", "media"],
        "active_since": "2009",
        "ttps": {
            "tactics": {
                "TA0001": ["T1190", "T1566.001", "T1195.002"],
                "TA0002": ["T1059.001", "T1059.003"],
                "TA0003": ["T1547.001", "T1053.005"],
                "TA0005": ["T1027", "T1070", "T1014"],
                "TA0006": ["T1003", "T1110"],
                "TA0008": ["T1021.002", "T1570"],
                "TA0040": ["T1486", "T1561", "T1499"],
                "TA0011": ["T1071.001", "T1095"],
            }
        },
        "tools": ["BlackEnergy", "Industroyer", "NotPetya", "Olympic Destroyer", "CaddyWiper"],
        "iocs": {},
        "references": ["https://attack.mitre.org/groups/G0034/"],
    },
    {
        "name": "MuddyWater",
        "aliases": ["Mercury", "Mango Sandstorm", "Static Kitten", "TEMP.Zagros"],
        "description": "Iranian state-sponsored threat group attributed to MOIS. Conducts espionage operations primarily targeting Middle Eastern and Central Asian nations.",
        "country_origin": "Iran",
        "motivation": "espionage",
        "target_sectors": ["government", "telecommunications", "oil_gas", "defense"],
        "active_since": "2017",
        "ttps": {
            "tactics": {
                "TA0001": ["T1566.001", "T1566.002"],
                "TA0002": ["T1059.001", "T1059.005", "T1204.002"],
                "TA0003": ["T1547.001", "T1053.005"],
                "TA0005": ["T1027", "T1140"],
                "TA0006": ["T1003", "T1056.001"],
                "TA0007": ["T1082", "T1033"],
                "TA0010": ["T1041"],
                "TA0011": ["T1071.001", "T1105"],
            }
        },
        "tools": ["POWERSTATS", "MuddyC3", "Aclip", "SimpleHerp"],
        "iocs": {},
        "references": ["https://attack.mitre.org/groups/G0069/"],
    },
    {
        "name": "Carbanak",
        "aliases": ["Anunak", "Carbon Spider"],
        "description": "Financially motivated threat group responsible for stealing over $1 billion from banks worldwide through sophisticated network intrusions.",
        "country_origin": "Unknown",
        "motivation": "financial",
        "target_sectors": ["finance", "banking", "hospitality"],
        "active_since": "2013",
        "ttps": {
            "tactics": {
                "TA0001": ["T1566.001", "T1566.002"],
                "TA0002": ["T1059.001", "T1059.003"],
                "TA0003": ["T1547.001", "T1543.003"],
                "TA0005": ["T1036", "T1055", "T1112"],
                "TA0006": ["T1056.001", "T1003"],
                "TA0007": ["T1083", "T1057"],
                "TA0009": ["T1113", "T1125"],
                "TA0010": ["T1041"],
                "TA0011": ["T1071.001", "T1105"],
            }
        },
        "tools": ["Carbanak", "Cobalt Strike"],
        "iocs": {},
        "references": ["https://attack.mitre.org/groups/G0008/"],
    },
]


# Vulnerability type -> MITRE ATT&CK v18 technique mapping
VULN_TYPE_TO_TECHNIQUES: dict[str, list[str]] = {
    # Injection / Initial Access
    "xss": ["T1189", "T1059.007"],
    "dom_xss": ["T1189", "T1059.007"],
    "sqli": ["T1190", "T1505.001"],
    "sql_injection": ["T1190", "T1213.006"],  # v18: Databases
    "ssrf": ["T1190", "T1071.001", "T1552.005"],
    "xxe": ["T1190", "T1005"],
    "command_injection": ["T1190", "T1059.004"],
    "lfi": ["T1190", "T1005"],
    "rfi": ["T1190", "T1105"],
    "ssti": ["T1190", "T1059"],
    "ssi": ["T1190", "T1059"],
    "deserialization": ["T1190", "T1059"],
    "csrf": ["T1189", "T1204.001"],
    "open_redirect": ["T1189", "T1566.002"],
    "proto_pollution": ["T1189", "T1059.007"],
    # Access Control / Auth
    "broken_access_control": ["T1068", "T1548"],
    "auth_bypass": ["T1068", "T1110"],
    "default_credentials": ["T1078.001"],
    "weak_password": ["T1110", "T1110.001"],
    "jwt_vuln": ["T1068", "T1550.001"],
    "cors_misconfiguration": ["T1189", "T1557"],
    # Misconfig / Info Disclosure
    "security_misconfiguration": ["T1190", "T1082"],
    "misconfig": ["T1190", "T1082"],
    "information_disclosure": ["T1082", "T1083", "T1580"],
    "directory_listing": ["T1083", "T1217", "T1680"],  # v18: Local Storage Discovery
    "insecure_cookie": ["T1539"],
    "security_headers_missing": ["T1189"],
    # Red Team / Post-Exploit
    "webshell": ["T1505.003"],
    "backdoor": ["T1505.003", "T1546"],
    "c2_indicator": ["T1071.001", "T1095", "T1572"],
    "dns_tunneling": ["T1071.004", "T1048.001"],
    "data_exfiltration": ["T1041", "T1048", "T1567"],
    "privilege_escalation": ["T1068", "T1548"],
    "lateral_movement": ["T1021", "T1570"],
    "persistence": ["T1547.001", "T1053.005", "T1546.015"],
    # Cloud / Supply Chain
    "cloud_misconfiguration": ["T1190", "T1580", "T1651"],  # v18: Cloud Admin Command
    "supply_chain": ["T1195.002", "T1195.003"],
    "container_escape": ["T1611", "T1059.013"],  # v18: Container CLI/API
    # Attack Chains
    "attack_chain": ["T1190", "T1078"],
}


class ThreatMatcher:
    """Match findings against threat actor profiles using MITRE technique correlation."""

    @staticmethod
    def extract_techniques_from_findings(findings: list[dict]) -> set[str]:
        """Extract all MITRE techniques from a list of findings."""
        techniques = set()
        for finding in findings:
            # From explicit mitre_techniques field
            for tech in finding.get("mitre_techniques", []):
                if isinstance(tech, dict):
                    techniques.add(tech.get("id", ""))
                elif isinstance(tech, str):
                    techniques.add(tech)

            # From vulnerability type mapping
            vuln_type = finding.get("type", "").lower()
            for mapped_tech in VULN_TYPE_TO_TECHNIQUES.get(vuln_type, []):
                techniques.add(mapped_tech)

        techniques.discard("")
        return techniques

    @staticmethod
    def extract_profile_techniques(profile_ttps: dict) -> set[str]:
        """Extract all techniques from a threat profile's TTPs."""
        techniques = set()
        tactics = profile_ttps.get("tactics", {})
        for tactic_id, tech_list in tactics.items():
            for tech in tech_list:
                techniques.add(tech)
        return techniques

    def match(
        self, finding_techniques: set[str], profiles: list[dict]
    ) -> list[dict]:
        """
        Match finding techniques against threat profiles.

        Returns:
            Sorted list of matches with coverage percentage.
        """
        matches = []
        for profile in profiles:
            profile_techs = self.extract_profile_techniques(profile.get("ttps", {}))
            if not profile_techs:
                continue

            matched = finding_techniques & profile_techs
            coverage = (len(matched) / len(profile_techs)) * 100 if profile_techs else 0

            if matched:
                matches.append({
                    "profile_id": profile.get("id", ""),
                    "profile_name": profile.get("name", ""),
                    "coverage_pct": round(coverage, 1),
                    "matched_techniques": sorted(matched),
                    "total_techniques": len(profile_techs),
                })

        # Sort by coverage descending
        matches.sort(key=lambda m: m["coverage_pct"], reverse=True)
        return matches
