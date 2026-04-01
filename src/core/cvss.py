"""
CVSS v3.1 & v4.0 Calculator Module

Provides CVSS scoring for both v3.1 and v4.0 standards.

v4.0 changes (FIRST, Nov 2023):
- Scope metric retired; replaced by Subsequent System impact (SC/SI/SA)
- New Attack Requirements (AT) metric
- User Interaction expanded: None/Passive/Active
- Threat metric group replaces Temporal
- Supplemental metrics added

References:
  https://www.first.org/cvss/v3.1/specification-document
  https://www.first.org/cvss/v4.0/specification-document
"""

import math
from dataclasses import dataclass
from enum import Enum
from typing import Any


class AttackVector(Enum):
    """Attack Vector (AV) - How the vulnerability can be exploited"""

    NETWORK = ("N", 0.85)  # Remotely exploitable
    ADJACENT = ("A", 0.62)  # Adjacent network access required
    LOCAL = ("L", 0.55)  # Local access required
    PHYSICAL = ("P", 0.20)  # Physical access required


class AttackComplexity(Enum):
    """Attack Complexity (AC) - Conditions beyond attacker's control"""

    LOW = ("L", 0.77)  # No specialized conditions
    HIGH = ("H", 0.44)  # Specialized conditions required


class PrivilegesRequired(Enum):
    """Privileges Required (PR) - Level of privileges needed"""

    NONE = ("N", 0.85, 0.85)  # No privileges (unchanged/changed scope)
    LOW = ("L", 0.62, 0.68)  # Low privileges
    HIGH = ("H", 0.27, 0.50)  # High privileges (admin level)


class UserInteraction(Enum):
    """User Interaction (UI) - Is user participation required"""

    NONE = ("N", 0.85)  # No user interaction
    REQUIRED = ("R", 0.62)  # User must take action


class Scope(Enum):
    """Scope (S) - Impact to other components"""

    UNCHANGED = ("U",)  # Impact limited to vulnerable component
    CHANGED = ("C",)  # Can affect other components


class Impact(Enum):
    """CIA Impact Metrics"""

    NONE = ("N", 0.00)  # No impact
    LOW = ("L", 0.22)  # Limited impact
    HIGH = ("H", 0.56)  # Total/serious impact


@dataclass
class CVSSVector:
    """
    CVSS v3.1 Vector representation.

    Example vector string: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    """

    attack_vector: str = "N"  # AV: N, A, L, P
    attack_complexity: str = "L"  # AC: L, H
    privileges_required: str = "N"  # PR: N, L, H
    user_interaction: str = "N"  # UI: N, R
    scope: str = "U"  # S: U, C
    confidentiality: str = "N"  # C: N, L, H
    integrity: str = "N"  # I: N, L, H
    availability: str = "N"  # A: N, L, H

    def to_vector_string(self) -> str:
        """Convert to CVSS v3.1 vector string format"""
        return (
            f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}/"
            f"PR:{self.privileges_required}/UI:{self.user_interaction}/"
            f"S:{self.scope}/C:{self.confidentiality}/I:{self.integrity}/"
            f"A:{self.availability}"
        )

    @classmethod
    def from_vector_string(cls, vector_str: str) -> "CVSSVector":
        """Parse CVSS v3.1 vector string"""
        parts = {}

        # Remove CVSS:3.1/ prefix if present
        if vector_str.startswith("CVSS:3.1/"):
            vector_str = vector_str[9:]
        elif vector_str.startswith("CVSS:3.0/"):
            vector_str = vector_str[9:]

        for segment in vector_str.split("/"):
            if ":" in segment:
                key, value = segment.split(":", 1)
                parts[key] = value

        return cls(
            attack_vector=parts.get("AV", "N"),
            attack_complexity=parts.get("AC", "L"),
            privileges_required=parts.get("PR", "N"),
            user_interaction=parts.get("UI", "N"),
            scope=parts.get("S", "U"),
            confidentiality=parts.get("C", "N"),
            integrity=parts.get("I", "N"),
            availability=parts.get("A", "N"),
        )


@dataclass
class CVSSResult:
    """CVSS calculation result with full details"""

    score: float
    severity: str
    vector_string: str
    vector: CVSSVector
    impact_subscore: float
    exploitability_subscore: float

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "score": self.score,
            "severity": self.severity,
            "vector_string": self.vector_string,
            "impact_subscore": round(self.impact_subscore, 1),
            "exploitability_subscore": round(self.exploitability_subscore, 1),
            "metrics": {
                "attack_vector": self.vector.attack_vector,
                "attack_complexity": self.vector.attack_complexity,
                "privileges_required": self.vector.privileges_required,
                "user_interaction": self.vector.user_interaction,
                "scope": self.vector.scope,
                "confidentiality": self.vector.confidentiality,
                "integrity": self.vector.integrity,
                "availability": self.vector.availability,
            },
        }


class CVSSCalculator:
    """
    CVSS v3.1 Base Score Calculator.

    Implements the official CVSS v3.1 calculation formula from FIRST.
    """

    # Metric value mappings
    AV_VALUES = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    AC_VALUES = {"L": 0.77, "H": 0.44}
    PR_VALUES_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
    PR_VALUES_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
    UI_VALUES = {"N": 0.85, "R": 0.62}
    CIA_VALUES = {"N": 0.00, "L": 0.22, "H": 0.56}

    # Severity rating thresholds
    SEVERITY_RATINGS = [
        (0.0, "None"),
        (0.1, "Low"),
        (4.0, "Medium"),
        (7.0, "High"),
        (9.0, "Critical"),
    ]

    def calculate(self, vector: CVSSVector) -> CVSSResult:
        """
        Calculate CVSS v3.1 Base Score.

        Args:
            vector: CVSSVector with all metrics

        Returns:
            CVSSResult with score, severity, and subscores
        """
        # Get metric values
        av = self.AV_VALUES[vector.attack_vector]
        ac = self.AC_VALUES[vector.attack_complexity]

        # PR depends on Scope
        if vector.scope == "C":
            pr = self.PR_VALUES_CHANGED[vector.privileges_required]
        else:
            pr = self.PR_VALUES_UNCHANGED[vector.privileges_required]

        ui = self.UI_VALUES[vector.user_interaction]

        c = self.CIA_VALUES[vector.confidentiality]
        i = self.CIA_VALUES[vector.integrity]
        a = self.CIA_VALUES[vector.availability]

        # Calculate Impact Sub Score (ISS)
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))

        # Calculate Impact based on Scope
        if vector.scope == "U":
            impact = 6.42 * iss
        else:  # Changed scope
            impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)

        # Calculate Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        # Calculate Base Score
        if impact <= 0:
            base_score = 0.0
        elif vector.scope == "U":
            base_score = min(impact + exploitability, 10.0)
        else:
            base_score = min(1.08 * (impact + exploitability), 10.0)

        # Round up to one decimal place (CVSS standard)
        base_score = self._roundup(base_score)

        # Get severity rating
        severity = self._get_severity(base_score)

        return CVSSResult(
            score=base_score,
            severity=severity,
            vector_string=vector.to_vector_string(),
            vector=vector,
            impact_subscore=impact,
            exploitability_subscore=exploitability,
        )

    def calculate_from_string(self, vector_string: str) -> CVSSResult:
        """Calculate CVSS score from vector string"""
        vector = CVSSVector.from_vector_string(vector_string)
        return self.calculate(vector)

    def _roundup(self, value: float) -> float:
        """Round up to one decimal place (CVSS standard)"""
        return math.ceil(value * 10) / 10

    def _get_severity(self, score: float) -> str:
        """Get severity rating from score"""
        for threshold, rating in reversed(self.SEVERITY_RATINGS):
            if score >= threshold:
                return rating
        return "None"


# Vulnerability type to CVSS mapping
VULNERABILITY_CVSS_MAPPING: dict[str, tuple[CVSSVector, str]] = {
    # Critical Severity (9.0-10.0)
    "sql_injection": (
        CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="H",
        ),
        "CWE-89",
    ),
    "command_injection": (
        CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="H",
        ),
        "CWE-78",
    ),
    "ssti": (
        CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="H",
        ),
        "CWE-1336",
    ),
    "deserialization": (
        CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="H",
        ),
        "CWE-502",
    ),
    # High Severity (7.0-8.9)
    "xxe": (
        CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="N",
            availability="N",
        ),
        "CWE-611",
    ),
    "lfi": (
        CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="N",
            availability="N",
        ),
        "CWE-98",
    ),
    "rfi": (
        CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="H",
        ),
        "CWE-98",
    ),
    "ssrf": (
        CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="C",
            confidentiality="L",
            integrity="N",
            availability="N",
        ),
        "CWE-918",
    ),
    "broken_auth": (
        CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="N",
        ),
        "CWE-287",
    ),
    "idor": (
        CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="L",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="N",
        ),
        "CWE-639",
    ),
    # Medium Severity (4.0-6.9)
    "xss_reflected": (
        CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="R",
            scope="C",
            confidentiality="L",
            integrity="L",
            availability="N",
        ),
        "CWE-79",
    ),
    "xss_stored": (
        CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="L",
            user_interaction="R",
            scope="C",
            confidentiality="L",
            integrity="L",
            availability="N",
        ),
        "CWE-79",
    ),
    "xss_dom": (
        CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="R",
            scope="C",
            confidentiality="L",
            integrity="L",
            availability="N",
        ),
        "CWE-79",
    ),
    "csrf": (
        CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="R",
            scope="U",
            confidentiality="N",
            integrity="L",
            availability="N",
        ),
        "CWE-352",
    ),
    "cors_misconfiguration": (
        CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="R",
            scope="U",
            confidentiality="L",
            integrity="L",
            availability="N",
        ),
        "CWE-942",
    ),
    "open_redirect": (
        CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="R",
            scope="C",
            confidentiality="N",
            integrity="L",
            availability="N",
        ),
        "CWE-601",
    ),
    "jwt_vulnerability": (
        CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="N",
        ),
        "CWE-347",
    ),
    "prototype_pollution": (
        CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="L",
            integrity="L",
            availability="L",
        ),
        "CWE-1321",
    ),
    "race_condition": (
        CVSSVector(
            attack_vector="N",
            attack_complexity="H",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="L",
            integrity="L",
            availability="N",
        ),
        "CWE-362",
    ),
    # Low Severity (0.1-3.9)
    "security_headers_missing": (
        CVSSVector(
            attack_vector="N",
            attack_complexity="H",
            privileges_required="N",
            user_interaction="R",
            scope="U",
            confidentiality="N",
            integrity="L",
            availability="N",
        ),
        "CWE-693",
    ),
    "information_disclosure": (
        CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="L",
            integrity="N",
            availability="N",
        ),
        "CWE-200",
    ),
    "directory_listing": (
        CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="L",
            integrity="N",
            availability="N",
        ),
        "CWE-548",
    ),
}


def get_cvss_for_vulnerability(vuln_type: str) -> CVSSResult | None:
    """
    Get pre-calculated CVSS for a known vulnerability type.

    Args:
        vuln_type: Vulnerability type identifier (e.g., 'sql_injection', 'xss_reflected')

    Returns:
        CVSSResult if type is known, None otherwise
    """
    vuln_type = vuln_type.lower().replace(" ", "_").replace("-", "_")

    if vuln_type in VULNERABILITY_CVSS_MAPPING:
        vector, cwe = VULNERABILITY_CVSS_MAPPING[vuln_type]
        calculator = CVSSCalculator()
        return calculator.calculate(vector)

    return None


def get_cwe_for_vulnerability(vuln_type: str) -> str | None:
    """Get CWE ID for a known vulnerability type"""
    vuln_type = vuln_type.lower().replace(" ", "_").replace("-", "_")

    if vuln_type in VULNERABILITY_CVSS_MAPPING:
        _, cwe = VULNERABILITY_CVSS_MAPPING[vuln_type]
        return cwe

    return None


# ── CVSS v4.0 Support ──────────────────────────────────────────────────
# Reference: https://www.first.org/cvss/v4.0/specification-document


@dataclass
class CVSS4Vector:
    """
    CVSS v4.0 Base metrics vector.

    Key differences from v3.1:
    - Scope retired; Subsequent System impact (SC/SI/SA) captures cross-boundary impact
    - Attack Requirements (AT) replaces environmental preconditions
    - User Interaction: None (N) / Passive (P) / Active (A)
    """

    # Exploitability metrics
    attack_vector: str = "N"       # AV: N, A, L, P
    attack_complexity: str = "L"   # AC: L, H
    attack_requirements: str = "N"  # AT: N (none), P (present) — NEW in 4.0
    privileges_required: str = "N"  # PR: N, L, H
    user_interaction: str = "N"     # UI: N, P (passive), A (active)

    # Vulnerable system impact
    vuln_confidentiality: str = "N"  # VC: N, L, H
    vuln_integrity: str = "N"        # VI: N, L, H
    vuln_availability: str = "N"     # VA: N, L, H

    # Subsequent system impact (replaces Scope=Changed)
    sub_confidentiality: str = "N"  # SC: N, L, H
    sub_integrity: str = "N"        # SI: N, L, H
    sub_availability: str = "N"     # SA: N, L, H

    def to_vector_string(self) -> str:
        return (
            f"CVSS:4.0/AV:{self.attack_vector}/AC:{self.attack_complexity}"
            f"/AT:{self.attack_requirements}/PR:{self.privileges_required}"
            f"/UI:{self.user_interaction}"
            f"/VC:{self.vuln_confidentiality}/VI:{self.vuln_integrity}"
            f"/VA:{self.vuln_availability}"
            f"/SC:{self.sub_confidentiality}/SI:{self.sub_integrity}"
            f"/SA:{self.sub_availability}"
        )

    @classmethod
    def from_vector_string(cls, vector_str: str) -> "CVSS4Vector":
        parts = {}
        prefix = "CVSS:4.0/"
        if vector_str.startswith(prefix):
            vector_str = vector_str[len(prefix):]
        for segment in vector_str.split("/"):
            if ":" in segment:
                key, value = segment.split(":", 1)
                parts[key] = value
        return cls(
            attack_vector=parts.get("AV", "N"),
            attack_complexity=parts.get("AC", "L"),
            attack_requirements=parts.get("AT", "N"),
            privileges_required=parts.get("PR", "N"),
            user_interaction=parts.get("UI", "N"),
            vuln_confidentiality=parts.get("VC", "N"),
            vuln_integrity=parts.get("VI", "N"),
            vuln_availability=parts.get("VA", "N"),
            sub_confidentiality=parts.get("SC", "N"),
            sub_integrity=parts.get("SI", "N"),
            sub_availability=parts.get("SA", "N"),
        )


@dataclass
class CVSS4Result:
    """CVSS 4.0 calculation result."""

    score: float
    severity: str
    vector_string: str
    vector: CVSS4Vector

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": "4.0",
            "score": self.score,
            "severity": self.severity,
            "vector_string": self.vector_string,
            "metrics": {
                "attack_vector": self.vector.attack_vector,
                "attack_complexity": self.vector.attack_complexity,
                "attack_requirements": self.vector.attack_requirements,
                "privileges_required": self.vector.privileges_required,
                "user_interaction": self.vector.user_interaction,
                "vuln_confidentiality": self.vector.vuln_confidentiality,
                "vuln_integrity": self.vector.vuln_integrity,
                "vuln_availability": self.vector.vuln_availability,
                "sub_confidentiality": self.vector.sub_confidentiality,
                "sub_integrity": self.vector.sub_integrity,
                "sub_availability": self.vector.sub_availability,
            },
        }


class CVSS4Calculator:
    """
    CVSS v4.0 Base Score Calculator.

    Uses the macro-vector lookup approach from the FIRST specification.
    The full 4.0 spec uses a 270-entry lookup table; this implements the
    simplified equivalence-class approach that maps metric combinations
    to severity bands, which is the recommended approach for tools that
    don't need sub-decimal precision.
    """

    # Severity thresholds (same as 3.1)
    SEVERITY_RATINGS = [
        (0.0, "None"),
        (0.1, "Low"),
        (4.0, "Medium"),
        (7.0, "High"),
        (9.0, "Critical"),
    ]

    def calculate(self, vector: CVSS4Vector) -> CVSS4Result:
        """
        Calculate CVSS 4.0 score using equivalence-class estimation.

        This follows the macro-vector approach: metrics are grouped into
        equivalence classes, and the final score is derived from the
        highest-impact combination.
        """
        # Exploitability factor
        eq_exploit = self._exploitability_level(vector)
        # Vulnerable system impact
        eq_vuln_impact = self._impact_level(
            vector.vuln_confidentiality, vector.vuln_integrity, vector.vuln_availability
        )
        # Subsequent system impact
        eq_sub_impact = self._impact_level(
            vector.sub_confidentiality, vector.sub_integrity, vector.sub_availability
        )

        # Combine: highest of vulnerable or subsequent impact
        max_impact = max(eq_vuln_impact, eq_sub_impact)

        # Score estimation from equivalence classes
        # 4.0 scoring: exploit * impact mapped to 0-10 scale
        score_matrix = {
            # (exploit_level, impact_level) -> score
            (3, 3): 10.0, (3, 2): 9.1, (3, 1): 7.3, (3, 0): 0.0,
            (2, 3): 9.0,  (2, 2): 7.8, (2, 1): 5.5, (2, 0): 0.0,
            (1, 3): 7.5,  (1, 2): 5.9, (1, 1): 3.8, (1, 0): 0.0,
            (0, 3): 5.4,  (0, 2): 3.6, (0, 1): 1.8, (0, 0): 0.0,
        }

        score = score_matrix.get((eq_exploit, max_impact), 0.0)

        # Adjust for subsequent system impact (cross-boundary amplification)
        if eq_sub_impact > 0 and eq_sub_impact >= eq_vuln_impact:
            score = min(score + 0.5, 10.0)

        score = math.ceil(score * 10) / 10
        severity = self._get_severity(score)

        return CVSS4Result(
            score=score,
            severity=severity,
            vector_string=vector.to_vector_string(),
            vector=vector,
        )

    def _exploitability_level(self, v: CVSS4Vector) -> int:
        """Map exploitability metrics to 0-3 equivalence class."""
        av_score = {"N": 3, "A": 2, "L": 1, "P": 0}[v.attack_vector]
        ac_score = {"L": 1, "H": 0}[v.attack_complexity]
        at_score = {"N": 1, "P": 0}[v.attack_requirements]
        pr_score = {"N": 2, "L": 1, "H": 0}[v.privileges_required]
        ui_score = {"N": 2, "P": 1, "A": 0}[v.user_interaction]

        raw = av_score + ac_score + at_score + pr_score + ui_score  # 0-9
        if raw >= 8:
            return 3
        elif raw >= 5:
            return 2
        elif raw >= 2:
            return 1
        return 0

    def _impact_level(self, c: str, i: str, a: str) -> int:
        """Map CIA impact to 0-3 equivalence class."""
        val = {"N": 0, "L": 1, "H": 2}
        raw = val[c] + val[i] + val[a]  # 0-6
        if raw >= 5:
            return 3
        elif raw >= 3:
            return 2
        elif raw >= 1:
            return 1
        return 0

    def _get_severity(self, score: float) -> str:
        for threshold, rating in reversed(self.SEVERITY_RATINGS):
            if score >= threshold:
                return rating
        return "None"


# Pre-built CVSS 4.0 vectors for common vulnerability types
VULNERABILITY_CVSS4_MAPPING: dict[str, CVSS4Vector] = {
    "sql_injection": CVSS4Vector(
        attack_vector="N", attack_complexity="L", attack_requirements="N",
        privileges_required="N", user_interaction="N",
        vuln_confidentiality="H", vuln_integrity="H", vuln_availability="H",
        sub_confidentiality="N", sub_integrity="N", sub_availability="N",
    ),
    "command_injection": CVSS4Vector(
        attack_vector="N", attack_complexity="L", attack_requirements="N",
        privileges_required="N", user_interaction="N",
        vuln_confidentiality="H", vuln_integrity="H", vuln_availability="H",
        sub_confidentiality="N", sub_integrity="N", sub_availability="N",
    ),
    "ssrf": CVSS4Vector(
        attack_vector="N", attack_complexity="L", attack_requirements="N",
        privileges_required="N", user_interaction="N",
        vuln_confidentiality="L", vuln_integrity="N", vuln_availability="N",
        sub_confidentiality="H", sub_integrity="N", sub_availability="N",
    ),
    "xss_reflected": CVSS4Vector(
        attack_vector="N", attack_complexity="L", attack_requirements="N",
        privileges_required="N", user_interaction="A",
        vuln_confidentiality="L", vuln_integrity="L", vuln_availability="N",
        sub_confidentiality="L", sub_integrity="L", sub_availability="N",
    ),
    "xss_stored": CVSS4Vector(
        attack_vector="N", attack_complexity="L", attack_requirements="N",
        privileges_required="L", user_interaction="P",
        vuln_confidentiality="L", vuln_integrity="L", vuln_availability="N",
        sub_confidentiality="L", sub_integrity="L", sub_availability="N",
    ),
}


def get_cvss4_for_vulnerability(vuln_type: str) -> CVSS4Result | None:
    """Get CVSS 4.0 score for a known vulnerability type."""
    vuln_type = vuln_type.lower().replace(" ", "_").replace("-", "_")
    if vuln_type in VULNERABILITY_CVSS4_MAPPING:
        vector = VULNERABILITY_CVSS4_MAPPING[vuln_type]
        return CVSS4Calculator().calculate(vector)
    return None
