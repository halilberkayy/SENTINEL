# Exploit Scoring Engine - Halil Berkay Şahin
import math
from dataclasses import dataclass
from enum import Enum


class SeverityLevel(Enum):
    """Vulnerability severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ExploitDifficulty(Enum):
    """Exploitation difficulty levels."""

    TRIVIAL = "TRIVIAL"  # Can be exploited with basic tools
    EASY = "EASY"  # Requires some technical knowledge
    MEDIUM = "MEDIUM"  # Requires specialized tools/knowledge
    HARD = "HARD"  # Requires expert knowledge
    EXTREME = "EXTREME"  # Requires extensive research/development


class BusinessImpact(Enum):
    """Business impact levels."""

    CRITICAL = "CRITICAL"  # Complete system compromise, data breach
    HIGH = "HIGH"  # Significant data exposure, service disruption
    MEDIUM = "MEDIUM"  # Limited data exposure, partial disruption
    LOW = "LOW"  # Minimal impact, information disclosure
    NEGLIGIBLE = "NEGLIGIBLE"  # Almost no business impact


@dataclass
class ExploitabilityFactors:
    """Factors that influence exploitability."""

    authentication_required: bool = False
    user_interaction_required: bool = False
    network_access_required: str = "REMOTE"  # REMOTE, LOCAL, ADJACENT
    complexity: str = "LOW"  # LOW, MEDIUM, HIGH
    privileges_required: str = "NONE"  # NONE, LOW, HIGH
    scope_change: bool = False
    confidentiality_impact: str = "HIGH"  # NONE, LOW, HIGH
    integrity_impact: str = "HIGH"  # NONE, LOW, HIGH
    availability_impact: str = "HIGH"  # NONE, LOW, HIGH


@dataclass
class ExploitScore:
    """Complete exploit score assessment."""

    vulnerability_id: str
    url: str
    vulnerability_type: str

    # CVSS-like scores
    base_score: float
    temporal_score: float
    environmental_score: float
    overall_score: float

    # Risk assessments
    severity: str
    exploit_difficulty: str
    business_impact: str
    remediation_priority: str

    # Detailed breakdown
    exploitability_score: float
    impact_score: float

    # Factors
    factors: ExploitabilityFactors

    # Risk description
    risk_description: str
    remediation_guidance: str

    # Scoring metadata
    scoring_version: str = "1.0"
    confidence_level: str = "MEDIUM"  # LOW, MEDIUM, HIGH


class ExploitScoringEngine:
    """Advanced exploit scoring engine with CVSS-inspired methodology."""

    def __init__(self):
        """Initialize scoring engine."""
        self.version = "1.0"

        # Scoring weights and modifiers
        self.vulnerability_weights = {
            "XSS": {"base": 6.1, "modifiers": {"stored": 1.5, "reflected": 1.0, "dom": 1.2}},
            "SQL_INJECTION": {"base": 9.3, "modifiers": {"blind": 0.8, "time_based": 0.7, "union": 1.0}},
            "DIRECTORY_TRAVERSAL": {"base": 7.5, "modifiers": {"file_read": 1.0, "file_write": 1.3}},
            "INSECURE_HEADERS": {"base": 3.9, "modifiers": {"missing_hsts": 0.8, "missing_csp": 1.0}},
            "SENSITIVE_FILE": {"base": 5.3, "modifiers": {"config": 1.2, "backup": 1.0, "source": 1.1}},
            "FORM_DISCOVERY": {"base": 2.1, "modifiers": {"login": 1.0, "upload": 1.3, "admin": 1.4}},
            "API_ENDPOINT": {"base": 4.3, "modifiers": {"unauthenticated": 1.2, "documented": 0.8}},
            "WEAK_AUTHENTICATION": {"base": 8.1, "modifiers": {"default_creds": 1.3, "weak_password": 1.0}},
            "INFORMATION_DISCLOSURE": {"base": 4.0, "modifiers": {"error_messages": 0.8, "debug_info": 1.0}},
            "OTHER": {"base": 5.0, "modifiers": {"unknown": 1.0}},
        }

        # Environmental factors (organization-specific)
        self.environmental_factors = {
            "data_sensitivity": {"high": 1.3, "medium": 1.0, "low": 0.7},
            "system_criticality": {"critical": 1.4, "high": 1.2, "medium": 1.0, "low": 0.8},
            "public_exposure": {"internet": 1.3, "intranet": 1.0, "isolated": 0.6},
            "user_base": {"large": 1.2, "medium": 1.0, "small": 0.8},
        }

        # Remediation priorities
        self.priority_thresholds = {"IMMEDIATE": 9.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 0.0}

    def calculate_exploit_score(
        self,
        vulnerability_type: str,
        url: str,
        factors: ExploitabilityFactors = None,
        vulnerability_details: dict = None,
        environmental_context: dict = None,
    ) -> ExploitScore:
        """
        Calculate comprehensive exploit score.

        Args:
            vulnerability_type: Type of vulnerability
            url: Target URL
            factors: Exploitability factors
            vulnerability_details: Additional vulnerability information
            environmental_context: Environmental factors

        Returns:
            Complete exploit score assessment
        """
        if factors is None:
            factors = ExploitabilityFactors()

        if vulnerability_details is None:
            vulnerability_details = {}

        if environmental_context is None:
            environmental_context = {}

        # Calculate base score components
        exploitability_score = self._calculate_exploitability_score(factors)
        impact_score = self._calculate_impact_score(factors)

        # Calculate base score (CVSS-inspired)
        base_score = self._calculate_base_score(exploitability_score, impact_score, factors)

        # Apply vulnerability-specific modifiers
        base_score = self._apply_vulnerability_modifiers(base_score, vulnerability_type, vulnerability_details)

        # Calculate temporal score (considers exploit maturity, remediation level, etc.)
        temporal_score = self._calculate_temporal_score(base_score, vulnerability_details)

        # Calculate environmental score
        environmental_score = self._calculate_environmental_score(temporal_score, environmental_context)

        # Overall score is the environmental score
        overall_score = environmental_score

        # Determine severity, difficulty, and impact
        severity = self._determine_severity(overall_score)
        exploit_difficulty = self._determine_exploit_difficulty(factors, vulnerability_type)
        business_impact = self._determine_business_impact(factors, overall_score)
        remediation_priority = self._determine_remediation_priority(overall_score)

        # Generate descriptions
        risk_description = self._generate_risk_description(
            vulnerability_type, severity, exploit_difficulty, business_impact
        )
        remediation_guidance = self._generate_remediation_guidance(vulnerability_type, remediation_priority)

        return ExploitScore(
            vulnerability_id=vulnerability_details.get("id", "unknown"),
            url=url,
            vulnerability_type=vulnerability_type,
            base_score=round(base_score, 1),
            temporal_score=round(temporal_score, 1),
            environmental_score=round(environmental_score, 1),
            overall_score=round(overall_score, 1),
            severity=severity,
            exploit_difficulty=exploit_difficulty,
            business_impact=business_impact,
            remediation_priority=remediation_priority,
            exploitability_score=round(exploitability_score, 1),
            impact_score=round(impact_score, 1),
            factors=factors,
            risk_description=risk_description,
            remediation_guidance=remediation_guidance,
            confidence_level=self._determine_confidence_level(vulnerability_details),
        )

    def _calculate_exploitability_score(self, factors: ExploitabilityFactors) -> float:
        """Calculate exploitability score based on attack vector, complexity, etc."""
        # Base exploitability score
        score = 8.22

        # Attack vector impact
        if factors.network_access_required == "LOCAL":
            score *= 0.55
        elif factors.network_access_required == "ADJACENT":
            score *= 0.62
        # REMOTE uses full score (no modification)

        # Attack complexity
        if factors.complexity == "HIGH":
            score *= 0.44
        elif factors.complexity == "MEDIUM":
            score *= 0.72
        # LOW uses full score

        # Privileges required
        if factors.privileges_required == "HIGH":
            score *= 0.27 if factors.scope_change else 0.50
        elif factors.privileges_required == "LOW":
            score *= 0.62 if factors.scope_change else 0.68
        # NONE uses full score

        # User interaction
        if factors.user_interaction_required:
            score *= 0.85

        # Authentication requirement
        if factors.authentication_required:
            score *= 0.70

        return max(0.0, min(10.0, score))

    def _calculate_impact_score(self, factors: ExploitabilityFactors) -> float:
        """Calculate impact score based on CIA (Confidentiality, Integrity, Availability)."""
        # Impact values
        impact_values = {"NONE": 0.0, "LOW": 0.22, "HIGH": 0.56}

        conf_impact = impact_values.get(factors.confidentiality_impact, 0.56)
        integ_impact = impact_values.get(factors.integrity_impact, 0.56)
        avail_impact = impact_values.get(factors.availability_impact, 0.56)

        # Calculate base impact
        impact = 1 - ((1 - conf_impact) * (1 - integ_impact) * (1 - avail_impact))

        # Apply scope modifier
        if factors.scope_change:
            impact_score = 7.52 * (impact - 0.029) - 3.25 * math.pow(impact - 0.02, 15)
        else:
            impact_score = 6.42 * impact

        return max(0.0, min(10.0, impact_score))

    def _calculate_base_score(self, exploitability: float, impact: float, factors: ExploitabilityFactors) -> float:
        """Calculate base CVSS score."""
        if impact <= 0:
            return 0.0

        if factors.scope_change:
            score = min(1.08 * (impact + exploitability), 10.0)
        else:
            score = min(impact + exploitability, 10.0)

        # Round up to nearest 0.1
        return math.ceil(score * 10) / 10

    def _apply_vulnerability_modifiers(self, base_score: float, vuln_type: str, details: dict) -> float:
        """Apply vulnerability-specific modifiers."""
        if vuln_type not in self.vulnerability_weights:
            return base_score

        weight_info = self.vulnerability_weights[vuln_type]

        # Adjust based on vulnerability type base weight
        type_weight = weight_info["base"] / 10.0  # Normalize to 0-1
        adjusted_score = base_score * (0.5 + 0.5 * type_weight)

        # Apply specific modifiers
        modifiers = weight_info.get("modifiers", {})
        for modifier_key, modifier_value in modifiers.items():
            if modifier_key in details:
                adjusted_score *= modifier_value

        return min(10.0, adjusted_score)

    def _calculate_temporal_score(self, base_score: float, details: dict) -> float:
        """Calculate temporal score considering exploit maturity and remediation."""
        temporal_score = base_score

        # Exploit code maturity
        exploit_maturity = details.get("exploit_maturity", "PROOF_OF_CONCEPT")
        maturity_modifiers = {"NOT_DEFINED": 1.0, "PROOF_OF_CONCEPT": 0.94, "FUNCTIONAL": 0.97, "HIGH": 1.0}
        temporal_score *= maturity_modifiers.get(exploit_maturity, 0.94)

        # Remediation level
        remediation_level = details.get("remediation_level", "OFFICIAL_FIX")
        remediation_modifiers = {
            "NOT_DEFINED": 1.0,
            "OFFICIAL_FIX": 0.95,
            "TEMPORARY_FIX": 0.96,
            "WORKAROUND": 0.97,
            "UNAVAILABLE": 1.0,
        }
        temporal_score *= remediation_modifiers.get(remediation_level, 0.97)

        # Report confidence
        confidence = details.get("report_confidence", "CONFIRMED")
        confidence_modifiers = {"NOT_DEFINED": 1.0, "CONFIRMED": 1.0, "REASONABLE": 0.96, "UNKNOWN": 0.92}
        temporal_score *= confidence_modifiers.get(confidence, 0.96)

        return temporal_score

    def _calculate_environmental_score(self, temporal_score: float, context: dict) -> float:
        """Calculate environmental score based on organizational context."""
        environmental_score = temporal_score

        # Apply environmental factors
        for factor_name, factor_value in context.items():
            if factor_name in self.environmental_factors:
                factor_modifiers = self.environmental_factors[factor_name]
                modifier = factor_modifiers.get(factor_value, 1.0)
                environmental_score *= modifier

        return min(10.0, environmental_score)

    def _determine_severity(self, score: float) -> str:
        """Determine severity level based on score."""
        if score >= 9.0:
            return SeverityLevel.CRITICAL.value
        elif score >= 7.0:
            return SeverityLevel.HIGH.value
        elif score >= 4.0:
            return SeverityLevel.MEDIUM.value
        elif score >= 0.1:
            return SeverityLevel.LOW.value
        else:
            return SeverityLevel.INFO.value

    def _determine_exploit_difficulty(self, factors: ExploitabilityFactors, vuln_type: str) -> str:
        """Determine exploitation difficulty."""
        difficulty_score = 0

        # Base difficulty by vulnerability type
        type_difficulties = {
            "XSS": 1,
            "SQL_INJECTION": 2,
            "DIRECTORY_TRAVERSAL": 1,
            "INSECURE_HEADERS": 0,
            "SENSITIVE_FILE": 0,
            "FORM_DISCOVERY": 0,
            "API_ENDPOINT": 1,
            "WEAK_AUTHENTICATION": 1,
            "INFORMATION_DISCLOSURE": 0,
            "OTHER": 1,
        }
        difficulty_score += type_difficulties.get(vuln_type, 1)

        # Factor-based adjustments
        if factors.authentication_required:
            difficulty_score += 1
        if factors.user_interaction_required:
            difficulty_score += 1
        if factors.privileges_required == "HIGH":
            difficulty_score += 2
        elif factors.privileges_required == "LOW":
            difficulty_score += 1
        if factors.complexity == "HIGH":
            difficulty_score += 2
        elif factors.complexity == "MEDIUM":
            difficulty_score += 1
        if factors.network_access_required == "LOCAL":
            difficulty_score += 2
        elif factors.network_access_required == "ADJACENT":
            difficulty_score += 1

        # Map to difficulty levels
        if difficulty_score <= 1:
            return ExploitDifficulty.TRIVIAL.value
        elif difficulty_score <= 3:
            return ExploitDifficulty.EASY.value
        elif difficulty_score <= 5:
            return ExploitDifficulty.MEDIUM.value
        elif difficulty_score <= 7:
            return ExploitDifficulty.HARD.value
        else:
            return ExploitDifficulty.EXTREME.value

    def _determine_business_impact(self, factors: ExploitabilityFactors, score: float) -> str:
        """Determine business impact level."""
        # Base impact from score
        if score >= 9.0:
            base_impact = 4
        elif score >= 7.0:
            base_impact = 3
        elif score >= 4.0:
            base_impact = 2
        elif score >= 0.1:
            base_impact = 1
        else:
            base_impact = 0

        # Adjust based on CIA impact
        if (
            factors.confidentiality_impact == "HIGH"
            or factors.integrity_impact == "HIGH"
            or factors.availability_impact == "HIGH"
        ):
            base_impact += 1

        # Map to business impact levels
        if base_impact >= 5:
            return BusinessImpact.CRITICAL.value
        elif base_impact >= 4:
            return BusinessImpact.HIGH.value
        elif base_impact >= 2:
            return BusinessImpact.MEDIUM.value
        elif base_impact >= 1:
            return BusinessImpact.LOW.value
        else:
            return BusinessImpact.NEGLIGIBLE.value

    def _determine_remediation_priority(self, score: float) -> str:
        """Determine remediation priority."""
        for priority, threshold in self.priority_thresholds.items():
            if score >= threshold:
                return priority
        return "LOW"

    def _determine_confidence_level(self, details: dict) -> str:
        """Determine confidence level based on detection details."""
        confidence_factors = 0

        # Multiple detection methods increase confidence
        if details.get("multiple_payloads_confirmed"):
            confidence_factors += 1
        if details.get("response_analysis_confirmed"):
            confidence_factors += 1
        if details.get("manual_verification"):
            confidence_factors += 2
        if details.get("low_false_positive_risk"):
            confidence_factors += 1

        if confidence_factors >= 4:
            return "HIGH"
        elif confidence_factors >= 2:
            return "MEDIUM"
        else:
            return "LOW"

    def _generate_risk_description(self, vuln_type: str, severity: str, difficulty: str, impact: str) -> str:
        """Generate human-readable risk description."""
        descriptions = {
            "XSS": "Cross-Site Scripting vulnerability allows attackers to inject malicious scripts",
            "SQL_INJECTION": "SQL Injection vulnerability allows database manipulation and data extraction",
            "DIRECTORY_TRAVERSAL": "Directory traversal allows unauthorized file system access",
            "INSECURE_HEADERS": "Missing security headers expose the application to various attacks",
            "SENSITIVE_FILE": "Sensitive files are accessible without proper authorization",
            "FORM_DISCOVERY": "Forms discovered that may accept malicious input",
            "API_ENDPOINT": "API endpoints discovered that may lack proper security controls",
            "WEAK_AUTHENTICATION": "Weak authentication mechanisms allow unauthorized access",
            "INFORMATION_DISCLOSURE": "Information disclosure reveals sensitive system details",
            "OTHER": "Security vulnerability identified that requires investigation",
        }

        base_desc = descriptions.get(vuln_type, descriptions["OTHER"])

        return f"{base_desc}. Severity: {severity}, Exploitation difficulty: {difficulty}, Business impact: {impact}."

    def _generate_remediation_guidance(self, vuln_type: str, priority: str) -> str:
        """Generate remediation guidance."""
        guidance = {
            "XSS": "Implement proper input validation, output encoding, and Content Security Policy (CSP)",
            "SQL_INJECTION": "Use parameterized queries, input validation, and least privilege database access",
            "DIRECTORY_TRAVERSAL": "Implement proper file path validation and access controls",
            "INSECURE_HEADERS": "Configure security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options",
            "SENSITIVE_FILE": "Remove or properly secure sensitive files with authentication and authorization",
            "FORM_DISCOVERY": "Implement proper input validation, CSRF protection, and rate limiting",
            "API_ENDPOINT": "Implement proper authentication, authorization, and input validation for API endpoints",
            "WEAK_AUTHENTICATION": "Implement strong authentication mechanisms, enforce strong passwords",
            "INFORMATION_DISCLOSURE": "Remove debug information and error details from production responses",
            "OTHER": "Investigate the vulnerability and implement appropriate security controls",
        }

        base_guidance = guidance.get(vuln_type, guidance["OTHER"])

        priority_suffix = {
            "IMMEDIATE": " This should be addressed immediately.",
            "HIGH": " This should be prioritized for immediate remediation.",
            "MEDIUM": " This should be scheduled for remediation in the next sprint.",
            "LOW": " This can be addressed in regular maintenance cycles.",
        }

        return base_guidance + priority_suffix.get(priority, "")

    def calculate_portfolio_risk(self, vulnerabilities: list[ExploitScore]) -> dict:
        """Calculate overall portfolio risk from multiple vulnerabilities."""
        if not vulnerabilities:
            return {"total_risk": 0.0, "risk_level": "NONE"}

        # Calculate weighted risk score
        total_weighted_score = 0.0
        weight_sum = 0.0

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        for vuln in vulnerabilities:
            # Weight by severity and confidence
            severity_weight = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.6, "LOW": 0.4, "INFO": 0.2}
            confidence_weight = {"HIGH": 1.0, "MEDIUM": 0.8, "LOW": 0.6}

            weight = severity_weight.get(vuln.severity, 0.6) * confidence_weight.get(vuln.confidence_level, 0.8)

            total_weighted_score += vuln.overall_score * weight
            weight_sum += weight

            severity_counts[vuln.severity] += 1

        portfolio_score = total_weighted_score / weight_sum if weight_sum > 0 else 0.0

        # Determine overall risk level
        if portfolio_score >= 8.0 or severity_counts["CRITICAL"] > 0:
            risk_level = "CRITICAL"
        elif portfolio_score >= 6.0 or severity_counts["HIGH"] > 2:
            risk_level = "HIGH"
        elif portfolio_score >= 4.0 or severity_counts["MEDIUM"] > 5:
            risk_level = "MEDIUM"
        elif portfolio_score >= 2.0:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"

        return {
            "total_risk": round(portfolio_score, 1),
            "risk_level": risk_level,
            "vulnerability_count": len(vulnerabilities),
            "severity_breakdown": severity_counts,
            "immediate_action_required": severity_counts["CRITICAL"] > 0 or severity_counts["HIGH"] > 3,
            "recommendation": self._get_portfolio_recommendation(risk_level, severity_counts),
        }

    def _get_portfolio_recommendation(self, risk_level: str, severity_counts: dict) -> str:
        """Get portfolio-level recommendations."""
        if risk_level == "CRITICAL":
            return (
                "Immediate action required. Address critical vulnerabilities before proceeding with normal operations."
            )
        elif risk_level == "HIGH":
            return "High risk detected. Prioritize remediation of high and critical severity vulnerabilities."
        elif risk_level == "MEDIUM":
            return "Moderate risk level. Plan remediation activities for the next development cycle."
        elif risk_level == "LOW":
            return "Low risk level. Address vulnerabilities during regular maintenance windows."
        else:
            return "Minimal risk detected. Continue with regular security practices."


# Convenience functions
def quick_score_vulnerability(vuln_type: str, url: str, severity: str = None) -> ExploitScore:
    """Quick scoring for basic vulnerability assessment."""
    engine = ExploitScoringEngine()

    # Create basic factors based on vulnerability type
    factors = ExploitabilityFactors()

    # Adjust factors based on vulnerability type
    if vuln_type == "SQL_INJECTION":
        factors.confidentiality_impact = "HIGH"
        factors.integrity_impact = "HIGH"
        factors.availability_impact = "HIGH"
    elif vuln_type == "XSS":
        factors.confidentiality_impact = "HIGH"
        factors.integrity_impact = "LOW"
        factors.user_interaction_required = True
    elif vuln_type == "DIRECTORY_TRAVERSAL":
        factors.confidentiality_impact = "HIGH"
        factors.integrity_impact = "MEDIUM"

    return engine.calculate_exploit_score(vuln_type, url, factors)
