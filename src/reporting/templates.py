"""
Report templates for vulnerability scanner.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass
class ReportTemplate:
    """Base report template class."""

    name: str
    description: str
    template_type: str
    sections: list[str]

    def generate_template(self, scan_data: dict[str, Any]) -> str:
        """Generate template content."""
        raise NotImplementedError


class ExecutiveSummaryTemplate(ReportTemplate):
    """Executive summary report template."""

    def __init__(self):
        super().__init__(
            name="Executive Summary",
            description="High-level security assessment summary for executives",
            template_type="executive",
            sections=["overview", "risk_assessment", "key_findings", "recommendations"],
        )

    def generate_template(self, scan_data: dict[str, Any]) -> str:
        """Generate executive summary template."""
        results = scan_data.get("results", [])

        # Calculate statistics
        total_vulnerabilities = 0
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

        for result in results:
            vulnerabilities = result.get("vulnerabilities", [])
            total_vulnerabilities += len(vulnerabilities)

            for vuln in vulnerabilities:
                severity = vuln.get("severity", "Unknown")
                if severity in severity_counts:
                    severity_counts[severity] += 1

        risk_score = self._calculate_risk_score(severity_counts)
        risk_level = self._get_risk_level(risk_score)

        template = f"""
# Executive Security Assessment Summary

## Overview
This report presents the findings of a comprehensive security assessment conducted on {scan_data.get('url', 'the target application')} using Simple Web Vulnerability Scanner v4.0.0.

**Assessment Date:** {scan_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}
**Target Application:** {scan_data.get('url', 'Unknown')}
**Scan Type:** {scan_data.get('scan_type', 'Standard Security Assessment')}

## Risk Assessment

### Overall Risk Score: {risk_score}/100
**Risk Level:** {risk_level.upper()}

### Vulnerability Distribution
- Critical Vulnerabilities: {severity_counts['Critical']}
- High Severity Vulnerabilities: {severity_counts['High']}
- Medium Severity Vulnerabilities: {severity_counts['Medium']}
- Low Severity Vulnerabilities: {severity_counts['Low']}
- Informational Findings: {severity_counts['Info']}

## Key Findings

### Critical Issues
{self._format_critical_findings(results)}

### High Priority Issues
{self._format_high_findings(results)}

### Security Posture
{self._assess_security_posture(risk_score, severity_counts)}

## Business Impact

### Immediate Actions Required
{self._get_immediate_actions(severity_counts)}

### Compliance Considerations
{self._get_compliance_impact(severity_counts)}

## Recommendations

### Short-term (1-2 weeks)
{self._get_short_term_recommendations(severity_counts)}

### Medium-term (1-3 months)
{self._get_medium_term_recommendations(severity_counts)}

### Long-term (3-6 months)
{self._get_long_term_recommendations(severity_counts)}

## Next Steps

1. **Immediate Response:** Address all Critical and High severity vulnerabilities
2. **Security Review:** Conduct comprehensive code review for identified issues
3. **Monitoring:** Implement continuous security monitoring
4. **Training:** Provide security awareness training to development team
5. **Follow-up Assessment:** Schedule follow-up security assessment

---

*This executive summary provides a high-level overview of the security assessment. For detailed technical findings, please refer to the complete technical report.*
        """

        return template

    def _calculate_risk_score(self, severity_counts: dict[str, int]) -> float:
        """Calculate overall risk score."""
        weights = {"Critical": 10, "High": 7, "Medium": 4, "Low": 2, "Info": 1}
        total_score = sum(severity_counts[sev] * weights[sev] for sev in weights)
        return min(100, total_score)

    def _get_risk_level(self, score: float) -> str:
        """Get risk level based on score."""
        if score >= 70:
            return "Critical"
        elif score >= 50:
            return "High"
        elif score >= 30:
            return "Medium"
        elif score >= 10:
            return "Low"
        else:
            return "Info"

    def _format_critical_findings(self, results: list[dict[str, Any]]) -> str:
        """Format critical findings."""
        critical_findings = []

        for result in results:
            vulnerabilities = result.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                if vuln.get("severity") == "Critical":
                    critical_findings.append(
                        f"- **{vuln.get('title', 'Unknown')}** in {result.get('module', 'Unknown Module')}"
                    )

        if critical_findings:
            return "\n".join(critical_findings)
        else:
            return "- No critical vulnerabilities identified"

    def _format_high_findings(self, results: list[dict[str, Any]]) -> str:
        """Format high priority findings."""
        high_findings = []

        for result in results:
            vulnerabilities = result.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                if vuln.get("severity") == "High":
                    high_findings.append(
                        f"- **{vuln.get('title', 'Unknown')}** in {result.get('module', 'Unknown Module')}"
                    )

        if high_findings:
            return "\n".join(high_findings[:5])  # Limit to top 5
        else:
            return "- No high severity vulnerabilities identified"

    def _assess_security_posture(self, risk_score: float, severity_counts: dict[str, int]) -> str:
        """Assess overall security posture."""
        if risk_score >= 70:
            return "**CRITICAL:** The application has severe security vulnerabilities that require immediate attention. The current security posture is inadequate for production use."
        elif risk_score >= 50:
            return "**HIGH RISK:** The application has significant security vulnerabilities that need to be addressed promptly. Security controls require strengthening."
        elif risk_score >= 30:
            return "**MODERATE RISK:** The application has some security vulnerabilities that should be addressed. Security posture needs improvement."
        elif risk_score >= 10:
            return "**LOW RISK:** The application has minor security issues. Overall security posture is acceptable but can be improved."
        else:
            return "**GOOD:** The application shows good security practices with minimal vulnerabilities identified."

    def _get_immediate_actions(self, severity_counts: dict[str, int]) -> str:
        """Get immediate actions required."""
        actions = []

        if severity_counts["Critical"] > 0:
            actions.append("- **URGENT:** Address all Critical vulnerabilities immediately")
        if severity_counts["High"] > 0:
            actions.append("- **HIGH PRIORITY:** Fix High severity vulnerabilities within 1 week")
        if severity_counts["Medium"] > 0:
            actions.append("- **MEDIUM PRIORITY:** Address Medium severity vulnerabilities within 2 weeks")

        if not actions:
            actions.append("- No immediate actions required")

        return "\n".join(actions)

    def _get_compliance_impact(self, severity_counts: dict[str, int]) -> str:
        """Get compliance impact assessment."""
        if severity_counts["Critical"] > 0 or severity_counts["High"] > 0:
            return "**COMPLIANCE RISK:** Critical and High severity vulnerabilities may impact compliance with security standards (ISO 27001, SOC 2, PCI DSS, etc.)"
        elif severity_counts["Medium"] > 0:
            return "**MODERATE COMPLIANCE RISK:** Medium severity vulnerabilities should be addressed to maintain compliance"
        else:
            return "**COMPLIANCE STATUS:** Current findings do not pose significant compliance risks"

    def _get_short_term_recommendations(self, severity_counts: dict[str, int]) -> str:
        """Get short-term recommendations."""
        recommendations = [
            "- Implement input validation and output encoding",
            "- Update security headers configuration",
            "- Review and fix identified vulnerabilities",
            "- Implement proper error handling",
        ]

        if severity_counts["Critical"] > 0 or severity_counts["High"] > 0:
            recommendations.insert(0, "- **URGENT:** Prioritize fixing Critical and High severity vulnerabilities")

        return "\n".join(recommendations)

    def _get_medium_term_recommendations(self, severity_counts: dict[str, int]) -> str:
        """Get medium-term recommendations."""
        return """
- Implement comprehensive security testing in CI/CD pipeline
- Conduct security code review training for development team
- Establish security monitoring and alerting
- Implement automated vulnerability scanning
- Review and update security policies and procedures
        """.strip()

    def _get_long_term_recommendations(self, severity_counts: dict[str, int]) -> str:
        """Get long-term recommendations."""
        return """
- Establish DevSecOps practices
- Implement threat modeling in development process
- Conduct regular security assessments
- Establish incident response procedures
- Implement security metrics and KPIs
        """.strip()


class TechnicalReportTemplate(ReportTemplate):
    """Technical detailed report template."""

    def __init__(self):
        super().__init__(
            name="Technical Report",
            description="Detailed technical report with vulnerability specifics",
            template_type="technical",
            sections=["methodology", "findings", "evidence", "remediation"],
        )

    def generate_template(self, scan_data: dict[str, Any]) -> str:
        """Generate technical report template."""
        results = scan_data.get("results", [])

        template = f"""
# Technical Security Assessment Report

## Assessment Information
- **Target URL:** {scan_data.get('url', 'Unknown')}
- **Assessment Date:** {scan_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}
- **Scanner Version:** 4.0.0
- **Scan Type:** {scan_data.get('scan_type', 'Standard Security Assessment')}

## Methodology

### Scanning Approach
This assessment utilized automated vulnerability scanning techniques to identify common web application security vulnerabilities including:

- Cross-Site Scripting (XSS)
- SQL Injection (SQLi)
- Directory Traversal
- Security Header Analysis
- Information Disclosure
- Configuration Issues

### Tools and Techniques
- **Scanner:** Simple Web Vulnerability Scanner v4.0.0
- **Payload Database:** Comprehensive vulnerability payloads
- **Detection Methods:** Pattern matching, response analysis, behavior testing
- **Coverage:** URL parameters, form inputs, headers, files

## Detailed Findings

{self._format_detailed_findings(results)}

## Evidence and Proof of Concept

{self._format_evidence_section(results)}

## Remediation Guidelines

{self._format_remediation_section(results)}

## Risk Assessment Matrix

{self._format_risk_matrix(results)}

## Conclusion

{self._format_conclusion(results)}

---

*This technical report provides detailed information about identified vulnerabilities and remediation steps. For executive summary, please refer to the executive report.*
        """

        return template

    def _format_detailed_findings(self, results: list[dict[str, Any]]) -> str:
        """Format detailed findings section."""
        sections = []

        for result in results:
            module_name = result.get("module", "Unknown")
            vulnerabilities = result.get("vulnerabilities", [])

            if vulnerabilities:
                sections.append(f"### {module_name}")
                sections.append(f"**Status:** {result.get('status', 'Unknown')}")
                sections.append(f"**Details:** {result.get('details', '')}")
                sections.append("")

                for vuln in vulnerabilities:
                    sections.append(f"#### {vuln.get('title', 'Unknown Vulnerability')}")
                    sections.append(f"**Severity:** {vuln.get('severity', 'Unknown')}")
                    sections.append(f"**Type:** {vuln.get('type', 'Unknown')}")
                    sections.append(f"**CWE ID:** {vuln.get('cwe_id', 'N/A')}")
                    sections.append(f"**CVSS Score:** {vuln.get('cvss_score', 'N/A')}")
                    sections.append("")
                    sections.append(f"**Description:** {vuln.get('description', 'No description available')}")
                    sections.append("")

                    if vuln.get("evidence"):
                        sections.append("**Evidence:**")
                        sections.append("```json")
                        sections.append(f"{vuln.get('evidence')}")
                        sections.append("```")
                        sections.append("")

                    if vuln.get("remediation"):
                        sections.append("**Remediation:**")
                        sections.append(f"{vuln.get('remediation')}")
                        sections.append("")

                    if vuln.get("references"):
                        sections.append("**References:**")
                        for ref in vuln.get("references", []):
                            sections.append(f"- {ref}")
                        sections.append("")
            else:
                sections.append(f"### {module_name}")
                sections.append("✅ No vulnerabilities found")
                sections.append("")

        return "\n".join(sections)

    def _format_evidence_section(self, results: list[dict[str, Any]]) -> str:
        """Format evidence section."""
        evidence_items = []

        for result in results:
            vulnerabilities = result.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                if vuln.get("evidence"):
                    evidence_items.append(f"**{vuln.get('title', 'Unknown')}**")
                    evidence_items.append(f"Module: {result.get('module', 'Unknown')}")
                    evidence_items.append(f"Evidence: {vuln.get('evidence')}")
                    evidence_items.append("")

        if evidence_items:
            return "\n".join(evidence_items)
        else:
            return "No detailed evidence available for the identified vulnerabilities."

    def _format_remediation_section(self, results: list[dict[str, Any]]) -> str:
        """Format remediation section."""
        remediation_items = []

        for result in results:
            vulnerabilities = result.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                if vuln.get("remediation"):
                    remediation_items.append(f"**{vuln.get('title', 'Unknown')}**")
                    remediation_items.append(f"Remediation: {vuln.get('remediation')}")
                    remediation_items.append("")

        if remediation_items:
            return "\n".join(remediation_items)
        else:
            return "Specific remediation steps should be developed based on the application's architecture and technology stack."

    def _format_risk_matrix(self, results: list[dict[str, Any]]) -> str:
        """Format risk assessment matrix."""
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

        for result in results:
            vulnerabilities = result.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "Unknown")
                if severity in severity_counts:
                    severity_counts[severity] += 1

        matrix = """
| Severity | Count | Risk Level | Action Required |
|----------|-------|------------|-----------------|
"""

        for severity, count in severity_counts.items():
            if count > 0:
                if severity == "Critical":
                    risk_level = "Extreme"
                    action = "Immediate"
                elif severity == "High":
                    risk_level = "High"
                    action = "Within 1 week"
                elif severity == "Medium":
                    risk_level = "Medium"
                    action = "Within 2 weeks"
                elif severity == "Low":
                    risk_level = "Low"
                    action = "Within 1 month"
                else:
                    risk_level = "Info"
                    action = "Monitor"

                matrix += f"| {severity} | {count} | {risk_level} | {action} |\n"

        return matrix

    def _format_conclusion(self, results: list[dict[str, Any]]) -> str:
        """Format conclusion section."""
        total_vulnerabilities = sum(len(result.get("vulnerabilities", [])) for result in results)

        if total_vulnerabilities == 0:
            return "The security assessment did not identify any significant vulnerabilities. The application demonstrates good security practices."
        else:
            return f"The security assessment identified {total_vulnerabilities} vulnerabilities that require attention. Immediate action is recommended to address Critical and High severity issues."


class RemediationTemplate(ReportTemplate):
    """Remediation guide template."""

    def __init__(self):
        super().__init__(
            name="Remediation Guide",
            description="Step-by-step remediation guide for identified vulnerabilities",
            template_type="remediation",
            sections=["prioritization", "step_by_step", "verification", "prevention"],
        )

    def generate_template(self, scan_data: dict[str, Any]) -> str:
        """Generate remediation guide template."""
        results = scan_data.get("results", [])

        template = f"""
# Vulnerability Remediation Guide

## Overview
This guide provides step-by-step instructions for remediating the vulnerabilities identified during the security assessment of {scan_data.get('url', 'the target application')}.

**Assessment Date:** {scan_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}
**Total Vulnerabilities:** {sum(len(result.get('vulnerabilities', [])) for result in results)}

## Remediation Priority Matrix

{self._format_priority_matrix(results)}

## Step-by-Step Remediation

{self._format_step_by_step_remediation(results)}

## Verification Steps

{self._format_verification_steps(results)}

## Prevention Measures

{self._format_prevention_measures(results)}

## Timeline and Milestones

{self._format_timeline(results)}

---

*This remediation guide should be used in conjunction with the technical report for complete vulnerability details.*
        """

        return template

    def _format_priority_matrix(self, results: list[dict[str, Any]]) -> str:
        """Format remediation priority matrix."""
        vulnerabilities_by_severity = {"Critical": [], "High": [], "Medium": [], "Low": [], "Info": []}

        for result in results:
            module_name = result.get("module", "Unknown")
            for vuln in result.get("vulnerabilities", []):
                severity = vuln.get("severity", "Unknown")
                if severity in vulnerabilities_by_severity:
                    vulnerabilities_by_severity[severity].append(
                        {
                            "title": vuln.get("title", "Unknown"),
                            "module": module_name,
                            "type": vuln.get("type", "Unknown"),
                        }
                    )

        matrix = """
| Priority | Severity | Count | Timeline | Vulnerabilities |
|----------|----------|-------|----------|-----------------|
"""

        priority_order = ["Critical", "High", "Medium", "Low", "Info"]
        priority_names = ["P0 - Immediate", "P1 - High", "P2 - Medium", "P3 - Low", "P4 - Info"]
        timelines = ["Immediate", "1 week", "2 weeks", "1 month", "Monitor"]

        for i, severity in enumerate(priority_order):
            vulns = vulnerabilities_by_severity[severity]
            if vulns:
                vuln_list = ", ".join([v["title"] for v in vulns[:3]])  # Show first 3
                if len(vulns) > 3:
                    vuln_list += f" (+{len(vulns) - 3} more)"

                matrix += f"| {priority_names[i]} | {severity} | {len(vulns)} | {timelines[i]} | {vuln_list} |\n"

        return matrix

    def _format_step_by_step_remediation(self, results: list[dict[str, Any]]) -> str:
        """Format step-by-step remediation instructions."""
        steps = []

        # Group by vulnerability type
        vuln_types = {}
        for result in results:
            for vuln in result.get("vulnerabilities", []):
                vuln_type = vuln.get("type", "Unknown")
                if vuln_type not in vuln_types:
                    vuln_types[vuln_type] = []
                vuln_types[vuln_type].append(vuln)

        for vuln_type, _ in vuln_types.items():
            steps.append(f"### {vuln_type} Vulnerabilities")
            steps.append("")

            if vuln_type == "XSS":
                steps.extend(self._get_xss_remediation_steps())
            elif vuln_type == "SQL Injection":
                steps.extend(self._get_sqli_remediation_steps())
            elif vuln_type == "Directory Traversal":
                steps.extend(self._get_directory_remediation_steps())
            elif vuln_type == "Security Headers":
                steps.extend(self._get_headers_remediation_steps())
            else:
                steps.extend(self._get_general_remediation_steps())

            steps.append("")

        return "\n".join(steps)

    def _get_xss_remediation_steps(self) -> list[str]:
        """Get XSS remediation steps."""
        return [
            "1. **Input Validation**",
            "   - Implement strict input validation on all user inputs",
            "   - Use allowlist approach for acceptable characters",
            "   - Validate input length and format",
            "",
            "2. **Output Encoding**",
            "   - Encode all dynamic content before output",
            "   - Use context-appropriate encoding (HTML, JavaScript, CSS, URL)",
            "   - Implement Content Security Policy (CSP)",
            "",
            "3. **Framework Security**",
            "   - Use modern web frameworks with built-in XSS protection",
            "   - Enable automatic output encoding",
            "   - Keep frameworks updated to latest versions",
            "",
            "4. **Content Security Policy**",
            "   - Implement strict CSP headers",
            "   - Disable inline scripts and styles",
            "   - Use nonce or hash-based script execution",
        ]

    def _get_sqli_remediation_steps(self) -> list[str]:
        """Get SQL injection remediation steps."""
        return [
            "1. **Prepared Statements**",
            "   - Use parameterized queries for all database operations",
            "   - Avoid string concatenation for SQL queries",
            "   - Implement proper parameter binding",
            "",
            "2. **Input Validation**",
            "   - Validate and sanitize all user inputs",
            "   - Use type checking for numeric parameters",
            "   - Implement input length restrictions",
            "",
            "3. **Database Security**",
            "   - Use least privilege database accounts",
            "   - Implement proper error handling",
            "   - Disable detailed error messages in production",
            "",
            "4. **ORM Usage**",
            "   - Use Object-Relational Mapping (ORM) frameworks",
            "   - Leverage built-in SQL injection protection",
            "   - Avoid raw SQL queries when possible",
        ]

    def _get_directory_remediation_steps(self) -> list[str]:
        """Get directory traversal remediation steps."""
        return [
            "1. **Path Validation**",
            "   - Implement strict path validation",
            "   - Use allowlist for allowed directories",
            "   - Normalize and validate file paths",
            "",
            "2. **Access Controls**",
            "   - Implement proper file access controls",
            "   - Restrict access to sensitive directories",
            "   - Use chroot or similar isolation techniques",
            "",
            "3. **File Operations**",
            "   - Use safe file handling libraries",
            "   - Implement proper file permissions",
            "   - Avoid direct file path manipulation",
        ]

    def _get_headers_remediation_steps(self) -> list[str]:
        """Get security headers remediation steps."""
        return [
            "1. **Content Security Policy**",
            "   - Implement strict CSP headers",
            "   - Configure appropriate directives",
            "   - Test CSP implementation thoroughly",
            "",
            "2. **HTTPS Enforcement**",
            "   - Enable HSTS (HTTP Strict Transport Security)",
            "   - Redirect all HTTP traffic to HTTPS",
            "   - Use secure cookie flags",
            "",
            "3. **Other Security Headers**",
            "   - Implement X-Frame-Options",
            "   - Enable X-Content-Type-Options",
            "   - Configure Referrer-Policy",
            "   - Implement X-XSS-Protection",
        ]

    def _get_general_remediation_steps(self) -> list[str]:
        """Get general remediation steps."""
        return [
            "1. **Code Review**",
            "   - Conduct thorough security code review",
            "   - Identify and fix root causes",
            "   - Implement secure coding practices",
            "",
            "2. **Testing**",
            "   - Perform security testing after fixes",
            "   - Implement automated security testing",
            "   - Conduct penetration testing",
            "",
            "3. **Documentation**",
            "   - Document all security fixes",
            "   - Update security procedures",
            "   - Train development team",
        ]

    def _format_verification_steps(self, results: list[dict[str, Any]]) -> str:
        """Format verification steps."""
        return """
## Verification Steps

### 1. Automated Testing
- Re-run vulnerability scanner after fixes
- Verify all identified vulnerabilities are resolved
- Check for new vulnerabilities introduced by fixes

### 2. Manual Testing
- Test fixed functionality manually
- Verify security controls are working
- Check for regression issues

### 3. Code Review
- Review all security-related code changes
- Ensure secure coding practices are followed
- Verify input validation and output encoding

### 4. Security Testing
- Perform targeted security testing
- Verify WAF rules if applicable
- Test security headers implementation

### 5. Documentation
- Update security documentation
- Document lessons learned
- Update incident response procedures
        """

    def _format_prevention_measures(self, results: list[dict[str, Any]]) -> str:
        """Format prevention measures."""
        return """
## Prevention Measures

### 1. Secure Development Lifecycle
- Implement secure coding standards
- Conduct regular security training
- Include security in code reviews

### 2. Automated Security Testing
- Integrate security testing in CI/CD
- Implement automated vulnerability scanning
- Use SAST and DAST tools

### 3. Security Monitoring
- Implement security monitoring and alerting
- Monitor for suspicious activities
- Regular security assessments

### 4. Patch Management
- Keep all software and dependencies updated
- Monitor security advisories
- Implement timely patch management

### 5. Security Awareness
- Regular security training for team
- Security best practices documentation
- Incident response procedures
        """

    def _format_timeline(self, results: list[dict[str, Any]]) -> str:
        """Format remediation timeline."""
        return """
## Remediation Timeline

### Week 1 (Critical Issues)
- Address all Critical severity vulnerabilities
- Implement immediate security controls
- Conduct initial verification

### Week 2 (High Priority)
- Fix High severity vulnerabilities
- Implement additional security measures
- Conduct security testing

### Week 3-4 (Medium Priority)
- Address Medium severity issues
- Implement preventive measures
- Update security documentation

### Month 2-3 (Long-term)
- Address Low severity issues
- Implement security monitoring
- Conduct security training

### Ongoing
- Regular security assessments
- Monitor for new vulnerabilities
- Update security procedures
        """


class ReportTemplateManager:
    """Manager for report templates."""

    def __init__(self):
        self.templates = {
            "executive": ExecutiveSummaryTemplate(),
            "technical": TechnicalReportTemplate(),
            "remediation": RemediationTemplate(),
        }

    def get_template(self, template_type: str) -> ReportTemplate | None:
        """Get template by type."""
        return self.templates.get(template_type)

    def list_templates(self) -> list[str]:
        """List available template types."""
        return list(self.templates.keys())

    def generate_report(self, template_type: str, scan_data: dict[str, Any]) -> str:
        """Generate report using specified template."""
        template = self.get_template(template_type)
        if template:
            return template.generate_template(scan_data)
        else:
            raise ValueError(f"Unknown template type: {template_type}")

    def generate_all_reports(self, scan_data: dict[str, Any]) -> dict[str, str]:
        """Generate all report types."""
        reports = {}
        for template_type in self.templates:
            reports[template_type] = self.generate_report(template_type, scan_data)
        return reports
