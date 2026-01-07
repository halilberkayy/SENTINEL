"""
Report formatters for different output formats.
Provides formatting capabilities for JSON, TXT, and HTML reports.
"""

import html
import json
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from .smart_summary import SmartSummaryGenerator


class BaseFormatter(ABC):
    """Base class for report formatters."""

    @abstractmethod
    def format_report(self, scan_data: dict[str, Any]) -> str:
        """Format scan data into specific format."""
        pass


class JSONFormatter(BaseFormatter):
    """JSON report formatter."""

    def format_report(self, scan_data: dict[str, Any]) -> str:
        """Format scan data as JSON."""

        # Create comprehensive JSON report
        report = {
            "scan_info": {
                "target_url": scan_data.get("url", "Unknown"),
                "scan_type": scan_data.get("scan_type", "Vulnerability Assessment"),
                "timestamp": scan_data.get("timestamp", datetime.now().isoformat()),
                "scanner_version": "2.0.0",
                "modules_scanned": scan_data.get("modules", []),
            },
            "summary": self._generate_summary(scan_data),
            "vulnerabilities": self._format_vulnerabilities(scan_data.get("results", [])),
            "module_results": self._format_module_results(scan_data.get("results", [])),
            "statistics": self._generate_statistics(scan_data.get("results", [])),
            "recommendations": self._generate_recommendations(scan_data.get("results", [])),
        }

        return json.dumps(report, indent=2, ensure_ascii=False, default=str)

    def _generate_summary(self, scan_data: dict[str, Any]) -> dict[str, Any]:
        """Generate scan summary."""
        results = scan_data.get("results", [])

        total_vulns = 0
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for result in results:
            vulns = result.get("vulnerabilities", [])
            total_vulns += len(vulns)

            for vuln in vulns:
                severity = vuln.get("severity", "unknown").lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1

        return {
            "total_modules": len(results),
            "total_vulnerabilities": total_vulns,
            "severity_breakdown": severity_counts,
            "scan_status": "completed",
            "risk_level": self._calculate_overall_risk(severity_counts),
        }

    def _format_vulnerabilities(self, results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Format vulnerabilities for JSON output."""
        all_vulnerabilities = []

        for result in results:
            module_name = result.get("module", "Unknown")
            vulnerabilities = result.get("vulnerabilities", [])

            for vuln in vulnerabilities:
                formatted_vuln = {
                    "id": f"{module_name}_{len(all_vulnerabilities) + 1}",
                    "module": module_name,
                    "title": vuln.get("title", "Unknown Vulnerability"),
                    "description": vuln.get("description", ""),
                    "severity": vuln.get("severity", "unknown"),
                    "type": vuln.get("type", "unknown"),
                    "cwe_id": vuln.get("cwe_id"),
                    "cvss_score": vuln.get("cvss_score"),
                    "evidence": vuln.get("evidence", {}),
                    "remediation": vuln.get("remediation", ""),
                    "references": vuln.get("references", []),
                }
                all_vulnerabilities.append(formatted_vuln)

        return all_vulnerabilities

    def _format_module_results(self, results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Format module results for JSON output."""
        formatted_results = []

        for result in results:
            formatted_result = {
                "module": result.get("module", "Unknown"),
                "status": result.get("status", "Unknown"),
                "details": result.get("details", ""),
                "risk_level": result.get("risk_level", "unknown"),
                "scan_time": result.get("scan_time", 0),
                "vulnerabilities_count": len(result.get("vulnerabilities", [])),
                "evidence": result.get("evidence", {}),
            }
            formatted_results.append(formatted_result)

        return formatted_results

    def _generate_statistics(self, results: list[dict[str, Any]]) -> dict[str, Any]:
        """Generate scan statistics."""
        total_scan_time = sum(result.get("scan_time", 0) for result in results)
        successful_modules = len([r for r in results if r.get("status") != "Error"])
        error_modules = len([r for r in results if r.get("status") == "Error"])

        return {
            "total_scan_time": round(total_scan_time, 2),
            "successful_modules": successful_modules,
            "error_modules": error_modules,
            "average_scan_time": round(total_scan_time / len(results) if results else 0, 2),
        }

    def _generate_recommendations(self, results: list[dict[str, Any]]) -> list[str]:
        """Generate security recommendations."""
        recommendations = set()

        for result in results:
            vulnerabilities = result.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                remediation = vuln.get("remediation")
                if remediation and remediation not in recommendations:
                    recommendations.add(remediation)

        return list(recommendations)

    def _calculate_overall_risk(self, severity_counts: dict[str, int]) -> str:
        """Calculate overall risk level."""
        if severity_counts["critical"] > 0:
            return "critical"
        elif severity_counts["high"] > 0:
            return "high"
        elif severity_counts["medium"] > 0:
            return "medium"
        elif severity_counts["low"] > 0:
            return "low"
        else:
            return "clean"


class TXTFormatter(BaseFormatter):
    """Plain text report formatter."""

    def format_report(self, scan_data: dict[str, Any]) -> str:
        """Format scan data as plain text."""

        lines = []

        # Header
        lines.append("=" * 80)
        lines.append("WEB VULNERABILITY SCANNER REPORT")
        lines.append("=" * 80)
        lines.append("")

        # Scan information
        lines.append("SCAN INFORMATION:")
        lines.append(f"  Target URL: {scan_data.get('url', 'Unknown')}")
        lines.append(f"  Scan Type: {scan_data.get('scan_type', 'Vulnerability Assessment')}")
        lines.append(f"  Timestamp: {scan_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}")
        lines.append("  Scanner Version: 2.0.0")
        lines.append(f"  Modules: {', '.join(scan_data.get('modules', []))}")
        lines.append("")

        # Smart Executive Summary
        results = scan_data.get("results", [])
        chain_results = []
        for res in results:
            if res.get("module") == "ChainAnalyzer":
                # ChainAnalyzer results are wrapped in a dict that mimics a vulnerability
                # But wait, ChainAnalyzer creates vulnerabilities in a "ChainAnalyzer" module result?
                # Actually, in chain_analyzer.py, it returns separate vulnerability dicts.
                # In scanner_engine.py, it appends them to self.results.
                # Usually ChainAnalyzer results are appended as a ScanResult object with module_name="ChainAnalyzer" and a list of vulnerabilities.
                # I need to find the "ChainAnalyzer" module result object/dict.

                # Let's look at how scanner_engine.py adds it:
                # self.results.append({'module': 'ChainAnalyzer', 'vulnerabilities': chains_as_vulns, ...})

                chain_results.extend(res.get("vulnerabilities", []))

        # Because chain results are formatted as vulnerabilities, we need to extract the original chain info or just use title/desc
        # The SmartSummaryGenerator expects "chains" which are dicts with title, description, etc.
        # The ChainAnalyzer formats them as standard vulnerability dicts. This works for SmartSummaryGenerator.

        # Only use chains detected by ChainAnalyzer for this summary
        if chain_results:
            summary_gen = SmartSummaryGenerator()
            narrative = summary_gen.generate_executive_narrative(chain_results)

            lines.append("=" * 80)
            lines.append(narrative["title"])
            lines.append("=" * 80)
            lines.append(narrative["narrative"])
            lines.append("")
            lines.append("STRATEGIC RECOMMENDATION:")
            lines.append(narrative["recommendation"])
            lines.append("")
            lines.append("-" * 80)
            lines.append("")

        # Summary
        results = scan_data.get("results", [])
        summary = self._generate_txt_summary(results)
        lines.append("SCAN SUMMARY:")
        lines.extend([f"  {line}" for line in summary])
        lines.append("")

        # Vulnerability breakdown
        severity_counts = self._count_vulnerabilities_by_severity(results)
        lines.append("VULNERABILITY BREAKDOWN:")
        for severity, count in severity_counts.items():
            if count > 0:
                lines.append(f"  {severity.upper()}: {count}")
        lines.append("")

        # Detailed results
        lines.append("DETAILED RESULTS:")
        lines.append("-" * 60)

        for result in results:
            lines.extend(self._format_module_result_txt(result))
            lines.append("")

        # Recommendations
        recommendations = self._generate_txt_recommendations(results)
        if recommendations:
            lines.append("SECURITY RECOMMENDATIONS:")
            lines.append("-" * 40)
            for i, rec in enumerate(recommendations, 1):
                lines.append(f"{i}. {rec}")
            lines.append("")

        # Footer
        lines.append("=" * 80)
        lines.append("Report generated by Web Vulnerability Scanner v2.0.0")
        lines.append("For educational and authorized testing purposes only")
        lines.append("=" * 80)

        return "\n".join(lines)

    def _generate_txt_summary(self, results: list[dict[str, Any]]) -> list[str]:
        """Generate text summary."""
        total_modules = len(results)
        successful_modules = len([r for r in results if r.get("status") != "Error"])
        total_vulns = sum(len(r.get("vulnerabilities", [])) for r in results)
        total_time = sum(r.get("scan_time", 0) for r in results)

        return [
            f"Total modules scanned: {total_modules}",
            f"Successful scans: {successful_modules}",
            f"Total vulnerabilities found: {total_vulns}",
            f"Total scan time: {total_time:.2f} seconds",
        ]

    def _count_vulnerabilities_by_severity(self, results: list[dict[str, Any]]) -> dict[str, int]:
        """Count vulnerabilities by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for result in results:
            vulnerabilities = result.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "unknown").lower()
                if severity in counts:
                    counts[severity] += 1

        return counts

    def _format_module_result_txt(self, result: dict[str, Any]) -> list[str]:
        """Format a single module result for text output."""
        lines = []

        module_name = result.get("module", "Unknown")
        status = result.get("status", "Unknown")
        details = result.get("details", "")
        scan_time = result.get("scan_time", 0)
        vulnerabilities = result.get("vulnerabilities", [])

        lines.append(f"MODULE: {module_name}")
        lines.append(f"Status: {status}")
        lines.append(f"Scan Time: {scan_time:.2f} seconds")
        lines.append(f"Details: {details}")

        if vulnerabilities:
            lines.append(f"Vulnerabilities Found: {len(vulnerabilities)}")
            lines.append("")

            for i, vuln in enumerate(vulnerabilities, 1):
                lines.append(f"  {i}. {vuln.get('title', 'Unknown')}")
                lines.append(f"     Severity: {vuln.get('severity', 'unknown').upper()}")
                lines.append(f"     Type: {vuln.get('type', 'unknown')}")

                description = vuln.get("description", "")
                if description:
                    # Wrap long descriptions
                    wrapped_desc = self._wrap_text(description, 70)
                    lines.append(f"     Description: {wrapped_desc[0]}")
                    for line in wrapped_desc[1:]:
                        lines.append(f"                  {line}")

                remediation = vuln.get("remediation", "")
                if remediation:
                    wrapped_rem = self._wrap_text(remediation, 70)
                    lines.append(f"     Remediation: {wrapped_rem[0]}")
                    for line in wrapped_rem[1:]:
                        lines.append(f"                  {line}")

                lines.append("")

        return lines

    def _wrap_text(self, text: str, width: int) -> list[str]:
        """Wrap text to specified width."""
        words = text.split()
        lines = []
        current_line = []
        current_length = 0

        for word in words:
            if current_length + len(word) + len(current_line) <= width:
                current_line.append(word)
                current_length += len(word)
            else:
                if current_line:
                    lines.append(" ".join(current_line))
                current_line = [word]
                current_length = len(word)

        if current_line:
            lines.append(" ".join(current_line))

        return lines if lines else [text]

    def _generate_txt_recommendations(self, results: list[dict[str, Any]]) -> list[str]:
        """Generate recommendations for text output."""
        recommendations = set()

        for result in results:
            vulnerabilities = result.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                remediation = vuln.get("remediation")
                if remediation:
                    recommendations.add(remediation)

        return list(recommendations)


class HTMLFormatter(BaseFormatter):
    """HTML report formatter."""

    def format_report(self, scan_data: dict[str, Any]) -> str:
        """Format scan data as HTML."""

        # Generate HTML report
        html_content = self._generate_html_template(scan_data)
        return html_content

    def _generate_html_template(self, scan_data: dict[str, Any]) -> str:
        """Generate HTML template with scan data."""

        results = scan_data.get("results", [])
        severity_counts = self._count_vulnerabilities_by_severity(results)

        html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report</title>
    <style>
        {self._get_css_styles()}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>🛡️ Web Vulnerability Scanner Report</h1>
            <div class="scan-info">
                <p><strong>Target:</strong> {html.escape(scan_data.get('url', 'Unknown'))}</p>
                <p><strong>Scan Type:</strong> {html.escape(scan_data.get('scan_type', 'Vulnerability Assessment'))}</p>
                <p><strong>Timestamp:</strong> {html.escape(scan_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')))}</p>
                <p><strong>Modules:</strong> {html.escape(', '.join(scan_data.get('modules', [])))}</p>
            </div>
        </header>

        <section class="summary">
            {self._generate_executive_html(results)}
            <h2>📊 Executive Summary</h2>
            {self._generate_summary_html(results, severity_counts)}
        </section>

        <section class="vulnerabilities">
            <h2>🔍 Vulnerability Details</h2>
            {self._generate_vulnerabilities_html(results)}
        </section>

        <section class="recommendations">
            <h2>🛠️ Recommendations</h2>
            {self._generate_recommendations_html(results)}
        </section>

        <footer class="footer">
            <p>Generated by Web Vulnerability Scanner v2.0.0</p>
            <p>For educational and authorized testing purposes only</p>
        </footer>
    </div>
</body>
</html>
        """

        return html_template

    def _get_css_styles(self) -> str:
        """Get CSS styles for HTML report."""
        return """
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
        }
        .scan-info {
            margin-top: 20px;
            text-align: left;
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 5px;
        }
        .scan-info p {
            margin: 5px 0;
        }
        section {
            padding: 30px;
            border-bottom: 1px solid #eee;
        }
        section h2 {
            color: #444;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        .severity-chart {
            display: flex;
            gap: 20px;
            margin: 20px 0;
            flex-wrap: wrap;
        }
        .severity-item {
            flex: 1;
            min-width: 150px;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            color: white;
            font-weight: bold;
        }
        .severity-critical { background-color: #dc3545; }
        .severity-high { background-color: #fd7e14; }
        .severity-medium { background-color: #ffc107; color: #333; }
        .severity-low { background-color: #28a745; }
        .severity-info { background-color: #17a2b8; }
        .vulnerability {
            margin: 20px 0;
            padding: 20px;
            border-left: 4px solid #667eea;
            background-color: #f8f9fa;
            border-radius: 0 8px 8px 0;
        }
        .vulnerability.critical { border-left-color: #dc3545; }
        .vulnerability.high { border-left-color: #fd7e14; }
        .vulnerability.medium { border-left-color: #ffc107; }
        .vulnerability.low { border-left-color: #28a745; }
        .vulnerability.info { border-left-color: #17a2b8; }
        .vulnerability h3 {
            margin: 0 0 10px 0;
            color: #333;
        }
        .vulnerability-meta {
            display: flex;
            gap: 20px;
            margin: 10px 0;
            font-size: 0.9em;
            color: #666;
        }
        .module-results {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .module-result {
            padding: 20px;
            border-radius: 8px;
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
        }
        .module-result h3 {
            margin: 0 0 15px 0;
            color: #667eea;
        }
        .status-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            color: white;
        }
        .status-vulnerable { background-color: #dc3545; }
        .status-clean { background-color: #28a745; }
        .status-error { background-color: #6c757d; }
        .recommendations ul {
            list-style-type: none;
            padding: 0;
        }
        .recommendations li {
            margin: 10px 0;
            padding: 15px;
            background-color: #e7f3ff;
            border-left: 4px solid #007bff;
            border-radius: 0 4px 4px 0;
        }
        .footer {
            background-color: #f8f9fa;
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }
        """

    def _generate_summary_html(self, results: list[dict[str, Any]], severity_counts: dict[str, int]) -> str:
        """Generate summary HTML section."""
        total_vulns = sum(severity_counts.values())
        total_modules = len(results)
        successful_modules = len([r for r in results if r.get("status") != "Error"])

        severity_html = ""
        for severity, count in severity_counts.items():
            if count > 0:
                severity_html += f"""
                <div class="severity-item severity-{severity}">
                    <div style="font-size: 2em;">{count}</div>
                    <div>{severity.upper()}</div>
                </div>
                """

        return f"""
        <div class="severity-chart">
            {severity_html}
        </div>
        <p><strong>Total Vulnerabilities:</strong> {total_vulns}</p>
        <p><strong>Modules Scanned:</strong> {successful_modules}/{total_modules}</p>
        """

    def _generate_vulnerabilities_html(self, results: list[dict[str, Any]]) -> str:
        """Generate vulnerabilities HTML section."""
        html_parts = []

        for result in results:
            module_name = result.get("module", "Unknown")
            vulnerabilities = result.get("vulnerabilities", [])

            if vulnerabilities:
                for vuln in vulnerabilities:
                    severity = vuln.get("severity", "info").lower()
                    html_parts.append(
                        f"""
                    <div class="vulnerability {severity}">
                        <h3>{html.escape(vuln.get('title', 'Unknown Vulnerability'))}</h3>
                        <div class="vulnerability-meta">
                            <span><strong>Module:</strong> {html.escape(module_name)}</span>
                            <span><strong>Severity:</strong> {html.escape(vuln.get('severity', 'unknown').upper())}</span>
                            <span><strong>Type:</strong> {html.escape(vuln.get('type', 'unknown'))}</span>
                        </div>
                        <p><strong>Description:</strong> {html.escape(vuln.get('description', ''))}</p>
                        <p><strong>Remediation:</strong> {html.escape(vuln.get('remediation', ''))}</p>
                    </div>
                    """
                    )

        if not html_parts:
            return "<p>No vulnerabilities found. ✅</p>"

        return "".join(html_parts)

    def _generate_recommendations_html(self, results: list[dict[str, Any]]) -> str:
        """Generate recommendations HTML section."""
        recommendations = set()

        for result in results:
            vulnerabilities = result.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                remediation = vuln.get("remediation")
                if remediation:
                    recommendations.add(remediation)

        if not recommendations:
            return "<p>No specific recommendations at this time.</p>"

        html_parts = ["<ul>"]
        for rec in recommendations:
            html_parts.append(f"<li>{html.escape(rec)}</li>")
        html_parts.append("</ul>")

        return "".join(html_parts)

    def _count_vulnerabilities_by_severity(self, results: list[dict[str, Any]]) -> dict[str, int]:
        """Count vulnerabilities by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for result in results:
            vulnerabilities = result.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "unknown").lower()
                if severity in counts:
                    counts[severity] += 1

        return counts

    def _generate_executive_html(self, results: list[dict[str, Any]]) -> str:
        """Generate executive summary HTML if chains exist."""
        chain_results = []
        for res in results:
            if res.get("module") == "ChainAnalyzer":
                chain_results.extend(res.get("vulnerabilities", []))

        if not chain_results:
            return ""

        summary_gen = SmartSummaryGenerator()
        narrative = summary_gen.generate_executive_narrative(chain_results)

        # Replace newlines with <p> tags for narrative
        narrative_html = narrative["narrative"].replace("\n", "<br>")

        return f"""
        <div class="executive-alert" style="background-color: #fff3cd; border-left: 6px solid #ffc107; padding: 20px; margin-bottom: 30px;">
            <h2 style="color: #856404; border-bottom: none; margin-top: 0;">{html.escape(narrative['title'])}</h2>
            <p style="font-size: 1.1em; line-height: 1.6;">{narrative_html}</p>
            <div style="background-color: rgba(255,255,255,0.5); padding: 15px; border-radius: 5px; margin-top: 15px;">
                <strong>💡 STRATEGIC RECOMMENDATION:</strong><br>
                {html.escape(narrative['recommendation'])}
            </div>
        </div>
        """


class MarkdownFormatter(BaseFormatter):
    """Markdown report formatter."""

    def format_report(self, scan_data: dict[str, Any]) -> str:
        """Format scan data as Markdown."""
        lines = []

        # Header
        lines.append("# 🛡️ Web Vulnerability Scan Report")
        lines.append("")
        lines.append(f"**Target:** `{scan_data.get('url', 'Unknown')}`  ")
        lines.append(f"**Timestamp:** `{scan_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}`  ")
        lines.append("**Scanner Version:** `2.0.0`")
        lines.append("")
        lines.append("---")
        lines.append("")

        # Executive Summary (Smart)
        results = scan_data.get("results", [])
        chain_results = []
        for res in results:
            if res.get("module") == "ChainAnalyzer":
                chain_results.extend(res.get("vulnerabilities", []))

        if chain_results:
            summary_gen = SmartSummaryGenerator()
            narrative = summary_gen.generate_executive_narrative(chain_results)

            lines.append(f"## 🚨 Executive Alert: {narrative['title']}")
            lines.append(f"> {narrative['narrative']}")
            lines.append("")
            lines.append("**💡 Strategic Recommendation:**")
            lines.append(f"{narrative['recommendation']}")
            lines.append("")
            lines.append("---")
            lines.append("")

        # Summary Statistics
        severity_counts = self._count_vulnerabilities_by_severity(results)

        lines.append("## 📊 Scan Summary")
        lines.append("| Severity | Count |")
        lines.append("| :--- | :---: |")
        lines.append(f"| 🔴 CRITICAL | {severity_counts['critical']} |")
        lines.append(f"| 🟠 HIGH | {severity_counts['high']} |")
        lines.append(f"| 🟡 MEDIUM | {severity_counts['medium']} |")
        lines.append(f"| 🟢 LOW | {severity_counts['low']} |")
        lines.append(f"| 🔵 INFO | {severity_counts['info']} |")
        lines.append("")

        # Detailed Findings
        lines.append("## 🔍 Detailed Findings")

        if not results:
            lines.append("No modules were executed.")

        for result in results:
            vulnerabilities = result.get("vulnerabilities", [])
            if not vulnerabilities:
                continue

            module_name = result.get("module", "Unknown")
            lines.append(f"### Module: {module_name}")

            for i, vuln in enumerate(vulnerabilities, 1):
                severity = vuln.get("severity", "info").upper()
                cwe = vuln.get("cwe_id", "CHECK-000")
                title = vuln.get("title", "Unknown Issue")

                icon = "🔵"
                if severity == "CRITICAL":
                    icon = "🔴"
                elif severity == "HIGH":
                    icon = "🟠"
                elif severity == "MEDIUM":
                    icon = "🟡"
                elif severity == "LOW":
                    icon = "🟢"

                lines.append(f"#### {icon} {i}. {title} ({severity})")
                lines.append(f"**CWE:** `{cwe}` | **Type:** `{vuln.get('type','generic')}`")
                lines.append("")
                lines.append("**Description:**")
                lines.append(f"{vuln.get('description', 'No description provided.')}")
                lines.append("")

                if vuln.get("evidence"):
                    lines.append("**Evidence:**")
                    lines.append("```json")
                    lines.append(json.dumps(vuln.get("evidence"), indent=2, default=str))
                    lines.append("```")
                    lines.append("")

                if vuln.get("remediation"):
                    lines.append("**🛠️ Remediation:**")
                    lines.append(f"{vuln.get('remediation')}")
                    lines.append("")

                lines.append("---")

        lines.append("")
        lines.append("*Generated by Sentinel Web Vulnerability Scanner*")

        return "\n".join(lines)

    def _count_vulnerabilities_by_severity(self, results: list[dict[str, Any]]) -> dict[str, int]:
        """Count vulnerabilities by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for result in results:
            vulnerabilities = result.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "unknown").lower()
                if severity in counts:
                    counts[severity] += 1
        return counts
