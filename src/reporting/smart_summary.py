"""
Smart Executive Summary Generator.
Translates technical vulnerability chains into business risk language.
"""

from typing import Any


class SmartSummaryGenerator:
    """Generates business-centric executive summaries from technical findings."""

    RISK_TRANSLATIONS = {
        "Cloud Infrastructure Takeover": {
            "business_impact": "Complete loss of cloud environment control. Attackers can delete servers, steal all data, and incur massive financial costs via resource mining.",
            "urgency": "IMMEDIATE - STOP THE LINE",
            "estimated_cost": "$100,000 - $1,000,000+ (Breach costs + Fines)",
        },
        "Critical Credential Leak": {
            "business_impact": "Unauthorized access to core systems. Potential for full data breach and long-term persistence in the network.",
            "urgency": "Critical - Revoke keys within 1 hour",
            "estimated_cost": "$50,000 - $500,000",
        },
        "Account Takeover": {
            "business_impact": "Compromise of user accounts, leading to identity theft, fraud, and loss of customer trust.",
            "urgency": "High - Patch immediately",
            "estimated_cost": "$10,000 - $100,000 (per incident scale)",
        },
        "Internal Network Reconnaissance": {
            "business_impact": "Breach of perimeter defenses. Attackers are 'inside the building' and can pivot to sensitive internal databases.",
            "urgency": "High",
            "estimated_cost": "Variable - High risk of escalation",
        },
    }

    def generate_executive_narrative(self, chains: list[dict[str, Any]]) -> dict[str, str]:
        """
        Creates a narrative summary for the report.
        Returns a dict with 'title', 'narrative', 'recommendation'.
        """
        if not chains:
            return {
                "title": "Security Posture Summary",
                "narrative": "No critical attack chains were identified. The security posture appears resilient against complex multi-step attacks, though individual vulnerabilities may still exist.",
                "recommendation": "Continue regular maintainence and patch individual low/medium findings.",
            }

        # We have chains, this is bad.
        # critical_chains = [c for c in chains if c.get('severity') == 'critical']

        narrative = []
        narrative.append(f"⚠️ CRITICAL SECURITY ALERT: {len(chains)} Verifyable Attack Paths Detected.")
        narrative.append(
            "Testing has identified critical weaknesses that can be chained together to compromise the system completely."
        )
        narrative.append("")

        impacts = []

        for chain in chains:
            title = chain.get("title", "")
            # Find matching risk translation
            risk_info = None
            for key, info in self.RISK_TRANSLATIONS.items():
                if key in title or key in chain.get("description", ""):
                    risk_info = info
                    break

            if risk_info:
                impacts.append(
                    f"- {title}: {risk_info['business_impact']} (Est. Impact: {risk_info['estimated_cost']})"
                )
                # max_cost = risk_info['estimated_cost'] # Simplified logic
            else:
                impacts.append(f"- {title}: Technical compromise with high business impact.")

        narrative.append("Business Impact Analysis:")
        narrative.extend(impacts)

        return {
            "title": "🚨 EXECUTIVE SECURITY ALERT - IMMEDIATE ACTION REQUIRED",
            "narrative": "\n".join(narrative),
            "recommendation": "A specialized security team must be assembled immediately to break these attack chains. Refer to the technical section for 'Chain Breaking' remediation steps.",
        }
