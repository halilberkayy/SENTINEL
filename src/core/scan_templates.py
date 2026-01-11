"""
Scan templates/presets for common vulnerability scanning scenarios.
These presets define module combinations for different scan types.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScanTemplate:
    """Represents a scan template/preset."""
    
    id: str
    name: str
    description: str
    modules: list[str]
    category: str
    estimated_time: str
    intensity: str = "medium"  # low, medium, high
    tags: list[str] = field(default_factory=list)


# Pre-defined scan templates
SCAN_TEMPLATES: list[ScanTemplate] = [
    ScanTemplate(
        id="quick_scan",
        name="Quick Scan",
        description="Fast reconnaissance and common vulnerability detection",
        modules=[
            "recon_scanner",
            "headers_scanner",
            "robots_scanner",
            "security_txt_scanner",
        ],
        category="reconnaissance",
        estimated_time="1-3 minutes",
        intensity="low",
        tags=["quick", "non-intrusive", "safe"],
    ),
    ScanTemplate(
        id="owasp_top10",
        name="OWASP Top 10 2025",
        description="Complete OWASP Top 10 2025 vulnerability assessment",
        modules=[
            "xss_scanner",
            "sqli_scanner",
            "auth_scanner",
            "broken_access_control",
            "security_misconfig",
            "dependency_scanner",
            "logging_scanner",
            "ssrf_scanner",
            "supply_chain_scanner",
            "exception_scanner",
        ],
        category="compliance",
        estimated_time="15-30 minutes",
        intensity="medium",
        tags=["owasp", "compliance", "comprehensive"],
    ),
    ScanTemplate(
        id="api_security",
        name="API Security Assessment",
        description="Focused API and web service security testing",
        modules=[
            "api_scanner",
            "jwt_scanner",
            "graphql_scanner",
            "cors_scanner",
            "rate_limit_scanner",
            "auth_scanner",
            "mobile_api_scanner",
        ],
        category="api",
        estimated_time="10-20 minutes",
        intensity="medium",
        tags=["api", "rest", "graphql", "jwt"],
    ),
    ScanTemplate(
        id="injection_suite",
        name="Injection Testing Suite",
        description="All injection-based vulnerability tests",
        modules=[
            "xss_scanner",
            "sqli_scanner",
            "cmd_injection",
            "ssti_scanner",
            "xxe_scanner",
            "lfi_scanner",
            "ssi_scanner",
        ],
        category="injection",
        estimated_time="20-40 minutes",
        intensity="high",
        tags=["injection", "intrusive", "exploitation"],
    ),
    ScanTemplate(
        id="security_config",
        name="Security Configuration",
        description="Server and application security configuration audit",
        modules=[
            "headers_scanner",
            "misconfig",
            "cors_scanner",
            "csrf_scanner",
            "security_txt_scanner",
            "robots_scanner",
            "directory_scanner",
            "cloud_scanner",
        ],
        category="configuration",
        estimated_time="5-15 minutes",
        intensity="low",
        tags=["configuration", "headers", "best-practices"],
    ),
    ScanTemplate(
        id="full_pentest",
        name="Full Penetration Test",
        description="Comprehensive security assessment with all modules",
        modules=[
            "recon_scanner",
            "subdomain_scanner",
            "xss_scanner",
            "sqli_scanner",
            "lfi_scanner",
            "ssrf_scanner",
            "cmd_injection",
            "misconfig",
            "xxe_scanner",
            "ssti_scanner",
            "deserialization",
            "graphql_scanner",
            "jwt_scanner",
            "api_scanner",
            "auth_scanner",
            "cors_scanner",
            "csrf_scanner",
            "open_redirect",
            "proto_pollution",
            "webshell_scanner",
            "robots_scanner",
            "ssi_scanner",
            "js_secrets_scanner",
            "port_scanner",
            "broken_access_control",
            "cloud_scanner",
            "directory_scanner",
            "headers_scanner",
            "race_condition",
            "security_txt_scanner",
            "webshell_uploader",
            "dependency_scanner",
            "waf_detector",
            "logging_scanner",
            "websocket_scanner",
            "rate_limit_scanner",
            "grpc_scanner",
            "mobile_api_scanner",
            "recursive_scanner",
            "exception_scanner",
            "supply_chain_scanner",
        ],
        category="comprehensive",
        estimated_time="60-120 minutes",
        intensity="high",
        tags=["comprehensive", "all", "pentest"],
    ),
    ScanTemplate(
        id="web_recon",
        name="Web Reconnaissance",
        description="Information gathering and technology fingerprinting",
        modules=[
            "recon_scanner",
            "subdomain_scanner",
            "robots_scanner",
            "security_txt_scanner",
            "directory_scanner",
            "waf_detector",
            "port_scanner",
            "js_secrets_scanner",
        ],
        category="reconnaissance",
        estimated_time="10-20 minutes",
        intensity="low",
        tags=["recon", "osint", "discovery"],
    ),
    ScanTemplate(
        id="external_tools",
        name="External Tool Integration",
        description="Scans using external tools (Nmap, Nikto, Gobuster)",
        modules=[
            "nmap_scanner",
            "gobuster_scanner",
            "nikto_scanner",
            "wordlist_builder",
            "hash_cracker",
        ],
        category="external",
        estimated_time="20-45 minutes",
        intensity="high",
        tags=["external", "nmap", "nikto", "gobuster"],
    ),
]


class TemplateManager:
    """Manages scan templates."""
    
    def __init__(self):
        self.templates = {t.id: t for t in SCAN_TEMPLATES}
    
    def get_all_templates(self) -> list[dict[str, Any]]:
        """Get all templates as dictionaries."""
        return [self._template_to_dict(t) for t in SCAN_TEMPLATES]
    
    def get_template(self, template_id: str) -> ScanTemplate | None:
        """Get a specific template by ID."""
        return self.templates.get(template_id)
    
    def get_template_dict(self, template_id: str) -> dict[str, Any] | None:
        """Get a template as a dictionary."""
        template = self.get_template(template_id)
        if template:
            return self._template_to_dict(template)
        return None
    
    def get_templates_by_category(self, category: str) -> list[dict[str, Any]]:
        """Get templates filtered by category."""
        return [
            self._template_to_dict(t) 
            for t in SCAN_TEMPLATES 
            if t.category == category
        ]
    
    def get_templates_by_tag(self, tag: str) -> list[dict[str, Any]]:
        """Get templates that have a specific tag."""
        return [
            self._template_to_dict(t) 
            for t in SCAN_TEMPLATES 
            if tag in t.tags
        ]
    
    def get_categories(self) -> list[str]:
        """Get all unique categories."""
        return list(set(t.category for t in SCAN_TEMPLATES))
    
    def _template_to_dict(self, template: ScanTemplate) -> dict[str, Any]:
        """Convert template to dictionary."""
        return {
            "id": template.id,
            "name": template.name,
            "description": template.description,
            "modules": template.modules,
            "module_count": len(template.modules),
            "category": template.category,
            "estimated_time": template.estimated_time,
            "intensity": template.intensity,
            "tags": template.tags,
        }


# Global template manager instance
_template_manager: TemplateManager | None = None


def get_template_manager() -> TemplateManager:
    """Get global template manager instance."""
    global _template_manager
    if _template_manager is None:
        _template_manager = TemplateManager()
    return _template_manager
