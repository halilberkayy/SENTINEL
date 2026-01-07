"""
Professional-grade scanner engine with dynamic module discovery and optimized async execution.
"""

import asyncio
import importlib
import logging
import pkgutil
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from ..modules.api_scanner import ApiScanner
from ..modules.auth_scanner import AuthScanner
from ..modules.base_scanner import BaseScanner

# Additional modules
from ..modules.broken_access_control_scanner import BrokenAccessControlScanner
from ..modules.cloud_scanner import CloudScanner
from ..modules.command_injection_scanner import CommandInjectionScanner
from ..modules.cors_scanner import CORSScanner
from ..modules.csrf_scanner import CsrfScanner

# New modules
from ..modules.dependency_scanner import DependencyScanner
from ..modules.deserialization_scanner import DeserializationScanner
from ..modules.directory_scanner import DirectoryScanner

# OWASP 2025 modules
from ..modules.exception_scanner import ExceptionScanner
from ..modules.gobuster_scanner import GobusterScanner
from ..modules.graphql_scanner import GraphQLScanner

# Advanced modules
from ..modules.grpc_scanner import GRPCScanner
from ..modules.hash_cracker import HashCracker
from ..modules.headers_scanner import HeadersScanner
from ..modules.js_secrets_scanner import JSSecretsScanner
from ..modules.jwt_scanner import JWTScanner
from ..modules.lfi_rfi_scanner import LfiRfiScanner
from ..modules.logging_scanner import LoggingScanner
from ..modules.mobile_api_scanner import MobileAPIScanner
from ..modules.nikto_scanner import NiktoScanner

# External Tool Integration Modules
from ..modules.nmap_scanner import NmapScanner
from ..modules.open_redirect_scanner import OpenRedirectScanner
from ..modules.port_scanner import PortScanner
from ..modules.proto_pollution_scanner import ProtoPollutionScanner
from ..modules.protocol_scanner import ProtocolScanner
from ..modules.race_condition_scanner import RaceConditionScanner
from ..modules.rate_limit_scanner import RateLimitScanner
from ..modules.recon_scanner import ReconScanner
from ..modules.recursive_scanner import RecursiveScanner
from ..modules.robots_txt_scanner import RobotsTxtScanner
from ..modules.security_misconfig_scanner import SecurityMisconfigScanner
from ..modules.security_txt_scanner import SecurityTxtScanner
from ..modules.sqli_scanner import SQLIScanner
from ..modules.sse_scanner import SSEScanner
from ..modules.ssi_scanner import SSIScanner
from ..modules.ssrf_scanner import SSRFScanner
from ..modules.ssti_scanner import SSTIScanner
from ..modules.subdomain_scanner import SubdomainScanner
from ..modules.supply_chain_scanner import SupplyChainScanner
from ..modules.waf_detector import WAFDetector
from ..modules.webshell_scanner import WebshellScanner
from ..modules.webshell_uploader_module import WebshellUploaderScanner
from ..modules.websocket_scanner import WebSocketScanner
from ..modules.wordlist_builder import WordlistBuilder

# Scanner Imports
from ..modules.xss_scanner import XSSScanner
from ..modules.xxe_scanner import XXEScanner
from ..reporting.templates import ReportTemplateManager
from .chain_analyzer import ChainAnalyzer
from .config import Config
from .exceptions import ScannerException
from .http_client import HTTPClient

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Consolidated scan result with rich metadata."""

    module_name: str
    status: str
    details: str
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    duration: float = 0.0
    risk_level: str = "unknown"


class ScannerEngine:
    """High-performance security scanning orchestrator."""

    def __init__(self, config: Config):
        self.config = config
        self.http_client = HTTPClient(config.network)
        if config.scanner.enable_waf_bypass:
            self.http_client.enable_stealth()
        self.semaphore = asyncio.Semaphore(config.scanner.concurrent_requests)
        self.results: list[ScanResult] = []
        self.start_time: datetime | None = None
        self.end_time: datetime | None = None
        self.target_url: str | None = None
        self.template_manager = ReportTemplateManager()

        # Explicit registration
        self.modules: dict[str, BaseScanner] = {
            "recon_scanner": ReconScanner(config, self.http_client),
            "subdomain_scanner": SubdomainScanner(config, self.http_client),
            "xss_scanner": XSSScanner(config, self.http_client),
            "sqli_scanner": SQLIScanner(config, self.http_client),
            "lfi_scanner": LfiRfiScanner(config, self.http_client),
            "ssrf_scanner": SSRFScanner(config, self.http_client),
            "cmd_injection": CommandInjectionScanner(config, self.http_client),
            "misconfig": SecurityMisconfigScanner(config, self.http_client),
            "xxe_scanner": XXEScanner(config, self.http_client),
            "ssti_scanner": SSTIScanner(config, self.http_client),
            "deserialization": DeserializationScanner(config, self.http_client),
            "graphql_scanner": GraphQLScanner(config, self.http_client),
            "jwt_scanner": JWTScanner(config, self.http_client),
            "api_scanner": ApiScanner(config, self.http_client),
            "auth_scanner": AuthScanner(config, self.http_client),
            "cors_scanner": CORSScanner(config, self.http_client),
            "csrf_scanner": CsrfScanner(config, self.http_client),
            "open_redirect": OpenRedirectScanner(config, self.http_client),
            "proto_pollution": ProtoPollutionScanner(config, self.http_client),
            "webshell_scanner": WebshellScanner(config, self.http_client),
            "robots_scanner": RobotsTxtScanner(config, self.http_client),
            "ssi_scanner": SSIScanner(config, self.http_client),
            "js_secrets_scanner": JSSecretsScanner(config, self.http_client),
            "port_scanner": PortScanner(config, self.http_client),
            # Additional modules
            "broken_access_control": BrokenAccessControlScanner(config, self.http_client),
            "cloud_scanner": CloudScanner(config, self.http_client),
            "directory_scanner": DirectoryScanner(config, self.http_client),
            "headers_scanner": HeadersScanner(config, self.http_client),
            "race_condition": RaceConditionScanner(config, self.http_client),
            "security_txt_scanner": SecurityTxtScanner(config, self.http_client),
            "webshell_uploader": WebshellUploaderScanner(config, self.http_client),
            # New modules (OWASP A06, A09 + Advanced)
            "dependency_scanner": DependencyScanner(config, self.http_client),
            "waf_detector": WAFDetector(config, self.http_client),
            "logging_scanner": LoggingScanner(config, self.http_client),
            "websocket_scanner": WebSocketScanner(config, self.http_client),
            "rate_limit_scanner": RateLimitScanner(config, self.http_client),
            # Advanced modules
            "grpc_scanner": GRPCScanner(config, self.http_client),
            "mobile_api_scanner": MobileAPIScanner(config, self.http_client),
            "recursive_scanner": RecursiveScanner(config, self.http_client),
            # OWASP 2025 modules
            "exception_scanner": ExceptionScanner(config, self.http_client),
            "supply_chain_scanner": SupplyChainScanner(config, self.http_client),
            # External Tool Integration (Nmap, Gobuster, Nikto, etc.)
            "nmap_scanner": NmapScanner(config, self.http_client),
            "gobuster_scanner": GobusterScanner(config, self.http_client),
            "nikto_scanner": NiktoScanner(config, self.http_client),
            "hash_cracker": HashCracker(config, self.http_client),
            "wordlist_builder": WordlistBuilder(config, self.http_client),
            "sse_scanner": SSEScanner(config, self.http_client),
            "protocol_scanner": ProtocolScanner(config, self.http_client),
        }

    def _discover_modules(self):
        """Dynamically discover and register scanning modules from the modules package."""
        modules_path = Path(__file__).parent.parent / "modules"

        for _, name, is_pkg in pkgutil.iter_modules([str(modules_path)]):
            if is_pkg or name == "base_scanner":
                continue

            try:
                module = importlib.import_module(f"..modules.{name}", package="src.core")
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if isinstance(attr, type) and issubclass(attr, BaseScanner) and attr is not BaseScanner:

                        module_instance = attr(self.config, self.http_client)
                        module_id = name.replace("_scanner", "")
                        self.modules[module_id] = module_instance
                        logger.debug(f"Registered module: {module_id} ({attr_name})")

            except Exception as e:
                logger.error(f"Failed to load module {name}: {e}")

    async def scan_target(
        self, url: str, module_names: list[str] | None = None, progress_callback: Callable | None = None
    ) -> list[ScanResult]:
        """
        Execute a full security assessment on the target URL.
        """
        self.target_url = url
        if not self.config.validate_target(url):
            raise ScannerException(f"Permission denied: Target '{url}' is blacklisted or not in whitelist.")

        active_module_ids = module_names if module_names else list(self.modules.keys())

        # Verify selected modules exist
        for mid in active_module_ids:
            if mid not in self.modules:
                raise ScannerException(f"Unknown module requested: {mid}")

        logger.info(f"Initializing scan on {url} with {len(active_module_ids)} modules.")
        self.start_time = datetime.now()
        self.results = []

        # Concurrency control: limit number of modules running at once
        semaphore = asyncio.Semaphore(5)

        async def sem_run(mid):
            async with semaphore:
                return await self._run_module(mid, url, progress_callback)

        try:
            await self.http_client.start()

            tasks = [sem_run(mid) for mid in active_module_ids]
            self.results = await asyncio.gather(*tasks)

            # --- POST-SCAN ANALYSIS: CHAINING ---
            if self.results:
                logger.info("Running post-scan Chain Analysis...")
                analyzer = ChainAnalyzer()
                chains = analyzer.analyze(self.results)

                if chains:
                    # Create a consolidated result for chains
                    chain_vulnerabilities = [analyzer._format_chain_as_vulnerability(c) for c in chains]

                    chain_result = ScanResult(
                        module_name="ChainAnalyzer",
                        status="Completed",
                        details=f"Identified {len(chains)} attack chains.",
                        vulnerabilities=chain_vulnerabilities,
                        evidence={"chains": [c.__dict__ for c in chains]},
                        risk_level="critical" if any(c.risk_level == "critical" for c in chains) else "high",
                        duration=0.0,  # Instant
                    )
                    self.results.append(chain_result)
                    logger.info(f"Chain Analysis added {len(chains)} complex findings.")
            # ------------------------------------

        finally:
            await self.http_client.close()
            self.end_time = datetime.now()

        return self.results

    async def _run_module(self, module_id: str, url: str, progress_callback: Callable | None) -> ScanResult:
        """Run an individual module with timing and error isolation."""
        module = self.modules[module_id]
        start = datetime.now()

        try:
            if progress_callback:
                progress_callback(module_id, "starting", 0)

            raw_result = await module.scan(url, progress_callback)
            duration = (datetime.now() - start).total_seconds()

            return ScanResult(
                module_name=module_id,
                status=raw_result.get("status", "Completed"),
                details=raw_result.get("details", ""),
                vulnerabilities=raw_result.get("vulnerabilities", []),
                evidence=raw_result.get("evidence", {}),
                duration=duration,
                risk_level=raw_result.get("risk_level", "info"),
            )

        except Exception as e:
            logger.exception(f"Module '{module_id}' crashed: {e}")
            return ScanResult(
                module_name=module_id,
                status="Error",
                details=str(e),
                duration=(datetime.now() - start).total_seconds(),
                risk_level="unknown",
            )

    async def get_scan_summary_async(self) -> dict[str, Any]:
        """Generate high-level statistics with async capability for HTTP stats."""
        if not self.results:
            return {"error": "No results available"}

        vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        total_vulns = 0

        for res in self.results:
            for v in res.vulnerabilities:
                sev = v.get("severity", "info").lower()
                if sev in vuln_counts:
                    vuln_counts[sev] += 1
                    total_vulns += 1

        duration = (self.end_time - self.start_time).total_seconds() if self.end_time else 0
        http_stats = await self.http_client.get_stats() if self.http_client else {}

        return {
            "target": self.target_url,
            "scan_duration": round(duration, 2),
            "total_modules": len(self.results),
            "vulnerability_counts": vuln_counts,
            "total_vulnerabilities": total_vulns,
            "http_stats": http_stats,
            "timestamp": self.start_time.isoformat() if self.start_time else None,
        }

    def get_scan_summary(self) -> dict[str, Any]:
        """Synchronous version for internal metrics (omits async HTTP stats if needed)."""
        # This matches the legacy signature but avoids blocking calls
        vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        total_vulns = 0
        for res in self.results:
            for v in res.vulnerabilities:
                sev = v.get("severity", "info").lower()
                if sev in vuln_counts:
                    vuln_counts[sev] += 1
                    total_vulns += 1

        duration = (self.end_time - self.start_time).total_seconds() if self.end_time and self.start_time else 0
        return {
            "target": self.target_url,
            "scan_duration": round(duration, 2),
            "total_modules": len(self.results),
            "vulnerability_counts": vuln_counts,
            "total_vulnerabilities": total_vulns,
            "status": "completed" if self.end_time else "running",
            "start_time": self.start_time.isoformat() if self.start_time else None,
        }

    def export_results(self, format_type: str = "json") -> str:
        """Export results in a specific format for CLI output or redirection."""
        from ..reporting.formatters import HTMLFormatter, JSONFormatter, MarkdownFormatter, TXTFormatter

        scan_data = {"summary": self.get_scan_summary(), "results": [r.__dict__ for r in self.results]}

        if format_type.lower() == "json":
            return JSONFormatter().format_report(scan_data)
        elif format_type.lower() == "txt":
            return TXTFormatter().format_report(scan_data)
        elif format_type.lower() == "html":
            return HTMLFormatter().format_report(scan_data)
        elif format_type.lower() == "md":
            return MarkdownFormatter().format_report(scan_data)
        else:
            raise ScannerException(f"Unsupported export format: {format_type}")

    def generate_comprehensive_report(self, output_dir: str = "output/reports") -> dict[str, str]:
        """Orchestrate report generation across all supported formats and templates."""
        from ..reporting.formatters import HTMLFormatter, JSONFormatter, MarkdownFormatter, TXTFormatter

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        scan_data = {
            "url": self.target_url,
            "timestamp": (
                self.start_time.strftime("%Y-%m-%d %H:%M:%S")
                if self.start_time
                else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ),
            "scan_type": "Comprehensive Security Assessment",
            "summary": self.get_scan_summary(),
            "results": [r.__dict__ for r in self.results],
            "modules": [m.__class__.__name__ for m in self.modules.values()],
        }

        generated_files = {}

        # 1. Base Formatters
        report_map = {
            "json": (JSONFormatter(), f"report_{timestamp}.json"),
            "txt": (TXTFormatter(), f"report_{timestamp}.txt"),
            "html": (HTMLFormatter(), f"report_{timestamp}.html"),
            "md": (MarkdownFormatter(), f"report_{timestamp}.md"),
        }

        for fmt, (formatter, filename) in report_map.items():
            try:
                content = formatter.format_report(scan_data)
                path = output_path / filename
                path.write_text(content, encoding="utf-8")
                generated_files[fmt] = str(path)
            except Exception as e:
                logger.error(f"Failed to generate {fmt} report: {e}")

        # 2. Template-based Reports (Markdown)
        for t_type in self.template_manager.list_templates():
            try:
                content = self.template_manager.generate_report(t_type, scan_data)
                filename = f"{t_type}_{timestamp}.md"
                path = output_path / filename
                path.write_text(content, encoding="utf-8")
                generated_files[t_type] = str(path)
            except Exception as e:
                logger.error(f"Failed to generate {t_type} template: {e}")

        return generated_files

    async def diagnostic_check(self) -> dict[str, Any]:
        """Perform system health and readiness diagnostics."""
        health = {
            "status": "healthy",
            "issues": [],
            "stats": {
                "modules_loaded": len(self.modules),
                "http_client": "active" if self.http_client else "inactive",
                "config_loaded": True,
            },
        }

        # Check wordlists
        wordlists_dir = Path("wordlists")
        if not wordlists_dir.exists():
            health["issues"].append("Wordlists directory missing")
            health["status"] = "degraded"

        # Check output directories
        for d in ["output/reports", "output/logs", "output/temp"]:
            Path(d).mkdir(parents=True, exist_ok=True)

        return health
