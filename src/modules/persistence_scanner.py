"""
Persistence Assessment Module - Attack Persistence Vector Scanner

WARNING: This module is designed for AUTHORIZED penetration testing and security
assessments ONLY. Unauthorized use against systems you do not own or have explicit
written permission to test is ILLEGAL and UNETHICAL. Always obtain proper authorization
before conducting any security assessment.

This module performs ASSESSMENT ONLY - it identifies persistence opportunities
but does NOT plant any backdoors, web shells, or persistent access mechanisms.
It analyzes upload vectors, scheduled task injection points, service manipulation
opportunities, and backdoor indicators.
"""

import asyncio
import logging
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from .base_scanner import BaseScanner, Vulnerability

logger = logging.getLogger(__name__)


# Web shell signatures for detection
WEBSHELL_SIGNATURES = [
    {"pattern": r"eval\s*\(\s*\$_(POST|GET|REQUEST)", "name": "PHP eval injection", "severity": "critical"},
    {"pattern": r"system\s*\(\s*\$_(POST|GET|REQUEST)", "name": "PHP system call", "severity": "critical"},
    {"pattern": r"passthru\s*\(", "name": "PHP passthru", "severity": "critical"},
    {"pattern": r"shell_exec\s*\(", "name": "PHP shell_exec", "severity": "critical"},
    {"pattern": r"exec\s*\(\s*\$_(POST|GET|REQUEST)", "name": "PHP exec injection", "severity": "critical"},
    {"pattern": r"<\?php.*?(eval|exec|system|passthru|popen)", "name": "PHP webshell pattern", "severity": "critical"},
    {"pattern": r"Runtime\.getRuntime\(\)\.exec", "name": "Java runtime exec", "severity": "critical"},
    {"pattern": r"ProcessBuilder", "name": "Java ProcessBuilder", "severity": "high"},
    {"pattern": r"os\.system\(|subprocess\.call\(", "name": "Python command execution", "severity": "critical"},
    {"pattern": r"<%.*?Runtime.*?exec", "name": "JSP webshell", "severity": "critical"},
]

# Upload endpoint patterns
UPLOAD_ENDPOINTS = [
    "/upload", "/file/upload", "/api/upload", "/api/v1/upload",
    "/media/upload", "/image/upload", "/attachment/upload",
    "/admin/upload", "/wp-admin/upload.php", "/editor/upload",
    "/filemanager/upload", "/cms/upload",
]

# Scheduled task indicators
SCHEDULED_TASK_INDICATORS = {
    "cron_paths": [
        "/cron", "/api/cron", "/admin/cron", "/scheduler",
        "/api/scheduler", "/tasks", "/api/tasks",
        "/admin/scheduled-tasks", "/jobs", "/api/jobs",
    ],
    "cron_patterns": [
        r"\*/\d+\s+\*\s+\*\s+\*\s+\*",  # */5 * * * *
        r"crontab", r"cron\.d", r"at\s+\d",
        r"schtasks", r"Task Scheduler",
    ],
}

# Backdoor detection indicators
BACKDOOR_INDICATORS = {
    "reverse_shell_patterns": [
        r"nc\s+-[elp]", r"ncat\s+-", r"socat\s+",
        r"bash\s+-i\s+>&", r"/dev/tcp/", r"/dev/udp/",
        r"python.*?socket.*?connect", r"ruby.*?TCPSocket",
        r"perl.*?socket.*?connect", r"php.*?fsockopen",
    ],
    "bind_shell_patterns": [
        r"nc\s+-l", r"ncat\s+--listen", r"socat\s+TCP-LISTEN",
        r"socket\.bind\(", r"ServerSocket\(",
    ],
    "suspicious_ports": [4444, 5555, 1337, 31337, 8888, 9999, 6666],
}

# Service/config modification paths
SERVICE_PATHS = [
    "/admin/services", "/api/services", "/admin/config",
    "/api/config", "/api/v1/config", "/admin/settings",
    "/settings", "/configuration", "/admin/system",
]


class PersistenceScanner(BaseScanner):
    """
    Persistence Assessment Scanner.

    AUTHORIZED USE ONLY: This module identifies persistence opportunities
    WITHOUT planting any persistent access. It assesses:

    - Web shell upload vector analysis
    - Cron job / scheduled task injection points
    - Startup script modification vectors
    - Service manipulation opportunities
    - Configuration modification paths
    - Backdoor detection (reverse/bind shells)
    """

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "PersistenceScanner"
        self.description = "Persistence vector assessment (detection only)"
        self.version = "1.0.0"
        self.capabilities = [
            "Web Shell Vector Analysis",
            "Scheduled Task Injection Detection",
            "Service Manipulation Assessment",
            "Configuration Modification Detection",
            "Backdoor Detection",
            "Startup Script Analysis",
        ]
        self.max_requests = 80

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform persistence assessment scan."""
        logger.info(f"Starting Persistence assessment for {url}")
        vulnerabilities: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "webshell_vectors": {},
            "scheduled_tasks": {},
            "service_manipulation": {},
            "config_modification": {},
            "backdoor_detection": {},
            "startup_scripts": {},
        }

        try:
            # Phase 1: Web Shell Upload Vector Analysis (20%)
            self._update_progress(progress_callback, 10, "Analyzing web shell upload vectors")
            ws_vulns, ws_evidence = await self._analyze_webshell_vectors(url)
            vulnerabilities.extend(ws_vulns)
            evidence["webshell_vectors"] = ws_evidence

            # Phase 2: Scheduled Task Injection (35%)
            self._update_progress(progress_callback, 25, "Scanning scheduled task injection points")
            st_vulns, st_evidence = await self._scan_scheduled_tasks(url)
            vulnerabilities.extend(st_vulns)
            evidence["scheduled_tasks"] = st_evidence

            # Phase 3: Service Manipulation (50%)
            self._update_progress(progress_callback, 40, "Checking service manipulation vectors")
            svc_vulns, svc_evidence = await self._check_service_manipulation(url)
            vulnerabilities.extend(svc_vulns)
            evidence["service_manipulation"] = svc_evidence

            # Phase 4: Configuration Modification (65%)
            self._update_progress(progress_callback, 55, "Scanning config modification paths")
            cfg_vulns, cfg_evidence = await self._scan_config_modification(url)
            vulnerabilities.extend(cfg_vulns)
            evidence["config_modification"] = cfg_evidence

            # Phase 5: Backdoor Detection (80%)
            self._update_progress(progress_callback, 70, "Detecting backdoor indicators")
            bd_vulns, bd_evidence = await self._detect_backdoors(url)
            vulnerabilities.extend(bd_vulns)
            evidence["backdoor_detection"] = bd_evidence

            # Phase 6: Startup Script Analysis (100%)
            self._update_progress(progress_callback, 85, "Analyzing startup script vectors")
            ss_vulns, ss_evidence = await self._analyze_startup_scripts(url)
            vulnerabilities.extend(ss_vulns)
            evidence["startup_scripts"] = ss_evidence

            self._update_progress(progress_callback, 100, "completed")

        except Exception as e:
            logger.error(f"Persistence assessment error: {e}")
            return self._format_result(
                "Error", f"Assessment failed: {str(e)}", vulnerabilities, evidence
            )

        details = (
            f"Persistence assessment completed (ASSESSMENT ONLY). "
            f"Found {len(vulnerabilities)} persistence vector(s). "
            f"Upload vectors: {ws_evidence.get('upload_endpoints_found', 0)}, "
            f"Task injection: {st_evidence.get('injection_points', 0)}, "
            f"Backdoors: {bd_evidence.get('indicators_found', 0)}"
        )

        return self._format_result("Completed", details, vulnerabilities, evidence)

    async def _analyze_webshell_vectors(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Analyze web shell upload vectors."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "upload_endpoints_found": 0,
            "endpoints": [],
            "existing_shells": [],
        }

        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # Check for upload endpoints
            for endpoint in UPLOAD_ENDPOINTS:
                try:
                    resp = await self.http_client.get(f"{base_url}{endpoint}")
                    if resp and resp.status not in [404, 405]:
                        endpoint_info = {
                            "path": endpoint,
                            "status": resp.status,
                            "accessible": resp.status == 200,
                        }

                        # Check if file type restrictions are present
                        if resp.status == 200:
                            try:
                                body = await resp.text()
                                has_restriction = any(
                                    w in body.lower()
                                    for w in ["accept=", "allowed types", "file type", ".jpg", ".png", ".pdf"]
                                )
                                endpoint_info["file_type_restriction"] = has_restriction
                            except Exception:
                                pass

                        evidence["endpoints"].append(endpoint_info)
                        if resp.status == 200:
                            evidence["upload_endpoints_found"] += 1
                except Exception:
                    pass

            # Check for existing web shells in common locations
            shell_paths = [
                "/shell.php", "/cmd.php", "/c99.php", "/r57.php",
                "/b374k.php", "/webshell.php", "/upload/shell.php",
                "/images/shell.php", "/tmp/shell.php",
                "/shell.asp", "/cmd.asp", "/shell.aspx",
                "/shell.jsp", "/cmd.jsp",
            ]

            for shell_path in shell_paths:
                try:
                    resp = await self.http_client.get(f"{base_url}{shell_path}")
                    if resp and resp.status == 200:
                        try:
                            body = await resp.text()
                            # Check for web shell indicators
                            for sig in WEBSHELL_SIGNATURES[:5]:
                                if re.search(sig["pattern"], body, re.IGNORECASE):
                                    evidence["existing_shells"].append({
                                        "path": shell_path,
                                        "signature": sig["name"],
                                        "severity": sig["severity"],
                                    })
                                    break
                        except Exception:
                            pass
                except Exception:
                    pass

            if evidence["existing_shells"]:
                vulns.append(self._create_vulnerability(
                    title=f"Web Shells Detected ({len(evidence['existing_shells'])})",
                    description=(
                        "Active web shells were detected on the server. This indicates "
                        "an existing compromise and active persistence mechanism."
                    ),
                    severity="critical",
                    type="persistence_webshell",
                    evidence={"shells": evidence["existing_shells"]},
                    cwe_id="CWE-506",
                    remediation="Remove detected web shells immediately. Investigate the compromise source.",
                ))

            if evidence["upload_endpoints_found"] > 0:
                unrestricted = [
                    e for e in evidence["endpoints"]
                    if e.get("accessible") and not e.get("file_type_restriction", True)
                ]
                if unrestricted:
                    vulns.append(self._create_vulnerability(
                        title=f"Unrestricted File Upload ({len(unrestricted)} endpoints)",
                        description=(
                            "Upload endpoints without file type restrictions were found. "
                            "An attacker could upload web shells for persistent access."
                        ),
                        severity="high",
                        type="persistence_unrestricted_upload",
                        evidence={"unrestricted_uploads": unrestricted[:5]},
                        cwe_id="CWE-434",
                        remediation="Implement strict file type validation. Store uploads outside web root.",
                    ))

        except Exception as e:
            logger.debug(f"Web shell vector analysis error: {e}")

        return vulns, evidence

    async def _scan_scheduled_tasks(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Scan for scheduled task injection points."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "injection_points": 0,
            "task_endpoints": [],
        }

        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            for path in SCHEDULED_TASK_INDICATORS["cron_paths"]:
                try:
                    resp = await self.http_client.get(f"{base_url}{path}")
                    if resp and resp.status not in [404, 405]:
                        endpoint_info = {
                            "path": path,
                            "status": resp.status,
                            "accessible": resp.status == 200,
                        }

                        if resp.status == 200:
                            try:
                                body = await resp.text()
                                # Check for cron/task patterns
                                for pattern_str in SCHEDULED_TASK_INDICATORS["cron_patterns"]:
                                    pattern = re.compile(pattern_str, re.IGNORECASE)
                                    if pattern.search(body):
                                        endpoint_info["cron_data_exposed"] = True
                                        evidence["injection_points"] += 1
                                        break
                            except Exception:
                                pass

                        evidence["task_endpoints"].append(endpoint_info)

                except Exception:
                    pass

            if evidence["injection_points"] > 0:
                vulns.append(self._create_vulnerability(
                    title="Scheduled Task Management Exposed",
                    description=(
                        "Scheduled task/cron job management endpoints are accessible. "
                        "An attacker could modify or create scheduled tasks for persistence."
                    ),
                    severity="high",
                    type="persistence_scheduled_task",
                    evidence=evidence,
                    cwe_id="CWE-284",
                    remediation="Restrict task management endpoints. Require admin authentication.",
                ))

        except Exception as e:
            logger.debug(f"Scheduled task scan error: {e}")

        return vulns, evidence

    async def _check_service_manipulation(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Check for service manipulation opportunities."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "accessible_services": [],
            "manipulation_risk": False,
        }

        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            for path in SERVICE_PATHS:
                try:
                    resp = await self.http_client.get(f"{base_url}{path}")
                    if resp and resp.status == 200:
                        service_info = {
                            "path": path,
                            "status": resp.status,
                        }

                        try:
                            body = await resp.text()
                            # Check for service management capabilities
                            mgmt_indicators = [
                                "restart", "stop", "start", "enable",
                                "disable", "service", "daemon",
                            ]
                            found_indicators = [
                                w for w in mgmt_indicators if w in body.lower()
                            ]
                            if found_indicators:
                                service_info["management_capabilities"] = found_indicators
                                evidence["manipulation_risk"] = True
                        except Exception:
                            pass

                        evidence["accessible_services"].append(service_info)

                except Exception:
                    pass

            if evidence["manipulation_risk"]:
                vulns.append(self._create_vulnerability(
                    title="Service Management Endpoints Accessible",
                    description=(
                        "Service management endpoints are accessible and expose "
                        "start/stop/restart capabilities. An attacker could manipulate "
                        "services to maintain persistence."
                    ),
                    severity="high",
                    type="persistence_service",
                    evidence={"services": evidence["accessible_services"][:5]},
                    cwe_id="CWE-284",
                    remediation="Restrict service management to authenticated admin users only.",
                ))

        except Exception as e:
            logger.debug(f"Service manipulation check error: {e}")

        return vulns, evidence

    async def _scan_config_modification(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Scan for configuration modification paths."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "writable_configs": [],
            "exposed_configs": [],
        }

        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            config_paths = [
                "/.env", "/config.json", "/config.yml", "/config.yaml",
                "/settings.json", "/settings.yml", "/app.config",
                "/web.config", "/wp-config.php", "/config.php",
                "/application.properties", "/application.yml",
            ]

            for path in config_paths:
                try:
                    resp = await self.http_client.get(f"{base_url}{path}")
                    if resp and resp.status == 200:
                        config_info = {
                            "path": path,
                            "status": resp.status,
                            "content_type": resp.headers.get("Content-Type", ""),
                        }

                        try:
                            body = await resp.text()
                            # Check for sensitive content
                            sensitive_patterns = [
                                "password", "secret", "api_key", "token",
                                "database", "db_host", "redis",
                            ]
                            has_sensitive = any(
                                p in body.lower() for p in sensitive_patterns
                            )
                            config_info["contains_sensitive"] = has_sensitive
                            config_info["size"] = len(body)
                        except Exception:
                            pass

                        evidence["exposed_configs"].append(config_info)

                except Exception:
                    pass

            # Test if configs are writable (PUT/PATCH)
            for config in evidence["exposed_configs"][:3]:
                try:
                    config_url = f"{base_url}{config['path']}"
                    # Test PUT method
                    resp = await self.http_client.request("OPTIONS", config_url)
                    if resp:
                        allow = resp.headers.get("Allow", "")
                        if "PUT" in allow or "PATCH" in allow:
                            evidence["writable_configs"].append({
                                "path": config["path"],
                                "allowed_methods": allow,
                            })
                except Exception:
                    pass

            if evidence["exposed_configs"]:
                sensitive_configs = [
                    c for c in evidence["exposed_configs"]
                    if c.get("contains_sensitive")
                ]
                if sensitive_configs:
                    vulns.append(self._create_vulnerability(
                        title=f"Sensitive Config Files Exposed ({len(sensitive_configs)})",
                        description=(
                            "Configuration files containing sensitive data (passwords, API keys) "
                            "are accessible. An attacker could extract credentials or modify "
                            "configuration for persistence."
                        ),
                        severity="critical",
                        type="persistence_config_exposure",
                        evidence={"configs": sensitive_configs[:5]},
                        cwe_id="CWE-538",
                        remediation="Block access to configuration files via web server rules.",
                    ))

        except Exception as e:
            logger.debug(f"Config modification scan error: {e}")

        return vulns, evidence

    async def _detect_backdoors(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Detect backdoor indicators on the target."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "indicators_found": 0,
            "reverse_shell_indicators": [],
            "bind_shell_indicators": [],
            "suspicious_ports": [],
        }

        try:
            response = await self.http_client.get(url)
            if not response or response.status != 200:
                return vulns, evidence

            html = ""
            try:
                html = await response.text()
            except Exception:
                return vulns, evidence

            # Check for reverse shell patterns in page content
            for pattern_str in BACKDOOR_INDICATORS["reverse_shell_patterns"]:
                try:
                    pattern = re.compile(pattern_str, re.IGNORECASE)
                    matches = pattern.findall(html)
                    if matches:
                        evidence["reverse_shell_indicators"].append({
                            "pattern": pattern_str[:50],
                            "matches": len(matches),
                        })
                        evidence["indicators_found"] += 1
                except Exception:
                    pass

            # Check for bind shell patterns
            for pattern_str in BACKDOOR_INDICATORS["bind_shell_patterns"]:
                try:
                    pattern = re.compile(pattern_str, re.IGNORECASE)
                    matches = pattern.findall(html)
                    if matches:
                        evidence["bind_shell_indicators"].append({
                            "pattern": pattern_str[:50],
                            "matches": len(matches),
                        })
                        evidence["indicators_found"] += 1
                except Exception:
                    pass

            # Check for suspicious port references
            port_pattern = re.compile(r':(\d{4,5})')
            port_matches = port_pattern.findall(html)
            for port_str in port_matches:
                try:
                    port = int(port_str)
                    if port in BACKDOOR_INDICATORS["suspicious_ports"]:
                        evidence["suspicious_ports"].append(port)
                        evidence["indicators_found"] += 1
                except ValueError:
                    pass

            if evidence["indicators_found"] > 0:
                vulns.append(self._create_vulnerability(
                    title=f"Backdoor Indicators Detected ({evidence['indicators_found']})",
                    description=(
                        "Patterns associated with backdoor access (reverse shells, "
                        "bind shells, suspicious ports) were found in the target's content."
                    ),
                    severity="critical",
                    type="persistence_backdoor",
                    evidence={
                        "reverse_shells": evidence["reverse_shell_indicators"][:5],
                        "bind_shells": evidence["bind_shell_indicators"][:5],
                        "suspicious_ports": evidence["suspicious_ports"][:10],
                    },
                    cwe_id="CWE-506",
                    remediation="Investigate immediately. Scan for rootkits and unauthorized access.",
                ))

        except Exception as e:
            logger.debug(f"Backdoor detection error: {e}")

        return vulns, evidence

    async def _analyze_startup_scripts(self, url: str) -> tuple[list[Vulnerability], dict]:
        """Analyze startup script modification vectors."""
        vulns: list[Vulnerability] = []
        evidence: dict[str, Any] = {
            "startup_paths_found": [],
            "modification_risk": False,
        }

        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            startup_paths = [
                "/init.d", "/rc.local", "/systemd",
                "/admin/startup", "/api/startup",
                "/admin/init", "/api/init",
                "/admin/autostart", "/autostart",
            ]

            for path in startup_paths:
                try:
                    resp = await self.http_client.get(f"{base_url}{path}")
                    if resp and resp.status == 200:
                        evidence["startup_paths_found"].append({
                            "path": path,
                            "status": resp.status,
                        })
                        evidence["modification_risk"] = True
                except Exception:
                    pass

            if evidence["modification_risk"]:
                vulns.append(self._create_vulnerability(
                    title="Startup Script Paths Accessible",
                    description=(
                        "Startup/initialization script paths are accessible via web. "
                        "An attacker could modify startup scripts for boot-persistent access."
                    ),
                    severity="high",
                    type="persistence_startup_script",
                    evidence={"paths": evidence["startup_paths_found"][:5]},
                    cwe_id="CWE-284",
                    remediation="Block access to system initialization paths from web server.",
                ))

        except Exception as e:
            logger.debug(f"Startup script analysis error: {e}")

        return vulns, evidence
