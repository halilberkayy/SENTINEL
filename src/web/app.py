"""
SENTINEL Web UI application.
FastAPI-based web dashboard with WebSocket progress reporting.
"""

import asyncio
import logging
import os
import uuid
from typing import Any, Optional

from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .scan_manager import ScanManager

# Setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()
api_key_status = "FOUND" if os.getenv("GOOGLE_AI_API_KEY") else "MISSING"
logger.info(f"AI CONFIGURATION STATUS: GOOGLE_AI_API_KEY is {api_key_status}")

app = FastAPI(title="SENTINEL - Tactical Security Assessment")

# Static files
app.mount("/static", StaticFiles(directory="web/static"), name="static")

# State management
scan_manager = ScanManager()


# ── Request models ──────────────────────────────────────────────────
class ScanRequest(BaseModel):
    url: str
    modules: list[str]


class AIReportRequest(BaseModel):
    scan_id: str
    report_type: str = "executive"
    language: str = "en"


class SettingsUpdate(BaseModel):
    timeout: int
    rate_limit: int
    concurrent_requests: int
    waf_evasion: Optional[bool] = False
    ua_rotation: Optional[bool] = True
    ssl_verification: Optional[bool] = True


class NmapRequest(BaseModel):
    target: str
    profile: str = "quick"


class GobusterRequest(BaseModel):
    target: str
    wordlist: Optional[str] = None
    extensions: str = "php,asp,aspx,jsp,html,js,txt"


class WordlistRequest(BaseModel):
    target: str
    min_length: int = 4
    max_length: int = 20


# ── Core routes ──────────────────────────────────────────────────────
@app.get("/")
async def get():
    with open("web/index.html", "r") as f:
        return HTMLResponse(content=f.read())


@app.get("/api/modules")
async def get_modules():
    modules = []
    for mod_id, mod_obj in scan_manager.engine.modules.items():
        modules.append({
            "id": mod_id,
            "name": mod_obj.name,
            "description": getattr(mod_obj, "description", "No description available"),
        })
    return modules


# ── Scan templates ────────────────────────────────────────────────────
@app.get("/api/templates")
async def get_scan_templates(category: Optional[str] = None, tag: Optional[str] = None):
    from src.core.scan_templates import get_template_manager

    manager = get_template_manager()
    if category:
        templates = manager.get_templates_by_category(category)
    elif tag:
        templates = manager.get_templates_by_tag(tag)
    else:
        templates = manager.get_all_templates()
    return {"templates": templates, "count": len(templates), "categories": manager.get_categories()}


@app.get("/api/templates/{template_id}")
async def get_template_details(template_id: str):
    from src.core.scan_templates import get_template_manager

    manager = get_template_manager()
    template = manager.get_template_dict(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    return template


@app.post("/api/scan/start/template/{template_id}")
async def start_scan_from_template(template_id: str, url: str, background_tasks: BackgroundTasks):
    from src.core.scan_templates import get_template_manager

    manager = get_template_manager()
    template = manager.get_template(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    scan_id = uuid.uuid4().hex[:8]
    scan_manager.active_scans[scan_id] = {
        "url": url, "status": "starting", "results": [], "progress": 0, "template": template_id
    }
    background_tasks.add_task(run_scan_task, scan_id, url, template.modules)
    return {"scan_id": scan_id, "message": f"Scan started with template: {template.name}", "template": template_id, "modules": template.modules}


@app.post("/api/scan/start")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    url = request.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    scan_id = uuid.uuid4().hex[:8]
    scan_manager.active_scans[scan_id] = {"url": url, "status": "starting", "results": [], "progress": 0}
    background_tasks.add_task(run_scan_task, scan_id, url, request.modules)
    return {"scan_id": scan_id, "message": "Scan started"}


# ── Settings ──────────────────────────────────────────────────────────
@app.get("/api/settings")
async def get_settings():
    return {
        "timeout": scan_manager.config.network.timeout,
        "rate_limit": scan_manager.config.network.rate_limit,
        "concurrent_requests": scan_manager.config.scanner.concurrent_requests,
        "waf_evasion": getattr(scan_manager.config.scanner, "enable_waf_bypass", False),
        "ua_rotation": getattr(scan_manager.config.scanner, "enable_ua_rotation", True),
        "ssl_verification": getattr(scan_manager.config.network, "verify_ssl", True),
        "ai_enabled": bool(os.getenv("GOOGLE_AI_API_KEY")),
    }


@app.post("/api/settings")
async def update_settings(settings: SettingsUpdate):
    from src.core.scanner_engine import ScannerEngine

    scan_manager.config.network.timeout = settings.timeout
    scan_manager.config.network.rate_limit = settings.rate_limit
    scan_manager.config.scanner.concurrent_requests = settings.concurrent_requests

    if hasattr(scan_manager.config.scanner, "enable_waf_bypass"):
        scan_manager.config.scanner.enable_waf_bypass = settings.waf_evasion
    if hasattr(scan_manager.config.scanner, "enable_ua_rotation"):
        scan_manager.config.scanner.enable_ua_rotation = settings.ua_rotation
    if hasattr(scan_manager.config.network, "verify_ssl"):
        scan_manager.config.network.verify_ssl = settings.ssl_verification

    scan_manager.config.save()
    scan_manager.engine = ScannerEngine(scan_manager.config)
    return {"message": "Settings updated and engine re-initialized"}


# ── External tools ────────────────────────────────────────────────────
@app.get("/api/external-tools")
async def get_external_tools_status():
    from src.utils.command_runner import ExternalCommandRunner

    runner = ExternalCommandRunner()
    tools = runner.get_available_tools()
    return {"tools": tools, "available_count": sum(1 for v in tools.values() if v), "total_count": len(tools)}


@app.post("/api/tools/nmap")
async def run_nmap_scan(request: NmapRequest, background_tasks: BackgroundTasks):
    from src.utils.command_runner import ExternalCommandRunner

    runner = ExternalCommandRunner()
    if not runner.check_tool_available("nmap"):
        raise HTTPException(status_code=400, detail="Nmap is not installed on the system")

    scan_id = f"nmap_{uuid.uuid4().hex[:8]}"
    scan_manager.active_scans[scan_id] = {"status": "starting", "tool": "nmap"}
    background_tasks.add_task(_run_tool_task, scan_id, "nmap", request.target, request.profile)
    return {"scan_id": scan_id, "message": "Nmap scan started"}


@app.post("/api/tools/gobuster")
async def run_gobuster_scan(request: GobusterRequest, background_tasks: BackgroundTasks):
    from src.utils.command_runner import ExternalCommandRunner

    runner = ExternalCommandRunner()
    if not runner.check_tool_available("gobuster") and not runner.check_tool_available("dirb"):
        raise HTTPException(status_code=400, detail="Neither Gobuster nor Dirb is installed")

    scan_id = f"gobuster_{uuid.uuid4().hex[:8]}"
    scan_manager.active_scans[scan_id] = {"status": "starting", "tool": "gobuster"}
    background_tasks.add_task(_run_tool_task, scan_id, "gobuster", request.target)
    return {"scan_id": scan_id, "message": "Directory scan started"}


@app.post("/api/tools/nikto")
async def run_nikto_scan(request: NmapRequest, background_tasks: BackgroundTasks):
    from src.utils.command_runner import ExternalCommandRunner

    runner = ExternalCommandRunner()
    if not runner.check_tool_available("nikto"):
        raise HTTPException(status_code=400, detail="Nikto is not installed")

    scan_id = f"nikto_{uuid.uuid4().hex[:8]}"
    background_tasks.add_task(_run_tool_task, scan_id, "nikto", request.target)
    return {"scan_id": scan_id, "message": "Nikto scan started"}


@app.post("/api/tools/wordlist")
async def generate_wordlist(request: WordlistRequest, background_tasks: BackgroundTasks):
    scan_id = f"wordlist_{uuid.uuid4().hex[:8]}"
    background_tasks.add_task(_run_tool_task, scan_id, "wordlist", request.target)
    return {"scan_id": scan_id, "message": "Wordlist generation started"}


@app.get("/api/tools/wordlists")
async def list_generated_wordlists():
    from pathlib import Path

    wordlist_dir = Path("output/wordlists")
    if not wordlist_dir.exists():
        return {"wordlists": []}

    wordlists = []
    for f in wordlist_dir.glob("*.txt"):
        wordlists.append({"name": f.name, "path": str(f), "size": f.stat().st_size, "lines": sum(1 for _ in f.open())})
    return {"wordlists": wordlists}


# ── Payloads ──────────────────────────────────────────────────────────
@app.get("/api/payloads")
async def get_payloads(category: Optional[str] = None):
    from src.core.payload_manager import PayloadManager

    pm = PayloadManager()
    if category:
        return pm.get_payloads_by_category(category)
    return pm.payloads


@app.get("/api/payloads/{payload_id}/guide")
async def get_payload_guide(payload_id: str):
    from src.core.payload_manager import PayloadManager

    pm = PayloadManager()
    guide = pm.get_attack_guide(payload_id)
    if not guide:
        raise HTTPException(status_code=404, detail="Payload not found")
    return guide


# ── Scan history ──────────────────────────────────────────────────────
@app.get("/api/scans/history")
async def get_scan_history(limit: int = 50):
    scans = scan_manager.get_recent_scans(limit)
    return {"scans": scans, "count": len(scans)}


@app.get("/api/scans/{scan_id}")
async def get_scan_details(scan_id: str):
    scan = scan_manager.get_scan_results(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: str):
    if scan_manager.store.delete_scan(scan_id):
        scan_manager.last_scan_results.pop(scan_id, None)
        return {"message": "Scan deleted successfully"}
    raise HTTPException(status_code=404, detail="Scan not found")


# ── AI narrator ───────────────────────────────────────────────────────
@app.get("/api/ai/status")
async def get_ai_status():
    api_key = os.getenv("GOOGLE_AI_API_KEY")
    return {
        "available": bool(api_key),
        "enabled": bool(api_key),
        "key_configured": bool(api_key),
        "provider": os.getenv("AI_PROVIDER", "gemini"),
        "model": os.getenv("AI_MODEL", "models/gemini-1.5-flash"),
    }


@app.post("/api/ai/generate")
async def generate_ai_report(request: AIReportRequest, background_tasks: BackgroundTasks):
    api_key = os.getenv("GOOGLE_AI_API_KEY")
    if not api_key:
        raise HTTPException(status_code=400, detail="AI not configured. Set GOOGLE_AI_API_KEY in .env file")

    scan_results = scan_manager.last_scan_results.get(request.scan_id)
    if not scan_results and scan_manager.last_scan_results:
        latest_id = list(scan_manager.last_scan_results.keys())[-1]
        scan_results = scan_manager.last_scan_results[latest_id]

    if not scan_results:
        raise HTTPException(status_code=404, detail="Scan results not found. Make sure a scan has completed.")

    background_tasks.add_task(_generate_ai_report_task, request.scan_id, scan_results, request.report_type, request.language)
    return {"message": "AI report generation started", "scan_id": request.scan_id}


@app.get("/api/poc/{scan_id}/{vuln_index}")
async def get_poc(scan_id: str, vuln_index: int):
    from src.reporting.poc_generator import PoCGenerator

    scan_results = scan_manager.last_scan_results.get(scan_id)
    if not scan_results:
        raise HTTPException(status_code=404, detail="Scan results not found")

    all_vulns = []
    for result in scan_results.get("results", []):
        for vuln in result.get("vulnerabilities", []):
            all_vulns.append(vuln)

    if vuln_index >= len(all_vulns):
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    vuln = all_vulns[vuln_index]
    poc = PoCGenerator()
    pocs = poc.generate_poc(vuln)
    return {"vulnerability": vuln.get("title", "Unknown"), "pocs": pocs}


@app.get("/api/cvss/{vuln_type}")
async def get_cvss_info(vuln_type: str):
    from src.core.cvss import get_cvss_for_vulnerability, get_cwe_for_vulnerability

    result = get_cvss_for_vulnerability(vuln_type)
    cwe = get_cwe_for_vulnerability(vuln_type)
    if result:
        return {
            "vuln_type": vuln_type,
            "cvss_score": result.score,
            "severity": result.severity,
            "vector": result.vector_string,
            "cwe": cwe,
            "details": result.to_dict(),
        }
    return {"vuln_type": vuln_type, "message": "No CVSS data available"}


# ── WebSocket ─────────────────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    scan_manager.connected_clients.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in scan_manager.connected_clients:
            scan_manager.connected_clients.remove(websocket)


# ── Background tasks ─────────────────────────────────────────────────
async def run_scan_task(scan_id: str, url: str, modules: list[str]) -> None:
    """Execute a vulnerability scan in the background."""
    try:
        async def module_result_callback(r: Any) -> None:
            vulns = []
            for v in r.vulnerabilities:
                vulns.append({
                    "title": v.get("title", "Unknown Issue"),
                    "severity": v.get("severity", "info"),
                    "description": v.get("description", ""),
                    "remediation": v.get("remediation", ""),
                    "evidence": v.get("evidence", {}),
                    "type": v.get("type", "unknown"),
                    "cvss_score": v.get("cvss_score", 0),
                    "cvss_vector": v.get("cvss_vector", ""),
                    "cwe_id": v.get("cwe_id", ""),
                })
            await scan_manager.broadcast({
                "type": "module_result", "scan_id": scan_id,
                "module": r.module_name, "status": r.status, "vulnerabilities": vulns,
            })

        results = await scan_manager.engine.scan_target(
            url, modules,
            progress_callback=lambda m, s, p: asyncio.create_task(
                scan_manager.broadcast({"type": "progress", "scan_id": scan_id, "module": m, "status": s, "percentage": p})
            ),
            result_callback=module_result_callback,
        )

        await scan_manager.broadcast({"type": "progress", "scan_id": scan_id, "module": "ChainAnalyzer", "status": "Running post-scan correlation analysis...", "percentage": 95})

        final_results = []
        for r in results:
            vulns = []
            for v in r.vulnerabilities:
                vulns.append({
                    "title": v.get("title", "Unknown Issue"),
                    "severity": v.get("severity", "info"),
                    "description": v.get("description", ""),
                    "remediation": v.get("remediation", ""),
                    "evidence": v.get("evidence", {}),
                    "type": v.get("type", "unknown"),
                    "cvss_score": v.get("cvss_score", 0),
                    "cvss_vector": v.get("cvss_vector", ""),
                    "cwe_id": v.get("cwe_id", ""),
                })
            final_results.append({"module": r.module_name, "status": r.status, "vulnerabilities": vulns})

        scan_manager.last_scan_results[scan_id] = {"url": url, "results": final_results, "timestamp": asyncio.get_event_loop().time()}

        await scan_manager.broadcast({
            "type": "complete", "scan_id": scan_id, "results": final_results,
            "summary": scan_manager.engine.get_scan_summary(), "ai_available": bool(os.getenv("GOOGLE_AI_API_KEY")),
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        await scan_manager.broadcast({"type": "error", "scan_id": scan_id, "message": str(e)})


async def _run_tool_task(scan_id: str, tool: str, target: str, profile: str = "quick") -> None:
    """Run an external tool scan in the background."""
    try:
        from src.core.config import Config
        from src.core.http_client import HTTPClient

        config = Config()
        http_client = HTTPClient(config.network)

        scanner_class = None
        if tool == "nmap":
            from src.modules.nmap_scanner import NmapScanner
            scanner_class = NmapScanner
        elif tool == "gobuster":
            from src.modules.gobuster_scanner import GobusterScanner
            scanner_class = GobusterScanner
        elif tool == "nikto":
            from src.modules.nikto_scanner import NiktoScanner
            scanner_class = NiktoScanner
        elif tool == "wordlist":
            from src.modules.wordlist_builder import WordlistBuilder
            scanner_class = WordlistBuilder

        if scanner_class:
            await http_client.start()
            scanner = scanner_class(config, http_client)
            result = await scanner.scan(target)
            await http_client.close()

            await scan_manager.broadcast({"type": "tool_complete", "scan_id": scan_id, "tool": tool, "result": result})
    except Exception as e:
        await scan_manager.broadcast({"type": "tool_error", "scan_id": scan_id, "tool": tool, "error": str(e)})


async def _generate_ai_report_task(scan_id: str, scan_results: dict, report_type: str, language: str) -> None:
    """Generate AI-powered report in background."""
    try:
        from src.reporting.ai_narrator import AIProvider, AINarrator, NarratorConfig

        config = NarratorConfig(
            provider=AIProvider.GEMINI,
            api_key=os.getenv("GOOGLE_AI_API_KEY"),
            model=os.getenv("AI_MODEL", "models/gemini-3-flash-preview"),
            language=language,
        )

        narrator = AINarrator(config)
        await narrator.initialize()

        if report_type == "executive":
            report = await narrator.generate_executive_summary(scan_results)
            report_data = {"executive_summary": report}
        elif report_type == "technical":
            report = await narrator.generate_technical_report(scan_results)
            report_data = {"technical_report": report}
        elif report_type == "risk":
            report = await narrator.generate_risk_narrative(scan_results)
            report_data = {"risk_narrative": report}
        else:
            report_data = await narrator.generate_full_report(scan_results)

        await scan_manager.broadcast({"type": "ai_report", "scan_id": scan_id, "report_type": report_type, "data": report_data, "status": "complete"})
    except Exception as e:
        import traceback
        traceback.print_exc()
        await scan_manager.broadcast({"type": "ai_report", "scan_id": scan_id, "status": "error", "message": str(e)})


# ── Red Team Campaign Dashboard ──────────────────────────────────────
@app.get("/campaigns")
async def campaigns_page():
    """Campaign dashboard page."""
    try:
        with open("web/campaigns.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Campaign dashboard not found</h1>", status_code=404)


@app.get("/attack-map")
async def attack_map_page():
    """MITRE ATT&CK heatmap page."""
    try:
        with open("web/attack_map.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Attack map not found</h1>", status_code=404)
