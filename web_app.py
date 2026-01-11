import sys
import os
import asyncio
from pathlib import Path
from dotenv import load_dotenv
import logging
from typing import List, Optional, Dict
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, BackgroundTasks, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
import uvicorn
import json

# Setup basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()
api_key_status = "FOUND" if os.getenv("GOOGLE_AI_API_KEY") else "MISSING"
logger.info(f"AI CONFIGURATION STATUS: GOOGLE_AI_API_KEY is {api_key_status}")

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.core.config import Config
from src.core.scanner_engine import ScannerEngine
from src.core.exceptions import ScannerException

app = FastAPI(title="SENTINEL - Tactical Security Assessment")

# Static files
app.mount("/static", StaticFiles(directory="web/static"), name="static")

# State management
class ScanManager:
    def __init__(self):
        self.active_scans: Dict[str, dict] = {}
        self.config = Config()
        self.engine = ScannerEngine(self.config)
        self.connected_clients: List[WebSocket] = []
        self.last_scan_results: Dict[str, dict] = {}  # Store results for AI analysis
        
        # Initialize persistent storage
        from src.core.scan_repository import get_memory_store
        self.store = get_memory_store()

    async def broadcast(self, data: dict):
        disconnected_clients = []
        for client in self.connected_clients:
            try:
                await client.send_json(data)
            except (WebSocketDisconnect, RuntimeError, Exception) as e:
                # Log the error and mark client for removal
                print(f"Failed to send data to client: {e}")
                disconnected_clients.append(client)

        # Remove disconnected clients
        for client in disconnected_clients:
            if client in self.connected_clients:
                self.connected_clients.remove(client)
    
    def save_scan_results(self, scan_id: str, url: str, modules: list, results: list):
        """Save scan results to persistent storage."""
        scan_data = {
            "scan_id": scan_id,
            "url": url,
            "modules": modules,
            "results": results,
            "vulnerability_count": sum(len(r.get("vulnerabilities", [])) for r in results),
            "completed_at": asyncio.get_event_loop().time() if asyncio.get_event_loop().is_running() else 0,
        }
        self.store.save_scan(scan_id, scan_data)
        self.last_scan_results[scan_id] = scan_data
    
    def get_scan_results(self, scan_id: str) -> dict | None:
        """Get scan results from storage."""
        return self.store.get_scan(scan_id) or self.last_scan_results.get(scan_id)
    
    def get_recent_scans(self, limit: int = 50) -> list:
        """Get recent scans."""
        return self.store.get_recent_scans(limit)

scan_manager = ScanManager()

class ScanRequest(BaseModel):
    url: str
    modules: List[str]

class AIReportRequest(BaseModel):
    scan_id: str
    report_type: str = "executive"  # executive, technical, risk, all
    language: str = "en"  # en, tr

@app.get("/")
async def get():
    with open("web/index.html", "r") as f:
        return HTMLResponse(content=f.read())

@app.get("/api/modules")
async def get_modules():
    # Mapping modules from engine
    modules = []
    for mod_id, mod_obj in scan_manager.engine.modules.items():
        modules.append({
            "id": mod_id,
            "name": mod_obj.name,
            "description": getattr(mod_obj, 'description', 'No description available')
        })
    return modules


# =============================================
# SCAN TEMPLATES ENDPOINTS
# =============================================

@app.get("/api/templates")
async def get_scan_templates(category: Optional[str] = None, tag: Optional[str] = None):
    """Get available scan templates/presets."""
    from src.core.scan_templates import get_template_manager
    
    manager = get_template_manager()
    
    if category:
        templates = manager.get_templates_by_category(category)
    elif tag:
        templates = manager.get_templates_by_tag(tag)
    else:
        templates = manager.get_all_templates()
    
    return {
        "templates": templates,
        "count": len(templates),
        "categories": manager.get_categories()
    }

@app.get("/api/templates/{template_id}")
async def get_template_details(template_id: str):
    """Get details of a specific scan template."""
    from src.core.scan_templates import get_template_manager
    
    manager = get_template_manager()
    template = manager.get_template_dict(template_id)
    
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    
    return template

@app.post("/api/scan/start/template/{template_id}")
async def start_scan_from_template(template_id: str, url: str, background_tasks: BackgroundTasks):
    """Start a scan using a predefined template."""
    from src.core.scan_templates import get_template_manager
    
    manager = get_template_manager()
    template = manager.get_template(template_id)
    
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    scan_id = str(len(scan_manager.active_scans) + 1)
    scan_manager.active_scans[scan_id] = {
        "url": url,
        "status": "starting",
        "results": [],
        "progress": 0,
        "template": template_id
    }
    
    background_tasks.add_task(run_scan_task, scan_id, url, template.modules)
    return {
        "scan_id": scan_id,
        "message": f"Scan started with template: {template.name}",
        "template": template_id,
        "modules": template.modules
    }

@app.post("/api/scan/start")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    url = request.url
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    scan_id = str(len(scan_manager.active_scans) + 1)
    scan_manager.active_scans[scan_id] = {
        "url": url,
        "status": "starting",
        "results": [],
        "progress": 0
    }
    
    background_tasks.add_task(run_scan_task, scan_id, url, request.modules)
    return {"scan_id": scan_id, "message": "Scan started"}

@app.get("/api/settings")
async def get_settings():
    return {
        "timeout": scan_manager.config.network.timeout,
        "rate_limit": scan_manager.config.network.rate_limit,
        "concurrent_requests": scan_manager.config.scanner.concurrent_requests,
        "waf_evasion": getattr(scan_manager.config.scanner, 'enable_waf_bypass', False),
        "ua_rotation": getattr(scan_manager.config.scanner, 'enable_ua_rotation', True),
        "ssl_verification": getattr(scan_manager.config.network, 'verify_ssl', True),
        "ai_enabled": bool(os.getenv("GOOGLE_AI_API_KEY"))
    }

@app.get("/api/external-tools")
async def get_external_tools_status():
    """Check availability of external security tools (nmap, nikto, gobuster, etc.)"""
    from src.utils.command_runner import ExternalCommandRunner
    runner = ExternalCommandRunner()
    
    tools = runner.get_available_tools()
    
    return {
        "tools": tools,
        "available_count": sum(1 for v in tools.values() if v),
        "total_count": len(tools)
    }

class SettingsUpdate(BaseModel):
    timeout: int
    rate_limit: int
    concurrent_requests: int
    waf_evasion: Optional[bool] = False
    ua_rotation: Optional[bool] = True
    ssl_verification: Optional[bool] = True

@app.post("/api/settings")
async def update_settings(settings: SettingsUpdate):
    scan_manager.config.network.timeout = settings.timeout
    scan_manager.config.network.rate_limit = settings.rate_limit
    scan_manager.config.scanner.concurrent_requests = settings.concurrent_requests
    
    if hasattr(scan_manager.config.scanner, 'enable_waf_bypass'):
        scan_manager.config.scanner.enable_waf_bypass = settings.waf_evasion
    if hasattr(scan_manager.config.scanner, 'enable_ua_rotation'):
        scan_manager.config.scanner.enable_ua_rotation = settings.ua_rotation
    if hasattr(scan_manager.config.network, 'verify_ssl'):
        scan_manager.config.network.verify_ssl = settings.ssl_verification
        
    # Persist the configuration
    scan_manager.config.save()
    
    # Re-initialize engine to apply changes
    scan_manager.engine = ScannerEngine(scan_manager.config)
    return {"message": "Settings updated and engine re-initialized"}

@app.get("/api/payloads")
async def get_payloads(category: Optional[str] = None):
    """Get attack payloads, optionally filtered by category"""
    from src.core.payload_manager import PayloadManager
    pm = PayloadManager()
    if category:
        return pm.get_payloads_by_category(category)
    return pm.payloads

@app.get("/api/payloads/{payload_id}/guide")
async def get_payload_guide(payload_id: str):
    """Get attack guide for a specific payload"""
    from src.core.payload_manager import PayloadManager
    pm = PayloadManager()
    guide = pm.get_attack_guide(payload_id)
    if not guide:
        raise HTTPException(status_code=404, detail="Payload not found")
    return guide


# =============================================
# SCAN HISTORY & RESULTS ENDPOINTS
# =============================================

@app.get("/api/scans/history")
async def get_scan_history(limit: int = 50):
    """Get recent scan history."""
    scans = scan_manager.get_recent_scans(limit)
    return {
        "scans": scans,
        "count": len(scans)
    }

@app.get("/api/scans/{scan_id}")
async def get_scan_details(scan_id: str):
    """Get details of a specific scan."""
    scan = scan_manager.get_scan_results(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan from history."""
    if scan_manager.store.delete_scan(scan_id):
        if scan_id in scan_manager.last_scan_results:
            del scan_manager.last_scan_results[scan_id]
        return {"message": "Scan deleted successfully"}
    raise HTTPException(status_code=404, detail="Scan not found")

# =============================================
# EXTERNAL TOOLS ENDPOINTS (Nmap, Nikto, etc.)
# =============================================

class NmapRequest(BaseModel):
    target: str
    profile: str = "quick"  # quick, standard, comprehensive, stealth, vuln

class GobusterRequest(BaseModel):
    target: str
    wordlist: Optional[str] = None
    extensions: str = "php,asp,aspx,jsp,html,js,txt"

class WordlistRequest(BaseModel):
    target: str
    min_length: int = 4
    max_length: int = 20

@app.post("/api/tools/nmap")
async def run_nmap_scan(request: NmapRequest, background_tasks: BackgroundTasks):
    """Run Nmap scan on target"""
    from src.utils.command_runner import ExternalCommandRunner
    runner = ExternalCommandRunner()
    
    if not runner.check_tool_available('nmap'):
        raise HTTPException(status_code=400, detail="Nmap is not installed on the system")
    
    scan_id = f"nmap_{len(scan_manager.active_scans) + 1}"
    scan_manager.active_scans[scan_id] = {"status": "starting", "tool": "nmap"}
    
    background_tasks.add_task(run_nmap_task, scan_id, request.target, request.profile)
    return {"scan_id": scan_id, "message": "Nmap scan started"}

async def run_nmap_task(scan_id: str, target: str, profile: str):
    """Background task for Nmap scan"""
    try:
        from src.modules.nmap_scanner import NmapScanner
        from src.core.config import Config
        from src.core.http_client import HTTPClient
        
        config = Config()
        http_client = HTTPClient(config.network)
        scanner = NmapScanner(config, http_client)
        
        result = await scanner.scan(target)
        
        await scan_manager.broadcast({
            "type": "tool_complete",
            "scan_id": scan_id,
            "tool": "nmap",
            "result": result
        })
    except Exception as e:
        await scan_manager.broadcast({
            "type": "tool_error",
            "scan_id": scan_id,
            "tool": "nmap",
            "error": str(e)
        })

@app.post("/api/tools/gobuster")
async def run_gobuster_scan(request: GobusterRequest, background_tasks: BackgroundTasks):
    """Run Gobuster directory scan"""
    from src.utils.command_runner import ExternalCommandRunner
    runner = ExternalCommandRunner()
    
    has_gobuster = runner.check_tool_available('gobuster')
    has_dirb = runner.check_tool_available('dirb')
    
    if not has_gobuster and not has_dirb:
        raise HTTPException(status_code=400, detail="Neither Gobuster nor Dirb is installed")
    
    scan_id = f"gobuster_{len(scan_manager.active_scans) + 1}"
    scan_manager.active_scans[scan_id] = {"status": "starting", "tool": "gobuster"}
    
    background_tasks.add_task(run_gobuster_task, scan_id, request.target)
    return {"scan_id": scan_id, "message": "Directory scan started"}

async def run_gobuster_task(scan_id: str, target: str):
    """Background task for Gobuster scan"""
    try:
        from src.modules.gobuster_scanner import GobusterScanner
        from src.core.config import Config
        from src.core.http_client import HTTPClient
        
        config = Config()
        http_client = HTTPClient(config.network)
        await http_client.start()
        
        scanner = GobusterScanner(config, http_client)
        result = await scanner.scan(target)
        
        await http_client.close()
        
        await scan_manager.broadcast({
            "type": "tool_complete",
            "scan_id": scan_id,
            "tool": "gobuster",
            "result": result
        })
    except Exception as e:
        await scan_manager.broadcast({
            "type": "tool_error",
            "scan_id": scan_id,
            "tool": "gobuster",
            "error": str(e)
        })

@app.post("/api/tools/nikto")
async def run_nikto_scan(request: NmapRequest, background_tasks: BackgroundTasks):
    """Run Nikto web server scan"""
    from src.utils.command_runner import ExternalCommandRunner
    runner = ExternalCommandRunner()
    
    if not runner.check_tool_available('nikto'):
        raise HTTPException(status_code=400, detail="Nikto is not installed")
    
    scan_id = f"nikto_{len(scan_manager.active_scans) + 1}"
    background_tasks.add_task(run_nikto_task, scan_id, request.target)
    return {"scan_id": scan_id, "message": "Nikto scan started"}

async def run_nikto_task(scan_id: str, target: str):
    """Background task for Nikto scan"""
    try:
        from src.modules.nikto_scanner import NiktoScanner
        from src.core.config import Config
        from src.core.http_client import HTTPClient
        
        config = Config()
        http_client = HTTPClient(config.network)
        await http_client.start()
        
        scanner = NiktoScanner(config, http_client)
        result = await scanner.scan(target)
        
        await http_client.close()
        
        await scan_manager.broadcast({
            "type": "tool_complete",
            "scan_id": scan_id,
            "tool": "nikto",
            "result": result
        })
    except Exception as e:
        await scan_manager.broadcast({
            "type": "tool_error",
            "scan_id": scan_id,
            "tool": "nikto",
            "error": str(e)
        })

@app.post("/api/tools/wordlist")
async def generate_wordlist(request: WordlistRequest, background_tasks: BackgroundTasks):
    """Generate custom wordlist from target"""
    scan_id = f"wordlist_{len(scan_manager.active_scans) + 1}"
    background_tasks.add_task(run_wordlist_task, scan_id, request.target)
    return {"scan_id": scan_id, "message": "Wordlist generation started"}

async def run_wordlist_task(scan_id: str, target: str):
    """Background task for wordlist generation"""
    try:
        from src.modules.wordlist_builder import WordlistBuilder
        from src.core.config import Config
        from src.core.http_client import HTTPClient
        
        config = Config()
        http_client = HTTPClient(config.network)
        await http_client.start()
        
        builder = WordlistBuilder(config, http_client)
        result = await builder.scan(target)
        
        await http_client.close()
        
        await scan_manager.broadcast({
            "type": "tool_complete",
            "scan_id": scan_id,
            "tool": "wordlist",
            "result": result
        })
    except Exception as e:
        await scan_manager.broadcast({
            "type": "tool_error",
            "scan_id": scan_id,
            "tool": "wordlist",
            "error": str(e)
        })

@app.get("/api/tools/wordlists")
async def list_generated_wordlists():
    """List generated wordlists"""
    from pathlib import Path
    wordlist_dir = Path("output/wordlists")
    
    if not wordlist_dir.exists():
        return {"wordlists": []}
    
    wordlists = []
    for f in wordlist_dir.glob("*.txt"):
        wordlists.append({
            "name": f.name,
            "path": str(f),
            "size": f.stat().st_size,
            "lines": sum(1 for _ in f.open())
        })
    
    return {"wordlists": wordlists}


# =============================================
# AI NARRATOR ENDPOINTS
# =============================================

@app.get("/api/ai/status")
async def get_ai_status():
    """Check if AI narrator is available"""
    api_key = os.getenv("GOOGLE_AI_API_KEY")
    return {
        "available": bool(api_key),
        "enabled": bool(api_key),
        "key_preview": f"{api_key[:4]}...{api_key[-4:]}" if api_key and len(api_key) > 8 else "INVALID",
        "provider": os.getenv("AI_PROVIDER", "gemini"),
        "model": os.getenv("AI_MODEL", "models/gemini-1.5-flash")
    }

@app.post("/api/ai/generate")
async def generate_ai_report(request: AIReportRequest, background_tasks: BackgroundTasks):
    """Generate AI-powered security report"""
    api_key = os.getenv("GOOGLE_AI_API_KEY")
    
    if not api_key:
        raise HTTPException(
            status_code=400, 
            detail="AI not configured. Set GOOGLE_AI_API_KEY in .env file"
        )
    
    # Try to get results by scan_id
    scan_results = scan_manager.last_scan_results.get(request.scan_id)
    
    # Fallback to absolute latest scan if id doesn't match and results exist
    if not scan_results and scan_manager.last_scan_results:
        # Get the most recently added scan result
        latest_id = list(scan_manager.last_scan_results.keys())[-1]
        scan_results = scan_manager.last_scan_results[latest_id]
        logger.info(f"Scan ID {request.scan_id} not found. Falling back to latest scan: {latest_id}")
    
    if not scan_results:
        raise HTTPException(status_code=404, detail="Scan results not found. Make sure a scan has completed.")
    
    # Generate report in background
    background_tasks.add_task(
        generate_ai_report_task, 
        request.scan_id, 
        scan_results, 
        request.report_type,
        request.language
    )
    
    return {"message": "AI report generation started", "scan_id": request.scan_id}

async def generate_ai_report_task(scan_id: str, scan_results: dict, report_type: str, language: str):
    """Background task to generate AI report"""
    try:
        from src.reporting.ai_narrator import AINarrator, NarratorConfig, AIProvider
        
        config = NarratorConfig(
            provider=AIProvider.GEMINI,
            api_key=os.getenv("GOOGLE_AI_API_KEY"),
            model=os.getenv("AI_MODEL", "models/gemini-2.0-flash"),
            language=language
        )
        
        narrator = AINarrator(config)
        await narrator.initialize()
        
        # Generate requested report type
        if report_type == "executive":
            report = await narrator.generate_executive_summary(scan_results)
            report_data = {"executive_summary": report}
        elif report_type == "technical":
            report = await narrator.generate_technical_report(scan_results)
            report_data = {"technical_report": report}
        elif report_type == "risk":
            report = await narrator.generate_risk_narrative(scan_results)
            report_data = {"risk_narrative": report}
        else:  # all
            report_data = await narrator.generate_full_report(scan_results)
        
        await scan_manager.broadcast({
            "type": "ai_report",
            "scan_id": scan_id,
            "report_type": report_type,
            "data": report_data,
            "status": "complete"
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        await scan_manager.broadcast({
            "type": "ai_report",
            "scan_id": scan_id,
            "status": "error",
            "message": str(e)
        })

@app.get("/api/poc/{scan_id}/{vuln_index}")
async def get_poc(scan_id: str, vuln_index: int):
    """Generate PoC for a specific vulnerability"""
    try:
        from src.reporting.poc_generator import PoCGenerator
        
        scan_results = scan_manager.last_scan_results.get(scan_id)
        if not scan_results:
            raise HTTPException(status_code=404, detail="Scan results not found")
        
        # Find vulnerability by index
        all_vulns = []
        for result in scan_results.get("results", []):
            for vuln in result.get("vulnerabilities", []):
                all_vulns.append(vuln)
        
        if vuln_index >= len(all_vulns):
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        
        vuln = all_vulns[vuln_index]
        poc = PoCGenerator()
        pocs = poc.generate_poc(vuln)
        
        return {
            "vulnerability": vuln.get("title", "Unknown"),
            "pocs": pocs
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/cvss/{vuln_type}")
async def get_cvss_info(vuln_type: str):
    """Get CVSS information for a vulnerability type"""
    try:
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
                "details": result.to_dict()
            }
        else:
            return {"vuln_type": vuln_type, "message": "No CVSS data available"}
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# =============================================
# SCAN TASK
# =============================================

async def run_scan_task(scan_id: str, url: str, modules: List[str]):
    try:
        def progress_callback(module_name, status, percentage):
            # This is called from various threads/loops, ensuring broadcast is safe
            pass 

        async def module_result_callback(r):
            vulns = []
            for v in r.vulnerabilities:
                vuln_dict = {
                    "title": v.get('title', 'Unknown Issue'),
                    "severity": v.get('severity', 'info'),
                    "description": v.get('description', ''),
                    "remediation": v.get('remediation', ''),
                    "evidence": v.get('evidence', {}),
                    "type": v.get('type', 'unknown'),
                    "cvss_score": v.get('cvss_score', 0),
                    "cvss_vector": v.get('cvss_vector', ''),
                    "cwe_id": v.get('cwe_id', '')
                }
                vulns.append(vuln_dict)
            
            await scan_manager.broadcast({
                "type": "module_result",
                "scan_id": scan_id,
                "module": r.module_name,
                "status": r.status,
                "vulnerabilities": vulns
            })

        results = await scan_manager.engine.scan_target(
            url, 
            modules, 
            progress_callback=lambda m, s, p: asyncio.create_task(
                scan_manager.broadcast({
                    "type": "progress",
                    "scan_id": scan_id,
                    "module": m,
                    "status": s,
                    "percentage": p
                })
            ),
            result_callback=module_result_callback
        )
        
        # Post-scan reporting
        await scan_manager.broadcast({
            "type": "progress",
            "scan_id": scan_id,
            "module": "ChainAnalyzer",
            "status": "Running post-scan correlation analysis...",
            "percentage": 95
        })
        
        # Prepare results for JSON serialization
        final_results = []
        for r in results:
            vulns = []
            for v in r.vulnerabilities:
                vuln_dict = {
                    "title": v.get('title', 'Unknown Issue'),
                    "severity": v.get('severity', 'info'),
                    "description": v.get('description', ''),
                    "remediation": v.get('remediation', ''),
                    "evidence": v.get('evidence', {}),
                    "type": v.get('type', 'unknown'),
                    "cvss_score": v.get('cvss_score', 0),
                    "cvss_vector": v.get('cvss_vector', ''),
                    "cwe_id": v.get('cwe_id', '')
                }
                vulns.append(vuln_dict)
            final_results.append({
                "module": r.module_name,
                "status": r.status,
                "vulnerabilities": vulns
            })
        
        # Store for AI analysis
        scan_manager.last_scan_results[scan_id] = {
            "url": url,
            "results": final_results,
            "timestamp": asyncio.get_event_loop().time()
        }

        await scan_manager.broadcast({
            "type": "complete",
            "scan_id": scan_id,
            "results": final_results,
            "summary": scan_manager.engine.get_scan_summary(),
            "ai_available": bool(os.getenv("GOOGLE_AI_API_KEY"))
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        await scan_manager.broadcast({
            "type": "error",
            "scan_id": scan_id,
            "message": str(e)
        })

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    scan_manager.connected_clients.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        scan_manager.connected_clients.remove(websocket)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

