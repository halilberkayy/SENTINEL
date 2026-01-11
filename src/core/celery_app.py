"""
Celery application configuration for distributed task processing.
Used for asynchronous scan tasks and background job processing.
"""

import os
from celery import Celery
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Redis URL for Celery broker and backend
REDIS_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/1")
RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/2")

# Create Celery app
app = Celery(
    "sentinel",
    broker=REDIS_URL,
    backend=RESULT_BACKEND,
    include=[
        "src.core.tasks",
    ]
)

# Celery configuration
app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour max per task
    task_soft_time_limit=3300,  # 55 minutes soft limit
    worker_prefetch_multiplier=1,
    worker_concurrency=4,
    result_expires=86400,  # Results expire after 1 day
    task_acks_late=True,
    task_reject_on_worker_lost=True,
)

# Task routing
app.conf.task_routes = {
    "src.core.tasks.run_scan_task": {"queue": "scans"},
    "src.core.tasks.generate_report_task": {"queue": "reports"},
}


@app.task(bind=True, max_retries=3)
def run_scan_async(self, url: str, modules: list, scan_id: str):
    """
    Asynchronous scan task.
    
    Args:
        url: Target URL to scan
        modules: List of module names to run
        scan_id: Unique scan identifier
    """
    import asyncio
    from src.core.config import Config
    from src.core.scanner_engine import ScannerEngine
    
    try:
        config = Config()
        engine = ScannerEngine(config)
        
        # Run the async scan
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            results = loop.run_until_complete(
                engine.scan_target(url, modules)
            )
            
            # Format results for storage
            formatted_results = []
            for r in results:
                formatted_results.append({
                    "module_name": r.module_name,
                    "status": r.status,
                    "details": r.details,
                    "vulnerabilities": r.vulnerabilities,
                    "duration": r.duration,
                    "risk_level": r.risk_level,
                })
            
            return {
                "scan_id": scan_id,
                "url": url,
                "status": "completed",
                "results": formatted_results,
                "summary": engine.get_scan_summary(),
            }
            
        finally:
            loop.close()
            
    except Exception as exc:
        # Retry on transient failures
        self.retry(exc=exc, countdown=60 * (self.request.retries + 1))


@app.task(bind=True)
def generate_report_async(self, scan_id: str, scan_results: dict, report_type: str = "all", language: str = "en"):
    """
    Asynchronous report generation task.
    
    Args:
        scan_id: Scan identifier
        scan_results: Scan results dictionary
        report_type: Type of report to generate
        language: Report language
    """
    import asyncio
    import os
    from src.reporting.ai_narrator import AINarrator, NarratorConfig, AIProvider
    
    api_key = os.getenv("GOOGLE_AI_API_KEY")
    if not api_key:
        return {"error": "AI not configured", "scan_id": scan_id}
    
    try:
        config = NarratorConfig(
            provider=AIProvider.GEMINI,
            api_key=api_key,
            language=language
        )
        
        narrator = AINarrator(config)
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            if report_type == "all":
                report = loop.run_until_complete(
                    narrator.generate_full_report(scan_results)
                )
            elif report_type == "executive":
                report = {
                    "executive_summary": loop.run_until_complete(
                        narrator.generate_executive_summary(scan_results)
                    )
                }
            elif report_type == "technical":
                report = {
                    "technical_report": loop.run_until_complete(
                        narrator.generate_technical_report(scan_results)
                    )
                }
            elif report_type == "risk":
                report = {
                    "risk_narrative": loop.run_until_complete(
                        narrator.generate_risk_narrative(scan_results)
                    )
                }
            else:
                report = {}
            
            return {
                "scan_id": scan_id,
                "report_type": report_type,
                "status": "complete",
                "data": report,
            }
            
        finally:
            loop.close()
            
    except Exception as e:
        return {
            "scan_id": scan_id,
            "status": "error",
            "error": str(e),
        }


# Health check task
@app.task
def health_check():
    """Simple health check task."""
    return {"status": "healthy", "worker": "active"}


if __name__ == "__main__":
    app.start()
