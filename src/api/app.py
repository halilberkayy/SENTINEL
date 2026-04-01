"""
Enterprise FastAPI application with full feature set.
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import make_asgi_app

from src.api.middleware.auth import AuthMiddleware
from src.api.middleware.rate_limit import RateLimitMiddleware
from src.api.v1 import router as api_v1_router
from src.core.cache import init_cache
from src.core.database import get_db_manager, init_database
from src.core.security import SecurityHeaders
from src.core.security.secrets import get_secrets_manager

# Structured logging
logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """Application lifespan management."""
    # Startup
    logger.info("Starting Enterprise Scanner API...")

    # Initialize secrets
    secrets = get_secrets_manager()
    database_url = await secrets.get_database_url()
    redis_url = await secrets.get_redis_url()

    # Initialize database
    await init_database(database_url)
    logger.info("Database initialized")

    # Initialize cache
    await init_cache(redis_url)
    logger.info("Cache initialized")

    yield

    # Shutdown
    logger.info("Shutting down Enterprise Scanner API...")
    db_manager = get_db_manager()
    await db_manager.close()


# Create FastAPI app
app = FastAPI(
    title="SENTINEL Red Team Platform API",
    description="Red team platform with scanning, campaign management, and MITRE ATT&CK coverage",
    version="6.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# CORS middleware - Secure configuration
# SECURITY: allow_origins=["*"] with allow_credentials=True is a browser security violation.
# Browsers will reject CORS responses with Access-Control-Allow-Origin: * when credentials are included.
# Production deployments MUST set CORS_ALLOWED_ORIGINS to specific origins.
import os

_cors_env = os.getenv("CORS_ALLOWED_ORIGINS", "").strip()
_cors_origins_raw = [o.strip() for o in _cors_env.split(",") if o.strip()] if _cors_env else []
_is_wildcard = _cors_origins_raw == ["*"] or not _cors_origins_raw

if _is_wildcard:
    # Wildcard mode: no credentials allowed (safe default for development)
    logger.warning(
        "CORS configured with wildcard origins. Set CORS_ALLOWED_ORIGINS for production.",
        hint="Example: CORS_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Requested-With", "Accept"],
    )
else:
    # Explicit origins: credentials are safe to allow
    logger.info("CORS configured with explicit origins", origins=_cors_origins_raw)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins_raw,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Requested-With", "Accept"],
    )

# Gzip compression
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Rate limiting
app.add_middleware(RateLimitMiddleware)

# Authentication
app.add_middleware(AuthMiddleware)


# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    headers = SecurityHeaders.get_security_headers()
    for key, value in headers.items():
        response.headers[key] = value
    return response


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception", exc_info=exc, request_path=request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal server error",
            "message": "An unexpected error occurred. Please contact support.",
        },
    )

# Health check endpoint
@app.get("/health", tags=["System"])
async def health_check():
    """Health check endpoint for load balancers."""
    return {
        "status": "healthy",
        "version": "6.0.0",
        "timestamp": structlog.processors.TimeStamper()(None, None, None)["timestamp"],
    }


# Detailed health check with component status
@app.get("/health/detailed", tags=["System"])
async def detailed_health_check():
    """Detailed health check with component status."""
    components = {
        "api": {"status": "healthy", "version": "6.0.0"},
        "database": {"status": "unknown"},
        "cache": {"status": "unknown"},
    }
    
    overall_healthy = True
    
    # Check database
    try:
        db_manager = get_db_manager()
        async with db_manager.session() as session:
            from sqlalchemy import text
            await session.execute(text("SELECT 1"))
        components["database"]["status"] = "healthy"
    except Exception as e:
        components["database"]["status"] = "unhealthy"
        components["database"]["error"] = str(e)
        overall_healthy = False
    
    # Check Redis cache
    try:
        from src.core.cache import get_cache_manager
        cache = get_cache_manager()
        if await cache.ping():
            components["cache"]["status"] = "healthy"
        else:
            components["cache"]["status"] = "degraded"
    except Exception as e:
        components["cache"]["status"] = "unavailable"
        components["cache"]["error"] = str(e)
        # Cache is optional, don't fail health check
    
    return {
        "status": "healthy" if overall_healthy else "degraded",
        "version": "6.0.0",
        "components": components,
        "timestamp": structlog.processors.TimeStamper()(None, None, None)["timestamp"],
    }


# Readiness check
@app.get("/ready", tags=["System"])
async def readiness_check():
    """Readiness check for orchestrators."""
    try:
        db_manager = get_db_manager()
        # Simple DB check
        async with db_manager.session() as session:
            from sqlalchemy import text
            await session.execute(text("SELECT 1"))

        return {"status": "ready"}
    except Exception as e:
        logger.error("Readiness check failed", exc_info=e)
        raise HTTPException(status_code=503, detail="Service not ready")


# Prometheus metrics endpoint
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

# API v1 routes
app.include_router(api_v1_router, prefix="/api/v1")


# Root endpoint
@app.get("/", tags=["Root"])
async def root():
    """API root endpoint."""
    return {
        "name": "SENTINEL API",
        "version": "6.0.0",
        "docs": "/api/docs",
        "health": "/health",
        "metrics": "/metrics",
    }


def start_server():
    """Start the API server (for poetry script)."""
    import uvicorn

    import os

    uvicorn.run(
        "src.api.app:app",
        host="0.0.0.0",
        port=8000,
        reload=os.getenv("ENVIRONMENT") != "production",
        log_level="info",
    )


if __name__ == "__main__":
    start_server()
