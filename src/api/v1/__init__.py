"""
API v1 routes.
"""

import asyncio

import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.schemas import (
    LoginRequest,
    PaginationParams,
    RegisterRequest,
    ScanRequest,
    ScanResponse,
    StatsResponse,
    TokenResponse,
    UserResponse,
    VulnerabilityResponse,
)
from src.core.config import Config
from src.core.database import ScanJob, UserModel, Vulnerability, get_db, get_db_manager
from src.core.scanner_engine import ScannerEngine
from src.core.security import AuthenticationManager, Role, User
from src.core.security.secrets import get_secrets_manager
from src.plugins.manager import PluginManager

logger = structlog.get_logger()

# Plugin manager singleton
_plugin_manager: PluginManager = None


def get_plugin_manager() -> PluginManager:
    global _plugin_manager
    if _plugin_manager is None:
        _plugin_manager = PluginManager()
    return _plugin_manager


router = APIRouter()


# Auth routes
@router.post("/auth/login", response_model=TokenResponse, tags=["Authentication"])
async def login(credentials: LoginRequest, db: AsyncSession = Depends(get_db)):
    """Authenticate user and return JWT token."""
    # Get user from database
    result = await db.execute(select(UserModel).where(UserModel.username == credentials.username))
    user_model = result.scalar_one_or_none()

    if user_model is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # Verify password
    secrets = get_secrets_manager()
    secret_key = await secrets.get_secret_key()
    auth_manager = AuthenticationManager(secret_key)

    if not auth_manager.verify_password(credentials.password, user_model.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # Create user object
    user = User(
        id=user_model.id,
        username=user_model.username,
        email=user_model.email,
        role=Role(user_model.role),
        is_active=user_model.is_active,
        created_at=user_model.created_at,
    )

    # Generate token
    token = auth_manager.create_access_token(user)

    logger.info("User logged in", username=user.username)

    return token


@router.post("/auth/register", response_model=UserResponse, tags=["Authentication"])
async def register(user_data: RegisterRequest, db: AsyncSession = Depends(get_db)):
    """Register a new user."""
    # Check if user exists
    result = await db.execute(
        select(UserModel).where((UserModel.username == user_data.username) | (UserModel.email == user_data.email))
    )
    existing_user = result.scalar_one_or_none()

    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username or email already exists")

    # Hash password
    secrets = get_secrets_manager()
    secret_key = await secrets.get_secret_key()
    auth_manager = AuthenticationManager(secret_key)
    hashed_password = auth_manager.get_password_hash(user_data.password)

    # Create user
    new_user = UserModel(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_password,
        role=user_data.role,
    )

    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    logger.info("New user registered", username=new_user.username)

    return new_user


# Background scan execution
async def run_scan_background(scan_id: str, target_url: str, modules: list):
    """Execute vulnerability scan in background."""
    try:
        config = Config()
        engine = ScannerEngine(config)
        results = await engine.scan_target(target_url, modules)

        # Update scan job status in database
        db_manager = get_db_manager()
        async with db_manager.session() as session:
            result = await session.execute(select(ScanJob).where(ScanJob.id == scan_id))
            scan = result.scalar_one_or_none()
            if scan:
                scan.status = "completed"
                # Store vulnerabilities
                for r in results:
                    for vuln in r.vulnerabilities:
                        vuln_record = Vulnerability(
                            scan_job_id=scan_id,
                            title=vuln.get("title", "Unknown"),
                            description=vuln.get("description", ""),
                            severity=vuln.get("severity", "info"),
                            module=r.module_name,
                            evidence=vuln.get("evidence", {}),
                            cwe_id=vuln.get("cwe_id"),
                            remediation=vuln.get("remediation"),
                        )
                        session.add(vuln_record)
                await session.commit()

        logger.info("Background scan completed", scan_id=scan_id, vulns_found=len(results))

    except Exception as e:
        logger.error(f"Background scan failed: {e}", scan_id=scan_id)
        try:
            db_manager = get_db_manager()
            async with db_manager.session() as session:
                result = await session.execute(select(ScanJob).where(ScanJob.id == scan_id))
                scan = result.scalar_one_or_none()
                if scan:
                    scan.status = "failed"
                    scan.error_message = str(e)
                    await session.commit()
        except Exception as db_error:
            logger.error(f"Failed to update scan status: {db_error}")


# Scan routes
@router.post("/scans", response_model=ScanResponse, status_code=status.HTTP_201_CREATED, tags=["Scans"])
async def create_scan(
    scan_request: ScanRequest, request: Request, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)
):
    """Create a new vulnerability scan job."""
    user_id = request.state.user_id

    # Create scan job
    scan_job = ScanJob(
        target_url=str(scan_request.target_url),
        modules=scan_request.modules,
        user_id=user_id,
        status="running",
    )

    db.add(scan_job)
    await db.commit()
    await db.refresh(scan_job)

    # Trigger async scan execution in background
    asyncio.create_task(run_scan_background(str(scan_job.id), str(scan_request.target_url), scan_request.modules))

    logger.info("Scan created and started", scan_id=scan_job.id, target=scan_job.target_url)

    return scan_job


@router.get("/scans", response_model=list[ScanResponse], tags=["Scans"])
async def list_scans(request: Request, pagination: PaginationParams = Depends(), db: AsyncSession = Depends(get_db)):
    """List all scan jobs for the authenticated user."""
    user_id = request.state.user_id

    offset = (pagination.page - 1) * pagination.page_size

    result = await db.execute(
        select(ScanJob)
        .where(ScanJob.user_id == user_id)
        .offset(offset)
        .limit(pagination.page_size)
        .order_by(ScanJob.created_at.desc())
    )
    scans = result.scalars().all()

    return scans


@router.get("/scans/{scan_id}", response_model=ScanResponse, tags=["Scans"])
async def get_scan(scan_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Get a specific scan by ID."""
    user_id = request.state.user_id

    result = await db.execute(select(ScanJob).where((ScanJob.id == scan_id) & (ScanJob.user_id == user_id)))
    scan = result.scalar_one_or_none()

    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    return scan


@router.get("/scans/{scan_id}/vulnerabilities", response_model=list[VulnerabilityResponse], tags=["Scans"])
async def get_scan_vulnerabilities(
    scan_id: str, request: Request, severity: str = None, db: AsyncSession = Depends(get_db)
):
    """Get vulnerabilities for a specific scan."""
    user_id = request.state.user_id

    # Verify scan ownership
    scan_result = await db.execute(select(ScanJob).where((ScanJob.id == scan_id) & (ScanJob.user_id == user_id)))
    scan = scan_result.scalar_one_or_none()

    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    # Build query
    query = select(Vulnerability).where(Vulnerability.scan_job_id == scan_id)

    if severity:
        query = query.where(Vulnerability.severity == severity)

    result = await db.execute(query)
    vulnerabilities = result.scalars().all()

    return vulnerabilities


# Stats route
@router.get("/stats", response_model=StatsResponse, tags=["System"])
async def get_stats(request: Request, db: AsyncSession = Depends(get_db)):
    """Get system statistics."""
    # Total scans
    total_scans_result = await db.execute(select(func.count(ScanJob.id)))
    total_scans = total_scans_result.scalar()

    # Active scans
    active_scans_result = await db.execute(select(func.count(ScanJob.id)).where(ScanJob.status == "running"))
    active_scans = active_scans_result.scalar()

    # Total vulnerabilities
    total_vulns_result = await db.execute(select(func.count(Vulnerability.id)))
    total_vulnerabilities = total_vulns_result.scalar()

    # Users count
    users_count_result = await db.execute(select(func.count(UserModel.id)))
    users_count = users_count_result.scalar()

    # Get plugin count
    plugin_manager = get_plugin_manager()
    plugins_count = len(plugin_manager.plugins)

    return StatsResponse(
        total_scans=total_scans,
        active_scans=active_scans,
        total_vulnerabilities=total_vulnerabilities,
        users_count=users_count,
        plugins_loaded=plugins_count,
    )
