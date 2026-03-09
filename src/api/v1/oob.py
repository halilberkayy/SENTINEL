"""
OOB (Out-of-Band) Callback Listener API routes.
Manages listeners for blind vulnerability verification (SSRF, XXE, OAST).
"""

from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.schemas.oob import (
    OOBInteractionResponse,
    OOBListenerCreateRequest,
    OOBListenerResponse,
)
from src.core.database import Campaign, OOBInteraction, get_db
from src.core.oob_listener import get_oob_manager

logger = structlog.get_logger()

router = APIRouter(prefix="/oob", tags=["OOB Callbacks"])


@router.post("/listeners", response_model=OOBListenerResponse, status_code=status.HTTP_201_CREATED)
async def create_listener(
    listener_data: OOBListenerCreateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Create an OOB callback listener for a campaign."""
    # Verify campaign exists
    result = await db.execute(
        select(Campaign).where(Campaign.id == listener_data.campaign_id)
    )
    campaign = result.scalar_one_or_none()
    if campaign is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Campaign not found")

    # Validate listener types
    valid_types = {"http", "dns"}
    for t in listener_data.types:
        if t not in valid_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid listener type: {t}. Valid types: {valid_types}",
            )

    # Determine base URL from request
    base_url = str(request.base_url).rstrip("/")
    manager = get_oob_manager(base_url)

    listener = manager.create_listener(
        campaign_id=listener_data.campaign_id,
        types=listener_data.types,
    )

    return OOBListenerResponse(
        listener_id=listener["listener_id"],
        campaign_id=listener["campaign_id"],
        callback_url=listener["callback_url"],
        dns_subdomain=listener["dns_subdomain"],
        types=listener["types"],
        active=listener["active"],
        created_at=listener["created_at"],
    )


@router.get("/listeners", response_model=list[OOBListenerResponse])
async def list_listeners(
    request: Request,
    campaign_id: str | None = None,
):
    """List active OOB listeners."""
    manager = get_oob_manager()
    listeners = manager.list_listeners(campaign_id=campaign_id)

    return [
        OOBListenerResponse(
            listener_id=l["listener_id"],
            campaign_id=l["campaign_id"],
            callback_url=l["callback_url"],
            dns_subdomain=l["dns_subdomain"],
            types=l["types"],
            active=l["active"],
            created_at=l["created_at"],
        )
        for l in listeners
    ]


@router.delete("/listeners/{listener_id}", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_listener(listener_id: str, request: Request):
    """Deactivate an OOB listener."""
    manager = get_oob_manager()
    if not manager.deactivate_listener(listener_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listener not found")


@router.get("/interactions", response_model=list[OOBInteractionResponse])
async def list_interactions(
    request: Request,
    campaign_id: str | None = None,
    listener_id: str | None = None,
    interaction_type: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """List OOB interactions with optional filters."""
    query = select(OOBInteraction)

    if campaign_id:
        query = query.where(OOBInteraction.campaign_id == campaign_id)
    if listener_id:
        query = query.where(OOBInteraction.listener_id == listener_id)
    if interaction_type:
        query = query.where(OOBInteraction.interaction_type == interaction_type)

    query = query.order_by(OOBInteraction.received_at.desc()).limit(100)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/interactions/correlate/{scan_id}", response_model=list[OOBInteractionResponse])
async def correlate_interactions(
    scan_id: str, request: Request, db: AsyncSession = Depends(get_db)
):
    """Correlate OOB interactions with a specific scan job."""
    result = await db.execute(
        select(OOBInteraction)
        .where(OOBInteraction.scan_job_id == scan_id)
        .order_by(OOBInteraction.received_at.desc())
    )
    return result.scalars().all()


@router.post("/callback/{listener_id}")
async def receive_callback(
    listener_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    HTTP callback endpoint for OOB interactions.
    This endpoint receives callbacks from blind SSRF/XXE/OAST payloads.
    No authentication required (callbacks come from external targets).
    """
    manager = get_oob_manager()

    # Validate listener
    listener = manager.validate_callback(listener_id)
    if listener is None:
        # Return 200 OK even for invalid listeners to avoid information leakage
        return Response(status_code=200, content="OK")

    # Extract request information
    body = None
    try:
        body_bytes = await request.body()
        body = body_bytes.decode("utf-8", errors="replace")[:10000]  # Limit body size
    except Exception:
        pass

    headers = dict(request.headers)

    # Extract correlation ID from query params or path
    correlation_id = request.query_params.get("c") or request.query_params.get("correlation_id")

    # Get client IP
    source_ip = request.client.host if request.client else None

    # Store interaction
    interaction = OOBInteraction(
        campaign_id=listener["campaign_id"],
        listener_id=listener_id,
        interaction_type="http",
        source_ip=source_ip,
        source_port=request.client.port if request.client else None,
        raw_request=f"{request.method} {request.url.path}",
        headers=headers,
        body=body,
        correlation_id=correlation_id,
    )
    db.add(interaction)
    await db.commit()

    logger.info(
        "OOB callback received",
        listener_id=listener_id,
        source_ip=source_ip,
        correlation_id=correlation_id,
    )

    return Response(status_code=200, content="OK")


@router.get("/callback/{listener_id}")
async def receive_callback_get(
    listener_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """GET variant of the callback endpoint (some OOB payloads use GET)."""
    return await receive_callback(listener_id, request, db)
