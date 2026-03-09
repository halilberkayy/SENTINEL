"""
Payload Builder and Mutation Engine API routes.
Provides payload encoding, mutation, template browsing, and effectiveness tracking.
"""

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.schemas.payloads import (
    EncoderInfo,
    MutationInfo,
    MutationResult,
    PayloadBuildRequest,
    PayloadBuildResponse,
    PayloadMutateRequest,
    PayloadMutateResponse,
    PayloadRecordResponse,
    PayloadTemplate,
    PayloadTrackRequest,
)
from src.core.database import PayloadRecord, get_db
from src.core.mutation_engine import MutationEngine
from src.core.payload_builder import PayloadBuilder
from src.core.payload_manager import PayloadManager

logger = structlog.get_logger()

router = APIRouter(prefix="/payloads", tags=["Payloads"])

# Singletons
_builder = PayloadBuilder()
_mutation_engine = MutationEngine()


@router.post("/build", response_model=PayloadBuildResponse)
async def build_payload(payload_data: PayloadBuildRequest, request: Request):
    """Build an encoded payload by applying a chain of encoders sequentially."""
    # Validate encoders
    valid_encoders = set(_builder.ENCODERS.keys())
    for encoder in payload_data.encoders:
        if encoder not in valid_encoders:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unknown encoder: {encoder}. Valid: {sorted(valid_encoders)}",
            )

    encoded = _builder.build(payload_data.payload, payload_data.encoders)

    return PayloadBuildResponse(
        original=payload_data.payload,
        encoded=encoded,
        chain=payload_data.encoders,
    )


@router.post("/mutate", response_model=PayloadMutateResponse)
async def mutate_payload(mutation_data: PayloadMutateRequest, request: Request):
    """Generate payload mutations using various evasion techniques."""
    # Validate mutations
    valid_mutations = set(_mutation_engine.MUTATIONS.keys())
    for mutation in mutation_data.mutations:
        if mutation not in valid_mutations:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unknown mutation: {mutation}. Valid: {sorted(valid_mutations)}",
            )

    results = _mutation_engine.mutate(
        mutation_data.payload, mutation_data.mutations, mutation_data.count
    )

    return PayloadMutateResponse(
        original=mutation_data.payload,
        mutations=[MutationResult(payload=r["payload"], applied=r["applied"]) for r in results],
    )


@router.get("/encoders", response_model=list[EncoderInfo])
async def list_encoders(request: Request):
    """List all available payload encoders."""
    return _builder.get_encoders()


@router.get("/mutations", response_model=list[MutationInfo])
async def list_mutations(request: Request):
    """List all available mutation techniques."""
    return _mutation_engine.get_mutations()


@router.get("/templates", response_model=list[PayloadTemplate])
async def list_templates(request: Request, category: str | None = None):
    """List payload templates from the attack library."""
    pm = PayloadManager()
    if category:
        payloads = pm.get_payloads_by_category(category)
    else:
        payloads = pm.payloads

    return [
        PayloadTemplate(
            id=p.get("id", ""),
            name=p.get("name", ""),
            category=p.get("category", ""),
            payload=p.get("payload", ""),
            risk=p.get("risk", ""),
            target_parameters=p.get("target_parameters", []),
            evasion_techniques=p.get("evasion_techniques", []),
        )
        for p in payloads
    ]


@router.post("/track", response_model=PayloadRecordResponse, status_code=status.HTTP_201_CREATED)
async def track_payload(
    track_data: PayloadTrackRequest, request: Request, db: AsyncSession = Depends(get_db)
):
    """Record payload effectiveness for analysis."""
    record = PayloadRecord(
        campaign_id=track_data.campaign_id,
        name=track_data.name or track_data.category,
        category=track_data.category,
        original_payload=track_data.payload,
        encoded_payload=track_data.encoded_payload,
        encoder_chain=track_data.encoder_chain,
        mutations_applied=track_data.mutations_applied,
        target_url=track_data.target_url,
        effectiveness=track_data.effectiveness,
        response_code=track_data.response_code,
        response_snippet=track_data.response_snippet,
        waf_bypassed=track_data.waf_bypassed,
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)

    logger.info("Payload effectiveness tracked", record_id=record.id, effectiveness=track_data.effectiveness.value)
    return record


@router.get("/effectiveness", response_model=list[PayloadRecordResponse])
async def get_effectiveness(
    request: Request,
    campaign_id: str | None = None,
    category: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """Query payload effectiveness records."""
    query = select(PayloadRecord)

    if campaign_id:
        query = query.where(PayloadRecord.campaign_id == campaign_id)
    if category:
        query = query.where(PayloadRecord.category == category)

    query = query.order_by(PayloadRecord.created_at.desc()).limit(100)
    result = await db.execute(query)
    return result.scalars().all()
