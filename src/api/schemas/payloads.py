"""
Pydantic schemas for Payload Builder API.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from src.core.database.models import PayloadEffectiveness


class PayloadBuildRequest(BaseModel):
    """Request body for building an encoded payload."""

    payload: str = Field(..., min_length=1, description="Original payload string")
    encoders: list[str] = Field(
        ...,
        min_length=1,
        description="Ordered list of encoders to apply: base64, hex, url_encode, double_url_encode, html_entities, unicode, utf7, random_case",
    )


class PayloadBuildResponse(BaseModel):
    """Response with original and encoded payload."""

    original: str
    encoded: str
    chain: list[str]


class PayloadMutateRequest(BaseModel):
    """Request body for generating payload mutations."""

    payload: str = Field(..., min_length=1, description="Original payload string")
    mutations: list[str] = Field(
        ...,
        min_length=1,
        description="Mutation techniques: random_case, url_encode, double_url_encode, space_to_comment, space_to_plus, null_byte_injection, between_operator, comment_garbage, concat_split, char_encoding, whitespace_variation, case_swap",
    )
    count: int = Field(default=10, ge=1, le=100, description="Number of mutations to generate")


class MutationResult(BaseModel):
    """Single mutation result."""

    payload: str
    applied: list[str]


class PayloadMutateResponse(BaseModel):
    """Response with list of payload mutations."""

    original: str
    mutations: list[MutationResult]


class EncoderInfo(BaseModel):
    """Encoder metadata."""

    name: str
    description: str


class MutationInfo(BaseModel):
    """Mutation technique metadata."""

    name: str
    description: str


class PayloadTemplate(BaseModel):
    """Payload template from the library."""

    id: str
    name: str
    category: str
    payload: str
    risk: str
    target_parameters: list[str] = []
    evasion_techniques: list[str] = []


class PayloadTrackRequest(BaseModel):
    """Request body for tracking payload effectiveness."""

    campaign_id: str | None = None
    name: str = Field(default="", max_length=200)
    category: str = Field(..., max_length=50)
    payload: str = Field(..., min_length=1)
    encoded_payload: str | None = None
    encoder_chain: list[str] = []
    mutations_applied: list[str] = []
    target_url: str | None = None
    effectiveness: PayloadEffectiveness
    response_code: int | None = None
    response_snippet: str | None = Field(default=None, max_length=500)
    waf_bypassed: bool = False


class PayloadRecordResponse(BaseModel):
    """Payload record response model."""

    id: str
    campaign_id: str | None = None
    name: str
    category: str
    original_payload: str
    encoded_payload: str | None = None
    encoder_chain: list[str]
    mutations_applied: list[str]
    target_url: str | None = None
    effectiveness: PayloadEffectiveness | None = None
    response_code: int | None = None
    waf_bypassed: bool
    created_at: datetime
    used_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)
