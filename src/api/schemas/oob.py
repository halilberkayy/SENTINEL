"""
Pydantic schemas for OOB (Out-of-Band) Callback Listener API.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class OOBListenerCreateRequest(BaseModel):
    """Request body for creating an OOB listener."""

    campaign_id: str = Field(..., description="Campaign to associate the listener with")
    types: list[str] = Field(
        default=["http"],
        description="Listener types: http, dns",
    )


class OOBListenerResponse(BaseModel):
    """OOB listener response with callback URLs."""

    listener_id: str
    campaign_id: str
    callback_url: str
    dns_subdomain: str | None = None
    types: list[str]
    active: bool = True
    created_at: datetime


class OOBInteractionResponse(BaseModel):
    """OOB interaction record response."""

    id: str
    campaign_id: str
    listener_id: str
    interaction_type: str
    source_ip: str | None = None
    source_port: int | None = None
    raw_request: str | None = None
    headers: dict[str, Any]
    body: str | None = None
    dns_query: str | None = None
    correlation_id: str | None = None
    scan_job_id: str | None = None
    received_at: datetime

    model_config = ConfigDict(from_attributes=True)
