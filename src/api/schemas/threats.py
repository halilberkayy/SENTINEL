"""
Pydantic schemas for Threat Intelligence API.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ThreatProfileCreateRequest(BaseModel):
    """Request body for creating a custom threat profile."""

    name: str = Field(..., min_length=1, max_length=200)
    aliases: list[str] = []
    description: str
    country_origin: str | None = None
    motivation: str | None = Field(default=None, pattern="^(espionage|financial|hacktivism|destruction|unknown)$")
    target_sectors: list[str] = []
    active_since: str | None = Field(default=None, max_length=10)
    ttps: dict[str, Any] = Field(..., description="MITRE ATT&CK TTPs: {'tactics': {'TA0001': ['T1190', ...]}}")
    tools: list[str] = []
    iocs: dict[str, Any] = Field(default={})
    references: list[str] = []


class ThreatProfileUpdateRequest(BaseModel):
    """Request body for updating a threat profile."""

    name: str | None = Field(default=None, max_length=200)
    aliases: list[str] | None = None
    description: str | None = None
    country_origin: str | None = None
    motivation: str | None = None
    target_sectors: list[str] | None = None
    ttps: dict[str, Any] | None = None
    tools: list[str] | None = None
    iocs: dict[str, Any] | None = None
    references: list[str] | None = None


class ThreatProfileResponse(BaseModel):
    """Threat profile response model."""

    id: str
    name: str
    aliases: list[str]
    description: str
    country_origin: str | None = None
    motivation: str | None = None
    target_sectors: list[str]
    active_since: str | None = None
    is_builtin: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ThreatProfileDetailResponse(ThreatProfileResponse):
    """Threat profile detail with full TTPs."""

    ttps: dict[str, Any]
    tools: list[str]
    iocs: dict[str, Any]
    references: list[str]


class ThreatMatchRequest(BaseModel):
    """Request body for matching findings against threat actor TTPs."""

    campaign_id: str | None = None
    finding_types: list[str] | None = None  # Alternative: provide finding types directly


class ThreatMatchResult(BaseModel):
    """Single threat actor match result."""

    profile_id: str
    profile_name: str
    coverage_pct: float = Field(ge=0.0, le=100.0)
    matched_techniques: list[str]
    total_techniques: int


class ThreatMatchResponse(BaseModel):
    """Threat matching response."""

    matches: list[ThreatMatchResult]


class AttackPathStep(BaseModel):
    """Single step in an attack path."""

    finding_id: str | None = None
    title: str
    type: str
    severity: str
    mitre_technique: str | None = None


class AttackPath(BaseModel):
    """Attack path with risk scoring."""

    chain_title: str
    risk_score: float = Field(ge=0.0, le=100.0)
    steps: list[AttackPathStep]
    mitre_chain: list[str] = []
    description: str


class AttackPathResponse(BaseModel):
    """Attack path analysis response."""

    campaign_id: str
    paths: list[AttackPath]
    total_paths: int = 0


class MITREMatrixTechnique(BaseModel):
    """Technique in the MITRE matrix."""

    id: str
    name: str
    count: int = 0
    findings: list[str] = []


class MITREMatrixTactic(BaseModel):
    """Tactic in the MITRE matrix."""

    id: str
    name: str
    techniques: list[MITREMatrixTechnique] = []


class MITREMatrixResponse(BaseModel):
    """Full MITRE ATT&CK matrix for heatmap visualization."""

    campaign_id: str | None = None
    tactics: list[MITREMatrixTactic] = []
    total_techniques_covered: int = 0
