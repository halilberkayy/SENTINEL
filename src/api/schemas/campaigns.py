"""
Pydantic schemas for Campaign Management API.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from src.core.database.models import (
    CampaignPhase,
    CampaignStatus,
    FindingStatus,
    MemberRole,
    Severity,
    TargetStatus,
)


# ── Campaign schemas ────────────────────────────────────────────────


class CampaignScope(BaseModel):
    """Campaign scope definition for target validation."""

    allowed_domains: list[str] = Field(..., min_length=1, description="Domains authorized for testing")
    allowed_ips: list[str] = Field(default=[], description="IP addresses/ranges authorized for testing")
    excluded_paths: list[str] = Field(default=[], description="URL paths to exclude from testing")


class CampaignCreateRequest(BaseModel):
    """Request body for creating a campaign."""

    name: str = Field(..., min_length=1, max_length=200)
    description: str | None = None
    scope: CampaignScope
    objectives: list[str] = Field(default=[])
    start_date: datetime | None = None
    end_date: datetime | None = None


class CampaignUpdateRequest(BaseModel):
    """Request body for updating a campaign."""

    name: str | None = Field(default=None, max_length=200)
    description: str | None = None
    scope: CampaignScope | None = None
    objectives: list[str] | None = None
    status: CampaignStatus | None = None
    start_date: datetime | None = None
    end_date: datetime | None = None


class CampaignPhaseRequest(BaseModel):
    """Request body for advancing campaign phase."""

    phase: CampaignPhase


class CampaignResponse(BaseModel):
    """Campaign response model."""

    id: str
    name: str
    description: str | None = None
    scope: dict[str, Any]
    objectives: list[str]
    phase: CampaignPhase
    status: CampaignStatus
    mitre_coverage: dict[str, Any]
    start_date: datetime | None = None
    end_date: datetime | None = None
    created_by: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CampaignDetailResponse(CampaignResponse):
    """Campaign detail response with computed stats."""

    targets_count: int = 0
    members_count: int = 0
    findings_count: int = 0
    critical_findings: int = 0
    high_findings: int = 0


# ── Campaign Target schemas ─────────────────────────────────────────


class CampaignTargetCreateRequest(BaseModel):
    """Request body for adding a target to a campaign."""

    target_url: str = Field(..., min_length=1, max_length=2048)
    target_type: str = Field(default="web", pattern="^(web|api|network|host)$")
    notes: str | None = None


class CampaignTargetResponse(BaseModel):
    """Campaign target response model."""

    id: str
    campaign_id: str
    target_url: str
    target_type: str
    status: TargetStatus
    notes: str | None = None
    scan_job_id: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TargetScanRequest(BaseModel):
    """Request body for launching a scan against a campaign target."""

    modules: list[str] = Field(..., min_length=1, description="Scanner modules to run")


# ── Campaign Member schemas ─────────────────────────────────────────


class CampaignMemberCreateRequest(BaseModel):
    """Request body for adding a member to a campaign."""

    user_id: str
    role: MemberRole = MemberRole.OPERATOR


class CampaignMemberResponse(BaseModel):
    """Campaign member response model."""

    id: str
    campaign_id: str
    user_id: str
    role: MemberRole
    joined_at: datetime
    username: str | None = None  # Populated from user relationship

    model_config = ConfigDict(from_attributes=True)


# ── Finding schemas ─────────────────────────────────────────────────


class MITRETechnique(BaseModel):
    """MITRE ATT&CK technique reference."""

    id: str = Field(..., pattern=r"^T\d{4}(\.\d{3})?$")
    name: str
    tactic: str = Field(..., pattern=r"^TA\d{4}$")


class FindingCreateRequest(BaseModel):
    """Request body for creating a manual finding."""

    title: str = Field(..., min_length=1, max_length=500)
    description: str
    type: str = Field(..., min_length=1, max_length=100)
    severity: Severity
    evidence: dict[str, Any] = Field(default={})
    remediation: str | None = None
    mitre_techniques: list[MITRETechnique] = Field(default=[])
    payload_used: str | None = None
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cwe_id: str | None = None


class FindingUpdateRequest(BaseModel):
    """Request body for updating a finding."""

    status: FindingStatus | None = None
    severity: Severity | None = None
    remediation: str | None = None
    mitre_techniques: list[MITRETechnique] | None = None


class FindingNoteRequest(BaseModel):
    """Request body for adding a note to a finding."""

    text: str = Field(..., min_length=1, max_length=5000)


class FindingResponse(BaseModel):
    """Finding response model."""

    id: str
    campaign_id: str
    campaign_target_id: str | None = None
    vulnerability_id: str | None = None
    title: str
    description: str
    type: str
    severity: Severity
    status: FindingStatus
    cvss_score: float | None = None
    cwe_id: str | None = None
    evidence: dict[str, Any]
    remediation: str | None = None
    mitre_techniques: list[dict[str, str]]
    notes: list[dict[str, Any]]
    payload_used: str | None = None
    oob_interaction_id: str | None = None
    detected_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ── MITRE Coverage schemas ──────────────────────────────────────────


class MITRETechniqueDetail(BaseModel):
    """MITRE technique with finding count."""

    id: str
    name: str
    count: int = 0
    findings: list[str] = []  # Finding IDs


class MITRETacticDetail(BaseModel):
    """MITRE tactic with its techniques."""

    id: str
    name: str
    techniques: list[MITRETechniqueDetail] = []


class MITRECoverageResponse(BaseModel):
    """Campaign MITRE ATT&CK coverage matrix."""

    campaign_id: str
    total_techniques: int = 0
    tactics: list[MITRETacticDetail] = []
