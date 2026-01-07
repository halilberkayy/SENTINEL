"""
Pydantic schemas for API request/response validation.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field, HttpUrl


# Enums
class ScanStatusEnum(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SeverityEnum(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Auth schemas
class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=100)
    password: str = Field(..., min_length=8)


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=8)
    role: str = Field(default="viewer")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


# User schemas
class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime
    last_login: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


# Scan schemas
class ScanRequest(BaseModel):
    target_url: HttpUrl = Field(..., description="Target URL to scan")
    modules: list[str] = Field(..., min_length=1, description="List of scanner modules to run")
    options: dict[str, Any] | None = Field(default=None, description="Additional scan options")


class ScanResponse(BaseModel):
    id: str
    target_url: str
    status: ScanStatusEnum
    modules: list[str]
    user_id: str
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    total_vulnerabilities: int = 0
    duration_seconds: float | None = None

    model_config = ConfigDict(from_attributes=True)


# Vulnerability schemas
class VulnerabilityResponse(BaseModel):
    id: str
    scan_job_id: str
    title: str
    description: str
    type: str
    severity: SeverityEnum
    cvss_score: float | None = None
    cwe_id: str | None = None
    evidence: dict[str, Any]
    remediation: str | None = None
    references: list[str] = []
    module_name: str
    detected_at: datetime

    model_config = ConfigDict(from_attributes=True)


# Pagination
class PaginationParams(BaseModel):
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)


class PaginatedResponse(BaseModel):
    items: list[Any]
    total: int
    page: int
    page_size: int
    total_pages: int


# Plugin schemas
class PluginResponse(BaseModel):
    name: str
    version: str
    author: str
    description: str
    capabilities: list[dict[str, Any]]
    loaded: bool


# Report schemas
class ReportRequest(BaseModel):
    scan_id: str
    format: str = Field(..., pattern="^(txt|json|html|pdf)$")
    include_evidence: bool = True


# System schemas
class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: str


class StatsResponse(BaseModel):
    total_scans: int
    active_scans: int
    total_vulnerabilities: int
    users_count: int
    plugins_loaded: int
