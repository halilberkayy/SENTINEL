"""
Database models using SQLAlchemy 2.0+ async.
"""

import enum
from datetime import datetime
from uuid import uuid4

from sqlalchemy import JSON, Boolean, DateTime
from sqlalchemy import Enum as SQLEnum
from sqlalchemy import Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.sql import func


class Base(DeclarativeBase):
    """Base model class."""

    pass


class ScanStatus(str, enum.Enum):
    """Scan job status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, enum.Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class UserModel(Base):
    """User table."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), nullable=False, default="viewer", index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    api_key: Mapped[str | None] = mapped_column(String(255), unique=True, nullable=True, index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    scan_jobs: Mapped[list["ScanJob"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class ScanJob(Base):
    """Scan job table."""

    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)
    status: Mapped[ScanStatus] = mapped_column(SQLEnum(ScanStatus), default=ScanStatus.PENDING, index=True)
    modules: Mapped[list[str]] = mapped_column(JSON, nullable=False)

    # Ownership
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Results metadata
    total_vulnerabilities: Mapped[int] = mapped_column(Integer, default=0)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    user: Mapped["UserModel"] = relationship(back_populates="scan_jobs")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        back_populates="scan_job", cascade="all, delete-orphan"
    )


class Vulnerability(Base):
    """Vulnerability findings table."""

    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scan_job_id: Mapped[str] = mapped_column(ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True)

    # Vulnerability details
    title: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    severity: Mapped[Severity] = mapped_column(SQLEnum(Severity), nullable=False, index=True)

    # Scoring
    cvss_score: Mapped[float] = mapped_column(Float, nullable=True, index=True)
    cwe_id: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)

    # Evidence and remediation
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    references: Mapped[list[str]] = mapped_column(JSON, default=list)

    # Metadata
    module_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)

    # Relationships
    scan_job: Mapped["ScanJob"] = relationship(back_populates="vulnerabilities")


class AuditLog(Base):
    """Audit log for security events."""

    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(36), nullable=True)

    details: Mapped[dict] = mapped_column(JSON, default=dict)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(500), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)


class PluginMetadata(Base):
    """Plugin metadata table."""

    __tablename__ = "plugins"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(20), nullable=False)
    author: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    config: Mapped[dict] = mapped_column(JSON, default=dict)

    installed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


# ── Red Team Platform Models (v6.0.0) ──────────────────────────────────


class CampaignPhase(str, enum.Enum):
    """Red team campaign phases aligned with MITRE ATT&CK kill chain."""

    RECON = "recon"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    C2 = "c2"
    COMPLETED = "completed"


class CampaignStatus(str, enum.Enum):
    """Campaign lifecycle status."""

    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class TargetStatus(str, enum.Enum):
    """Campaign target scan status."""

    PENDING = "pending"
    SCANNING = "scanning"
    COMPLETED = "completed"
    SKIPPED = "skipped"


class MemberRole(str, enum.Enum):
    """Campaign team member role."""

    LEAD = "lead"
    OPERATOR = "operator"
    OBSERVER = "observer"


class FindingStatus(str, enum.Enum):
    """Finding triage status."""

    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    REMEDIATED = "remediated"
    ACCEPTED_RISK = "accepted_risk"


class PayloadEffectiveness(str, enum.Enum):
    """Payload test result classification."""

    SUCCESSFUL = "successful"
    PARTIAL = "partial"
    BLOCKED = "blocked"
    UNTESTED = "untested"


class Campaign(Base):
    """Red team campaign entity for multi-target operations."""

    __tablename__ = "campaigns"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    scope: Mapped[dict] = mapped_column(JSON, nullable=False)  # {"allowed_domains": [], "allowed_ips": [], "excluded_paths": []}
    objectives: Mapped[list] = mapped_column(JSON, default=list)
    phase: Mapped[CampaignPhase] = mapped_column(SQLEnum(CampaignPhase), default=CampaignPhase.RECON, index=True)
    status: Mapped[CampaignStatus] = mapped_column(SQLEnum(CampaignStatus), default=CampaignStatus.ACTIVE, index=True)
    mitre_coverage: Mapped[dict] = mapped_column(JSON, default=dict)  # {"technique_id": {"count": N, "findings": [...]}}

    # Schedule
    start_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    end_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Ownership
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    creator: Mapped["UserModel"] = relationship(foreign_keys=[created_by])
    targets: Mapped[list["CampaignTarget"]] = relationship(back_populates="campaign", cascade="all, delete-orphan")
    members: Mapped[list["CampaignMember"]] = relationship(back_populates="campaign", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="campaign", cascade="all, delete-orphan")
    oob_interactions: Mapped[list["OOBInteraction"]] = relationship(back_populates="campaign", cascade="all, delete-orphan")


class CampaignTarget(Base):
    """Target within a red team campaign."""

    __tablename__ = "campaign_targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True)
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(50), nullable=False, default="web")  # web, api, network, host
    status: Mapped[TargetStatus] = mapped_column(SQLEnum(TargetStatus), default=TargetStatus.PENDING, index=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Link to scan job when executed
    scan_job_id: Mapped[str | None] = mapped_column(ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True, index=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    campaign: Mapped["Campaign"] = relationship(back_populates="targets")
    scan_job: Mapped["ScanJob | None"] = relationship(foreign_keys=[scan_job_id])


class CampaignMember(Base):
    """Team member assignment within a campaign."""

    __tablename__ = "campaign_members"
    __table_args__ = (
        # Prevent duplicate membership
        {"sqlite_autoincrement": True},
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role: Mapped[MemberRole] = mapped_column(SQLEnum(MemberRole), default=MemberRole.OPERATOR)

    # Timestamps
    joined_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    campaign: Mapped["Campaign"] = relationship(back_populates="members")
    user: Mapped["UserModel"] = relationship(foreign_keys=[user_id])


class Finding(Base):
    """Enhanced finding with campaign linkage, notes, and status tracking."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True)
    campaign_target_id: Mapped[str | None] = mapped_column(
        ForeignKey("campaign_targets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    vulnerability_id: Mapped[str | None] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # Finding details
    title: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    severity: Mapped[Severity] = mapped_column(SQLEnum(Severity), nullable=False, index=True)
    status: Mapped[FindingStatus] = mapped_column(SQLEnum(FindingStatus), default=FindingStatus.OPEN, index=True)

    # Scoring
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cwe_id: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # Evidence and remediation
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    mitre_techniques: Mapped[list] = mapped_column(JSON, default=list)  # [{"id": "T1190", "name": "...", "tactic": "TA0001"}]
    notes: Mapped[list] = mapped_column(JSON, default=list)  # [{"user_id": "...", "text": "...", "created_at": "..."}]

    # Payload tracking
    payload_used: Mapped[str | None] = mapped_column(Text, nullable=True)
    oob_interaction_id: Mapped[str | None] = mapped_column(
        ForeignKey("oob_interactions.id", ondelete="SET NULL"), nullable=True
    )

    # Timestamps
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    campaign: Mapped["Campaign"] = relationship(back_populates="findings")
    campaign_target: Mapped["CampaignTarget | None"] = relationship(foreign_keys=[campaign_target_id])
    vulnerability: Mapped["Vulnerability | None"] = relationship(foreign_keys=[vulnerability_id])
    oob_interaction: Mapped["OOBInteraction | None"] = relationship(foreign_keys=[oob_interaction_id])


class OOBInteraction(Base):
    """Out-of-band callback interaction record."""

    __tablename__ = "oob_interactions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True)
    listener_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    interaction_type: Mapped[str] = mapped_column(String(20), nullable=False)  # http, dns, smtp

    # Source information
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Request data
    raw_request: Mapped[str | None] = mapped_column(Text, nullable=True)
    headers: Mapped[dict] = mapped_column(JSON, default=dict)
    body: Mapped[str | None] = mapped_column(Text, nullable=True)
    dns_query: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Correlation
    correlation_id: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    scan_job_id: Mapped[str | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # Timestamps
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)

    # Relationships
    campaign: Mapped["Campaign"] = relationship(back_populates="oob_interactions")
    scan_job: Mapped["ScanJob | None"] = relationship(foreign_keys=[scan_job_id])


class PayloadRecord(Base):
    """Payload effectiveness tracking record."""

    __tablename__ = "payload_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    campaign_id: Mapped[str | None] = mapped_column(
        ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=True, index=True
    )

    # Payload details
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str] = mapped_column(String(50), nullable=False, index=True)  # xss, sqli, ssrf, xxe, etc.
    original_payload: Mapped[str] = mapped_column(Text, nullable=False)
    encoded_payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    encoder_chain: Mapped[list] = mapped_column(JSON, default=list)  # ["base64", "url_encode", "random_case"]
    mutations_applied: Mapped[list] = mapped_column(JSON, default=list)  # ["space_to_comment", "null_byte"]

    # Target and result
    target_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    effectiveness: Mapped[PayloadEffectiveness | None] = mapped_column(
        SQLEnum(PayloadEffectiveness), nullable=True
    )
    response_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)  # First 500 chars
    waf_bypassed: Mapped[bool] = mapped_column(Boolean, default=False)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ThreatProfile(Base):
    """APT/threat actor profile with MITRE ATT&CK TTP mapping."""

    __tablename__ = "threat_profiles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False, index=True)
    aliases: Mapped[list] = mapped_column(JSON, default=list)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    country_origin: Mapped[str | None] = mapped_column(String(100), nullable=True)
    motivation: Mapped[str | None] = mapped_column(String(100), nullable=True)  # espionage, financial, hacktivism, destruction
    target_sectors: Mapped[list] = mapped_column(JSON, default=list)  # ["government", "defense", "finance"]
    active_since: Mapped[str | None] = mapped_column(String(10), nullable=True)  # Year string e.g. "2004"

    # MITRE ATT&CK mapping
    ttps: Mapped[dict] = mapped_column(JSON, nullable=False)  # {"tactics": {"TA0001": ["T1190", "T1133"]}, ...}
    tools: Mapped[list] = mapped_column(JSON, default=list)  # ["Mimikatz", "Cobalt Strike"]
    iocs: Mapped[dict] = mapped_column(JSON, default=dict)  # {"domains": [], "ips": [], "hashes": []}
    references: Mapped[list] = mapped_column(JSON, default=list)

    # Metadata
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
