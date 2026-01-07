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
    role: Mapped[str] = mapped_column(String(50), nullable=False, default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    api_key: Mapped[str | None] = mapped_column(String(255), unique=True, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
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
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
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
    scan_job_id: Mapped[str] = mapped_column(ForeignKey("scan_jobs.id"), nullable=False, index=True)

    # Vulnerability details
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    severity: Mapped[Severity] = mapped_column(SQLEnum(Severity), nullable=False, index=True)

    # Scoring
    cvss_score: Mapped[float] = mapped_column(Float, nullable=True)
    cwe_id: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # Evidence and remediation
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    references: Mapped[list[str]] = mapped_column(JSON, default=list)

    # Metadata
    module_name: Mapped[str] = mapped_column(String(100), nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

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
