"""Database package initialization."""

from .models import (
    AuditLog,
    Base,
    Campaign,
    CampaignMember,
    CampaignPhase,
    CampaignStatus,
    CampaignTarget,
    Finding,
    FindingStatus,
    MemberRole,
    OOBInteraction,
    PayloadEffectiveness,
    PayloadRecord,
    PluginMetadata,
    ScanJob,
    ScanStatus,
    Severity,
    TargetStatus,
    ThreatProfile,
    UserModel,
    Vulnerability,
)
from .session import DatabaseManager, get_db, get_db_manager, init_database

__all__ = [
    # Base
    "Base",
    # Original models
    "UserModel",
    "ScanJob",
    "Vulnerability",
    "AuditLog",
    "PluginMetadata",
    # Original enums
    "ScanStatus",
    "Severity",
    # Red Team models (v6.0.0)
    "Campaign",
    "CampaignTarget",
    "CampaignMember",
    "Finding",
    "OOBInteraction",
    "PayloadRecord",
    "ThreatProfile",
    # Red Team enums
    "CampaignPhase",
    "CampaignStatus",
    "TargetStatus",
    "MemberRole",
    "FindingStatus",
    "PayloadEffectiveness",
    # Session management
    "DatabaseManager",
    "init_database",
    "get_db_manager",
    "get_db",
]
