"""
Campaign Management API routes for Red Team operations.
Provides CRUD for campaigns, targets, members, and findings.
"""

from datetime import datetime, timezone
from urllib.parse import urlparse

import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.schemas.campaigns import (
    CampaignCreateRequest,
    CampaignDetailResponse,
    CampaignMemberCreateRequest,
    CampaignMemberResponse,
    CampaignPhaseRequest,
    CampaignResponse,
    CampaignTargetCreateRequest,
    CampaignTargetResponse,
    CampaignUpdateRequest,
    FindingCreateRequest,
    FindingNoteRequest,
    FindingResponse,
    FindingUpdateRequest,
    MITRECoverageResponse,
    MITRETacticDetail,
    MITRETechniqueDetail,
    TargetScanRequest,
)
from src.api.schemas import PaginationParams, ScanResponse
from src.core.database import (
    Campaign,
    CampaignMember,
    CampaignPhase,
    CampaignStatus,
    CampaignTarget,
    Finding,
    FindingStatus,
    MemberRole,
    ScanJob,
    Severity,
    TargetStatus,
    UserModel,
    Vulnerability,
    get_db,
)
from src.reporting.mitre_attack_mapper import TACTICS

logger = structlog.get_logger()

router = APIRouter(prefix="/campaigns", tags=["Campaigns"])


# ── Helpers ─────────────────────────────────────────────────────────


def _validate_target_in_scope(target_url: str, scope: dict) -> bool:
    """Validate that a target URL falls within the campaign scope."""
    try:
        parsed = urlparse(target_url)
        hostname = parsed.hostname or ""

        allowed_domains = scope.get("allowed_domains", [])
        allowed_ips = scope.get("allowed_ips", [])
        excluded_paths = scope.get("excluded_paths", [])

        # Check excluded paths
        for excluded in excluded_paths:
            if parsed.path.startswith(excluded):
                return False

        # Check allowed domains (supports wildcard subdomains)
        for domain in allowed_domains:
            if domain.startswith("*."):
                base = domain[2:]
                if hostname == base or hostname.endswith("." + base):
                    return True
            elif hostname == domain:
                return True

        # Check allowed IPs
        if hostname in allowed_ips:
            return True

        return False
    except Exception:
        return False


async def _get_campaign_or_404(
    campaign_id: str, db: AsyncSession, user_id: str | None = None
) -> Campaign:
    """Fetch campaign or raise 404."""
    result = await db.execute(select(Campaign).where(Campaign.id == campaign_id))
    campaign = result.scalar_one_or_none()
    if campaign is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Campaign not found")
    return campaign


async def _check_campaign_membership(
    campaign_id: str, user_id: str, db: AsyncSession, min_role: MemberRole = MemberRole.OBSERVER
) -> CampaignMember | None:
    """Check if user is a member of the campaign with sufficient role."""
    result = await db.execute(
        select(CampaignMember).where(
            (CampaignMember.campaign_id == campaign_id) & (CampaignMember.user_id == user_id)
        )
    )
    member = result.scalar_one_or_none()

    # Campaign creator always has full access
    campaign_result = await db.execute(
        select(Campaign.created_by).where(Campaign.id == campaign_id)
    )
    creator_id = campaign_result.scalar_one_or_none()
    if creator_id == user_id:
        return member  # Creator has implicit lead access

    if member is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this campaign")

    role_hierarchy = {MemberRole.OBSERVER: 0, MemberRole.OPERATOR: 1, MemberRole.LEAD: 2}
    if role_hierarchy.get(member.role, 0) < role_hierarchy.get(min_role, 0):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient campaign role")

    return member


# ── Campaign CRUD ───────────────────────────────────────────────────


@router.post("", response_model=CampaignResponse, status_code=status.HTTP_201_CREATED)
async def create_campaign(
    campaign_data: CampaignCreateRequest, request: Request, db: AsyncSession = Depends(get_db)
):
    """Create a new red team campaign with scope definition."""
    user_id = request.state.user_id

    campaign = Campaign(
        name=campaign_data.name,
        description=campaign_data.description,
        scope=campaign_data.scope.model_dump(),
        objectives=campaign_data.objectives,
        start_date=campaign_data.start_date,
        end_date=campaign_data.end_date,
        created_by=user_id,
    )
    db.add(campaign)

    # Auto-add creator as lead member
    member = CampaignMember(
        campaign_id=campaign.id,
        user_id=user_id,
        role=MemberRole.LEAD,
    )
    db.add(member)

    await db.commit()
    await db.refresh(campaign)

    logger.info("Campaign created", campaign_id=campaign.id, name=campaign.name)
    return campaign


@router.get("", response_model=list[CampaignResponse])
async def list_campaigns(
    request: Request,
    campaign_status: CampaignStatus | None = None,
    pagination: PaginationParams = Depends(),
    db: AsyncSession = Depends(get_db),
):
    """List campaigns accessible to the authenticated user."""
    user_id = request.state.user_id
    offset = (pagination.page - 1) * pagination.page_size

    # Show campaigns where user is creator or member
    query = (
        select(Campaign)
        .outerjoin(CampaignMember, CampaignMember.campaign_id == Campaign.id)
        .where((Campaign.created_by == user_id) | (CampaignMember.user_id == user_id))
        .distinct()
    )

    if campaign_status:
        query = query.where(Campaign.status == campaign_status)

    query = query.offset(offset).limit(pagination.page_size).order_by(Campaign.created_at.desc())
    result = await db.execute(query)
    campaigns = result.scalars().all()

    return campaigns


@router.get("/{campaign_id}", response_model=CampaignDetailResponse)
async def get_campaign(campaign_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Get campaign details with computed statistics."""
    user_id = request.state.user_id
    campaign = await _get_campaign_or_404(campaign_id, db, user_id)

    # Compute stats
    targets_count = (await db.execute(
        select(func.count(CampaignTarget.id)).where(CampaignTarget.campaign_id == campaign_id)
    )).scalar() or 0

    members_count = (await db.execute(
        select(func.count(CampaignMember.id)).where(CampaignMember.campaign_id == campaign_id)
    )).scalar() or 0

    findings_count = (await db.execute(
        select(func.count(Finding.id)).where(Finding.campaign_id == campaign_id)
    )).scalar() or 0

    critical_findings = (await db.execute(
        select(func.count(Finding.id)).where(
            (Finding.campaign_id == campaign_id) & (Finding.severity == Severity.CRITICAL)
        )
    )).scalar() or 0

    high_findings = (await db.execute(
        select(func.count(Finding.id)).where(
            (Finding.campaign_id == campaign_id) & (Finding.severity == Severity.HIGH)
        )
    )).scalar() or 0

    return CampaignDetailResponse(
        **{c.key: getattr(campaign, c.key) for c in Campaign.__table__.columns},
        targets_count=targets_count,
        members_count=members_count,
        findings_count=findings_count,
        critical_findings=critical_findings,
        high_findings=high_findings,
    )


@router.put("/{campaign_id}", response_model=CampaignResponse)
async def update_campaign(
    campaign_id: str,
    update_data: CampaignUpdateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Update campaign details. Requires lead role."""
    user_id = request.state.user_id
    campaign = await _get_campaign_or_404(campaign_id, db, user_id)
    await _check_campaign_membership(campaign_id, user_id, db, min_role=MemberRole.LEAD)

    update_dict = update_data.model_dump(exclude_unset=True)
    if "scope" in update_dict and update_dict["scope"] is not None:
        update_dict["scope"] = update_data.scope.model_dump()

    for key, value in update_dict.items():
        setattr(campaign, key, value)

    await db.commit()
    await db.refresh(campaign)

    logger.info("Campaign updated", campaign_id=campaign_id)
    return campaign


@router.delete("/{campaign_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_campaign(campaign_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Delete a campaign. Requires admin role or campaign creator."""
    user_id = request.state.user_id
    campaign = await _get_campaign_or_404(campaign_id, db, user_id)

    if campaign.created_by != user_id:
        # Check if user is admin (via request.state if available)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only campaign creator or admin can delete")

    await db.delete(campaign)
    await db.commit()

    logger.info("Campaign deleted", campaign_id=campaign_id)


@router.put("/{campaign_id}/phase", response_model=CampaignResponse)
async def advance_campaign_phase(
    campaign_id: str,
    phase_data: CampaignPhaseRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Advance campaign to a new phase. Requires lead role."""
    user_id = request.state.user_id
    campaign = await _get_campaign_or_404(campaign_id, db, user_id)
    await _check_campaign_membership(campaign_id, user_id, db, min_role=MemberRole.LEAD)

    campaign.phase = phase_data.phase

    if phase_data.phase == CampaignPhase.COMPLETED:
        campaign.status = CampaignStatus.COMPLETED

    await db.commit()
    await db.refresh(campaign)

    logger.info("Campaign phase advanced", campaign_id=campaign_id, phase=phase_data.phase.value)
    return campaign


# ── Campaign Targets ────────────────────────────────────────────────


@router.post("/{campaign_id}/targets", response_model=CampaignTargetResponse, status_code=status.HTTP_201_CREATED)
async def add_target(
    campaign_id: str,
    target_data: CampaignTargetCreateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Add a target to a campaign. Target must be within campaign scope."""
    user_id = request.state.user_id
    campaign = await _get_campaign_or_404(campaign_id, db, user_id)
    await _check_campaign_membership(campaign_id, user_id, db, min_role=MemberRole.OPERATOR)

    # Validate target against scope
    if not _validate_target_in_scope(target_data.target_url, campaign.scope):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Target URL is outside campaign scope. Allowed domains: {campaign.scope.get('allowed_domains', [])}",
        )

    target = CampaignTarget(
        campaign_id=campaign_id,
        target_url=target_data.target_url,
        target_type=target_data.target_type,
        notes=target_data.notes,
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)

    logger.info("Target added to campaign", campaign_id=campaign_id, target_url=target_data.target_url)
    return target


@router.get("/{campaign_id}/targets", response_model=list[CampaignTargetResponse])
async def list_targets(
    campaign_id: str,
    request: Request,
    target_status: TargetStatus | None = None,
    db: AsyncSession = Depends(get_db),
):
    """List all targets in a campaign."""
    await _get_campaign_or_404(campaign_id, db)

    query = select(CampaignTarget).where(CampaignTarget.campaign_id == campaign_id)
    if target_status:
        query = query.where(CampaignTarget.status == target_status)

    result = await db.execute(query.order_by(CampaignTarget.created_at))
    return result.scalars().all()


@router.delete("/{campaign_id}/targets/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_target(
    campaign_id: str, target_id: str, request: Request, db: AsyncSession = Depends(get_db)
):
    """Remove a target from a campaign."""
    user_id = request.state.user_id
    await _check_campaign_membership(campaign_id, user_id, db, min_role=MemberRole.OPERATOR)

    result = await db.execute(
        select(CampaignTarget).where(
            (CampaignTarget.id == target_id) & (CampaignTarget.campaign_id == campaign_id)
        )
    )
    target = result.scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")

    await db.delete(target)
    await db.commit()


@router.post("/{campaign_id}/targets/{target_id}/scan", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def scan_target(
    campaign_id: str,
    target_id: str,
    scan_data: TargetScanRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Launch a scan against a campaign target. Target must be in scope."""
    user_id = request.state.user_id
    campaign = await _get_campaign_or_404(campaign_id, db, user_id)
    await _check_campaign_membership(campaign_id, user_id, db, min_role=MemberRole.OPERATOR)

    # Get target
    result = await db.execute(
        select(CampaignTarget).where(
            (CampaignTarget.id == target_id) & (CampaignTarget.campaign_id == campaign_id)
        )
    )
    target = result.scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")

    # Re-validate scope (defense in depth)
    if not _validate_target_in_scope(target.target_url, campaign.scope):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Target is outside campaign scope")

    # Create scan job linked to campaign target
    scan_job = ScanJob(
        target_url=target.target_url,
        modules=scan_data.modules,
        user_id=user_id,
        status="running",
    )
    db.add(scan_job)
    await db.commit()
    await db.refresh(scan_job)

    # Link target to scan job
    target.scan_job_id = scan_job.id
    target.status = TargetStatus.SCANNING
    await db.commit()

    # Import and run scan in background (reuses existing scan infrastructure)
    from src.api.v1 import run_scan_background
    background_tasks.add_task(run_scan_background, str(scan_job.id), target.target_url, scan_data.modules)

    logger.info(
        "Campaign scan launched",
        campaign_id=campaign_id,
        target_id=target_id,
        scan_id=scan_job.id,
    )
    return scan_job


# ── Campaign Members ────────────────────────────────────────────────


@router.post("/{campaign_id}/members", response_model=CampaignMemberResponse, status_code=status.HTTP_201_CREATED)
async def add_member(
    campaign_id: str,
    member_data: CampaignMemberCreateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Add a team member to a campaign. Requires lead role."""
    user_id = request.state.user_id
    await _get_campaign_or_404(campaign_id, db)
    await _check_campaign_membership(campaign_id, user_id, db, min_role=MemberRole.LEAD)

    # Verify user exists
    user_result = await db.execute(select(UserModel).where(UserModel.id == member_data.user_id))
    target_user = user_result.scalar_one_or_none()
    if target_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Check for duplicate membership
    existing = await db.execute(
        select(CampaignMember).where(
            (CampaignMember.campaign_id == campaign_id) & (CampaignMember.user_id == member_data.user_id)
        )
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User is already a member")

    member = CampaignMember(
        campaign_id=campaign_id,
        user_id=member_data.user_id,
        role=member_data.role,
    )
    db.add(member)
    await db.commit()
    await db.refresh(member)

    logger.info("Member added to campaign", campaign_id=campaign_id, user_id=member_data.user_id)
    return CampaignMemberResponse(
        id=member.id,
        campaign_id=member.campaign_id,
        user_id=member.user_id,
        role=member.role,
        joined_at=member.joined_at,
        username=target_user.username,
    )


@router.get("/{campaign_id}/members", response_model=list[CampaignMemberResponse])
async def list_members(campaign_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    """List all members of a campaign."""
    await _get_campaign_or_404(campaign_id, db)

    result = await db.execute(
        select(CampaignMember, UserModel.username)
        .join(UserModel, CampaignMember.user_id == UserModel.id)
        .where(CampaignMember.campaign_id == campaign_id)
    )
    rows = result.all()

    return [
        CampaignMemberResponse(
            id=member.id,
            campaign_id=member.campaign_id,
            user_id=member.user_id,
            role=member.role,
            joined_at=member.joined_at,
            username=username,
        )
        for member, username in rows
    ]


@router.delete("/{campaign_id}/members/{member_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    campaign_id: str, member_id: str, request: Request, db: AsyncSession = Depends(get_db)
):
    """Remove a member from a campaign. Requires lead role."""
    user_id = request.state.user_id
    await _check_campaign_membership(campaign_id, user_id, db, min_role=MemberRole.LEAD)

    result = await db.execute(
        select(CampaignMember).where(
            (CampaignMember.id == member_id) & (CampaignMember.campaign_id == campaign_id)
        )
    )
    member = result.scalar_one_or_none()
    if member is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found")

    await db.delete(member)
    await db.commit()


# ── Findings ────────────────────────────────────────────────────────


@router.get("/{campaign_id}/findings", response_model=list[FindingResponse])
async def list_findings(
    campaign_id: str,
    request: Request,
    severity: Severity | None = None,
    finding_status: FindingStatus | None = None,
    finding_type: str | None = None,
    pagination: PaginationParams = Depends(),
    db: AsyncSession = Depends(get_db),
):
    """List all findings in a campaign with optional filters."""
    await _get_campaign_or_404(campaign_id, db)

    offset = (pagination.page - 1) * pagination.page_size
    query = select(Finding).where(Finding.campaign_id == campaign_id)

    if severity:
        query = query.where(Finding.severity == severity)
    if finding_status:
        query = query.where(Finding.status == finding_status)
    if finding_type:
        query = query.where(Finding.type == finding_type)

    query = query.offset(offset).limit(pagination.page_size).order_by(Finding.detected_at.desc())
    result = await db.execute(query)
    return result.scalars().all()


@router.post("/{campaign_id}/findings", response_model=FindingResponse, status_code=status.HTTP_201_CREATED)
async def create_finding(
    campaign_id: str,
    finding_data: FindingCreateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Create a manual finding in a campaign. Requires operator role."""
    user_id = request.state.user_id
    await _get_campaign_or_404(campaign_id, db)
    await _check_campaign_membership(campaign_id, user_id, db, min_role=MemberRole.OPERATOR)

    finding = Finding(
        campaign_id=campaign_id,
        title=finding_data.title,
        description=finding_data.description,
        type=finding_data.type,
        severity=finding_data.severity,
        evidence=finding_data.evidence,
        remediation=finding_data.remediation,
        mitre_techniques=[t.model_dump() for t in finding_data.mitre_techniques],
        payload_used=finding_data.payload_used,
        cvss_score=finding_data.cvss_score,
        cwe_id=finding_data.cwe_id,
    )
    db.add(finding)
    await db.commit()
    await db.refresh(finding)

    logger.info("Finding created", campaign_id=campaign_id, finding_id=finding.id)
    return finding


@router.put("/{campaign_id}/findings/{finding_id}", response_model=FindingResponse)
async def update_finding(
    campaign_id: str,
    finding_id: str,
    update_data: FindingUpdateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Update a finding's status, severity, or remediation."""
    user_id = request.state.user_id
    await _check_campaign_membership(campaign_id, user_id, db, min_role=MemberRole.OPERATOR)

    result = await db.execute(
        select(Finding).where((Finding.id == finding_id) & (Finding.campaign_id == campaign_id))
    )
    finding = result.scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    update_dict = update_data.model_dump(exclude_unset=True)
    if "mitre_techniques" in update_dict and update_dict["mitre_techniques"] is not None:
        update_dict["mitre_techniques"] = [t.model_dump() for t in update_data.mitre_techniques]

    for key, value in update_dict.items():
        setattr(finding, key, value)

    await db.commit()
    await db.refresh(finding)

    return finding


@router.post("/{campaign_id}/findings/{finding_id}/notes", response_model=FindingResponse)
async def add_finding_note(
    campaign_id: str,
    finding_id: str,
    note_data: FindingNoteRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Add a note to a finding."""
    user_id = request.state.user_id

    result = await db.execute(
        select(Finding).where((Finding.id == finding_id) & (Finding.campaign_id == campaign_id))
    )
    finding = result.scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    note = {
        "user_id": user_id,
        "text": note_data.text,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    current_notes = list(finding.notes) if finding.notes else []
    current_notes.append(note)
    finding.notes = current_notes

    await db.commit()
    await db.refresh(finding)

    return finding


# ── MITRE Coverage ──────────────────────────────────────────────────


@router.get("/{campaign_id}/mitre", response_model=MITRECoverageResponse)
async def get_mitre_coverage(campaign_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Get MITRE ATT&CK coverage matrix for a campaign."""
    await _get_campaign_or_404(campaign_id, db)

    # Get all findings with MITRE techniques
    result = await db.execute(
        select(Finding).where(Finding.campaign_id == campaign_id)
    )
    findings = result.scalars().all()

    # Build coverage map
    tactic_map: dict[str, dict[str, list[str]]] = {}
    for finding in findings:
        for technique in (finding.mitre_techniques or []):
            tactic_id = technique.get("tactic", "")
            technique_id = technique.get("id", "")
            technique_name = technique.get("name", "")

            if tactic_id not in tactic_map:
                tactic_map[tactic_id] = {}
            if technique_id not in tactic_map[tactic_id]:
                tactic_map[tactic_id][technique_id] = {"name": technique_name, "findings": []}
            tactic_map[tactic_id][technique_id]["findings"].append(finding.id)

    # Format response
    tactics = []
    total_techniques = 0
    for tactic_id, tactic_info in TACTICS.items():
        techniques = []
        if tactic_id in tactic_map:
            for tech_id, tech_data in tactic_map[tactic_id].items():
                techniques.append(MITRETechniqueDetail(
                    id=tech_id,
                    name=tech_data["name"],
                    count=len(tech_data["findings"]),
                    findings=tech_data["findings"],
                ))
                total_techniques += 1

        tactics.append(MITRETacticDetail(
            id=tactic_id,
            name=tactic_info["name"],
            techniques=techniques,
        ))

    return MITRECoverageResponse(
        campaign_id=campaign_id,
        total_techniques=total_techniques,
        tactics=tactics,
    )
