"""
Threat Intelligence and Attack Path API routes.
Provides threat actor profiles, TTP matching, and attack path analysis.
"""

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.schemas.threats import (
    AttackPath,
    AttackPathResponse,
    AttackPathStep,
    MITREMatrixResponse,
    MITREMatrixTactic,
    MITREMatrixTechnique,
    ThreatMatchRequest,
    ThreatMatchResponse,
    ThreatMatchResult,
    ThreatProfileCreateRequest,
    ThreatProfileDetailResponse,
    ThreatProfileResponse,
    ThreatProfileUpdateRequest,
)
from src.core.database import (
    Campaign,
    Finding,
    ThreatProfile,
    get_db,
)
from src.core.threat_profiles import (
    BUILTIN_PROFILES,
    VULN_TYPE_TO_TECHNIQUES,
    ThreatMatcher,
)
from src.reporting.mitre_attack_mapper import TACTICS, VULN_TO_TECHNIQUE

logger = structlog.get_logger()

router = APIRouter(prefix="/threats", tags=["Threat Intelligence"])

_matcher = ThreatMatcher()


@router.get("/profiles", response_model=list[ThreatProfileResponse])
async def list_profiles(
    request: Request,
    sector: str | None = None,
    motivation: str | None = None,
    search: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """List threat actor profiles (built-in and custom)."""
    # Query database for custom profiles
    query = select(ThreatProfile)
    if motivation:
        query = query.where(ThreatProfile.motivation == motivation)
    if search:
        query = query.where(ThreatProfile.name.ilike(f"%{search}%"))

    result = await db.execute(query.order_by(ThreatProfile.name))
    db_profiles = result.scalars().all()

    # Combine with built-in profiles (if not already in DB)
    db_names = {p.name for p in db_profiles}
    responses = [p for p in db_profiles]

    # Add built-in profiles not yet in DB
    for builtin in BUILTIN_PROFILES:
        if builtin["name"] not in db_names:
            # Filter by sector/motivation if requested
            if sector and sector not in builtin.get("target_sectors", []):
                continue
            if motivation and builtin.get("motivation") != motivation:
                continue
            if search and search.lower() not in builtin["name"].lower():
                continue

            # Return as response (without DB persistence)
            responses.append(
                ThreatProfileResponse(
                    id=f"builtin:{builtin['name'].lower().replace(' ', '_')}",
                    name=builtin["name"],
                    aliases=builtin.get("aliases", []),
                    description=builtin["description"],
                    country_origin=builtin.get("country_origin"),
                    motivation=builtin.get("motivation"),
                    target_sectors=builtin.get("target_sectors", []),
                    active_since=builtin.get("active_since"),
                    is_builtin=True,
                    created_at=None,
                    updated_at=None,
                )
            )

    return responses


@router.get("/profiles/{profile_id}", response_model=ThreatProfileDetailResponse)
async def get_profile(profile_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Get a threat profile with full TTP details."""
    # Check built-in profiles first
    if profile_id.startswith("builtin:"):
        builtin_key = profile_id.replace("builtin:", "").replace("_", " ")
        for builtin in BUILTIN_PROFILES:
            if builtin["name"].lower() == builtin_key.lower():
                return ThreatProfileDetailResponse(
                    id=profile_id,
                    name=builtin["name"],
                    aliases=builtin.get("aliases", []),
                    description=builtin["description"],
                    country_origin=builtin.get("country_origin"),
                    motivation=builtin.get("motivation"),
                    target_sectors=builtin.get("target_sectors", []),
                    active_since=builtin.get("active_since"),
                    is_builtin=True,
                    ttps=builtin["ttps"],
                    tools=builtin.get("tools", []),
                    iocs=builtin.get("iocs", {}),
                    references=builtin.get("references", []),
                    created_at=None,
                    updated_at=None,
                )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile not found")

    # Database profile
    result = await db.execute(select(ThreatProfile).where(ThreatProfile.id == profile_id))
    profile = result.scalar_one_or_none()
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile not found")

    return profile


@router.post("/profiles", response_model=ThreatProfileResponse, status_code=status.HTTP_201_CREATED)
async def create_profile(
    profile_data: ThreatProfileCreateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Create a custom threat actor profile."""
    # Check for duplicate name
    result = await db.execute(
        select(ThreatProfile).where(ThreatProfile.name == profile_data.name)
    )
    if result.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A profile with this name already exists",
        )

    profile = ThreatProfile(
        name=profile_data.name,
        aliases=profile_data.aliases,
        description=profile_data.description,
        country_origin=profile_data.country_origin,
        motivation=profile_data.motivation,
        target_sectors=profile_data.target_sectors,
        active_since=profile_data.active_since,
        ttps=profile_data.ttps,
        tools=profile_data.tools,
        iocs=profile_data.iocs,
        references=profile_data.references,
        is_builtin=False,
    )
    db.add(profile)
    await db.commit()
    await db.refresh(profile)

    logger.info("Custom threat profile created", profile_id=profile.id, name=profile.name)
    return profile


@router.put("/profiles/{profile_id}", response_model=ThreatProfileResponse)
async def update_profile(
    profile_id: str,
    update_data: ThreatProfileUpdateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Update a custom threat profile. Built-in profiles cannot be modified."""
    if profile_id.startswith("builtin:"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Built-in profiles cannot be modified",
        )

    result = await db.execute(select(ThreatProfile).where(ThreatProfile.id == profile_id))
    profile = result.scalar_one_or_none()
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile not found")

    update_dict = update_data.model_dump(exclude_unset=True)
    for key, value in update_dict.items():
        setattr(profile, key, value)

    await db.commit()
    await db.refresh(profile)

    return profile


@router.post("/match", response_model=ThreatMatchResponse)
async def match_threats(
    match_data: ThreatMatchRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Match campaign findings against threat actor TTPs."""
    findings_data = []

    if match_data.campaign_id:
        # Get findings from campaign
        result = await db.execute(
            select(Finding).where(Finding.campaign_id == match_data.campaign_id)
        )
        findings = result.scalars().all()
        findings_data = [
            {
                "type": f.type,
                "mitre_techniques": f.mitre_techniques or [],
            }
            for f in findings
        ]
    elif match_data.finding_types:
        findings_data = [{"type": t, "mitre_techniques": []} for t in match_data.finding_types]
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provide either campaign_id or finding_types",
        )

    # Extract techniques from findings
    techniques = _matcher.extract_techniques_from_findings(findings_data)

    if not techniques:
        return ThreatMatchResponse(matches=[])

    # Get all profiles (DB + builtin)
    db_result = await db.execute(select(ThreatProfile))
    db_profiles = [
        {
            "id": p.id,
            "name": p.name,
            "ttps": p.ttps,
        }
        for p in db_result.scalars().all()
    ]

    all_profiles = db_profiles + [
        {
            "id": f"builtin:{p['name'].lower().replace(' ', '_')}",
            "name": p["name"],
            "ttps": p["ttps"],
        }
        for p in BUILTIN_PROFILES
    ]

    matches = _matcher.match(techniques, all_profiles)

    return ThreatMatchResponse(
        matches=[
            ThreatMatchResult(
                profile_id=m["profile_id"],
                profile_name=m["profile_name"],
                coverage_pct=m["coverage_pct"],
                matched_techniques=m["matched_techniques"],
                total_techniques=m["total_techniques"],
            )
            for m in matches
        ]
    )


@router.get("/attack-paths/{campaign_id}", response_model=AttackPathResponse)
async def get_attack_paths(
    campaign_id: str, request: Request, db: AsyncSession = Depends(get_db)
):
    """Analyze attack paths within a campaign using enhanced chain analysis."""
    # Verify campaign
    campaign_result = await db.execute(select(Campaign).where(Campaign.id == campaign_id))
    if campaign_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Campaign not found")

    # Get findings
    result = await db.execute(
        select(Finding)
        .where(Finding.campaign_id == campaign_id)
        .order_by(Finding.severity.desc())
    )
    findings = result.scalars().all()

    if not findings:
        return AttackPathResponse(campaign_id=campaign_id, paths=[], total_paths=0)

    # Build attack paths by analyzing finding relationships
    paths = _build_attack_paths(findings)

    return AttackPathResponse(
        campaign_id=campaign_id,
        paths=paths,
        total_paths=len(paths),
    )


def _build_attack_paths(findings: list) -> list[AttackPath]:
    """Build attack paths from findings by analyzing type relationships."""
    severity_scores = {"critical": 10, "high": 8, "medium": 5, "low": 2, "info": 1}

    # Group findings by type
    by_type = {}
    for f in findings:
        by_type.setdefault(f.type, []).append(f)

    paths = []

    # Check for known attack chains
    chain_patterns = [
        {
            "name": "SSRF to Internal Access",
            "types": ["ssrf", "information_disclosure"],
            "description": "Server-Side Request Forgery enables access to internal services, potentially exposing sensitive data or enabling further attacks.",
            "mitre": ["T1190", "T1071.001"],
        },
        {
            "name": "XSS to Session Hijacking to Account Takeover",
            "types": ["xss", "csrf", "broken_access_control"],
            "description": "Cross-Site Scripting enables session theft, combined with CSRF bypasses security controls for full account compromise.",
            "mitre": ["T1189", "T1059.007"],
        },
        {
            "name": "SQL Injection to Data Exfiltration",
            "types": ["sqli", "information_disclosure"],
            "description": "SQL injection provides database access, enabling extraction of credentials and sensitive data.",
            "mitre": ["T1190", "T1505.001", "T1041"],
        },
        {
            "name": "Authentication Bypass to Privilege Escalation",
            "types": ["auth_bypass", "broken_access_control"],
            "description": "Authentication bypass combined with access control flaws enables unauthorized privilege escalation.",
            "mitre": ["T1068", "T1078"],
        },
        {
            "name": "Default Credentials to Persistence",
            "types": ["default_credentials", "webshell", "persistence"],
            "description": "Default credentials enable initial access, followed by webshell deployment for persistent access.",
            "mitre": ["T1078.001", "T1505.003"],
        },
        {
            "name": "Command Injection to Full Compromise",
            "types": ["command_injection"],
            "description": "Command injection provides remote code execution on the server, enabling full system compromise.",
            "mitre": ["T1190", "T1059"],
        },
    ]

    for pattern in chain_patterns:
        matching_findings = []
        for ptype in pattern["types"]:
            matching_findings.extend(by_type.get(ptype, []))

        if len(matching_findings) >= 1:
            steps = [
                AttackPathStep(
                    finding_id=f.id,
                    title=f.title,
                    type=f.type,
                    severity=f.severity.value if hasattr(f.severity, "value") else f.severity,
                    mitre_technique=pattern["mitre"][0] if pattern["mitre"] else None,
                )
                for f in matching_findings[:5]  # Limit steps
            ]

            # Calculate risk score
            total_severity = sum(
                severity_scores.get(
                    f.severity.value if hasattr(f.severity, "value") else f.severity, 1
                )
                for f in matching_findings
            )
            risk_score = min(100, (total_severity / len(matching_findings)) * 10)

            paths.append(AttackPath(
                chain_title=pattern["name"],
                risk_score=round(risk_score, 1),
                steps=steps,
                mitre_chain=pattern["mitre"],
                description=pattern["description"],
            ))

    # Sort by risk score descending
    paths.sort(key=lambda p: p.risk_score, reverse=True)
    return paths


@router.get("/mitre-matrix", response_model=MITREMatrixResponse)
async def get_mitre_matrix(
    request: Request,
    campaign_id: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """Get full MITRE ATT&CK matrix for heatmap visualization."""
    findings = []

    if campaign_id:
        result = await db.execute(
            select(Finding).where(Finding.campaign_id == campaign_id)
        )
        findings = result.scalars().all()

    # Build technique -> findings mapping
    technique_map: dict[str, dict] = {}
    for finding in findings:
        # From explicit MITRE techniques
        for tech in (finding.mitre_techniques or []):
            tech_id = tech.get("id", "") if isinstance(tech, dict) else str(tech)
            tech_name = tech.get("name", tech_id) if isinstance(tech, dict) else tech_id
            if tech_id:
                if tech_id not in technique_map:
                    technique_map[tech_id] = {"name": tech_name, "findings": []}
                technique_map[tech_id]["findings"].append(finding.id)

        # From vulnerability type mapping
        for mapped in VULN_TO_TECHNIQUE.get(finding.type.lower(), []):
            tech_id = mapped["id"]
            if tech_id not in technique_map:
                technique_map[tech_id] = {"name": mapped["name"], "findings": []}
            technique_map[tech_id]["findings"].append(finding.id)

    # Build MITRE matrix organized by tactics
    tactics = []
    total_covered = 0

    for tactic_id, tactic_info in TACTICS.items():
        techniques = []
        for tech_id, tech_data in technique_map.items():
            # Check if this technique belongs to this tactic
            # (simplified -- in production, use full MITRE data)
            for vuln_type, mapped_techs in VULN_TO_TECHNIQUE.items():
                for mapped in mapped_techs:
                    if mapped["id"] == tech_id and mapped.get("tactic") == tactic_id:
                        techniques.append(MITREMatrixTechnique(
                            id=tech_id,
                            name=tech_data["name"],
                            count=len(tech_data["findings"]),
                            findings=list(set(tech_data["findings"])),
                        ))
                        break

        # Deduplicate techniques
        seen = set()
        unique_techniques = []
        for t in techniques:
            if t.id not in seen:
                seen.add(t.id)
                unique_techniques.append(t)
                total_covered += 1

        tactics.append(MITREMatrixTactic(
            id=tactic_id,
            name=tactic_info["name"],
            techniques=unique_techniques,
        ))

    return MITREMatrixResponse(
        campaign_id=campaign_id,
        tactics=tactics,
        total_techniques_covered=total_covered,
    )
