"""Engagement routes used by the console. No account is required for the local file."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from src.core.assessment import AssessmentError, run_scan, run_verify, write_report
from src.core.engagements import EngagementStore

router = APIRouter(prefix="/engagements", tags=["Engagements"])


class EngagementCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = ""
    allowed_domains: list[str] = Field(..., min_length=1, max_length=50)
    objectives: list[str] = Field(default_factory=list, max_length=20)


class TargetRequest(BaseModel):
    url: str = Field(..., min_length=4, max_length=2048)
    modules: list[str] = Field(default_factory=list, max_length=20)


def _store() -> EngagementStore:
    return EngagementStore()


def _call(action):
    try:
        return action()
    except AssessmentError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Engagement not found.") from exc


@router.post("", status_code=201)
async def create_engagement(body: EngagementCreate):
    try:
        engagement = _store().create(body.name, body.allowed_domains, body.description, body.objectives)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _store().summary(engagement)


@router.get("")
async def list_engagements():
    store = _store()
    return [store.summary(item) for item in store.list_all()]


@router.get("/{engagement_id}")
async def get_engagement(engagement_id: str):
    engagement = _store().get(engagement_id)
    if engagement is None:
        raise HTTPException(status_code=404, detail="Engagement not found.")
    public = dict(engagement)
    public.pop("notes", None)
    public["summary"] = _store().summary(engagement)
    return public


@router.post("/{engagement_id}/scan")
async def scan_engagement(engagement_id: str, body: TargetRequest):
    async def action():
        return await run_scan(engagement_id, body.url, _store())

    try:
        return await action()
    except AssessmentError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{engagement_id}/verify")
async def verify_engagement(engagement_id: str, body: TargetRequest):
    try:
        return await run_verify(engagement_id, body.url, body.modules or None, _store())
    except AssessmentError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{engagement_id}/report")
async def report_engagement(engagement_id: str):
    return _call(lambda: write_report(engagement_id, _store()))
