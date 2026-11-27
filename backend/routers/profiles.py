"""Versioned application-context profile APIs."""
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import and_, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError

from db.models import AnalysisCase, AnalysisRevision, ApplicationProfile, AuditEvent, ExceptionDraft, get_db
from services.application_context import active_application_profiles, application_context_for
from services.inference_context import application_host
from services.profile_files import MAX_ROUTE_PARAMETERS, MAX_ROUTES, MAX_TEXT_CHARS


router = APIRouter(prefix="/api/application-profiles", tags=["application-profiles"])


class ProfileBody(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    host_patterns: list[str] = Field(default_factory=list, max_length=100)
    context: dict[str, Any] = Field(default_factory=dict)
    routes: list[dict[str, Any]] = Field(default_factory=list, max_length=MAX_ROUTES)
    source_metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("routes")
    @classmethod
    def check_routes(cls, routes):
        for route in routes:
            if not isinstance(route.get("path"), str) or not route["path"].startswith("/"):
                raise ValueError("Each route needs an absolute path")
            if "methods" in route and (
                not isinstance(route["methods"], list)
                or any(not isinstance(method, str) for method in route["methods"])
            ):
                raise ValueError("Route methods must be a list of HTTP method names")
            if "parameters" in route and not isinstance(route["parameters"], dict):
                raise ValueError("Route parameters must map names to application semantics")
            if len(route.get("parameters") or {}) > MAX_ROUTE_PARAMETERS:
                raise ValueError(f"A route documents at most {MAX_ROUTE_PARAMETERS} parameters")
            texts = [route.get("notes"), *(route.get("parameters") or {}).values()]
            if any(isinstance(text, str) and len(text) > MAX_TEXT_CHARS for text in texts):
                raise ValueError(f"Route notes and parameter meanings are at most {MAX_TEXT_CHARS} characters")
        return routes


def _serialize(profile: ApplicationProfile) -> dict:
    return {
        "id": profile.id,
        "name": profile.name,
        "version": profile.version,
        "active": profile.active,
        "host_patterns": profile.host_patterns or [],
        "context": profile.context or {},
        "routes": profile.routes or [],
        "source_metadata": profile.source_metadata or {},
        "created_at": profile.created_at.isoformat() if profile.created_at else None,
        "updated_at": profile.updated_at.isoformat() if profile.updated_at else None,
    }


async def _create_version(db: AsyncSession, body: ProfileBody, version: int) -> ApplicationProfile:
    now = datetime.now(timezone.utc)
    await db.execute(
        update(ApplicationProfile).where(ApplicationProfile.name == body.name)
        .values(active=ApplicationProfile.active)
    )
    previous_profiles = await active_application_profiles(db)
    await db.execute(
        update(ApplicationProfile)
        .where(ApplicationProfile.name == body.name, ApplicationProfile.active.is_(True))
        .values(active=False, updated_at=now)
    )
    profile = ApplicationProfile(
        name=body.name,
        version=version,
        active=True,
        host_patterns=body.host_patterns,
        context=body.context,
        routes=body.routes,
        source_metadata=body.source_metadata,
        created_at=now,
        updated_at=now,
    )
    db.add(profile)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(status_code=409, detail="Application profile version already exists") from exc
    current_profiles = [item for item in previous_profiles if item.name != profile.name] + [profile]
    last_id = 0
    while True:
        rows = (await db.execute(
            select(
                AnalysisCase.id, AnalysisCase.method, AnalysisCase.path, AnalysisCase.application_host,
                AuditEvent.raw_event["uri"].as_string(), AuditEvent.raw_event["raw_request"]["headers"],
            )
            .outerjoin(AuditEvent, and_(
                AuditEvent.event_line == AnalysisCase.latest_event_line,
                or_(AnalysisCase.application_host.is_(None), AnalysisCase.application_host == ""),
            ))
            .where(AnalysisCase.state == "complete", AnalysisCase.id > last_id)
            .order_by(AnalysisCase.id)
            .limit(256)
        )).all()
        if not rows:
            break
        last_id = rows[-1][0]
        affected = []
        for case_id, method, path, host, uri, headers in rows:
            host = host or application_host({"uri": uri, "raw_request": {"headers": headers}})
            previous, _ = application_context_for(previous_profiles, host, method, path)
            current, _ = application_context_for(current_profiles, host, method, path)
            if previous != current:
                affected.append(case_id)
        if not affected:
            continue
        revision_ids = select(AnalysisRevision.id).where(AnalysisRevision.analysis_case_id.in_(affected))
        await db.execute(
            update(AnalysisCase).where(AnalysisCase.id.in_(affected))
            .values(state="stale", updated_at=now)
        )
        await db.execute(
            update(ExceptionDraft)
            .where(
                ExceptionDraft.analysis_revision_id.in_(revision_ids),
                ExceptionDraft.status.in_(["pending", "approved"]),
            )
            .values(status="stale", validation_status="stale_context", rule_placement=None,
                    validation_error="Application profile changed. Reanalyze the case to refresh this draft.")
        )
    await db.commit()
    await db.refresh(profile)
    return profile


@router.get("")
async def list_profiles(db: AsyncSession = Depends(get_db)):
    profiles = (
        await db.execute(
            select(ApplicationProfile)
            .order_by(ApplicationProfile.name.asc(), ApplicationProfile.version.desc())
        )
    ).scalars().all()
    return {"items": [_serialize(profile) for profile in profiles]}


@router.post("")
async def create_profile(body: ProfileBody, db: AsyncSession = Depends(get_db)):
    existing = (
        await db.execute(
            select(ApplicationProfile.id).where(ApplicationProfile.name == body.name).limit(1)
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status_code=409, detail="Profile already exists; create a new version instead")
    return _serialize(await _create_version(db, body, 1))


@router.put("/{profile_id}")
async def create_profile_version(
    profile_id: int, body: ProfileBody, db: AsyncSession = Depends(get_db)
):
    current = await db.get(ApplicationProfile, profile_id)
    if current is None:
        raise HTTPException(status_code=404, detail="Profile not found")
    if body.name != current.name:
        raise HTTPException(status_code=400, detail="Profile name cannot change between versions")
    highest = (
        await db.execute(
            select(ApplicationProfile.version)
            .where(ApplicationProfile.name == current.name)
            .order_by(ApplicationProfile.version.desc())
            .limit(1)
        )
    ).scalar_one()
    return _serialize(await _create_version(db, body, highest + 1))
