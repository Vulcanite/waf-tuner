"""Versioned application-context profile APIs."""
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import AnalysisCase, ApplicationProfile, ExceptionDraft, get_db


router = APIRouter(prefix="/api/application-profiles", tags=["application-profiles"])


class ProfileBody(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    host_patterns: list[str] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    routes: list[dict[str, Any]] = Field(default_factory=list)
    source_metadata: dict[str, Any] = Field(default_factory=dict)


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
    # Profile changes invalidate conclusions, but reanalysis remains explicit.
    await db.execute(
        update(AnalysisCase)
        .where(AnalysisCase.state == "complete")
        .values(state="stale", updated_at=now)
    )
    await db.execute(
        update(ExceptionDraft)
        .where(ExceptionDraft.status.in_(["pending", "approved"]))
        .values(status="stale")
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
