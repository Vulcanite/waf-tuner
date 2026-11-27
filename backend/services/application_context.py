"""Application profile selection and route-specific context enrichment."""
from __future__ import annotations

from sqlalchemy import select

from db.models import ApplicationProfile
from services.inference_context import application_host, split_request_uri
from services.profile_match import application_context_for


async def active_application_profiles(session):
    return (await session.scalars(select(ApplicationProfile).where(ApplicationProfile.active.is_(True)))).all()


async def select_application_context(session, event: dict) -> tuple[ApplicationProfile | None, dict]:
    profiles = await active_application_profiles(session)
    method = str(event.get("method") or "").upper()
    path = split_request_uri(str(event.get("uri") or "/")).path or "/"
    return application_context_for(profiles, application_host(event), method, path)


async def profile_is_current(session, event: dict, profile_id: int | None, profile_version: int | None) -> bool:
    profile, _ = await select_application_context(session, event)
    return (profile.id, profile.version) == (profile_id, profile_version) if profile else profile_id is None
