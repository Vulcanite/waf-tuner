"""Application profile selection and route-specific context enrichment."""
from __future__ import annotations

import copy
import logging
from datetime import datetime, timezone

from sqlalchemy import select

from db.models import ApplicationProfile, get_session_factory
from services.inference_context import application_host, split_request_uri
from services.lab_profiles import (  # noqa: F401 - re-exported for callers and tests
    DEFAULT_LAB_PROFILE_NAME,
    DEFAULT_LAB_ROUTES,
    SEEDED_PROFILES,
    SHOP_LAB_PROFILE_NAME,
    SHOP_LAB_ROUTES,
    seed_metadata,
)
from services.llm_options import env_bool
from services.profile_match import _host_score, _route_score, application_context_for  # noqa: F401

logger = logging.getLogger(__name__)


async def ensure_default_application_profile() -> bool:
    """Insert the seeded lab profiles (DVWA and the Flask Lab Shop) when no profiles exist.

    Returns True when profiles were created. Operator-authored profiles are
    never overwritten. Disable with SEED_DEFAULT_PROFILE=false.
    """
    if not env_bool("SEED_DEFAULT_PROFILE", True):
        return False
    factory = get_session_factory()
    async with factory() as session:
        existing = (
            await session.execute(select(ApplicationProfile.id).limit(1))
        ).scalar_one_or_none()
        if existing is not None:
            return False
        now = datetime.now(timezone.utc)
        for profile in SEEDED_PROFILES:
            session.add(
                ApplicationProfile(
                    name=profile["name"],
                    version=1,
                    active=True,
                    host_patterns=list(profile["host_patterns"]),
                    context=copy.deepcopy(profile["context"]),
                    routes=copy.deepcopy(profile["routes"]),
                    source_metadata=seed_metadata(profile["name"]),
                    created_at=now,
                    updated_at=now,
                )
            )
            # Flush per profile so ids follow SEEDED_PROFILES order (ranking breaks ties on id).
            await session.flush()
        await session.commit()
    logger.info("Seeded application profiles %s", ", ".join(profile["name"] for profile in SEEDED_PROFILES))
    return True


async def active_application_profiles(session):
    return (await session.scalars(select(ApplicationProfile).where(ApplicationProfile.active.is_(True)))).all()


async def select_application_context(session, event: dict) -> tuple[ApplicationProfile | None, dict]:
    profiles = await active_application_profiles(session)
    method = str(event.get("method") or "").upper()
    path = split_request_uri(str(event.get("uri") or "/")).path or "/"
    return application_context_for(profiles, application_host(event), method, path)


def route_supports_exception(application_context: dict, parameter: str | None) -> bool:
    route = application_context.get("route") or {}
    parameters = route.get("parameters")
    if not parameter or route.get("path") in (None, "", "/*") or not isinstance(parameters, dict):
        return False
    semantics = parameters.get(parameter)
    return bool(
        (isinstance(semantics, str) and semantics.strip())
        or (isinstance(semantics, dict) and semantics)
    )


async def profile_is_current(session, event: dict, profile_id: int | None, profile_version: int | None) -> bool:
    profile, _ = await select_application_context(session, event)
    return (profile.id, profile.version) == (profile_id, profile_version) if profile else profile_id is None
