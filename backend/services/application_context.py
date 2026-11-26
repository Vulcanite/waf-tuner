"""Application profile selection and route-specific context enrichment."""
from __future__ import annotations

import fnmatch
import logging
import re
from datetime import datetime, timezone

from sqlalchemy import select

from db.models import ApplicationProfile, get_session_factory
from services.inference_context import application_host, split_request_uri
from services.llm_options import env_bool

logger = logging.getLogger(__name__)

DEFAULT_LAB_PROFILE_NAME = "default-lab"

# The catch-all supplies general lab context. Draft eligibility requires
# documented semantics for the observed parameter on a specific route.
DEFAULT_LAB_ROUTES = [
    {
        "path": "/login.php",
        "methods": ["GET", "POST"],
        "parameters": {
            "username": "account username",
            "password": "account password",
            "user_token": "csrf token",
            "Login": "form submit",
        },
        "notes": "DVWA login. Credential fields are not SQL.",
    },
    {
        "path": "/security.php",
        "methods": ["GET", "POST"],
        "parameters": {
            "security": "DVWA security level",
            "seclev_submit": "form submit",
            "user_token": "csrf token",
        },
        "notes": "DVWA security-level form.",
    },
    {
        "path": "/vulnerabilities/sqli/",
        "methods": ["GET", "POST"],
        "parameters": {"id": "user id lookup", "Submit": "form submit"},
        "notes": "DVWA SQL injection lab. Natural-language id values are search terms.",
    },
    {
        "path": "/vulnerabilities/sqli_blind/",
        "methods": ["GET", "POST"],
        "parameters": {"id": "user id lookup", "Submit": "form submit"},
        "notes": "DVWA blind SQL injection lab.",
    },
    {
        "path": "/vulnerabilities/xss_r/",
        "methods": ["GET", "POST"],
        "parameters": {"name": "display name shown in greeting"},
        "notes": "DVWA reflected XSS lab. Names may include punctuation.",
    },
    {
        "path": "/vulnerabilities/xss_s/",
        "methods": ["GET", "POST"],
        "parameters": {
            "txtName": "guestbook author name",
            "mtxMessage": "guestbook message, may include sanitized markup",
            "btnSign": "form submit",
        },
        "notes": "DVWA stored XSS / guestbook lab.",
    },
    {
        "path": "/vulnerabilities/exec/",
        "methods": ["GET", "POST"],
        "parameters": {"ip": "host to ping", "Submit": "form submit"},
        "notes": "DVWA command-injection lab. ip is a hostname or address.",
    },
    {
        "path": "/vulnerabilities/fi/",
        "methods": ["GET"],
        "parameters": {"page": "local content page name"},
        "notes": "DVWA file-inclusion lab. page is a local include name, not a filesystem path.",
    },
    {
        "path": "/*",
        "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
        "parameters": {},
        "notes": "General lab context for paths without a documented route.",
    },
]


async def ensure_default_application_profile() -> bool:
    """Insert a catch-all lab profile when no application profiles exist.

    Returns True when a profile was created. Operator-authored profiles are
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
        session.add(
            ApplicationProfile(
                name=DEFAULT_LAB_PROFILE_NAME,
                version=1,
                active=True,
                host_patterns=["*"],
                context={
                    "purpose": "OWASP DVWA lab application behind ModSecurity CRS",
                    "languages": ["php"],
                    "frameworks": ["dvwa"],
                    "data_stores": ["mysql"],
                },
                routes=list(DEFAULT_LAB_ROUTES),
                source_metadata={
                    "seeded": True,
                    "seed": DEFAULT_LAB_PROFILE_NAME,
                    "replace_with_operator_profile": True,
                },
                created_at=now,
                updated_at=now,
            )
        )
        await session.commit()
    logger.info("Seeded default application profile %s", DEFAULT_LAB_PROFILE_NAME)
    return True


def _route_score(route: dict, method: str, path: str) -> int:
    methods = [str(item).upper() for item in (route.get("methods") or [])]
    if methods and method.upper() not in methods:
        return -1
    pattern = str(route.get("path") or "")
    if not pattern:
        return -1
    if pattern.endswith("/*") and path.startswith(pattern[:-1]):
        return 100 + len(pattern)
    if "{" in pattern:
        expression = re.escape(pattern)
        expression = re.sub(r"\\\{[^/{}]+\\\}", r"[^/]+", expression)
        if re.fullmatch(expression, path):
            return 500 + len(pattern.replace("{", "").replace("}", ""))
        return -1
    return 1000 + len(pattern) if pattern == path else -1


def _host_score(patterns: list[str], host: str) -> tuple[int, int]:
    best = (-1, 0)
    for pattern in patterns or ["*"]:
        pattern = pattern.lower().rstrip(".")
        if not fnmatch.fnmatchcase(host, pattern):
            continue
        if pattern == "*":
            score = (0, 0)
        elif any(character in pattern for character in "*?["):
            score = (1, len(pattern))
        else:
            score = (2, len(pattern))
        best = max(best, score)
    return best


def application_context_for(profiles, host: str, method: str, path: str):
    """Rank host and route evidence together, with the lab profile as a fallback."""
    chosen = best_route = best = None
    for profile in profiles:
        host_score = _host_score(profile.host_patterns, host)
        if host_score[0] < 0:
            continue
        route = None
        route_score = -1
        for candidate in profile.routes or []:
            if not isinstance(candidate, dict):
                continue
            score = _route_score(candidate, method, path)
            if score > route_score:
                route, route_score = candidate, score
        specific_route = route is not None and route.get("path") != "/*"
        score = (
            specific_route, host_score, route_score, profile.name != DEFAULT_LAB_PROFILE_NAME,
            profile.version, -profile.id,
        )
        if best is None or score > best:
            chosen, best_route, best = profile, route, score
    if chosen is None:
        return None, {}
    return chosen, {
        "application": chosen.context or {},
        "route": best_route,
        "profile_name": chosen.name,
        "profile_version": chosen.version,
        "fact_provenance": chosen.source_metadata or {},
    }


async def active_application_profiles(session):
    return (await session.scalars(select(ApplicationProfile).where(ApplicationProfile.active.is_(True)))).all()


async def select_application_context(session, event: dict) -> tuple[ApplicationProfile | None, dict]:
    profiles = await active_application_profiles(session)
    method = str(event.get("method") or "GET").upper()
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
