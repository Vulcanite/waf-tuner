"""Application profile selection and route-specific context enrichment."""
from __future__ import annotations

import fnmatch
import logging
import os
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

from sqlalchemy import select

from db.models import ApplicationProfile, get_session_factory

logger = logging.getLogger(__name__)

DEFAULT_LAB_PROFILE_NAME = "default-lab"

# Catch-all so first-run analysis can match a route before the operator writes
# application-specific profiles. More specific operator routes still win because
# `_route_score` ranks exact and templated paths above `/*`.
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
        "notes": "Catch-all so first-run exclusions are not blocked pending operator profiles.",
    },
]


def _seed_default_profile_enabled() -> bool:
    return os.environ.get("SEED_DEFAULT_PROFILE", "true").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


async def ensure_default_application_profile() -> bool:
    """Insert a catch-all lab profile when no application profiles exist.

    Returns True when a profile was created. Operator-authored profiles are
    never overwritten. Disable with SEED_DEFAULT_PROFILE=false.
    """
    if not _seed_default_profile_enabled():
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


def _header(headers: dict, name: str) -> str:
    wanted = name.lower()
    for key, value in (headers or {}).items():
        if str(key).lower() == wanted:
            return str(value).split(":", 1)[0].lower()
    return ""


def _route_score(route: dict, method: str, path: str) -> int:
    methods = [str(item).upper() for item in route.get("methods", [])]
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


async def select_application_context(session, event: dict) -> tuple[ApplicationProfile | None, dict]:
    """Select the most specific active profile and route for an event."""
    result = await session.execute(
        select(ApplicationProfile)
        .where(ApplicationProfile.active.is_(True))
        .order_by(ApplicationProfile.version.desc(), ApplicationProfile.id.asc())
    )
    profiles = result.scalars().all()
    request = event.get("raw_request") or {}
    host = _header(request.get("headers") or {}, "host")
    method = str(event.get("method") or "GET").upper()
    path = urlsplit(str(event.get("uri") or "/")).path or "/"

    chosen = None
    for profile in profiles:
        patterns = profile.host_patterns or []
        if not patterns or any(fnmatch.fnmatch(host, str(pattern).lower()) for pattern in patterns):
            chosen = profile
            break
    if chosen is None:
        return None, {}

    best_route = None
    best_score = -1
    for route in chosen.routes or []:
        score = _route_score(route, method, path)
        if score > best_score:
            best_score = score
            best_route = route

    return chosen, {
        "application": chosen.context or {},
        "route": best_route,
        "profile_name": chosen.name,
        "profile_version": chosen.version,
        "fact_provenance": chosen.source_metadata or {},
    }
