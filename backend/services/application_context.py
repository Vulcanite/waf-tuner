"""Application profile selection and route-specific context enrichment."""
import fnmatch
import re
from urllib.parse import urlsplit

from sqlalchemy import select

from db.models import ApplicationProfile


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
