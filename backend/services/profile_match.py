"""Rank application profiles and routes for a request (standard library only).

eval/ imports this to attach the same application context the backend would.
"""
from __future__ import annotations

import fnmatch
import re

from services.lab_profiles import DEFAULT_LAB_PROFILE_NAME


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
