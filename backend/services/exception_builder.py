"""Deterministic ModSecurity exclusion builder.

The LLM classifies; this module writes SecLang so free-form rule hallucination
never reaches deploy.
"""
from __future__ import annotations

import hashlib
import re

# Collections we will auto-exclude (target-specific only).
SAFE_TARGET_COLLECTIONS = frozenset({
    "ARGS", "ARGS_NAMES", "REQUEST_HEADERS", "REQUEST_COOKIES",
    "FILES", "FILES_NAMES", "XML",
})

# Reserved agent exception ID space (before typical custom rules, after CRS setup).
_EXCEPTION_ID_BASE = 1_000_000
_EXCEPTION_ID_SPAN = 100_000  # 1_000_000 .. 1_099_999


def stable_exception_id(scope: dict) -> int:
    uri = str(scope.get("uri") or "")
    rule_id = str(scope.get("rule_id") or "")
    collection = str(scope.get("collection") or "")
    parameter = str(scope.get("parameter") or "")
    digest = hashlib.sha256(
        f"{uri}:{rule_id}:{collection}:{parameter}".encode()
    ).hexdigest()
    return _EXCEPTION_ID_BASE + (int(digest, 16) % _EXCEPTION_ID_SPAN)


def can_build_exception(scope: dict) -> tuple[bool, str | None]:
    """Return whether a safe exclusion can be synthesized from ground-truth scope."""
    uri = str(scope.get("uri") or "")
    if not uri or uri == "/":
        return False, "Root or empty URI scopes are not permitted."
    if any(ch in uri for ch in ('"', "\\", "\r", "\n", "?", "#")):
        return False, "The incident path cannot be represented safely in a rule."
    if not uri.startswith("/"):
        return False, "The incident path must be absolute."
    rule_id = str(scope.get("rule_id") or "")
    if not re.fullmatch(r"\d+", rule_id):
        return False, "A numeric CRS rule ID is required."
    collection = str(scope.get("collection") or "").upper()
    parameter = scope.get("parameter")
    if collection not in SAFE_TARGET_COLLECTIONS:
        return False, f"Collection {collection or '(none)'} cannot be auto-excluded."
    if not parameter or not str(parameter).strip():
        return False, "Only a specifically observed request parameter can be excluded."
    param = str(parameter).strip()
    if any(ch in param for ch in ('"', "'", "\r", "\n", ";", ",", " ")):
        return False, "The parameter name contains characters unsafe for SecLang."
    return True, None


def build_exception_rule(scope: dict, *, phase: int = 1) -> str:
    """Build a canonical exclusion SecRule from ground-truth scope.

    Uses REQUEST_FILENAME so query strings on the live request do not break matching.
    """
    ok, error = can_build_exception(scope)
    if not ok:
        raise ValueError(error or "Cannot build exception")

    uri = str(scope["uri"])
    rule_id = str(scope["rule_id"])
    collection = str(scope["collection"]).upper()
    parameter = str(scope["parameter"]).strip()
    phase = 1 if phase not in (1, 2) else phase
    rid = stable_exception_id(scope)
    target = f"{collection}:{parameter}"
    return (
        f'SecRule REQUEST_FILENAME "@streq {uri}" '
        f'"id:{rid},phase:{phase},pass,nolog,t:none,'
        f'ctl:ruleRemoveTargetById={rule_id};{target}"'
    )
