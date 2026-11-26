"""Deterministic ModSecurity exclusion builder.

The LLM classifies; this module writes SecLang so free-form rule hallucination
never reaches deploy.
"""
from __future__ import annotations

import re
from hashlib import sha256

from services.draft_scope import canonical_scope_key

# Collections we will auto-exclude (target-specific only).
SAFE_TARGET_COLLECTIONS = frozenset({
    "ARGS", "ARGS_NAMES", "REQUEST_HEADERS", "REQUEST_COOKIES",
    "FILES", "FILES_NAMES", "XML",
})

# Reserved agent exception ID space (before typical custom rules, after CRS setup).
_PLAIN_PARAMETER = re.compile(r"[A-Za-z0-9_.\-\[\]]+")

_EXCEPTION_ID_BASE = 1_000_000
_EXCEPTION_ID_SPAN = 100_000  # 1_000_000 .. 1_099_999


def stable_exception_id(scope: dict) -> int:
    if scope.get("host") or scope.get("method"):
        digest = canonical_scope_key(scope)
    else:
        # Preserve IDs for callers constructing the legacy path-only form.
        parts = [str(scope.get(key) or "") for key in ("uri", "rule_id", "collection", "parameter")]
        digest = sha256(":".join(parts).encode()).hexdigest()
    return _EXCEPTION_ID_BASE + (int(digest, 16) % _EXCEPTION_ID_SPAN)


def can_build_exception(scope: dict) -> tuple[bool, str | None]:
    """Return whether a safe exclusion can be synthesized from ground-truth scope."""
    uri = str(scope.get("uri") or "")
    if not uri or uri == "/":
        return False, "Root or empty URI scopes are not permitted."
    if any(ch in uri for ch in ('"', "\\", "?", "#")) or "%{" in uri or any(
        character.isspace() or ord(character) < 32 or ord(character) == 127 for character in uri
    ):
        return False, "The incident path cannot be represented safely in a rule."
    if not uri.startswith("/"):
        return False, "The incident path must be absolute."
    host, method = str(scope.get("host") or ""), str(scope.get("method") or "")
    if host or method:
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", host):
            return False, "A specific DNS host or IPv4 address is required for this exclusion."
        if not re.fullmatch(r"[A-Z]{1,24}", method.upper()):
            return False, "The observed HTTP method cannot be represented safely in a rule."
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
    # Plain names only: a name like "/.*/" would be read by ModSecurity as a
    # regex target and exclude every parameter on the path.
    if not _PLAIN_PARAMETER.fullmatch(param):
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
    actions = f"id:{rid},phase:{phase},pass,nolog,t:none"
    control = f"ctl:ruleRemoveTargetById={rule_id};{target}"
    uri_rule = f'SecRule REQUEST_FILENAME "@streq {uri}"'
    if not scope.get("host"):
        return f'{uri_rule} "{actions},{control}"'

    method = str(scope["method"]).upper()
    # Put ctl on the final clause so the full scope must match on v2 and v3.
    host_pattern = str(scope["host"]).lower().replace(".", "[.]")
    return (
        f'{uri_rule} "{actions},chain"\n'
        f'    SecRule REQUEST_METHOD "@streq {method}" "t:none,chain"\n'
        f'    SecRule REQUEST_HEADERS:Host "@rx ^{host_pattern}[.]?(?::[0-9]+)?$" '
        f'"t:none,t:lowercase,{control}"'
    )
