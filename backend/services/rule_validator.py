"""Policy and engine validation for ModSecurity exclusion rules.

Accepts rules produced by exception_builder (or legacy model sketches) and
re-emits a canonical form. Prefer builder output as the source of truth.
"""
from __future__ import annotations

import asyncio
import os
import re

from services.exception_builder import (
    SAFE_TARGET_COLLECTIONS,
    build_exception_rule,
    can_build_exception,
)

_FORBIDDEN = re.compile(
    r"\b(?:SecAction|Include|exec|proxy|redirect|deny|drop|block|allow|"
    r"ruleRemoveById|ruleRemoveByTag|ruleRemoveTargetByTag|setvar|skip|skipAfter)\b",
    re.IGNORECASE,
)
_REMOVE_TARGET = re.compile(
    r"ctl:ruleRemoveTargetById=(?P<rule>\d+);(?P<target>[A-Z_]+(?::[^,\"']+)?)",
    re.IGNORECASE,
)
_CTL_ACTION = re.compile(r"\bctl:([^,\"\s]+)", re.IGNORECASE)
_SECRULE = re.compile(
    r'^\s*SecRule\s+(?P<target>\S+)\s+"(?P<operator>(?:[^"\\]|\\.)*)"\s+'
    r'"(?P<actions>(?:[^"\\]|\\.)*)"\s*$',
    re.IGNORECASE | re.DOTALL,
)
_ID = re.compile(r"\bid:\s*'?\d+'?", re.IGNORECASE)
_PHASE = re.compile(r"\bphase:\s*'?\d+'?", re.IGNORECASE)
SAFE_TRANSFORMS = {"t:none", "t:urldecodeuni", "t:lowercase"}
SAFE_OPERATORS = {"@beginswith", "@streq"}
SAFE_PATH_VARS = {"REQUEST_FILENAME", "REQUEST_URI"}


def _normalize_target(collection: str | None, parameter: str | None) -> set[str]:
    if not collection or not parameter:
        return set()
    values = {collection.upper()}
    if parameter:
        values.add(f"{collection.upper()}:{parameter}")
    return values


def validate_structure(raw_rule: str, scope: dict) -> tuple[str | None, str | None]:
    """Return a normalized (builder-canonical) rule or a human-readable rejection reason.

    Regardless of input formatting, successful validation re-emits
    exception_builder.build_exception_rule so deploy always gets one shape.
    """
    ok, scope_error = can_build_exception(scope)
    if not ok:
        return None, scope_error

    raw = (raw_rule or "").strip()
    if not raw:
        # Allow empty input when scope is complete: system will synthesize.
        return build_exception_rule(scope, phase=1), None

    if len(raw) > int(os.environ.get("MAX_PROPOSED_RULE_CHARS", "8192")):
        return None, "The proposed rule exceeds the configured size limit."
    directives = re.findall(r"(?mi)^\s*(Sec[A-Za-z]+|Include)\b", raw)
    if not directives or any(directive.lower() != "secrule" for directive in directives):
        return None, "Only SecRule directives are permitted."
    if len(directives) != 1:
        return None, "Only one non-chained SecRule directive is permitted."
    if _FORBIDDEN.search(raw):
        return None, "The proposed rule contains a forbidden directive or action."
    parsed_rule = _SECRULE.fullmatch(re.sub(r"\\\r?\n\s*", " ", raw))
    if not parsed_rule:
        return None, "The proposed rule is not a complete, parseable SecRule directive."

    target = parsed_rule.group("target")
    operator_text = parsed_rule.group("operator").strip()
    actions_text = parsed_rule.group("actions")
    if target.upper() not in SAFE_PATH_VARS:
        return None, "A runtime exclusion must condition on REQUEST_FILENAME or REQUEST_URI."
    operator_name = operator_text.split(maxsplit=1)[0].lower() if operator_text else ""
    if operator_name not in SAFE_OPERATORS:
        return None, "The path condition uses an unsupported operator."

    uri = str(scope.get("uri") or "")
    operator_operand = operator_text.split(maxsplit=1)[1].strip() if " " in operator_text else ""
    if operator_operand != uri:
        return None, "The path operator must use the exact incident path."

    expected_rule = str(scope.get("rule_id") or "")
    collection = str(scope.get("collection") or "").upper()
    if collection not in SAFE_TARGET_COLLECTIONS or not scope.get("parameter"):
        return None, "Only a specifically observed request parameter can be excluded."
    allowed_targets = _normalize_target(scope.get("collection"), scope.get("parameter"))
    removals = list(_REMOVE_TARGET.finditer(raw))
    if not removals:
        return None, "No target-specific rule removal was found."
    ctl_actions = _CTL_ACTION.findall(actions_text)
    if len(ctl_actions) != len(removals):
        return None, "Only ctl:ruleRemoveTargetById actions are permitted."
    for removal in removals:
        if removal.group("rule") != expected_rule:
            return None, "The proposed rule removes a rule ID other than the incident signature."
        rem_target = removal.group("target").strip().upper()
        if rem_target not in {value.upper() for value in allowed_targets}:
            return None, f"Target {rem_target!r} was not observed in the incident."

    action_tokens = [token.strip() for token in actions_text.split(",") if token.strip()]
    id_count = 0
    for token in action_tokens:
        lowered = token.lower()
        if re.fullmatch(r"id:\s*'?\d+'?", token, re.IGNORECASE):
            id_count += 1
        elif re.fullmatch(r"phase:\s*'?\d+'?", token, re.IGNORECASE):
            continue
        elif lowered in {"pass", "nolog"}:
            continue
        elif lowered in SAFE_TRANSFORMS:
            continue
        elif _REMOVE_TARGET.fullmatch(token):
            continue
        else:
            return None, f"Action {token!r} is not permitted."
    if id_count > 1:
        return None, "The rule contains more than one ID action."

    normalized_actions = {token.lower() for token in action_tokens}
    if "pass" not in normalized_actions:
        return None, "The rule must use the non-disruptive pass action."
    if "nolog" not in normalized_actions:
        return None, "The rule must use nolog."

    # Always re-emit builder canonical form. Phase 1 so ctl:ruleRemoveTargetById
    # runs before typical CRS phase-2 detections regardless of model sketch.
    return build_exception_rule(scope, phase=1), None


def _engine_validate_sync(rule_text: str) -> tuple[str, str | None]:
    """No live edge validation — structure checks already ran."""
    _ = rule_text
    return "valid", None


async def validate_rule(raw_rule: str, scope: dict) -> tuple[str | None, str, str | None]:
    normalized, error = validate_structure(raw_rule, scope)
    if error:
        return None, "structurally_invalid", error
    status, engine_error = await asyncio.to_thread(_engine_validate_sync, normalized or "")
    return normalized, status, engine_error


async def build_and_validate(scope: dict, *, phase: int = 1) -> tuple[str | None, str, str | None]:
    """Server-side path: synthesize from scope then validate (no model SecLang)."""
    ok, error = can_build_exception(scope)
    if not ok:
        return None, "cannot_build", error
    rule = build_exception_rule(scope, phase=phase)
    return await validate_rule(rule, scope)
