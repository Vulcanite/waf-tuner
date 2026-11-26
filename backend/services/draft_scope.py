"""Canonical exception scope and server-owned rule ID helpers."""
import hashlib
import re


def canonical_scope_key(scope: dict) -> str:
    path = str(scope.get("uri") or "").split("?", 1)[0] or "/"
    parts = (
        path,
        str(scope.get("rule_id") or ""),
        str(scope.get("collection") or "").upper(),
        str(scope.get("parameter") or "").strip(),
    )
    if scope.get("host") or scope.get("method"):
        parts += (str(scope.get("host") or "").lower(), str(scope.get("method") or "").upper())
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()


def case_exception_scope(case) -> dict:
    scope = {"uri": case.path, "collection": case.collection, "parameter": case.parameter, "rule_id": case.rule_id}
    if case.application_host and case.method:
        scope.update(host=case.application_host, method=case.method)
    return scope


def rule_numeric_id(rule: str | None) -> int | None:
    match = re.search(r"(?:^|[,\s])id:(\d+)", rule or "")
    return int(match.group(1)) if match else None
