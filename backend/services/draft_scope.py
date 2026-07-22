"""Canonical exception scope and server-owned rule ID helpers."""
import hashlib
import re


def canonical_scope_key(scope: dict) -> str:
    path = str(scope.get("uri") or "").split("?", 1)[0].rstrip("/") or "/"
    parts = (
        path,
        str(scope.get("rule_id") or ""),
        str(scope.get("collection") or "").upper(),
        str(scope.get("parameter") or ""),
    )
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()


def rule_numeric_id(rule: str | None) -> int | None:
    match = re.search(r"(?:^|[,\s])id:(\d+)", rule or "")
    return int(match.group(1)) if match else None
