"""Incident identity, durable occurrence registration, and case deduplication."""
import hashlib
import hmac
import json
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from sqlalchemy import select
from sqlalchemy.dialects.sqlite import insert

from db.models import AnalysisCase, AuditEvent, IncidentOccurrence


_WITHIN_RE = re.compile(
    r"\bwithin\s+(?P<collection>[A-Z_]+)(?::(?P<parameter>[^\s,;]+))?",
    re.IGNORECASE,
)
_VARIABLE_RE = re.compile(
    r"\bvariable\s+(?P<collection>[A-Z_]+)(?::(?P<parameter>[^\s,)]+))?",
    re.IGNORECASE,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_timestamp(value) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
    return _utcnow()


def extract_match_target(matched_data: str) -> tuple[str | None, str | None]:
    """Return the ModSecurity collection and parameter named in log data."""
    text = matched_data or ""
    match = _WITHIN_RE.search(text) or _VARIABLE_RE.search(text)
    if not match:
        return None, None
    collection = match.group("collection").upper()
    parameter = match.group("parameter")
    if parameter:
        parameter = parameter.strip("'\"[]:.,")[:512]
    return collection, parameter or None


def normalized_path(uri: str) -> str:
    path = urlsplit(uri or "/").path or "/"
    return path if path.startswith("/") else f"/{path}"


def _normalize_matched_data(value) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return str(value or "").replace("\r\n", "\n").replace("\r", "\n")


def _request_payload_digest(event: dict) -> str:
    """Hash canonical query/body evidence so generic CRS matches do not collide."""
    uri = urlsplit(str(event.get("uri") or "/"))
    query = sorted(parse_qsl(uri.query, keep_blank_values=True))
    request = event.get("raw_request") or {}
    body = request.get("body", "")
    if isinstance(body, (dict, list)):
        canonical_body = body
    else:
        text_body = _normalize_matched_data(body)
        try:
            canonical_body = json.loads(text_body) if text_body else ""
        except (json.JSONDecodeError, TypeError):
            headers = request.get("headers") or {}
            content_type = next(
                (
                    str(value).lower()
                    for key, value in headers.items()
                    if str(key).lower() == "content-type"
                ),
                "",
            )
            if "application/x-www-form-urlencoded" in content_type:
                canonical_body = sorted(parse_qsl(text_body, keep_blank_values=True))
            else:
                canonical_body = text_body
    encoded = json.dumps(
        {"query": query, "body": canonical_body},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _fingerprint_key() -> bytes:
    configured = os.environ.get("INCIDENT_FINGERPRINT_KEY")
    if configured:
        return configured.encode("utf-8")

    data_dir = Path(os.environ.get("EVENTS_JSONL_PATH", "/shared/events.jsonl")).parent
    key_path = Path(os.environ.get("INCIDENT_FINGERPRINT_KEY_PATH", data_dir / "fingerprint.key"))
    key_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        return key_path.read_bytes().strip()
    except FileNotFoundError:
        key = secrets.token_hex(32).encode("ascii")
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(key + b"\n")
        return key


def incident_fingerprint(event: dict, match: dict) -> tuple[str, str | None, str | None]:
    collection, parameter = extract_match_target(match.get("matched_data", ""))
    identity = {
        "method": str(event.get("method") or "GET").upper(),
        "path": normalized_path(event.get("uri", "/")),
        "rule_id": str(match.get("rule_id") or ""),
        "collection": collection,
        "parameter": parameter,
        "matched_data": _normalize_matched_data(match.get("matched_data", "")),
        "request_payload_digest": _request_payload_digest(event),
    }
    encoded = json.dumps(
        identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hmac.new(_fingerprint_key(), encoded, hashlib.sha256).hexdigest(), collection, parameter


async def transaction_exists(session, transaction_id: str) -> bool:
    result = await session.execute(
        select(AuditEvent.id).where(AuditEvent.transaction_id == transaction_id)
    )
    return result.scalar_one_or_none() is not None


async def register_event(session, event: dict, event_line: int) -> bool:
    """Register a JSONL event and all signature occurrences atomically.

    Returns False when the transaction was already registered.
    """
    transaction_id = str(event.get("transaction_id") or "")
    if not transaction_id:
        raise ValueError("event has no transaction_id")

    observed_at = parse_timestamp(event.get("timestamp"))
    event_stmt = (
        insert(AuditEvent)
        .values(
            transaction_id=transaction_id,
            event_line=event_line,
            timestamp=observed_at,
            raw_event=event,
        )
        .on_conflict_do_nothing(index_elements=[AuditEvent.transaction_id])
        .returning(AuditEvent.id)
    )
    audit_event_id = (await session.execute(event_stmt)).scalar_one_or_none()
    if audit_event_id is None:
        return False

    for match_index, match in enumerate(event.get("matches") or []):
        rule_id = str(match.get("rule_id") or "")
        if not rule_id:
            continue
        fingerprint, collection, parameter = incident_fingerprint(event, match)
        now = _utcnow()
        case_stmt = (
            insert(AnalysisCase)
            .values(
                fingerprint=fingerprint,
                method=str(event.get("method") or "GET").upper(),
                path=normalized_path(event.get("uri", "/")),
                rule_id=rule_id,
                collection=collection,
                parameter=parameter,
                matched_data=_normalize_matched_data(match.get("matched_data", "")),
                occurrence_count=1,
                first_seen_at=observed_at,
                last_seen_at=observed_at,
                latest_event_line=event_line,
                state="queued",
                created_at=now,
                updated_at=now,
            )
            .on_conflict_do_update(
                index_elements=[AnalysisCase.fingerprint],
                set_={
                    "occurrence_count": AnalysisCase.occurrence_count + 1,
                    "last_seen_at": observed_at,
                    "latest_event_line": event_line,
                    "updated_at": now,
                },
            )
            .returning(AnalysisCase.id)
        )
        case_id = (await session.execute(case_stmt)).scalar_one()
        session.add(
            IncidentOccurrence(
                audit_event_id=audit_event_id,
                analysis_case_id=case_id,
                transaction_id=transaction_id,
                event_line=event_line,
                match_index=match_index,
                rule_id=rule_id,
                fingerprint=fingerprint,
                observed_at=observed_at,
            )
        )
    return True
