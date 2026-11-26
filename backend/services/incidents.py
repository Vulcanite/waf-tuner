"""Incident identity, durable occurrence registration, and case deduplication."""
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from sqlalchemy import case, select
from sqlalchemy.dialects.sqlite import insert

from db.models import AnalysisCase, AuditEvent, IncidentOccurrence
from services.audit_event import parse_audit_timestamp
from services.inference_context import (
    is_aggregate_match,
    match_evidence,
    match_target,
    prepare_request_evidence,
    split_request_uri,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def normalized_path(uri: str) -> str:
    path = split_request_uri(uri or '/').path or '/'
    return path if path.startswith('/') else f'/{path}'


def _normalize_matched_data(value) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    return str(value or '').replace('\r\n', '\n').replace('\r', '\n')


@lru_cache(maxsize=8)
def _load_fingerprint_key(key_path: Path) -> bytes:
    key_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        return key_path.read_bytes().strip()
    except FileNotFoundError:
        key = secrets.token_hex(32).encode('ascii')
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(key + b'\n')
        return key


def _fingerprint_key() -> bytes:
    configured = os.environ.get('INCIDENT_FINGERPRINT_KEY')
    if configured:
        return configured.encode('utf-8')
    data_dir = Path(os.environ.get('EVENTS_JSONL_PATH', '/shared/events.jsonl')).parent
    return _load_fingerprint_key(Path(os.environ.get('INCIDENT_FINGERPRINT_KEY_PATH', data_dir / 'fingerprint.key')))


def _encode_identity(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def _transaction_identity(event: dict, request: dict) -> bytes:
    siblings = [
        (str(match.get('rule_id') or ''), *request['targets'][index])
        for index, match in enumerate(event.get('matches') or [])
    ]
    siblings = sorted(set(siblings), key=_encode_identity)
    shared = {
        'host': request['host'],
        'method': request['method'],
        'path': request['path'],
        'response_status': event.get('response_status'),
        'anomaly_score': event.get('anomaly_score'),
        'anomaly_score_source': event.get('anomaly_score_source'),
        'media_type': request['media_type'],
        'body_status': request['body_status'],
        'signatures': siblings,
    }
    return hashlib.sha256(_encode_identity(shared)).digest()


def _fallback_identity(event: dict, request: dict) -> bytes:
    # Generic detections have no exact target. Hash their raw request once so
    # differing traffic does not reuse a result solely on a fixed log message.
    fallback = {
        'query': request['query_items'],
        'request': event.get('raw_request') or {},
    }
    return hashlib.sha256(_encode_identity(fallback)).digest()


def _incident_fingerprint(match: dict, target, values: dict, payload_identity: bytes, key: bytes) -> tuple[str, str | None, str | None]:
    collection, parameter = target
    identity = _encode_identity({
        'rule_id': str(match.get('rule_id') or ''),
        'target': [collection, parameter],
        'matched_data': _normalize_matched_data(match.get('matched_data', '')),
        'values': values,
    })
    return hmac.new(key, b'evidence-v2\0' + payload_identity + identity, hashlib.sha256).hexdigest(), collection, parameter


def incident_fingerprint(event: dict, match: dict) -> tuple[str, str | None, str | None]:
    request = prepare_request_evidence(event)
    target = match_target(match)
    values = match_evidence(request, *target, match)
    identity = _transaction_identity(event, request)
    if not any(values.values()):
        identity += _fallback_identity(event, request)
    return _incident_fingerprint(match, target, values, identity, _fingerprint_key())


async def transaction_exists(session, transaction_id: str) -> bool:
    result = await session.execute(select(AuditEvent.id).where(AuditEvent.transaction_id == transaction_id))
    return result.scalar_one_or_none() is not None


async def register_event(session, event: dict, event_line: int) -> bool:
    """Register an audit transaction and detection occurrences atomically."""
    transaction_id = str(event.get('transaction_id') or '')
    if not transaction_id:
        raise ValueError('event has no transaction_id')
    observed_at = parse_audit_timestamp(event.get('timestamp')) or _utcnow()
    path = normalized_path(event.get('uri') or '/')
    statement = (
        insert(AuditEvent)
        .values(
            transaction_id=transaction_id,
            event_line=event_line,
            timestamp=observed_at,
            path=path,
            anomaly_score=event.get('anomaly_score'),
            raw_event=event,
        )
        .on_conflict_do_nothing(index_elements=[AuditEvent.transaction_id])
        .returning(AuditEvent.id)
    )
    audit_event_id = (await session.execute(statement)).scalar_one_or_none()
    if audit_event_id is None:
        return False

    detections = [
        (index, match) for index, match in enumerate(event.get('matches') or [])
        if match.get('rule_id') and not is_aggregate_match(match)
    ]
    if not detections:
        return True
    request = prepare_request_evidence(event)
    shared_identity = _transaction_identity(event, request)
    fingerprint_key = _fingerprint_key()
    fallback_identity = None
    now = _utcnow()
    for match_index, match in detections:
        rule_id = str(match['rule_id'])
        target = request['targets'][match_index]
        values = match_evidence(request, *target, match)
        payload_identity = shared_identity
        if not any(values.values()):
            if fallback_identity is None:
                fallback_identity = shared_identity + _fallback_identity(event, request)
            payload_identity = fallback_identity
        fingerprint, collection, parameter = _incident_fingerprint(match, target, values, payload_identity, fingerprint_key)
        statement = (
            insert(AnalysisCase)
            .values(
                fingerprint=fingerprint,
                application_host=request['host'],
                method=request['method'],
                path=path,
                rule_id=rule_id,
                collection=collection,
                parameter=parameter,
                matched_data=_normalize_matched_data(match.get('matched_data', '')),
                occurrence_count=1,
                first_seen_at=observed_at,
                last_seen_at=observed_at,
                latest_event_line=event_line,
                state='queued',
                enqueued_at=now,
                created_at=now,
                updated_at=now,
            )
            .on_conflict_do_update(
                index_elements=[AnalysisCase.fingerprint],
                set_={
                    'occurrence_count': AnalysisCase.occurrence_count + 1,
                    'first_seen_at': case((AnalysisCase.first_seen_at > observed_at, observed_at), else_=AnalysisCase.first_seen_at),
                    'last_seen_at': case((AnalysisCase.last_seen_at <= observed_at, observed_at), else_=AnalysisCase.last_seen_at),
                    'latest_event_line': case((AnalysisCase.last_seen_at <= observed_at, event_line), else_=AnalysisCase.latest_event_line),
                    'updated_at': now,
                },
            )
            .returning(AnalysisCase.id)
        )
        case_id = (await session.execute(statement)).scalar_one()
        session.add(IncidentOccurrence(
            audit_event_id=audit_event_id,
            analysis_case_id=case_id,
            transaction_id=transaction_id,
            event_line=event_line,
            match_index=match_index,
            rule_id=rule_id,
            fingerprint=fingerprint,
            observed_at=observed_at,
        ))
    return True
