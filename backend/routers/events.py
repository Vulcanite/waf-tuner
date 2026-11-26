"""Paginated transaction summaries and on-demand audit evidence."""
import json
from datetime import datetime, timezone
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import AuditEvent, ExceptionDraft, IncidentOccurrence, get_db

router = APIRouter(prefix="/api/events", tags=["events"])


def audit_path_column():
    raw_uri = AuditEvent.raw_event["uri"].as_string()
    query_start = func.instr(raw_uri, "?")
    legacy_path = case((query_start > 0, func.substr(raw_uri, 1, query_start - 1)), else_=raw_uri)
    return func.coalesce(AuditEvent.path, legacy_path)


def _as_utc(value: datetime):
    return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)


async def _get_event_by_line(db: AsyncSession, line_num: int) -> Optional[dict]:
    return (await db.execute(
        select(AuditEvent.raw_event).where(AuditEvent.event_line == line_num)
        .order_by(AuditEvent.id.desc()).limit(1)
    )).scalar_one_or_none()


@router.get("")
async def list_events(
    page: Annotated[int, Query(ge=1)] = 1,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    rule_id: Optional[str] = None,
    uri: Optional[str] = None,
    min_score: Optional[int] = None,
    max_score: Optional[int] = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    db: AsyncSession = Depends(get_db),
):
    filters = []
    matches = func.json_each(AuditEvent.raw_event, "$.matches").table_valued("value", joins_implicitly=True)
    match_rule = func.json_extract(matches.c.value, "$.rule_id")
    if rule_id:
        occurrence = select(1).where(
            IncidentOccurrence.audit_event_id == AuditEvent.id, IncidentOccurrence.rule_id == rule_id
        ).exists()
        # The audit entry also holds scoring rules intentionally excluded from the analysis queue.
        unqueued_match = select(1).select_from(matches).where(match_rule == rule_id).correlate(AuditEvent).exists()
        filters.append(occurrence | unqueued_match)
    path = audit_path_column()
    if uri:
        filters.append(path.ilike(f"%{uri}%"))
    score = func.coalesce(AuditEvent.anomaly_score, AuditEvent.raw_event["anomaly_score"].as_integer())
    if min_score is not None:
        filters.append(score >= min_score)
    if max_score is not None:
        filters.append(score <= max_score)
    if date_from:
        filters.append(AuditEvent.timestamp >= _as_utc(date_from))
    if date_to:
        filters.append(AuditEvent.timestamp <= _as_utc(date_to))

    total = await db.scalar(select(func.count()).select_from(AuditEvent).where(*filters))
    match_ids = (
        select(func.json_group_array(func.json_object("rule_id", match_rule)))
        .select_from(matches).correlate(AuditEvent).scalar_subquery()
    )
    draft_status = (
        select(ExceptionDraft.status).where(ExceptionDraft.transaction_id == AuditEvent.transaction_id)
        .order_by(ExceptionDraft.id.desc()).limit(1).correlate(AuditEvent).scalar_subquery()
    )
    rows = (await db.execute(
        select(
            AuditEvent.event_line, AuditEvent.transaction_id, AuditEvent.timestamp,
            AuditEvent.raw_event["method"].as_string(), path, score, match_ids, draft_status,
        )
        .where(*filters)
        .order_by(AuditEvent.event_line, AuditEvent.id)
        .offset((page - 1) * limit).limit(limit)
    )).all()
    items = [
        {
            "event_line": line, "transaction_id": transaction, "timestamp": _as_utc(timestamp).isoformat() if timestamp else None,
            "method": method, "uri": uri_path, "anomaly_score": anomaly, "matches": json.loads(ids or "[]"),
            "draft_status": status,
        }
        for line, transaction, timestamp, method, uri_path, anomaly, ids, status in rows
    ]
    return {"total": total, "page": page, "limit": limit, "items": items}


@router.get("/{line}")
async def get_event(line: int, db: AsyncSession = Depends(get_db)):
    event = await _get_event_by_line(db, line)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")

    draft = None
    if event.get("transaction_id"):
        draft_row = await db.scalar(select(ExceptionDraft).where(
            ExceptionDraft.transaction_id == event["transaction_id"]
        ).order_by(ExceptionDraft.id.desc()).limit(1))
        if draft_row:
            draft = {
                "id": draft_row.id,
                "classification": draft_row.classification,
                "confidence": draft_row.confidence,
                "verdict": draft_row.verdict,
                "status": draft_row.status,
                "proposed_rule": None,
            }
    return {"line": line, "event": event, "draft": draft}
