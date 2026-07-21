"""
Events Router — Phase 5

Serves events from events.jsonl. No database reads for event data.
"""
import json
import os
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from db.models import get_db, ExceptionDraft, AuditEvent

router = APIRouter(prefix="/api/events", tags=["events"])

EVENTS_JSONL_PATH = os.environ.get("EVENTS_JSONL_PATH", "/shared/events.jsonl")


async def _get_event_by_line(db: AsyncSession, line_num: int) -> Optional[dict]:
    """Return the event at the given 0-based line number."""
    result = await db.execute(
        select(AuditEvent.raw_event).where(AuditEvent.event_line == line_num)
    )
    return result.scalar_one_or_none()


@router.get("")
async def list_events(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=500),
    rule_id: Optional[str] = None,
    uri: Optional[str] = None,
    min_score: Optional[int] = None,
    max_score: Optional[int] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    from db.models import IncidentOccurrence
    stmt = select(AuditEvent)

    if rule_id:
        stmt = stmt.where(
            select(1)
            .select_from(IncidentOccurrence)
            .where(
                (IncidentOccurrence.audit_event_id == AuditEvent.id)
                & (IncidentOccurrence.rule_id == rule_id)
            )
            .exists()
        )
    if uri:
        stmt = stmt.where(AuditEvent.raw_event["uri"].as_string().ilike(f"%{uri}%"))
    if min_score is not None:
        stmt = stmt.where(AuditEvent.raw_event["anomaly_score"].as_integer() >= min_score)
    if max_score is not None:
        stmt = stmt.where(AuditEvent.raw_event["anomaly_score"].as_integer() <= max_score)
    if date_from:
        stmt = stmt.where(AuditEvent.timestamp >= date_from)
    if date_to:
        stmt = stmt.where(AuditEvent.timestamp <= date_to)

    # Count query
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    # Paginate
    stmt = stmt.order_by(AuditEvent.event_line.asc())
    stmt = stmt.offset((page - 1) * limit).limit(limit)
    result = await db.execute(stmt)
    events_rows = result.scalars().all()
    page_events = [row.raw_event for row in events_rows]

    # Enrich with draft_status
    txn_ids = [e.get("transaction_id") for e in page_events if e.get("transaction_id")]
    draft_map: dict[str, str] = {}
    if txn_ids:
        result = await db.execute(
            select(ExceptionDraft.transaction_id, ExceptionDraft.status)
            .where(ExceptionDraft.transaction_id.in_(txn_ids))
        )
        for txn_id, status in result:
            draft_map[txn_id] = status

    enriched = []
    for e in page_events:
        item = dict(e)
        item["draft_status"] = draft_map.get(e.get("transaction_id", ""))
        enriched.append(item)

    return {"total": total, "page": page, "limit": limit, "items": enriched}


@router.get("/{line}")
async def get_event(line: int, db: AsyncSession = Depends(get_db)):
    from fastapi import HTTPException
    event = await _get_event_by_line(db, line)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")

    draft = None
    txn_id = event.get("transaction_id")
    if txn_id:
        result = await db.execute(
            select(ExceptionDraft).where(ExceptionDraft.transaction_id == txn_id)
        )
        draft_row = result.scalars().first()
        if draft_row:
            draft = {
                "id": draft_row.id,
                "classification": draft_row.classification,
                "confidence": draft_row.confidence,
                "verdict": draft_row.verdict,
                "status": draft_row.status,
                "proposed_rule": draft_row.proposed_rule,
            }

    return {"line": line, "event": event, "draft": draft}
