"""
Events Router — Phase 5

Serves events from events.jsonl. No database reads for event data.
"""
import json
import os
import time
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from db.models import get_db, ExceptionDraft

router = APIRouter(prefix="/api/events", tags=["events"])

EVENTS_JSONL_PATH = os.environ.get("EVENTS_JSONL_PATH", "/app/data/events.jsonl")

# Simple in-memory cache for analytics scans (60-second TTL)
_analytics_cache: dict = {}
_analytics_ts: float = 0.0
ANALYTICS_TTL = 60.0


def _read_all_events() -> list[dict]:
    """Read all events from events.jsonl."""
    events = []
    path = os.environ.get("EVENTS_JSONL_PATH", EVENTS_JSONL_PATH)
    if not os.path.exists(path):
        return events
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def _get_event_by_line(line_num: int) -> Optional[dict]:
    """Return the event at the given 0-based line number."""
    path = os.environ.get("EVENTS_JSONL_PATH", EVENTS_JSONL_PATH)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        for i, line in enumerate(f):
            if i == line_num:
                try:
                    return json.loads(line.strip())
                except json.JSONDecodeError:
                    return None
    return None


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
    events = _read_all_events()

    # Apply filters
    if rule_id:
        events = [e for e in events if any(
            m.get("rule_id") == rule_id for m in e.get("matches", [])
        )]
    if uri:
        events = [e for e in events if uri.lower() in e.get("uri", "").lower()]
    if min_score is not None:
        events = [e for e in events if e.get("anomaly_score", 0) >= min_score]
    if max_score is not None:
        events = [e for e in events if e.get("anomaly_score", 0) <= max_score]
    if date_from:
        events = [e for e in events if e.get("timestamp", "") >= date_from]
    if date_to:
        events = [e for e in events if e.get("timestamp", "") <= date_to]

    total = len(events)
    start = (page - 1) * limit
    page_events = events[start:start + limit]

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
    event = _get_event_by_line(line)
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
