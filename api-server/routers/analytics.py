"""
Analytics Router — Phase 5

Computes analytics from events.jsonl with a 60-second in-memory cache.
"""
import json
import os
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import get_db, ExceptionDraft

router = APIRouter(prefix="/api/analytics", tags=["analytics"])

EVENTS_JSONL_PATH = os.environ.get("EVENTS_JSONL_PATH", "/app/data/events.jsonl")
_cache: dict = {}
_cache_ts: float = 0.0
CACHE_TTL = 60.0


def _load_events_cached() -> list[dict]:
    global _cache, _cache_ts
    now = time.time()
    if now - _cache_ts < CACHE_TTL and "events" in _cache:
        return _cache["events"]

    events = []
    path = os.environ.get("EVENTS_JSONL_PATH", EVENTS_JSONL_PATH)
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    _cache = {"events": events}
    _cache_ts = now
    return events


@router.get("/summary")
async def summary(db: AsyncSession = Depends(get_db)):
    events = _load_events_cached()
    total_events = len(events)

    counts = {}
    for status in ("pending", "approved", "deployed", "rejected", "stale"):
        r = await db.execute(
            select(func.count()).select_from(ExceptionDraft)
            .where(ExceptionDraft.status == status)
        )
        counts[status] = r.scalar() or 0

    total_drafts_r = await db.execute(select(func.count()).select_from(ExceptionDraft))
    total_drafts = total_drafts_r.scalar() or 0

    return {
        "total_events": total_events,
        "total_drafts": total_drafts,
        "pending_review": counts["pending"],
        "approved": counts["approved"],
        "deployed": counts["deployed"],
        "rejected": counts["rejected"],
        "stale": counts["stale"],
    }


@router.get("/top-rules")
async def top_rules():
    events = _load_events_cached()
    rule_counts: Counter = Counter()
    rule_messages: dict[str, str] = {}

    for e in events:
        for m in e.get("matches", []):
            rid = m.get("rule_id", "")
            if rid:
                rule_counts[rid] += 1
                if rid not in rule_messages:
                    rule_messages[rid] = m.get("rule_message", "")

    top = rule_counts.most_common(10)
    return [
        {"rule_id": rid, "count": cnt, "rule_message": rule_messages.get(rid, "")}
        for rid, cnt in top
    ]


@router.get("/top-uris")
async def top_uris():
    events = _load_events_cached()
    uri_counts: Counter = Counter()

    for e in events:
        uri = e.get("uri", "").split("?")[0]
        if uri:
            uri_counts[uri] += 1

    top = uri_counts.most_common(10)
    return [{"uri": uri, "count": cnt} for uri, cnt in top]


@router.get("/timeline")
async def timeline(
    interval: str = Query("hour", regex="^(hour|day)$"),
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
):
    events = _load_events_cached()
    buckets: Counter = Counter()

    for e in events:
        ts_str = e.get("timestamp", "")
        if not ts_str:
            continue
        try:
            # Handle both Z and +00:00 suffixes
            ts_str_clean = ts_str.replace("Z", "+00:00")
            ts = datetime.fromisoformat(ts_str_clean)
        except ValueError:
            continue

        if date_from and ts_str < date_from:
            continue
        if date_to and ts_str > date_to:
            continue

        if interval == "hour":
            bucket = ts.strftime("%Y-%m-%dT%H:00:00")
        else:
            bucket = ts.strftime("%Y-%m-%d")

        buckets[bucket] += 1

    sorted_buckets = sorted(buckets.items())
    return [{"time": t, "count": c} for t, c in sorted_buckets]
