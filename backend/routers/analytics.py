"""
Analytics Router — Phase 5

Computes analytics from events.jsonl with a 60-second in-memory cache.
"""
import json
import os
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import AnalysisCase, AnalysisRevision, ExceptionDraft, InferenceAttempt, get_db
from services.agent import PROMPT_SHA256, PROMPT_VERSION, public_model_settings, request_budget

router = APIRouter(prefix="/api/analytics", tags=["analytics"])

EVENTS_JSONL_PATH = os.environ.get("EVENTS_JSONL_PATH", "/shared/events.jsonl")
_cache: dict = {}
_cache_ts: float = 0.0
CACHE_TTL = 60.0


def _grouped(rows) -> dict[str, int]:
    return {str(key or "none"): int(count) for key, count in rows}


@router.get("/analysis-health")
async def analysis_health(db: AsyncSession = Depends(get_db)):
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=1)
    case_states = _grouped((await db.execute(
        select(AnalysisCase.state, func.count()).group_by(AnalysisCase.state)
    )).all())
    revision_states = _grouped((await db.execute(
        select(AnalysisRevision.state, func.count()).group_by(AnalysisRevision.state)
    )).all())
    error_codes = _grouped((await db.execute(
        select(AnalysisRevision.error_code, func.count())
        .where(AnalysisRevision.error_code.is_not(None))
        .group_by(AnalysisRevision.error_code)
    )).all())
    active_attempts = int((await db.execute(
        select(func.count()).select_from(InferenceAttempt).where(InferenceAttempt.status == "active")
    )).scalar_one())
    oldest_queued = (await db.execute(
        select(func.min(AnalysisCase.created_at)).where(
            AnalysisCase.state.in_(["queued", "retryable_error"])
        )
    )).scalar_one_or_none()
    last_success = (await db.execute(
        select(func.max(AnalysisRevision.completed_at)).where(AnalysisRevision.state == "complete")
    )).scalar_one_or_none()
    valid = int((await db.execute(
        select(func.count()).select_from(AnalysisRevision).where(
            AnalysisRevision.state == "complete", AnalysisRevision.error_code.is_(None)
        )
    )).scalar_one())
    invalid = int((await db.execute(
        select(func.count()).select_from(AnalysisRevision).where(AnalysisRevision.error_code == "invalid_output")
    )).scalar_one())
    initial = int((await db.execute(
        select(func.count()).select_from(InferenceAttempt).where(InferenceAttempt.attempt_type == "initial")
    )).scalar_one())
    repairs = int((await db.execute(
        select(func.count()).select_from(InferenceAttempt).where(InferenceAttempt.attempt_type == "repair")
    )).scalar_one())
    used = int((await db.execute(
        select(func.count()).select_from(InferenceAttempt).where(InferenceAttempt.started_at >= cutoff)
    )).scalar_one())
    budget = request_budget()
    settings = public_model_settings()
    return {
        "worker_count": max(1, min(16, int(os.environ.get("AGENT_WORKER_CONCURRENCY", "4")))),
        "hourly_budget": budget,
        "cases_by_state": case_states,
        "revisions_by_state": revision_states,
        "revisions_by_error_code": error_codes,
        "active_attempts": active_attempts,
        "oldest_queued_at": oldest_queued.isoformat() if oldest_queued else None,
        "last_successful_completion": last_success.isoformat() if last_success else None,
        "valid_output_rate": valid / (valid + invalid) if valid + invalid else None,
        "repair_rate": repairs / initial if initial else None,
        "hourly_requests_used": used,
        "hourly_requests_remaining": max(0, budget - used),
        "model": settings["model"],
        "prompt_version": PROMPT_VERSION,
        "prompt_sha256": PROMPT_SHA256,
        "structured_output": settings["structured_output"],
        "paused_by_budget": used >= budget,
    }


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
    for status in ("pending", "approved", "rejected"):
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
        "ready_to_copy": counts["approved"],
        "rejected": counts["rejected"],
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
    interval: str = Query("hour", pattern="^(hour|day)$"),
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
