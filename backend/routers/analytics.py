"""Indexed audit summaries and stage timing statistics from SQLite."""
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import Integer, cast, func, literal, select, true, union_all
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import AnalysisCase, AnalysisRevision, AuditEvent, ExceptionDraft, InferenceAttempt, get_db
from services.agent import PROMPT_SHA256, PROMPT_VERSION, public_model_settings, request_budget
from services.crs_index import index_status
from routers.events import _as_utc, audit_path_column

router = APIRouter(prefix="/api/analytics", tags=["analytics"])

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
    # One aggregate query per table; FILTER keeps each count's own condition.
    oldest_queued = (await db.execute(
        select(func.min(func.coalesce(AnalysisCase.enqueued_at, AnalysisCase.created_at))).where(
            AnalysisCase.state.in_(["queued", "retryable_error"])
        )
    )).scalar_one_or_none()
    last_success, valid, invalid = (await db.execute(
        select(
            func.max(AnalysisRevision.completed_at).filter(AnalysisRevision.state == "complete"),
            func.count().filter(
                AnalysisRevision.state == "complete", AnalysisRevision.error_code.is_(None)
            ),
            func.count().filter(AnalysisRevision.error_code == "invalid_output"),
        )
    )).one()
    active_attempts, initial, repairs, used, first_attempt = (await db.execute(
        select(
            func.count().filter(InferenceAttempt.status == "active"),
            func.count().filter(InferenceAttempt.attempt_type == "initial"),
            func.count().filter(InferenceAttempt.attempt_type == "repair"),
            func.count().filter(InferenceAttempt.started_at >= cutoff),
            func.min(InferenceAttempt.started_at).filter(InferenceAttempt.started_at >= cutoff),
        )
    )).one()
    budget = request_budget()
    settings = public_model_settings()
    timings = await _stage_timings(db, cutoff)
    return {
        "worker_count": max(1, min(16, int(os.environ.get("AGENT_WORKER_CONCURRENCY", "4")))),
        "configuration_error": settings.get("configuration_error"),
        "hourly_budget": budget,
        "cases_by_state": case_states,
        "revisions_by_state": revision_states,
        "revisions_by_error_code": error_codes,
        "active_attempts": active_attempts,
        "oldest_queued_at": _as_utc(oldest_queued).isoformat() if isinstance(oldest_queued, datetime) else oldest_queued,
        "last_successful_completion": _as_utc(last_success).isoformat() if last_success else None,
        "valid_output_rate": valid / (valid + invalid) if valid + invalid else None,
        "repair_rate": repairs / initial if initial else None,
        "hourly_requests_used": used,
        "hourly_requests_remaining": max(0, budget - used),
        "model": settings["model"],
        "prompt_version": PROMPT_VERSION,
        "prompt_sha256": PROMPT_SHA256,
        "structured_output": settings["structured_output"],
        "paused_by_budget": used >= budget,
        "budget_resumes_at": (_as_utc(first_attempt) + timedelta(hours=1)).isoformat()
        if used >= budget and first_attempt else None,
        "stages_last_hour": timings,
        "crs_rules": index_status(),
    }


async def _stage_timings(db: AsyncSession, cutoff: datetime) -> dict:
    metric = func.json_each(AnalysisRevision.stage_metrics).table_valued("key", "value", "type")
    samples = [
        select(metric.c.key.label("stage"), metric.c.value.label("value"))
        .select_from(AnalysisRevision).join(metric, true())
        .where(AnalysisRevision.completed_at >= cutoff, metric.c.type.in_(["integer", "real"]))
    ]
    for name, column in (
        ("provider_ms", InferenceAttempt.provider_ms),
        ("prompt_tokens", InferenceAttempt.prompt_tokens),
        ("completion_tokens", InferenceAttempt.completion_tokens),
        ("reasoning_tokens", InferenceAttempt.reasoning_tokens),
    ):
        samples.append(select(literal(name).label("stage"), column.label("value")).where(
            InferenceAttempt.started_at >= cutoff, column.is_not(None)
        ))
    samples = union_all(*samples).subquery()
    ranked = select(
        samples.c.stage, samples.c.value,
        func.row_number().over(partition_by=samples.c.stage, order_by=samples.c.value).label("rank"),
        func.count().over(partition_by=samples.c.stage).label("samples"),
    ).subquery()
    rows = (await db.execute(select(
        ranked.c.stage,
        func.max(ranked.c.samples),
        func.max(ranked.c.value).filter(ranked.c.rank == cast((ranked.c.samples + 1) / 2, Integer)),
        func.max(ranked.c.value).filter(ranked.c.rank == cast((ranked.c.samples * 95 + 99) / 100, Integer)),
    ).group_by(ranked.c.stage))).all()
    return {stage: {"samples": n, "p50": p50, "p95": p95} for stage, n, p50, p95 in rows}


@router.get("/summary")
async def summary(db: AsyncSession = Depends(get_db)):
    total_events = await db.scalar(select(func.count()).select_from(AuditEvent))
    total, pending, approved, ready, rejected = (await db.execute(select(
        func.count(),
        func.count().filter(ExceptionDraft.status == "pending"),
        func.count().filter(ExceptionDraft.status == "approved"),
        func.count().filter(
            ExceptionDraft.status == "approved", ExceptionDraft.validation_status == "valid",
            ExceptionDraft.proposed_rule.is_not(None),
        ),
        func.count().filter(ExceptionDraft.status == "rejected"),
    ))).one()
    return {
        "total_events": total_events, "total_drafts": total, "pending_review": pending,
        "approved": approved, "ready_to_copy": ready, "rejected": rejected,
    }


@router.get("/top-rules")
async def top_rules(db: AsyncSession = Depends(get_db)):
    matches = func.json_each(AuditEvent.raw_event, "$.matches").table_valued("value")
    rule = func.json_extract(matches.c.value, "$.rule_id")
    message = func.json_extract(matches.c.value, "$.rule_message")
    count = func.count()
    rows = (await db.execute(
        select(rule, count, func.min(message)).select_from(AuditEvent).join(matches, true())
        .where(rule.is_not(None), rule != "").group_by(rule).order_by(count.desc(), rule).limit(10)
    )).all()
    return [{"rule_id": rule_id, "count": n, "rule_message": text or ""} for rule_id, n, text in rows]


@router.get("/top-uris")
async def top_uris(db: AsyncSession = Depends(get_db)):
    path = audit_path_column()
    count = func.count()
    rows = (await db.execute(
        select(path, count).where(path.is_not(None), path != "")
        .group_by(path).order_by(count.desc(), path).limit(10)
    )).all()
    return [{"uri": uri, "count": n} for uri, n in rows]


@router.get("/timeline")
async def timeline(
    interval: str = Query("hour", pattern="^(hour|day)$"),
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    db: AsyncSession = Depends(get_db),
):
    label = "%Y-%m-%dT%H:00:00Z" if interval == "hour" else "%Y-%m-%d"
    bucket = func.strftime(label, AuditEvent.timestamp)
    filters = [AuditEvent.timestamp.is_not(None)]
    if date_from is not None:
        filters.append(AuditEvent.timestamp >= _as_utc(date_from))
    if date_to is not None:
        filters.append(AuditEvent.timestamp <= _as_utc(date_to))
    rows = (await db.execute(
        select(bucket, func.count()).where(*filters).group_by(bucket).order_by(bucket.desc()).limit(366)
    )).all()
    return [{"time": time_bucket, "count": n} for time_bucket, n in reversed(rows) if time_bucket]
