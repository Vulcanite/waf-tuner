"""Deduplicated incident case and reanalysis APIs."""
from datetime import datetime, timezone
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defer

from db.models import (
    AnalysisCase, AnalysisRevision, AuditEvent, ExceptionDraft, IncidentOccurrence, get_db,
)
from routers.events import _as_utc
from services import agent

router = APIRouter(prefix="/api/cases", tags=["cases"])


def _case_dict(case: AnalysisCase, *, include_evidence: bool = True) -> dict:
    return {
        "id": case.id,
        "fingerprint": case.fingerprint,
        "method": case.method,
        "path": case.path,
        "rule_id": case.rule_id,
        "collection": case.collection,
        "parameter": case.parameter,
        "matched_data": case.matched_data if include_evidence else None,
        "application_host": case.application_host,
        "occurrence_count": case.occurrence_count,
        "first_seen_at": _as_utc(case.first_seen_at).isoformat(),
        "last_seen_at": _as_utc(case.last_seen_at).isoformat(),
        "latest_event_line": case.latest_event_line,
        "state": case.state,
        "retry_count": case.retry_count,
        "next_retry_at": _as_utc(case.next_retry_at).isoformat() if case.next_retry_at else None,
        "last_error": case.last_error,
        "budget_deferred": bool(case.state == "queued" and case.next_retry_at and case.last_error),
    }


def _revision_dict(revision: AnalysisRevision | None, *, include_rule: bool = False) -> Optional[dict]:
    if revision is None:
        return None
    return {
        "id": revision.id,
        "state": revision.state,
        "model": revision.model,
        "prompt_version": revision.prompt_version,
        "prompt_sha256": revision.prompt_sha256,
        "model_settings": revision.model_settings,
        "error_code": revision.error_code,
        "profile_version": revision.profile_version,
        "crs_digest": revision.crs_digest,
        "classification": revision.classification,
        "confidence": revision.confidence,
        "verdict": revision.verdict,
        "context_factors": revision.context_factors,
        "uncertainty_factors": revision.uncertainty_factors,
        "normalized_rule": revision.normalized_rule if include_rule else None,
        "proposed_rule_scope": revision.proposed_rule_scope,
        "validation_status": revision.validation_status,
        "validation_error": revision.validation_error,
        "started_at": _as_utc(revision.started_at).isoformat() if revision.started_at else None,
        "completed_at": _as_utc(revision.completed_at).isoformat() if revision.completed_at else None,
    }


@router.get("")
async def list_cases(
    state: Optional[str] = None,
    rule_id: Optional[str] = None,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    filters = []
    if state:
        filters.append(AnalysisCase.state == state)
    if rule_id:
        filters.append(AnalysisCase.rule_id == rule_id)
    total = (
        await db.execute(select(func.count()).select_from(AnalysisCase).where(*filters))
    ).scalar_one()
    cases = (
        await db.execute(
            select(AnalysisCase).options(defer(AnalysisCase.matched_data))
            .where(*filters)
            .order_by(AnalysisCase.last_seen_at.desc(), AnalysisCase.id.desc())
            .offset((page - 1) * limit)
            .limit(limit)
        )
    ).scalars().all()
    return {"total": total, "page": page, "limit": limit, "items": [_case_dict(case, include_evidence=False) for case in cases]}


def _latest_evidence_expired(case_id: int):
    latest = (
        select(AuditEvent.raw_event["evidence_expired"].as_boolean())
        .join(IncidentOccurrence, IncidentOccurrence.audit_event_id == AuditEvent.id)
        .where(IncidentOccurrence.analysis_case_id == case_id)
        .order_by(IncidentOccurrence.observed_at.desc(), IncidentOccurrence.id.desc())
        .limit(1)
        .scalar_subquery()
    )
    return func.coalesce(latest, False)


@router.get("/{case_id}")
async def get_case(
    case_id: int,
    db: AsyncSession = Depends(get_db),
    revision_limit: Annotated[int, Query(ge=1, le=100)] = 25,
    before_revision: Annotated[int | None, Query(ge=1)] = None,
):
    case = await db.get(AnalysisCase, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    revisions_query = (
        select(AnalysisRevision)
        .options(defer(AnalysisRevision.context), defer(AnalysisRevision.raw_response),
                 defer(AnalysisRevision.pending_repair_input))
        .where(AnalysisRevision.analysis_case_id == case_id)
        .order_by(AnalysisRevision.id.desc())
        .limit(revision_limit + 1)
    )
    if before_revision is not None:
        revisions_query = revisions_query.where(AnalysisRevision.id < before_revision)
    revisions = (await db.scalars(revisions_query)).all()
    occurrences = (
        await db.execute(
            select(IncidentOccurrence)
            .where(IncidentOccurrence.analysis_case_id == case_id)
            .order_by(IncidentOccurrence.observed_at.desc(), IncidentOccurrence.id.desc())
            .limit(100)
        )
    ).scalars().all()
    expired = bool(await db.scalar(select(_latest_evidence_expired(case_id))))
    generation = agent.current_analysis_generation()
    current_rule = not expired and case.state == "complete" and bool(generation and generation == case.completed_generation)
    return {
        **_case_dict(case, include_evidence=not expired),
        "evidence_expired": expired,
        "revisions": [
            _revision_dict(revision, include_rule=current_rule and index == 0 and before_revision is None)
            for index, revision in enumerate(revisions[:revision_limit])
        ],
        "next_revision": revisions[revision_limit - 1].id if len(revisions) > revision_limit else None,
        "occurrences": [
            {
                "id": occurrence.id,
                "transaction_id": occurrence.transaction_id,
                "event_line": occurrence.event_line,
                "match_index": occurrence.match_index,
                "observed_at": _as_utc(occurrence.observed_at).isoformat(),
            }
            for occurrence in occurrences
        ],
    }


@router.post("/{case_id}/reanalyze")
async def reanalyze_case(case_id: int, db: AsyncSession = Depends(get_db)):
    now = datetime.now(timezone.utc)
    case = (await db.scalars(
        update(AnalysisCase)
        .where(
            AnalysisCase.id == case_id, AnalysisCase.state != "analyzing",
            _latest_evidence_expired(case_id).is_(False),
        )
        .values(
            state="queued", retry_count=0, next_retry_at=None, lease_expires_at=None,
            lease_token=None, last_error=None, enqueued_at=now, updated_at=now,
        )
        .returning(AnalysisCase)
    )).one_or_none()
    if case is None:
        if await db.get(AnalysisCase, case_id) is None:
            raise HTTPException(status_code=404, detail="Case not found")
        if await db.scalar(select(_latest_evidence_expired(case_id))):
            raise HTTPException(status_code=409, detail="Audit evidence expired. Capture a new occurrence to analyze this case.")
        raise HTTPException(status_code=409, detail="Case is currently being analyzed")
    await db.execute(update(AnalysisRevision).where(
        AnalysisRevision.analysis_case_id == case_id,
        AnalysisRevision.pending_repair_input.is_not(None),
    ).values(pending_repair_input=None))
    revision_ids = select(AnalysisRevision.id).where(AnalysisRevision.analysis_case_id == case_id)
    await db.execute(
        update(ExceptionDraft)
        .where(
            ExceptionDraft.analysis_revision_id.in_(revision_ids),
            ExceptionDraft.status.in_(["pending", "approved"]),
        )
        .values(status="stale", proposed_rule=None, rule_placement=None)
    )
    await db.commit()
    agent.analysis_queue_changed.set()
    return _case_dict(case)
