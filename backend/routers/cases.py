"""Deduplicated incident case and reanalysis APIs."""
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import (
    AnalysisCase, AnalysisRevision, ExceptionDraft, IncidentOccurrence, get_db,
)


router = APIRouter(prefix="/api/cases", tags=["cases"])


def _case_dict(case: AnalysisCase) -> dict:
    return {
        "id": case.id,
        "fingerprint": case.fingerprint,
        "method": case.method,
        "path": case.path,
        "rule_id": case.rule_id,
        "collection": case.collection,
        "parameter": case.parameter,
        "matched_data": case.matched_data,
        "occurrence_count": case.occurrence_count,
        "first_seen_at": case.first_seen_at.isoformat(),
        "last_seen_at": case.last_seen_at.isoformat(),
        "latest_event_line": case.latest_event_line,
        "state": case.state,
        "retry_count": case.retry_count,
        "next_retry_at": case.next_retry_at.isoformat() if case.next_retry_at else None,
        "last_error": case.last_error,
    }


def _revision_dict(revision: AnalysisRevision | None) -> Optional[dict]:
    if revision is None:
        return None
    return {
        "id": revision.id,
        "state": revision.state,
        "model": revision.model,
        "prompt_version": revision.prompt_version,
        "profile_version": revision.profile_version,
        "crs_digest": revision.crs_digest,
        "classification": revision.classification,
        "confidence": revision.confidence,
        "verdict": revision.verdict,
        "context_factors": revision.context_factors,
        "uncertainty_factors": revision.uncertainty_factors,
        "raw_proposed_rule": revision.raw_proposed_rule,
        "normalized_rule": revision.normalized_rule,
        "proposed_rule_scope": revision.proposed_rule_scope,
        "validation_status": revision.validation_status,
        "validation_error": revision.validation_error,
        "started_at": revision.started_at.isoformat() if revision.started_at else None,
        "completed_at": revision.completed_at.isoformat() if revision.completed_at else None,
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
            select(AnalysisCase)
            .where(*filters)
            .order_by(AnalysisCase.last_seen_at.desc())
            .offset((page - 1) * limit)
            .limit(limit)
        )
    ).scalars().all()
    return {"total": total, "page": page, "limit": limit, "items": [_case_dict(case) for case in cases]}


@router.get("/{case_id}")
async def get_case(case_id: int, db: AsyncSession = Depends(get_db)):
    case = await db.get(AnalysisCase, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    revisions = (
        await db.execute(
            select(AnalysisRevision)
            .where(AnalysisRevision.analysis_case_id == case_id)
            .order_by(AnalysisRevision.id.desc())
        )
    ).scalars().all()
    occurrences = (
        await db.execute(
            select(IncidentOccurrence)
            .where(IncidentOccurrence.analysis_case_id == case_id)
            .order_by(IncidentOccurrence.observed_at.desc())
            .limit(100)
        )
    ).scalars().all()
    return {
        **_case_dict(case),
        "revisions": [_revision_dict(revision) for revision in revisions],
        "occurrences": [
            {
                "id": occurrence.id,
                "transaction_id": occurrence.transaction_id,
                "event_line": occurrence.event_line,
                "match_index": occurrence.match_index,
                "observed_at": occurrence.observed_at.isoformat(),
            }
            for occurrence in occurrences
        ],
    }


@router.post("/{case_id}/reanalyze")
async def reanalyze_case(case_id: int, db: AsyncSession = Depends(get_db)):
    case = await db.get(AnalysisCase, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    if case.state == "analyzing":
        raise HTTPException(status_code=409, detail="Case is currently being analyzed")
    now = datetime.now(timezone.utc)
    case.state = "queued"
    case.retry_count = 0
    case.next_retry_at = None
    case.lease_expires_at = None
    case.last_error = None
    case.updated_at = now
    revision_ids = select(AnalysisRevision.id).where(AnalysisRevision.analysis_case_id == case_id)
    await db.execute(
        update(ExceptionDraft)
        .where(
            ExceptionDraft.analysis_revision_id.in_(revision_ids),
            ExceptionDraft.status.in_(["pending", "approved"]),
        )
        .values(status="stale")
    )
    await db.commit()
    return _case_dict(case)
