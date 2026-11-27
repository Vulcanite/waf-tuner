"""Optional retention for raw audit and inference artifacts in SQLite."""
import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, text, update

from db.models import (
    AnalysisCase, AnalysisRevision, AuditEvent, ExceptionDraft, IncidentOccurrence, InferenceAttempt, get_session_factory,
)

logger = logging.getLogger(__name__)

APPROVED_EVIDENCE_EXPIRED = (
    "The supporting audit evidence expired after approval. The rule was verified when it was approved."
)


def retention_days(name: str) -> int:
    days = int(os.getenv(name, "0"))
    if not 0 <= days <= 36500:
        raise ValueError(f"{name} must be between 0 and 36500")
    return days


async def prune_inference_artifacts(cutoff: datetime) -> int:
    batch_size = 500
    async with get_session_factory()() as session:
        finished_attempts = (
            select(InferenceAttempt.id).where(
                InferenceAttempt.completed_at < cutoff,
                InferenceAttempt.raw_response.is_not(None),
            ).limit(batch_size)
        )
        attempts = await session.execute(
            update(InferenceAttempt).where(InferenceAttempt.id.in_(finished_attempts)).values(raw_response=None)
        )
        finished_revisions = (
            select(AnalysisRevision.id).where(
                AnalysisRevision.completed_at < cutoff,
                AnalysisRevision.raw_response.is_not(None),
                AnalysisRevision.state.in_(["complete", "failed"]),
            ).limit(batch_size)
        )
        revisions = await session.execute(
            update(AnalysisRevision).where(AnalysisRevision.id.in_(finished_revisions)).values(raw_response=None)
        )
        await session.commit()
        return attempts.rowcount + revisions.rowcount


async def prune_audit_evidence(cutoff: datetime) -> int:
    async with get_session_factory()() as session:
        # Prevent a reanalysis claim between checking the old rows and expiring them.
        await session.execute(text("BEGIN IMMEDIATE"))
        active_case = (
            select(1).select_from(IncidentOccurrence)
            .join(AnalysisCase, IncidentOccurrence.analysis_case_id == AnalysisCase.id)
            .where(
                IncidentOccurrence.audit_event_id == AuditEvent.id,
                AnalysisCase.state.in_(["queued", "analyzing", "retryable_error"]),
            )
            .exists()
        )
        events = (await session.scalars(
            select(AuditEvent).where(
                AuditEvent.created_at < cutoff,
                AuditEvent.raw_event["evidence_expired"].as_boolean().is_not(True),
                ~active_case,
            ).order_by(AuditEvent.created_at, AuditEvent.id).limit(200)
        )).all()
        for event in events:
            evidence = event.raw_event
            uri = event.path or str(evidence.get("uri") or "/").partition("?")[0]
            uri = uri if uri.startswith("/") else "/"
            event.raw_event = {
                **{key: evidence[key] for key in (
                    "transaction_id", "timestamp", "method", "anomaly_score", "anomaly_score_source", "response_status",
                ) if key in evidence},
                "uri": uri,
                "matches": [{"rule_id": match.get("rule_id")} for match in evidence.get("matches", [])],
                "evidence_expired": True,
            }
        if events:
            lines = [event.event_line for event in events]
            transactions = [event.transaction_id for event in events]
            # An approved exclusion may already be deployed. It keeps its rule text, its revision and
            # its case so the operator can still copy and export it; only pending drafts go stale.
            approved_revisions = select(ExceptionDraft.analysis_revision_id).where(
                ExceptionDraft.status == "approved", ExceptionDraft.analysis_revision_id.is_not(None),
            )
            approved_cases = select(AnalysisRevision.analysis_case_id).where(AnalysisRevision.id.in_(approved_revisions))
            expired_cases = select(AnalysisCase.id).where(
                AnalysisCase.latest_event_line.in_(lines), AnalysisCase.id.not_in(approved_cases),
            )
            reason = "The supporting audit evidence expired."
            await session.execute(update(AnalysisRevision).where(
                AnalysisRevision.analysis_case_id.in_(expired_cases),
                AnalysisRevision.normalized_rule.is_not(None),
            ).values(normalized_rule=None, validation_status="evidence_expired", validation_error=reason))
            await session.execute(update(AnalysisCase).where(
                AnalysisCase.id.in_(expired_cases), AnalysisCase.state == "complete",
            ).values(state="stale", last_error=reason))
            await session.execute(
                update(AnalysisCase).where(AnalysisCase.latest_event_line.in_(lines)).values(matched_data="")
            )
            await session.execute(update(ExceptionDraft).where(
                ExceptionDraft.transaction_id.in_(transactions),
                ExceptionDraft.status == "pending",
                ExceptionDraft.classification == "false_positive",
            ).values(
                status="stale", proposed_rule=None, rule_placement=None,
                validation_status="evidence_expired", validation_error=reason,
            ))
            await session.execute(update(ExceptionDraft).where(
                ExceptionDraft.transaction_id.in_(transactions),
                ExceptionDraft.status == "approved",
                ExceptionDraft.classification == "false_positive",
            ).values(validation_error=APPROVED_EVIDENCE_EXPIRED))
        await session.commit()
        return len(events)


async def inference_retention_worker(days: int, audit_days: int) -> None:
    while True:
        removed = 0
        try:
            now = datetime.now(timezone.utc)
            if days:
                removed += await prune_inference_artifacts(now - timedelta(days=days))
            if audit_days:
                removed += await prune_audit_evidence(now - timedelta(days=audit_days))
        except Exception:
            logger.exception("Evidence retention failed")
        await asyncio.sleep(5 if removed else 3600)
