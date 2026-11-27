"""Review and export evidence-backed ModSecurity exception drafts."""
import csv
import io
import json
from datetime import datetime, timezone
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Query, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defer

from db.models import AnalysisCase, AnalysisRevision, AuditEvent, ExceptionDraft, get_db, get_session_factory
from services.agent import current_analysis_generation
from services.application_context import active_application_profiles, application_context_for, profile_is_current
from services.crs_index import get_rule
from services.draft_scope import canonical_scope_key, case_exception_scope, rule_numeric_id
from services.exception_builder import build_exception_rule, can_build_exception
from services.scope_conflicts import (
    SCOPE_CONFLICT_ERROR, has_true_positive,
)

router = APIRouter(prefix="/api/exceptions", tags=["exceptions"])


async def _get_draft_event(db: AsyncSession, draft: ExceptionDraft) -> Optional[dict]:
    result = await db.execute(
        select(AuditEvent.raw_event).where(AuditEvent.transaction_id == draft.transaction_id)
    )
    return result.scalar_one_or_none()


def _current_crs_rule(case: AnalysisCase, revision: AnalysisRevision) -> bool:
    crs = get_rule(case.rule_id)
    if crs is None or crs.chain or revision.crs_digest != crs.signature:
        return False
    ruleset_digest = (revision.model_settings or {}).get("ruleset_digest")
    return ruleset_digest is None or ruleset_digest == getattr(crs, "ruleset_digest", None)


def _certified_rule(draft, case, revision, generation) -> bool:
    if case is None or revision is None or case.state != "complete" or revision.state != "complete":
        return False
    scope = case_exception_scope(case)
    return bool(
        generation and case.completed_generation == generation
        and can_build_exception(scope)[0]
        and canonical_scope_key(scope) == draft.scope_key == canonical_scope_key(draft.proposed_rule_scope or {})
        and revision.classification == "false_positive" and revision.validation_status == "valid"
        and draft.proposed_rule == build_exception_rule(scope) == revision.normalized_rule
        and draft.rule_numeric_id == rule_numeric_id(draft.proposed_rule)
        and _current_crs_rule(case, revision)
    )


async def _case_profile_is_current(db, case, revision) -> bool:
    """The profile check from the case's own host, method and path, for evidence that has expired."""
    profile, _ = application_context_for(
        await active_application_profiles(db), case.application_host, case.method, case.path,
    )
    observed = (profile.id, profile.version) if profile else (None, None)
    return observed == (revision.application_profile_id, revision.profile_version)


async def _current_evidence(db, draft, case, revision, event, *, approved: bool = False) -> bool:
    """Whether the draft's rule can still be shown, copied or approved.

    Approval needs the audit evidence. An already approved rule keeps working after retention
    expires that evidence: the rule, ruleset, profile and true-positive checks still apply.
    """
    if event is None:
        return False
    expired = bool(event.get("evidence_expired"))
    if expired and not approved:
        return False
    if not _certified_rule(draft, case, revision, current_analysis_generation()):
        return False
    if expired:
        profile_current = await _case_profile_is_current(db, case, revision)
    else:
        profile_current = await profile_is_current(db, event, revision.application_profile_id, revision.profile_version)
    return profile_current and not await has_true_positive(db, case, draft.proposed_rule_scope or {}, revision=revision)


def _matching_evidence(matches: list, scope: dict) -> dict | None:
    index = scope.get("match_index")
    rule_id = str(scope.get("rule_id") or "")
    if isinstance(index, int) and 0 <= index < len(matches) and str(matches[index].get("rule_id")) == rule_id:
        return matches[index]
    candidates = [match for match in matches if str(match.get("rule_id")) == rule_id]
    return candidates[0] if len(candidates) == 1 else None


def _draft_to_dict(
    d: ExceptionDraft,
    event: Optional[dict] = None,
    *,
    case: Optional[AnalysisCase] = None,
    revision: Optional[AnalysisRevision] = None,
    crs_meta: Optional[dict] = None,
    summary: bool = False,
) -> dict:
    scope = d.proposed_rule_scope or {}
    # Prefer ground-truth case fields for zone display.
    zone = {
        "uri": (case.path if case else None) or scope.get("uri"),
        "collection": (case.collection if case else None) or scope.get("collection"),
        "parameter": (case.parameter if case else None) or scope.get("parameter"),
        "rule_id": (case.rule_id if case else None) or scope.get("rule_id"),
        "method": scope.get("method") or (case.method if case else (event.get("method") if event else None)),
        "host": scope.get("host"),
        "match_index": scope.get("match_index"),
        "sibling_rule_ids": scope.get("sibling_rule_ids") or [],
    }
    this_match = _matching_evidence((event or {}).get("matches") or [], zone)

    return {
        "id": d.id,
        "transaction_id": d.transaction_id,
        "event_line": d.event_line,
        "classification": d.classification,
        "confidence": d.confidence,
        "verdict": d.verdict,
        "crs_rule_raw": None if summary else d.crs_rule_raw,
        "proposed_rule": d.proposed_rule if not summary and d.status in {"pending", "approved"}
        and d.validation_status == "valid" else None,
        "proposed_rule_scope": d.proposed_rule_scope,
        "status": d.status,
        "rejection_reason": d.rejection_reason,
        "created_at": d.created_at.isoformat() if d.created_at else None,
        "reviewed_at": d.reviewed_at.isoformat() if d.reviewed_at else None,
        "last_seen_at": d.last_seen_at.isoformat() if d.last_seen_at else None,
        "supporting_case_count": d.supporting_case_count or 1,
        "scope_key": d.scope_key,
        "rule_numeric_id": d.rule_numeric_id,
        "analysis_revision_id": d.analysis_revision_id,
        "analysis_case_id": case.id if case else (
            revision.analysis_case_id if revision else None
        ),
        "validation_status": d.validation_status,
        "validation_error": d.validation_error,
        "rule_placement": d.rule_placement,
        "zone": zone,
        "this_match": this_match,
        "signature": crs_meta,
        # The explanation copied with the verdict; null on drafts made before offpath-v8.
        **{key: getattr(d, key) for key in ("rule_looks_for", "payload_is", "why")},
        "uncertainty_factors": revision.uncertainty_factors if revision else None,
        "event_summary": {
            "uri": event.get("uri") if event else None,
            "method": event.get("method") if event else None,
            "timestamp": event.get("timestamp") if event else None,
            "anomaly_score": event.get("anomaly_score") if event else None,
            "evidence_expired": event.get("evidence_expired", False),
            "matches": event.get("matches") if event else None,
            "raw_request": event.get("raw_request") if event else None,
        } if event else None,
        "evidence": _parse_matched_evidence(
            (this_match or {}).get("matched_data") if this_match else None
        ),
    }


def _parse_matched_evidence(matched_data: Optional[str]) -> Optional[dict]:
    """Split ModSecurity matched_data into snippet vs inspected value when possible.

    Typical form:
      Matched Data: <snippet> found within ARGS:body: <full value>
    """
    text = (matched_data or "").strip() if isinstance(matched_data, str) else (json.dumps(matched_data) if matched_data else "")
    if not text:
        return None
    lower = text.lower()
    within = " found within "
    if within in lower:
        idx = lower.index(within)
        left = text[:idx]
        right = text[idx + len(within) :]
        snippet = left
        for prefix in ("Matched Data:", "Matched data:", "matched data:"):
            if snippet.startswith(prefix):
                snippet = snippet[len(prefix) :].strip()
                break
        variable = right
        full_value = None
        # ARGS:q: value  or  ARGS:body: value
        if ":" in right:
            parts = right.split(":", 2)
            if len(parts) >= 3:
                variable = f"{parts[0]}:{parts[1]}"
                full_value = parts[2].lstrip()
            elif len(parts) == 2:
                variable = parts[0]
                full_value = parts[1].lstrip()
        return {
            "raw": text,
            "snippet": snippet or None,
            "variable": variable or None,
            "full_value": full_value,
        }
    return {"raw": text, "snippet": text, "variable": None, "full_value": None}


async def _enrich_draft(db: AsyncSession, d: ExceptionDraft) -> dict:
    event = await _get_draft_event(db, d)
    revision = None
    case = None
    if d.analysis_revision_id:
        revision = await db.get(AnalysisRevision, d.analysis_revision_id, options=(
            defer(AnalysisRevision.context), defer(AnalysisRevision.raw_response), defer(AnalysisRevision.pending_repair_input),
        ))
        if revision:
            case = await db.get(AnalysisCase, revision.analysis_case_id, options=(defer(AnalysisCase.matched_data),))
    rule_id = (case.rule_id if case else None) or (d.proposed_rule_scope or {}).get("rule_id")
    crs = get_rule(str(rule_id)) if rule_id else None
    crs_meta = None
    if crs and (not d.crs_rule_raw or d.crs_rule_raw == crs.raw):
        op = (crs.operator or "").strip()
        op_name = op.split(None, 1)[0] if op else ""
        op_body = op[len(op_name) :].strip() if op_name else op
        # Keep the full operator available; UI shows a short summary by default.
        op_summary = op_body
        if len(op_summary) > 120:
            op_summary = op_summary[:117] + "…"
        crs_meta = {
            "rule_id": crs.rule_id,
            "message": crs.message,
            "operator": crs.operator,
            "operator_name": op_name,
            "operator_summary": op_summary,
            "targets": crs.targets,
            "tags": crs.tags,
            "paranoia_level": crs.paranoia_level,
            "severity": crs.severity,
            "phase": crs.phase,
            "chain": crs.chain,
        }
    elif d.crs_rule_raw:
        crs_meta = {"rule_id": rule_id, "message": "", "raw_available": True}
    result = _draft_to_dict(d, event, case=case, revision=revision, crs_meta=crs_meta)
    if d.status == "approved" and not await _current_evidence(db, d, case, revision, event, approved=True):
        result.update(
            status="stale", proposed_rule=None, rule_placement=None, validation_status="stale_context",
            validation_error="The current rule or application evidence could not be verified. Reanalyze this case.",
        )
    return result


@router.get("")
async def list_exceptions(
    status: Optional[str] = None,
    classification: Optional[str] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    limit: Annotated[int, Query(ge=1, le=200)] = 20,
    db: AsyncSession = Depends(get_db),
):
    filters = []
    if status:
        filters.append(ExceptionDraft.status == status)
    if classification:
        filters.append(ExceptionDraft.classification == classification)
    total = await db.scalar(select(func.count()).select_from(ExceptionDraft).where(*filters))
    drafts = (await db.scalars(
        select(ExceptionDraft)
        .options(defer(ExceptionDraft.crs_rule_raw), defer(ExceptionDraft.proposed_rule))
        .where(*filters)
        .order_by(ExceptionDraft.created_at.desc(), ExceptionDraft.id.desc())
        .offset((page - 1) * limit).limit(limit)
    )).all()

    items = [_draft_to_dict(d, summary=True) for d in drafts]

    return {"total": total, "page": page, "limit": limit, "items": items}


def _csv_safe(value) -> str:
    """Stop spreadsheet apps from running attacker-controlled payloads as formulas."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


@router.get("/export/false-positives")
async def export_false_positives(
    status: Optional[str] = None,
):
    """Stream matched evidence for false-positive review without request bodies."""
    stmt = (
        select(
            ExceptionDraft, AuditEvent.raw_event["matches"], AuditEvent.timestamp, AnalysisCase, AnalysisRevision,
        )
        .outerjoin(AuditEvent, AuditEvent.transaction_id == ExceptionDraft.transaction_id)
        .outerjoin(AnalysisRevision, AnalysisRevision.id == ExceptionDraft.analysis_revision_id)
        .outerjoin(AnalysisCase, AnalysisCase.id == AnalysisRevision.analysis_case_id)
        .options(
            defer(AnalysisRevision.context), defer(AnalysisRevision.raw_response),
            defer(AnalysisRevision.pending_repair_input), defer(AnalysisCase.matched_data),
        )
        .where(ExceptionDraft.classification == "false_positive")
        .order_by(ExceptionDraft.id)
        .execution_options(yield_per=100)
    )
    if status:
        stmt = stmt.where(ExceptionDraft.status == status)

    async def rows():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "Timestamp", "URI", "Payload / Matched Data", "Signature ID",
            "Signature Pattern (CRS Rule)", "Confidence", "Status",
            "Proposed Exception Rule", "Verdict",
        ])
        yield buf.getvalue()
        async with get_session_factory()() as db:
            active_profiles = await active_application_profiles(db)
            generation = current_analysis_generation()
            result = await db.stream(stmt)
            async for draft, matches, observed_at, case, revision in result:
                scope = draft.proposed_rule_scope or {}
                rule_id = scope.get("rule_id", "")
                match = _matching_evidence(matches or [], scope) or {}
                rule = None
                # An approved rule stays exportable after its audit evidence expires.
                if (draft.status == "approved" and draft.validation_status == "valid"
                        and _certified_rule(draft, case, revision, generation)):
                    profile, _ = application_context_for(active_profiles, case.application_host, case.method, case.path)
                    observed_profile = (profile.id, profile.version) if profile else (None, None)
                    if (observed_profile == (revision.application_profile_id, revision.profile_version)
                            and not await has_true_positive(db, case, scope, revision=revision)):
                        rule = draft.proposed_rule
                buf.seek(0)
                buf.truncate()
                writer.writerow([_csv_safe(value) for value in (
                    observed_at or draft.created_at, scope.get("uri", ""), match.get("matched_data"), rule_id,
                    draft.crs_rule_raw, f"{round(draft.confidence * 100)}%", draft.status, rule, draft.verdict,
                )])
                yield buf.getvalue()

    filename = f"false_positives_{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.csv"
    return StreamingResponse(
        rows(), media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{draft_id}")
async def get_exception(draft_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ExceptionDraft).where(ExceptionDraft.id == draft_id)
    )
    draft = result.scalars().first()
    if not draft:
        raise HTTPException(status_code=404, detail="Draft not found")

    return await _enrich_draft(db, draft)


@router.post("/{draft_id}/approve")
async def approve_exception(draft_id: int, db: AsyncSession = Depends(get_db)):
    # Serialize review with profile changes and worker publication in SQLite.
    await db.execute(update(ExceptionDraft).where(ExceptionDraft.id == draft_id).values(status=ExceptionDraft.status))
    result = await db.execute(
        select(ExceptionDraft).where(ExceptionDraft.id == draft_id)
    )
    draft = result.scalars().first()
    if not draft:
        raise HTTPException(status_code=404, detail="Draft not found")
    if draft.status not in ("pending",):
        raise HTTPException(status_code=400, detail=f"Cannot approve draft with status '{draft.status}'")
    if draft.classification != "false_positive":
        raise HTTPException(status_code=400, detail="Only false-positive drafts can be approved")
    if draft.validation_status != "valid":
        raise HTTPException(
            status_code=400,
            detail=f"Rule did not pass the builder's structure checks (status: {draft.validation_status})",
        )
    if draft.analysis_revision_id is None:
        raise HTTPException(status_code=400, detail="Draft has no reproducible analysis revision")
    revision = await db.get(AnalysisRevision, draft.analysis_revision_id)
    case = await db.get(AnalysisCase, revision.analysis_case_id) if revision else None
    if case is None:
        raise HTTPException(status_code=400, detail="Draft has no analysis case")
    # Recheck this scope while approval owns the SQLite write transaction.
    if await has_true_positive(db, case, draft.proposed_rule_scope or {}, revision=revision):
        draft.proposed_rule = None
        draft.validation_status = "scope_conflict"
        draft.validation_error = SCOPE_CONFLICT_ERROR
        draft.rule_placement = None
        draft.status = "stale"
        await db.commit()
        raise HTTPException(status_code=409, detail=SCOPE_CONFLICT_ERROR)

    active_scope_conflict = (
        await db.execute(
            select(ExceptionDraft.id).where(
                ExceptionDraft.id != draft.id,
                ExceptionDraft.scope_key == draft.scope_key,
                ExceptionDraft.scope_key.is_not(None),
                ExceptionDraft.classification == "false_positive",
                ExceptionDraft.status.in_(["pending", "approved"]),
            ).limit(1)
        )
    ).scalar_one_or_none()
    if active_scope_conflict is not None:
        draft.proposed_rule = None
        draft.rule_placement = None
        draft.validation_status = "duplicate_scope"
        draft.validation_error = f"Active draft {active_scope_conflict} already owns this scope."
        draft.status = "stale"
        await db.commit()
        raise HTTPException(status_code=409, detail=draft.validation_error)
    if draft.rule_numeric_id is not None:
        id_conflict = (
            await db.execute(
                select(ExceptionDraft.id).where(
                    ExceptionDraft.id != draft.id,
                    ExceptionDraft.rule_numeric_id == draft.rule_numeric_id,
                    ExceptionDraft.classification == "false_positive",
                    ExceptionDraft.status.in_(["pending", "approved"]),
                ).limit(1)
            )
        ).scalar_one_or_none()
        if id_conflict is not None:
            draft.proposed_rule = None
            draft.rule_placement = None
            draft.rule_numeric_id = None
            draft.validation_status = "id_conflict"
            draft.validation_error = f"Rule ID is already used by active draft {id_conflict}."
            draft.status = "stale"
            await db.commit()
            raise HTTPException(status_code=409, detail=draft.validation_error)

    event = await _get_draft_event(db, draft)
    if not await _current_evidence(db, draft, case, revision, event):
        draft.status = "stale"
        draft.rule_placement = None
        draft.validation_status = "stale_context"
        draft.validation_error = "The current rule or application evidence could not be verified. Reanalyze this case."
        await db.commit()
        raise HTTPException(status_code=409, detail=draft.validation_error)

    draft.status = "approved"
    draft.reviewed_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(draft)
    return await _enrich_draft(db, draft)


class RejectBody(BaseModel):
    reason: Optional[str] = None


@router.post("/{draft_id}/reject")
async def reject_exception(
    draft_id: int, body: RejectBody, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(ExceptionDraft).where(ExceptionDraft.id == draft_id)
    )
    draft = result.scalars().first()
    if not draft:
        raise HTTPException(status_code=404, detail="Draft not found")
    if draft.status not in ("pending", "approved"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot reject draft with status '{draft.status}'",
        )

    draft.status = "rejected"
    draft.rejection_reason = body.reason
    draft.reviewed_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(draft)
    return await _enrich_draft(db, draft)
