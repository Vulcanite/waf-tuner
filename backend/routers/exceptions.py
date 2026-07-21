"""
Exceptions Router — Phase 5
"""
import io
import json
import os
from datetime import datetime, timezone
from typing import Optional

import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from fastapi import APIRouter, Depends, Query, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import AnalysisCase, AnalysisRevision, ExceptionDraft, get_db, AuditEvent
from services.scope_conflicts import (
    SCOPE_CONFLICT_ERROR, has_true_positive, lock_scope,
)

router = APIRouter(prefix="/api/exceptions", tags=["exceptions"])

EVENTS_JSONL_PATH = os.environ.get("EVENTS_JSONL_PATH", "/shared/events.jsonl")


async def _get_event_by_line(db: AsyncSession, line_num: int) -> Optional[dict]:
    result = await db.execute(
        select(AuditEvent.raw_event).where(AuditEvent.event_line == line_num)
    )
    return result.scalar_one_or_none()


def _draft_to_dict(
    d: ExceptionDraft,
    event: Optional[dict] = None,
    *,
    case: Optional[AnalysisCase] = None,
    revision: Optional[AnalysisRevision] = None,
    crs_meta: Optional[dict] = None,
) -> dict:
    scope = d.proposed_rule_scope or {}
    # Prefer ground-truth case fields for zone display.
    zone = {
        "uri": (case.path if case else None) or scope.get("uri"),
        "collection": (case.collection if case else None) or scope.get("collection"),
        "parameter": (case.parameter if case else None) or scope.get("parameter"),
        "rule_id": (case.rule_id if case else None) or scope.get("rule_id"),
        "method": case.method if case else (event.get("method") if event else None),
        "match_index": scope.get("match_index"),
        "sibling_rule_ids": scope.get("sibling_rule_ids") or [],
    }
    this_match = None
    if event and event.get("matches") is not None:
        idx = zone.get("match_index")
        matches = event.get("matches") or []
        if isinstance(idx, int) and 0 <= idx < len(matches):
            this_match = matches[idx]
        else:
            rid = str(zone.get("rule_id") or "")
            this_match = next(
                (m for m in matches if str(m.get("rule_id") or "") == rid),
                matches[0] if matches else None,
            )

    return {
        "id": d.id,
        "transaction_id": d.transaction_id,
        "event_line": d.event_line,
        "classification": d.classification,
        "confidence": d.confidence,
        "verdict": d.verdict,
        "crs_rule_raw": d.crs_rule_raw,
        "proposed_rule": d.proposed_rule,
        "proposed_rule_scope": d.proposed_rule_scope,
        "status": d.status,
        "rejection_reason": d.rejection_reason,
        "created_at": d.created_at.isoformat() if d.created_at else None,
        "reviewed_at": d.reviewed_at.isoformat() if d.reviewed_at else None,
        "deployed_at": d.deployed_at.isoformat() if d.deployed_at else None,
        "last_seen_at": d.last_seen_at.isoformat() if d.last_seen_at else None,
        "analysis_revision_id": d.analysis_revision_id,
        "analysis_case_id": case.id if case else (
            revision.analysis_case_id if revision else None
        ),
        "raw_proposed_rule": d.raw_proposed_rule,
        "validation_status": d.validation_status,
        "validation_error": d.validation_error,
        "rule_placement": d.rule_placement,
        "zone": zone,
        "this_match": this_match,
        "signature": crs_meta,
        "context_factors": revision.context_factors if revision else None,
        "uncertainty_factors": revision.uncertainty_factors if revision else None,
        "event_summary": {
            "uri": event.get("uri") if event else None,
            "method": event.get("method") if event else None,
            "timestamp": event.get("timestamp") if event else None,
            "anomaly_score": event.get("anomaly_score") if event else None,
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
    text = (matched_data or "").strip()
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
    from services.crs_index import get_rule

    event = await _get_event_by_line(db, d.event_line)
    revision = None
    case = None
    if d.analysis_revision_id:
        revision = await db.get(AnalysisRevision, d.analysis_revision_id)
        if revision:
            case = await db.get(AnalysisCase, revision.analysis_case_id)
    rule_id = (case.rule_id if case else None) or (d.proposed_rule_scope or {}).get("rule_id")
    crs = get_rule(str(rule_id)) if rule_id else None
    crs_meta = None
    if crs:
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
    return _draft_to_dict(d, event, case=case, revision=revision, crs_meta=crs_meta)


@router.get("")
async def list_exceptions(
    status: Optional[str] = None,
    classification: Optional[str] = None,
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(ExceptionDraft)
    if status:
        stmt = stmt.where(ExceptionDraft.status == status)
    if classification:
        stmt = stmt.where(ExceptionDraft.classification == classification)
    stmt = stmt.order_by(ExceptionDraft.created_at.desc())

    count_stmt = select(func.count()).select_from(ExceptionDraft)
    if status:
        count_stmt = count_stmt.where(ExceptionDraft.status == status)
    if classification:
        count_stmt = count_stmt.where(ExceptionDraft.classification == classification)

    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    stmt = stmt.offset((page - 1) * limit).limit(limit)
    result = await db.execute(stmt)
    drafts = result.scalars().all()

    items = [await _enrich_draft(db, d) for d in drafts]

    return {"total": total, "page": page, "limit": limit, "items": items}


@router.get("/export/false-positives")
async def export_false_positives(
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Export all false positive exception drafts as an Excel file."""
    stmt = select(ExceptionDraft).where(
        ExceptionDraft.classification == "false_positive"
    )
    if status:
        stmt = stmt.where(ExceptionDraft.status == status)
    stmt = stmt.order_by(ExceptionDraft.created_at.asc())

    result = await db.execute(stmt)
    drafts = result.scalars().all()

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "False Positives"

    # --- Styles ---
    header_fill = PatternFill("solid", fgColor="1C1C1C")
    header_font = Font(bold=True, color="F59E0B", name="Consolas", size=10)
    cell_font = Font(name="Consolas", size=9, color="E4E4E7")
    alt_fill = PatternFill("solid", fgColor="27272A")
    base_fill = PatternFill("solid", fgColor="18181B")
    border_side = Side(style="thin", color="3F3F46")
    thin_border = Border(
        left=border_side, right=border_side,
        top=border_side, bottom=border_side,
    )
    wrap = Alignment(wrap_text=True, vertical="top")

    # --- Headers ---
    headers = [
        ("Timestamp", 22),
        ("URI", 28),
        ("Payload / Matched Data", 55),
        ("Signature ID", 14),
        ("Signature Pattern (CRS Rule)", 70),
        ("Confidence", 12),
        ("Status", 12),
        ("Proposed Exception Rule", 70),
        ("Verdict", 60),
    ]
    for col_idx, (label, width) in enumerate(headers, start=1):
        cell = ws.cell(row=1, column=col_idx, value=label)
        cell.font = header_font
        cell.fill = header_fill
        cell.border = thin_border
        cell.alignment = Alignment(vertical="center", horizontal="center")
        ws.column_dimensions[get_column_letter(col_idx)].width = width

    ws.row_dimensions[1].height = 20
    ws.freeze_panes = "A2"

    # --- Rows ---
    for row_idx, draft in enumerate(drafts, start=2):
        event = await _get_event_by_line(db, draft.event_line)
        scope = draft.proposed_rule_scope or {}
        rule_id = scope.get("rule_id", "")

        # Timestamp from linked event, fallback to draft created_at
        timestamp = ""
        if event and event.get("timestamp"):
            timestamp = event["timestamp"]
        elif draft.created_at:
            timestamp = draft.created_at.isoformat()

        # URI
        uri = scope.get("uri") or (event.get("uri", "") if event else "")

        # Payload: collect all matched_data from the event's matches for this rule
        payload = ""
        if event:
            payloads = [
                m.get("matched_data", "")
                for m in event.get("matches", [])
                if m.get("rule_id") == rule_id and m.get("matched_data")
            ]
            payload = "\n".join(payloads) if payloads else (
                event.get("matches", [{}])[0].get("matched_data", "") if event.get("matches") else ""
            )

        # Signature pattern: first line of the raw CRS SecRule
        crs_pattern = ""
        if draft.crs_rule_raw:
            crs_pattern = draft.crs_rule_raw.replace("\\\n", " ").replace("\n", " ").strip()

        fill = alt_fill if row_idx % 2 == 0 else base_fill
        row_values = [
            timestamp,
            uri,
            payload,
            rule_id,
            crs_pattern,
            f"{round(draft.confidence * 100)}%",
            draft.status,
            draft.proposed_rule or "",
            draft.verdict or "",
        ]

        for col_idx, value in enumerate(row_values, start=1):
            cell = ws.cell(row=row_idx, column=col_idx, value=value)
            cell.font = cell_font
            cell.fill = fill
            cell.border = thin_border
            cell.alignment = wrap

        # Auto-height hint for wrapped rows
        ws.row_dimensions[row_idx].height = 40

    # Add autofilter on header row
    ws.auto_filter.ref = f"A1:{get_column_letter(len(headers))}1"

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)

    filename = f"false_positives_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xlsx"
    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
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
            detail=f"Rule is not engine-validated (status: {draft.validation_status})",
        )
    if draft.analysis_revision_id is None:
        raise HTTPException(status_code=400, detail="Draft has no reproducible analysis revision")
    revision = await db.get(AnalysisRevision, draft.analysis_revision_id)
    case = await db.get(AnalysisCase, revision.analysis_case_id) if revision else None
    if case is None:
        raise HTTPException(status_code=400, detail="Draft has no analysis case")
    await lock_scope(db, case)
    if await has_true_positive(db, case):
        draft.proposed_rule = None
        draft.validation_status = "scope_conflict"
        draft.validation_error = SCOPE_CONFLICT_ERROR
        draft.rule_placement = None
        draft.status = "stale"
        await db.commit()
        raise HTTPException(status_code=409, detail=SCOPE_CONFLICT_ERROR)

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
