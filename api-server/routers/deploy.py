"""
Deploy Router — Phase 5

Explicit, operator-triggered deployment of approved exception rules.
"""
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import get_db, ExceptionDraft
from services.rule_writer import write_exception, validate_exception, delete_exception, reload_nginx

router = APIRouter(prefix="/api/deploy", tags=["deploy"])


def _draft_to_dict(d: ExceptionDraft) -> dict:
    return {
        "id": d.id,
        "transaction_id": d.transaction_id,
        "classification": d.classification,
        "confidence": d.confidence,
        "verdict": d.verdict,
        "proposed_rule": d.proposed_rule,
        "proposed_rule_scope": d.proposed_rule_scope,
        "status": d.status,
        "deployed_at": d.deployed_at.isoformat() if d.deployed_at else None,
        "last_seen_at": d.last_seen_at.isoformat() if d.last_seen_at else None,
    }


@router.get("/pending")
async def get_pending(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ExceptionDraft)
        .where(ExceptionDraft.status == "approved")
        .order_by(ExceptionDraft.reviewed_at.desc())
    )
    drafts = result.scalars().all()
    return {"items": [_draft_to_dict(d) for d in drafts], "total": len(drafts)}


class DeployBody(BaseModel):
    ids: Optional[list[int]] = None  # None means deploy all approved


@router.post("")
async def deploy(body: DeployBody, db: AsyncSession = Depends(get_db)):
    # Fetch target drafts
    stmt = select(ExceptionDraft).where(ExceptionDraft.status == "approved")
    if body.ids:
        stmt = stmt.where(ExceptionDraft.id.in_(body.ids))

    result = await db.execute(stmt)
    drafts = result.scalars().all()

    if not drafts:
        return {"deployed": [], "failed": [], "nginx_reloaded": False}

    deployed_ids = []
    failed_ids = []

    for draft in drafts:
        if not draft.proposed_rule:
            failed_ids.append(draft.id)
            continue

        try:
            ok = validate_exception(draft)
            if ok:
                deployed_ids.append(draft.id)
                draft.status = "deployed"
                draft.deployed_at = datetime.now(timezone.utc)
            else:
                failed_ids.append(draft.id)
        except Exception as e:
            failed_ids.append(draft.id)

    await db.commit()

    nginx_reloaded = False
    if deployed_ids:
        nginx_reloaded = reload_nginx()

    return {
        "deployed": deployed_ids,
        "failed": failed_ids,
        "nginx_reloaded": nginx_reloaded,
    }


@router.delete("/{draft_id}")
async def rollback(draft_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ExceptionDraft).where(ExceptionDraft.id == draft_id)
    )
    draft = result.scalars().first()
    if not draft:
        raise HTTPException(status_code=404, detail="Draft not found")
    if draft.status != "deployed":
        raise HTTPException(status_code=400, detail="Draft is not deployed")

    delete_exception(draft)
    draft.status = "approved"
    draft.deployed_at = None
    await db.commit()
    await db.refresh(draft)

    reload_nginx()
    return _draft_to_dict(draft)
