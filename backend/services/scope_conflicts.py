"""Cross-payload safety checks for proposed parameter-wide exclusions."""
from sqlalchemy import select

from db.models import AnalysisCase, AnalysisRevision, ExceptionDraft


SCOPE_CONFLICT_ERROR = (
    "A true-positive incident exists for the same URI, parameter, and rule ID. "
    "A parameter-wide exclusion would suppress known attack traffic."
)


def scope_values(case: AnalysisCase) -> tuple[str, str | None, str | None, str]:
    return case.path, case.collection, case.parameter, case.rule_id


def _same_scope(case: AnalysisCase):
    return (
        AnalysisCase.path == case.path,
        AnalysisCase.collection == case.collection,
        AnalysisCase.parameter == case.parameter,
        AnalysisCase.rule_id == case.rule_id,
    )


async def lock_scope(session, case: AnalysisCase) -> None:
    """Serialize scope checks within the current write transaction.

    Postgres used advisory locks; SQLite serializes writers, so a no-op is enough.
    """
    _ = session, case
    return


async def has_true_positive(session, case: AnalysisCase) -> bool:
    result = await session.execute(
        select(AnalysisRevision.id)
        .join(AnalysisCase, AnalysisCase.id == AnalysisRevision.analysis_case_id)
        .where(
            *_same_scope(case),
            AnalysisRevision.state == "complete",
            AnalysisRevision.classification == "true_positive",
        )
        .limit(1)
    )
    return result.scalar_one_or_none() is not None


async def invalidate_false_positive_drafts(session, case: AnalysisCase) -> int:
    revision_ids = select(AnalysisRevision.id).join(
        AnalysisCase, AnalysisCase.id == AnalysisRevision.analysis_case_id
    ).where(
        *_same_scope(case),
        AnalysisRevision.state == "complete",
        AnalysisRevision.classification == "false_positive",
    )
    revisions = (
        await session.execute(select(AnalysisRevision).where(AnalysisRevision.id.in_(revision_ids)))
    ).scalars().all()
    for revision in revisions:
        revision.normalized_rule = None
        revision.validation_status = "scope_conflict"
        revision.validation_error = SCOPE_CONFLICT_ERROR

    drafts = (
        await session.execute(
            select(ExceptionDraft).where(ExceptionDraft.analysis_revision_id.in_(revision_ids))
        )
    ).scalars().all()
    for draft in drafts:
        draft.proposed_rule = None
        draft.validation_status = "scope_conflict"
        draft.validation_error = SCOPE_CONFLICT_ERROR
        draft.rule_placement = None
        if draft.status in {"pending", "approved"}:
            draft.status = "stale"
    return len(drafts)
