"""Protect an exclusion scope from suppressing a known true positive."""
from sqlalchemy import or_, select, update

from db.models import AnalysisCase, AnalysisRevision, ExceptionDraft
from services.draft_scope import case_exception_scope


SCOPE_CONFLICT_ERROR = (
    "A true-positive incident exists for the same URI, parameter, and rule ID "
    "within this exclusion's scope. An exclusion could suppress that traffic."
)


def _same_target(case: AnalysisCase):
    return (
        AnalysisCase.path == case.path,
        AnalysisCase.collection == case.collection,
        AnalysisCase.parameter == case.parameter,
        AnalysisCase.rule_id == case.rule_id,
    )


async def has_true_positive(session, case: AnalysisCase, scope: dict | None = None) -> bool:
    observed_scope = case_exception_scope(case) if scope is None else scope
    filters = list(_same_target(case))
    if observed_scope.get("host") and observed_scope.get("method"):
        filters.extend((
            or_(
                AnalysisCase.application_host == observed_scope["host"],
                AnalysisCase.application_host.is_(None),
                AnalysisCase.application_host == "",
            ),
            AnalysisCase.method == observed_scope["method"],
        ))
    result = await session.execute(
        select(AnalysisRevision.id)
        .join(AnalysisCase, AnalysisCase.id == AnalysisRevision.analysis_case_id)
        .where(
            *filters,
            AnalysisRevision.state == "complete",
            AnalysisRevision.classification == "true_positive",
        )
        .limit(1)
    )
    return result.scalar_one_or_none() is not None


async def invalidate_false_positive_drafts(session, case: AnalysisCase) -> int:
    scope = case_exception_scope(case)
    revision_scope = AnalysisRevision.proposed_rule_scope
    profile_method = revision_scope["method"].as_string()
    profile_host = revision_scope["host"].as_string()
    filters = [or_(profile_method.is_(None), profile_method == scope.get("method", case.method))]
    if scope.get("host"):
        filters.append(or_(profile_host.is_(None), profile_host == scope["host"]))
    revision_ids = select(AnalysisRevision.id).join(
        AnalysisCase, AnalysisCase.id == AnalysisRevision.analysis_case_id
    ).where(
        *_same_target(case),
        *filters,
        AnalysisRevision.state == "complete",
        AnalysisRevision.classification == "false_positive",
    )
    policy = dict(validation_status="scope_conflict", validation_error=SCOPE_CONFLICT_ERROR)
    await session.execute(
        update(AnalysisRevision).where(AnalysisRevision.id.in_(revision_ids))
        .values(normalized_rule=None, **policy).execution_options(synchronize_session=False)
    )
    result = await session.execute(
        update(ExceptionDraft)
        .where(
            ExceptionDraft.analysis_revision_id.in_(revision_ids),
            ExceptionDraft.classification == "false_positive",
            ExceptionDraft.status.in_(["pending", "approved"]),
        )
        .values(proposed_rule=None, rule_numeric_id=None, rule_placement=None, status="stale", **policy)
        .execution_options(synchronize_session=False)
    )
    return result.rowcount
