"""Protect an exclusion scope from suppressing a known true positive."""
import json

from sqlalchemy import func, or_, select, update

from db.models import AnalysisCase, AnalysisRevision, ExceptionDraft
from services.draft_scope import case_exception_scope


SCOPE_CONFLICT_ERROR = (
    "A true-positive verdict exists for the same input value on this host, method and path "
    "or for the same rule and target within this exclusion's scope."
)


def _same_target(case: AnalysisCase):
    return (
        AnalysisCase.path == case.path,
        AnalysisCase.collection == case.collection,
        AnalysisCase.parameter == case.parameter,
        AnalysisCase.rule_id == case.rule_id,
    )


def _same_input(case: AnalysisCase, revision: AnalysisRevision, classification: str):
    """Complete verdicts of any rule, in any transaction, on the same observed input.

    The input keys already cover host, method and path; filtering on the case's path and host
    first lets SQLite narrow the candidates with an index before comparing keys.
    """
    keys = func.json_each(AnalysisRevision.input_keys).table_valued("value", joins_implicitly=True)
    observed = func.json_each(json.dumps(revision.input_keys)).table_valued("value")
    overlap = select(1).where(keys.c.value.in_(select(observed.c.value))).correlate(AnalysisRevision)
    host = (
        AnalysisCase.application_host == case.application_host if case.application_host
        else or_(AnalysisCase.application_host.is_(None), AnalysisCase.application_host == "")
    )
    return (
        select(AnalysisRevision.id)
        .join(AnalysisCase, AnalysisCase.id == AnalysisRevision.analysis_case_id)
        .where(
            AnalysisCase.path == case.path,
            host,
            AnalysisRevision.state == "complete",
            AnalysisRevision.classification == classification,
            AnalysisRevision.input_keys.is_not(None),
            overlap.exists(),
        )
    )


async def has_true_positive(
    session, case: AnalysisCase, scope: dict | None = None, *, revision: AnalysisRevision | None = None,
) -> bool:
    observed_scope = case_exception_scope(case) if scope is None else scope
    filters = list(_same_target(case))
    if observed_scope.get("host") and observed_scope.get("method"):
        filters.extend((
            or_(
                AnalysisCase.application_host == observed_scope["host"],
                AnalysisCase.application_host.is_(None),
                AnalysisCase.application_host == "",
            ),
            # A detection whose method was not logged could have used any method.
            or_(AnalysisCase.method == observed_scope["method"], AnalysisCase.method.is_(None), AnalysisCase.method == ""),
        ))
    matches = (
        select(AnalysisRevision.id)
        .join(AnalysisCase, AnalysisCase.id == AnalysisRevision.analysis_case_id)
        .where(
            *filters,
            AnalysisRevision.state == "complete",
            AnalysisRevision.classification == "true_positive",
        )
    )
    if revision and revision.input_keys:
        matches = matches.union_all(_same_input(case, revision, "true_positive"))
    result = await session.execute(matches.limit(1))
    return result.scalar_one_or_none() is not None


async def invalidate_false_positive_drafts(
    session, case: AnalysisCase, *, revision: AnalysisRevision | None = None,
) -> int:
    revision_scope = AnalysisRevision.proposed_rule_scope
    profile_method = revision_scope["method"].as_string()
    profile_host = revision_scope["host"].as_string()
    filters = []
    # An unknown method could be any method, so only a known one narrows the overlap; a known host still does.
    if case.method:
        filters.append(or_(profile_method.is_(None), profile_method == case.method))
    if case.application_host:
        filters.append(or_(profile_host.is_(None), profile_host == case.application_host))
    revision_ids = select(AnalysisRevision.id).join(
        AnalysisCase, AnalysisCase.id == AnalysisRevision.analysis_case_id
    ).where(
        *_same_target(case),
        *filters,
        AnalysisRevision.state == "complete",
        AnalysisRevision.classification == "false_positive",
    )
    if revision and revision.input_keys:
        revision_ids = revision_ids.union_all(_same_input(case, revision, "false_positive"))
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
