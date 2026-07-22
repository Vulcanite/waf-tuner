import asyncio
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from db import models
from db.models import AnalysisCase, AnalysisRevision, ExceptionDraft, InferenceAttempt
from services import agent
from services.redaction import REDACTED, sanitize_inference_context, split_and_redact_uri


VALID = json.dumps({
    "classification": "true_positive",
    "confidence": 0.95,
    "verdict": "Executable attack syntax is present in the inspected parameter.",
    "context_factors": ["attack syntax"],
    "uncertainty_factors": [],
})


class ModelResponseTests(unittest.TestCase):
    def test_tls_verification_defaults_on_and_can_be_disabled(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertTrue(agent._verify_ssl())
        with patch.dict(os.environ, {"LLM_VERIFY_SSL": "false"}, clear=True):
            self.assertFalse(agent._verify_ssl())

    def test_parser_accepts_complete_fenced_and_reasoning_prefixed_objects(self):
        self.assertEqual(agent._extract_json(VALID)["classification"], "true_positive")
        self.assertEqual(agent._extract_json(f"```json\n{VALID}\n```")["confidence"], 0.95)
        prefixed = 'Reasoning mentioned {not json}. Final:\n' + VALID
        self.assertEqual(agent._extract_json(prefixed)["classification"], "true_positive")

    def test_parser_uses_newest_complete_fenced_object(self):
        older = VALID.replace("true_positive", "uncertain")
        self.assertEqual(
            agent._extract_json(f"```json\n{older}\n```\n```json\n{VALID}\n```")["classification"],
            "true_positive",
        )

    def test_parser_rejects_truncated_or_invalid_output(self):
        with self.assertRaises(ValueError):
            agent._extract_json('{"classification":"true_positive"')
        with self.assertRaises(ValueError):
            agent._extract_json("no object")

    def test_exactly_one_repair_is_attempted(self):
        provider = AsyncMock(side_effect=["not json", VALID])
        with patch.object(agent, "_provider_request", provider):
            result, _, repaired = asyncio.run(agent._call_model({}, {}, 1))
        self.assertTrue(repaired)
        self.assertEqual(result["classification"], "true_positive")
        self.assertEqual(provider.await_count, 2)

    def test_missing_route_context_prevents_copyable_rule_when_required(self):
        result = json.loads(VALID.replace("true_positive", "false_positive"))
        scope = {"uri": "/search", "rule_id": "942100", "collection": "ARGS", "parameter": "q"}
        with patch.dict(os.environ, {"REQUIRE_APPLICATION_CONTEXT": "true"}):
            normalized, status, error = asyncio.run(
                agent._apply_draft_policy(result, scope, False)
            )
        self.assertIsNone(normalized)
        self.assertEqual(status, "missing_application_context")
        self.assertIn("reanalyze", error)

    def test_missing_route_context_allowed_by_default(self):
        result = json.loads(VALID.replace("true_positive", "false_positive"))
        scope = {
            "uri": "/search",
            "rule_id": "942100",
            "collection": "ARGS",
            "parameter": "q",
        }
        with patch.dict(os.environ, {"REQUIRE_APPLICATION_CONTEXT": "false"}):
            normalized, status, error = asyncio.run(
                agent._apply_draft_policy(result, scope, False)
            )
        # Builder runs without a route profile; structure validation should pass.
        self.assertEqual(status, "valid")
        self.assertIsNotNone(normalized)
        self.assertIsNone(error)

    def test_failed_repair_is_terminal_invalid_output(self):
        provider = AsyncMock(side_effect=["not json", "still not json"])
        with patch.object(agent, "_provider_request", provider):
            with self.assertRaises(agent.InvalidOutputError):
                asyncio.run(agent._call_model({}, {}, 1))
        self.assertEqual(provider.await_count, 2)


class InferenceRedactionTests(unittest.TestCase):
    def test_uri_and_every_context_location_are_sanitized(self):
        uri = split_and_redact_uri("/search?q=shoes&token=secret")
        self.assertEqual(uri["path"], "/search")
        self.assertEqual(uri["query"]["token"], REDACTED)
        context, fields = sanitize_inference_context({
            "incident": {
                "parameter": "password",
                "matched_data": "secret payload",
                "other_matches": [{"parameter": "api_key", "matched_data": "key value"}],
            },
            "request": {"headers": {"Authorization": "Bearer secret"}},
            "application_context": {"client_secret": "value", "purpose": "search"},
        })
        self.assertEqual(context["incident"]["matched_data"], REDACTED)
        self.assertEqual(context["incident"]["other_matches"][0]["matched_data"], REDACTED)
        self.assertEqual(context["request"]["headers"]["Authorization"], REDACTED)
        self.assertEqual(context["application_context"]["client_secret"], REDACTED)
        self.assertEqual(context["application_context"]["purpose"], "search")
        self.assertGreaterEqual(len(fields), 4)


class SqliteAgentTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.old_path = os.environ.get("DATABASE_PATH")
        self.old_url = os.environ.pop("DATABASE_URL", None)
        os.environ["DATABASE_PATH"] = str(Path(self.directory.name) / "agent.db")
        models._async_engine = None
        models._async_session_factory = None
        asyncio.run(models.init_db())

    def tearDown(self):
        engine = models._async_engine
        if engine is not None:
            asyncio.run(engine.dispose())
        models._async_engine = None
        models._async_session_factory = None
        if self.old_path is None:
            os.environ.pop("DATABASE_PATH", None)
        else:
            os.environ["DATABASE_PATH"] = self.old_path
        if self.old_url is not None:
            os.environ["DATABASE_URL"] = self.old_url
        self.directory.cleanup()

    @staticmethod
    def _case(index: int, *, state: str = "queued", lease_expires_at=None):
        now = datetime.now(timezone.utc)
        return AnalysisCase(
            fingerprint=f"fingerprint-{index}", method="GET", path=f"/path/{index}",
            rule_id="942100", collection="ARGS", parameter="q", matched_data="select",
            latest_event_line=index, state=state, first_seen_at=now + timedelta(seconds=index),
            last_seen_at=now, lease_expires_at=lease_expires_at,
        )

    def test_four_workers_claim_one_case_once(self):
        async def run():
            factory = models.get_session_factory()
            async with factory() as session:
                session.add(self._case(1))
                await session.commit()
            return await asyncio.gather(*(agent._claim_case() for _ in range(4)))
        claims = asyncio.run(run())
        self.assertEqual(sum(value is not None for value in claims), 1)

    def test_four_queued_cases_produce_distinct_claims(self):
        async def run():
            factory = models.get_session_factory()
            async with factory() as session:
                session.add_all([self._case(index) for index in range(4)])
                await session.commit()
            return await asyncio.gather(*(agent._claim_case() for _ in range(4)))
        claims = asyncio.run(run())
        self.assertEqual(len(set(claims)), 4)
        self.assertNotIn(None, claims)

    def test_expired_lease_closes_abandoned_revision(self):
        async def run():
            factory = models.get_session_factory()
            async with factory() as session:
                case = self._case(1, state="analyzing", lease_expires_at=datetime.now(timezone.utc) - timedelta(minutes=1))
                session.add(case)
                await session.flush()
                revision = AnalysisRevision(
                    analysis_case_id=case.id, model="fixture", prompt_version="old",
                    state="analyzing", context={}, model_settings={},
                )
                session.add(revision)
                await session.flush()
                attempt = InferenceAttempt(
                    analysis_revision_id=revision.id,
                    attempt_type="initial",
                    status="active",
                    started_at=datetime.now(timezone.utc) - timedelta(seconds=5),
                )
                session.add(attempt)
                await session.commit()
                revision_id = revision.id
                attempt_id = attempt.id
            claimed = await agent._claim_case()
            async with factory() as session:
                closed = await session.get(AnalysisRevision, revision_id)
                closed_attempt = await session.get(InferenceAttempt, attempt_id)
                return claimed, closed.state, closed.error_code, closed_attempt.status, closed_attempt.error_code
        claimed, state, error, attempt_state, attempt_error = asyncio.run(run())
        self.assertIsNotNone(claimed)
        self.assertEqual((state, error), ("failed", "lease_expired"))
        self.assertEqual((attempt_state, attempt_error), ("error", "lease_expired"))

    def test_hourly_budget_is_atomic_across_workers(self):
        async def run():
            factory = models.get_session_factory()
            async with factory() as session:
                case = self._case(1)
                session.add(case)
                await session.flush()
                revision = AnalysisRevision(
                    analysis_case_id=case.id, model="fixture", prompt_version="test",
                    state="analyzing", context={}, model_settings={},
                )
                session.add(revision)
                await session.commit()
                revision_id = revision.id
            results = await asyncio.gather(
                *(agent._reserve_attempt(revision_id, "initial") for _ in range(4)),
                return_exceptions=True,
            )
            return results
        old = os.environ.get("AGENT_MAX_REQUESTS_PER_HOUR")
        os.environ["AGENT_MAX_REQUESTS_PER_HOUR"] = "2"
        try:
            results = asyncio.run(run())
        finally:
            if old is None:
                os.environ.pop("AGENT_MAX_REQUESTS_PER_HOUR", None)
            else:
                os.environ["AGENT_MAX_REQUESTS_PER_HOUR"] = old
        self.assertEqual(sum(isinstance(value, int) for value in results), 2)
        self.assertEqual(sum(isinstance(value, agent.BudgetDeferred) for value in results), 2)

    def test_retry_after_is_respected_and_terminal_error_is_explicit(self):
        async def run():
            factory = models.get_session_factory()
            async with factory() as session:
                case = self._case(1, state="analyzing")
                session.add(case)
                await session.flush()
                revision = AnalysisRevision(
                    analysis_case_id=case.id, model="fixture", prompt_version="test",
                    state="analyzing", context={}, model_settings={},
                )
                session.add(revision)
                await session.commit()
                case_id = case.id
            before = datetime.now(timezone.utc)
            await agent._record_retry(
                case_id,
                agent.RetryableAnalysisError("rate limited", error_code="rate_limited", retry_after=300),
            )
            async with factory() as session:
                deferred = await session.get(AnalysisCase, case_id)
                revision = (await session.execute(
                    select(AnalysisRevision).where(
                        AnalysisRevision.analysis_case_id == case_id
                    )
                )).scalars().first()
                retry_delay = deferred.next_retry_at.replace(tzinfo=timezone.utc) - before
                retry_state = (deferred.state, revision.error_code, retry_delay.total_seconds())
            async with factory() as session:
                terminal_case = self._case(2, state="analyzing")
                session.add(terminal_case)
                await session.flush()
                terminal_revision = AnalysisRevision(
                    analysis_case_id=terminal_case.id, model="fixture", prompt_version="test",
                    state="analyzing", context={}, model_settings={},
                )
                session.add(terminal_revision)
                await session.commit()
                terminal_id = terminal_case.id
            await agent._record_retry(
                terminal_id, agent.InvalidOutputError("bad repair", "invalid raw"), terminal=True
            )
            async with factory() as session:
                failed_case = await session.get(AnalysisCase, terminal_id)
                failed_revision = (await session.execute(
                    select(AnalysisRevision).where(
                        AnalysisRevision.analysis_case_id == terminal_id
                    )
                )).scalars().first()
                terminal_state = (failed_case.state, failed_revision.state, failed_revision.error_code, failed_revision.raw_response)
            return retry_state, terminal_state

        retry_state, terminal_state = asyncio.run(run())
        self.assertEqual(retry_state[:2], ("retryable_error", "rate_limited"))
        self.assertGreaterEqual(retry_state[2], 299)
        self.assertEqual(terminal_state, ("failed", "failed", "invalid_output", "invalid raw"))

    def test_active_scope_and_numeric_rule_ids_are_unique(self):
        async def add(scope_key, numeric_id):
            factory = models.get_session_factory()
            async with factory() as session:
                session.add(ExceptionDraft(
                    transaction_id=f"txn-{scope_key}-{numeric_id}", event_line=numeric_id,
                    classification="false_positive", confidence=0.99, verdict="Fixture verdict long enough for policy.",
                    status="pending", validation_status="valid", scope_key=scope_key,
                    rule_numeric_id=numeric_id,
                ))
                try:
                    await session.commit()
                    return True
                except IntegrityError:
                    await session.rollback()
                    return False

        async def run():
            first = await add("scope-a", 1000001)
            same_scope = await add("scope-a", 1000002)
            same_id = await add("scope-b", 1000001)
            stale = await add("scope-c", 1000003)
            factory = models.get_session_factory()
            async with factory() as session:
                draft = (await session.execute(
                    select(ExceptionDraft).where(ExceptionDraft.scope_key == "scope-c")
                )).scalars().one()
                draft.status = "stale"
                await session.commit()
            reused_after_stale = await add("scope-c", 1000003)
            return first, same_scope, same_id, stale, reused_after_stale

        self.assertEqual(asyncio.run(run()), (True, False, False, True, True))

    def test_pending_draft_upgrades_after_reanalyze_with_route(self):
        from services.draft_scope import canonical_scope_key, rule_numeric_id
        from services.exception_builder import build_exception_rule

        scope = {
            "uri": "/search",
            "rule_id": "942100",
            "collection": "ARGS",
            "parameter": "q",
        }
        scope_key = canonical_scope_key(scope)
        rule = build_exception_rule(scope)
        numeric = rule_numeric_id(rule)
        result = {
            "classification": "false_positive",
            "confidence": 0.96,
            "verdict": "Route profile explains a legitimate product search parameter.",
            "context_factors": ["route match"],
            "uncertainty_factors": [],
        }

        async def run():
            factory = models.get_session_factory()
            async with factory() as session:
                case = self._case(10)
                session.add(case)
                await session.flush()
                first_revision = AnalysisRevision(
                    analysis_case_id=case.id,
                    model="fixture",
                    prompt_version="test",
                    state="complete",
                    context={},
                    model_settings={},
                    classification="false_positive",
                    confidence=0.91,
                    verdict="Likely false positive pending route profile.",
                    validation_status="missing_application_context",
                )
                session.add(first_revision)
                await session.flush()
                draft = ExceptionDraft(
                    transaction_id="txn-upgrade",
                    event_line=1,
                    classification="false_positive",
                    confidence=0.91,
                    verdict="Likely false positive pending route profile.",
                    status="pending",
                    validation_status="missing_application_context",
                    validation_error="Create a matching application route profile, then explicitly reanalyze.",
                    analysis_revision_id=first_revision.id,
                    scope_key=scope_key,
                    supporting_case_count=1,
                )
                session.add(draft)
                await session.commit()
                draft_id = draft.id
                case_id = case.id

            async with factory() as session:
                case = await session.get(AnalysisCase, case_id)
                second_revision = AnalysisRevision(
                    analysis_case_id=case.id,
                    model="fixture",
                    prompt_version="test",
                    state="complete",
                    context={},
                    model_settings={},
                )
                session.add(second_revision)
                await session.flush()
                draft = await session.get(ExceptionDraft, draft_id)
                agent.refresh_active_false_positive_draft(
                    draft,
                    case=case,
                    revision=second_revision,
                    result=result,
                    scope=scope,
                    match_index=0,
                    sibling_rule_ids=[],
                    normalized_rule=rule,
                    validation_status="valid",
                    validation_error=None,
                    numeric_id=numeric,
                    crs_raw=None,
                    transaction_id="txn-upgrade-2",
                    event_line=2,
                )
                await session.commit()

            async with factory() as session:
                draft = await session.get(ExceptionDraft, draft_id)
                return (
                    draft.status,
                    draft.validation_status,
                    draft.proposed_rule,
                    draft.rule_numeric_id,
                    draft.supporting_case_count,
                    draft.analysis_revision_id,
                )

        status, validation, proposed, rule_id, support, revision_id = asyncio.run(run())
        self.assertEqual(status, "pending")
        self.assertEqual(validation, "valid")
        self.assertEqual(proposed, rule)
        self.assertEqual(rule_id, numeric)
        self.assertEqual(support, 2)
        self.assertIsNotNone(revision_id)

    def test_approved_draft_is_not_rewritten_on_merge(self):
        from services.draft_scope import canonical_scope_key, rule_numeric_id
        from services.exception_builder import build_exception_rule

        scope = {
            "uri": "/search",
            "rule_id": "942100",
            "collection": "ARGS",
            "parameter": "q",
        }
        scope_key = canonical_scope_key(scope)
        original = build_exception_rule(scope)
        other_scope = {
            "uri": "/search",
            "rule_id": "942100",
            "collection": "ARGS",
            "parameter": "other",
        }
        # Different parameter would change the rule text; merge must ignore for approved.
        other_rule = build_exception_rule(other_scope)

        async def run():
            factory = models.get_session_factory()
            async with factory() as session:
                case = self._case(11)
                session.add(case)
                await session.flush()
                revision = AnalysisRevision(
                    analysis_case_id=case.id,
                    model="fixture",
                    prompt_version="test",
                    state="complete",
                    context={},
                    model_settings={},
                )
                session.add(revision)
                await session.flush()
                draft = ExceptionDraft(
                    transaction_id="txn-approved",
                    event_line=1,
                    classification="false_positive",
                    confidence=0.99,
                    verdict="Approved exclusion for product search.",
                    status="approved",
                    validation_status="valid",
                    proposed_rule=original,
                    raw_proposed_rule=original,
                    rule_placement="before_crs",
                    analysis_revision_id=revision.id,
                    scope_key=scope_key,
                    rule_numeric_id=rule_numeric_id(original),
                    supporting_case_count=1,
                )
                session.add(draft)
                await session.commit()
                draft_id = draft.id
                case_id = case.id
                original_revision = revision.id

            async with factory() as session:
                case = await session.get(AnalysisCase, case_id)
                next_revision = AnalysisRevision(
                    analysis_case_id=case.id,
                    model="fixture",
                    prompt_version="test",
                    state="complete",
                    context={},
                    model_settings={},
                )
                session.add(next_revision)
                await session.flush()
                draft = await session.get(ExceptionDraft, draft_id)
                agent.refresh_active_false_positive_draft(
                    draft,
                    case=case,
                    revision=next_revision,
                    result={
                        "classification": "false_positive",
                        "confidence": 0.5,
                        "verdict": "Should not overwrite approved drafts.",
                        "context_factors": [],
                        "uncertainty_factors": [],
                    },
                    scope=scope,
                    match_index=0,
                    sibling_rule_ids=[],
                    normalized_rule=other_rule,
                    validation_status="valid",
                    validation_error=None,
                    numeric_id=rule_numeric_id(other_rule),
                    crs_raw=None,
                    transaction_id="txn-approved-2",
                    event_line=9,
                )
                await session.commit()

            async with factory() as session:
                draft = await session.get(ExceptionDraft, draft_id)
                return (
                    draft.status,
                    draft.proposed_rule,
                    draft.verdict,
                    draft.supporting_case_count,
                    draft.analysis_revision_id,
                    original_revision,
                )

        status, proposed, verdict, support, revision_id, kept_revision = asyncio.run(run())
        self.assertEqual(status, "approved")
        self.assertEqual(proposed, original)
        self.assertEqual(verdict, "Approved exclusion for product search.")
        self.assertEqual(support, 2)
        self.assertEqual(revision_id, kept_revision)

    def test_approve_id_conflict_marks_draft_stale(self):
        """Defense-in-depth path: conflicting rule id must leave no half-pending draft.

        Partial unique indexes normally prevent two active rows with the same
        rule_numeric_id; the approve handler still retires the victim as stale.
        """
        from fastapi import HTTPException
        from routers import exceptions as exceptions_router
        from services.exception_builder import build_exception_rule

        rule = build_exception_rule({
            "uri": "/search",
            "rule_id": "942100",
            "collection": "ARGS",
            "parameter": "q",
        })

        async def run():
            factory = models.get_session_factory()
            async with factory() as session:
                case = self._case(40)
                session.add(case)
                await session.flush()
                revision = AnalysisRevision(
                    analysis_case_id=case.id,
                    model="fixture",
                    prompt_version="test",
                    state="complete",
                    context={},
                    model_settings={},
                )
                session.add(revision)
                await session.flush()
                draft = ExceptionDraft(
                    transaction_id="txn-id-conflict",
                    event_line=1,
                    classification="false_positive",
                    confidence=0.99,
                    verdict="Pending draft that hits an id conflict on approve.",
                    status="pending",
                    validation_status="valid",
                    proposed_rule=rule,
                    rule_placement="before_crs",
                    analysis_revision_id=revision.id,
                    scope_key="scope-id-conflict-victim",
                    rule_numeric_id=1_000_042,
                )
                session.add(draft)
                await session.commit()
                draft_id = draft.id

            async with factory() as session:
                # Patch the id-conflict query to simulate a legacy/racy peer row.
                original_execute = session.execute

                async def execute_with_conflict(statement, *args, **kwargs):
                    sql = str(statement).lower()
                    where = sql.split("where", 1)
                    # Only the approve id-conflict filter matches rule_numeric_id in WHERE.
                    if len(where) == 2 and "rule_numeric_id" in where[1]:
                        class _Result:
                            def scalar_one_or_none(self_inner):
                                return 999
                            def scalars(self_inner):
                                return self_inner
                            def first(self_inner):
                                return None
                        return _Result()
                    return await original_execute(statement, *args, **kwargs)

                session.execute = execute_with_conflict  # type: ignore[method-assign]
                try:
                    await exceptions_router.approve_exception(draft_id, session)
                    raised = None
                except HTTPException as exc:
                    raised = (exc.status_code, str(exc.detail))
                draft = await session.get(ExceptionDraft, draft_id)
                return (
                    raised,
                    draft.status,
                    draft.validation_status,
                    draft.proposed_rule,
                    draft.rule_numeric_id,
                )

        raised, status, validation, proposed, numeric = asyncio.run(run())
        self.assertEqual(raised[0], 409)
        self.assertIn("Rule ID is already used", raised[1])
        self.assertEqual(status, "stale")
        self.assertEqual(validation, "id_conflict")
        self.assertIsNone(proposed)
        self.assertIsNone(numeric)
