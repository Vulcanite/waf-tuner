"""Operator review and evidence APIs exercised against isolated SQLite."""
import asyncio
import csv
import hashlib
import io
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from db import models
from routers import analytics, cases, events, exceptions, profiles
from services import agent
from services.profile_match import application_context_for, route_supports_exception
from services.crs_index import CRSRule
from services.draft_scope import canonical_scope_key, rule_numeric_id
from services.exception_builder import build_exception_rule


def test_specific_route_with_named_evidence_wins_over_a_catchall():
    catchall = SimpleNamespace(id=1, name="default-lab", version=9, context={}, source_metadata={},
                               host_patterns=["catalog.test"], routes=[{"path": "/*"}])
    specific = SimpleNamespace(id=2, name="catalog", version=1, context={}, source_metadata={}, host_patterns=["*.test"],
                              routes=[{"path": "/catalog", "methods": ["GET"], "parameters": {"q": "product search"}}])
    chosen, context = application_context_for([catchall, specific], "catalog.test", "GET", "/catalog")
    assert chosen is specific
    assert route_supports_exception(context, "ARGS", "q")
    assert not route_supports_exception(context, "ARGS", "other")
    chosen, context = application_context_for([catchall, specific], "catalog.test", "POST", "/catalog")
    assert chosen is catchall
    assert not route_supports_exception(context, "ARGS", "q")


def test_exclusion_identity_matches_exact_scoped_rule():
    scope = {"uri": "/catalog/", "collection": "ARGS", "parameter": "q", "rule_id": "10001",
             "host": "catalog.test", "method": "GET"}
    text = build_exception_rule(scope)
    lines = text.splitlines()
    assert 'REQUEST_FILENAME "@streq /catalog/"' in lines[0]
    assert 'REQUEST_METHOD "@streq GET"' in lines[1]
    assert "catalog[.]test" in lines[2]
    assert "ctl:" not in "\n".join(lines[:2])
    assert "ctl:ruleRemoveTargetById=10001;ARGS:q" in lines[2]
    for alteration in ({"uri": "/catalog"}, {"host": "other.test"}, {"method": "POST"}):
        assert canonical_scope_key(scope) != canonical_scope_key({**scope, **alteration})


@pytest.fixture
def sqlite(monkeypatch, tmp_path):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "review.sqlite"))
    monkeypatch.setattr(models, "_async_engine", None)
    monkeypatch.setattr(models, "_async_session_factory", None)
    try:
        yield
    finally:
        if models._async_engine is not None:
            asyncio.run(models._async_engine.dispose())


def test_event_lists_project_metadata_and_health_uses_timing_samples(sqlite):
    async def run():
        await models.init_db()
        now = datetime.now(timezone.utc)
        async with models.get_session_factory()() as db:
            event = models.AuditEvent(transaction_id="catalog-test", event_line=17, timestamp=now, path="/catalog",
                                      anomaly_score=5, raw_event={
                "transaction_id": "catalog-test", "method": "GET", "uri": "/catalog?q=music",
                "raw_request": {"body": "fixture evidence only"},
                "matches": [{"rule_id": "10001", "rule_message": "Fixture", "matched_data": "music"}],
            })
            case = models.AnalysisCase(fingerprint="catalog-test", method="GET", path="/catalog", rule_id="10001",
                                       latest_event_line=17, state="complete", application_host="catalog.test")
            db.add_all([event, case])
            await db.flush()
            for ms in (10, 20, 100):
                db.add(models.AnalysisRevision(
                    analysis_case_id=case.id, model="fixture", prompt_version="demo", state="complete",
                    completed_at=now, stage_metrics={"audit_to_verdict_ms": ms},
                ))
            await db.commit()

            projected = await events.list_events(rule_id="10001", db=db)
            assert projected["total"] == 1
            item = projected["items"][0]
            assert item["uri"] == "/catalog" and item["event_line"] == 17
            assert item["matches"] == [{"rule_id": "10001"}]
            assert "raw_request" not in item
            assert (await events.get_event(17, db))["event"]["raw_request"]["body"] == "fixture evidence only"
            assert (await analytics.top_rules(db))[0]["count"] == 1
            assert (await analytics.top_uris(db))[0]["uri"] == "/catalog"
            assert (await analytics.timeline(interval="hour", db=db))[0]["count"] == 1
            assert (await analytics.analysis_health(db))["stages_last_hour"]["audit_to_verdict_ms"] == {
                "samples": 3, "p50": 20, "p95": 100,
            }
            detail = await cases.get_case(case.id, db, revision_limit=1)
            earlier = await cases.get_case(case.id, db, revision_limit=2, before_revision=detail["next_revision"])
            assert len(detail["revisions"]) == 1 and len(earlier["revisions"]) == 2
    asyncio.run(run())


def test_profile_addition_and_reanalysis_only_change_affected_cases(sqlite, monkeypatch):
    queue = asyncio.Event()
    monkeypatch.setattr(agent, "analysis_queue_changed", queue)

    async def run():
        await models.init_db()
        async with models.get_session_factory()() as db:
            for n, host in enumerate(("catalog.test", "other.test"), 1):
                db.add(models.AnalysisCase(fingerprint=host, application_host=host, method="GET", path="/catalog",
                                           rule_id="10001", latest_event_line=n, state="complete"))
            await db.commit()
            body = profiles.ProfileBody(name="catalog", host_patterns=["catalog.test"], routes=[{"path": "/catalog"}])
            await profiles.create_profile(body, db)
            affected, unrelated = (await db.scalars(select(models.AnalysisCase).order_by(models.AnalysisCase.id))).all()
            assert affected.state == "stale" and unrelated.state == "complete"
            requeued = await cases.reanalyze_case(affected.id, db)
            assert requeued["state"] == "queued" and unrelated.state == "complete"
            assert queue.is_set()
    asyncio.run(run())


def test_copy_and_export_require_approved_current_scoped_rule(sqlite, monkeypatch):
    crs_rule = CRSRule(
        rule_id="10001", raw='SecRule ARGS:q "@streq music" "id:10001,phase:2,log"',
        targets=["ARGS:q"], operator="@streq music", message="Local test rule", tags=[],
        paranoia_level=0, phase=2, severity="NOTICE", chain=False, signature="signature-a",
    )
    monkeypatch.setattr(exceptions, "get_rule", lambda _: crs_rule)
    monkeypatch.setattr(exceptions, "current_analysis_generation", lambda: "fixture-generation")
    scope = {"uri": "/catalog", "collection": "ARGS", "parameter": "q", "rule_id": "10001",
             "host": "catalog.test", "method": "GET", "match_index": 0}
    proposed_rule = build_exception_rule(scope)

    async def run():
        await models.init_db()
        now = datetime.now(timezone.utc)
        async with models.get_session_factory()() as db:
            case = models.AnalysisCase(
                fingerprint="catalog-test", method="GET", path="/catalog", rule_id="10001", collection="ARGS",
                parameter="q", latest_event_line=17, state="complete", application_host="catalog.test",
                completed_generation="fixture-generation",
            )
            profile = models.ApplicationProfile(name="catalog", version=1, host_patterns=["catalog.test"], routes=[{
                "path": "/catalog", "parameters": {"q": "product search"},
            }])
            event = models.AuditEvent(transaction_id="catalog-test", event_line=17, timestamp=now, raw_event={
                "transaction_id": "catalog-test", "method": "GET", "uri": "/catalog?q=music",
                "raw_request": {"headers": {"Host": "catalog.test"}},
                "matches": [{"rule_id": "10001", "matched_data": "music"}],
            })
            db.add_all([case, event, profile])
            await db.flush()
            revision = models.AnalysisRevision(
                analysis_case_id=case.id, state="complete", classification="false_positive", model="fixture",
                prompt_version="test", profile_version=1, application_profile_id=profile.id,
                crs_digest=crs_rule.signature, validation_status="valid",
                normalized_rule=proposed_rule, proposed_rule_scope=scope,
            )
            db.add(revision)
            await db.flush()
            draft = models.ExceptionDraft(
                analysis_revision_id=revision.id, event_line=17, transaction_id="catalog-test",
                classification="false_positive", confidence=0.96, verdict="Product search accepts this keyword.",
                status="pending", validation_status="valid", proposed_rule_scope=scope,
                proposed_rule=proposed_rule, crs_rule_raw=crs_rule.raw,
                scope_key=canonical_scope_key(scope), rule_numeric_id=rule_numeric_id(proposed_rule),
            )
            db.add(draft)
            await db.commit()

            assert (await exceptions.list_exceptions(db=db))["items"][0]["proposed_rule"] is None
            approved = await exceptions.approve_exception(draft.id, db)
            assert approved["status"] == "approved" and approved["proposed_rule"] == proposed_rule

            async def exported_rule():
                response = await exceptions.export_false_positives()
                content = "".join([chunk async for chunk in response.body_iterator])
                return next(csv.DictReader(io.StringIO(content)))["Proposed Exception Rule"]

            assert await exported_rule() == proposed_rule
            monkeypatch.setattr(exceptions, "current_analysis_generation", lambda: "new-generation")
            assert (await exceptions.get_exception(draft.id, db))["status"] == "stale"
            assert await exported_rule() == ""
            monkeypatch.setattr(exceptions, "current_analysis_generation", lambda: "fixture-generation")
            crs_rule.chain = True
            assert (await exceptions.get_exception(draft.id, db))["status"] == "stale"
            assert await exported_rule() == ""
            crs_rule.chain = False
            crs_rule.signature = "signature-b"  # same directive text, edited .data file
            assert (await exceptions.get_exception(draft.id, db))["status"] == "stale"
            assert await exported_rule() == ""
            crs_rule.signature = "signature-a"
            monkeypatch.setattr(exceptions, "get_rule", lambda _: None)
            assert (await exceptions.get_exception(draft.id, db))["status"] == "stale"
            assert await exported_rule() == ""
    asyncio.run(run())


def test_expired_occurrence_blocks_reanalysis(sqlite):
    async def run():
        await models.init_db()
        async with models.get_session_factory()() as db:
            case = models.AnalysisCase(
                fingerprint="expired", method="GET", path="/catalog", rule_id="10001",
                latest_event_line=1, state="complete", matched_data="old evidence",
            )
            event = models.AuditEvent(transaction_id="expired", event_line=1, raw_event={"evidence_expired": True})
            db.add_all([case, event])
            await db.flush()
            db.add(models.IncidentOccurrence(
                analysis_case_id=case.id, audit_event_id=event.id, transaction_id="expired",
                event_line=1, rule_id="10001", fingerprint="expired", match_index=0,
            ))
            await db.commit()
            detail = await cases.get_case(case.id, db)
            assert detail["evidence_expired"] and detail["matched_data"] is None
            with pytest.raises(HTTPException, match="Audit evidence expired") as error:
                await cases.reanalyze_case(case.id, db)
            assert error.value.status_code == 409 and case.state == "complete"
    asyncio.run(run())


def test_detection_without_a_method_blocks_an_overlapping_get_exclusion(sqlite):
    from services.scope_conflicts import has_true_positive, invalidate_false_positive_drafts

    scope = {"uri": "/catalog", "collection": "ARGS", "parameter": "q", "rule_id": "10001",
             "host": "catalog.test", "method": "GET"}

    async def run():
        await models.init_db()
        async with models.get_session_factory()() as db:
            def case(name, method, classification):
                row = models.AnalysisCase(
                    fingerprint=name, method=method, path="/catalog", rule_id="10001", collection="ARGS",
                    parameter="q", latest_event_line=1, state="complete", application_host="catalog.test",
                )
                db.add(row)
                return row, classification

            rows = [case("allowed", "GET", "false_positive"), case("detected", "", "true_positive")]
            await db.flush()
            for row, classification in rows:
                db.add(models.AnalysisRevision(
                    analysis_case_id=row.id, state="complete", classification=classification, model="fixture",
                    prompt_version="test", validation_status="valid", proposed_rule_scope=scope,
                    normalized_rule="rule" if classification == "false_positive" else None,
                ))
            await db.flush()
            revision = (await db.scalars(select(models.AnalysisRevision).where(
                models.AnalysisRevision.classification == "false_positive"))).one()
            db.add(models.ExceptionDraft(
                analysis_revision_id=revision.id, event_line=1, transaction_id="allowed",
                classification="false_positive", confidence=0.95, verdict="Search term.", status="approved",
                validation_status="valid", proposed_rule_scope=scope, proposed_rule="rule",
                scope_key=canonical_scope_key(scope),
            ))
            await db.commit()
            allowed, detected = rows[0][0], rows[1][0]
            # Exclusion approved after the detection: the overlap check must see the method-less detection.
            assert await has_true_positive(db, allowed, scope)
            # Detection arriving after the exclusion: the approved GET draft must be invalidated.
            assert await invalidate_false_positive_drafts(db, detected) == 1
    asyncio.run(run())
