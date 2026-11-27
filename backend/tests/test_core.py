import os
import tempfile
import unittest
from pathlib import Path

from services.profile_match import _route_score
from services.crs_index import build_crs_index
from services.exception_builder import build_exception_rule, can_build_exception
from services.incidents import incident_fingerprint, normalized_path
from services.inference_context import extract_match_target
from services.log_tailer import _decode_complete_objects


class AuditFramingTests(unittest.TestCase):
    def test_partial_json_and_quoted_braces_are_preserved(self):
        first = b'{"transaction":{"id":"one","request":{"body":"value } { text"}}}'
        second = b'{"transaction":{"id":"two"}}'
        objects, pending = _decode_complete_objects(first[:25])
        self.assertEqual(objects, [])
        self.assertEqual(pending, first[:25])

        objects, pending = _decode_complete_objects(pending + first[25:] + second[:10])
        self.assertEqual([item["transaction"]["id"] for item in objects], ["one"])
        self.assertEqual(pending, second[:10])

        objects, pending = _decode_complete_objects(pending + second[10:])
        self.assertEqual(objects[0]["transaction"]["id"], "two")
        self.assertEqual(pending, b"")

    def test_many_objects_with_noise_decode_in_order(self):
        records = "".join(f'{{"n": {i}, "s": "}}"}}\n' for i in range(20000))
        objects, rest = _decode_complete_objects(("noise " + records + '{"n": "partial').encode())
        self.assertEqual(len(objects), 20000)
        self.assertEqual(objects[-1]["n"], 19999)
        self.assertEqual(rest, b'{"n": "partial')

    def test_malformed_entry_does_not_block_later_entries(self):
        import asyncio
        import json
        from unittest import mock
        from db import models as db_models
        from services import log_tailer as tailer

        def entry(txn, request):
            return json.dumps({"transaction": {
                "id": txn, "request": request, "response": {"status": 200},
                "messages": [{"ruleId": "942100", "message": "SQLi", "data": "within ARGS:q"}],
            }})

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            audit = root / "audit.log"
            audit.write_text(entry("bad", "not-an-object") + "\n" + entry("good", {"method": "GET", "uri": "/s?q=1"}) + "\n")
            env = {
                "DATABASE_PATH": str(root / "t.db"), "DATA_DIR": str(root),
                "AUDIT_CURSOR_PATH": str(root / "cursor.json"), "RUNTIME_CONFIG_PATH": str(root / "rc.json"),
                "MODSEC_AUDIT_LOG": str(audit), "INCIDENT_FINGERPRINT_KEY": "test",
            }
            db_models._async_engine = None
            db_models._async_session_factory = None
            try:
                with mock.patch.dict(os.environ, env):
                    os.environ.pop("DATABASE_URL", None)

                    async def run():
                        from sqlalchemy import select
                        await db_models.init_db()
                        task = asyncio.create_task(tailer.log_tailer())
                        try:
                            for _ in range(50):
                                await asyncio.sleep(0.1)
                                async with db_models.get_session_factory()() as session:
                                    ids = set((await session.execute(
                                        select(db_models.AuditEvent.transaction_id))).scalars())
                                if "good" in ids:
                                    return ids
                            return ids
                        finally:
                            task.cancel()
                            await asyncio.gather(task, return_exceptions=True)

                    self.assertEqual(asyncio.run(run()), {"good"})
            finally:
                db_models._async_engine = None
                db_models._async_session_factory = None


class IncidentIdentityTests(unittest.TestCase):
    def test_target_and_stable_fingerprint(self):
        with tempfile.TemporaryDirectory() as directory:
            old_path = os.environ.get("INCIDENT_FINGERPRINT_KEY_PATH")
            old_key = os.environ.get("INCIDENT_FINGERPRINT_KEY")
            os.environ.pop("INCIDENT_FINGERPRINT_KEY", None)
            os.environ["INCIDENT_FINGERPRINT_KEY_PATH"] = str(Path(directory) / "key")
            try:
                event = {"method": "get", "uri": "/search?q=x"}
                match = {
                    "rule_id": "942100",
                    "matched_data": "Matched Data: select found within ARGS:q",
                }
                one = incident_fingerprint(event, match)
                two = incident_fingerprint(event, match)
                self.assertEqual(one, two)
                self.assertEqual(one[1:], ("ARGS", "q"))

                different_payload = {"method": "get", "uri": "/search?q=y"}
                self.assertNotEqual(one[0], incident_fingerprint(different_payload, match)[0])
            finally:
                if old_path is None:
                    os.environ.pop("INCIDENT_FINGERPRINT_KEY_PATH", None)
                else:
                    os.environ["INCIDENT_FINGERPRINT_KEY_PATH"] = old_path
                if old_key is not None:
                    os.environ["INCIDENT_FINGERPRINT_KEY"] = old_key

    def test_modsecurity_variable_format(self):
        self.assertEqual(
            extract_match_target("Matched operator against variable REQUEST_HEADERS:User-Agent)"),
            ("REQUEST_HEADERS", "User-Agent"),
        )

    def test_normalized_path_strips_query(self):
        self.assertEqual(normalized_path("/search?q=select+all"), "/search")


class ApplicationContextTests(unittest.TestCase):
    def test_route_specificity(self):
        self.assertGreater(
            _route_score({"path": "/users/me", "methods": ["GET"]}, "GET", "/users/me"),
            _route_score({"path": "/users/{id}", "methods": ["GET"]}, "GET", "/users/me"),
        )
        self.assertEqual(_route_score({"path": "/users/{id}", "methods": ["POST"]}, "GET", "/users/me"), -1)


class ExceptionBuilderTests(unittest.TestCase):
    def setUp(self):
        self.scope = {
            "uri": "/search",
            "collection": "ARGS",
            "parameter": "q",
            "rule_id": "942100",
            "host": "shop.example",
            "method": "GET",
        }

    def test_builds_request_filename_rule(self):
        rule = build_exception_rule(self.scope, phase=1)
        self.assertIn("REQUEST_FILENAME", rule)
        self.assertIn('@streq /search', rule)
        self.assertIn("ctl:ruleRemoveTargetById=942100;ARGS:q", rule)
        self.assertIn("phase:1", rule)
        self.assertRegex(rule, r"id:1\d{6}")

    def test_rejects_root_and_query_in_path(self):
        ok, _ = can_build_exception({**self.scope, "uri": "/"})
        self.assertFalse(ok)
        ok, _ = can_build_exception({**self.scope, "uri": "/search?q=1"})
        self.assertFalse(ok)

    def test_rejects_a_scope_without_host_or_method(self):
        for key in ("host", "method"):
            ok, err = can_build_exception({**self.scope, key: None})
            self.assertFalse(ok)
            self.assertIn("host and HTTP method", err)

    def test_rejects_missing_parameter(self):
        ok, err = can_build_exception({**self.scope, "parameter": None})
        self.assertFalse(ok)
        self.assertIn("parameter", err.lower())


class RulePolicyTests(unittest.TestCase):
    """The server builds the only rule shape; these are the scopes it must refuse."""

    def setUp(self):
        self.scope = {"uri": "/search", "collection": "ARGS", "parameter": "q", "rule_id": "942100",
                      "host": "shop.example", "method": "GET"}

    def test_rule_removes_only_the_observed_target(self):
        rule = build_exception_rule(self.scope)
        self.assertIn("ctl:ruleRemoveTargetById=942100;ARGS:q\"", rule)
        self.assertNotIn("ruleRemoveById", rule)
        self.assertIn("pass,nolog", rule)

    def test_regex_like_parameter_name_is_rejected(self):
        for name in ("/.*/", "a|b", "q:x", "a%2fb", "x y"):
            ok, err = can_build_exception({**self.scope, "parameter": name})
            self.assertFalse(ok, name)
            self.assertIn("unsafe", err)

    def test_plain_parameter_names_are_allowed(self):
        for name in ("q", "user.name", "items[0]", "csrf-token", "a_b"):
            self.assertTrue(can_build_exception({**self.scope, "parameter": name})[0], name)

    def test_non_numeric_rule_id_is_rejected(self):
        self.assertFalse(can_build_exception({**self.scope, "rule_id": "942100,ctl:ruleEngine=Off"})[0])

    def test_transaction_collection_is_rejected(self):
        scope = {**self.scope, "collection": "TX", "parameter": "inbound_anomaly_score", "rule_id": "949110"}
        ok, err = can_build_exception(scope)
        self.assertFalse(ok)
        self.assertIn("cannot be auto-excluded", err)


class CRSIndexTests(unittest.TestCase):
    def test_chain_children_are_included(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "rules.conf").write_text(
                'SecRule ARGS "@rx select" "id:942100,phase:2,pass,chain,msg:\'SQL\',tag:\'paranoia-level/1\'"\n'
                'SecRule REQUEST_METHOD "@streq POST" "t:none"\n'
            )
            rule = build_crs_index(directory)["942100"]
            self.assertTrue(rule.chain)
            self.assertEqual(len(rule.chain_rules), 1)
            self.assertIn("REQUEST_METHOD", rule.raw)


class MatchedEvidenceParseTests(unittest.TestCase):
    def test_snippet_and_full_value_are_split(self):
        # Import lazily so unit tests that only need builders stay light.
        from routers.exceptions import _parse_matched_evidence

        parsed = _parse_matched_evidence(
            "Matched Data: with <em found within ARGS:body: hello **world** with <em>markup</em>"
        )
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["snippet"], "with <em")
        self.assertEqual(parsed["variable"], "ARGS:body")
        self.assertEqual(parsed["full_value"], "hello **world** with <em>markup</em>")

    def test_empty_matched_data(self):
        from routers.exceptions import _parse_matched_evidence

        self.assertIsNone(_parse_matched_evidence(""))
        self.assertIsNone(_parse_matched_evidence(None))


class RuntimeConfigTests(unittest.TestCase):
    def test_audit_log_path_persists(self):
        from services import runtime_config as rc

        with tempfile.TemporaryDirectory() as directory:
            old = {
                "RUNTIME_CONFIG_PATH": os.environ.get("RUNTIME_CONFIG_PATH"),
                "DATA_DIR": os.environ.get("DATA_DIR"),
                "MODSEC_AUDIT_LOG": os.environ.get("MODSEC_AUDIT_LOG"),
            }
            cfg = Path(directory) / "runtime_config.json"
            log_path = Path(directory) / "modsec" / "audit.log"
            log_path.parent.mkdir(parents=True)
            log_path.write_text("")
            os.environ["RUNTIME_CONFIG_PATH"] = str(cfg)
            os.environ["DATA_DIR"] = directory
            os.environ.pop("MODSEC_AUDIT_LOG", None)
            rc._cache = None
            try:
                status = rc.set_audit_log_path(str(log_path))
                self.assertTrue(status["exists"])
                self.assertEqual(rc.get_audit_log_path(), str(log_path.resolve()))
                rc._cache = None
                self.assertEqual(rc.get_audit_log_path(), str(log_path.resolve()))
            finally:
                rc._cache = None
                for k, v in old.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v


class SqliteDbTests(unittest.TestCase):
    def test_init_db_creates_sqlite_file(self):
        import asyncio
        from db import models as db_models

        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "test.db"
            old_url = os.environ.get("DATABASE_URL")
            old_path = os.environ.get("DATABASE_PATH")
            os.environ.pop("DATABASE_URL", None)
            os.environ["DATABASE_PATH"] = str(db_path)
            # Reset cached engine so the new path is used.
            db_models._async_engine = None
            db_models._async_session_factory = None
            try:
                url = db_models.get_database_url()
                self.assertTrue(url.startswith("sqlite+aiosqlite:///"))
                self.assertIn(str(db_path), url)

                async def _run():
                    await db_models.init_db()
                    factory = db_models.get_session_factory()
                    async with factory() as session:
                        from db.models import ExceptionDraft
                        from sqlalchemy import select

                        count = (
                            await session.execute(select(ExceptionDraft.id).limit(1))
                        ).scalar_one_or_none()
                        self.assertIsNone(count)

                asyncio.run(_run())
                self.assertTrue(db_path.exists())
            finally:
                db_models._async_engine = None
                db_models._async_session_factory = None
                if old_url is None:
                    os.environ.pop("DATABASE_URL", None)
                else:
                    os.environ["DATABASE_URL"] = old_url
                if old_path is None:
                    os.environ.pop("DATABASE_PATH", None)
                else:
                    os.environ["DATABASE_PATH"] = old_path


class DefaultProfileSeedTests(unittest.TestCase):
    def _isolate_db(self, directory: str):
        from db import models as db_models

        self._db_models = db_models
        self._old_url = os.environ.get("DATABASE_URL")
        self._old_path = os.environ.get("DATABASE_PATH")
        self._old_seed = os.environ.get("SEED_DEFAULT_PROFILE")
        os.environ.pop("DATABASE_URL", None)
        os.environ["DATABASE_PATH"] = str(Path(directory) / "seed.db")
        db_models._async_engine = None
        db_models._async_session_factory = None

    def _restore_db(self):
        db_models = self._db_models
        if db_models._async_engine is not None:
            import asyncio

            asyncio.run(db_models._async_engine.dispose())
        db_models._async_engine = None
        db_models._async_session_factory = None
        if self._old_url is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = self._old_url
        if self._old_path is None:
            os.environ.pop("DATABASE_PATH", None)
        else:
            os.environ["DATABASE_PATH"] = self._old_path
        if self._old_seed is None:
            os.environ.pop("SEED_DEFAULT_PROFILE", None)
        else:
            os.environ["SEED_DEFAULT_PROFILE"] = self._old_seed

    def test_first_run_creates_catch_all_profile(self):
        import asyncio
        from db.models import ApplicationProfile
        from services.application_context import ensure_default_application_profile, select_application_context
        from services.lab_profiles import DEFAULT_LAB_PROFILE_NAME, SHOP_LAB_PROFILE_NAME
        from sqlalchemy import func, select

        with tempfile.TemporaryDirectory() as directory:
            self._isolate_db(directory)
            try:
                async def _run():
                    await self._db_models.init_db()
                    created = await ensure_default_application_profile()
                    again = await ensure_default_application_profile()
                    factory = self._db_models.get_session_factory()
                    async with factory() as session:
                        count = (
                            await session.execute(select(func.count()).select_from(ApplicationProfile))
                        ).scalar_one()
                        profile, context = await select_application_context(
                            session,
                            {
                                "method": "GET",
                                "uri": "/vulnerabilities/sqli/?id=select+all",
                                "raw_request": {"headers": {"Host": "localhost"}},
                            },
                        )
                        _, fallback = await select_application_context(
                            session,
                            {"method": "POST", "uri": "/some/other/app/path", "raw_request": {}},
                        )
                        shop, shop_context = await select_application_context(
                            session,
                            {
                                "method": "GET",
                                "uri": "/download?name=user-guide.v2.pdf",
                                "raw_request": {"headers": {"Host": "shop.lab:8080"}},
                            },
                        )
                        _, shop_fallback = await select_application_context(
                            session,
                            {"method": "GET", "uri": "/unknown", "raw_request": {"headers": {"Host": "shop.lab"}}},
                        )
                    return created, again, count, profile, context, fallback, shop, shop_context, shop_fallback

                created, again, count, profile, context, fallback, shop, shop_context, shop_fallback = asyncio.run(_run())
                self.assertTrue(created)
                self.assertFalse(again)
                self.assertEqual(count, 2)
                # The Flask lab app has its own seeded profile, selected by Host.
                self.assertEqual(shop.name, SHOP_LAB_PROFILE_NAME)
                self.assertEqual(shop_context["application"]["languages"], ["python"])
                self.assertEqual(shop_context["route"]["path"], "/download")
                self.assertIn("name", shop_context["route"]["parameters"])
                self.assertEqual(shop_fallback["profile_name"], SHOP_LAB_PROFILE_NAME)
                self.assertEqual(shop_fallback["route"]["path"], "/*")
                self.assertEqual(profile.name, DEFAULT_LAB_PROFILE_NAME)
                self.assertEqual(context["route"]["path"], "/vulnerabilities/sqli/")
                # Catch-all keeps REQUIRE_APPLICATION_CONTEXT (default on) satisfied
                # for any lab path, even without a Host header.
                self.assertEqual(fallback["route"]["path"], "/*")
            finally:
                self._restore_db()

    def test_seed_skipped_when_disabled(self):
        import asyncio

        from services.application_context import ensure_default_application_profile

        with tempfile.TemporaryDirectory() as directory:
            self._isolate_db(directory)
            os.environ["SEED_DEFAULT_PROFILE"] = "false"
            try:
                async def _run():
                    await self._db_models.init_db()
                    return await ensure_default_application_profile()

                self.assertFalse(asyncio.run(_run()))
            finally:
                self._restore_db()


class ProductInfoTests(unittest.TestCase):
    def test_audit_log_contract(self):
        from services.app_mode import product_info

        self.assertIn("JSON", product_info()["audit_log_contract"]["format"])


if __name__ == "__main__":
    unittest.main()


class TruncatedOutputTests(unittest.TestCase):
    def test_cut_off_output_is_refused_without_repair(self):
        import asyncio
        from types import SimpleNamespace
        from unittest import mock

        from services import agent

        draft = '{"classification": "false_positive", "confidence": 0.99, "verdict": "a draft written mid-reasoning", "context_factors": [], "uncertainty_factors": []}'
        calls = []

        class FakeClient:
            def __init__(self, **_kwargs):
                self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

            async def create(self, **options):
                calls.append(options)
                message = SimpleNamespace(content="Thinking... " + draft + " but wait", model_extra={})
                return SimpleNamespace(choices=[SimpleNamespace(message=message, finish_reason="length")], usage=None)

            async def close(self):
                pass

        async def noop(*_args, **_kwargs):
            return 1

        env = {"LLM_API_KEY": "test-key", "LLM_MAX_OUTPUT_TOKEN": "100"}
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(agent, "AsyncOpenAI", FakeClient), \
                mock.patch.object(agent, "_reserve_attempt", noop), \
                mock.patch.object(agent, "_finish_attempt", noop):
            with self.assertRaises(agent.InvalidOutputError) as caught:
                asyncio.run(agent._call_model({}, {}, revision_id=1))
        self.assertIn("cut off", str(caught.exception))
        self.assertEqual(len(calls), 1)  # no repair request
        self.assertEqual(calls[0]["extra_body"], {"thinking": {"type": "enabled"}, "reasoning_effort": "high"})


class ThinkingOptionsTests(unittest.TestCase):
    def test_defaults_enable_thinking_at_high_effort(self):
        from unittest import mock

        from services.llm_options import thinking_options

        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(thinking_options(), {"thinking": {"type": "enabled"}, "reasoning_effort": "high"})
        with mock.patch.dict(os.environ, {"LLM_THINKING": "disabled", "LLM_REASONING_EFFORT": "max"}):
            self.assertEqual(thinking_options(), {"thinking": {"type": "disabled"}})
        with mock.patch.dict(os.environ, {"LLM_THINKING": "off"}):
            self.assertEqual(thinking_options(), {})
        with mock.patch.dict(os.environ, {"LLM_THINKING": "yes"}), self.assertRaises(ValueError):
            thinking_options()

    def test_escalation_needs_thinking_and_passes_effort_through(self):
        from unittest import mock

        from services.llm_options import request_payload, request_settings

        env = {"LLM_API_KEY": "test", "LLM_ESCALATION_REASONING_EFFORT": "xhigh"}
        with mock.patch.dict(os.environ, env, clear=True):
            escalation = request_payload(request_settings(), [], "escalation")
            self.assertEqual((escalation["thinking"], escalation["reasoning_effort"]), ({"type": "enabled"}, "xhigh"))
        for thinking in ("off", "disabled"):
            with mock.patch.dict(os.environ, {**env, "LLM_THINKING": thinking}, clear=True):
                self.assertEqual(request_settings()["escalation_effort"], "")
