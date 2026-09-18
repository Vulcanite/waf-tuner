import os
import tempfile
import unittest
from pathlib import Path

from services.application_context import _route_score
from services.crs_index import build_crs_index
from services.exception_builder import build_exception_rule, can_build_exception
from services.incidents import extract_match_target, incident_fingerprint, normalized_path
from services.log_tailer import _decode_complete_objects, _last_archived_transaction
from services.redaction import REDACTED, redact_request
from services.rule_validator import validate_structure


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

    def test_last_archived_transaction_supports_large_records(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory, "events.jsonl")
            archive.write_text(
                '{"transaction_id":"one"}\n'
                + '{"transaction_id":"two","body":"'
                + ("x" * 70000)
                + '"}\n'
            )
            self.assertEqual(_last_archived_transaction(str(archive)), "two")


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


class RedactionTests(unittest.TestCase):
    def test_headers_and_nested_body_secrets_are_removed(self):
        result = redact_request({
            "headers": {"Authorization": "Bearer secret", "Content-Type": "application/json"},
            "body": '{"user":"alice","password":"secret","nested":{"api_key":"value"}}',
        })
        self.assertEqual(result["headers"]["Authorization"], REDACTED)
        self.assertEqual(result["body"]["password"], REDACTED)
        self.assertEqual(result["body"]["nested"]["api_key"], REDACTED)
        self.assertEqual(result["body"]["user"], "alice")

    def test_form_password_and_multipart_body_are_removed(self):
        form = redact_request({
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "body": "username=alice&password=secret",
        })
        self.assertEqual(form["body"]["password"], REDACTED)
        upload = redact_request({
            "headers": {"Content-Type": "multipart/form-data; boundary=abc"},
            "body": "--abc\r\nsecret file bytes\r\n--abc--",
        })
        self.assertEqual(upload["body"]["multipart"], "[MULTIPART BODY OMITTED]")


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

    def test_rejects_missing_parameter(self):
        ok, err = can_build_exception({**self.scope, "parameter": None})
        self.assertFalse(ok)
        self.assertIn("parameter", err.lower())


class RulePolicyTests(unittest.TestCase):
    def setUp(self):
        self.scope = {"uri": "/search", "collection": "ARGS", "parameter": "q", "rule_id": "942100"}

    def test_builder_output_validates(self):
        raw = build_exception_rule(self.scope)
        normalized, error = validate_structure(raw, self.scope)
        self.assertIsNone(error)
        self.assertIn("REQUEST_FILENAME", normalized)
        self.assertIn('@streq /search', normalized)

    def test_legacy_request_uri_sketch_is_canonicalized(self):
        raw = (
            'SecRule REQUEST_URI "@beginsWith /search" '
            '"id:42,phase:2,pass,nolog,t:none,ctl:ruleRemoveTargetById=942100;ARGS:q"'
        )
        normalized, error = validate_structure(raw, self.scope)
        self.assertIsNone(error)
        self.assertIn("REQUEST_FILENAME", normalized)
        self.assertIn("phase:1", normalized)
        self.assertNotIn("id:42", normalized)

    def test_empty_raw_synthesizes_from_scope(self):
        normalized, error = validate_structure("", self.scope)
        self.assertIsNone(error)
        self.assertIn("REQUEST_FILENAME", normalized)

    def test_global_removal_is_rejected(self):
        raw = (
            'SecRule REQUEST_FILENAME "@streq /search" '
            '"id:42,phase:1,pass,nolog,ctl:ruleRemoveById=942100"'
        )
        normalized, error = validate_structure(raw, self.scope)
        self.assertIsNone(normalized)
        self.assertIn("forbidden", error)

    def test_unobserved_target_is_rejected(self):
        raw = (
            'SecRule REQUEST_FILENAME "@streq /search" '
            '"id:42,phase:1,pass,nolog,ctl:ruleRemoveTargetById=942100;ARGS:other"'
        )
        normalized, error = validate_structure(raw, self.scope)
        self.assertIsNone(normalized)
        self.assertIn("not observed", error)

    def test_additional_ctl_action_is_rejected(self):
        raw = (
            'SecRule REQUEST_FILENAME "@streq /search" '
            '"id:42,phase:1,pass,nolog,ctl:ruleRemoveTargetById=942100;ARGS:q,'
            'ctl:ruleEngine=Off"'
        )
        normalized, error = validate_structure(raw, self.scope)
        self.assertIsNone(normalized)
        self.assertIn("Only ctl:ruleRemoveTargetById", error)

    def test_unknown_side_effect_action_is_rejected(self):
        raw = (
            'SecRule REQUEST_FILENAME "@streq /search" '
            '"id:42,phase:1,pass,nolog,pause:5000,'
            'ctl:ruleRemoveTargetById=942100;ARGS:q"'
        )
        normalized, error = validate_structure(raw, self.scope)
        self.assertIsNone(normalized)
        self.assertIn("not permitted", error)

    def test_second_rule_is_rejected(self):
        raw = (
            'SecRule REQUEST_FILENAME "@streq /search" '
            '"id:42,phase:1,pass,nolog,ctl:ruleRemoveTargetById=942100;ARGS:q"\n'
            'SecRule REQUEST_FILENAME "@streq /admin" "id:43,phase:1,pass,nolog"'
        )
        normalized, error = validate_structure(raw, self.scope)
        self.assertIsNone(normalized)
        self.assertIn("one non-chained", error)

    def test_broader_uri_operand_is_rejected(self):
        raw = (
            'SecRule REQUEST_FILENAME "@beginsWith /sear" '
            '"id:42,phase:1,pass,nolog,ctl:ruleRemoveTargetById=942100;ARGS:q"'
        )
        normalized, error = validate_structure(raw, self.scope)
        self.assertIsNone(normalized)
        self.assertIn("exact incident path", error)

    def test_regex_uri_scope_is_rejected(self):
        raw = (
            'SecRule REQUEST_FILENAME "@rx ^/search(?:/.*)?$" '
            '"id:42,phase:1,pass,nolog,ctl:ruleRemoveTargetById=942100;ARGS:q"'
        )
        normalized, error = validate_structure(raw, self.scope)
        self.assertIsNone(normalized)
        self.assertIn("unsupported operator", error)

    def test_transaction_collection_is_rejected(self):
        scope = {
            "uri": "/search", "collection": "TX",
            "parameter": "inbound_anomaly_score", "rule_id": "949110",
        }
        raw = (
            'SecRule REQUEST_FILENAME "@streq /search" '
            '"id:42,phase:1,pass,nolog,ctl:ruleRemoveTargetById=949110;TX:inbound_anomaly_score"'
        )
        normalized, error = validate_structure(raw, scope)
        self.assertIsNone(normalized)
        self.assertTrue(
            "auto-excluded" in (error or "").lower()
            or "parameter" in (error or "").lower()
            or "collection" in (error or "").lower()
        )


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
                "EVENTS_JSONL_PATH": os.environ.get("EVENTS_JSONL_PATH"),
                "MODSEC_AUDIT_LOG": os.environ.get("MODSEC_AUDIT_LOG"),
            }
            cfg = Path(directory) / "runtime_config.json"
            log_path = Path(directory) / "modsec" / "audit.log"
            log_path.parent.mkdir(parents=True)
            log_path.write_text("")
            os.environ["RUNTIME_CONFIG_PATH"] = str(cfg)
            os.environ["EVENTS_JSONL_PATH"] = str(Path(directory) / "events.jsonl")
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
        from services.application_context import (
            DEFAULT_LAB_PROFILE_NAME,
            ensure_default_application_profile,
            select_application_context,
        )
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
                    return created, again, count, profile, context

                created, again, count, profile, context = asyncio.run(_run())
                self.assertTrue(created)
                self.assertFalse(again)
                self.assertEqual(count, 1)
                self.assertEqual(profile.name, DEFAULT_LAB_PROFILE_NAME)
                self.assertEqual(context["route"]["path"], "/vulnerabilities/sqli/")
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
    def test_no_edge_writes(self):
        from services.app_mode import product_info

        info = product_info()
        self.assertFalse(info["deploy_enabled"])
        self.assertFalse(info["config_writes_enabled"])
        self.assertFalse(info["engine_mode_control_enabled"])
        self.assertIn("JSON", info["audit_log_contract"]["format"])


if __name__ == "__main__":
    unittest.main()
