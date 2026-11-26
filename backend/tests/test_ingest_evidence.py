import asyncio
import errno
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import select
from sqlalchemy.exc import OperationalError

from db import models
from services.audit_event import normalize_audit_event
from services.inference_context import bound_repair_input, build_inference_context, serialize_inference_context
from services.incidents import incident_fingerprint, register_event
from services.redaction import sanitize_evidence_text
from services import log_tailer


def audit_object(transaction_id='test-event', host='shop.example'):
    return {
        'transaction': {
            'unique_id': transaction_id,
            'time_stamp': 'Mon Jan  1 12:00:00 2024',
            'request': {'method': 'POST', 'uri': '/search?q=books&q=music', 'headers': {'Host': host}},
            'messages': [
                {'message': 'Keyword match', 'details': {
                    'ruleId': '942100',
                    'match': "Matched operator against variable `ARGS:q' (Value: `books')",
                    'data': 'Matched Data: books found within ARGS:q: books',
                    'severity': '2',
                }},
                {'message': 'Inbound Anomaly Score Exceeded (Total Score: 8)', 'details': {'ruleId': '949110', 'severity': '2'}},
            ],
        },
    }


class EvidenceTests(unittest.TestCase):
    def test_native_timestamp_target_and_anomaly_score(self):
        with patch.dict(os.environ, {'MODSEC_AUDIT_TIMEZONE': 'UTC'}):
            event = normalize_audit_event(audit_object())
        self.assertEqual(event['timestamp'], '2024-01-01T12:00:00+00:00')
        self.assertEqual(event['timestamp_source'], 'audit_log')
        self.assertEqual(event['matches'][0]['collection'], 'ARGS')
        self.assertEqual(event['matches'][0]['parameter'], 'q')
        self.assertEqual((event['anomaly_score'], event['anomaly_score_source']), (8, 'modsecurity'))
        raw = audit_object()
        raw['transaction']['messages'].pop()
        self.assertEqual(normalize_audit_event(raw)['anomaly_score'], 5)

    def test_projection_keeps_duplicate_target_values_and_drops_unrelated_evidence(self):
        raw = audit_object()
        request = raw['transaction']['request']
        request['uri'] = '/account/top-secret-184?other=unrelated-private&q=books&q=music'
        request['headers']['Contact-Field'] = 'private-header'
        request['headers']['Content-Type'] = 'application/x-www-form-urlencoded'
        request['body'] = 'q=first&q=second&other=hidden-body&password=hidden-form-secret'
        event = normalize_audit_event(raw)
        context = build_inference_context(event, event['matches'][0], crs_rule={'operator': '@detectSQLi'})
        serialized = serialize_inference_context(context)
        self.assertEqual(context['incident']['matched_data'], 'books')
        self.assertEqual(context['incident']['uri']['query'], ['books', 'music'])
        self.assertEqual(context['request']['matched_values']['body'], ['first', 'second'])
        self.assertEqual(context['crs_rule']['operator'], '@detectSQLi')
        self.assertEqual(context['incident']['other_matches'][0]['rule_id'], '949110')
        for private in ('unrelated-private', 'private-header', 'hidden-body', 'hidden-form-secret'):
            self.assertNotIn(private, serialized)

    def test_native_matched_value_when_request_field_is_missing(self):
        event = normalize_audit_event(audit_object())
        event['uri'] = '/search'
        context = build_inference_context(event, event['matches'][0])
        self.assertEqual(context['request']['matched_values']['audit_log_value'], ['books'])
        self.assertFalse(context['redaction']['target_hidden'])

    def test_restart_opens_unread_rotated_inode_first(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'audit.log')
            path.write_text('first log')
            info = path.stat()
            path.rename(path.with_suffix('.log.1'))
            path.write_text('second log')
            cursor = {'device': info.st_dev, 'inode': info.st_ino, 'audit_path': str(path)}
            with log_tailer._open_log(str(path), log_tailer._path_identity(str(path)), cursor) as old:
                self.assertEqual(old.read(), b'first log')

    def test_unsafe_evidence_and_repairs_are_bounded(self):
        event = normalize_audit_event(audit_object())
        event['raw_request']['headers']['Authorization'] = 'private-authorization'
        match = {'rule_id': '942100', 'matched_data': 'private-authorization', 'collection': 'REQUEST_HEADERS', 'parameter': 'Authorization'}
        with patch.dict(os.environ, {'AI_MAX_CONTEXT_BYTES': '300'}):
            context = build_inference_context(event, match)
            serialized = serialize_inference_context(context)
            self.assertLessEqual(len(serialized.encode('utf-8')), 300)
            self.assertNotIn('private-authorization', serialized)
            candidate = '{"classification":"uncertain","verdict":"private-authorization"}'
            repaired = bound_repair_input(candidate, {'incident': {'rule_id': '942100'}})
            self.assertIn('uncertain', repaired)
            self.assertNotIn('private-authorization', repaired)
            quoted_credentials = '{"password": "private two words", "cookie": "private cookie"}'
            self.assertNotIn('private', sanitize_evidence_text(quoted_credentials))

    def test_case_identity_distinguishes_hosts_and_ignores_unrelated_field_values(self):
        first = normalize_audit_event(audit_object())
        second = normalize_audit_event(audit_object(host='news.example'))
        with patch.dict(os.environ, {'INCIDENT_FINGERPRINT_KEY': 'test-key'}):
            identity = incident_fingerprint(first, first['matches'][0])
            self.assertNotEqual(identity, incident_fingerprint(second, second['matches'][0]))
            first['uri'] += '&unrelated=another-value'
            self.assertEqual(identity, incident_fingerprint(first, first['matches'][0]))
            first['uri'] = '/search?q=music&q=books'
            self.assertNotEqual(identity, incident_fingerprint(first, first['matches'][0]))

    def test_restart_reconciles_the_actual_mirror_tail(self):
        with tempfile.TemporaryDirectory() as directory:
            active = Path(directory, 'events.jsonl')
            row = json.dumps({'transaction_id': 'orphan', 'event_line': 8}) + '\n'
            active.write_text(row)
            # A crash after rotation can leave a different record with the
            # same byte count as the old mirror in the checkpoint.
            cursor = {'archive_size': len(row), 'archive_last_transaction': 'before', 'archive_last_event_line': 7, 'next_event_line': 8}
            self.assertEqual(log_tailer._mirror_state(str(active), cursor), (len(row), 9, 'orphan', 8))

    def test_recovers_valid_record_after_a_corrupt_line_and_partial_utf8(self):
        raw = json.dumps(audit_object()).encode()
        malformed = b'{"transaction": [MALFORMED]}\n'
        trailing = b'{"s":"caf\xc3'
        objects, pending = log_tailer._decode_complete_objects(malformed + raw + b'\n' + trailing)
        self.assertEqual(objects[0]['transaction']['unique_id'], 'test-event')
        self.assertEqual(pending, trailing)
        objects, pending = log_tailer._decode_complete_objects(pending + b'\xa9"}\n')
        self.assertEqual(objects, [{'s': 'café'}])
        self.assertEqual(pending, b'')


class DurableIngestTests(unittest.IsolatedAsyncioTestCase):
    async def test_recovers_from_archive_and_sqlite_failures_at_eof(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            audit = root / 'audit.log'
            archive = root / 'events.jsonl'
            audit.write_text(json.dumps(audit_object()) + '\n')
            env = {
                'MODSEC_AUDIT_LOG': str(audit),
                'EVENTS_JSONL_PATH': str(archive),
                'AUDIT_CURSOR_PATH': str(root / 'cursor.json'),
                'RUNTIME_CONFIG_PATH': str(root / 'runtime.json'),
                'DATABASE_URL': f'sqlite+aiosqlite:///{root / "test.db"}',
                'INCIDENT_FINGERPRINT_KEY': 'test-key',
            }
            models._async_engine = None
            models._async_session_factory = None
            with patch.dict(os.environ, env):
                await models.init_db()
                archive_attempts = db_attempts = 0
                append_event = log_tailer._append_event

                def append_when_space_available(*args):
                    nonlocal archive_attempts
                    archive_attempts += 1
                    if archive_attempts <= 3:
                        raise OSError(errno.ENOSPC, 'No space left on device')
                    return append_event(*args)

                async def register_when_unlocked(session, event, line):
                    nonlocal db_attempts
                    db_attempts += 1
                    if db_attempts <= 3:
                        raise OperationalError('INSERT', {}, sqlite3.OperationalError('database is locked'))
                    return await register_event(session, event, line)

                wake = asyncio.Event()
                try:
                    with (
                        patch.object(log_tailer, 'INGEST_STORAGE_RETRY_SECONDS', 0.01),
                        patch.object(log_tailer, '_append_event', append_when_space_available),
                        patch.object(log_tailer, 'register_event', register_when_unlocked),
                    ):
                        worker = asyncio.create_task(log_tailer.log_tailer(wake))
                        try:
                            await asyncio.wait_for(wake.wait(), 5)
                        finally:
                            worker.cancel()
                            await asyncio.gather(worker, return_exceptions=True)
                    self.assertEqual((archive_attempts, db_attempts), (4, 4))
                    self.assertEqual(len(archive.read_text().splitlines()), 1)
                    async with models.get_session_factory()() as session:
                        events = (await session.execute(select(models.AuditEvent))).scalars().all()
                        cases = (await session.execute(select(models.AnalysisCase))).scalars().all()
                        self.assertEqual(len(events[0].raw_event['matches']), 2)
                        self.assertEqual(events[0].event_line, 0)
                        self.assertEqual([(case.rule_id, case.application_host) for case in cases], [('942100', 'shop.example')])
                finally:
                    await models.get_async_engine().dispose()
                    models._async_engine = None
                    models._async_session_factory = None

    async def test_archive_rotation_and_restart_keep_global_event_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            audit = root / 'audit.log'
            archive = root / 'events.jsonl'
            previous = root / 'events.jsonl.1'
            first = audit_object('first')
            first['transaction']['request']['body'] = {'description': 'x' * 3000}
            audit.write_text(json.dumps(first) + '\n')
            env = {
                'MODSEC_AUDIT_LOG': str(audit),
                'EVENTS_JSONL_PATH': str(archive),
                'EVENTS_JSONL_MAX_BYTES': '2000',
                'AUDIT_CURSOR_PATH': str(root / 'cursor.json'),
                'RUNTIME_CONFIG_PATH': str(root / 'runtime.json'),
                'DATABASE_URL': f'sqlite+aiosqlite:///{root / "test.db"}',
                'INCIDENT_FINGERPRINT_KEY': 'test-key',
            }
            models._async_engine = None
            models._async_session_factory = None
            with patch.dict(os.environ, env):
                await models.init_db()
                async def ingest_until_ready(wait_for_rotation=False):
                    wake = asyncio.Event()
                    worker = asyncio.create_task(log_tailer.log_tailer(wake))
                    try:
                        await asyncio.wait_for(wake.wait(), 3)
                        if wait_for_rotation:
                            async with asyncio.timeout(3):
                                while not previous.exists():
                                    await asyncio.sleep(0.01)
                    finally:
                        worker.cancel()
                        await asyncio.gather(worker, return_exceptions=True)

                try:
                    await ingest_until_ready(wait_for_rotation=True)
                    self.assertEqual(json.loads(previous.read_text())['event_line'], 0)
                    with audit.open('a') as source:
                        source.write(json.dumps(audit_object('second')) + '\n')
                    await ingest_until_ready()
                    self.assertEqual(json.loads(archive.read_text())['event_line'], 1)
                    async with models.get_session_factory()() as session:
                        records = (await session.execute(
                            select(models.AuditEvent.transaction_id, models.AuditEvent.event_line)
                            .order_by(models.AuditEvent.event_line)
                        )).all()
                        self.assertEqual(records, [('first', 0), ('second', 1)])
                finally:
                    await models.get_async_engine().dispose()
                    models._async_engine = None
                    models._async_session_factory = None

    async def test_a_record_that_always_fails_is_skipped_after_three_tries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            audit = root / 'audit.log'
            bad = audit_object('bad')
            bad['transaction']['anomaly_score'] = 2**63
            audit.write_text(json.dumps(bad) + '\n' + json.dumps(audit_object('good')) + '\n')
            env = {
                'MODSEC_AUDIT_LOG': str(audit),
                'EVENTS_JSONL_PATH': str(root / 'events.jsonl'),
                'AUDIT_CURSOR_PATH': str(root / 'cursor.json'),
                'RUNTIME_CONFIG_PATH': str(root / 'runtime.json'),
                'DATABASE_URL': f'sqlite+aiosqlite:///{root / "test.db"}',
                'INCIDENT_FINGERPRINT_KEY': 'test-key',
            }
            models._async_engine = None
            models._async_session_factory = None
            with patch.dict(os.environ, env):
                await models.init_db()
                calls = []

                async def track_registration(session, event, line):
                    calls.append(event['transaction_id'])
                    return await register_event(session, event, line)

                wake = asyncio.Event()
                try:
                    with patch.object(log_tailer, 'register_event', track_registration):
                        worker = asyncio.create_task(log_tailer.log_tailer(wake))
                        try:
                            await asyncio.wait_for(wake.wait(), 15)
                        finally:
                            worker.cancel()
                            await asyncio.gather(worker, return_exceptions=True)
                    self.assertEqual(calls, ['bad', 'bad', 'bad', 'good'])
                    async with models.get_session_factory()() as session:
                        ids = (await session.execute(select(models.AuditEvent.transaction_id))).scalars().all()
                        self.assertEqual(ids, ['good'])
                finally:
                    await models.get_async_engine().dispose()
                    models._async_engine = None
                    models._async_session_factory = None
