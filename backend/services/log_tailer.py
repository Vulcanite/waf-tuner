"""Tail the serial ModSecurity audit log and register cases durably."""
import asyncio
import codecs
import json
import logging
import os
import re
import stat
from pathlib import Path
from typing import BinaryIO
from zoneinfo import ZoneInfoNotFoundError

from sqlalchemy import func, select

from db.models import AuditEvent, get_session_factory
from services.audit_cursor import count_lines, load_cursor, save_cursor
from services.audit_event import normalize_audit_event as _parse_modsec_json
from services.incidents import register_event, transaction_exists

logger = logging.getLogger(__name__)

EVENTS_JSONL_PATH = os.environ.get('EVENTS_JSONL_PATH', '/shared/events.jsonl')
READ_CHUNK_BYTES = 8 * 1024 * 1024
MAX_AUDIT_RECORD_BYTES = 96 * 1024 * 1024
_AUDIT_RECORD_START = re.compile(r'(?m)^[ \t]*\{[ \t]*"transaction"\s*:')


def _decode_complete_objects(pending: bytes) -> tuple[list[dict], bytes]:
    """Recover whole objects and preserve incomplete JSON and UTF-8 at EOF."""
    try:
        text = pending.decode('utf-8')
        utf8_tail = b''
    except UnicodeDecodeError as exc:
        if exc.reason != 'unexpected end of data' or exc.end != len(pending):
            logger.warning('Replacing invalid UTF-8 in the audit log')
        incremental = codecs.getincrementaldecoder('utf-8')(errors='replace')
        text = incremental.decode(pending, final=False)
        utf8_tail, _ = incremental.getstate()

    decoder = json.JSONDecoder()
    objects = []
    index = 0
    length = len(text)
    while index < length:
        while index < length and text[index].isspace():
            index += 1
        if index >= length:
            break
        try:
            value, end = decoder.raw_decode(text, index)
        except (ValueError, RecursionError):
            if text[index] != '{':
                next_object = text.find('{', index)
                if next_object >= 0:
                    index = next_object
                    continue
            # Native serial JSON frames transactions at line boundaries.
            candidate = _AUDIT_RECORD_START.search(text, index + 1)
            if candidate:
                logger.warning('Skipped a malformed audit fragment before the next transaction')
                index = candidate.start()
                continue
            fragment = text[index:].encode('utf-8') + utf8_tail
            if len(fragment) <= MAX_AUDIT_RECORD_BYTES:
                return objects, fragment
            logger.error('Discarding an audit fragment larger than %d bytes', MAX_AUDIT_RECORD_BYTES)
            _, _, trailing_line = fragment.rpartition(b'\n')
            return objects, trailing_line if len(trailing_line) < 64 else b''
        if isinstance(value, dict):
            objects.append(value)
        index = end
    return objects, utf8_tail


def _archive_tail(path: str) -> tuple[str | None, int | None]:
    """Read final mirror record for crash and rotation reconciliation."""
    try:
        with open(path, 'rb') as handle:
            handle.seek(0, os.SEEK_END)
            position = handle.tell()
            pieces = []
            found_end = False
            while position > 0:
                size = min(64 * 1024, position)
                position -= size
                handle.seek(position)
                chunk = handle.read(size)
                if not found_end:
                    chunk = chunk.rstrip(b'\r\n \t')
                    found_end = bool(chunk)
                if found_end:
                    previous_line = chunk.rfind(b'\n')
                    pieces.append(chunk[previous_line + 1:])
                    if previous_line != -1 or position == 0:
                        value = json.loads(b''.join(reversed(pieces)))
                        transaction = str(value.get('transaction_id') or '') or None
                        line = value.get('event_line')
                        return transaction, line if type(line) is int and line >= 0 else None
    except (OSError, AttributeError, ValueError):
        pass
    return None, None


def _mirror_state(path: str, cursor: dict) -> tuple[int, int, str | None, int | None]:
    try:
        size = os.path.getsize(path)
    except FileNotFoundError:
        size = 0
    next_line = cursor.get('next_event_line', 0)
    transaction, last_line = _archive_tail(path if size else path + '.1')
    if last_line is None and size:
        physical_lines = count_lines(path)
        if transaction:
            last_line = physical_lines - 1
        next_line = max(next_line, physical_lines)
    if last_line is not None:
        next_line = max(next_line, last_line + 1)
    return size, next_line, transaction, last_line


def _read_at(handle: BinaryIO, offset: int) -> tuple[bytes, int]:
    handle.seek(offset)
    data = handle.read(READ_CHUNK_BYTES)
    return data, handle.tell()


def _file_identity(info) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _path_identity(path: str) -> tuple[int, int] | None:
    try:
        info = os.stat(path)
        return _file_identity(info) if stat.S_ISREG(info.st_mode) else None
    except FileNotFoundError:
        return None


def _open_log(path: str, target_identity, cursor: dict) -> BinaryIO:
    previous = (cursor.get('device'), cursor.get('inode'))
    if previous[1] and previous != target_identity and cursor.get('audit_path') in (None, path):
        # After downtime, a rename-style rotation may still have the original
        # inode available beside the configured source. Finish it first.
        with os.scandir(Path(path).parent) as files:
            for entry in files:
                try:
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISREG(info.st_mode) and _file_identity(info) == previous:
                        return open(entry.path, 'rb')
                except FileNotFoundError:
                    continue
        logger.warning('Previous audit inode unavailable after rotation; unread records may have been lost')
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0))
    handle = os.fdopen(descriptor, 'rb')
    if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
        handle.close()
        raise OSError('audit source must be a regular file')
    return handle


def _append_event(path: str, event: dict, event_line: int, fsync: bool) -> int:
    payload = json.dumps({**event, 'event_line': event_line}, ensure_ascii=True, separators=(',', ':')).encode('ascii') + b'\n'
    with open(path, 'a+b') as archive:
        start = archive.tell()
        try:
            archive.write(payload)
            archive.flush()
            if fsync:
                os.fsync(archive.fileno())
        except OSError:
            archive.truncate(start)
            raise
    return start + len(payload)


async def log_tailer(queue_changed: asyncio.Event | None = None):
    from services.runtime_config import get_audit_log_path

    events_path = os.environ.get('EVENTS_JSONL_PATH', EVENTS_JSONL_PATH)
    cursor = await asyncio.to_thread(load_cursor, events_path)
    archive_size, next_event_line, last_transaction, last_event_line = await asyncio.to_thread(_mirror_state, events_path, cursor)
    max_mirror_bytes = max(0, int(os.environ.get('EVENTS_JSONL_MAX_BYTES', '0')))
    factory = get_session_factory()
    async with factory() as session:
        last_registered_line = await session.scalar(select(func.max(AuditEvent.event_line)))
        if last_registered_line is not None:
            next_event_line = max(next_event_line, last_registered_line + 1)
    fsync = os.environ.get('EVENTS_FSYNC', 'false').lower() in ('1', 'true', 'yes')
    reader = None
    drain_rotated = True
    last_logged_path = None
    try:
        while True:
            try:
                updated_cursor = cursor.copy()
                backlog = False
                if not cursor.get('retry_pending'):
                    audit_path = get_audit_log_path()
                    if audit_path != last_logged_path:
                        logger.info('Log tailer watching: %s', audit_path)
                        last_logged_path = audit_path
                    target_identity = _path_identity(audit_path)
                    if reader is None:
                        if target_identity is None:
                            await asyncio.sleep(5)
                            continue
                        reader = _open_log(audit_path, target_identity, cursor if drain_rotated else {})
                        drain_rotated = False
                    info = os.fstat(reader.fileno())
                    identity = _file_identity(info)
                    if identity != (cursor.get('device'), cursor.get('inode')) or info.st_size < cursor['offset']:
                        if cursor.get('pending'):
                            logger.warning('Audit source changed with an incomplete JSON fragment')
                        updated_cursor.update(device=identity[0], inode=identity[1], offset=0, pending=b'', audit_path=audit_path)
                    new_content, updated_cursor['offset'] = await asyncio.to_thread(_read_at, reader, updated_cursor['offset'])
                    if not new_content:
                        if target_identity is not None and identity != target_identity:
                            reader.close()
                            reader = None
                            continue
                        await asyncio.sleep(2)
                        continue
                    backlog = len(new_content) == READ_CHUNK_BYTES
                    updated_cursor['pending'] += new_content
                objects, remainder = await asyncio.to_thread(_decode_complete_objects, updated_cursor['pending'])
                updated_cursor.update(pending=remainder, retry_pending=False)

                async with factory() as session:
                    for index, obj in enumerate(objects):
                        try:
                            event = _parse_modsec_json(obj)
                        except ZoneInfoNotFoundError:
                            logger.error('MODSEC_AUDIT_TIMEZONE must name an installed IANA timezone')
                            raise
                        except (TypeError, ValueError, RecursionError) as exc:
                            logger.warning('Skipped an invalid ModSecurity audit record (%s)', type(exc).__name__)
                            continue
                        if event is None:
                            continue
                        transaction_id = event['transaction_id']
                        try:
                            if await transaction_exists(session, transaction_id):
                                continue
                            if last_transaction == transaction_id and last_event_line is not None:
                                event_line = last_event_line
                            else:
                                event_line = next_event_line
                                archive_size = await asyncio.to_thread(_append_event, events_path, event, event_line, fsync)
                                last_transaction = transaction_id
                                last_event_line = event_line
                                next_event_line += 1
                            registered = await register_event(session, event, event_line)
                            await session.commit()
                            if registered and queue_changed is not None:
                                queue_changed.set()
                        except Exception as exc:
                            logger.warning('Audit ingest will retry transaction %s (%s)', transaction_id, type(exc).__name__)
                            retry = b''.join(
                                json.dumps(item, ensure_ascii=True, separators=(',', ':')).encode('ascii') + b'\n'
                                for item in objects[index:]
                            )
                            updated_cursor.update(pending=retry + remainder, retry_pending=True)
                            break

                updated_cursor.update(
                    next_event_line=next_event_line,
                )
                await asyncio.to_thread(save_cursor, updated_cursor)
                cursor = updated_cursor
                if max_mirror_bytes and archive_size >= max_mirror_bytes and not cursor.get('retry_pending'):
                    await asyncio.to_thread(os.replace, events_path, events_path + '.1')
                    archive_size = 0
                if backlog and not cursor.get('retry_pending'):
                    continue
            except Exception as exc:
                logger.error('Audit tailer error (%s)', type(exc).__name__)
            await asyncio.sleep(2)
    finally:
        if reader is not None:
            reader.close()
