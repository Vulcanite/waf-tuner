"""
Log Tailer — Phase 2

Continuously tails the ModSecurity JSON audit log and appends parsed
events to events.jsonl. Runs as a background asyncio task.
"""
import asyncio
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Optional

from services.audit_cursor import count_lines, load_cursor, save_cursor
from services.incidents import register_event, transaction_exists

logger = logging.getLogger(__name__)

EVENTS_JSONL_PATH = os.environ.get("EVENTS_JSONL_PATH", "/shared/events.jsonl")

# Severity → numeric score for anomaly computation
SEVERITY_SCORES = {
    "CRITICAL": 5,
    "ERROR": 4,
    "WARNING": 3,
    "NOTICE": 2,
}

def _compute_anomaly_score(messages: list[dict]) -> int:
    """Sum severity scores across all matched rules in a transaction."""
    total = 0
    for msg in messages:
        # Try to extract severity from the message details
        details = msg.get("details", {})
        severity = details.get("severity", "").upper()
        total += SEVERITY_SCORES.get(severity, 0)
        # Also try TX:anomaly_score if present
        data = msg.get("message", "")
        m = re.search(r"anomaly_score[=\s]+(\d+)", str(data), re.IGNORECASE)
        if m:
            total = max(total, int(m.group(1)))
    return total if total > 0 else len(messages) * 2


def _parse_modsec_json(raw: str) -> Optional[dict]:
    """
    Parse a single ModSecurity JSON audit log blob and return an
    events.jsonl-compatible dict, or None if parsing fails.
    """
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return None

    txn = obj.get("transaction", {})
    txn_id = txn.get("id") or txn.get("unique_id")
    if not txn_id:
        return None

    timestamp = txn.get("time") or txn.get("timestamp") or datetime.now(timezone.utc).isoformat()
    client_ip = txn.get("client_ip", "") or txn.get("remote_address", "")
    request = txn.get("request", {})
    method = request.get("method", "GET")
    uri = request.get("uri", "/")
    headers = request.get("headers", {})
    body = request.get("body", "")
    response = txn.get("response", {})
    resp_status = response.get("status", 0)

    messages = txn.get("messages", [])

    matches = []
    for msg in messages:
        rule_id = str(msg.get("ruleId") or msg.get("rule_id") or "")
        rule_message = msg.get("message", "")
        # matched data may be nested
        data = msg.get("data", "") or msg.get("matched_data", "")
        details = msg.get("details", {})
        if not rule_id and details:
            rule_id = str(details.get("ruleId") or details.get("id") or "")
        if not rule_message and details:
            rule_message = details.get("message", "")
        if not data and details:
            data = details.get("data", "")

        if rule_id:
            matches.append({
                "rule_id": rule_id,
                "rule_message": rule_message,
                "matched_data": data,
            })

    if not matches:
        return None  # Skip events with no rule matches

    anomaly_score = _compute_anomaly_score(messages)

    return {
        "transaction_id": txn_id,
        "timestamp": timestamp,
        "client_ip": client_ip,
        "method": method,
        "uri": uri,
        "anomaly_score": anomaly_score,
        "raw_request": {"headers": headers, "body": body},
        "response_status": resp_status,
        "matches": matches,
    }


def _decode_complete_objects(pending: bytes) -> tuple[list[dict], bytes]:
    """Decode complete concatenated JSON objects and retain an incomplete tail.

    json.JSONDecoder understands quoted braces and escapes, unlike brace-counting.
    Pending bytes are kept intact when a UTF-8 code point or JSON object is split
    across writes.
    """
    if not pending:
        return [], b""
    try:
        text = pending.decode("utf-8")
    except UnicodeDecodeError as exc:
        if exc.end == len(pending):
            return [], pending
        text = pending.decode("utf-8", errors="replace")

    decoder = json.JSONDecoder()
    objects = []
    remaining = text
    while remaining:
        stripped = remaining.lstrip()
        if not stripped:
            return objects, b""
        try:
            value, end = decoder.raw_decode(stripped)
        except json.JSONDecodeError:
            # Recover from non-JSON noise before the next plausible object, but
            # retain a plausible object because it may simply be incomplete.
            if not stripped.startswith("{"):
                next_object = stripped.find("{")
                if next_object >= 0:
                    remaining = stripped[next_object:]
                    continue
            return objects, stripped.encode("utf-8")
        if isinstance(value, dict):
            objects.append(value)
        remaining = stripped[end:]
    return objects, b""


def _last_archived_transaction(path: str) -> str | None:
    """Read only the final JSONL record for crash reconciliation."""
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            position = handle.tell()
            buffer = b""
            while position > 0:
                size = min(64 * 1024, position)
                position -= size
                handle.seek(position)
                buffer = handle.read(size) + buffer
                lines = [line for line in buffer.splitlines() if line.strip()]
                if len(lines) >= 2 or position == 0:
                    if not lines:
                        return None
                    value = json.loads(lines[-1])
                    return str(value.get("transaction_id") or "") or None
    except (FileNotFoundError, OSError, json.JSONDecodeError, ValueError):
        return None
    return None


async def _update_last_seen(uri: str) -> None:
    """No edge-deploy lifecycle — no-op kept for call-site stability."""
    _ = uri
    return


async def log_tailer():
    """
    Background task: tail ModSecurity audit log and append to events.jsonl.
    Recovers automatically if the audit log is temporarily missing.

    Audit path is re-read each loop so Settings / runtime_config changes apply
    without restarting the backend.
    """
    from services.runtime_config import get_audit_log_path

    events_path = os.environ.get("EVENTS_JSONL_PATH", EVENTS_JSONL_PATH)
    cursor = load_cursor(events_path)
    last_logged_path: str | None = None
    logger.info("Log tailer started (path from runtime config / env)")

    while True:
        try:
            audit_path = get_audit_log_path()
            if audit_path != last_logged_path:
                logger.info("Log tailer watching: %s", audit_path)
                last_logged_path = audit_path

            if not os.path.exists(audit_path):
                await asyncio.sleep(5)
                continue

            stat = os.stat(audit_path)
            identity = (stat.st_dev, stat.st_ino)
            old_identity = (cursor.get("device"), cursor.get("inode"))
            if old_identity != identity:
                if cursor.get("pending"):
                    logger.warning("Audit log rotated with an incomplete JSON fragment; discarding the orphaned fragment")
                logger.info("Audit log identity changed, resetting byte offset")
                cursor.update(device=stat.st_dev, inode=stat.st_ino, offset=0, pending=b"")
            elif stat.st_size < cursor.get("offset", 0):
                logger.info("Audit log truncated, resetting byte offset")
                cursor.update(offset=0, pending=b"")

            if stat.st_size == cursor.get("offset", 0):
                await asyncio.sleep(2)
                continue

            with open(audit_path, "rb") as f:
                f.seek(cursor.get("offset", 0))
                new_content = f.read()
                cursor["offset"] = f.tell()

            if not new_content:
                await asyncio.sleep(2)
                continue

            objects, remainder = _decode_complete_objects(cursor.get("pending", b"") + new_content)
            cursor["pending"] = remainder
            if not objects:
                save_cursor(cursor)
                await asyncio.sleep(2)
                continue

            appended = 0
            archive_line_count = None
            for object_index, obj in enumerate(objects):
                try:
                    event = _parse_modsec_json(json.dumps(obj, ensure_ascii=False))
                    if event is None:
                        continue

                    from db.models import get_session_factory
                    factory = get_session_factory()
                    async with factory() as session:
                        if await transaction_exists(session, event["transaction_id"]):
                            if archive_line_count is None:
                                archive_line_count = count_lines(events_path)
                            cursor["next_event_line"] = archive_line_count
                            continue
                        event_line = int(cursor.get("next_event_line", 0))
                        # If the prior process died after append but before the DB
                        # commit/cursor save, reuse that final archive line.
                        archive_has_event = (
                            _last_archived_transaction(events_path) == event["transaction_id"]
                        )
                        if not archive_has_event:
                            with open(events_path, "a") as ef:
                                ef.write(json.dumps(event, ensure_ascii=False) + "\n")
                                ef.flush()
                                if os.environ.get("EVENTS_FSYNC", "false").lower() in ("1", "true", "yes"):
                                    os.fsync(ef.fileno())
                        registered = await register_event(session, event, event_line)
                        await session.commit()
                        if registered:
                            cursor["next_event_line"] = event_line + 1
                            archive_line_count = event_line + 1
                            appended += 1
                            await _update_last_seen(event["uri"])
                        elif not archive_has_event:
                            # Archive line was written but DB insert raced/conflicted.
                            # Still advance the line counter so event_line stays monotonic.
                            cursor["next_event_line"] = event_line + 1
                            archive_line_count = event_line + 1

                except Exception as e:
                    logger.warning("Error ingesting audit object: %s | transaction=%s", e, obj.get("transaction", {}).get("id"))
                    # Database or archive failures are retryable. Put the failed
                    # object and every subsequent object back in the durable cursor.
                    retry_objects = objects[object_index:]
                    cursor["pending"] = (
                        "\n".join(json.dumps(item, ensure_ascii=False) for item in retry_objects).encode("utf-8")
                        + b"\n"
                        + cursor.get("pending", b"")
                    )
                    break

            if appended:
                logger.debug("Log tailer appended %d events", appended)
            save_cursor(cursor)

        except Exception as e:
            logger.error("Log tailer error: %s", e)

        await asyncio.sleep(2)
