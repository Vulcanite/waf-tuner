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
from collections import deque
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

AUDIT_LOG_PATH = os.environ.get("MODSEC_AUDIT_LOG", "/var/log/modsec/audit.log")
EVENTS_JSONL_PATH = os.environ.get("EVENTS_JSONL_PATH", "/app/data/events.jsonl")

# Severity → numeric score for anomaly computation
SEVERITY_SCORES = {
    "CRITICAL": 5,
    "ERROR": 4,
    "WARNING": 3,
    "NOTICE": 2,
}

# Fixed-size cache to detect duplicate transaction IDs
_seen_transactions: deque = deque(maxlen=2000)


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


def _split_json_blobs(content: str) -> list[str]:
    """
    ModSecurity JSON audit log may have multiple JSON objects concatenated
    (one per transaction). Split them by detecting object boundaries.
    """
    blobs = []
    depth = 0
    start = None

    for i, ch in enumerate(content):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                blobs.append(content[start:i + 1])
                start = None

    return blobs


async def _update_last_seen(uri: str) -> None:
    """
    Update last_seen_at on deployed exceptions whose URI matches this event.
    Imported lazily to avoid circular imports.
    """
    try:
        from datetime import datetime, timezone
        from db.models import get_session_factory, ExceptionDraft
        from sqlalchemy import select, update

        factory = get_session_factory()
        async with factory() as session:
            now = datetime.now(timezone.utc)
            # Update all deployed exceptions matching this URI
            stmt = (
                update(ExceptionDraft)
                .where(
                    ExceptionDraft.status == "deployed",
                    ExceptionDraft.proposed_rule_scope["uri"].astext == uri,
                )
                .values(last_seen_at=now)
            )
            await session.execute(stmt)
            await session.commit()
    except Exception as e:
        logger.debug("last_seen_at update failed: %s", e)


async def log_tailer():
    """
    Background task: tail ModSecurity audit log and append to events.jsonl.
    Recovers automatically if the audit log is temporarily missing.
    """
    audit_path = os.environ.get("MODSEC_AUDIT_LOG", AUDIT_LOG_PATH)
    events_path = os.environ.get("EVENTS_JSONL_PATH", EVENTS_JSONL_PATH)

    file_pos = 0
    logger.info("Log tailer started. Watching: %s", audit_path)

    while True:
        try:
            if not os.path.exists(audit_path):
                await asyncio.sleep(5)
                continue

            # If file shrank (rotated), reset
            size = os.path.getsize(audit_path)
            if size < file_pos:
                logger.info("Audit log rotated, resetting position")
                file_pos = 0

            if size == file_pos:
                await asyncio.sleep(2)
                continue

            with open(audit_path, "r", errors="replace") as f:
                f.seek(file_pos)
                new_content = f.read()
                file_pos = f.tell()

            if not new_content.strip():
                await asyncio.sleep(2)
                continue

            blobs = _split_json_blobs(new_content)
            if not blobs:
                await asyncio.sleep(2)
                continue

            appended = 0
            for blob in blobs:
                try:
                    event = _parse_modsec_json(blob)
                    if event is None:
                        continue

                    txn_id = event["transaction_id"]
                    if txn_id in _seen_transactions:
                        continue
                    _seen_transactions.append(txn_id)

                    with open(events_path, "a") as ef:
                        ef.write(json.dumps(event) + "\n")

                    appended += 1
                    await _update_last_seen(event["uri"])

                except Exception as e:
                    logger.warning("Error parsing blob: %s | blob[:100]=%s", e, blob[:100])

            if appended:
                logger.debug("Log tailer appended %d events", appended)

        except Exception as e:
            logger.error("Log tailer error: %s", e)

        await asyncio.sleep(2)
