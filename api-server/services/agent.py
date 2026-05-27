"""
LLM Agent — Phase 4

Reads unprocessed events from events.jsonl using the byte offset tracker,
classifies each rule match with Claude, and inserts drafts into Postgres.
"""
import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from openai import OpenAI

from services.crs_index import get_rule
from services.offset_tracker import get_last_offset, set_last_offset, count_lines_to_offset

logger = logging.getLogger(__name__)

EVENTS_JSONL_PATH = os.environ.get("EVENTS_JSONL_PATH", "/app/data/events.jsonl")

SYSTEM_PROMPT = """You are a WAF security analyst specializing in ModSecurity and OWASP CRS rule tuning.

You will receive a ModSecurity security event enriched with the full CRS rule definition
that triggered it. Use the rule's operator, targets, paranoia level, and tags — not just
the matched payload — to determine whether this is a false positive or a true positive.

Key reasoning guidance:
- The operator tells you exactly what the rule is detecting: @detectSQLi uses libinjection,
  @rx uses a regex pattern, @pmFromFile matches against a phrase list. Reason from the
  operator logic, not just the surface appearance of the payload.
- Paranoia level is a strong prior. PL3 and PL4 rules are intentionally aggressive and
  produce far more false positives than PL1/PL2. A PL4 rule firing on a blog post field
  is almost certainly a false positive.
- The targets list tells you which part of the request was inspected. A rule targeting
  ARGS firing on a parameter named 'blog_content', 'search_query', or 'comment_body'
  is a strong signal toward false positive. A rule targeting REQUEST_COOKIES or
  REQUEST_HEADERS firing on unusual content is stronger toward true positive.
- Chained rules require ALL conditions in the chain to match — a chain match is a
  stronger signal toward true positive than a single-rule match.

Respond ONLY with a JSON object in this exact format — no preamble, no markdown fences:

{
  "classification": "false_positive" | "true_positive" | "uncertain",
  "confidence": <float 0.0 to 1.0>,
  "verdict": "We are {confidence_pct}% sure this is a [false positive / true positive / uncertain case] because the parameter is '{parameter}' and {specific reason referencing the matched_data, the rule operator, and the paranoia level}.",
  "proposed_rule_scope": {
    "parameter": "<the specific ARGS parameter name that was matched, or null if it was REQUEST_BODY/REQUEST_FILENAME/etc>"
  }
}

Notes on proposed_rule_scope:
- Only populate "parameter" if classification is false_positive AND confidence >= 0.75.
- "parameter" should be the exact parameter name from matched_data (e.g. "q", "password", "body").
- Set "parameter" to null for true_positive or uncertain classifications.
- Do NOT include "uri" or "rule_id" — those are extracted from the event automatically."""


def _extract_scope(event: dict, match: dict) -> dict:
    """Extract (uri, parameter, rule_id) scope from actual event data."""
    param = None
    md = match.get("matched_data", "")
    if "within ARGS:" in md:
        raw = md.split("within ARGS:")[-1].strip().split()[0]
        param = raw.rstrip(":")  # strip trailing colon from "param: value" format
    elif "within REQUEST_BODY" in md:
        param = "REQUEST_BODY"
    elif "within ARGS_NAMES" in md:
        param = "ARGS_NAMES"
    elif "within REQUEST_FILENAME" in md:
        param = "REQUEST_FILENAME"
    elif "within REQUEST_HEADERS" in md:
        param = "REQUEST_HEADERS"
    uri = event.get("uri", "/").split("?")[0]
    return {"uri": uri, "parameter": param, "rule_id": match.get("rule_id", "")}


def _build_proposed_rule(scope: dict, phase: int = 2) -> str:
    """Generate a canonical ModSecurity exception rule from verified scope data."""
    import hashlib
    uri = scope["uri"]
    rule_id = scope["rule_id"]
    param = scope.get("parameter")

    if param and param not in ("REQUEST_BODY", "ARGS_NAMES"):
        target = f"ARGS:{param}"
    elif param == "REQUEST_BODY":
        target = "REQUEST_BODY"
    else:
        target = "ARGS"

    # Deterministic exception ID in the 1000000–9999999 range
    exc_id = 1000000 + (
        int(hashlib.md5(f"{uri}:{rule_id}:{param}".encode()).hexdigest(), 16) % 9000000
    )
    return (
        f'SecRule REQUEST_URI "@beginsWith {uri}" '
        f'"id:{exc_id},phase:{phase},pass,nolog,'
        f'ctl:ruleRemoveTargetById={rule_id};{target}"'
    )


def read_jsonl_from_offset(
    path: str, start_offset: int, limit: int
) -> tuple[list[tuple[dict, int]], int]:
    """Read up to `limit` JSONL lines starting at byte `start_offset`."""
    results = []
    current_offset = start_offset

    try:
        with open(path, "r") as f:
            f.seek(start_offset)
            for _ in range(limit):
                line = f.readline()
                if not line:
                    break
                current_offset = f.tell()
                try:
                    results.append((json.loads(line.strip()), current_offset))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        pass

    return results, current_offset


async def _draft_exists_for_scope(session, scope: dict) -> bool:
    """Check if a pending/approved/deployed draft already covers this scope."""
    from sqlalchemy import select, text
    from db.models import ExceptionDraft

    stmt = select(ExceptionDraft.id).where(
        ExceptionDraft.status.in_(["pending", "approved", "deployed"]),
        ExceptionDraft.proposed_rule_scope["uri"].astext == scope["uri"],
        ExceptionDraft.proposed_rule_scope["rule_id"].astext == scope["rule_id"],
    )
    if scope.get("parameter"):
        stmt = stmt.where(
            ExceptionDraft.proposed_rule_scope["parameter"].astext == scope["parameter"]
        )

    result = await session.execute(stmt)
    return result.first() is not None


async def analyze_match(event: dict, match: dict, event_line: int) -> Optional[dict]:
    """
    Call the Anthropic API to classify a single rule match.
    Returns a dict suitable for inserting into exception_drafts, or None on hard failure.
    """
    crs_rule = get_rule(match.get("rule_id", ""))

    context = {
        "uri": event.get("uri", ""),
        "method": event.get("method", ""),
        "rule_id": match.get("rule_id", ""),
        "rule_message": match.get("rule_message", ""),
        "matched_data": match.get("matched_data", ""),
        "anomaly_score": event.get("anomaly_score", 0),
        "raw_request": event.get("raw_request", {}),
        "other_matches_in_transaction": [
            m for m in event.get("matches", [])
            if m.get("rule_id") != match.get("rule_id")
        ],
        "crs_rule": {
            "raw": crs_rule.raw,
            "targets": crs_rule.targets,
            "operator": crs_rule.operator,
            "tags": crs_rule.tags,
            "paranoia_level": crs_rule.paranoia_level,
            "severity": crs_rule.severity,
            "chain": crs_rule.chain,
        } if crs_rule else None,
    }

    user_prompt = (
        "Analyze this ModSecurity event. Pay close attention to the crs_rule field — "
        "the operator and paranoia_level are the most important signals for determining "
        "false positive vs true positive. Do not rely solely on the appearance of the "
        "matched_data.\n\n"
        + json.dumps(context, indent=2)
    )

    api_key = os.environ.get("API_KEY", "")
    api_url = os.environ.get("API_URL", "https://openrouter.ai/api/v1")
    api_model = os.environ.get("API_MODEL", "anthropic/claude-sonnet-4-5")

    if not api_key or api_key.startswith("sk-or-..."):
        logger.warning("No valid API_KEY — skipping LLM call for rule %s", match.get("rule_id"))
        return None

    try:
        client = OpenAI(api_key=api_key, base_url=api_url)
        response = client.chat.completions.create(
            model=api_model,
            max_tokens=1000,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        )
        raw = response.choices[0].message.content or ""
    except Exception as e:
        logger.error("LLM API error: %s", e)
        return {
            "transaction_id": event.get("transaction_id", ""),
            "event_line": event_line,
            "classification": "uncertain",
            "confidence": 0.0,
            "verdict": f"Agent API error: {type(e).__name__}",
            "crs_rule_raw": crs_rule.raw if crs_rule else None,
            "proposed_rule": None,
            "proposed_rule_scope": _extract_scope(event, match),
            "status": "pending",
        }

    # Parse LLM response
    try:
        # Strip markdown fences and leaked chat-template tokens (e.g. </assistant>)
        clean = raw.strip()
        if clean.startswith("```"):
            clean = "\n".join(clean.split("\n")[1:])
        if clean.endswith("```"):
            clean = "\n".join(clean.split("\n")[:-1])
        clean = clean.replace("</assistant>", "").strip()
        # Extract the first JSON object if extra text surrounds it
        brace_start = clean.find("{")
        brace_end = clean.rfind("}")
        if brace_start != -1 and brace_end != -1:
            clean = clean[brace_start:brace_end + 1]
        parsed = json.loads(clean)
    except json.JSONDecodeError:
        logger.warning("Could not parse agent response: %s", raw[:200])
        parsed = {
            "classification": "uncertain",
            "confidence": 0.0,
            "verdict": "Agent response could not be parsed.",
            "proposed_rule": None,
            "proposed_rule_scope": _extract_scope(event, match),
        }

    # Downgrade low-confidence false positives
    classification = parsed.get("classification", "uncertain")
    confidence = float(parsed.get("confidence", 0.0))
    if classification == "false_positive" and confidence < 0.75:
        classification = "uncertain"
        parsed["proposed_rule"] = None

    # Prepend note if CRS rule was missing
    verdict = parsed.get("verdict", "")
    if crs_rule is None:
        verdict = "CRS rule definition not found in index — classification based on payload and rule message only. " + verdict

    # Derive ground-truth scope from actual event data — never fully trust LLM for these
    actual_scope = _extract_scope(event, match)
    llm_scope = parsed.get("proposed_rule_scope") or {}

    # Detect hallucinated URI or rule_id
    llm_uri = (llm_scope.get("uri") or "").split("?")[0]
    llm_rule_id = str(llm_scope.get("rule_id") or "")
    scope_hallucinated = (
        llm_uri != actual_scope["uri"] or llm_rule_id != actual_scope["rule_id"]
    )

    # Build final scope: always use actual uri + rule_id.
    # For parameter: matched_data is ground truth — only fall back to LLM's suggestion
    # if extraction from matched_data failed (e.g. non-ARGS target like REQUEST_BODY).
    scope = {
        "uri": actual_scope["uri"],
        "rule_id": actual_scope["rule_id"],
        "parameter": actual_scope.get("parameter") or llm_scope.get("parameter"),
    }

    # Always generate proposed_rule from verified scope — never trust the LLM's string.
    # The LLM reliably hallucinates URIs/rule_ids in the rule string even when the scope
    # metadata is correct. We own all the variables (uri, rule_id, phase, parameter)
    # so there is no value in using the LLM's syntax.
    if classification == "false_positive":
        phase = crs_rule.phase if crs_rule else 2
        proposed_rule = _build_proposed_rule(scope, phase)
    else:
        proposed_rule = None

    if scope_hallucinated:
        logger.warning(
            "LLM hallucinated scope for rule %s on %s (got uri=%r rule_id=%r) — scope and rule corrected",
            actual_scope["rule_id"], actual_scope["uri"], llm_uri, llm_rule_id,
        )

    return {
        "transaction_id": event.get("transaction_id", ""),
        "event_line": event_line,
        "classification": classification,
        "confidence": confidence,
        "verdict": verdict,
        "crs_rule_raw": crs_rule.raw if crs_rule else None,
        "proposed_rule": proposed_rule,
        "proposed_rule_scope": scope,
        "status": "pending",
    }


async def agent_worker():
    """
    Background task: poll events.jsonl every 30 seconds for unprocessed events,
    classify each rule match, and write drafts to Postgres.
    """
    from db.models import get_session_factory, ExceptionDraft

    logger.info("Agent worker started")
    events_path = os.environ.get("EVENTS_JSONL_PATH", EVENTS_JSONL_PATH)

    while True:
        try:
            last_offset = get_last_offset()
            new_events, next_offset = read_jsonl_from_offset(
                events_path, start_offset=last_offset, limit=5
            )

            if not new_events:
                await asyncio.sleep(30)
                continue

            factory = get_session_factory()
            async with factory() as session:
                for event, event_offset in new_events:
                    event_line = count_lines_to_offset(events_path, event_offset)

                    for match in event.get("matches", []):
                        scope = _extract_scope(event, match)

                        if await _draft_exists_for_scope(session, scope):
                            logger.debug(
                                "Skipping duplicate scope: %s rule %s",
                                scope["uri"], scope["rule_id"]
                            )
                            continue

                        draft_data = await analyze_match(event, match, event_line)
                        if draft_data is None:
                            continue

                        draft = ExceptionDraft(**draft_data)
                        session.add(draft)
                        # Throttle to avoid hitting OpenAI rate limits
                        await asyncio.sleep(1)

                    await session.commit()
                    set_last_offset(event_offset)

        except Exception as e:
            logger.error("Agent worker error: %s", e, exc_info=True)

        await asyncio.sleep(30)
