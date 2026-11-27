#!/usr/bin/env python3
"""Label the captured pairs with the CRS plugins as ground truth and write requests.jsonl.

For every request and every request-phase CRS match in the CRS-only WAF's audit
record (aggregate anomaly-score rules and RESPONSE-* rules are skipped):

  benign request  -> expected false_positive; plugin_excluded is true when the
                     same rule no longer matches the same input behind the
                     CRS + plugin WAF, false when it still does.
  attack request  -> matches on the payload's input are true_positive (with
                     plugin_excluded marking a plugin-suppressed detection);
                     matches on other inputs stay unlabeled.

Requests with no labeled match are left out of requests.jsonl, as in
eval/requests.jsonl, but are counted in the summary.

    python3 eval/bench/label.py [--pairs eval/bench/pairs.jsonl] [--output eval/bench/requests.jsonl]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from benchlib import AGGREGATE_IDS, BENCH_DIR, application_context, audit_matches, load_profiles, unwrap_target  # noqa: E402

_URI = {"REQUEST_URI", "REQUEST_URI_RAW", "REQUEST_FILENAME", "REQUEST_BASENAME", "REQUEST_LINE", "QUERY_STRING"}
_BODY = {"REQUEST_BODY", "XML", "ARGS_POST", "FILES", "FILES_NAMES", "FILES_COMBINED_SIZE"}
_VALUE = re.compile(r"\(Value: [`'](?P<value>.*)['`] \)\s*$", re.S)


def is_response_rule(match: dict) -> bool:
    return "/RESPONSE-" in match["file"] or match["rule_id"][:3] in {"950", "951", "952", "953", "954", "955", "956", "959"}


def match_key(match: dict) -> tuple:
    return (match["rule_id"], *unwrap_target(match["collection"], match["parameter"]))


def _flatten_json(value, prefix="json"):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _flatten_json(item, f"{prefix}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _flatten_json(item, f"{prefix}.array_{index}")
    else:
        yield prefix, "" if value is None else str(value)


def request_args(event: dict) -> dict[str, str]:
    request = (event.get("transaction") or {}).get("request") or {}
    args = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(request.get("uri") or "").query, keep_blank_values=True))
    body = request.get("body") or ""
    ctype = next((str(v) for k, v in (request.get("headers") or {}).items() if k.lower() == "content-type"), "")
    if "json" in ctype:
        try:
            args.update(_flatten_json(json.loads(body)))
        except ValueError:
            pass
    elif "x-www-form-urlencoded" in ctype:
        args.update(urllib.parse.parse_qsl(body, keep_blank_values=True))
    return args


def hits_payload(item: dict, match: dict, event: dict) -> bool:
    target = item.get("target") or {}
    want_collection, want_parameter = target.get("collection"), target.get("parameter")
    collection, parameter = unwrap_target(match["collection"], match["parameter"])
    if collection == "TX" and parameter and parameter.isdigit():
        # Capture-group targets (TX:0, TX:1): compare the inspected value with the payload input.
        value = _VALUE.search(match.get("description") or "")
        payload = request_args(event).get(want_parameter or "", "") if want_parameter else \
            ((event.get("transaction") or {}).get("request") or {}).get("body", "")
        return bool(value and payload and value.group("value")[:40] in urllib.parse.unquote_plus(payload))
    if want_collection == "ARGS":
        if collection in {"ARGS", "ARGS_GET", "ARGS_POST"}:
            return parameter == want_parameter
        if collection in {"ARGS_NAMES", "ARGS_GET_NAMES", "ARGS_POST_NAMES"}:
            return False
        if collection in _URI:
            return item["method"] in ("GET", "HEAD")
        return collection == "REQUEST_BODY" and item["method"] not in ("GET", "HEAD")
    if want_collection == "REQUEST_BODY":
        return collection in _BODY or (collection in {"ARGS", "ARGS_POST"} and item["method"] not in ("GET", "HEAD"))
    if want_collection == "FILES":
        return collection in {"FILES", "FILES_NAMES", "FILES_TMPNAMES", "FILES_TMP_CONTENT"} or \
            (collection == "TX" and (parameter or "").upper() == "EXTENSION")
    if want_collection == "REQUEST_HEADERS":
        return collection == "REQUEST_HEADERS" and (parameter or "").lower() == (want_parameter or "").lower()
    if want_collection in _URI:
        return collection in _URI or (collection == "TX" and (parameter or "").upper() == "EXTENSION")
    return False


def label_pair(item: dict, profiles: dict) -> tuple[dict | None, dict]:
    stats = Counter()
    base, plugin = item["base_audit"], item["plugin_audit"]
    if base is None or plugin is None:
        stats["missing_audit"] += 1
        return None, stats
    base_matches = audit_matches(base)
    plugin_keys = {match_key(m) for m in audit_matches(plugin)}
    labels, ignored = [], []
    for index, match in enumerate(base_matches):
        if match["rule_id"] in AGGREGATE_IDS:
            continue
        if is_response_rule(match):
            stats["response_matches_skipped"] += 1
            continue
        excluded = match_key(match) not in plugin_keys
        if item["kind"] == "benign":
            labels.append({"match_index": index, "expected": "false_positive", "plugin_excluded": excluded})
        elif hits_payload(item, match, base):
            labels.append({"match_index": index, "expected": "true_positive", "plugin_excluded": excluded})
        else:
            ignored.append(match["rule_id"])
    base_keys = {match_key(m) for m in base_matches}
    stats["plugin_only_matches"] += sum(key[0] not in AGGREGATE_IDS for key in plugin_keys - base_keys)
    if not labels:
        return None, stats
    request = base["transaction"]["request"]
    host = str(next((v for k, v in (request.get("headers") or {}).items() if k.lower() == "host"), "")).lower()
    path = urllib.parse.urlsplit(request.get("uri") or "/").path or "/"
    context = application_context(profiles[item["app"]], host, request.get("method") or "", path)
    suppressed = [base_matches[label["match_index"]]["rule_id"] for label in labels
                  if label["expected"] == "true_positive" and label["plugin_excluded"]]
    notes = item["notes"]
    if suppressed:
        notes += f"; the CRS plugin suppresses detection rule(s) {', '.join(sorted(set(suppressed)))} on the payload"
    if ignored:
        notes += f"; unlabeled matches on other inputs: {', '.join(ignored)}"
    record = {
        "id": item["id"],
        "app": item["app"],
        "source": "bench-capture",
        "expected_request": "true_positive" if item["kind"] == "attack" else "false_positive",
        "modsec_audit": base,
        "labels": labels,
        "application_context": context,
        "payload_target": item.get("target"),
        "category": item["category"],
        "wrong_stack": False,
        "notes": notes,
    }
    return record, stats


def summarize(items: list[dict], records: list[dict], totals: Counter) -> dict:
    summary: dict = {}
    by_id = {r["id"]: r for r in records}
    for app in ("wordpress", "nextcloud"):
        sent = [i for i in items if i["app"] == app]
        recs = [r for r in records if r["app"] == app]
        labels = [l for r in recs for l in r["labels"]]
        suppressed = defaultdict(list)
        for r in recs:
            for label in r["labels"]:
                if label["expected"] == "true_positive" and label["plugin_excluded"]:
                    suppressed[r["id"]].append(audit_matches(r["modsec_audit"])[label["match_index"]]["rule_id"])
        attacks_sent = [i for i in sent if i["kind"] == "attack"]
        summary[app] = {
            "requests_sent": len(sent),
            "benign_sent": len(sent) - len(attacks_sent),
            "attacks_sent": len(attacks_sent),
            "records": len(recs),
            "benign_records": sum(r["expected_request"] == "false_positive" for r in recs),
            "attack_records": sum(r["expected_request"] == "true_positive" for r in recs),
            "labeled_matches": len(labels),
            "fp_plugin_excluded": sum(l["expected"] == "false_positive" and l["plugin_excluded"] for l in labels),
            "fp_not_covered": sum(l["expected"] == "false_positive" and not l["plugin_excluded"] for l in labels),
            "tp": sum(l["expected"] == "true_positive" for l in labels),
            "tp_plugin_suppressed": sum(l["expected"] == "true_positive" and l["plugin_excluded"] for l in labels),
            "attacks_with_suppressed_tp": len(suppressed),
            "attacks_fully_suppressed": sum(all(l["plugin_excluded"] for l in by_id[rid]["labels"]) for rid in suppressed),
            "attacks_without_payload_match": [i["id"] for i in attacks_sent if i["id"] not in by_id],
            "suppressed": {rid: sorted(set(rules)) for rid, rules in suppressed.items()},
        }
    summary["totals"] = dict(totals)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pairs", default=str(BENCH_DIR / "pairs.jsonl"))
    parser.add_argument("--output", default=str(BENCH_DIR / "requests.jsonl"))
    parser.add_argument("--summary", default=str(BENCH_DIR / "summary.json"))
    args = parser.parse_args()
    profiles = load_profiles()
    items = [json.loads(line) for line in Path(args.pairs).read_text().splitlines() if line.strip()]
    records, totals = [], Counter()
    for item in items:
        record, stats = label_pair(item, profiles)
        totals.update(stats)
        if record:
            records.append(record)
    Path(args.output).write_text("".join(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n" for r in records))
    summary = summarize(items, records, totals)
    Path(args.summary).write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    for app in ("wordpress", "nextcloud"):
        s = summary[app]
        print(f"{app}: sent {s['requests_sent']} ({s['benign_sent']} benign, {s['attacks_sent']} attacks); "
              f"records {s['records']} ({s['benign_records']} benign, {s['attack_records']} attack); "
              f"matches {s['labeled_matches']}: FP plugin-excluded {s['fp_plugin_excluded']}, FP not covered "
              f"{s['fp_not_covered']}, TP {s['tp']} (plugin-suppressed {s['tp_plugin_suppressed']} in "
              f"{s['attacks_with_suppressed_tp']} attacks, {s['attacks_fully_suppressed']} fully)")
    print(f"totals: {dict(totals)}; wrote {len(records)} records to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
