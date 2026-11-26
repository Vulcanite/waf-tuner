"""Normalize serial ModSecurity JSON used by ingestion and model evaluation."""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from services.inference_context import is_aggregate_match, match_target


_SEVERITY_SCORES = {'CRITICAL': 5, 'ERROR': 4, 'WARNING': 3, 'NOTICE': 2, '2': 5, '3': 4, '4': 3, '5': 2}
_TOTAL_SCORE = re.compile(r'\b(?:total\s+(?:inbound\s+|outbound\s+)?score|(?:inbound_|outbound_)?anomaly_score)\s*[:=]\s*(\d+)', re.IGNORECASE)


def parse_audit_timestamp(value) -> datetime | None:
    if not isinstance(value, (str, datetime)) or not value:
        return None
    if isinstance(value, datetime):
        result = value
    else:
        try:
            result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            for fmt in ('%a %b %d %H:%M:%S %Y', '%d/%b/%Y:%H:%M:%S %z'):
                try:
                    result = datetime.strptime(value, fmt)
                    break
                except ValueError:
                    continue
            else:
                return None
    if result.tzinfo is None:
        zone_name = os.environ.get('MODSEC_AUDIT_TIMEZONE', 'UTC')
        local_zone = timezone.utc if zone_name == 'UTC' else ZoneInfo(zone_name)
        result = result.replace(tzinfo=local_zone)
    return result.astimezone(timezone.utc)


def _scores(txn: dict, matches: list[dict]) -> tuple[int, str]:
    explicit = txn.get('anomaly_score')
    if isinstance(explicit, int) and not isinstance(explicit, bool) and explicit >= 0:
        return explicit, 'modsecurity'
    reported = []
    estimated = []
    for match in matches:
        if is_aggregate_match(match):
            total = _TOTAL_SCORE.search(match['rule_message'])
            if total:
                reported.append(int(total.group(1)))
        else:
            estimated.append(_SEVERITY_SCORES.get(str(match.get('severity') or '').upper(), 2))
    if reported:
        return max(reported), 'modsecurity'
    return sum(estimated), 'estimated_from_severity'


def normalize_audit_event(raw: str | dict) -> dict | None:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return None
    txn = raw.get('transaction') if isinstance(raw, dict) else None
    if not isinstance(txn, dict):
        return None
    txn_id = txn.get('id') or txn.get('unique_id')
    request = txn.get('request') or {}
    if not txn_id or not isinstance(request, dict):
        return None
    headers = request.get('headers') or {}
    if not isinstance(headers, dict):
        return None
    response = txn.get('response') or {}
    if not isinstance(response, dict):
        response = {}
    timestamp = parse_audit_timestamp(txn.get('time') or txn.get('time_stamp') or txn.get('timestamp'))
    matches = []
    for msg in txn.get('messages') or []:
        if not isinstance(msg, dict):
            continue
        details = msg.get('details') or {}
        if not isinstance(details, dict):
            details = {}
        rule_id = str(msg.get('ruleId') or msg.get('rule_id') or details.get('ruleId') or details.get('id') or '')
        if not rule_id:
            continue
        match = {
            'rule_id': rule_id,
            'rule_message': str(msg.get('message') or details.get('message') or ''),
            'matched_data': msg.get('data') or msg.get('matched_data') or details.get('data') or '',
            'match_description': details.get('match') or '',
            'severity': details.get('severity'),
        }
        match['collection'], match['parameter'] = match_target(match)
        matches.append(match)
    if not matches:
        return None
    score, score_source = _scores(txn, matches)
    return {
        'transaction_id': str(txn_id),
        'timestamp': (timestamp or datetime.now(timezone.utc)).isoformat(),
        'timestamp_source': 'audit_log' if timestamp else 'ingestion',
        'client_ip': txn.get('client_ip') or txn.get('remote_address') or '',
        # No default: a guessed method would let an exclusion pass the captured-scope check.
        'method': str(request.get('method') or ''),
        'uri': str(request.get('uri') or '/'),
        'anomaly_score': score,
        'anomaly_score_source': score_source,
        'raw_request': {'headers': headers, 'body': request.get('body', '')},
        'response_status': response.get('status') or response.get('http_code') or 0,
        'matches': matches,
    }
