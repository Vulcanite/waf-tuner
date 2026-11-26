"""Project the evidence for one WAF match into a bounded provider message."""
from __future__ import annotations

import json
import math
import os
import re
from collections.abc import Mapping
from urllib.parse import SplitResult, parse_qsl, unquote, unquote_plus, urlsplit

from services.json_extract import extract_json
from services.redaction import REDACTED, SENSITIVE_HEADERS, is_sensitive_name, sanitize_evidence_text


_AGGREGATE_IDS = frozenset({
    '949060', '949061', '949062', '949063', '949100', '949110',
    '959060', '959061', '959062', '959063', '959100',
    '980100', '980110', '980115', '980120', '980130', '980140', '980145', '980150',
})
_METHOD_COLLECTIONS = {'REQUEST_METHOD'}
_URI_COLLECTIONS = {'REQUEST_URI', 'REQUEST_URI_RAW', 'REQUEST_FILENAME', 'REQUEST_BASENAME'}
_HEADER_ALLOWLIST = frozenset({'host', 'content-type', 'user-agent', 'accept', 'accept-language', 'content-length'})
_ARGUMENT_COLLECTIONS = {'ARGS', 'ARGS_GET', 'ARGS_POST', 'ARGS_NAMES', 'ARGS_GET_NAMES', 'ARGS_POST_NAMES'}
_MATCH_TARGET_SUFFIX = re.compile(r'''\b(?:within|variable)\s+[`'\"]?(?P<collection>[A-Z_]+)(?::(?P<parameter>[^\s,;`'\"\)]+))?''', re.IGNORECASE)
_NATIVE_VALUE = re.compile(r'''(?s)\(Value:\s+[`'"](?P<value>.*)['"]\s*\)\s*$''')
_NATIVE_TARGET = re.compile(r'''\bagainst\s+variable\s+[`'\"](?P<collection>[A-Z_]+)(?::(?P<parameter>[^`'\"\r\n]+))?[`'\"]\s+\(Value:''', re.IGNORECASE)


def is_aggregate_match(match: dict) -> bool:
    return str(match.get('rule_id') or '') in _AGGREGATE_IDS


def extract_match_target(matched_data: str) -> tuple[str | None, str | None]:
    """Read the connector's structured target or the traditional log suffix."""
    if not isinstance(matched_data, str):
        return None, None
    native = _NATIVE_TARGET.search(matched_data)
    if native:
        parameter = native.group('parameter')
        return native.group('collection').upper(), parameter[:512] if parameter else None
    if matched_data.startswith('Matched Data:'):
        marker = matched_data.find(' found within ')
        if marker < 0:
            return None, None
        matched_data = matched_data[marker + len(' found '):]
    match = _MATCH_TARGET_SUFFIX.search(matched_data)
    if not match:
        return None, None
    parameter = match.group('parameter')
    return match.group('collection').upper(), parameter.rstrip(':,.')[:512] if parameter else None


def match_target(match: dict) -> tuple[str | None, str | None]:
    if match.get('collection'):
        return str(match['collection']).upper(), match.get('parameter')
    for key in ('match_description', 'matched_data'):
        collection, parameter = extract_match_target(match.get(key) or '')
        if collection:
            return collection, parameter
    return None, None


def split_request_uri(uri: str) -> SplitResult:
    # Origin-form request targets can legitimately start with two slashes.
    try:
        return urlsplit('http://waf.invalid' + uri if uri.startswith('/') else uri, allow_fragments=False)
    except ValueError:
        path, _, query = uri.partition('?')
        return SplitResult('', '', path, query, '')


def application_host(event: dict) -> str:
    """Use the normalized audited authority consistently across profiles and cases."""
    headers = (event.get('raw_request') or {}).get('headers') or {}
    host = next((str(value).strip() for name, value in headers.items() if str(name).lower() == 'host'), '')
    value = host or str(event.get('uri') or '')
    try:
        parsed = urlsplit('//' + value if host else value)
        _ = parsed.port  # Reject a malformed authority before discarding its port.
        if host and (parsed.path or parsed.query or parsed.fragment):
            return ''
        authority = (parsed.hostname or '').rstrip('.').lower() if host or parsed.scheme in ('http', 'https') else ''
    except ValueError:
        return ''
    if parsed.username is not None or not re.fullmatch(r'[a-z0-9.:-]+', authority):
        return ''
    return authority


class _ObjectPairs(list):
    """Ordered JSON object fields, including repeated names."""


def _body_items(value, prefix=''):
    if isinstance(value, Mapping):
        value = _ObjectPairs(value.items())
    if isinstance(value, _ObjectPairs):
        for name, child in value:
            path = f'{prefix}.{name}' if prefix else str(name)
            yield from _body_items(child, path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            path = f'{prefix}.{index}' if prefix else str(index)
            yield from _body_items(child, path)
    elif prefix:
        yield prefix, value


def prepare_request_evidence(event: dict) -> dict:
    """Parse shared request and sibling evidence once for all matches in a transaction."""
    uri = split_request_uri(str(event.get('uri') or '/'))
    request = event.get('raw_request') or {}
    headers = {str(name).lower(): value for name, value in (request.get('headers') or {}).items()}
    body = request.get('body')
    media_type = str(headers.get('content-type') or '').partition(';')[0].strip().lower()
    body_status = 'present' if body else 'empty'
    if isinstance(body, str) and body:
        if media_type == 'application/x-www-form-urlencoded':
            body_items = parse_qsl(body, keep_blank_values=True)
        elif media_type == 'application/json' or media_type.endswith('+json') or not media_type:
            try:
                body_items = list(_body_items(json.loads(body, object_pairs_hook=_ObjectPairs)))
                if not body_items:
                    body_status = 'unstructured body omitted'
            except (ValueError, RecursionError):
                body_items = []
                body_status = 'unstructured body omitted'
        else:
            body_items = []
            body_status = 'unsupported body media type omitted'
    elif isinstance(body, (dict, list)):
        body_items = list(_body_items(body))
    else:
        body_items = []
    return {
        'host': application_host(event),
        'method': str(event.get('method') or '').upper(),
        'path': uri.path or '/',
        'query_items': parse_qsl(uri.query, keep_blank_values=True),
        # REQUEST_URI_RAW inspects the query as sent, so keep its original encoding too.
        'raw_query_items': [part.partition('=')[::2] for part in uri.query.split('&') if part],
        'body_items': body_items,
        'body_status': body_status,
        'headers': headers,
        'media_type': media_type,
        'targets': [match_target(item) for item in event.get('matches') or []],
    }


def _query_or_body_values(items, parameter, collection):
    values = [value for name, value in items if name == parameter]
    if collection.endswith('_NAMES'):
        return [parameter] if values else []
    return values


def match_evidence(request: dict, collection: str | None, parameter: str | None, match: dict | None = None) -> dict:
    """Extract ordered values from the exact collection identified by the log."""
    values = {}
    if collection in _ARGUMENT_COLLECTIONS and parameter:
        values['query'] = [] if collection.startswith('ARGS_POST') else _query_or_body_values(request['query_items'], parameter, collection)
        values['body'] = [] if collection.startswith('ARGS_GET') else _query_or_body_values(request['body_items'], parameter, collection)
    elif collection == 'REQUEST_HEADERS' and parameter:
        value = request['headers'].get(parameter.lower())
        values['header'] = [value] if value is not None else []
    if values:
        # The connector's native Value field is evidence from a known target,
        # even when the captured request parts lack the original field value.
        description = match.get('match_description') if match else None
        native_value = _NATIVE_VALUE.search(description) if isinstance(description, str) else None
        if native_value and extract_match_target(description) == (collection, parameter):
            logged_value = native_value.group('value')
            if not any(logged_value in items for items in values.values()):
                values['audit_log_value'] = [logged_value]
        return values
    if collection == 'REQUEST_HEADERS_NAMES' and parameter:
        return {'header_name': [parameter] if parameter.lower() in request['headers'] else []}
    if collection in _METHOD_COLLECTIONS:
        return {'method': [request['method']]}
    if collection in _URI_COLLECTIONS:
        path = request['path']
        if collection == 'REQUEST_BASENAME':
            path = path.rsplit('/', 1)[-1]
        items = request['raw_query_items'] if collection == 'REQUEST_URI_RAW' else request['query_items']
        if collection in ('REQUEST_URI', 'REQUEST_URI_RAW') and items:
            # REQUEST_URI includes the query string; without it two different payloads look identical.
            # Raw pairs here keep the local fingerprint exact; the provider copy is redacted later.
            return {'path': [path], 'uri_query': [[name, value] for name, value in items]}
        return {'path': [path]}
    return {}


def _text(value, limit: int) -> str:
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=True, separators=(',', ':'), default=str)
    return sanitize_evidence_text(str(value))[:limit]


def _safe_path(path: str, limit: int) -> str:
    parts = path.split('/')
    for index, segment in enumerate(parts):
        if index and is_sensitive_name(unquote(parts[index - 1])):
            parts[index] = REDACTED
        elif unquote(segment) != segment and sanitize_evidence_text(unquote(segment)) != unquote(segment):
            parts[index] = REDACTED
    return _text('/'.join(parts), limit)


def _safe_target(collection, parameter) -> bool:
    if parameter and is_sensitive_name(parameter):
        return False
    if collection == 'REQUEST_HEADERS' and parameter:
        name = parameter.lower()
        return name in _HEADER_ALLOWLIST and name not in SENSITIVE_HEADERS
    return collection not in {'REQUEST_COOKIES', 'REQUEST_COOKIES_NAMES'}


def _safe_profile(value, depth=0):
    if depth >= 4:
        return None
    if isinstance(value, dict):
        return {
            _text(key, 80): _safe_profile(child, depth + 1)
            for key, child in list(value.items())[:16]
            if not is_sensitive_name(str(key))
        }
    if isinstance(value, (list, tuple)):
        return [_safe_profile(child, depth + 1) for child in value[:12]]
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _text(value, 512)


def _profile_projection(profile: dict, parameter: str | None) -> dict:
    application = profile.get('application') or {}
    route = profile.get('route')
    result = {
        'application': {key: application[key] for key in ('purpose', 'name', 'languages', 'frameworks', 'data_stores', 'notes') if key in application},
    }
    if isinstance(route, dict):
        route_fields = {key: route[key] for key in ('path', 'methods', 'notes', 'purpose') if key in route}
        parameters = route.get('parameters') or {}
        if isinstance(parameters, dict) and parameter in parameters and not is_sensitive_name(parameter):
            route_fields['parameter_semantics'] = parameters[parameter]
        result['route'] = route_fields
    for key in ('profile_name', 'profile_version'):
        if key in profile:
            result[key] = profile[key]
    provenance = profile.get('fact_provenance') or {}
    if isinstance(provenance, dict):
        result['fact_provenance'] = {key: provenance[key] for key in ('type', 'verified', 'seeded') if key in provenance}
    return _safe_profile(result)


def _rule_projection(rule, field_limit: int) -> dict | None:
    if rule is None:
        return None
    values = rule.get if isinstance(rule, dict) else lambda key: getattr(rule, key, None)
    context = {}
    for key in ('raw', 'operator', 'message', 'severity', 'source_file', 'ruleset_digest'):
        value = values(key)
        if value:
            context[key] = _text(value, field_limit)
    for key in ('targets', 'tags'):
        value = values(key)
        if value:
            context[key] = [_text(item, 128) for item in value[:16]]
    for key in ('paranoia_level', 'phase', 'chain'):
        value = values(key)
        if isinstance(value, (int, bool)):
            context[key] = value
    # The indexed raw directive includes chain children. For legacy fixtures
    # without raw syntax, preserve the separately stored chain definitions.
    if values('chain_rules') and not values('raw'):
        context['chain_rules'] = [_text(item, field_limit) for item in values('chain_rules')[:4]]
    return context or None


def _bounded_values(values: list, limit: int) -> list:
    return [
        _text(value, limit) if isinstance(value, (str, dict, list)) or isinstance(value, float) and not math.isfinite(value) else value
        for value in values[:32]
    ]


def _encode(context: dict) -> str:
    return json.dumps(context, ensure_ascii=True, allow_nan=False, separators=(',', ':'))


def max_context_bytes() -> int:
    limit = int(os.environ.get('AI_MAX_CONTEXT_BYTES') or os.environ.get('AI_MAX_REQUEST_CHARS') or '16384')
    if limit < 2:
        raise ValueError('AI_MAX_CONTEXT_BYTES must allow at least an empty JSON object (2 bytes)')
    return limit


def _fit_context(context: dict, budget: int) -> dict:
    if len(_encode(context)) <= budget:
        return context
    incident = context['incident']
    rule = context.get('crs_rule') or {}
    request = context['request']
    context['redaction']['truncated'] = True
    for container, key in (
        (rule, 'raw'), (rule, 'tags'), (incident, 'other_matches'),
        (context, 'application_context'), (rule, 'message'), (incident, 'rule_message'),
        (rule, 'source_file'), (incident, 'matched_data'), (request, 'content_type'),
    ):
        container.pop(key, None)
        if len(_encode(context)) <= budget:
            return context
    # Retain the identity at very small budgets and let the model abstain.
    minimal = {
        'incident': {key: incident.get(key) for key in ('method', 'rule_id', 'collection', 'parameter')},
        'redaction': {'truncated': True},
    }
    if len(_encode(minimal)) <= budget:
        return minimal
    return {}


def build_inference_context(event, match, *, match_index=0, crs_rule=None, application_context=None, collection=None, parameter=None) -> dict:
    request = prepare_request_evidence(event)
    observed_collection, observed_parameter = match_target(match)
    collection = collection or observed_collection
    parameter = parameter or observed_parameter
    field_limit = max(64, min(8192, int(os.environ.get('AI_MAX_FIELD_CHARS', '8192'))))
    safe_target = _safe_target(collection, parameter)
    evidence = match_evidence(request, collection, parameter, match) if safe_target else {}
    if 'uri_query' in evidence:
        evidence['query'] = [
            # Check the decoded name, so an encoded name such as pass%77ord is still redacted.
            f'{name}={REDACTED if is_sensitive_name(unquote_plus(name)) else value}'
            for name, value in evidence.pop('uri_query')
        ]
    values = {key: _bounded_values(items, field_limit) for key, items in evidence.items() if items}
    values_truncated = any(
        len(items) > 32 or any(isinstance(item, str) and len(item) > field_limit for item in items)
        for items in evidence.values()
    )
    if 'path' in values:
        values['path'] = [_safe_path(path, field_limit) for path in values['path']]
    target_redacted = any(REDACTED in str(item) for items in values.values() for item in items)
    match_data = match.get('matched_data') or ''
    # ModSecurity logdata may include multiple fields. Supply a logged value
    # only when it corroborates a selected, sanitized request field.
    excerpt = match_data if isinstance(match_data, str) else ''
    if excerpt.startswith('Matched Data:') and ' found within ' in excerpt:
        excerpt = excerpt[len('Matched Data:'):].split(' found within ', 1)[0].strip()
    safe_excerpt = _text(excerpt, field_limit)
    evidence_strings = [value for items in values.values() for value in items if isinstance(value, str)]
    corroborated = bool(safe_excerpt and any(safe_excerpt.casefold() in value.casefold() for value in evidence_strings))
    other_keys = {
        (str(item.get('rule_id') or ''), *(item or '' for item in request['targets'][index]))
        for index, item in enumerate(event.get('matches') or [])
        if index != match_index
    }
    other_matches = [{
        'rule_id': _text(rule_id, 24),
        'collection': collection_name or None,
        'parameter': REDACTED if is_sensitive_name(parameter_name) else _text(parameter_name, 128) if parameter_name else None,
    } for rule_id, collection_name, parameter_name in sorted(other_keys)[:16]]
    rule_operator = crs_rule.get('operator') if isinstance(crs_rule, dict) else getattr(crs_rule, 'operator', None)
    rule_raw = crs_rule.get('raw') if isinstance(crs_rule, dict) else getattr(crs_rule, 'raw', None)
    rule_truncated = any(len(value) > field_limit for value in (rule_operator, rule_raw) if isinstance(value, str))
    context = {
        'incident': {
            'method': _text(request['method'], 24),
            'uri': {'path': _safe_path(request['path'], field_limit), 'query': values.pop('query', [])},
            'rule_id': _text(match.get('rule_id') or '', 24),
            'rule_message': _text((crs_rule.get('message') if isinstance(crs_rule, dict) else getattr(crs_rule, 'message', None)) or '', 512),
            'matched_data': safe_excerpt if corroborated else None,
            'collection': collection,
            'parameter': _text(parameter, 512) if parameter else None,
            'match_index': match_index,
            'anomaly_score': event.get('anomaly_score'),
            'anomaly_score_source': event.get('anomaly_score_source'),
            'other_matches': other_matches,
        },
        'request': {'content_type': _text(request['media_type'], 128), 'body_status': request['body_status'], 'matched_values': values},
        'crs_rule': _rule_projection(crs_rule, field_limit),
        'application_context': _profile_projection(application_context, parameter) if application_context else {},
        'redaction': {
            'target_hidden': not safe_target or target_redacted,
            'logged_excerpt_omitted': bool(match_data and not corroborated),
            'truncated': values_truncated or rule_truncated or len(request['path']) > field_limit or len(other_keys) > 16,
        },
    }
    return _fit_context(context, max_context_bytes())


def serialize_inference_context(context: dict) -> str:
    encoded = _encode(context)
    if len(encoded) > max_context_bytes():
        raise ValueError('inference context exceeds AI_MAX_CONTEXT_BYTES')
    return encoded


def bound_repair_input(raw: str, context: dict) -> str:
    """Give repair only structured candidate fields plus the original sanitized evidence."""
    if len(raw) > max_context_bytes():
        return ''
    try:
        candidate = extract_json(raw)
    except ValueError:
        return ''
    classification = candidate.get('classification')
    if not isinstance(classification, str) or classification not in {'false_positive', 'true_positive', 'uncertain'}:
        return ''
    summary = {'classification': classification}
    confidence = candidate.get('confidence')
    if isinstance(confidence, (int, float)) and not isinstance(confidence, bool) and math.isfinite(confidence) and 0 <= confidence <= 1:
        summary['confidence'] = confidence
    result = {**summary, 'evidence': context}
    encoded = _encode(result)
    return encoded if len(encoded) <= max_context_bytes() else ''
