"""Project the evidence for one WAF match into a bounded provider message."""
from __future__ import annotations

import json
import math
import os
import re
from collections.abc import Mapping
from urllib.parse import SplitResult, parse_qsl, unquote, unquote_plus, urlsplit

from services.json_extract import extract_json
from services.redaction import REDACTED, is_credential_name, is_sensitive_name, sanitize_evidence_text


_AGGREGATE_IDS = frozenset({
    '949060', '949061', '949062', '949063', '949100', '949110',
    '959060', '959061', '959062', '959063', '959100',
    '980100', '980110', '980115', '980120', '980130', '980140', '980145', '980150',
})
_METHOD_COLLECTIONS = {'REQUEST_METHOD'}
_URI_COLLECTIONS = {'REQUEST_URI', 'REQUEST_URI_RAW', 'REQUEST_FILENAME', 'REQUEST_BASENAME'}
_ARGUMENT_COLLECTIONS = {'ARGS', 'ARGS_GET', 'ARGS_POST', 'ARGS_NAMES', 'ARGS_GET_NAMES', 'ARGS_POST_NAMES'}
_MATCH_TARGET_SUFFIX = re.compile(r'''\b(?:within|variable)\s+[`'\"]?(?P<collection>[A-Z_]+)(?::(?P<parameter>[^\s,;`'\"\)]+))?''', re.IGNORECASE)
_NATIVE_VALUE = re.compile(r'''(?s)\(Value:\s+[`'"](?P<value>.*)['"]\s*\)\s*$''')
_NATIVE_TARGET = re.compile(r'''\bagainst\s+variable\s+[`'\"](?P<collection>[A-Z_]+)(?::(?P<parameter>[^`'\"\r\n]+))?[`'\"]\s+\(Value:''', re.IGNORECASE)


# Request collections CRS copies into MATCHED_VARS or a TX variable before inspecting them again.
_INPUT_COLLECTIONS = frozenset({
    'ARGS', 'ARGS_GET', 'ARGS_POST', 'ARGS_NAMES', 'ARGS_GET_NAMES', 'ARGS_POST_NAMES',
    'REQUEST_HEADERS', 'REQUEST_HEADERS_NAMES', 'REQUEST_COOKIES', 'REQUEST_COOKIES_NAMES',
    'REQUEST_URI', 'REQUEST_URI_RAW', 'REQUEST_FILENAME', 'REQUEST_BASENAME', 'REQUEST_METHOD',
    'REQUEST_BODY', 'FILES', 'FILES_NAMES', 'XML',
})


def _tx_source(name: str) -> tuple[str, str] | None:
    """A TX variable named after its source: `<COLL>:<param>` or `<prefix>_<COLL>:<param>`."""
    head, _, parameter = name.partition(':')
    head = head.upper()
    # Longest name first, so ..._ARGS_GET:x resolves to ARGS_GET rather than failing on GET.
    for collection in sorted(_INPUT_COLLECTIONS, key=len, reverse=True):
        if parameter and (head == collection or head.endswith('_' + collection)):
            return collection, parameter
    return None


def resolve_input_target(collection: str | None, parameter: str | None) -> tuple[str | None, str | None]:
    """The request input behind a CRS wrapper, for evidence only.

    MATCHED_VARS:REQUEST_COOKIES:cart_id -> (REQUEST_COOKIES, cart_id) and
    TX:rfi_parameter_ARGS:name -> (ARGS, name). Anything else is returned unchanged.
    The exclusion scope keeps the inspected target: removing ARGS:name from a rule
    that inspects TX:rfi_parameter_ARGS:name would not stop that rule.
    """
    resolved = (collection, parameter)
    for _ in range(4):
        current, name = resolved
        if not name:
            break
        if current == 'MATCHED_VARS':
            inner, _, inner_name = name.partition(':')
            resolved = (inner.upper(), inner_name or None)
        elif current == 'TX' and (source := _tx_source(name)):
            resolved = source
        else:
            break
    return resolved if resolved[0] in _INPUT_COLLECTIONS else (collection, parameter)


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


def _cookie_items(header) -> list[tuple[str, str]]:
    """Split a Cookie header into ordered (name, value) pairs, as ModSecurity fills REQUEST_COOKIES."""
    if not isinstance(header, str):
        return []
    items = []
    for part in header.split(';'):
        name, _, value = part.strip().partition('=')
        if name.strip():
            items.append((name.strip(), value.strip()))
    return items


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
        'cookies': _cookie_items(headers.get('cookie')),
        'media_type': media_type,
        'targets': [match_target(item) for item in event.get('matches') or []],
    }


def _query_or_body_values(items, parameter, collection):
    values = [value for name, value in items if name == parameter]
    if collection.endswith('_NAMES'):
        return [parameter] if values else []
    return values


def match_evidence(request: dict, collection: str | None, parameter: str | None, match: dict | None = None) -> dict:
    """Extract ordered values from the exact collection identified by the log.

    `collection`/`parameter` are the inspected target; a MATCHED_VARS or TX wrapper is
    resolved to its request input (resolve_input_target) to find the values.
    """
    inspected = (collection, parameter)
    collection, parameter = resolve_input_target(collection, parameter)
    values = {}
    if collection in _ARGUMENT_COLLECTIONS and parameter:
        values['query'] = [] if collection.startswith('ARGS_POST') else _query_or_body_values(request['query_items'], parameter, collection)
        values['body'] = [] if collection.startswith('ARGS_GET') else _query_or_body_values(request['body_items'], parameter, collection)
    elif collection == 'REQUEST_HEADERS' and parameter:
        value = request['headers'].get(parameter.lower())
        values['header'] = [value] if value is not None else []
    elif collection == 'REQUEST_COOKIES' and parameter:
        # ModSecurity collection keys are case-insensitive.
        values['cookie'] = [value for name, value in request['cookies'] if name.lower() == parameter.lower()]
    if values:
        # The connector's native Value field is evidence from a known target,
        # even when the captured request parts lack the original field value.
        description = match.get('match_description') if match else None
        native_value = _NATIVE_VALUE.search(description) if isinstance(description, str) else None
        if native_value and extract_match_target(description) in (inspected, (collection, parameter)):
            logged_value = native_value.group('value')
            if not any(logged_value in items for items in values.values()):
                values['audit_log_value'] = [logged_value]
        return values
    if collection == 'REQUEST_HEADERS_NAMES' and parameter:
        return {'header_name': [parameter] if parameter.lower() in request['headers'] else []}
    if collection == 'REQUEST_COOKIES_NAMES' and parameter:
        return {'cookie_name': [parameter] if any(name.lower() == parameter.lower() for name, _ in request['cookies']) else []}
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


_HEADER_COOKIE_COLLECTIONS = frozenset({'REQUEST_HEADERS', 'REQUEST_COOKIES', 'REQUEST_COOKIES_NAMES'})


def _safe_target(collection, parameter) -> bool:
    """Whether the matched target's value may be sent to the model.

    Only the one matched header or cookie is ever sent, and only when its name does not
    look like a credential or session identifier (Authorization, Cookie, PHPSESSID, ...).
    """
    if parameter and is_sensitive_name(parameter):
        return False
    collection, parameter = resolve_input_target(collection, parameter)
    if parameter and is_sensitive_name(parameter):
        return False
    if collection in _HEADER_COOKIE_COLLECTIONS and parameter:
        return not is_credential_name(parameter)
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


def _profile_projection(profile: dict, parameter: str | None = None, *, parameters: list[str] | None = None) -> dict:
    application = profile.get('application') or {}
    route = profile.get('route')
    result = {
        'application': {key: application[key] for key in ('purpose', 'name', 'languages', 'frameworks', 'data_stores', 'notes') if key in application},
    }
    if isinstance(route, dict):
        route_fields = {key: route[key] for key in ('path', 'methods', 'notes', 'purpose') if key in route}
        semantics = route.get('parameters') or {}
        if isinstance(semantics, dict) and parameter in semantics and not is_sensitive_name(parameter):
            route_fields['parameter_semantics'] = semantics[parameter]
        if isinstance(semantics, dict) and parameters:
            # Request mode: semantics for every field of the request that the route documents.
            named = {name: semantics[name] for name in parameters if name in semantics and not is_sensitive_name(name)}
            if named:
                route_fields['parameter_semantics'] = named
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


def _field_limit() -> int:
    return max(64, min(8192, int(os.environ.get('AI_MAX_FIELD_CHARS', '8192'))))


def _rule_value(rule, key):
    return rule.get(key) if isinstance(rule, dict) else getattr(rule, key, None)


def _rule_truncated(rule, field_limit: int) -> bool:
    return any(len(value) > field_limit for value in (_rule_value(rule, 'operator'), _rule_value(rule, 'raw')) if isinstance(value, str))


def _project_match(request: dict, match: dict, collection, parameter, field_limit: int) -> dict:
    """Sanitized, bounded values of one match's own target, shared by both analysis units."""
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
    return {
        'values': values,
        'matched_data': safe_excerpt if corroborated else None,
        'target_hidden': not safe_target or target_redacted,
        'logged_excerpt_omitted': bool(match_data and not corroborated),
        'values_truncated': values_truncated,
    }


def _input_target(collection, parameter) -> dict | None:
    """The resolved request input, shown beside the inspected target when CRS wrapped it."""
    resolved = resolve_input_target(collection, parameter)
    if resolved == (collection, parameter):
        return None
    return {'collection': resolved[0], 'parameter': _text(resolved[1], 512) if resolved[1] else None}


def _context_matches(event: dict, request: dict, excluded: set[int]) -> tuple[list[dict], bool]:
    """Identity of the transaction's other matches (sibling and aggregate rules) as context only."""
    keys = {
        (str(item.get('rule_id') or ''), *(value or '' for value in request['targets'][index]))
        for index, item in enumerate(event.get('matches') or [])
        if index not in excluded
    }
    return [{
        'rule_id': _text(rule_id, 24),
        'collection': collection_name or None,
        'parameter': REDACTED if is_sensitive_name(parameter_name) else _text(parameter_name, 128) if parameter_name else None,
    } for rule_id, collection_name, parameter_name in sorted(keys)[:16]], len(keys) > 16


def build_inference_context(event, match, *, match_index=0, crs_rule=None, application_context=None, collection=None, parameter=None) -> dict:
    """Per-match analysis unit: bounded, redacted evidence for ONE match of an audited transaction.

    Used by the backend worker when ANALYSIS_UNIT=match and by eval/evaluate.py.
    Send the result with model_contract.response_messages(context).
    """
    request = prepare_request_evidence(event)
    observed_collection, observed_parameter = match_target(match)
    collection = collection or observed_collection
    parameter = parameter or observed_parameter
    field_limit = _field_limit()
    projected = _project_match(request, match, collection, parameter, field_limit)
    values = projected['values']
    other_matches, other_truncated = _context_matches(event, request, {match_index})
    input_target = _input_target(collection, parameter)
    context = {
        'incident': {
            'method': _text(request['method'], 24),
            'uri': {'path': _safe_path(request['path'], field_limit), 'query': values.pop('query', [])},
            'rule_id': _text(match.get('rule_id') or '', 24),
            'rule_message': _text(_rule_value(crs_rule, 'message') or '', 512),
            'matched_data': projected['matched_data'],
            'collection': collection,
            'parameter': _text(parameter, 512) if parameter else None,
            **({'input_target': input_target} if input_target else {}),
            'match_index': match_index,
            'anomaly_score': event.get('anomaly_score'),
            'anomaly_score_source': event.get('anomaly_score_source'),
            'other_matches': other_matches,
        },
        'request': {'content_type': _text(request['media_type'], 128), 'body_status': request['body_status'], 'matched_values': values},
        'crs_rule': _rule_projection(crs_rule, field_limit),
        'application_context': (
            _profile_projection(application_context, resolve_input_target(collection, parameter)[1])
            if application_context else {}
        ),
        'redaction': {
            'target_hidden': projected['target_hidden'],
            'logged_excerpt_omitted': projected['logged_excerpt_omitted'],
            'truncated': (
                projected['values_truncated'] or _rule_truncated(crs_rule, field_limit)
                or len(request['path']) > field_limit or other_truncated
            ),
        },
    }
    return _fit_context(context, max_context_bytes())


def _request_fields(items, field_limit: int) -> tuple[list, bool]:
    fields = [
        [_text(name, 128), REDACTED if is_sensitive_name(str(name)) else _bounded_values([value], field_limit)[0]]
        for name, value in items[:32]
    ]
    truncated = len(items) > 32 or any(isinstance(value, str) and len(value) > field_limit for _, value in items[:32])
    return fields, truncated


def _fit_request_context(context: dict, budget: int) -> dict:
    if len(_encode(context)) <= budget:
        return context
    context['redaction']['truncated'] = True
    request = context['request']
    rules = [entry['crs_rule'] for entry in context['matches'] if entry.get('crs_rule')]
    # Drop the least specific evidence first; each match keeps its own matched values longest.
    steps = [
        *((rule, 'raw') for rule in rules), *((rule, 'tags') for rule in rules),
        (context, 'other_matches'), (request, 'body'), (request, 'query'), (context, 'application_context'),
        *((rule, 'message') for rule in rules), *((entry, 'rule_message') for entry in context['matches']),
        *((rule, 'source_file') for rule in rules), *((entry, 'matched_data') for entry in context['matches']),
        (request, 'content_type'),
    ]
    for container, key in steps:
        container.pop(key, None)
        if len(_encode(context)) <= budget:
            return context
    # Retain each match's identity at very small budgets and let the model abstain.
    minimal = {
        'request': {'method': request.get('method')},
        'matches': [
            {key: entry.get(key) for key in ('match_index', 'rule_id', 'collection', 'parameter')}
            for entry in context['matches']
        ],
        'redaction': {'truncated': True},
    }
    if len(_encode(minimal)) <= budget:
        return minimal
    return {}


def build_request_context(event, match_indexes, crs_rules, application_context) -> dict:
    """Per-request analysis unit: the request once plus every match being analysed.

    `match_indexes` are indexes into event['matches']; aggregate (anomaly-score) matches
    are never listed for a verdict and appear only under `other_matches`. `crs_rules`
    maps match_index -> CRSRule (or a dict, or None). The whole request's query and
    body fields are included, redacted by name; a header or cookie value is included
    only inside the entry of a match on that header or cookie (see _safe_target).

    Shape: {'request': {...}, 'matches': [{'match_index', 'rule_id', 'collection',
    'parameter', 'input_target'?, 'matched_data', 'matched_values', 'crs_rule', 'redaction'}, ...],
    'other_matches': [...], 'application_context': {...}, 'redaction': {'truncated', ...}}.
    Bounded by AI_MAX_CONTEXT_BYTES. Send with model_contract.request_response_messages.
    Used by the backend worker when ANALYSIS_UNIT=request and by eval/evaluate.py.
    """
    request = prepare_request_evidence(event)
    matches = event.get('matches') or []
    field_limit = _field_limit()
    crs_rules = crs_rules or {}
    analysed = sorted({
        index for index in match_indexes
        if type(index) is int and 0 <= index < len(matches) and not is_aggregate_match(matches[index])
    })
    entries = []
    parameters = set()
    for index in analysed:
        match = matches[index]
        collection, parameter = request['targets'][index]
        crs_rule = crs_rules.get(index)
        projected = _project_match(request, match, collection, parameter, field_limit)
        input_target = _input_target(collection, parameter)
        input_parameter = resolve_input_target(collection, parameter)[1]
        if input_parameter:
            parameters.add(input_parameter)
        entries.append({
            'match_index': index,
            'rule_id': _text(match.get('rule_id') or '', 24),
            'rule_message': _text(_rule_value(crs_rule, 'message') or '', 512),
            'collection': collection,
            'parameter': _text(parameter, 512) if parameter else None,
            **({'input_target': input_target} if input_target else {}),
            'matched_data': projected['matched_data'],
            'matched_values': projected['values'],
            'crs_rule': _rule_projection(crs_rule, field_limit),
            'redaction': {
                'target_hidden': projected['target_hidden'],
                'logged_excerpt_omitted': projected['logged_excerpt_omitted'],
                'truncated': projected['values_truncated'] or _rule_truncated(crs_rule, field_limit),
            },
        })
    query, query_truncated = _request_fields(request['query_items'], field_limit)
    body, body_truncated = _request_fields(request['body_items'], field_limit)
    parameters.update(str(name) for name, _ in [*request['query_items'], *request['body_items']])
    other_matches, other_truncated = _context_matches(event, request, set(analysed))
    context = {
        'request': {
            'method': _text(request['method'], 24),
            'path': _safe_path(request['path'], field_limit),
            'query': query,
            'content_type': _text(request['media_type'], 128),
            'body_status': request['body_status'],
            'body': body,
            'anomaly_score': event.get('anomaly_score'),
            'anomaly_score_source': event.get('anomaly_score_source'),
        },
        'matches': entries,
        'other_matches': other_matches,
        'application_context': _profile_projection(application_context, parameters=sorted(parameters)) if application_context else {},
        'redaction': {
            # Set when the path or the whole context was cut; withholds every draft from this request.
            'truncated': len(request['path']) > field_limit,
            # Unmatched request fields were cut; each match's own values carry their own flag.
            'request_fields_truncated': query_truncated or body_truncated or other_truncated,
        },
    }
    return _fit_request_context(context, max_context_bytes())


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
    summary = _repair_candidate(candidate)
    if summary is None:
        return ''
    result = {**summary, 'evidence': context}
    encoded = _encode(result)
    return encoded if len(encoded) <= max_context_bytes() else ''


def _repair_candidate(value) -> dict | None:
    if not isinstance(value, dict):
        return None
    classification = value.get('classification')
    if not isinstance(classification, str) or classification not in {'false_positive', 'true_positive', 'uncertain'}:
        return None
    summary = {'classification': classification}
    confidence = value.get('confidence')
    if isinstance(confidence, (int, float)) and not isinstance(confidence, bool) and math.isfinite(confidence) and 0 <= confidence <= 1:
        summary['confidence'] = confidence
    return summary


def bound_request_repair_input(raw: str, context: dict, match_indexes) -> str:
    """Request-mode repair input: each match's candidate classification plus the sanitized evidence.

    Returns '' (no repair) unless the invalid output names exactly one classification for
    every analysed match_index, since a repair may restate but never choose a classification.
    """
    if len(raw) > max_context_bytes():
        return ''
    try:
        candidate = extract_json(raw)
    except ValueError:
        return ''
    expected = set(match_indexes)
    verdicts = candidate.get('verdicts')
    if not expected or not isinstance(verdicts, list):
        return ''
    summaries = {}
    for item in verdicts:
        index = item.get('match_index') if isinstance(item, dict) else None
        summary = _repair_candidate(item)
        if type(index) is not int or index not in expected or index in summaries or summary is None:
            return ''
        summaries[index] = {'match_index': index, **summary}
    if set(summaries) != expected:
        return ''
    encoded = _encode({'verdicts': [summaries[index] for index in sorted(summaries)], 'evidence': context})
    return encoded if len(encoded) <= max_context_bytes() else ''
