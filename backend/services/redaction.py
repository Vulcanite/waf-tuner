"""Mandatory request redaction and context-size limiting before AI inference."""
import json
import os
import re
from urllib.parse import parse_qsl, urlsplit


SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token",
}
_SENSITIVE_KEY_RE = re.compile(
    os.environ.get(
        "SENSITIVE_FIELD_PATTERN",
        r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|session|credential|private[_-]?key)",
    )
)
REDACTED = "[REDACTED]"


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + f"...[TRUNCATED {len(value) - limit} CHARS]"


def _redact_value(value, key: str | None = None, field_limit: int = 8192):
    if key and _SENSITIVE_KEY_RE.search(key):
        return REDACTED
    if isinstance(value, dict):
        return {
            str(child_key): _redact_value(child_value, str(child_key), field_limit)
            for child_key, child_value in value.items()
        }
    if isinstance(value, list):
        return [_redact_value(item, None, field_limit) for item in value]
    if isinstance(value, bytes):
        return {"upload": "[BINARY OMITTED]", "size": len(value)}
    if isinstance(value, str):
        return _truncate(value, field_limit)
    return value


def redact_request(raw_request: dict) -> dict:
    field_limit = int(os.environ.get("AI_MAX_FIELD_CHARS", "8192"))
    total_limit = int(os.environ.get("AI_MAX_REQUEST_CHARS", "32768"))
    raw_request = raw_request or {}
    headers = {}
    for key, value in (raw_request.get("headers") or {}).items():
        headers[str(key)] = REDACTED if str(key).lower() in SENSITIVE_HEADERS else _truncate(str(value), field_limit)

    content_type = ""
    for header_name, header_value in (raw_request.get("headers") or {}).items():
        if str(header_name).lower() == "content-type":
            content_type = str(header_value).lower()
            break

    body = raw_request.get("body", "")
    if isinstance(body, str):
        if "application/x-www-form-urlencoded" in content_type:
            parsed = {
                key: _redact_value(value, key, field_limit)
                for key, value in parse_qsl(body, keep_blank_values=True)
            }
        elif "multipart/form-data" in content_type:
            parsed = {
                "multipart": "[MULTIPART BODY OMITTED]",
                "size": len(body.encode("utf-8", errors="replace")),
            }
        else:
            try:
                parsed = json.loads(body)
            except (json.JSONDecodeError, TypeError):
                parsed = _redact_value(body, None, field_limit)
            else:
                parsed = _redact_value(parsed, None, field_limit)
        body = parsed
    else:
        body = _redact_value(body, None, field_limit)

    result = {"headers": headers, "body": body}
    encoded = json.dumps(result, ensure_ascii=False, default=str)
    if len(encoded) > total_limit:
        result["body"] = _truncate(json.dumps(body, ensure_ascii=False, default=str), max(0, total_limit - 1024))
        result["truncated"] = True
    return result


def sanitize_inference_context(context: dict) -> tuple[dict, list[str]]:
    """Redact every inference field and report paths changed for model uncertainty."""
    field_limit = int(os.environ.get("AI_MAX_FIELD_CHARS", "8192"))
    redacted: list[str] = []

    def walk(value, path: str = "", key: str | None = None):
        if key and _SENSITIVE_KEY_RE.search(key):
            redacted.append(path)
            return REDACTED
        if isinstance(value, dict):
            parameter = str(value.get("parameter") or value.get("variable") or "")
            result = {}
            for child_key, child_value in value.items():
                child_path = f"{path}.{child_key}" if path else str(child_key)
                if str(child_key).lower() == "transaction_id":
                    redacted.append(child_path)
                    continue
                if child_key == "matched_data" and _SENSITIVE_KEY_RE.search(parameter):
                    redacted.append(child_path)
                    result[str(child_key)] = REDACTED
                elif path.endswith("headers") and str(child_key).lower() in SENSITIVE_HEADERS:
                    redacted.append(child_path)
                    result[str(child_key)] = REDACTED
                else:
                    result[str(child_key)] = walk(child_value, child_path, str(child_key))
            return result
        if isinstance(value, list):
            return [walk(item, f"{path}[{index}]") for index, item in enumerate(value)]
        return _redact_value(value, key, field_limit)

    return walk(context), redacted


def split_and_redact_uri(uri: str | None) -> dict:
    """Return a query-free path and a sensitive-key-redacted query mapping."""
    parsed = urlsplit(str(uri or ""))
    query = {
        key: _redact_value(value, key)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
    }
    return {"path": parsed.path or "/", "query": query}
