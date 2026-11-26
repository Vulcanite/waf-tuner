"""Sensitive-field and text redaction for inference evidence."""
import os
import re


SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token",
}
_SENSITIVE_KEY_RE = re.compile(
    os.environ.get(
        "SENSITIVE_FIELD_PATTERN",
        r"(?i)(password|passwd|pwd|pass|secret|token|api[_-]?key|session|sessid|credential|"
        r"private[_-]?key|cvv|card[_-]?(?:number|no)|(?:^|[_.-])(?:pin|otp|ssn)(?:$|[_.-]))",
    )
)
REDACTED = "[REDACTED]"

_EMAIL_RE = re.compile(r"(?i)\b[\w.+-]{1,64}@[\w.-]{1,253}\.[a-z]{2,63}\b")
_INLINE_SECRET_RE = re.compile(
    r"""(?ix)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization|cookies?|
    set-cookie|session(?:id)?|credential|private[_-]?key|pin|otp|ssn|cvv|card[_-]?number)
    ["']?\s*[:=]\s*(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s,;&"']+)"""
)
_BEARER_RE = re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._+/=-]{8,}")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")


def is_sensitive_name(name: str) -> bool:
    return bool(_SENSITIVE_KEY_RE.search(name))


def sanitize_evidence_text(value: str) -> str:
    if 'PRIVATE KEY-----' in value:
        return REDACTED
    value = _EMAIL_RE.sub(REDACTED, value)
    value = _BEARER_RE.sub(REDACTED, value)
    value = _INLINE_SECRET_RE.sub(REDACTED, value)
    return _JWT_RE.sub(REDACTED, value)
