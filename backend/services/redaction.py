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
# Header, cookie and request-field names that usually carry a session, login, anti-forgery,
# API-key, SSO assertion, signature or one-time authorization value. `auth` skips `author`;
# `code` and `state` (OAuth) count only as a whole field name or a JSON leaf (json.code).
_SESSION_NAME_RE = re.compile(
    r"(?i)(sess|sid|token|auth(?!or)|jwt|csrf|xsrf|remember|logged[_-]?in|wordpress_|identity|"
    r"subscription[_-]?key|access[_-]?key|api[_-]?key|apikey|saml|signature|(?:^|\.)(?:code|state)$)"
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
# Session ids carried in a URL (;jsessionid=, ?PHPSESSID=, sid= in a Referer); no leading \b,
# so the name may follow `;` or a prefix such as `j` or `PHP`.
_URL_SESSION_RE = re.compile(r"(?i)(\w*(?:sess(?:ion)?_?id|sid)=)[^&;#?\s]+")


def is_sensitive_name(name: str) -> bool:
    return bool(_SENSITIVE_KEY_RE.search(name))


def is_credential_name(name: str) -> bool:
    """A header, cookie or request field whose value is a credential, session or one-time secret.

    Used for matched header/cookie targets and for query parameter names in the URI evidence.
    A matched ARGS target is checked with is_sensitive_name only, so a documented field such as
    `signature` or `author` can still be analysed when a rule matches it.
    """
    return name.lower() in SENSITIVE_HEADERS or is_sensitive_name(name) or bool(_SESSION_NAME_RE.search(name))


def sanitize_evidence_text(value: str) -> str:
    if 'PRIVATE KEY-----' in value:
        return REDACTED
    value = _EMAIL_RE.sub(REDACTED, value)
    value = _BEARER_RE.sub(REDACTED, value)
    value = _INLINE_SECRET_RE.sub(REDACTED, value)
    value = _URL_SESSION_RE.sub(lambda match: match.group(1) + REDACTED, value)
    return _JWT_RE.sub(REDACTED, value)
