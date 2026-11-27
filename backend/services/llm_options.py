"""Provider settings and request payload shared by the backend and eval."""
import json
import math
import os
from urllib.parse import urlsplit


ESCALATION_EFFORT_REJECTED = (
    "Provider rejected LLM_ESCALATION_REASONING_EFFORT. Escalation is paused. "
    "First-pass analysis remains available."
)


def is_escalation_effort_rejection(status: int | None, message: str) -> bool:
    return status in (400, 422) and "reasoning_effort" in message.casefold().replace(" ", "_")


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name, "").strip().lower()
    if default:
        return value not in {"0", "false", "no", "off"}
    return value in {"1", "true", "yes", "on"}


def thinking_options() -> dict:
    """Thinking controls as the `thinking` and `reasoning_effort` request fields. LLM_THINKING=off sends neither."""
    thinking = (os.environ.get("LLM_THINKING", "").strip() or "enabled").lower()
    if thinking == "off":
        return {}
    if thinking not in {"enabled", "disabled"}:
        raise ValueError("LLM_THINKING must be enabled, disabled or off")
    options: dict = {"thinking": {"type": thinking}}
    if thinking == "enabled":
        options["reasoning_effort"] = os.environ.get("LLM_REASONING_EFFORT", "").strip() or "high"
    return options


def request_settings(*, model: str | None = None) -> dict:
    base_url = (os.getenv("LLM_API_BASE_URL", "").strip() or "http://127.0.0.1:8001/v1").rstrip("/")
    parsed = urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.query or parsed.fragment:
        raise ValueError("LLM_API_BASE_URL must be an HTTP(S) endpoint without embedded credentials, query, or fragment")
    api_key = os.getenv("LLM_API_KEY", "").strip() or "local"
    if api_key in {"sk-...", "sk-or-..."}:
        raise ValueError("LLM API credentials are not configured")
    max_tokens = int(os.getenv("LLM_MAX_OUTPUT_TOKEN", "20000"))
    temperature = float(os.getenv("LLM_TEMPERATURE", "0.01"))
    timeout = float(os.getenv("LLM_TIMEOUT_SECONDS", "180"))
    if max_tokens <= 0 or not 0 <= temperature <= 2 or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("LLM max tokens and timeout must be positive and temperature must be 0..2")
    thinking = thinking_options()
    # The stronger second request raises the reasoning effort, so it needs thinking enabled.
    # Effort values pass through unchecked, like LLM_REASONING_EFFORT; the provider rejects unknown ones.
    escalation_effort = os.getenv("LLM_ESCALATION_REASONING_EFFORT", "").strip()
    if thinking.get("thinking", {}).get("type") != "enabled":
        escalation_effort = ""
    raw_headers = os.getenv("LLM_EXTRA_HEADERS", "").strip()
    headers = json.loads(raw_headers) if raw_headers else {}
    if not isinstance(headers, dict) or any(not isinstance(v, str) for v in headers.values()):
        raise ValueError("LLM_EXTRA_HEADERS must be a JSON object of string values")
    gateway = os.getenv("CF_AIG_GATEWAY_ID", "").strip()
    if gateway and "cf-aig-gateway-id" not in {name.lower() for name in headers}:
        headers["cf-aig-gateway-id"] = gateway
    return {
        "base_url": base_url,
        "api_key": api_key,
        "model": model or os.getenv("LLM_MODEL", "").strip() or "Foundation-Sec-1.1-8B-Instruct",
        "max_tokens": max_tokens,
        "temperature": temperature,
        "timeout": timeout,
        "structured_output": env_bool("LLM_STRUCTURED_OUTPUT"),
        "verify_ssl": env_bool("LLM_VERIFY_SSL", True),
        "headers": headers,
        "escalation_effort": escalation_effort,
        **thinking,
    }


def request_payload(settings: dict, messages: list[dict], attempt_type: str = "initial") -> dict:
    """Chat-completions payload."""
    from services.model_contract import RESPONSE_FORMAT

    thinking = {key: settings[key] for key in ("thinking", "reasoning_effort") if key in settings}
    if attempt_type == "escalation":
        thinking = {"thinking": {"type": "enabled"}, "reasoning_effort": settings["escalation_effort"]}
    options = {
        "model": settings["model"],
        "max_tokens": settings["max_tokens"],
        "temperature": settings["temperature"],
        "messages": messages,
        **thinking,
    }
    if settings.get("structured_output"):
        options["response_format"] = RESPONSE_FORMAT
    return options
