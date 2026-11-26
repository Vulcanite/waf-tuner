"""Pull the model's JSON object out of a raw completion.

Standard library only, so eval/evaluate.py can import it without the backend's
dependencies and score exactly the parser the backend uses.
"""
import json
import re


def extract_json(raw: str) -> dict:
    """Parse whole output, newest fenced JSON, then complete embedded objects."""
    clean = (raw or "").strip().replace("</assistant>", "").strip()
    decoder = json.JSONDecoder()

    def object_value(candidate: str) -> dict | None:
        try:
            value = json.loads(candidate)
        except json.JSONDecodeError:
            return None
        return value if isinstance(value, dict) else None

    complete = object_value(clean)
    if complete is not None:
        return complete
    fences = re.findall(r"```(?:json)?\s*(.*?)```", clean, flags=re.IGNORECASE | re.DOTALL)
    for candidate in reversed(fences):
        value = object_value(candidate.strip())
        if value is not None:
            return value
    objects = []
    for index, char in enumerate(clean):
        if char != "{":
            continue
        try:
            value, _ = decoder.raw_decode(clean[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            objects.append(value)
    if objects:
        return objects[-1]
    raise ValueError("model response does not contain a complete JSON object")
