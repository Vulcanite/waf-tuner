#!/usr/bin/env python3
"""Write an application profile JSON file from an OpenAPI 3.x JSON document.

  python3 scripts/openapi_to_profile.py lab/flask-app/openapi.json --name shop \\
      --host shop.lab --language python --framework flask --data-store sqlite \\
      --output data/profiles/shop.json

Put the file in PROFILES_DIR and restart the backend to load it (see docs/profiles.md).
Standard library only. YAML specs are not supported; convert them to JSON first.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from services.openapi_profile import OpenAPIError, load_spec, openapi_to_profile  # noqa: E402
from services.profile_files import MAX_DOCUMENT_BYTES  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("spec", type=Path, help="OpenAPI 3.x JSON file")
    parser.add_argument("--name", required=True, help="profile name")
    parser.add_argument("--host", action="append", default=[], help="host pattern (repeatable)")
    parser.add_argument("--language", action="append", default=[], help="language, e.g. python (repeatable)")
    parser.add_argument("--framework", action="append", default=[], help="framework (repeatable)")
    parser.add_argument("--data-store", action="append", default=[], help="database or store (repeatable)")
    parser.add_argument("--notes", help="free-text application notes")
    parser.add_argument("--base-path", help="URL path prefix (default: the first server URL's path)")
    parser.add_argument("--no-catch-all", action="store_true", help="do not add a /* route")
    parser.add_argument("--output", "-o", type=Path, help="output file (default: stdout)")
    args = parser.parse_args(argv)

    context = {"languages": args.language, "frameworks": args.framework, "data_stores": args.data_store}
    if args.notes:
        context["notes"] = args.notes
    try:
        if args.spec.stat().st_size > MAX_DOCUMENT_BYTES:
            raise OpenAPIError(f"The OpenAPI document is larger than {MAX_DOCUMENT_BYTES} bytes")
        profile = openapi_to_profile(
            load_spec(args.spec.read_bytes()), name=args.name, host_patterns=args.host, context=context,
            base_path=args.base_path, catch_all=not args.no_catch_all,
        )
    except (OSError, OpenAPIError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    text = json.dumps(profile, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
        print(f"wrote {args.output} ({len(profile['routes'])} routes)", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
