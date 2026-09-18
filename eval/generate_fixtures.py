#!/usr/bin/env python3
"""Append corpus cases onto eval/fixtures.jsonl in the release fixture schema."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "eval"))

from fixtures import FIXTURES_PATH, load_fixtures, merge_fixtures, synthesize_fixtures, write_fixtures, write_request_jsonl  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default=str(FIXTURES_PATH))
    args = parser.parse_args()
    output = Path(args.output)
    merged = merge_fixtures(load_fixtures(output), synthesize_fixtures())
    write_fixtures(merged, output)
    requests_path = write_request_jsonl()
    labels = {}
    for record in merged:
        labels[record["label"]] = labels.get(record["label"], 0) + 1
    print(f"Wrote {len(merged)} fixtures to {output} ({labels})")
    print(f"Wrote request corpus to {requests_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
