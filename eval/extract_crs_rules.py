#!/usr/bin/env python3
"""Copy the CRS rule set out of a WAF image, read-only, for live eval.

    python3 eval/extract_crs_rules.py                       # waftuner-capture-nginx -> eval/crs-rules
    python3 eval/extract_crs_rules.py --image owasp/modsecurity-crs:nginx-alpine --output /tmp/crs

The default image is the one lab/docker-compose.capture.yml builds, the same ModSecurity and CRS
that captured eval/requests.jsonl. The helper creates one stopped container from the image (never
started), copies the `.conf` and `.data` files out of the first CRS rules directory it finds, and
removes that container. It touches no other container, image or volume. Stdlib only.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_IMAGE = "waftuner-capture-nginx:latest"
DEFAULT_OUTPUT = ROOT / "eval" / "crs-rules"
# Same candidates as nginx/docker-entrypoint.d/09-seed-crs.sh.
RULE_DIRS = (
    "/etc/nginx/modsecurity/crs/rules", "/opt/owasp-crs/rules",
    "/usr/share/modsecurity-crs/rules", "/etc/modsecurity/crs/rules",
)


def _docker(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True)


def extract(image: str, output: Path) -> int:
    created = _docker("create", image)
    if created.returncode != 0:
        raise RuntimeError(f"docker create {image} failed: {created.stderr.strip()}")
    container = created.stdout.strip()
    try:
        with tempfile.TemporaryDirectory() as scratch:
            for source in RULE_DIRS:
                target = Path(scratch) / "rules"
                if _docker("cp", f"{container}:{source}/.", str(target)).returncode == 0 and any(target.glob("*.conf")):
                    break
                shutil.rmtree(target, ignore_errors=True)
            else:
                raise RuntimeError(f"no CRS rules directory found in {image} (looked in {', '.join(RULE_DIRS)})")
            files = sorted(path for path in target.iterdir() if path.is_file() and path.suffix in {".conf", ".data"})
            staged = Path(scratch) / "staged"
            staged.mkdir()
            for path in files:
                shutil.copy2(path, staged / path.name)
            if output.exists():
                # Only ever replace an earlier extraction, never an unrelated directory.
                foreign = [path.name for path in output.iterdir() if not path.is_file() or path.suffix not in {".conf", ".data"}]
                if foreign:
                    raise RuntimeError(f"{output} holds files other than CRS .conf/.data ({foreign[0]}); choose another --output")
                shutil.rmtree(output)
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(staged), str(output))
            return len(files)
    finally:
        _docker("rm", container)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="replaced with the extracted rule files")
    args = parser.parse_args(argv)
    try:
        count = extract(args.image, Path(args.output))
    except (OSError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(f"Copied {count} CRS files from {args.image} to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
