#!/usr/bin/env python3
"""Send the scripted WordPress and Nextcloud traffic through both WAFs and pair the audit records.

Needs the waftuner-bench lab up and installed (lab/bench/setup.sh). Writes one
line per request to --pairs: the request metadata, the CRS-only WAF's audit
record and the CRS + plugin WAF's audit record, with lab passwords and session
cookies scrubbed. Run label.py afterwards to build requests.jsonl.

    python3 eval/bench/capture.py
    python3 eval/bench/label.py
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from benchlib import APPS, BENCH_DIR, Bench, read_audit_log, scrub  # noqa: E402
import traffic_nextcloud  # noqa: E402
import traffic_wordpress  # noqa: E402

TRAFFIC = {"wordpress": traffic_wordpress.run, "nextcloud": traffic_nextcloud.run}


def wait_ready(timeout: float) -> None:
    deadline = time.time() + timeout
    for app, conf in APPS.items():
        for port in (conf["base"], conf["plugin"]):
            while True:
                try:
                    # /healthz lives on the image's default server, so no app Host header here.
                    urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=3)
                    break
                except OSError:
                    if time.time() > deadline:
                        raise SystemExit(f"WAF on 127.0.0.1:{port} not ready; is the waftuner-bench lab up?")
                    time.sleep(2)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--apps", default="wordpress,nextcloud")
    parser.add_argument("--pairs", default=str(BENCH_DIR / "pairs.jsonl"))
    parser.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args()
    wait_ready(args.timeout)
    bench = Bench()
    for app in args.apps.split(","):
        start = len(bench.sent)
        TRAFFIC[app](bench)
        statuses = Counter(item["status"][0] for item in bench.sent[start:])
        print(f"{app}: sent {len(bench.sent) - start} requests through both WAFs; base statuses {dict(statuses)}")
    time.sleep(2.0)
    services = sorted({conf[key] for conf in APPS.values() for key in ("base_service", "plugin_service")})
    logs = {service: read_audit_log(service) for service in services}
    missing = 0
    with Path(args.pairs).open("w") as handle:
        for item in bench.sent:
            conf = APPS[item["app"]]
            base = logs[conf["base_service"]].get(item["request_id"])
            plugin = logs[conf["plugin_service"]].get(item["request_id"])
            if base is None or plugin is None:
                missing += 1
            line = {**item, "base_audit": base, "plugin_audit": plugin}
            handle.write(json.dumps(scrub(line, bench.secrets), ensure_ascii=False, separators=(",", ":")) + "\n")
    print(f"wrote {len(bench.sent)} pairs to {args.pairs}; {missing} missing an audit record on one side")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
