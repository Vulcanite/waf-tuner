# Model evaluation

`requests.jsonl` is the labeled set: 245 requests captured through the real ModSecurity (CRS 4.30, PL2) in front of both lab apps: DVWA (PHP/MySQL, any Host) and the Flask Lab Shop (`lab/flask-app`, Python/SQLite, Host `shop.lab`). The cases are `request_cases()` in `corpus.py`. Each one is a complete form submission with one payload in a query/form/JSON field, header, cookie or the path. They include harmless input that trips CRS (SQL words in search, Markdown/HTML reviews, code in support messages, URLs, file names), attacks, and wrong-stack attacks (PHP to Flask, Jinja/Java/Node to DVWA), which are still labeled `attack`.

Each record holds the raw audit record (`modsec_audit`), `expected_request`, `labels` (`match_index` into `normalize_audit_event(modsec_audit)["matches"]`), the `application_context` the lab profiles in `lab/profiles/` give for that host/method/path, `payload_target`, `category` and `wrong_stack`. A match is labeled when it inspected the payload's input (same collection/parameter, including CRS's `MATCHED_VARS:`/`TX:` copies of it, or a URI/body collection holding it). Score rules (949/959/980) and matches on other inputs, such as response-body rules or the raw `Cookie` header, are left unlabeled. Requests with no labeled match are dropped. Each labeled match is analysed with one model call, built exactly as the worker builds it, so 245 requests give 868 scored matches.

## Recorded eval (CI, no API key)

```bash
PYTHONPATH=eval python3 -m pytest -q eval/tests
python3 eval/evaluate.py --mode recorded --model oracle --output eval/reports/oracle.json
python3 eval/report.py --models oracle --output-dir eval/reports
```

Recordings live in `eval/recordings/<name>.jsonl`, one line per scored match (`<request id>#<match_index>`). The `oracle` file answers with each label so CI can exercise the harness without a provider; its perfect scores say nothing about model quality. Regenerate it after changing `requests.jsonl`:

```bash
python3 eval/evaluate.py --write-oracle
```

Do not point recorded mode at a live `LLM_API_KEY`.

## Capture the request set

Capture into an isolated lab. This does not touch `lab-data/` or the main Compose lab:

```bash
export CAPTURE_DIR=/some/scratch/dir
docker compose -p waftuner-capture -f lab/docker-compose.capture.yml up -d --build
python3 eval/capture_lab.py --requests   # :18080, $CAPTURE_DIR/modsec/audit.log
docker compose -p waftuner-capture -f lab/docker-compose.capture.yml down
```

## Live provider eval

Copy the CRS rule set out of the WAF image the requests were captured with, then run:

```bash
python3 eval/extract_crs_rules.py          # waftuner-capture-nginx -> eval/crs-rules (gitignored)
set -a; . lab-data/.env; set +a
python3 eval/evaluate.py --output eval/report.json --record --concurrency 8
```

`extract_crs_rules.py` creates one stopped container from `--image` (default `waftuner-capture-nginx:latest`, built by `lab/docker-compose.capture.yml`), copies its `.conf`/`.data` rule files to `--output` (default `eval/crs-rules`) and removes that container. It never starts a container or touches others. `--crs-rules-dir` defaults to `eval/crs-rules` (or `CRS_RULES_DIR`); point it at other deployed CRS files or a published snapshot as needed. `lab-data/crs-rules` is the main lab's copy and can lag behind the capture image.

Live eval builds the same compact request as the analysis worker, uses the same provider settings and validator, and records the prompt, fixture, and request digests. Recorded replay marks an altered fixture invalid when a digest was captured. `--concurrency N` analyses N requests at a time in threads; rows, recordings and token totals come out in fixture order, as in a serial run. A 429, 5xx or timeout is retried twice per call; any other provider failure stops the run without sending the queued requests. The report records `wall_time_s`.

### What the report scores

- **False positives identified**: harmless matches the model classified `false_positive`.
- **Exclusions produced**: of those, the ones that would also pass the server's draft gates, in the worker's order: a captured host and a route that documents the target (`REQUIRE_APPLICATION_CONTEXT`, `route_supports_exception`), a buildable scope (`can_build_exception`), the CRS rule present and not chained, the profile not cut from the prompt, the matched evidence not withheld, and no true positive on the same input in the same request. True positives on the same rule and target in other requests, ruleset changes and rule-ID collisions are not modelled. `draft_withheld` counts the gate that stopped each identified false positive. The gate inputs are recorded from the exact context sent, so recordings without them (the oracle) report n/a.
- **Explanation fields present**: the share of scored matches whose verdict has non-empty `rule_looks_for`, `payload_is` and `why` (an invalid output or a bare "not stated" counts as missing).

For a held-out test, supply operator-labeled, scrubbed JSONL with an `id`, a `modsec_audit` object and `labels` as above, or one match per line with `expected` (`attack` or `false_positive`) and a zero-based `match_index`. An optional `application_context` gives the route and parameter semantics. Each line should use evidence you are allowed to send to the configured provider.

Use `--record-as` and different outputs to compare models or reasoning settings on the same fixtures, then `python3 eval/report.py --models a,b` for a side-by-side table. Compare p50/p95 latency, invalid output, uncertain attack cases, and benign accuracy. With a provider that supports the configured reasoning controls, run:

```bash
LLM_REASONING_EFFORT=low LLM_ESCALATION_REASONING_EFFORT=high \
  python3 eval/evaluate.py --record --record-as low-with-escalation --output /tmp/waf-eval-low.json
```

Thinking is off unless `LLM_THINKING=enabled` is set (the lab example sets it). `--record` writes a JSONL next to other recordings. Treat model outputs as evidence that can contain sensitive text. The command exits nonzero if any response remains invalid, any attack is classified as a false positive, or fewer than `--min-attack-detection` (default 0.5) of attacks are classified `true_positive`, so a model that answers "uncertain" to everything fails.
