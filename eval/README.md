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

```bash
set -a; . lab-data/.env; set +a
python3 eval/evaluate.py --output eval/report.json --record
```

`--crs-rules-dir` selects the deployed CRS files or a published snapshot. Live eval builds the same compact request as the analysis worker, uses the same provider settings and validator, and records the prompt, fixture, and request digests. Recorded replay marks an altered fixture invalid when a digest was captured.

For a held-out test, supply operator-labeled, scrubbed JSONL with an `id`, a `modsec_audit` object and `labels` as above, or one match per line with `expected` (`attack` or `false_positive`) and a zero-based `match_index`. An optional `application_context` gives the route and parameter semantics. Each line should use evidence you are allowed to send to the configured provider.

Use `--record-as` and different outputs to compare models or reasoning settings on the same fixtures, then `python3 eval/report.py --models a,b` for a side-by-side table. Compare p50/p95 latency, invalid output, uncertain attack cases, and benign accuracy. With a provider that supports the configured reasoning controls, run:

```bash
LLM_REASONING_EFFORT=low LLM_ESCALATION_REASONING_EFFORT=high \
  python3 eval/evaluate.py --record --record-as low-with-escalation --output /tmp/waf-eval-low.json
```

`--record` writes a JSONL next to other recordings. Treat model outputs as evidence that can contain sensitive text. The command exits nonzero if any response remains invalid, any attack is classified as a false positive, or fewer than `--min-attack-detection` (default 0.5) of attacks are classified `true_positive`, so a model that answers "uncertain" to everything fails.
