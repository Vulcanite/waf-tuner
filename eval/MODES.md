# Match vs request analysis units

The backend analyses either one rule match per model call (`ANALYSIS_UNIT=match`, the default)
or one audited request per call with one verdict per match (`ANALYSIS_UNIT=request`).
`eval/evaluate.py` runs the same comparison offline against `eval/requests.jsonl`.

## How the evaluator treats each unit

- `--unit match`: one call per labeled match, built with the worker's `build_inference_context`.
- `--unit request`: one call per request, built with `build_request_context`. Like the worker,
  it analyses every non-aggregate detection in the request, labeled or not. Anomaly-score
  matches such as 949110 go to the model as `other_matches` and get no verdict. Verdicts for
  unlabeled detections are kept in the recording (`classifications`) but are not scored.
  Recordings made when only labeled matches were analysed still replay; the recording's
  `match_indexes` says what was analysed.
- In both units each labeled match becomes one result row (`<request id>#<match_index>`), so both
  are scored the same way. Tokens are counted per call, so a request-unit call's tokens are
  counted once for its request and never copied onto each match.
- The worker's rules apply in both units: at most one repair, a repair cannot change any
  classification, escalation only for a first pass that was not repaired and has an uncertain
  verdict, and cut-off output is never parsed. Escalation replaces only the verdicts that were
  uncertain on the first pass; the recording keeps the first pass as `initial_raw` so replay
  merges the same way. In the request unit, a missing or extra `match_index` makes the whole
  output invalid.
- `--unit` defaults to `ANALYSIS_UNIT`, else `match`. Old match-level fixtures
  (`eval/fixtures.jsonl`) also run with `--unit request`, each as a one-match request.
- The run fails (exit 1) on any invalid output, on any attack classified false_positive, or
  when attack detection is below `--min-attack-detection` (default 0.5). Recordings and the
  report are still written first.

## Four runs (two models, each in both units)

Run these from the repo root. The scripts use only the standard library. Live runs need CRS
rules (the default is `lab-data/crs-rules`, or pass `--crs-rules-dir`). Any OpenAI-compatible
chat-completions provider works.

The API key comes from the environment. Never put it in a command, a file in the repo, or a recording:

```sh
read -rs LLM_API_KEY && export LLM_API_KEY      # paste the key; nothing is echoed
export LLM_API_BASE_URL=https://provider.example/v1
# Leave LLM_STRUCTURED_OUTPUT unset unless the provider accepts json_schema response formats.
```

Set `SMALL` and `LARGE` to two model IDs your provider lists, and `SMALL_RUN` / `LARGE_RUN` to
the recording names to use (for example `SMALL=deepseek-v4-flash` and `SMALL_RUN=deepseek-flash`
with DeepSeek):

```sh
SMALL=<model id>  SMALL_RUN=<run name>
LARGE=<model id>  LARGE_RUN=<run name>

for unit in match request; do
  LLM_MODEL=$SMALL python3 eval/evaluate.py --fixtures eval/requests.jsonl --unit $unit --record --record-as $SMALL_RUN --output eval/reports/live/${SMALL_RUN}__$unit.json
  LLM_MODEL=$LARGE python3 eval/evaluate.py --fixtures eval/requests.jsonl --unit $unit --record --record-as $LARGE_RUN --output eval/reports/live/${LARGE_RUN}__$unit.json
done
```

You can set `ANALYSIS_UNIT=match` or `ANALYSIS_UNIT=request` instead of `--unit`. If both are
given, `--unit` wins.

Each `--record` writes `eval/recordings/<record-as>__<unit>.jsonl`. Every recording stores the
prompt version and SHA-256 of the unit it used, the public settings (never the key), a
fingerprint of the fixture, and the token usage.

## Replay and compare

Replaying a run makes no provider call:

```sh
python3 eval/evaluate.py --mode recorded --fixtures eval/requests.jsonl --unit request --model $SMALL_RUN --output eval/reports/live/replay.json
```

To build one side-by-side table of the four runs:

```sh
python3 eval/report.py --fixtures eval/requests.jsonl \
  --runs ${SMALL_RUN}__match,${SMALL_RUN}__request,${LARGE_RUN}__match,${LARGE_RUN}__request \
  --output-dir eval/reports/modes
```

`eval/reports/modes/comparison.md` has one column per run. It shows the requests and scored
matches, invalid count, attacks classified false_positive (must be 0), attack detection,
harmless matches correctly cleared, uncertain rate, the estimate of copyable exclusions,
applies_to_stack by expected label, and wrong-stack attack detection. For tokens it shows model
calls, calls per request, and prompt, cached prompt, completion and reasoning tokens as totals
and as averages per request and per scored match.

The copyable-exclusions estimate counts harmless matches classified false_positive that pass
the worker's draft gates that can be computed offline:

- the collection is in `exception_builder.SAFE_TARGET_COLLECTIONS` and a parameter is named;
- the route gate: the fixture's `application_context` route documents that exact target (a
  cookie as `REQUEST_COOKIES:<name>`, a header as `REQUEST_HEADERS:<name>`, an argument by its
  plain name), as with the default `REQUIRE_APPLICATION_CONTEXT=true`;
- the evidence gate: the match's own target was not hidden or trimmed and a matched value
  survived. This is recorded from the exact context sent (`gate_inputs`); older recordings
  lack it, and then it is not applied.

Not modelled: the captured host and method the worker requires, the path, host and method
syntax checks of the rule builder, a missing or chained CRS rule, ruleset changes, conflicts
with true-positive verdicts for the same scope, and rule-ID collisions. The real number can be
lower.

`eval/requests.jsonl` was captured when the seeded profiles listed cookies under plain names.
Until it is regenerated (`eval/capture_lab.py`), its stored route contexts have no
`REQUEST_COOKIES:<name>` entries, so cookie matches never count as copyable and a plain entry
named like a cookie still counts for an argument of that name. Regenerating changes every
fixture digest, so re-record the runs afterwards.

Cached tokens come only from `prompt_tokens_details.cached_tokens`, the OpenAI-compatible field
(DeepSeek, for example, reports it too). Reasoning tokens come from
`completion_tokens_details.reasoning_tokens`.

`--models` and old recording names still work. For example,
`python3 eval/report.py --models oracle,<model>` reads the legacy match-unit files
`oracle.jsonl` and `<model>.jsonl`.
