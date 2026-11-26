# Match vs request analysis units

The backend analyses either one rule match per model call (`ANALYSIS_UNIT=match`, the default)
or one audited request per call with one verdict per match (`ANALYSIS_UNIT=request`).
`eval/evaluate.py` runs the same comparison offline against `eval/requests.jsonl`.

## How the evaluator treats each unit

- `--unit match`: one call per labeled match, built with the worker's `build_inference_context`.
- `--unit request`: one call per request, built with `build_request_context`. Only the labeled
  matches are analysed. The rest, including the 949110 anomaly-score match, go to the model as
  `other_matches` and get no verdict.
- In both units each labeled match becomes one result row (`<request id>#<match_index>`), so both
  are scored the same way. Tokens are counted per call, so a request-unit call's tokens are
  counted once for its request and never copied onto each match.
- The worker's rules apply in both units: at most one repair, a repair cannot change any
  classification, escalation only for a first pass that was not repaired and has an uncertain
  verdict, and cut-off output is never parsed. In the request unit, a missing or extra
  `match_index` makes the whole output invalid.
- `--unit` defaults to `ANALYSIS_UNIT`, else `match`. Old match-level fixtures
  (`eval/fixtures.jsonl`) also run with `--unit request`, each as a one-match request.
- The run fails (exit 1) on any invalid output, on any attack classified false_positive, or
  when attack detection is below `--min-attack-detection` (default 0.5). Recordings and the
  report are still written first.

## The four runs (Flash and Pro, each in both units)

Run these from the repo root. The scripts use only the standard library. Live runs need CRS
rules (the default is `lab-data/crs-rules`, or pass `--crs-rules-dir`).

The API key comes from the environment. Never put it in a command, a file in the repo, or a recording:

```sh
read -rs LLM_API_KEY && export LLM_API_KEY      # paste the key; nothing is echoed
export LLM_API_BASE_URL=https://api.deepseek.com/v1
# Leave LLM_STRUCTURED_OUTPUT unset unless the provider accepts json_schema response formats.
```

Set `FLASH` and `PRO` to the model IDs your provider lists:

```sh
FLASH=deepseek-v4-flash
PRO=deepseek-v4-pro

LLM_MODEL=$FLASH python3 eval/evaluate.py --fixtures eval/requests.jsonl --unit match   --record --record-as deepseek-flash --output eval/reports/live/deepseek-flash__match.json
LLM_MODEL=$FLASH python3 eval/evaluate.py --fixtures eval/requests.jsonl --unit request --record --record-as deepseek-flash --output eval/reports/live/deepseek-flash__request.json
LLM_MODEL=$PRO   python3 eval/evaluate.py --fixtures eval/requests.jsonl --unit match   --record --record-as deepseek-pro   --output eval/reports/live/deepseek-pro__match.json
LLM_MODEL=$PRO   python3 eval/evaluate.py --fixtures eval/requests.jsonl --unit request --record --record-as deepseek-pro   --output eval/reports/live/deepseek-pro__request.json
```

You can set `ANALYSIS_UNIT=match` or `ANALYSIS_UNIT=request` instead of `--unit`. If both are
given, `--unit` wins.

Each `--record` writes `eval/recordings/<record-as>__<unit>.jsonl`. Every recording stores the
prompt version and SHA-256 of the unit it used, the public settings (never the key), a
fingerprint of the fixture, and the token usage.

## Replay and compare

Replaying a run makes no provider call:

```sh
python3 eval/evaluate.py --mode recorded --fixtures eval/requests.jsonl --unit request --model deepseek-flash --output eval/reports/live/replay.json
```

To build one side-by-side table of the four runs:

```sh
python3 eval/report.py --fixtures eval/requests.jsonl \
  --runs deepseek-flash__match,deepseek-flash__request,deepseek-pro__match,deepseek-pro__request \
  --output-dir eval/reports/modes
```

`eval/reports/modes/comparison.md` has one column per run. It shows the requests and scored
matches, invalid count, attacks classified false_positive (must be 0), attack detection,
harmless matches correctly cleared, uncertain rate, the estimate of copyable exclusions,
applies_to_stack by expected label, and wrong-stack attack detection. For tokens it shows model
calls, calls per request, and prompt, cached prompt, completion and reasoning tokens as totals
and as averages per request and per scored match.

The copyable-exclusions estimate counts harmless matches classified false_positive whose
collection is in `exception_builder.SAFE_TARGET_COLLECTIONS` and that name a parameter. The
path, host and method checks need the live alert, so the real number can be lower. Cached
tokens come from `prompt_tokens_details.cached_tokens`, or from DeepSeek's
`prompt_cache_hit_tokens` when that field is missing. Reasoning tokens come from
`completion_tokens_details.reasoning_tokens`.

`--models` and old recording names still work. For example,
`python3 eval/report.py --models oracle,MiniMax-M3` reads the legacy match-unit files
`oracle.jsonl` and `MiniMax-M3.jsonl`.
