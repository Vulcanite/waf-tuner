# Model evaluation

`fixtures.jsonl` is the labeled release corpus. Each record has the original classifier context plus `label` (`attack` or `false_positive`) and `crs_rule_ids`.

## Recorded eval (CI, no API key)

```bash
python3 eval/evaluate.py --mode recorded --model oracle --output eval/reports/oracle.json
python3 eval/report.py --models oracle,MiniMax-M3 --output-dir eval/reports
PYTHONPATH=eval python3 -m pytest -q eval/tests
```

Recordings live in `eval/recordings/<model>.jsonl`. The `oracle` file is derived from fixture labels so CI can exercise the harness without a provider. `MiniMax-M3.jsonl` is the historical v0.1.0 run (original 19 fixtures only). Do not point recorded mode at a live `LLM_API_KEY`.

## Expand the corpus

```bash
# Synthesize fixtures from eval/corpus.py (no Docker).
python3 eval/generate_fixtures.py

# Optional: drive the Compose lab, crawl DVWA, replay CRS-category requests,
# and overlay observed ModSecurity rule IDs. Falls back to synthesis if the
# lab is unreachable. go-ftw is used when installed (`go install github.com/coreruleset/go-ftw@latest`).
python3 eval/capture_lab.py --compose
# Force synthesis:
python3 eval/capture_lab.py --synthesize

python3 eval/generate_recordings.py
```

The request set is `eval/corpus/requests.jsonl`. Attack requests are grouped by CRS category (SQLi 942xxx, XSS 941xxx, RCE 932xxx, LFI 930xxx, RFI 931xxx, protocol 920xxx) with cited rule IDs.

## Live provider eval

```bash
set -a; . lab-data/.env; set +a
python3 eval/evaluate.py --output eval/report.json --record
```

`--record` writes `eval/recordings/<LLM_MODEL>.jsonl`. The dependency-free evaluator sends one case per request, tries one JSON repair when needed, and exits nonzero if any response remains invalid or any attack is classified as a false positive. Attack uncertainty is reported separately; benign accuracy is informational. Do not commit reports containing sensitive provider metadata.
