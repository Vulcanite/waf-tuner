# Model evaluation

`fixtures.jsonl` is a sanitized release corpus with six benign application-intent cases and thirteen attack cases spanning SQL injection, XSS, command injection, traversal, and path probing.

Run it against the release provider configuration:

```bash
set -a; . lab-data/.env; set +a
python3 eval/evaluate.py --output eval/report.json
```

The dependency-free evaluator sends one case per request, tries one JSON repair when needed, and exits nonzero if any response remains invalid or any attack is classified as a false positive. Attack uncertainty is reported separately; benign accuracy is informational. Do not commit reports containing sensitive provider metadata.
