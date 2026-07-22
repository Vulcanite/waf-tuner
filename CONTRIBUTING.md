# Contributing

WAF Tuner v0.1 is an observe-and-recommend lab. Contributions must preserve these trust boundaries:

- Never put inference on the HTTP request path.
- Never write, reload, or claim to deploy edge configuration.
- Never treat model-authored SecLang as trusted output. Use `exception_builder` and structural `rule_validator` with case-owned scope.
- Never expose the unauthenticated API as a public-network default.

## Local verification

Use **Python 3.13** for the backend (matches CI and the backend image).

Run the complete backend suite; naming a single historical test module can accidentally omit new coverage:

```bash
cd backend
python3.13 -m venv .venv
.venv/bin/pip install -r requirements.txt pytest
PYTHONPATH=. .venv/bin/python -m pytest -q
```

Run the frontend lockfile build:

```bash
cd frontend
npm ci
npm run build
```

Run fixture-only model evaluation without live traffic using the evaluator documented in `eval/README.md`. Live provider evaluation and lab stacks are release checks, not normal PR CI.

```bash
# Docker lab (ModSecurity + DVWA + UI)
./scripts/e2e.sh

# Host-only lab (no Docker; synthetic audit log)
./scripts/e2e_baremetal.sh
```

## Change requirements

- Parser or response-contract changes need plain, fenced, prefixed, truncated, invalid, repair-success, and repair-failure tests.
- Builder or validator changes need tests proving parameter scope, rule-ID safety, and no edge writes.
- Classification-policy or prompt changes require a fresh evaluation report with prompt hash, model settings, classifications, validity, latency, and token usage.
- Persistence changes use the existing idempotent SQLite migration pattern and require upgrade tests.
- UI changes must remain legible in light and dark themes at 1440×900.

Keep pull requests focused. Do not add auto-deployment, model-authored SecLang, public-by-default listeners, or silent fallbacks that weaken a configured provider contract.
