# Contributing

1. **Off-path only** — never block HTTP on inference.
2. **No edge deploy/reload** in the current product.
3. **No free-form SecLang as truth** — use `exception_builder` + structural `rule_validator`.
4. **Ground-truth scope** from the case (path, collection, parameter, rule id).

## Dev setup

```bash
cd backend
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt pytest
PYTHONPATH=. .venv/bin/python -m pytest tests/test_core.py -q

cd ../frontend
npm install && npm run build
```

## E2E

```bash
./scripts/e2e.sh
# results → e2e-output/
```

## PRs

Prefer small PRs with tests for builder/validator/parser changes.
