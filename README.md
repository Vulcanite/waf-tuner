# WAF Tuner

WAF Tuner is a lab-grade, human review queue for ModSecurity CRS alerts. It uses an off-path LLM to classify evidence, then system-builds parameter-scoped exception drafts that an operator may copy into their own WAF configuration.

It is **not** a WAF, an authenticated SaaS, an edge control plane, or production-certified. It never writes edge configuration or reloads a server. Human review and an operator-managed, authenticated TLS reverse proxy are mandatory outside a loopback-only lab.

Version `0.1.x` is for evaluation. Model classifications can be wrong, provider behavior varies, sanitized alert evidence may leave the host, and raw events and model responses remain in local storage until the operator removes them.

[Architecture](./ARCHITECTURE.md) · [Security](./SECURITY.md) · [Integrations](./docs/integrations.md) · [Contributing](./CONTRIBUTING.md) · [Roadmap](./ROADMAP.md) · License: [Apache-2.0](./LICENSE)

Read [the story behind this project](https://amishtp.tech/blog/waf-tuner).

## What it does

- Ingests ModSecurity JSON Serial audit logs off the request path.
- Groups repeated alerts into reviewable cases.
- Classifies evidence as false positive, true positive, or uncertain.
- Builds narrowly scoped SecLang from server-owned evidence—not model-authored rules.
- Leaves every approval and configuration change to a human operator.

## Quick start (loopback lab)

```bash
cp lab-data/.env.example lab-data/.env
# Configure LLM_API_BASE_URL, LLM_API_KEY, and LLM_MODEL.
docker compose up --build
```

Open `http://localhost:3000`. The included DVWA lab is at `http://localhost:8080` (`admin` / `password`). Generate sample CRS traffic with:

```bash
./scripts/run_incident_matrix.sh
```

Compose publishes the UI, API, and lab WAF only on `127.0.0.1`. For remote access, put the UI behind an authenticated TLS reverse proxy and keep the backend private. WAF Tuner has no built-in authentication in v0.1.

## Local data and egress

| Path | Purpose |
|---|---|
| `lab-data/.env` | Provider credentials and runtime settings |
| `lab-data/modsec/audit.log` | ModSecurity audit log |
| `lab-data/waf-tuner.db` | SQLite workflow, audit, and inference data |
| `lab-data/events.jsonl` | Local event archive |
| `lab-data/runtime_config.json` | Selected audit-log path |
| `lab-data/crs-rules/` | CRS index used by the UI |

The backend sends bounded, match-specific evidence to the configured provider. Raw events stay in the local workspace. Optional age limits use `AUDIT_EVIDENCE_RETENTION_DAYS` and `INFERENCE_ARTIFACT_RETENTION_DAYS`. To bound the JSONL mirror, set `EVENTS_JSONL_MAX_BYTES`. See [SECURITY.md](./SECURITY.md) before using real traffic.

## Verify a change

Backend requires **Python 3.13**.

```bash
cd backend
python3.13 -m venv .venv
.venv/bin/pip install -r requirements.txt pytest
PYTHONPATH=. .venv/bin/python -m pytest -q

# Recorded eval (no API key), from the repo root
cd ..
PYTHONPATH=eval backend/.venv/bin/python -m pytest -q eval/tests
python3.13 eval/evaluate.py --mode recorded --model oracle --output eval/reports/oracle.json

cd frontend
npm ci
npm run build
```

The eval corpus has 280 cases: the original 19 hand-built fixtures plus 261 synthesized ones. Application profiles follow the route, not the label, and include attacks on profiled routes. The `oracle` recording is derived from the fixture labels, so the recorded eval in CI tests the harness and scoring, not model quality. The only real model run committed so far covers the original 19 fixtures. See [eval/README.md](./eval/README.md).

Lab checks are intentionally outside normal pull-request CI:

```bash
# Docker Compose lab (backend + frontend + ModSecurity + DVWA)
./scripts/e2e.sh

# Bare metal (host Python 3.13; no Docker). Synthetic audit inject by default.
# Uses :18000 so it can run alongside Compose on :8000.
./scripts/e2e_baremetal.sh
# Optional UI:  BAREMETAL_WITH_FRONTEND=1 ./scripts/e2e_baremetal.sh
# Real audit log: BAREMETAL_AUDIT_LOG=/var/log/modsec/audit.log ./scripts/e2e_baremetal.sh
```

## Operator workflow

1. Point the backend at a ModSecurity JSON Serial audit log.
2. Create an application profile for the host, route, and parameters you want to tune. Copyable false-positive exclusions require parameter semantics on the matching route by default. The seeded `default-lab` profile describes DVWA routes. Set `SEED_DEFAULT_PROFILE=false` when starting with your own profile.
3. Send traffic through the WAF and review Cases and Exceptions.
4. Validate approved rules in your environment, copy them into your configuration, run `nginx -t` or the Apache equivalent, and reload the edge yourself.

The lab publishes a versioned copy of the CRS rules for the analyzer. For a bare-metal setup, point `CRS_RULES_DIR` at the rules used by your WAF and restart the backend after updating them. The analysis health endpoint reports the loaded ruleset digest and availability.

Chained detections receive a verdict and stay in manual review for rule tuning. ModSecurity applies target exclusions to the first rule in a chain.

Run `bash scripts/e2e_fp_suppression.sh` to verify the generated host, method, path, and parameter scope in an isolated ModSecurity container. See [Model evaluation](./eval/README.md) for testing classification against labeled audit events and comparing reasoning settings.

## Current boundaries

- One backend process owns each SQLite data directory.
- No multi-version CRS compatibility guarantee.
- No authentication, RBAC, multi-tenancy, or automatic retention service.
- No edge writes, automatic reloads, or deployment state.
- LLM inference is off-path and recommendation-only.
