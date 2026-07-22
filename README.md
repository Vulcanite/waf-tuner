# WAF Tuner

WAF Tuner is a lab-grade, human review queue for ModSecurity CRS alerts. It uses an off-path LLM to classify evidence, then system-builds parameter-scoped exception drafts that an operator may copy into their own WAF configuration.

It is **not** a WAF, an authenticated SaaS, an edge control plane, or production-certified. It never writes edge configuration or reloads a server. Human review and an operator-managed, authenticated TLS reverse proxy are mandatory outside a loopback-only lab.

Version `0.1.x` is for evaluation. Model classifications can be wrong, provider behavior varies, sanitized alert evidence may leave the host, and raw events and model responses remain in local storage until the operator removes them.

[Architecture](./ARCHITECTURE.md) · [Security](./SECURITY.md) · [Integrations](./docs/integrations.md) · [Contributing](./CONTRIBUTING.md) · License: [Apache-2.0](./LICENSE)

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

Sensitive fields are redacted before inference, but sanitized evidence may be sent to the configured provider. Raw audit events and complete provider responses are retained locally until you remove the data. See [SECURITY.md](./SECURITY.md) before using real traffic.

## Verify a change

Backend requires **Python 3.13**.

```bash
cd backend
python3.13 -m venv .venv
.venv/bin/pip install -r requirements.txt pytest
PYTHONPATH=. .venv/bin/python -m pytest -q

cd ../frontend
npm ci
npm run build
```

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
2. Create matching application route profiles before requesting copyable exclusions.
3. Send traffic through the WAF and review Cases and Exceptions.
4. Validate approved rules in your environment, copy them into your configuration, run `nginx -t` or the Apache equivalent, and reload the edge yourself.

## Current boundaries

- One backend process owns each SQLite data directory.
- No multi-version CRS compatibility guarantee.
- No authentication, RBAC, multi-tenancy, or automatic retention service.
- No edge writes, automatic reloads, or deployment state.
- LLM inference is off-path and recommendation-only.
