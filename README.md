# WAF Tuner

**Off-path CRS tuning for open-source ModSecurity.**

Ingest JSON audit logs, classify false positives vs attacks with an LLM, and **system-build** tightly scoped exclusion SecRules for a human to **copy into their own WAF config**.

This application **never** writes Nginx/Apache configuration or reloads the edge.

[Architecture](./ARCHITECTURE.md) · [Integrations](./docs/integrations.md) · License: [Apache-2.0](./LICENSE)

---

## Why

- Which **payload** hit which **CRS signature**?
- Is it a **false positive** or a real probe?
- What is a **safe**, parameter-scoped exception?

Human review queue — not silent auto-disable.

## Quick start (lab)

```bash
cp lab-data/.env.example lab-data/.env
# Edit LLM_API_BASE_URL / LLM_API_KEY / LLM_MODEL

docker compose up --build

# UI
open http://localhost:3000

# DVWA behind ModSecurity
open http://localhost:8080 # admin / password

# Generate CRS traffic
./scripts/run_incident_matrix.sh
```

| Service | Container | Port |
|---------|-----------|------|
| **waf-tuner-frontend** | `waf-tuner-frontend` | 3000 |
| **waf-tuner-backend** | `waf-tuner-backend` | 8000 |
| **nginx** (ModSecurity + CRS) | `waf-lab-nginx` | 8080 |
| **dvwa** | `waf-lab-dvwa` | internal |

### Shared data: `./lab-data`

| Path | Purpose |
|------|---------|
| `.env` | LLM keys — edit, then `docker compose up -d waf-tuner-backend` |
| `modsec/audit.log` | ModSecurity JSON Serial audit log |
| `waf-tuner.db` | SQLite workflow DB |
| `events.jsonl` | Event archive |
| `runtime_config.json` | Audit log path from the UI |
| `crs-rules/` | CRS index for the UI |

### Unit tests

```bash
cd backend
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest
PYTHONPATH=. .venv/bin/python -m pytest tests/test_core.py -q
```

### E2E (saves under `e2e-output/`)

```bash
./scripts/e2e.sh
```

## Operator flow

1. Point backend at a ModSecurity **JSON Serial** audit log (lab default or Settings).
2. Optionally add **Application Context**.
3. Send traffic through your WAF (lab: DVWA on `:8080`).
4. Review **Cases** / **Exceptions** — copy SecRules into your own conf, `nginx -t` / Apache configtest, reload yourself.

## Design rules

| Piece | Behavior |
|-------|----------|
| Classification | LLM (off-path) |
| Exception SecRule | **Deterministic builder** from ground-truth zone |
| Validation | Structure allowlist only |
| Edge config | **Never** written by this app |

## Environment

See `lab-data/.env.example` and [docs/integrations.md](./docs/integrations.md).

## Non-goals (current)

- Edge deploy / auto-reload (future)
- Auth, multi-tenant SaaS
- Cloud WAF products
- Coraza (later)

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).
