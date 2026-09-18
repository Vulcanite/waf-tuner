# Integrations

Attach **waf-tuner-backend** to an existing Nginx or Apache ModSecurity deployment. The app only needs a readable **JSON Serial** audit log.

## What the product does

| Responsibility | App | Operator |
|----------------|-----|----------|
| Read audit log | ✓ | Configure path + format |
| Show events / cases / FP vs TP | ✓ | — |
| Generate exclusion SecRule | ✓ | — |
| Write `.conf` / reload edge | ✗ | Copy-paste + own process |

## Minimum config

```env
MODSEC_AUDIT_LOG=/path/to/audit.log
CRS_RULES_DIR=/path/to/crs/rules # optional
DATABASE_PATH=./data/waf-tuner.db
EVENTS_JSONL_PATH=./data/events.jsonl
```

LLM: `LLM_API_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL` (OpenAI-compatible).

## Audit log contract

```apache
SecAuditEngine On
SecAuditLog /var/log/modsec/audit.log
SecAuditLogFormat JSON
SecAuditLogType Serial
SecAuditLogParts ABCFHIJKZ
# Optional for DetectionOnly FPs on HTTP 200:
# SecAuditLogRelevantStatus ".*"
```

Required JSON: transaction id, request method/uri, `messages[]` with rule ids.

## Docker: shared volume

```
proxy container --write--> audit.log on volume --read--> waf-tuner-backend
```

- Mount the log volume **read-only** into the backend.
- Frontend only needs HTTP to the backend (not the log file).
- No Docker socket required.

### Lab compose

See root `docker-compose.yml` and `lab-data/`. Default path inside backend: `/shared/modsec/audit.log`.

## Bare metal

1. Install backend (+ optional frontend) and ensure SQLite / events paths are writable.
2. Set `MODSEC_AUDIT_LOG` to the host audit file (or use Settings UI).
3. Point `CRS_RULES_DIR` at a CRS rules tree if available.
4. Copy proposed rules into your ModSecurity exceptions include; reload yourself.

### Automated bare-metal lab test

Compose is not required. From the repo root:

```bash
# Unit tests + host uvicorn + synthetic ModSecurity JSON audit inject + API checks
./scripts/e2e_baremetal.sh

# Also build/preview the UI (default :13000)
BAREMETAL_WITH_FRONTEND=1 ./scripts/e2e_baremetal.sh

# Ingest from a real host audit log instead of the fixture
BAREMETAL_AUDIT_LOG=/var/log/modsec/audit.log ./scripts/e2e_baremetal.sh
```

Requires **Python 3.13** and `curl`. Defaults to **API :18000** (and UI :13000) so it can run next to Compose on :8000/:3000. Uses an isolated data directory under `e2e-output/baremetal-*` so it does not clobber the Docker `lab-data/` volume. Results land in that directory’s `SUMMARY.md`.

## Runtime API

| Endpoint | Purpose |
|----------|---------|
| `GET /api/settings/mode` | Product info + contract |
| `GET/PUT /api/settings/ingest` | Audit log path |
| `GET /health` | Liveness |

Changing `lab-data/.env` requires **restarting** the backend container.
