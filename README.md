# WAF Exception Agent

A containerized system that sits on top of Nginx + ModSecurity, observes WAF events, runs an LLM agent (Claude) to classify false positives and draft exception rules, and presents them to a human operator for approval and deployment via a web portal.

## Quick Start

```bash
# 1. Copy and edit the environment file
cp .env.example .env
# Edit .env and set your API_KEY (and optionally API_URL / API_MODEL)

# 2. Start all services
docker-compose up --build

# 3. Open the portal
open http://localhost:3000

# 4. Generate traffic (in a separate terminal)
docker-compose --profile traffic run traffic-generator
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| Portal | 3000 | React web portal |
| API Server | 8000 | FastAPI backend |
| Nginx+ModSec | 8080 | WAF reverse proxy |
| Postgres | 5432 | Exception drafts DB |

## Demo Flow

1. `docker-compose up` — all six containers start
2. Open `http://localhost:3000` — Analytics shows zero events
3. Run traffic generator — Locust generates 50 concurrent users for 5 minutes
4. Refresh Analytics — event counts and charts populate
5. Navigate to **Events** — events visible with rule IDs and matched payloads
6. Navigate to **Exceptions → Pending Review** — agent-generated drafts appear
7. Find a false positive (e.g. search query triggering rule 942100)
8. Read the verdict sentence — references parameter, operator (@detectSQLi), paranoia level
9. Click **Approve** → draft moves to Deploy panel
10. Navigate to **Deploy** → click **Deploy selected**
11. `curl "localhost:8080/search?q=select all products"` — no new WAF event generated
12. Navigate to **Exceptions → Deployed** — shows deployed timestamp

## Architecture

```
traffic-generator → nginx (ModSecurity PL2) → target-app
                        ↓ audit.log
                    api-server
                    ├── log_tailer    (modsec → events.jsonl)
                    ├── agent         (events.jsonl → Claude → Postgres)
                    └── stale_checker (marks old deployments stale)
                        ↓ REST API
                    portal (React)
                        ↓ approve/deploy
                    api-server → writes exception_*.conf → nginx reload
```

## Environment Variables

See `.env.example` for all variables. Key settings:

| Variable | Default | Description |
|----------|---------|-------------|
| `API_KEY` | — | API key for your LLM provider (required) |
| `API_URL` | `https://openrouter.ai/api/v1` | OpenAI-compatible base URL |
| `API_MODEL` | `anthropic/claude-sonnet-4-5` | Model identifier passed to the API |

The agent uses the OpenAI SDK pointed at `API_URL`, so any OpenAI-compatible provider works (OpenRouter, OpenAI directly, Ollama, Together AI, etc.).
