# Open-source support notes

WAF Tuner `0.1.x` is a lab-grade, observe-and-recommend copilot for ModSecurity CRS tuning. It is intended for evaluation and security research, not unattended production control.

## Trust and deployment boundaries

- Inference is off-path and cannot block requests.
- The server builds exclusions from ground-truth scope; operators decide whether to copy them.
- The application does not write WAF configuration, reload the edge, or represent rules as deployed.
- The API and UI have no built-in authentication. Compose binds to loopback. Remote operators must supply an authenticated TLS reverse proxy.
- Sanitized evidence may leave the host for the configured LLM provider. Raw events and provider responses are retained locally until removed by the operator.

## Runtime

- Backend targets **Python 3.13** (CI and `backend/Dockerfile`).

## Supported topology

- One backend process owns each SQLite data directory.
- Up to sixteen bounded inference workers may run inside that process; four is the default.
- No multi-version CRS compatibility guarantee is provided for `0.1.x`.
- No HA database, distributed queue, multi-tenancy, or automated retention service is supported.

## Repository layout

| Path | Role |
|---|---|
| `backend/` | FastAPI API, ingestion, analysis, policy, and SQLite state |
| `frontend/` | React operator portal |
| `nginx/` | Lab WAF image hooks |
| `lab-data/` | Local logs, SQLite database, configuration, and CRS data |
| `scripts/` | Fixture traffic and E2E checks |
| `docs/` | Integration guidance |

Security limitations and disclosure instructions are in [SECURITY.md](./SECURITY.md).
