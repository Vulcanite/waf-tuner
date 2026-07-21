# Architecture

WAF Tuner is an **observe-and-recommend** control plane for ModSecurity + OWASP CRS.

```
Traffic → Nginx/Apache + ModSecurity + CRS
 │ JSON Serial audit log
 ▼
 waf-tuner-backend
 ├── log tailer → events.jsonl + SQLite cases
 ├── redaction + LLM classify (off-path workers)
 ├── exception_builder + structural rule_validator
 └── REST API
 ▼
 waf-tuner-frontend
 └── human review → Copy SecRule (operator deploys externally)
```

## Principles

1. **Off-path** — inference never sits in the request path.
2. **No edge writes** — never patches conf or reloads proxies.
3. **System-built exclusions** — LLM classifies; SecLang is built server-side.
4. **Human gated** — review + copy-paste; no auto-mitigation.

## Data stores

| Store | Role |
|-------|------|
| Audit log file | Source of truth for ModSecurity hits |
| `events.jsonl` | Append-only archive of parsed transactions |
| SQLite (`waf-tuner.db`) | Cases, revisions, drafts, application profiles |
| `runtime_config.json` | Operator-set audit log path |

## Lab topology

Compose runs nginx (WAF) → DVWA, plus backend/frontend sharing `./lab-data`.

## Out of scope (future)

Managed deploy, engine mode switching, Docker-socket reload.
