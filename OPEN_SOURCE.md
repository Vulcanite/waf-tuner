# Open source notes

WAF Tuner is an evaluation / lab-grade **observe-and-recommend** co-pilot for ModSecurity CRS tuning.

## Trust boundaries

- LLM never runs on the request path.
- Exclusions are system-built; operators copy them out.
- No authentication on the lab API/UI — do not expose publicly without auth.

## Lab vs production-adjacent

| | Lab compose | Production-adjacent |
|--|-------------|---------------------|
| Edge | Included nginx + DVWA | Your existing ModSecurity |
| Data | `./lab-data` | Your paths / volume mounts |
| Deploy | N/A | You apply SecRules |

## Repository layout

| Path | Role |
|------|------|
| `backend/` | waf-tuner-backend |
| `frontend/` | waf-tuner-frontend |
| `nginx/` | Lab WAF image hooks |
| `lab-data/` | Shared logs, SQLite, `.env` |
| `scripts/` | DVWA traffic + E2E |
| `docs/` | Integrations |

## Support bar

Compose lab + unit tests. No multi-version CRS LTS guarantee yet.
