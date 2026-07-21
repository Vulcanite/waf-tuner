# `lab-data/` — shared lab volume

Mounted into **waf-lab-nginx** and **waf-tuner-backend**.

| File / dir | Purpose |
|------------|---------|
| `.env` | LLM keys (restart backend after edit) |
| `modsec/audit.log` | ModSecurity audit log |
| `waf-tuner.db` | SQLite |
| `events.jsonl` | Event archive |
| `runtime_config.json` | Audit path from UI |
| `crs-rules/` | CRS for rule index |

This app never writes exception conf for you — copy proposed rules into your own WAF.
