#!/usr/bin/env bash
# Bare-metal lab / E2E — no Docker required for the app stack.
#
# What this verifies:
#   1. Python 3.13 unit tests + exception builder
#   2. Backend starts on the host (uvicorn) against host paths under a temp data dir
#   3. Synthetic ModSecurity JSON audit events are ingested (no live WAF needed)
#   4. Health / product / analytics / events / cases API surface
#   5. Optional: frontend Vite preview on :3000 if Node 22+ is available
#   6. Optional: if BAREMETAL_AUDIT_LOG points at a real audit log, skip synthetic inject
#
# Usage:
#   ./scripts/e2e_baremetal.sh
#   BAREMETAL_WITH_FRONTEND=1 ./scripts/e2e_baremetal.sh
#   BAREMETAL_AUDIT_LOG=/var/log/modsec/audit.log ./scripts/e2e_baremetal.sh
#
# Requires: python3.13, curl. Optional: node/npm for UI, real ModSecurity log path.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$ROOT/e2e-output/baremetal-$STAMP"
DATA="$OUT/data"
mkdir -p "$OUT" "$DATA/modsec" "$DATA/crs-rules" "$DATA/exceptions"
SUMMARY="$OUT/SUMMARY.md"
LOG="$OUT/run.log"
PID_FILE="$OUT/pids.txt"
: >"$PID_FILE"

exec > >(tee -a "$LOG") 2>&1

pass=0
fail=0
note() { echo ""; echo "=== $* ==="; }
ok() { echo "OK: $*"; pass=$((pass + 1)); }
bad() { echo "FAIL: $*"; fail=$((fail + 1)); }

cleanup() {
  if [[ -f "$PID_FILE" ]]; then
    while read -r pid; do
      [[ -n "${pid:-}" ]] || continue
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    done <"$PID_FILE"
  fi
}
trap cleanup EXIT INT TERM

API_HOST="${BAREMETAL_API_HOST:-127.0.0.1}"
API_PORT="${BAREMETAL_API_PORT:-18000}"
API_BASE="http://${API_HOST}:${API_PORT}"

note "WAF Tuner bare-metal E2E @ $STAMP"
echo "output: $OUT"
echo "data:   $DATA"
echo "api:    $API_BASE (override with BAREMETAL_API_PORT; default 18000 avoids Docker :8000)"

# --- toolchain ---
note "Toolchain"
if command -v python3.13 >/dev/null; then
  PY=python3.13
elif python3 -c 'import sys; raise SystemExit(0 if sys.version_info[:2]==(3,13) else 1)' 2>/dev/null; then
  PY=python3
else
  bad "Python 3.13 required (found: $(python3 --version 2>&1 || true))"
  echo "Install Python 3.13 and re-run."
  exit 1
fi
ok "interpreter $PY ($($PY --version 2>&1))"

if ! command -v curl >/dev/null; then
  bad "curl is required"
  exit 1
fi
ok "curl"

# --- data + env ---
note "Prepare isolated data dir"
touch "$DATA/modsec/audit.log"
touch "$DATA/events.jsonl"
if [[ -d lab-data/crs-rules ]] && [[ -n "$(ls -A lab-data/crs-rules 2>/dev/null || true)" ]]; then
  cp -a lab-data/crs-rules/. "$DATA/crs-rules/" 2>/dev/null || true
  ok "copied lab-data/crs-rules"
else
  ok "empty CRS index dir (optional)"
fi

# Host-side env: prefer lab-data/.env secrets, override paths for isolated DATA
ENV_FILE="$OUT/baremetal.env"
if [[ -f lab-data/.env ]]; then
  # shellcheck disable=SC1091
  set -a
  # shellcheck disable=SC1091
  source lab-data/.env
  set +a
  ok "loaded secrets from lab-data/.env"
elif [[ -f lab-data/.env.example ]]; then
  set -a
  # shellcheck disable=SC1091
  source lab-data/.env.example
  set +a
  ok "loaded lab-data/.env.example (no lab-data/.env)"
else
  ok "no lab-data env; using script defaults"
fi

export MODSEC_AUDIT_LOG="${BAREMETAL_AUDIT_LOG:-$DATA/modsec/audit.log}"
export EVENTS_JSONL_PATH="$DATA/events.jsonl"
export AUDIT_CURSOR_PATH="$DATA/audit_cursor.json"
export DATABASE_PATH="$DATA/waf-tuner.db"
export RUNTIME_CONFIG_PATH="$DATA/runtime_config.json"
export CRS_RULES_DIR="${CRS_RULES_DIR:-$DATA/crs-rules/}"
export RULE_VALIDATION_MODE="${RULE_VALIDATION_MODE:-skip}"
export AGENT_WORKER_CONCURRENCY="${AGENT_WORKER_CONCURRENCY:-2}"
export AGENT_MAX_REQUESTS_PER_HOUR="${AGENT_MAX_REQUESTS_PER_HOUR:-60}"
export INCIDENT_FINGERPRINT_KEY="${INCIDENT_FINGERPRINT_KEY:-baremetal-lab-fingerprint-key}"
export CORS_ALLOW_ORIGINS="${CORS_ALLOW_ORIGINS:-http://127.0.0.1:5173,http://localhost:5173,http://127.0.0.1:3000,http://localhost:3000}"
export LLM_API_BASE_URL="${LLM_API_BASE_URL:-http://127.0.0.1:9/v1}"
export LLM_API_KEY="${LLM_API_KEY:-local}"
export LLM_MODEL="${LLM_MODEL:-baremetal-placeholder}"

# Persist resolved env for debugging
{
  echo "MODSEC_AUDIT_LOG=$MODSEC_AUDIT_LOG"
  echo "EVENTS_JSONL_PATH=$EVENTS_JSONL_PATH"
  echo "DATABASE_PATH=$DATABASE_PATH"
  echo "CRS_RULES_DIR=$CRS_RULES_DIR"
  echo "LLM_API_BASE_URL=$LLM_API_BASE_URL"
  echo "LLM_MODEL=$LLM_MODEL"
  echo "CORS_ALLOW_ORIGINS=$CORS_ALLOW_ORIGINS"
} >"$ENV_FILE"
ok "host paths written to $ENV_FILE"

# --- unit tests ---
note "Unit tests (host venv)"
VENV="$OUT/.venv"
if [[ ! -x "$VENV/bin/python" ]]; then
  "$PY" -m venv "$VENV"
  "$VENV/bin/pip" install -q -U pip
  "$VENV/bin/pip" install -q -r backend/requirements.txt pytest
fi
if (cd backend && PYTHONPATH=. "$VENV/bin/python" -m pytest -q --tb=line >"$OUT/unit-tests.txt" 2>&1); then
  ok "unit tests"
  tail -3 "$OUT/unit-tests.txt"
else
  bad "unit tests"
  tail -40 "$OUT/unit-tests.txt"
fi

# --- builder smoke ---
note "Exception builder"
if RULE=$(cd backend && PYTHONPATH=. "$VENV/bin/python" - <<'PY'
from services.exception_builder import build_exception_rule
scope = {"uri": "/vulnerabilities/sqli", "collection": "ARGS", "parameter": "id", "rule_id": "942100"}
print(build_exception_rule(scope))
PY
); then
  echo "$RULE" | tee "$OUT/sample-exclusion.secrule"
  if echo "$RULE" | grep -q 'REQUEST_FILENAME' && echo "$RULE" | grep -q 'ARGS:id'; then
    ok "builder"
  else
    bad "builder shape"
  fi
else
  bad "builder failed"
fi

# --- start backend ---
note "Start backend (uvicorn ${API_HOST}:${API_PORT})"
if curl -sf "${API_BASE}/health" >/dev/null 2>&1; then
  bad "port ${API_PORT} already serves /health — set BAREMETAL_API_PORT to a free port"
  exit 1
fi

BACKEND_LOG="$OUT/backend.log"
(
  cd backend
  # Process env wins over dotenv for paths; load LLM secrets via shell env only.
  exec env \
    MODSEC_AUDIT_LOG="$MODSEC_AUDIT_LOG" \
    EVENTS_JSONL_PATH="$EVENTS_JSONL_PATH" \
    AUDIT_CURSOR_PATH="$AUDIT_CURSOR_PATH" \
    DATABASE_PATH="$DATABASE_PATH" \
    RUNTIME_CONFIG_PATH="$RUNTIME_CONFIG_PATH" \
    CRS_RULES_DIR="$CRS_RULES_DIR" \
    RULE_VALIDATION_MODE="$RULE_VALIDATION_MODE" \
    AGENT_WORKER_CONCURRENCY="$AGENT_WORKER_CONCURRENCY" \
    AGENT_MAX_REQUESTS_PER_HOUR="$AGENT_MAX_REQUESTS_PER_HOUR" \
    INCIDENT_FINGERPRINT_KEY="$INCIDENT_FINGERPRINT_KEY" \
    CORS_ALLOW_ORIGINS="$CORS_ALLOW_ORIGINS" \
    LLM_API_BASE_URL="$LLM_API_BASE_URL" \
    LLM_API_KEY="$LLM_API_KEY" \
    LLM_MODEL="$LLM_MODEL" \
    "$VENV/bin/uvicorn" main:app --host "$API_HOST" --port "$API_PORT" --log-level info
) >"$BACKEND_LOG" 2>&1 &
BACKEND_PID=$!
echo "$BACKEND_PID" >>"$PID_FILE"
ok "backend pid $BACKEND_PID"

note "Wait for backend health"
healthy=0
for i in $(seq 1 60); do
  if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
    bad "backend process exited early"
    tail -50 "$BACKEND_LOG" || true
    break
  fi
  if curl -sf "${API_BASE}/health" >/dev/null 2>&1; then
    ok "backend healthy (attempt $i)"
    healthy=1
    break
  fi
  sleep 1
done
if [[ "$healthy" -ne 1 ]]; then
  bad "backend health timeout"
  tail -50 "$BACKEND_LOG" || true
fi

curl -sS "${API_BASE}/health" | tee "$OUT/health.json" || true
curl -sS "${API_BASE}/api/settings/product" | tee "$OUT/settings-product.json" || true
curl -sS "${API_BASE}/api/analytics/analysis-health" | tee "$OUT/analysis-health.json" || true

if "$VENV/bin/python" -c "import json; d=json.load(open('$OUT/health.json')); assert d.get('status')=='ok'; assert d.get('deploy_enabled') is False"; then
  ok "health status=ok deploy_enabled=false"
else
  bad "health check failed"
fi

# Refuse to continue if we accidentally hit another stack (e.g. Docker on :8000)
if "$VENV/bin/python" -c "
import json
p=json.load(open('$OUT/settings-product.json'))
env=p.get('env') or {}
db=env.get('DATABASE_PATH') or ''
events=env.get('EVENTS_JSONL_PATH') or ''
assert db == '$DATABASE_PATH', (db, '$DATABASE_PATH')
assert events == '$EVENTS_JSONL_PATH', (events, '$EVENTS_JSONL_PATH')
print('db', db)
"; then
  ok "product env points at isolated bare-metal data dir"
else
  bad "backend is not using isolated DATA paths (wrong process or env leak)"
  tail -30 "$BACKEND_LOG" || true
fi

# Point ingest at our audit log via API (mirrors Settings UI)
note "Configure ingest path"
INGEST_JSON=$("$VENV/bin/python" -c "import json; print(json.dumps({'modsec_audit_log': '''$MODSEC_AUDIT_LOG'''}))")
if curl -sf -X PUT "${API_BASE}/api/settings/ingest" \
  -H 'Content-Type: application/json' \
  -d "$INGEST_JSON" \
  | tee "$OUT/ingest-set.json" >/dev/null; then
  ok "PUT /api/settings/ingest"
else
  bad "PUT /api/settings/ingest"
  cat "$OUT/ingest-set.json" 2>/dev/null || true
fi

# --- inject or use real audit log ---
note "Audit log ingest"
AUDIT_BEFORE=$(wc -c <"$MODSEC_AUDIT_LOG" | tr -d ' ' || echo 0)
USE_SYNTHETIC=1
if [[ -n "${BAREMETAL_AUDIT_LOG:-}" ]]; then
  USE_SYNTHETIC=0
  ok "using external audit log BAREMETAL_AUDIT_LOG=$BAREMETAL_AUDIT_LOG (no synthetic inject)"
fi

if [[ "$USE_SYNTHETIC" -eq 1 ]]; then
  FIXTURE="$ROOT/scripts/fixtures/sample_modsec_audit.jsonl"
  if [[ ! -f "$FIXTURE" ]]; then
    bad "missing fixture $FIXTURE"
  else
    # Unique transaction ids per run so re-runs don't collide with prior DB
    RUN_TAG="${STAMP//[^0-9A-Za-z]/}"
    "$VENV/bin/python" - "$FIXTURE" "$MODSEC_AUDIT_LOG" "$RUN_TAG" <<'PY'
import json, sys, time
from pathlib import Path
src, dest, tag = sys.argv[1], sys.argv[2], sys.argv[3]
lines = Path(src).read_text(encoding="utf-8").splitlines()
with open(dest, "a", encoding="utf-8") as out:
    for i, line in enumerate(lines):
        if not line.strip():
            continue
        obj = json.loads(line)
        txn = obj.setdefault("transaction", {})
        base = txn.get("unique_id") or txn.get("id") or f"txn-{i}"
        txn["unique_id"] = f"{base}-{tag}"
        txn["id"] = txn["unique_id"]
        txn["time"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        out.write(json.dumps(obj, ensure_ascii=False) + "\n")
print(f"appended {len([l for l in lines if l.strip()])} audit objects")
PY
    ok "appended synthetic ModSecurity JSON to audit log"
  fi
fi

# Wait for tailer to pick up events
EVENTS_OK=0
for i in $(seq 1 40); do
  curl -sS "${API_BASE}/api/events?limit=5" >"$OUT/events-sample.json" || true
  if "$VENV/bin/python" -c "
import json
d=json.load(open('$OUT/events-sample.json'))
if isinstance(d, dict):
  total=d.get('total')
  if total is None:
    total=len(d.get('items') or [])
else:
  total=len(d)
assert int(total or 0) >= 1
print('total', total)
"; then
    ok "events ingested (attempt $i)"
    EVENTS_OK=1
    break
  fi
  sleep 1
done
if [[ "$EVENTS_OK" -ne 1 ]]; then
  bad "no events after inject/wait"
  tail -40 "$BACKEND_LOG" || true
fi

AUDIT_AFTER=$(wc -c <"$MODSEC_AUDIT_LOG" | tr -d ' ' || echo 0)
echo "audit.log bytes: before=$AUDIT_BEFORE after=$AUDIT_AFTER" | tee "$OUT/audit-size.txt"
if [[ "$USE_SYNTHETIC" -eq 1 ]]; then
  if [[ "${AUDIT_AFTER:-0}" -gt "${AUDIT_BEFORE:-0}" ]]; then
    ok "audit.log grew"
  else
    bad "audit.log did not grow after synthetic inject"
  fi
fi

# --- API surface ---
note "API surface"
curl -sS "${API_BASE}/api/analytics/summary" | tee "$OUT/analytics-summary.json" || true
curl -sS "${API_BASE}/api/cases?limit=5" | tee "$OUT/cases-sample.json" || true
curl -sS "${API_BASE}/api/settings/ingest" | tee "$OUT/ingest.json" || true

if "$VENV/bin/python" -c "
import json
s=json.load(open('$OUT/analytics-summary.json'))
assert 'total_events' in s
assert int(s.get('total_events') or 0) >= 1
# Synthetic fixture has 2 transactions; keep assertion loose for external logs
print('events', s.get('total_events'))
"; then
  ok "analytics summary has events"
else
  bad "analytics summary"
fi

if "$VENV/bin/python" -c "
import json
c=json.load(open('$OUT/cases-sample.json'))
items=c.get('items') or []
assert len(items) >= 1
print('cases', c.get('total', len(items)))
"; then
  ok "cases present"
else
  bad "cases missing"
fi

# Deploy API must not exist
code=$(curl -s -o /dev/null -w "%{http_code}" "${API_BASE}/api/deploy/pending" || echo err)
if [[ "$code" == "404" || "$code" == "405" ]]; then
  ok "deploy API absent ($code)"
else
  bad "deploy endpoint still reachable (HTTP $code)"
fi

# SQLite exists under isolated data dir
if [[ -f "$DATABASE_PATH" ]]; then
  ok "sqlite db at $DATABASE_PATH"
else
  bad "sqlite db missing at $DATABASE_PATH"
fi

if "$VENV/bin/python" -c "
import json
ing=json.load(open('$OUT/ingest.json'))
path=ing.get('modsec_audit_log') or ''
assert path == '$MODSEC_AUDIT_LOG', (path, '$MODSEC_AUDIT_LOG')
print(path)
"; then
  ok "ingest path is isolated audit log"
else
  bad "ingest path does not match bare-metal audit log"
fi

# --- optional frontend ---
note "Frontend (optional)"
if [[ "${BAREMETAL_WITH_FRONTEND:-0}" == "1" ]]; then
  if command -v npm >/dev/null; then
    (
      cd frontend
      if [[ ! -d node_modules ]]; then
        npm ci --no-audit --no-fund
      fi
      # Bake absolute API origin (no nginx /api proxy on bare metal).
      FE_PORT="${BAREMETAL_FE_PORT:-13000}"
      export VITE_API_URL="${VITE_API_URL:-$API_BASE}"
      npm run build
      exec npx vite preview --host 127.0.0.1 --port "$FE_PORT" --strictPort
    ) >"$OUT/frontend.log" 2>&1 &
    echo $! >>"$PID_FILE"
    FE_PORT="${BAREMETAL_FE_PORT:-13000}"
    fe_ok=0
    for i in $(seq 1 30); do
      if curl -sf -o /dev/null "http://127.0.0.1:${FE_PORT}/"; then
        ok "frontend :${FE_PORT}"
        fe_ok=1
        break
      fi
      sleep 1
    done
    [[ "$fe_ok" -eq 1 ]] || bad "frontend :${FE_PORT} not reachable"
  else
    bad "BAREMETAL_WITH_FRONTEND=1 but npm not found"
  fi
else
  ok "frontend skipped (set BAREMETAL_WITH_FRONTEND=1 to enable)"
fi

# --- summary ---
note "Results"
cat >"$SUMMARY" <<EOF
# Bare-metal E2E — $STAMP

| Check | Count |
|-------|-------|
| Passed | $pass |
| Failed | $fail |

## Mode
- App stack: host Python 3.13 + uvicorn (no Docker)
- API: \`$API_BASE\`
- Audit source: $([[ "$USE_SYNTHETIC" -eq 1 ]] && echo "synthetic fixture" || echo "external \$BAREMETAL_AUDIT_LOG")
- Data dir: \`$DATA\`
- Frontend: $([[ "${BAREMETAL_WITH_FRONTEND:-0}" == "1" ]] && echo "enabled" || echo "skipped")

## Artifacts
- \`unit-tests.txt\`, \`backend.log\`, \`health.json\`, \`events-sample.json\`, \`cases-sample.json\`
- \`baremetal.env\` (resolved paths)

## Notes
- Isolated data under e2e-output; does not require Compose, nginx, or DVWA.
- For a real host ModSecurity log: \`BAREMETAL_AUDIT_LOG=/path/to/audit.log ./scripts/e2e_baremetal.sh\`
- LLM calls may fail with placeholder credentials; ingest + cases still prove the lab path.
EOF
cat "$SUMMARY"

echo ""
if [[ "$fail" -gt 0 ]]; then
  echo "BARE-METAL E2E FAILED ($fail failures)"
  exit 1
fi
echo "BARE-METAL E2E PASSED ($pass checks)"
exit 0
