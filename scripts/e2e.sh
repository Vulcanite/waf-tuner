#!/usr/bin/env bash
# end-to-end: unit tests, stack up, health, DVWA traffic, audit log, API checks.
# Results written under e2e-output/<timestamp>/
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$ROOT/e2e-output/$STAMP"
mkdir -p "$OUT"
SUMMARY="$OUT/SUMMARY.md"
LOG="$OUT/run.log"

exec > >(tee -a "$LOG") 2>&1

pass=0
fail=0
note() { echo ""; echo "=== $* ==="; }
ok() { echo "OK: $*"; pass=$((pass + 1)); }
bad() { echo "FAIL: $*"; fail=$((fail + 1)); }

note "WAF Tuner E2E @ $STAMP"
echo "output: $OUT"

# --- 0. prep lab-data ---
note "Prepare lab-data"
mkdir -p lab-data/modsec lab-data/crs-rules lab-data/exceptions
touch lab-data/modsec/audit.log
if [[ ! -f lab-data/.env ]]; then
 cp lab-data/.env.example lab-data/.env
 echo "created lab-data/.env from example"
fi
ok "lab-data ready"

if ! command -v docker >/dev/null; then
 bad "docker not available — full E2E requires Compose"
 exit 1
fi

# --- 1. unit tests ---
note "Unit tests"
docker compose build waf-tuner-backend > "$OUT/backend-test-image.log" 2>&1
if docker compose run --rm --no-deps \
  -v "$ROOT/backend:/app" waf-tuner-backend \
  sh -lc 'pip install -q pytest && PYTHONPATH=. pytest -q --tb=line' \
  > "$OUT/unit-tests.txt" 2>&1; then
 ok "unit tests"
 tail -5 "$OUT/unit-tests.txt"
else
 bad "unit tests"
 cat "$OUT/unit-tests.txt" | tail -40
fi

# --- 2. builder smoke ---
note "Exception builder (DVWA SQLi scope)"
if RULE=$(docker compose run --rm --no-deps -T \
  -v "$ROOT/backend:/app" waf-tuner-backend python - <<'PY'
from services.exception_builder import build_exception_rule
scope = {"uri": "/vulnerabilities/sqli", "collection": "ARGS", "parameter": "id", "rule_id": "942100"}
print(build_exception_rule(scope))
PY
); then
 echo "$RULE" | tee "$OUT/sample-exclusion.secrule"
 echo "$RULE" | grep -q 'REQUEST_FILENAME' && echo "$RULE" | grep -q 'ARGS:id' && ok "builder" || bad "builder shape"
else
 bad "builder failed"
fi

# --- 3. docker compose ---
note "Docker compose up"

AUDIT_BEFORE=$(wc -c < lab-data/modsec/audit.log | tr -d ' ')

docker compose build > "$OUT/compose-build.log" 2>&1 || { bad "compose build"; tail -30 "$OUT/compose-build.log"; }
docker compose up -d > "$OUT/compose-up.log" 2>&1 || { bad "compose up"; tail -30 "$OUT/compose-up.log"; }
docker compose config --format json > "$OUT/compose-config.json"
if python3 -c "
import json
d=json.load(open('$OUT/compose-config.json'))
published=[p for service in d['services'].values() for p in service.get('ports', [])]
assert published and all(p.get('host_ip') == '127.0.0.1' for p in published), published
"; then
 ok "all published ports bind to loopback"
else
 bad "one or more published ports are not loopback-only"
fi

note "Wait for health"
for i in $(seq 1 60); do
 if curl -sf http://localhost:8000/health >/dev/null 2>&1 \
   && curl -sf http://localhost:8080/ >/dev/null 2>&1; then
  ok "backend + nginx healthy (attempt $i)"
  break
 fi
 if [[ $i -eq 60 ]]; then
  bad "health timeout"
  docker compose ps > "$OUT/compose-ps.txt" 2>&1 || true
  docker logs waf-tuner-backend --tail 80 > "$OUT/backend-logs.txt" 2>&1 || true
 fi
 sleep 3
done

curl -sS http://localhost:8000/health | tee "$OUT/health.json" || true
curl -sS http://localhost:8000/api/settings/product | tee "$OUT/settings-product.json" || true
curl -sS http://localhost:8000/api/analytics/analysis-health | tee "$OUT/analysis-health.json" || true

# assertions
if python3 -c "import json; d=json.load(open('$OUT/health.json')); assert d.get('status')=='ok'; assert d.get('deploy_enabled') is False" 2>/dev/null; then
  ok "health status=ok deploy_enabled=false"
else
  bad "health check failed"
fi

# LLM env from lab-data/.env reached the container
if python3 -c "
import json
d=json.load(open('$OUT/settings-product.json'))
env=d.get('env') or {}
assert 'nvidia.com' in (env.get('LLM_API_BASE_URL') or '') or (env.get('LLM_API_BASE_URL') or '')
assert env.get('LLM_MODEL')
print('model', env.get('LLM_MODEL'))
print('base', env.get('LLM_API_BASE_URL'))
" 2>/dev/null; then
  ok "LLM settings visible via /api/settings/product"
else
  bad "LLM settings not loaded from lab-data/.env"
fi

# Deploy API must not exist
if curl -sf -o /dev/null -w "%{http_code}" http://localhost:8000/api/deploy/pending | grep -qE '404|405'; then
 ok "deploy API absent (404/405)"
else
 code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/api/deploy/pending || echo err)
 if [[ "$code" == "404" || "$code" == "405" ]]; then
  ok "deploy API absent ($code)"
 else
  bad "deploy endpoint still reachable (HTTP $code)"
 fi
fi

# Frontend
if curl -sf -o /dev/null http://localhost:3000/; then
 ok "frontend :3000"
else
 bad "frontend :3000"
fi

# --- 4. DVWA traffic ---
note "DVWA attack matrix"
if ./scripts/run_incident_matrix.sh > "$OUT/attack-matrix.txt" 2>&1; then
 ok "attack matrix finished"
else
 bad "attack matrix"
fi
tail -30 "$OUT/attack-matrix.txt" || true

sleep 5
AUDIT_AFTER=$(wc -c < lab-data/modsec/audit.log | tr -d ' ')
echo "audit.log bytes: before=$AUDIT_BEFORE after=$AUDIT_AFTER" | tee "$OUT/audit-size.txt"
if [[ "${AUDIT_AFTER:-0}" -gt "${AUDIT_BEFORE:-0}" ]]; then
 ok "audit.log grew"
else
 bad "audit.log did not grow"
fi

# sample tail of audit log (redact-ish: first 2k of last lines)
tail -c 4000 lab-data/modsec/audit.log > "$OUT/audit-log-sample.txt" 2>/dev/null || true

# --- 5. API data surface ---
note "API surface"
curl -sS "http://localhost:8000/api/analytics/summary" | tee "$OUT/analytics-summary.json" || true
curl -sS "http://localhost:8000/api/events?limit=5" | tee "$OUT/events-sample.json" || true
curl -sS "http://localhost:8000/api/cases?limit=5" | tee "$OUT/cases-sample.json" || true
curl -sS "http://localhost:8000/api/settings/ingest" | tee "$OUT/ingest.json" || true

if python3 -c "
import json
s=json.load(open('$OUT/analytics-summary.json'))
assert 'total_events' in s
assert 'deployed' not in s
print('events', s.get('total_events'))
" 2>/dev/null; then
 ok "analytics summary"
else
 bad "analytics summary"
fi

for i in $(seq 1 40); do
 curl -sS http://localhost:8000/api/analytics/analysis-health > "$OUT/analysis-health.json" || true
 if python3 -c "
import json
h=json.load(open('$OUT/analysis-health.json'))
busy=sum(h['cases_by_state'].get(s, 0) for s in ('queued','analyzing','retryable_error'))
assert busy == 0 and h['active_attempts'] == 0
" 2>/dev/null; then
  break
 fi
 sleep 3
done

if python3 -c "
import json, sqlite3
h=json.load(open('$OUT/analysis-health.json'))
db=sqlite3.connect('lab-data/waf-tuner.db')
cases=dict(db.execute('select state,count(*) from analysis_cases group by state'))
attempts=db.execute(\"select count(*) from inference_attempts where status='active'\").fetchone()[0]
assert h['cases_by_state'] == cases, (h['cases_by_state'], cases)
assert h['active_attempts'] == attempts, (h['active_attempts'], attempts)
assert h['prompt_version'].startswith('offpath-v5')
"; then
 ok "analysis health matches SQLite state"
else
 bad "analysis health does not match SQLite state"
fi

# --- 6. e2e builder script ---
note "e2e_fp_suppression.sh"
if ./scripts/e2e_fp_suppression.sh > "$OUT/e2e-fp-suppression.txt" 2>&1; then
 ok "e2e_fp_suppression"
else
 bad "e2e_fp_suppression"
fi

# --- summary ---
note "Results"
cat > "$SUMMARY" <<EOF
# E2E results — $STAMP

| Check | Count |
|-------|-------|
| Passed | $pass |
| Failed | $fail |

## Artifacts

- \`unit-tests.txt\`
- \`sample-exclusion.secrule\`
- \`health.json\`, \`settings-product.json\`, \`analysis-health.json\`, \`ingest.json\`
- \`attack-matrix.txt\`
- \`audit-size.txt\`, \`audit-log-sample.txt\`
- \`analytics-summary.json\`, \`events-sample.json\`, \`cases-sample.json\`
- \`compose-build.log\`, \`compose-up.log\`, \`compose-config.json\`, \`backend-test-image.log\`, \`run.log\`

## Containers

\`\`\`
$(docker compose ps 2>/dev/null || true)
\`\`\`

## Notes

- Product is observe/recommend only (no deploy API).
- Stack left running (\`docker compose up -d\`). Tear down with \`docker compose down\`.
EOF

cat "$SUMMARY"
echo ""
echo "E2E complete: pass=$pass fail=$fail → $OUT"
[[ "$fail" -eq 0 ]]
