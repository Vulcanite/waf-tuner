#!/usr/bin/env bash
# Fresh lab start: wipe runtime data, rebuild images, bring the stack up.
# Keeps lab-data/.env (LLM keys). Use after editing .env or for a clean retest.
#
#   ./scripts/fresh_lab.sh
#   ./scripts/fresh_lab.sh --no-build   # wipe + recreate only (faster)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

NO_BUILD=0
for arg in "$@"; do
  case "$arg" in
    --no-build|-n) NO_BUILD=1 ;;
    -h|--help)
      sed -n '2,8p' "$0"
      exit 0
      ;;
  esac
done

echo "== stop stack =="
docker compose down --remove-orphans 2>/dev/null || true

echo "== wipe lab runtime data (keep .env) =="
mkdir -p lab-data/modsec lab-data/crs-rules lab-data/exceptions

rm -f \
  lab-data/waf-tuner.db \
  lab-data/waf-tuner.db-wal \
  lab-data/waf-tuner.db-shm \
  lab-data/events.jsonl \
  lab-data/audit_cursor.json \
  lab-data/audit_cursor.json.tmp \
  lab-data/runtime_config.json \
  lab-data/modsec_settings.json \
  lab-data/fingerprint.key \
  lab-data/*.key \
  2>/dev/null || true

# Empty audit + event archive (preserve file so volume mounts stay valid)
: > lab-data/modsec/audit.log
: > lab-data/events.jsonl

# Drop generated exception confs; keep optional placeholder
if [[ -d lab-data/exceptions ]]; then
  find lab-data/exceptions -type f \
    ! -name '00-placeholder.conf' \
    -delete 2>/dev/null || true
fi

if [[ ! -f lab-data/.env ]]; then
  echo "WARN: lab-data/.env missing — copying from lab-data/.env.example"
  cp lab-data/.env.example lab-data/.env
fi

echo "== start stack =="
if [[ "$NO_BUILD" -eq 1 ]]; then
  docker compose up -d --force-recreate
else
  docker compose up --build -d --force-recreate
fi

echo "== wait for health =="
for i in $(seq 1 60); do
  if curl -sf http://localhost:8000/health >/dev/null 2>&1 \
     && curl -sf http://localhost:3000/ >/dev/null 2>&1; then
    echo "OK (attempt $i)"
    break
  fi
  if [[ "$i" -eq 60 ]]; then
    echo "FAIL: health timeout"
    docker compose ps
    exit 1
  fi
  sleep 2
done

echo ""
echo "Fresh lab ready."
echo "  UI:     http://localhost:3000"
echo "  API:    http://localhost:8000/health"
echo "  DVWA:   http://localhost:8080  (admin / password)"
echo ""
echo "  Traffic:  ./scripts/run_incident_matrix.sh"
echo "  Unit:     cd backend && PYTHONPATH=. .venv/bin/python -m pytest -q  # Python 3.13"
echo "  Full E2E: bash scripts/e2e.sh"
curl -sS http://localhost:8000/api/analytics/summary 2>/dev/null | head -c 300 || true
echo ""
