#!/usr/bin/env bash
# Lab E2E: hit DVWA through the WAF, validate system-built exclusion shape.
# Requires: stack up (nginx :8080 → DVWA, backend :8000). No live LLM required.
set -euo pipefail

API="${API_BASE:-http://localhost:8000}"
NGINX="${NGINX_BASE:-http://localhost:8080}"
NGINX="${NGINX%/}"
RULE_ID="${RULE_ID:-942100}"
# DVWA SQL Injection module (parameter name is "id")
PATH_URI="${PATH_URI:-/vulnerabilities/sqli/}"
PARAM="${PARAM:-id}"
# Benign English that often trips @detectSQLi / SQL keyword rules
QUERY="${QUERY:-select all products from category shoes}"

echo "== health =="
curl -sf "$API/health" >/dev/null
curl -sf "$NGINX/" >/dev/null || curl -sf "$NGINX/login.php" >/dev/null || true

echo "== trigger FP-ish traffic on DVWA SQLi page =="
# Cookie jar optional: WAF inspects query/body even if DVWA redirects to login
cookie_jar="$(mktemp)"
trap 'rm -f "$cookie_jar"' EXIT

# Best-effort login so the request reaches the vuln handler
login_html="$(mktemp)"
curl --silent --cookie-jar "$cookie_jar" --cookie "$cookie_jar" \
  -o "$login_html" "${NGINX}/login.php" || true
token="$(python3 - "$login_html" <<'PY'
import re, sys
html = open(sys.argv[1], encoding="utf-8", errors="replace").read()
m = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)['\"]", html, re.I)
print(m.group(1) if m else "")
PY
)"
rm -f "$login_html"
if [[ -n "$token" ]]; then
  curl --silent --cookie-jar "$cookie_jar" --cookie "$cookie_jar" \
    --request POST "${NGINX}/login.php" \
    --data-urlencode "username=admin" \
    --data-urlencode "password=password" \
    --data-urlencode "Login=Login" \
    --data-urlencode "user_token=${token}" \
    -o /dev/null || true
fi

enc_q="$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$QUERY'''))")"
curl -sg --cookie "$cookie_jar" --cookie-jar "$cookie_jar" \
  "${NGINX}${PATH_URI}?${PARAM}=${enc_q}&Submit=Submit" -o /dev/null || true
sleep 2

echo "== build canonical exclusion via exception_builder =="
# Path-only scope (no query string); matches DVWA SQLi module after normalized_path()
RULE=$(
 cd "$(dirname "$0")/../backend" && PYTHONPATH=. \
  RULE_ID="$RULE_ID" PARAM="$PARAM" python3 - <<'PY'
import os
from services.exception_builder import build_exception_rule
scope = {
  "uri": "/vulnerabilities/sqli",
  "collection": "ARGS",
  "parameter": os.environ.get("PARAM", "id"),
  "rule_id": os.environ.get("RULE_ID", "942100"),
}
print(build_exception_rule(scope))
PY
)
echo "$RULE"

echo "== note: full deploy path needs a pending draft in SQLite =="
echo "This script validates builder output shape and stack health."
echo "For full suppression: approve a valid FP draft ( copy SecRule into your conf),"
echo "then re-run traffic and confirm rule ${RULE_ID} no longer fires for ARGS:${PARAM} on ${PATH_URI}."

# Structural assertion on builder output
echo "$RULE" | grep -q 'REQUEST_FILENAME' || { echo "FAIL: expected REQUEST_FILENAME"; exit 1; }
echo "$RULE" | grep -q '@streq /vulnerabilities/sqli' || { echo "FAIL: expected @streq /vulnerabilities/sqli"; exit 1; }
echo "$RULE" | grep -q "ruleRemoveTargetById=${RULE_ID};ARGS:${PARAM}" || { echo "FAIL: ctl target"; exit 1; }

echo "OK: stack healthy and exclusion builder output is correct for DVWA SQLi scope."
echo "Next: ./scripts/run_incident_matrix.sh # broader FP/TP matrix against DVWA"
