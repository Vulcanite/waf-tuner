#!/usr/bin/env bash
# Send FP-like and true-positive traffic through the lab WAF (nginx:8080 → DVWA).
#
# Usage:
#  ./scripts/run_incident_matrix.sh
#  WAF_BASE_URL=http://localhost:8080 ./scripts/run_incident_matrix.sh
#
# Requires: lab stack up (docker compose). Does not need a live LLM.
# Cookies: logs in as admin/password and sets DVWA security level to low so
# vuln pages are reachable; CRS still inspects every request either way.
set -euo pipefail

base_url="${WAF_BASE_URL:-http://localhost:8080}"
base_url="${base_url%/}"
cookie_jar="$(mktemp)"
trap 'rm -f "$cookie_jar"' EXIT

run_case() {
  local label="$1"
  shift
  local status
  status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
    --cookie "$cookie_jar" --cookie-jar "$cookie_jar" \
    --max-time 15 \
    "$@" 2>/dev/null || echo "000")
  printf '%-40s HTTP %s\n' "$label" "$status"
}

extract_token() {
  # DVWA CSRF tokens: <input ... name='user_token' value='...'>
  python3 - "$1" <<'PY'
import re, sys
html = open(sys.argv[1], encoding="utf-8", errors="replace").read()
m = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)['\"]", html, re.I)
if not m:
  m = re.search(r"value=['\"]([^'\"]+)['\"]\s+name=['\"]user_token['\"]", html, re.I)
print(m.group(1) if m else "")
PY
}

echo "== DVWA session setup (${base_url}) =="

# Login page + token
login_html="$(mktemp)"
curl --silent --show-error --cookie-jar "$cookie_jar" --cookie "$cookie_jar" \
  --max-time 15 \
  -o "$login_html" "${base_url}/login.php" || true
token="$(extract_token "$login_html")"
rm -f "$login_html"

if [[ -n "$token" ]]; then
  curl --silent --show-error --cookie-jar "$cookie_jar" --cookie "$cookie_jar" \
    --max-time 15 \
    --request POST "${base_url}/login.php" \
    --data-urlencode "username=admin" \
    --data-urlencode "password=password" \
    --data-urlencode "Login=Login" \
    --data-urlencode "user_token=${token}" \
    -o /dev/null || true
  echo "Logged in as admin / password"
else
  echo "WARN: no user_token on /login.php — continuing without session (WAF still sees payloads)"
fi

# Security level → low (another token page)
sec_html="$(mktemp)"
curl --silent --show-error --cookie-jar "$cookie_jar" --cookie "$cookie_jar" \
  --max-time 15 \
  -o "$sec_html" "${base_url}/security.php" || true
sec_token="$(extract_token "$sec_html")"
rm -f "$sec_html"
if [[ -n "$sec_token" ]]; then
  curl --silent --show-error --cookie-jar "$cookie_jar" --cookie "$cookie_jar" \
    --max-time 15 \
    --request POST "${base_url}/security.php" \
    --data-urlencode "security=low" \
    --data-urlencode "seclev_submit=Submit" \
    --data-urlencode "user_token=${sec_token}" \
    -o /dev/null || true
  echo "DVWA security level set to low"
fi

echo ""
echo "== False-positive-ish (benign text that often trips CRS) =="

# SQLi module with English SQL words (classic libinjection / keyword FPs)
run_case "FP SQLi module: select words" \
  --get "${base_url}/vulnerabilities/sqli/" \
  --data-urlencode "id=select all products from category shoes" \
  --data-urlencode "Submit=Submit"

run_case "FP SQLi module: drop down phrase" \
  --get "${base_url}/vulnerabilities/sqli/" \
  --data-urlencode "id=drop down menu navigation" \
  --data-urlencode "Submit=Submit"

# Reflected XSS with markdown-ish / HTML that is not an attack
run_case "FP XSS_r: markup emphasis" \
  --get "${base_url}/vulnerabilities/xss_r/" \
  --data-urlencode "name=I love the <em>design</em> and **bold** text"

# Stored XSS form with benign rich text
run_case "FP XSS_s: blog-like comment" \
  --request POST "${base_url}/vulnerabilities/xss_s/" \
  --data-urlencode "txtName=reviewer" \
  --data-urlencode "mtxMessage=This is **great**. I love the design of the guestbook." \
  --data-urlencode "btnSign=Sign Guestbook"

# Command injection page with tutorial-style shell docs (not a real payload)
run_case "FP exec: shell tutorial text" \
  --request POST "${base_url}/vulnerabilities/exec/" \
  --data-urlencode "ip=Run ls -la to list files in the tutorial; do not execute it." \
  --data-urlencode "Submit=Submit"

# Login form with special-char password (FP pattern for many WAFs)
run_case "FP login: special password chars" \
  --request POST "${base_url}/login.php" \
  --data-urlencode "username=demo_user" \
  --data-urlencode "password=P@ssw0rd!#\$" \
  --data-urlencode "Login=Login" \
  --data-urlencode "user_token=${token:-x}"

echo ""
echo "== True positives (deliberate attack strings via DVWA surfaces) =="

run_case "TP SQLi classic" \
  --get "${base_url}/vulnerabilities/sqli/" \
  --data-urlencode "id=1' OR '1'='1" \
  --data-urlencode "Submit=Submit"

run_case "TP SQLi UNION" \
  --get "${base_url}/vulnerabilities/sqli/" \
  --data-urlencode "id=1' UNION SELECT user,password FROM users--" \
  --data-urlencode "Submit=Submit"

run_case "TP SQLi blind boolean" \
  --get "${base_url}/vulnerabilities/sqli_blind/" \
  --data-urlencode "id=1' AND '1'='1" \
  --data-urlencode "Submit=Submit"

run_case "TP login SQLi" \
  --request POST "${base_url}/login.php" \
  --data-urlencode "username=admin'--" \
  --data-urlencode "password=x" \
  --data-urlencode "Login=Login" \
  --data-urlencode "user_token=${token:-x}"

run_case "TP XSS reflected script" \
  --get "${base_url}/vulnerabilities/xss_r/" \
  --data-urlencode "name=<script>alert(document.domain)</script>"

run_case "TP XSS event handler" \
  --get "${base_url}/vulnerabilities/xss_r/" \
  --data-urlencode 'name=<img src=x onerror=alert(1)>'

run_case "TP XSS stored payload" \
  --request POST "${base_url}/vulnerabilities/xss_s/" \
  --data-urlencode "txtName=attacker" \
  --data-urlencode "mtxMessage=<script>alert(1)</script>" \
  --data-urlencode "btnSign=Sign Guestbook"

run_case "TP command injection" \
  --request POST "${base_url}/vulnerabilities/exec/" \
  --data-urlencode "ip=127.0.0.1; cat /etc/passwd" \
  --data-urlencode "Submit=Submit"

run_case "TP command pipe" \
  --request POST "${base_url}/vulnerabilities/exec/" \
  --data-urlencode 'ip=127.0.0.1 | id' \
  --data-urlencode "Submit=Submit"

run_case "TP file inclusion traversal" \
  --get "${base_url}/vulnerabilities/fi/" \
  --data-urlencode "page=../../../../etc/passwd"

run_case "TP path scan .env" \
  "${base_url}/.env"

run_case "TP path scan phpmyadmin" \
  "${base_url}/phpmyadmin/"

run_case "TP path scan wp-admin" \
  "${base_url}/wp-admin/"

echo ""
echo "Done. Check waf-tuner Events/Cases and lab-data/modsec/audit.log for CRS hits."
echo " Frontend: http://localhost:3000"
echo " DVWA:   ${base_url}/ (admin / password)"
