#!/bin/bash
# verify_installation.sh - Verification script for local (non-docker) WAF Tuner setup.
# Target OS: Linux (Ubuntu/Debian)

# Color outputs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "============================================="
echo "  WAF Exception Agent Verification Script  "
echo "============================================="
echo ""

# Helper to check service status
check_service() {
  local service_name=$1
  if systemctl is-active --quiet "$service_name"; then
    echo -e "[${GREEN} OK ${NC}] Service '$service_name' is running."
    return 0
  else
    echo -e "[${RED}FAIL${NC}] Service '$service_name' is NOT running!"
    return 1
  fi
}

# 1. Verify Core System Services (bare-metal optional)
echo "1. Checking System Services..."
if command -v systemctl &> /dev/null && systemctl list-unit-files nginx.service &> /dev/null; then
  check_service nginx
else
  echo -e "[${YELLOW}WARN${NC}] systemctl/nginx unit not present (Compose lab is fine without host nginx)."
fi
echo ""

# 2. Verify SQLite workflow database (lab default or DATABASE_PATH)
echo "2. Checking SQLite workflow database..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DB_CANDIDATES=(
  "${DATABASE_PATH:-}"
  "${SQLITE_PATH:-}"
  "$REPO_ROOT/lab-data/waf-tuner.db"
  "/shared/waf-tuner.db"
)
DB_PATH=""
for candidate in "${DB_CANDIDATES[@]}"; do
  if [ -n "$candidate" ] && [ -f "$candidate" ]; then
    DB_PATH="$candidate"
    break
  fi
done

if [ -n "$DB_PATH" ]; then
  echo -e "[${GREEN} OK ${NC}] SQLite database found at $DB_PATH."
  if command -v sqlite3 &> /dev/null; then
    if sqlite3 "$DB_PATH" "SELECT 1 FROM sqlite_master WHERE type='table' AND name='exception_drafts';" | grep -q 1; then
      echo -e "[${GREEN} OK ${NC}] Table 'exception_drafts' exists."
    else
      echo -e "[${YELLOW}WARN${NC}] Table 'exception_drafts' not found yet (start the backend once to init schema)."
    fi
  else
    echo -e "[${YELLOW}WARN${NC}] sqlite3 CLI not installed; skipped table check."
  fi
else
  echo -e "[${YELLOW}WARN${NC}] No SQLite DB at lab-data/waf-tuner.db yet (created on first backend start)."
fi
echo ""

# 3. Verify Nginx + ModSecurity Configuration
echo "3. Checking Nginx & ModSecurity Configuration..."
if sudo nginx -t &> /dev/null; then
  echo -e "[${GREEN} OK ${NC}] Nginx configuration test passed (nginx -t)."
else
  echo -e "[${RED}FAIL${NC}] Nginx configuration test failed!"
  sudo nginx -t
fi

# Check if ModSecurity directives exist in Nginx virtual hosts
if grep -q "modsecurity on" /etc/nginx/sites-enabled/default 2>/dev/null; then
  echo -e "[${GREEN} OK ${NC}] ModSecurity is enabled ('modsecurity on') in Nginx default site config."
else
  echo -e "[${YELLOW}WARN${NC}] 'modsecurity on' directive not found in /etc/nginx/sites-enabled/default."
fi

# Check folders and placeholder
if [ -d "/etc/nginx/modsecurity/exceptions" ]; then
  echo -e "[${GREEN} OK ${NC}] Exceptions folder '/etc/nginx/modsecurity/exceptions/' exists."
  if [ -f "/etc/nginx/modsecurity/exceptions/exception_00_placeholder.conf" ]; then
    echo -e "[${GREEN} OK ${NC}] Placeholder exceptions file exists."
  else
    echo -e "[${YELLOW}WARN${NC}] Placeholder exceptions file is missing."
  fi
else
  echo -e "[${RED}FAIL${NC}] Exceptions directory '/etc/nginx/modsecurity/exceptions/' is missing!"
fi

# Check audit log write permissions
if [ -d "/var/log/modsec" ]; then
  echo -e "[${GREEN} OK ${NC}] Audit log directory '/var/log/modsec/' exists."
  if [ -w "/var/log/modsec" ]; then
    echo -e "[${GREEN} OK ${NC}] Audit log directory is writable."
  else
    echo -e "[${RED}FAIL${NC}] Audit log directory is NOT writable by current user."
  fi
else
  echo -e "[${RED}FAIL${NC}] Audit log directory '/var/log/modsec/' is missing!"
fi
echo ""

# 4. Verify Local Ports & Web Application Endpoints
echo "4. Checking Local Server Ports & Endpoints..."

check_endpoint() {
  local label=$1
  local url=$2
  local expected_code=$3
  
  local code=$(curl -s -o /dev/null -w "%{http_code}" "$url" --connect-timeout 2)
  if [ "$code" = "$expected_code" ] || { [ "$expected_code" = "200" ] && [ "$code" = "301" -o "$code" = "302" ]; }; then
    echo -e "[${GREEN} OK ${NC}] $label is running on $url (HTTP $code)."
    return 0
  else
    echo -e "[${RED}FAIL${NC}] $label is NOT reachable on $url! (Got HTTP code: '$code', expected '$expected_code')."
    return 1
  fi
}

# Lab compose ports (prefer Docker lab; fall back to bare-metal :80)
LAB_WAF="${LAB_WAF_URL:-http://127.0.0.1:8080}"
LAB_API="${LAB_API_URL:-http://127.0.0.1:8000}"
LAB_UI="${LAB_UI_URL:-http://127.0.0.1:3000}"

check_endpoint "WAF Tuner backend" "${LAB_API}/health" "200"
check_endpoint "Nginx WAF (→ DVWA)" "${LAB_WAF}/login.php" "200"

PORTAL_UP=0
if curl -s -o /dev/null -w "%{http_code}" "${LAB_UI}" --connect-timeout 2 | grep -q "^[23]"; then
  echo -e "[${GREEN} OK ${NC}] WAF Tuner frontend is running on ${LAB_UI}."
  PORTAL_UP=1
else
  echo -e "[${YELLOW}WARN${NC}] Frontend not reachable on ${LAB_UI}."
fi
echo ""

# 5. ModSecurity Rule Triggering via DVWA
echo "5. Testing ModSecurity Event Logging (DVWA SQLi path)..."
echo "Sending SQLi trigger through WAF → DVWA: /vulnerabilities/sqli/?id=..."
TRIGGER_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  --connect-timeout 5 \
  --get "${LAB_WAF}/vulnerabilities/sqli/" \
  --data-urlencode "id=1' OR '1'='1" \
  --data-urlencode "Submit=Submit" || echo "000")

if [ "$TRIGGER_CODE" = "000" ]; then
  echo -e "[${RED}FAIL${NC}] Could not send trigger to lab WAF at ${LAB_WAF}."
else
  echo -e "Proxy returned HTTP status code: $TRIGGER_CODE (DetectionOnly should not block)."
  sleep 3
  # Lab shared volume or bare-metal path
  if [ -f "lab-data/modsec/audit.log" ] && [ -s "lab-data/modsec/audit.log" ]; then
    echo -e "[${GREEN} OK ${NC}] ModSecurity logged to lab-data/modsec/audit.log."
  elif [ -f "/var/log/modsec/audit.log" ] && [ -s "/var/log/modsec/audit.log" ]; then
    echo -e "[${GREEN} OK ${NC}] ModSecurity logged to /var/log/modsec/audit.log."
  else
    echo -e "[${YELLOW}WARN${NC}] No audit log growth detected yet. Hit ./scripts/run_incident_matrix.sh and re-check lab-data/modsec/audit.log."
  fi
fi
echo ""

echo "============================================="
echo "       Verification Finished      "
echo "============================================="
