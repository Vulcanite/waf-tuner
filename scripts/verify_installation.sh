#!/bin/bash
# verify_installation.sh - Verification script for local (non-docker) WAF Tuner setup.
# Target OS: Linux (Ubuntu/Debian)

# Color outputs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "============================================="
echo "   WAF Exception Agent Verification Script   "
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

# 1. Verify Core System Services
echo "1. Checking System Services..."
check_service postgresql
check_service nginx
echo ""

# 2. Verify PostgreSQL Connection & Schema
echo "2. Checking PostgreSQL Connection and Database Schema..."
if command -v psql &> /dev/null; then
    if PGPASSWORD=waf psql -h 127.0.0.1 -U waf -d wafdb -c "SELECT 1;" &> /dev/null; then
        echo -e "[${GREEN} OK ${NC}] Successfully connected to PostgreSQL (wafdb)."
        
        # Check if table exists
        TABLE_EXISTS=$(PGPASSWORD=waf psql -h 127.0.0.1 -U waf -d wafdb -tAc "SELECT EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = 'exception_drafts');")
        if [ "$TABLE_EXISTS" = "t" ]; then
            echo -e "[${GREEN} OK ${NC}] Database table 'exception_drafts' exists."
        else
            echo -e "[${RED}FAIL${NC}] Table 'exception_drafts' does NOT exist!"
        fi
    else
        echo -e "[${RED}FAIL${NC}] Connection to PostgreSQL database (wafdb) failed!"
    fi
else
    echo -e "[${RED}FAIL${NC}] 'psql' client command not found!"
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

# Flask target app
check_endpoint "Flask Target App" "http://127.0.0.1:5000" "200"

# FastAPI API server
check_endpoint "FastAPI API Server" "http://127.0.0.1:8000/health" "200"

# Nginx reverse proxy
check_endpoint "Nginx Proxy Server" "http://127.0.0.1:8080" "200"

# React Portal
# Vite runs on 3000 or 5173 by default - check both
PORTAL_UP=0
if curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:3000" --connect-timeout 1 | grep -q "^[23]"; then
    echo -e "[${GREEN} OK ${NC}] React Portal is running on http://127.0.0.1:3000."
    PORTAL_UP=1
elif curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:5173" --connect-timeout 1 | grep -q "^[23]"; then
    echo -e "[${GREEN} OK ${NC}] React Portal is running on http://127.0.0.1:5173."
    PORTAL_UP=1
else
    echo -e "[${RED}FAIL${NC}] React Portal is NOT reachable on port 3000 or 5173!"
fi
echo ""

# 5. ModSecurity Rule Triggering & Log Ingestion test
echo "5. Testing ModSecurity Event Logging..."
# Send a trigger string (SQL Injection pattern) through the Nginx proxy
echo "Sending mock SQL Injection trigger: '/search?q=1%27+OR+%271%27%3D%271'"
TRIGGER_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8080/search?q=1%27+OR+%271%27%3D%271" --connect-timeout 2)

if [ "$TRIGGER_CODE" = "000" ]; then
    echo -e "[${RED}FAIL${NC}] Could not send trigger to Nginx proxy."
else
    echo -e "Proxy returned HTTP status code: $TRIGGER_CODE (ModSecurity configured in detection-only mode, so it should pass)."
    
    # Wait for logs to be written
    sleep 3
    
    # Check if anything was written to ModSec audit log
    if [ -f "/var/log/modsec/audit.log" ] && [ -s "/var/log/modsec/audit.log" ]; then
        echo -e "[${GREEN} OK ${NC}] ModSecurity logged the trigger to /var/log/modsec/audit.log."
    else
        echo -e "[${RED}FAIL${NC}] No logs found in /var/log/modsec/audit.log. Verify audit.log permissions and Nginx load_module status!"
    fi
fi
echo ""

echo "============================================="
echo "             Verification Finished           "
echo "============================================="
