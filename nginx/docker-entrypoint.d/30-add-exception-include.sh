#!/bin/sh
# Runs AFTER 20-envsubst-on-templates.sh has generated the final configs.
# Appends an Include for agent-generated exception rules to the ModSecurity
# rules file (NOT the nginx conf file /etc/nginx/conf.d/modsecurity.conf).
set -e

# This is the actual ModSecurity rules config (generated from template).
# /etc/nginx/conf.d/modsecurity.conf is an nginx file (modsecurity on; etc.) — do NOT touch that.
MODSEC_RULES="/etc/nginx/modsecurity.d/modsecurity.conf"

# Fallback locations used by some image versions
if [ ! -f "$MODSEC_RULES" ]; then
    for alt in \
        /etc/nginx/modsecurity.d/modsecurity-override.conf \
        /etc/modsecurity/modsecurity.conf \
        /etc/nginx/conf.d/modsecurity.d/modsecurity.conf; do
        if [ -f "$alt" ]; then
            MODSEC_RULES="$alt"
            break
        fi
    done
fi

if [ -f "$MODSEC_RULES" ]; then
    if ! grep -q "waf-data/exceptions" "$MODSEC_RULES" 2>/dev/null; then
        printf '\n# Agent-generated exception rules\nInclude /waf-data/exceptions/*.conf\n' >> "$MODSEC_RULES"
        echo "[30-add-exception-include] Appended exception Include to $MODSEC_RULES"
    else
        echo "[30-add-exception-include] Exception Include already present"
    fi
else
    echo "[30-add-exception-include] Warning: ModSecurity rules file not found"
fi
