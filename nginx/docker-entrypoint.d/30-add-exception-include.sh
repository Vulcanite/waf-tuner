#!/bin/sh
# Ensure agent exceptions load BEFORE CRS rules (ctl:ruleRemoveTargetById timing).
set -e

mkdir -p /waf-data/exceptions
PLACEHOLDER="/waf-data/exceptions/00-placeholder.conf"
if [ ! -f "$PLACEHOLDER" ]; then
    echo "# WAF Exception Agent — placeholder (do not delete)" > "$PLACEHOLDER"
fi

MODSEC_RULES=""
for candidate in \
    /etc/nginx/modsecurity.d/modsecurity.conf \
    /etc/nginx/modsecurity.d/modsecurity-override.conf \
    /etc/modsecurity.d/modsecurity.conf \
    /etc/modsecurity/modsecurity.conf \
    /etc/nginx/modsecurity/modsecurity.conf; do
    if [ -f "$candidate" ]; then
        MODSEC_RULES="$candidate"
        break
    fi
done

if [ -z "$MODSEC_RULES" ]; then
    echo "[30-add-exception-include] Warning: ModSecurity rules file not found"
    exit 0
fi

INCLUDE_LINE='Include /waf-data/exceptions/*.conf'

if grep -q "waf-data/exceptions" "$MODSEC_RULES" 2>/dev/null; then
    # Reposition: remove existing agent includes then re-insert before CRS.
    tmp="$(mktemp)"
    grep -v "waf-data/exceptions" "$MODSEC_RULES" > "$tmp" || true
    mv "$tmp" "$MODSEC_RULES"
fi

# Insert exception Include immediately before the first CRS rules Include, or at top.
tmp="$(mktemp)"
if grep -qE 'Include.*(crs|owasp).*rules' "$MODSEC_RULES" 2>/dev/null; then
    # shellcheck disable=SC2016
    awk -v inc="$INCLUDE_LINE" '
        !done && $0 ~ /Include.*(crs|owasp).*rules/ {
            print "# Agent-generated exception rules (before CRS)"
            print inc
            print ""
            done=1
        }
        { print }
        END {
            if (!done) {
                print ""
                print "# Agent-generated exception rules (before CRS)"
                print inc
            }
        }
    ' "$MODSEC_RULES" > "$tmp"
else
    {
        echo "# Agent-generated exception rules (before CRS)"
        echo "$INCLUDE_LINE"
        echo ""
        cat "$MODSEC_RULES"
    } > "$tmp"
fi
mv "$tmp" "$MODSEC_RULES"
echo "[30-add-exception-include] Ensured before-CRS Include in $MODSEC_RULES"
