#!/bin/sh
# Runs before template processing (20-envsubst-on-templates.sh).
# Seeds CRS rules into the shared waf-data volume so api-server can parse them.
set -e

CRS_DEST="/waf-data/crs-rules"
mkdir -p "$CRS_DEST" "/waf-data/exceptions"

# Placeholder so Include /waf-data/exceptions/*.conf never matches zero files
PLACEHOLDER="/waf-data/exceptions/00-placeholder.conf"
if [ ! -f "$PLACEHOLDER" ]; then
    echo "# WAF Exception Agent — placeholder (do not delete)" > "$PLACEHOLDER"
fi

if [ -z "$(ls -A "$CRS_DEST" 2>/dev/null)" ]; then
    for src in \
        /opt/owasp-crs/rules \
        /etc/nginx/modsecurity/crs/rules \
        /usr/share/modsecurity-crs/rules \
        /etc/modsecurity/crs/rules; do
        if [ -d "$src" ] && [ -n "$(ls -A "$src" 2>/dev/null)" ]; then
            cp -r "$src"/. "$CRS_DEST/"
            echo "[09-seed-crs] Seeded $(find "$CRS_DEST" -name '*.conf' | wc -l) CRS rule files from $src"
            break
        fi
    done
    if [ -z "$(ls -A "$CRS_DEST" 2>/dev/null)" ]; then
        echo "[09-seed-crs] Warning: could not find bundled CRS rules to seed"
    fi
else
    echo "[09-seed-crs] CRS rules already seeded ($(find "$CRS_DEST" -name '*.conf' | wc -l) files)"
fi
