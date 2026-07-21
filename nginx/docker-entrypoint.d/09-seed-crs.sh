#!/bin/sh
# Runs before template processing (20-envsubst-on-templates.sh).
# Seeds CRS rules into the shared data volume so waf-tuner-backend can parse them.
set -e

# Lab compose mounts one shared dir at /shared and also at /waf-data.
SHARED="${WAF_SHARED_DIR:-/shared}"
mkdir -p "$SHARED/modsec" "$SHARED/crs-rules" "$SHARED/exceptions" \
         /waf-data/crs-rules /waf-data/exceptions /var/log/modsec

# Keep legacy /waf-data paths populated (exception Include + CRS index).
CRS_DEST="/waf-data/crs-rules"
# If /waf-data is the same mount as /shared, also use shared layout.
if [ -d "$SHARED" ]; then
    mkdir -p "$SHARED/crs-rules" "$SHARED/exceptions" "$SHARED/modsec"
    # Prefer writing CRS under shared when distinct; always ensure waf-data exists.
    if [ "$SHARED" != "/waf-data" ] && [ ! -e /waf-data/crs-rules/.seeded ] 2>/dev/null; then
        :
    fi
fi

PLACEHOLDER="/waf-data/exceptions/00-placeholder.conf"
if [ ! -f "$PLACEHOLDER" ]; then
    echo "# WAF Tuner — placeholder (do not delete)" > "$PLACEHOLDER"
fi
if [ -d "$SHARED/exceptions" ] && [ ! -f "$SHARED/exceptions/00-placeholder.conf" ]; then
    echo "# WAF Tuner — placeholder (do not delete)" > "$SHARED/exceptions/00-placeholder.conf"
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
