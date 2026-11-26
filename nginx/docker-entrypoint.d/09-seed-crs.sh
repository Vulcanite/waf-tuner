#!/bin/sh
# Publish an immutable copy of the CRS files for the analyzer.
set -e
export LC_ALL=C

SHARED="${WAF_SHARED_DIR:-/shared}"
DEST="$SHARED/crs-rules"
mkdir -p "$SHARED/modsec" "$SHARED/exceptions" "$DEST/.snapshots"

source_dir="${WAF_CRS_SOURCE_DIR:-}"
if [ -z "$source_dir" ]; then
    for candidate in /etc/nginx/modsecurity/crs/rules /opt/owasp-crs/rules \
                     /usr/share/modsecurity-crs/rules /etc/modsecurity/crs/rules; do
        set -- "$candidate"/*.conf
        if [ -f "$1" ]; then
            source_dir="$candidate"
            break
        fi
    done
fi

marker="$(mktemp "$DEST/.active-snapshot.XXXXXX")"
snapshot="$(mktemp -d "$DEST/.snapshots/.new.XXXXXX")"
trap 'rm -f "$marker"; rm -rf "$snapshot"' EXIT

set -- "${source_dir:-/nonexistent}"/*.conf
if [ ! -f "$1" ]; then
    printf '%s\n' unavailable > "$marker"
    chmod 644 "$marker"
    mv -f "$marker" "$DEST/.active-snapshot"
    echo "[09-seed-crs] Unable to locate the CRS ruleset"
    exit 0
fi

for rule in "$source_dir"/*; do
    case "$rule" in
        *.conf|*.data) [ ! -f "$rule" ] || cp "$rule" "$snapshot/" ;;
    esac
done
digest="$(cd "$snapshot" && sha256sum -- * | sha256sum | cut -d ' ' -f 1)"
chmod 755 "$snapshot"
if [ ! -d "$DEST/.snapshots/$digest" ]; then
    mv "$snapshot" "$DEST/.snapshots/$digest"
fi
printf '%s\n' "$digest" > "$marker"
chmod 644 "$marker"
mv -f "$marker" "$DEST/.active-snapshot"
echo "[09-seed-crs] Published CRS snapshot $digest"
