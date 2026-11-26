#!/usr/bin/env bash
# Verify the generated rule's effective scope in an isolated ModSecurity instance.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${WAF_E2E_IMAGE:-owasp/modsecurity-crs:nginx-alpine}"
workspace="$(mktemp -d)"
trap 'rm -rf "$workspace"' EXIT
chmod 755 "$workspace"
mkdir "$workspace/www"
printf 'Catalog\n' > "$workspace/www/catalog"
printf 'Preview\n' > "$workspace/www/preview"

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$ROOT/backend" python3 -B - > "$workspace/exclusion.conf" <<'PY'
from services.exception_builder import build_exception_rule

print(build_exception_rule({
    "host": "catalog.test", "method": "GET", "uri": "/catalog",
    "collection": "ARGS", "parameter": "q", "rule_id": "10001",
}))
PY

cat > "$workspace/detection.conf" <<'MODSEC'
SecRuleEngine On
SecRule ARGS "@streq catalog-sample" "id:10001,phase:2,deny,status:403,t:none"
MODSEC
cat > "$workspace/nginx.conf" <<'NGINX'
load_module /usr/lib/nginx/modules/ngx_http_modsecurity_module.so;
pid /tmp/waf-tuner-test.pid;
error_log /dev/stderr crit;
events {}
http {
    access_log off;
    root /test/www;
    server {
        listen 127.0.0.1:8181;
        modsecurity on;
        modsecurity_rules_file /test/detection.conf;
    }
    server {
        listen 127.0.0.1:8182;
        modsecurity on;
        modsecurity_rules_file /test/exclusion.conf;
        modsecurity_rules_file /test/detection.conf;
    }
}
NGINX

docker run --rm --network none -v "$workspace:/test:ro" --entrypoint /bin/sh "$IMAGE" -eu -c '
    nginx -t -c /test/nginx.conf
    nginx -c /test/nginx.conf
    check() {
        expected="$1"
        shift
        actual="$(curl -sS --max-time 5 -o /dev/null -w "%{http_code}" "$@")"
        [ "$actual" = "$expected" ] || {
            printf "Expected HTTP %s, got %s for %s\n" "$expected" "$actual" "$*" >&2
            exit 1
        }
    }

    check 403 -H "Host: catalog.test" "http://127.0.0.1:8181/catalog?q=catalog-sample"
    check 200 -H "Host: catalog.test" "http://127.0.0.1:8182/catalog?q=catalog-sample"
    check 403 -H "Host: catalog.test" "http://127.0.0.1:8182/preview?q=catalog-sample"
    check 403 -H "Host: catalog.test" "http://127.0.0.1:8182/catalog?category=catalog-sample"
    check 403 -H "Host: another.test" "http://127.0.0.1:8182/catalog?q=catalog-sample"
    check 403 -X POST -H "Host: catalog.test" "http://127.0.0.1:8182/catalog?q=catalog-sample"
    printf "%s\n" "The exclusion suppresses the intended match. Host, path, method, and parameter controls still trigger detection."
'
