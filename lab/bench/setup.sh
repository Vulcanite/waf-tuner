#!/bin/sh
# Install WordPress (wp-cli) and Nextcloud (occ) inside the waftuner-bench lab.
# Idempotent: re-running skips what is already installed.
#
#   docker compose -p waftuner-bench -f lab/bench/docker-compose.yml up -d
#   lab/bench/setup.sh
#
# Throwaway lab credentials; override with the same env vars when capturing.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
DC="docker compose -p waftuner-bench -f $HERE/docker-compose.yml"
WP_ADMIN_USER="${BENCH_WP_ADMIN_USER:-benchadmin}"
WP_ADMIN_PASSWORD="${BENCH_WP_ADMIN_PASSWORD:-bench-wp-admin-pass}"
NC_ADMIN_USER="${BENCH_NC_ADMIN_USER:-benchadmin}"
NC_ADMIN_PASSWORD="${BENCH_NC_ADMIN_PASSWORD:-bench-nc-admin-pass}"
NC_SECOND_PASSWORD="${BENCH_NC_SECOND_PASSWORD:-bench-nc-bea-pass}"

wp() { $DC run --rm -T wpcli wp --path=/var/www/html "$@"; }
occ() { $DC exec -T -u www-data nextcloud php occ "$@"; }

echo "== waiting for the app containers"
for _ in $(seq 1 60); do
    if $DC exec -T wordpress test -f /var/www/html/wp-config.php 2>/dev/null \
        && $DC exec -T nextcloud test -f /var/www/html/version.php 2>/dev/null; then
        break
    fi
    sleep 3
done

echo "== WordPress"
if ! wp core is-installed 2>/dev/null; then
    wp core install --url=http://wp.bench --title="Bench Notes" \
        --admin_user="$WP_ADMIN_USER" --admin_password="$WP_ADMIN_PASSWORD" \
        --admin_email=admin@wp.bench.test --skip-email
fi
wp rewrite structure '/%postname%/' --hard
wp option update comment_moderation 0
wp option update comment_previously_approved 0
# A classic theme keeps the Customizer and Appearance > Menus screens; the
# block editor and REST API are the same under any theme. Needs internet.
wp theme install twentytwentyone --activate || echo "warning: classic theme install failed; customizer/menus flows may 404"
wp plugin install classic-editor --activate || echo "warning: classic-editor plugin install failed; classic flows post to the core post.php handler"
# Keep the block editor as default and let users switch to the classic one per post.
wp option update classic-editor-replace block || true
wp option update classic-editor-allow-users allow || true
wp post list --post_type=post --format=count

echo "== Nextcloud"
if ! occ status --output=json 2>/dev/null | grep -q '"installed":true'; then
    occ maintenance:install --database=sqlite \
        --admin-user="$NC_ADMIN_USER" --admin-pass="$NC_ADMIN_PASSWORD"
fi
occ config:system:set trusted_domains 1 --value=nc.bench
occ config:system:set overwrite.cli.url --value=http://nc.bench
# Lab only: the attack set must not lock the admin out or throttle the run.
occ config:system:set auth.bruteforce.protection.enabled --type=boolean --value=false
occ config:system:set ratelimit.protection.enabled --type=boolean --value=false
for app in calendar contacts notes; do
    occ app:list --output=json | grep -q "\"$app\"" || occ app:install "$app" \
        || echo "warning: could not install Nextcloud app $app (needs internet); its UI routes will 404"
    occ app:enable "$app" 2>/dev/null || true
done
if ! occ user:info bea >/dev/null 2>&1; then
    $DC exec -T -u www-data -e OC_PASS="$NC_SECOND_PASSWORD" nextcloud \
        php occ user:add --password-from-env --display-name="Bea Example" bea
fi
occ status
echo "== done"
