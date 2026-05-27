FROM owasp/modsecurity-crs:nginx-alpine

USER root

# Create runtime directories
RUN mkdir -p /var/log/modsec /waf-data/exceptions /waf-data/crs-rules \
    && chmod -R 777 /var/log/modsec /waf-data

# Drop init scripts into the image's entrypoint hook directory.
# The nginx entrypoint runs these in alphabetical order:
#   09-seed-crs.sh     → runs BEFORE template processing (20-envsubst...)
#   30-add-exception-include.sh → runs AFTER templates are generated
COPY docker-entrypoint.d/09-seed-crs.sh /docker-entrypoint.d/09-seed-crs.sh
COPY docker-entrypoint.d/30-add-exception-include.sh /docker-entrypoint.d/30-add-exception-include.sh
RUN chmod +x /docker-entrypoint.d/09-seed-crs.sh \
             /docker-entrypoint.d/30-add-exception-include.sh

EXPOSE 80
# No ENTRYPOINT override — the base image's entrypoint handles module loading,
# template processing (generates nginx.conf with load_module), and nginx startup.
