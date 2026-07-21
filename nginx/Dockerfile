FROM owasp/modsecurity-crs:nginx-alpine

USER root

# Create runtime directories
RUN mkdir -p /var/log/modsec /waf-data/exceptions /waf-data/crs-rules \
    && chmod -R 777 /var/log/modsec /waf-data

# Entrypoint hooks (alphabetical):
#   09-seed-crs.sh — seed CRS into shared volume for backend index
#   30-add-exception-include.sh — optional include path (unused by  app)
COPY docker-entrypoint.d/09-seed-crs.sh /docker-entrypoint.d/09-seed-crs.sh
COPY docker-entrypoint.d/30-add-exception-include.sh /docker-entrypoint.d/30-add-exception-include.sh
RUN chmod +x /docker-entrypoint.d/09-seed-crs.sh \
             /docker-entrypoint.d/30-add-exception-include.sh

EXPOSE 80
