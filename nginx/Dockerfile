FROM owasp/modsecurity-crs:nginx-alpine

USER root

# Create runtime directories
RUN mkdir -p /var/log/modsec /waf-data/exceptions /waf-data/crs-rules \
    && chmod -R 777 /var/log/modsec /waf-data

# Entrypoint hooks (alphabetical):
#   09-seed-crs.sh — seed CRS into shared volume for backend index
COPY docker-entrypoint.d/09-seed-crs.sh /docker-entrypoint.d/09-seed-crs.sh
RUN chmod +x /docker-entrypoint.d/09-seed-crs.sh

EXPOSE 80
