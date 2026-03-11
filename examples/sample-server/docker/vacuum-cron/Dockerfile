# vacuum-cron/Dockerfile
# ──────────────────────────────────────────────────────────────────────────────
# Lightweight Alpine container that runs a scheduled PostgreSQL VACUUM ANALYZE
# job against the oidc_cache table.
#
# Image size: ~12 MB (Alpine base + postgresql-client)
# Idle memory: < 5 MB (BusyBox crond + sh)
#
# Environment variables (all provided by docker-compose):
#   POSTGRES_USER      – database user
#   POSTGRES_PASSWORD  – database password
#   POSTGRES_DB        – database name
#   PGHOST             – postgres hostname (service name in the compose network)
#   PGPORT             – postgres port (default: 5432)
#   VACUUM_SCHEDULE    – 5-field cron expression (default: "0 0 * * *")
# ──────────────────────────────────────────────────────────────────────────────

FROM alpine:3.21

# Install the PostgreSQL client (psql) and tini as a minimal init process.
# tini ensures crond receives SIGTERM correctly and exits cleanly.
RUN apk add --no-cache \
        postgresql17-client \
        tini \
    && rm -rf /var/cache/apk/*

# Copy the entrypoint that writes the crontab and starts crond.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Copy the vacuum script that psql executes.
COPY vacuum.sh /usr/local/bin/vacuum.sh
RUN chmod +x /usr/local/bin/vacuum.sh

# Run as a non-root user for security.
RUN addgroup -S cronuser && adduser -S cronuser -G cronuser
USER cronuser

# tini is PID 1; it reaps zombies and forwards signals to crond.
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]
