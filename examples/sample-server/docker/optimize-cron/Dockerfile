# optimize-cron/Dockerfile
# ──────────────────────────────────────────────────────────────────────────────
# Lightweight Alpine container that runs a scheduled MySQL OPTIMIZE TABLE +
# ANALYZE TABLE maintenance job against the oidc_cache table.
#
# Image size: ~15 MB (Alpine base + mysql-client)
# Idle memory: < 5 MB (BusyBox crond + sh)
#
# Environment variables (all provided by docker-compose):
#   MYSQL_USER          – database user
#   MYSQL_PASSWORD      – database password
#   MYSQL_DATABASE      – database / schema name
#   MYSQL_HOST          – mysql hostname (service name in the compose network)
#   MYSQL_PORT_INNER    – mysql port (default: 3306)
#   OPTIMIZE_SCHEDULE   – 5-field cron expression (default: "0 0 * * *")
# ──────────────────────────────────────────────────────────────────────────────

FROM alpine:3.21

# Install the MySQL client (mysql / mysqladmin) and tini as a minimal init
# process.  tini ensures crond receives SIGTERM correctly and exits cleanly.
RUN apk add --no-cache \
        mysql-client \
        tini \
    && rm -rf /var/cache/apk/*

# Copy the entrypoint that writes the crontab and starts crond.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Copy the maintenance script that mysql executes.
COPY optimize.sh /usr/local/bin/optimize.sh
RUN chmod +x /usr/local/bin/optimize.sh

# Run as a non-root user for security.
RUN addgroup -S cronuser && adduser -S cronuser -G cronuser
USER cronuser

# tini is PID 1; it reaps zombies and forwards signals to crond.
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]
