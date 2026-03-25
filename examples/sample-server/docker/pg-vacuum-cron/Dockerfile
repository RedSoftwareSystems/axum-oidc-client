# pg-vacuum-cron/Dockerfile
# ──────────────────────────────────────────────────────────────────────────────
# Lightweight Alpine container that runs a scheduled PostgreSQL VACUUM ANALYZE
# job against the oidc_cache table.
#
# Image size: ~12 MB (Alpine base + postgresql-client)
# Idle memory: < 5 MB (BusyBox crond + sh)
#
# Why crond runs as root
# ──────────────────────
# BusyBox crond must start as root — it calls setuid/setgid to switch to the
# crontab owner before executing each job.  Launching it as an unprivileged
# user always fails with "Permission denied".
#
# The job script (vacuum.sh) is still executed as the unprivileged `cronuser`
# via `su-exec` inside the crontab line, so the PostgreSQL client process never
# runs with elevated privileges.
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

# Install the PostgreSQL client (psql), tini as a minimal init process, and
# su-exec to drop privileges when running the job script.
# tini ensures crond receives SIGTERM correctly and exits cleanly.
RUN apk add --no-cache \
        postgresql17-client \
        su-exec \
        tini \
    && rm -rf /var/cache/apk/*

# Copy the entrypoint that writes the crontab and starts crond.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Copy the vacuum script that psql executes.
COPY vacuum.sh /usr/local/bin/vacuum.sh
RUN chmod +x /usr/local/bin/vacuum.sh

# Create the unprivileged user that owns the job process at runtime.
# crond itself stays root; su-exec drops to cronuser before exec-ing vacuum.sh.
RUN addgroup -S cronuser && adduser -S cronuser -G cronuser

# crond must run as root — no USER directive here.

# tini is PID 1; it reaps zombies and forwards signals to crond.
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]
