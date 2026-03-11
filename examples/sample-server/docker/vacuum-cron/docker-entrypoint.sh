#!/bin/sh
# docker-entrypoint.sh
# ──────────────────────────────────────────────────────────────────────────────
# Entrypoint for the vacuum-cron container.
#
# Responsibilities:
#   1. Wait for PostgreSQL to accept connections (up to 60 s).
#   2. Write a crontab for the `cronuser` account using the VACUUM_SCHEDULE
#      environment variable (default: "0 0 * * *" — every day at midnight UTC).
#   3. Start BusyBox crond in the foreground so the container stays alive and
#      Docker can manage its lifecycle cleanly.
#
# Environment variables (injected by docker-compose):
#   POSTGRES_USER      – database user
#   POSTGRES_PASSWORD  – database password (written to ~/.pgpass)
#   POSTGRES_DB        – database name
#   PGHOST             – PostgreSQL hostname
#   PGPORT             – PostgreSQL port          (default: 5432)
#   VACUUM_SCHEDULE    – 5-field cron expression  (default: "0 0 * * *")
# ──────────────────────────────────────────────────────────────────────────────

set -eu

# ── Defaults ──────────────────────────────────────────────────────────────────
PGPORT="${PGPORT:-5432}"
VACUUM_SCHEDULE="${VACUUM_SCHEDULE:-0 0 * * *}"

# ── .pgpass — passwordless psql ───────────────────────────────────────────────
# Format: hostname:port:database:username:password
PGPASS_FILE="${HOME}/.pgpass"
printf '%s:%s:%s:%s:%s\n' \
    "${PGHOST}" \
    "${PGPORT}" \
    "${POSTGRES_DB}" \
    "${POSTGRES_USER}" \
    "${POSTGRES_PASSWORD}" \
    > "${PGPASS_FILE}"
chmod 600 "${PGPASS_FILE}"

# ── Wait for PostgreSQL to be ready ──────────────────────────────────────────
echo "[vacuum-cron] Waiting for PostgreSQL at ${PGHOST}:${PGPORT} ..."
RETRIES=30
until pg_isready \
        --host="${PGHOST}" \
        --port="${PGPORT}" \
        --username="${POSTGRES_USER}" \
        --dbname="${POSTGRES_DB}" \
        --quiet \
      || [ "${RETRIES}" -eq 0 ]; do
    RETRIES=$((RETRIES - 1))
    echo "[vacuum-cron] PostgreSQL not ready yet — retrying in 2 s (${RETRIES} retries left) ..."
    sleep 2
done

if [ "${RETRIES}" -eq 0 ]; then
    echo "[vacuum-cron] ERROR: PostgreSQL did not become ready in time. Exiting."
    exit 1
fi

echo "[vacuum-cron] PostgreSQL is ready."

# ── Write crontab ─────────────────────────────────────────────────────────────
# BusyBox crond reads per-user crontabs from /var/spool/cron/crontabs/<user>.
# We write directly to that file so no `crontab` binary interaction is needed.
CRONTAB_DIR="/var/spool/cron/crontabs"
CRONTAB_FILE="${CRONTAB_DIR}/cronuser"

# The directory may not be writable by a non-root user in some Alpine images.
# In practice, the official Alpine image creates this directory with 1777
# (world-writable with sticky bit) so cronuser can write its own file.
mkdir -p "${CRONTAB_DIR}" 2>/dev/null || true

cat > "${CRONTAB_FILE}" <<EOF
# VACUUM ANALYZE oidc_cache — schedule: ${VACUUM_SCHEDULE}
# Generated automatically by docker-entrypoint.sh at container startup.
# To change the schedule set VACUUM_SCHEDULE in docker-compose.postgres.yml and restart.
${VACUUM_SCHEDULE} /usr/local/bin/vacuum.sh >> /proc/1/fd/1 2>> /proc/1/fd/2
EOF

echo "[vacuum-cron] Crontab written to ${CRONTAB_FILE}:"
echo "  ${VACUUM_SCHEDULE}  /usr/local/bin/vacuum.sh"

# ── Start crond in foreground ─────────────────────────────────────────────────
# -f  run in foreground (do not daemonise — Docker needs the process alive)
# -l 8 log level 8 = debug (captures job start/stop in container logs)
# -L /dev/stdout redirects crond's own log to stdout so `docker logs` shows it
echo "[vacuum-cron] Starting crond (schedule: '${VACUUM_SCHEDULE}') ..."
exec crond -f -l 8 -L /dev/stdout
