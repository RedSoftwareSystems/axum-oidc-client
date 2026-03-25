#!/bin/sh
# docker-entrypoint.sh
# ──────────────────────────────────────────────────────────────────────────────
# Entrypoint for the sqlite-vacuum-cron container.
#
# Responsibilities:
#   1. Verify the SQLite database file is accessible (wait up to 60 s for the
#      volume mount to appear — the sample-server creates the file on first
#      connection, so we skip waiting if it does not exist yet and let the
#      cron job handle a missing file gracefully).
#   2. Write /etc/crontabs/cronuser with the VACUUM_SCHEDULE cron expression.
#   3. Start BusyBox crond in the foreground so the container stays alive and
#      Docker can manage its lifecycle cleanly.
#
# Why crond runs as root / why su-exec is used
# ─────────────────────────────────────────────
# BusyBox crond must be started as root — it calls setuid/setgid to switch to
# the crontab owner before executing each job.  The actual job (vacuum.sh) is
# invoked via `su-exec cronuser` so the sqlite3 process never runs with
# elevated privileges.
#
# Unlike the PostgreSQL and MySQL sidecars there are no credentials to protect,
# but we still drop privileges so the sqlite3 process cannot modify anything
# outside the mounted volume.
#
# Environment variables (injected by docker-compose):
#   SQLITE_DB_PATH   – absolute path to the SQLite database file
#                      (default: /data/oidc_cache.db)
#   VACUUM_SCHEDULE  – 5-field cron expression  (default: "0 0 * * *")
# ──────────────────────────────────────────────────────────────────────────────

set -eu

# ── Defaults ──────────────────────────────────────────────────────────────────
SQLITE_DB_PATH="${SQLITE_DB_PATH:-/data/oidc_cache.db}"
VACUUM_SCHEDULE="${VACUUM_SCHEDULE:-0 0 * * *}"

CRONUSER_HOME="$(getent passwd cronuser | cut -d: -f6)"

# ── Wait for the database file ────────────────────────────────────────────────
# The database file is created by the sample-server on first connection, not by
# this container.  We wait up to 60 s for it to appear so the first scheduled
# job does not fail immediately on a freshly provisioned stack.  If it still
# does not exist after the wait we log a warning and continue — the cron job
# itself will skip the VACUUM gracefully if the file is absent.
echo "[sqlite-vacuum-cron] Waiting for database file at ${SQLITE_DB_PATH} ..."
RETRIES=30
until [ -f "${SQLITE_DB_PATH}" ] || [ "${RETRIES}" -eq 0 ]; do
    RETRIES=$((RETRIES - 1))
    echo "[sqlite-vacuum-cron] Database file not found yet — retrying in 2 s (${RETRIES} retries left) ..."
    sleep 2
done

if [ -f "${SQLITE_DB_PATH}" ]; then
    echo "[sqlite-vacuum-cron] Database file found: ${SQLITE_DB_PATH}"
else
    echo "[sqlite-vacuum-cron] WARNING: database file not found after wait — cron job will retry on schedule."
fi

# Ensure cronuser can read and write the database file and its directory once
# the file exists.  The volume is mounted as root; we need group/other write
# permission or cronuser ownership on the file for sqlite3 to open it.
# We use chmod g+rw on the data directory so cronuser (a member of no special
# group) can at least create the WAL / journal side-files.
DB_DIR="$(dirname "${SQLITE_DB_PATH}")"
chmod o+rwx "${DB_DIR}" 2>/dev/null || true
if [ -f "${SQLITE_DB_PATH}" ]; then
    chmod o+rw "${SQLITE_DB_PATH}" 2>/dev/null || true
fi

# ── Write crontab ─────────────────────────────────────────────────────────────
# /etc/crontabs/ is owned by root and writable by root — no permission issues.
# The job is prefixed with `su-exec cronuser` so vacuum.sh runs unprivileged.
# crond executes jobs with a minimal environment; SQLITE_DB_PATH and HOME must
# be set explicitly so vacuum.sh finds the database file and its home dir.
CRONTAB_FILE="/etc/crontabs/cronuser"

cat > "${CRONTAB_FILE}" <<EOF
# VACUUM + PRAGMA optimize oidc_cache — schedule: ${VACUUM_SCHEDULE}
# Generated automatically by docker-entrypoint.sh at container startup.
# To change the schedule set VACUUM_SCHEDULE in docker-compose.sqlite.yml and restart.
${VACUUM_SCHEDULE} HOME=${CRONUSER_HOME} SQLITE_DB_PATH=${SQLITE_DB_PATH} su-exec cronuser /usr/local/bin/vacuum.sh >> /proc/1/fd/1 2>> /proc/1/fd/2
EOF

chmod 600 "${CRONTAB_FILE}"

echo "[sqlite-vacuum-cron] Crontab written to ${CRONTAB_FILE}:"
echo "  ${VACUUM_SCHEDULE}  su-exec cronuser /usr/local/bin/vacuum.sh"

# ── Start crond in foreground ─────────────────────────────────────────────────
# -f  run in foreground (do not daemonise — Docker needs the process alive)
# -l 8 log level 8 = debug (captures job start/stop in container logs)
# -L /dev/stdout redirects crond's own log to stdout so `docker logs` shows it
echo "[sqlite-vacuum-cron] Starting crond (schedule: '${VACUUM_SCHEDULE}') ..."
exec crond -f -l 8 -L /dev/stdout
