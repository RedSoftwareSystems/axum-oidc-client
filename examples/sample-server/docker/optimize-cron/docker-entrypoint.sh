#!/bin/sh
# docker-entrypoint.sh
# ──────────────────────────────────────────────────────────────────────────────
# Entrypoint for the optimize-cron container.
#
# Responsibilities:
#   1. Write ~/.my.cnf with credentials so mysql/mysqladmin never need
#      a password on the command line (no credentials in process args or logs).
#   2. Wait for MySQL to accept connections (up to 60 s).
#   3. Write a crontab for the `cronuser` account using the OPTIMIZE_SCHEDULE
#      environment variable (default: "0 0 * * *" — every day at midnight UTC).
#   4. Start BusyBox crond in the foreground so the container stays alive and
#      Docker can manage its lifecycle cleanly.
#
# Environment variables (injected by docker-compose):
#   MYSQL_USER          – database user
#   MYSQL_PASSWORD      – database password (written to ~/.my.cnf, mode 600)
#   MYSQL_DATABASE      – database / schema name
#   MYSQL_HOST          – MySQL hostname
#   MYSQL_PORT_INNER    – MySQL port                (default: 3306)
#   OPTIMIZE_SCHEDULE   – 5-field cron expression   (default: "0 0 * * *")
# ──────────────────────────────────────────────────────────────────────────────

set -eu

# ── Defaults ──────────────────────────────────────────────────────────────────
MYSQL_PORT_INNER="${MYSQL_PORT_INNER:-3306}"
OPTIMIZE_SCHEDULE="${OPTIMIZE_SCHEDULE:-0 0 * * *}"

# ── ~/.my.cnf — passwordless mysql / mysqladmin ───────────────────────────────
# The [client] group is read by all MySQL client programs.
# Storing credentials here avoids --password flags that would appear in `ps`
# output and container logs.
MY_CNF_FILE="${HOME}/.my.cnf"
cat > "${MY_CNF_FILE}" <<EOF
[client]
host     = ${MYSQL_HOST}
port     = ${MYSQL_PORT_INNER}
user     = ${MYSQL_USER}
password = ${MYSQL_PASSWORD}
database = ${MYSQL_DATABASE}
EOF
chmod 600 "${MY_CNF_FILE}"

# ── Wait for MySQL to be ready ────────────────────────────────────────────────
echo "[optimize-cron] Waiting for MySQL at ${MYSQL_HOST}:${MYSQL_PORT_INNER} ..."
RETRIES=30
until mysqladmin ping \
        --host="${MYSQL_HOST}" \
        --port="${MYSQL_PORT_INNER}" \
        --silent \
      2>/dev/null \
      || [ "${RETRIES}" -eq 0 ]; do
    RETRIES=$((RETRIES - 1))
    echo "[optimize-cron] MySQL not ready yet — retrying in 2 s (${RETRIES} retries left) ..."
    sleep 2
done

if [ "${RETRIES}" -eq 0 ]; then
    echo "[optimize-cron] ERROR: MySQL did not become ready in time. Exiting."
    exit 1
fi

echo "[optimize-cron] MySQL is ready."

# ── Write crontab ─────────────────────────────────────────────────────────────
# BusyBox crond reads per-user crontabs from /var/spool/cron/crontabs/<user>.
# Writing directly to that file avoids needing the `crontab` binary.
CRONTAB_DIR="/var/spool/cron/crontabs"
CRONTAB_FILE="${CRONTAB_DIR}/cronuser"

# The directory may not be writable by a non-root user in some Alpine images.
# The official Alpine image creates /var/spool/cron/crontabs with mode 1777
# (world-writable + sticky bit) so cronuser can write its own file.
mkdir -p "${CRONTAB_DIR}" 2>/dev/null || true

cat > "${CRONTAB_FILE}" <<EOF
# OPTIMIZE + ANALYZE oidc_cache — schedule: ${OPTIMIZE_SCHEDULE}
# Generated automatically by docker-entrypoint.sh at container startup.
# To change the schedule set OPTIMIZE_SCHEDULE in docker-compose.mysql.yml and restart.
${OPTIMIZE_SCHEDULE} /usr/local/bin/optimize.sh >> /proc/1/fd/1 2>> /proc/1/fd/2
EOF

echo "[optimize-cron] Crontab written to ${CRONTAB_FILE}:"
echo "  ${OPTIMIZE_SCHEDULE}  /usr/local/bin/optimize.sh"

# ── Start crond in foreground ─────────────────────────────────────────────────
# -f  run in foreground (do not daemonise — Docker needs the process alive)
# -l 8 log level 8 = debug (captures job start/stop in container logs)
# -L /dev/stdout redirects crond's own log to stdout so `docker logs` shows it
echo "[optimize-cron] Starting crond (schedule: '${OPTIMIZE_SCHEDULE}') ..."
exec crond -f -l 8 -L /dev/stdout
