#!/bin/sh
# docker-entrypoint.sh
# ──────────────────────────────────────────────────────────────────────────────
# Entrypoint for the mysql-optimize-cron container.
#
# Responsibilities:
#   1. Write ~cronuser/.my.cnf so mysql/mysqladmin can connect without a
#      password on the command line (credentials never appear in process
#      args or logs).
#   2. Wait for MySQL to accept connections (up to 60 s).
#   3. Write /etc/crontabs/cronuser with the OPTIMIZE_SCHEDULE cron expression.
#   4. Start BusyBox crond in the foreground so the container stays alive and
#      Docker can manage its lifecycle cleanly.
#
# Why crond runs as root / why su-exec is used
# ─────────────────────────────────────────────
# BusyBox crond must be started as root — it calls setuid/setgid to switch to
# the crontab owner before executing each job.  The actual job (optimize.sh) is
# invoked via `su-exec cronuser` so the mysql process never runs with elevated
# privileges.  Credentials are written to cronuser's home (/home/cronuser) so
# they are readable by the dropped-privilege process, not by root only.
#
# Environment variables (injected by docker-compose):
#   MYSQL_USER          – database user
#   MYSQL_PASSWORD      – database password (written to ~cronuser/.my.cnf)
#   MYSQL_DATABASE      – database / schema name
#   MYSQL_HOST          – MySQL hostname
#   MYSQL_PORT_INNER    – MySQL port                (default: 3306)
#   OPTIMIZE_SCHEDULE   – 5-field cron expression   (default: "0 0 * * *")
# ──────────────────────────────────────────────────────────────────────────────

set -eu

# ── Defaults ──────────────────────────────────────────────────────────────────
MYSQL_PORT_INNER="${MYSQL_PORT_INNER:-3306}"
OPTIMIZE_SCHEDULE="${OPTIMIZE_SCHEDULE:-0 0 * * *}"

CRONUSER_HOME="$(getent passwd cronuser | cut -d: -f6)"

# ── ~/.my.cnf — passwordless mysql / mysqladmin ───────────────────────────────
# Written to cronuser's home so the su-exec'd process can read it.
# The [client] group is read by all MySQL client programs.
# Storing credentials here avoids --password flags that would appear in `ps`
# output and container logs.
MY_CNF_FILE="${CRONUSER_HOME}/.my.cnf"
cat > "${MY_CNF_FILE}" <<EOF
[client]
host     = ${MYSQL_HOST}
port     = ${MYSQL_PORT_INNER}
user     = ${MYSQL_USER}
password = ${MYSQL_PASSWORD}
database = ${MYSQL_DATABASE}
EOF
chown cronuser:cronuser "${MY_CNF_FILE}"
chmod 600 "${MY_CNF_FILE}"

# ── Wait for MySQL to be ready ────────────────────────────────────────────────
echo "[mysql-optimize-cron] Waiting for MySQL at ${MYSQL_HOST}:${MYSQL_PORT_INNER} ..."
RETRIES=30
until mysqladmin ping \
        --host="${MYSQL_HOST}" \
        --port="${MYSQL_PORT_INNER}" \
        --silent \
      2>/dev/null \
      || [ "${RETRIES}" -eq 0 ]; do
    RETRIES=$((RETRIES - 1))
    echo "[mysql-optimize-cron] MySQL not ready yet — retrying in 2 s (${RETRIES} retries left) ..."
    sleep 2
done

if [ "${RETRIES}" -eq 0 ]; then
    echo "[mysql-optimize-cron] ERROR: MySQL did not become ready in time. Exiting."
    exit 1
fi

echo "[mysql-optimize-cron] MySQL is ready."

# ── Write crontab ─────────────────────────────────────────────────────────────
# /etc/crontabs/ is owned by root and writable by root — no permission issues.
# The job is prefixed with `su-exec cronuser` so optimize.sh runs unprivileged.
# crond executes jobs with a minimal environment; HOME must be set explicitly
# so mysql can find ~cronuser/.my.cnf.
CRONTAB_FILE="/etc/crontabs/cronuser"

cat > "${CRONTAB_FILE}" <<EOF
# OPTIMIZE + ANALYZE oidc_cache — schedule: ${OPTIMIZE_SCHEDULE}
# Generated automatically by docker-entrypoint.sh at container startup.
# To change the schedule set OPTIMIZE_SCHEDULE in docker-compose.mysql.yml and restart.
${OPTIMIZE_SCHEDULE} HOME=${CRONUSER_HOME} su-exec cronuser /usr/local/bin/optimize.sh >> /proc/1/fd/1 2>> /proc/1/fd/2
EOF

chmod 600 "${CRONTAB_FILE}"

echo "[mysql-optimize-cron] Crontab written to ${CRONTAB_FILE}:"
echo "  ${OPTIMIZE_SCHEDULE}  su-exec cronuser /usr/local/bin/optimize.sh"

# ── Start crond in foreground ─────────────────────────────────────────────────
# -f  run in foreground (do not daemonise — Docker needs the process alive)
# -l 8 log level 8 = debug (captures job start/stop in container logs)
# -L /dev/stdout redirects crond's own log to stdout so `docker logs` shows it
echo "[mysql-optimize-cron] Starting crond (schedule: '${OPTIMIZE_SCHEDULE}') ..."
exec crond -f -l 8 -L /dev/stdout
