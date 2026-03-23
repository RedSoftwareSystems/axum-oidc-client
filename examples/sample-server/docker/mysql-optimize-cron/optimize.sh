#!/bin/sh
# optimize.sh
# ──────────────────────────────────────────────────────────────────────────────
# Scheduled maintenance script executed by crond inside the mysql-optimize-cron
# container.
#
# What it does
# ────────────
#   1. Logs a timestamped start banner to stdout (forwarded to Docker logs).
#   2. Queries table status BEFORE the maintenance run so the log shows the
#      current fragmentation / data-free state.
#   3. Runs OPTIMIZE TABLE oidc_cache.
#      - Rebuilds the InnoDB tablespace from scratch, eliminating page
#        fragmentation left by bulk DELETEs.  Equivalent to:
#          ALTER TABLE oidc_cache ENGINE=InnoDB;
#      - Acquires a brief metadata lock; safe during off-peak hours.
#   4. Runs ANALYZE TABLE oidc_cache.
#      - Refreshes InnoDB index statistics so the query optimiser continues
#        to choose the idx_oidc_cache_expires index for cleanup and
#        TTL-filtered reads after the row distribution has shifted.
#   5. Queries table status AFTER maintenance to confirm fragmentation dropped.
#   6. Logs exit code and a completion banner.
#
# Why OPTIMIZE TABLE and not just ANALYZE TABLE?
# ───────────────────────────────────────────────
# InnoDB's background purge thread reclaims undo log space from deleted rows
# automatically (unlike PostgreSQL which needs VACUUM).  However, bulk DELETEs
# leave gaps (fragmented free pages) in the InnoDB B-tree that accumulate over
# time.  OPTIMIZE TABLE rebuilds the entire table, reclaiming those pages and
# shrinking the on-disk .ibd file.  ANALYZE TABLE alone does not reclaim space.
#
# Why not use the MySQL Event Scheduler?
# ──────────────────────────────────────
# The Event Scheduler requires superuser privileges to create events and ties
# maintenance logic to the database schema.  This external cron approach is
# self-contained, observable via `docker logs`, and independently restartable.
#
# Authentication
# ──────────────
# mysql reads credentials from ~/.my.cnf (written by docker-entrypoint.sh,
# mode 600) so no password appears in process arguments or logs.
#
# Environment variables (all provided by docker-compose via the parent entrypoint):
#   MYSQL_USER      – database user   (used only for the log banner)
#   MYSQL_DATABASE  – database name   (used only for the log banner)
#   MYSQL_HOST      – MySQL hostname  (used only for the log banner)
#   MYSQL_PORT_INNER – MySQL port     (default: 3306, used only for the log banner)
# ──────────────────────────────────────────────────────────────────────────────

set -eu

MYSQL_PORT_INNER="${MYSQL_PORT_INNER:-3306}"
TIMESTAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

echo "==================================================================="
echo "[mysql-optimize-cron] ${TIMESTAMP} — starting OPTIMIZE + ANALYZE oidc_cache"
echo "  host: ${MYSQL_HOST}:${MYSQL_PORT_INNER}  db: ${MYSQL_DATABASE}  user: ${MYSQL_USER}"
echo "==================================================================="

# ── Before stats ──────────────────────────────────────────────────────────────
echo "[mysql-optimize-cron] Table status BEFORE maintenance:"
mysql \
    --database="${MYSQL_DATABASE}" \
    --batch \
    --vertical \
    --execute="
SELECT
    table_name                                      AS table_name,
    table_rows                                      AS approx_row_count,
    ROUND(data_length  / 1024 / 1024, 3)            AS data_mb,
    ROUND(index_length / 1024 / 1024, 3)            AS index_mb,
    ROUND(data_free    / 1024 / 1024, 3)            AS free_mb,
    create_time,
    update_time
FROM information_schema.tables
WHERE table_schema = DATABASE()
  AND table_name   = 'oidc_cache';

SELECT
    index_name,
    stat_name,
    stat_value,
    sample_size
FROM mysql.innodb_index_stats
WHERE database_name = DATABASE()
  AND table_name    = 'oidc_cache'
ORDER BY index_name, stat_name;
"

# ── OPTIMIZE TABLE ─────────────────────────────────────────────────────────────
# Rebuilds the InnoDB tablespace: defragments pages, reclaims free space,
# and rebuilds all secondary indexes.
# Equivalent to: ALTER TABLE oidc_cache ENGINE=InnoDB;
# Returns a result set — capture it so it appears in the log.
echo "[mysql-optimize-cron] Running OPTIMIZE TABLE oidc_cache ..."
mysql \
    --database="${MYSQL_DATABASE}" \
    --batch \
    --execute="OPTIMIZE TABLE oidc_cache;"

# ── ANALYZE TABLE ──────────────────────────────────────────────────────────────
# Refreshes index statistics used by the InnoDB query optimiser.
# Should always be run after OPTIMIZE TABLE because the rebuild changes the
# internal page layout and row counts.
echo "[mysql-optimize-cron] Running ANALYZE TABLE oidc_cache ..."
mysql \
    --database="${MYSQL_DATABASE}" \
    --batch \
    --execute="ANALYZE TABLE oidc_cache;"

# ── After stats ───────────────────────────────────────────────────────────────
echo "[mysql-optimize-cron] Table status AFTER maintenance:"
mysql \
    --database="${MYSQL_DATABASE}" \
    --batch \
    --vertical \
    --execute="
SELECT
    table_name                                      AS table_name,
    table_rows                                      AS approx_row_count,
    ROUND(data_length  / 1024 / 1024, 3)            AS data_mb,
    ROUND(index_length / 1024 / 1024, 3)            AS index_mb,
    ROUND(data_free    / 1024 / 1024, 3)            AS free_mb,
    create_time,
    update_time
FROM information_schema.tables
WHERE table_schema = DATABASE()
  AND table_name   = 'oidc_cache';
"

EXIT_CODE=$?

DONE_TIMESTAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if [ "${EXIT_CODE}" -eq 0 ]; then
    echo "[mysql-optimize-cron] ${DONE_TIMESTAMP} — OPTIMIZE + ANALYZE completed successfully (exit 0)"
else
    echo "[mysql-optimize-cron] ${DONE_TIMESTAMP} — OPTIMIZE + ANALYZE FAILED (exit ${EXIT_CODE})" >&2
fi

exit "${EXIT_CODE}"
