#!/bin/sh
# vacuum.sh
# ──────────────────────────────────────────────────────────────────────────────
# Scheduled maintenance script executed by crond inside the vacuum-cron
# container.
#
# What it does
# ────────────
#   1. Logs a timestamped start banner to stdout (forwarded to Docker logs).
#   2. Runs VACUUM ANALYZE on the oidc_cache table via psql.
#      - VACUUM   : reclaims disk space occupied by dead tuples left by
#                   DELETE operations (PostgreSQL MVCC).
#      - ANALYZE  : updates planner statistics so query plans stay accurate
#                   after bulk deletes.
#   3. Logs the psql exit code and a completion banner.
#
# Why not VACUUM FULL?
# ────────────────────
# VACUUM FULL rewrites the entire table to disk and holds an ACCESS EXCLUSIVE
# lock for the duration, blocking all reads and writes.  For an active session
# cache that is unacceptable.  Plain VACUUM (without FULL) reclaims dead-tuple
# slots for reuse without any table lock beyond a brief ShareUpdateExclusiveLock
# that does not block normal DML.
#
# Authentication
# ──────────────
# psql reads credentials from ~/.pgpass (written by docker-entrypoint.sh) so
# no password appears in process arguments or logs.
#
# Environment variables (all provided by docker-compose via the parent entrypoint):
#   POSTGRES_USER   – database user
#   POSTGRES_DB     – database name
#   PGHOST          – PostgreSQL hostname
#   PGPORT          – PostgreSQL port (default: 5432)
# ──────────────────────────────────────────────────────────────────────────────

set -eu

PGPORT="${PGPORT:-5432}"
TIMESTAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

echo "==================================================================="
echo "[vacuum-cron] ${TIMESTAMP} — starting VACUUM ANALYZE oidc_cache"
echo "  host: ${PGHOST}:${PGPORT}  db: ${POSTGRES_DB}  user: ${POSTGRES_USER}"
echo "==================================================================="

# Run VACUUM ANALYZE.
# --no-psqlrc   : skip any ~/.psqlrc that might alter output format.
# --no-align    : machine-readable output (not strictly needed but clean).
# --tuples-only : suppress column headers.
# -v ON_ERROR_STOP=1 : exit with a non-zero status if the SQL fails.
psql \
    --host="${PGHOST}" \
    --port="${PGPORT}" \
    --username="${POSTGRES_USER}" \
    --dbname="${POSTGRES_DB}" \
    --no-psqlrc \
    -v ON_ERROR_STOP=1 \
    <<'SQL'
-- Report dead-tuple count before the vacuum so the log is informative.
SELECT
    relname                          AS table_name,
    n_dead_tup                       AS dead_tuples_before,
    n_live_tup                       AS live_tuples,
    last_vacuum                      AS last_vacuum,
    last_autovacuum                  AS last_autovacuum,
    last_analyze                     AS last_analyze,
    last_autoanalyze                 AS last_autoanalyze
FROM pg_stat_user_tables
WHERE relname = 'oidc_cache';

-- Reclaim dead tuples and refresh planner statistics.
-- Does NOT take an exclusive lock; concurrent reads and writes proceed normally.
VACUUM ANALYZE oidc_cache;

-- Report table size and dead-tuple count after the vacuum.
SELECT
    relname                          AS table_name,
    n_dead_tup                       AS dead_tuples_after,
    n_live_tup                       AS live_tuples,
    pg_size_pretty(
        pg_total_relation_size(relid)
    )                                AS total_size,
    last_vacuum                      AS last_vacuum,
    last_analyze                     AS last_analyze
FROM pg_stat_user_tables
WHERE relname = 'oidc_cache';
SQL

EXIT_CODE=$?

DONE_TIMESTAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if [ "${EXIT_CODE}" -eq 0 ]; then
    echo "[vacuum-cron] ${DONE_TIMESTAMP} — VACUUM ANALYZE completed successfully (exit 0)"
else
    echo "[vacuum-cron] ${DONE_TIMESTAMP} — VACUUM ANALYZE FAILED (exit ${EXIT_CODE})" >&2
fi

exit "${EXIT_CODE}"
