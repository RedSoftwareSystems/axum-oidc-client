#!/bin/sh
# vacuum.sh
# ──────────────────────────────────────────────────────────────────────────────
# Scheduled maintenance script executed by crond inside the sqlite-vacuum-cron
# container.
#
# What it does
# ────────────
#   1. Logs a timestamped start banner to stdout (forwarded to Docker logs).
#   2. Reports database file size and page statistics BEFORE maintenance.
#   3. Runs VACUUM against the oidc_cache database via sqlite3.
#      - VACUUM   : rewrites the entire database file into a new, compacted file,
#                   reclaiming all free pages left by DELETE operations.
#                   SQLite does not have a MVCC dead-tuple model — deleted rows
#                   leave free pages that are reused for future inserts but are
#                   not returned to the OS until VACUUM runs.
#   4. Runs PRAGMA optimize to refresh the query planner statistics.
#      - PRAGMA optimize : SQLite's equivalent of PostgreSQL ANALYZE.  It runs
#                          ANALYZE on any table whose statistics are stale
#                          (determined by SQLite's internal heuristics) without
#                          rewriting the database file.  This keeps the query
#                          planner accurate after large expiry waves.
#   5. Reports database file size AFTER maintenance.
#   6. Logs the exit code and a completion banner.
#
# Why VACUUM instead of VACUUM INTO?
# ───────────────────────────────────
# VACUUM rewrites the database in-place (using a temporary copy) and is the
# standard way to reclaim space.  VACUUM INTO writes to a separate file, which
# is useful for backups but does not shrink the original file.
#
# Why not WAL checkpoint instead?
# ────────────────────────────────
# A WAL checkpoint (`PRAGMA wal_checkpoint(TRUNCATE)`) only merges the WAL
# into the main database file; it does not compact free pages.  VACUUM is
# still required to reclaim space from deleted rows.
#
# Locking behaviour
# ─────────────────
# VACUUM acquires an EXCLUSIVE lock for its entire duration, which blocks all
# concurrent readers and writers.  For a session cache this is acceptable
# during off-peak hours (the default midnight schedule).  If the database is
# in WAL mode (the default for sqlx), concurrent reads are still possible
# during a checkpoint but not during VACUUM.  Schedule accordingly.
#
# Environment variables (injected by docker-compose via docker-entrypoint.sh):
#   SQLITE_DB_PATH  – absolute path to the SQLite database file
#                     (default: /data/oidc_cache.db)
# ──────────────────────────────────────────────────────────────────────────────

set -eu

SQLITE_DB_PATH="${SQLITE_DB_PATH:-/data/oidc_cache.db}"
TIMESTAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

echo "==================================================================="
echo "[sqlite-vacuum-cron] ${TIMESTAMP} — starting VACUUM + PRAGMA optimize"
echo "  db: ${SQLITE_DB_PATH}"
echo "==================================================================="

# ── Preflight: check the database file exists ─────────────────────────────────
if [ ! -f "${SQLITE_DB_PATH}" ]; then
    echo "[sqlite-vacuum-cron] WARNING: database file not found at ${SQLITE_DB_PATH} — skipping."
    echo "[sqlite-vacuum-cron] The file is created by the www-server on first connection."
    echo "[sqlite-vacuum-cron] Re-run after the server has started at least once."
    exit 0
fi

# ── Before stats ──────────────────────────────────────────────────────────────
echo "[sqlite-vacuum-cron] Database stats BEFORE maintenance:"
SIZE_BEFORE="$(du -sh "${SQLITE_DB_PATH}" | cut -f1)"
echo "  file size : ${SIZE_BEFORE}"

sqlite3 "${SQLITE_DB_PATH}" <<'SQL'
-- Page statistics before vacuum.
SELECT
    'page_count'      AS metric, page_count      AS value FROM pragma_page_count
UNION ALL SELECT
    'freelist_count'  AS metric, freelist_count  AS value FROM pragma_freelist_count
UNION ALL SELECT
    'page_size_bytes' AS metric, page_size       AS value FROM pragma_page_size;
SQL

# ── VACUUM ────────────────────────────────────────────────────────────────────
# Rewrites the database into a new compacted file, returning all free pages
# to the OS.  Acquires an EXCLUSIVE lock for the duration.
echo "[sqlite-vacuum-cron] Running VACUUM ..."
sqlite3 "${SQLITE_DB_PATH}" "VACUUM;"
VACUUM_EXIT=$?

if [ "${VACUUM_EXIT}" -ne 0 ]; then
    echo "[sqlite-vacuum-cron] ERROR: VACUUM failed (exit ${VACUUM_EXIT})" >&2
    exit "${VACUUM_EXIT}"
fi

echo "[sqlite-vacuum-cron] VACUUM completed (exit 0)."

# ── PRAGMA optimize ───────────────────────────────────────────────────────────
# Refreshes query planner statistics for tables whose statistics are stale.
# Equivalent to a selective ANALYZE — only runs on tables that need it.
# Safe to run while the database is in active use (shared lock only).
echo "[sqlite-vacuum-cron] Running PRAGMA optimize ..."
sqlite3 "${SQLITE_DB_PATH}" "PRAGMA optimize;"
OPTIMIZE_EXIT=$?

if [ "${OPTIMIZE_EXIT}" -ne 0 ]; then
    echo "[sqlite-vacuum-cron] ERROR: PRAGMA optimize failed (exit ${OPTIMIZE_EXIT})" >&2
    exit "${OPTIMIZE_EXIT}"
fi

echo "[sqlite-vacuum-cron] PRAGMA optimize completed (exit 0)."

# ── After stats ───────────────────────────────────────────────────────────────
echo "[sqlite-vacuum-cron] Database stats AFTER maintenance:"
SIZE_AFTER="$(du -sh "${SQLITE_DB_PATH}" | cut -f1)"
echo "  file size : ${SIZE_AFTER}  (was: ${SIZE_BEFORE})"

sqlite3 "${SQLITE_DB_PATH}" <<'SQL'
-- Page statistics after vacuum.
SELECT
    'page_count'      AS metric, page_count      AS value FROM pragma_page_count
UNION ALL SELECT
    'freelist_count'  AS metric, freelist_count  AS value FROM pragma_freelist_count
UNION ALL SELECT
    'page_size_bytes' AS metric, page_size       AS value FROM pragma_page_size;
SQL

# ── Done ──────────────────────────────────────────────────────────────────────
DONE_TIMESTAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "[sqlite-vacuum-cron] ${DONE_TIMESTAMP} — VACUUM + PRAGMA optimize completed successfully (exit 0)"
exit 0
