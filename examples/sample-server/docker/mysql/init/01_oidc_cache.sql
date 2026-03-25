-- 01_oidc_cache.sql
-- MySQL 8.0 initialisation script for the axum-oidc-client session cache.
--
-- Executed automatically by the official mysql Docker image on the very
-- first container startup (files in /docker-entrypoint-initdb.d are run once,
-- in lexicographic order, when the data directory is empty).
--
-- What this script does
-- ─────────────────────
-- 1. Selects the target database (created automatically by the MySQL image
--    when MYSQL_DATABASE is set in the container environment).
--
-- 2. Creates the `oidc_cache` InnoDB table that stores:
--      • PKCE code verifiers  (cache_key prefix: "cv:")
--      • Serialised auth sessions (cache_key prefix: "session:")
--
-- 3. Creates an index on `expires_at` so the background cleanup task and the
--    lazy-expiry read filter (`WHERE expires_at > <now>`) stay fast even with
--    millions of rows.
--
-- 4. Sets InnoDB row-format and stats options for a high-churn cache table.
--
-- InnoDB vs UNLOGGED (PostgreSQL comparison)
-- ───────────────────────────────────────────
-- PostgreSQL has UNLOGGED tables that bypass WAL for ephemeral data.
-- MySQL has no direct equivalent, but the combination of:
--   • innodb_flush_log_at_trx_commit=2  (set server-wide in docker-compose)
--   • STATS_PERSISTENT=0                (per-table: do not persist index
--                                         statistics to disk on every change)
--   • ROW_FORMAT=DYNAMIC                (efficient variable-length row storage)
-- gives the best write throughput for a high-churn cache table while keeping
-- crash-recovery semantics acceptable for ephemeral cache data.
--
-- STATS_PERSISTENT=0 rationale
-- ─────────────────────────────
-- By default InnoDB persists index statistics to the `mysql.innodb_index_stats`
-- and `mysql.innodb_table_stats` system tables after every significant data
-- change.  For a cache table that is written to and deleted from continuously
-- this creates unnecessary I/O.  Setting STATS_PERSISTENT=0 keeps statistics
-- in memory only; they are recomputed on restart and after ANALYZE TABLE.
--
-- OPTIMIZE TABLE and ANALYZE TABLE rationale
-- ───────────────────────────────────────────
-- InnoDB's background purge thread reclaims undo log space from deleted rows
-- automatically (unlike PostgreSQL which needs VACUUM).  However, over time
-- bulk DELETEs leave gaps (fragmented free pages) in the InnoDB B-tree that
-- are not reused efficiently for new inserts.
--
--   OPTIMIZE TABLE oidc_cache;
--     Equivalent to ALTER TABLE … ENGINE=InnoDB — rebuilds the table and all
--     its indexes from scratch, eliminating page fragmentation and shrinking
--     the on-disk .ibd file.  Acquires a brief metadata lock; safe to run
--     during off-peak hours.
--
--   ANALYZE TABLE oidc_cache;
--     Updates InnoDB index statistics so the query optimiser keeps choosing
--     the idx_oidc_cache_expires index for cleanup and TTL-filtered reads
--     after the row distribution has shifted significantly.
--
-- The companion `mysql-optimize-cron` Docker Compose service runs both statements
-- every day at midnight (configurable via OPTIMIZE_SCHEDULE).

-- ---------------------------------------------------------------------------
-- Select database
-- ---------------------------------------------------------------------------

-- USE is executed here as a safety net.  The official MySQL Docker image
-- already switches to MYSQL_DATABASE before running init scripts, but being
-- explicit avoids accidents if the script is ever run manually.
USE `oidc_cache`;

-- ---------------------------------------------------------------------------
-- Table
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS oidc_cache (
    -- Logical cache key.
    -- Format: "cv:<challenge_state>"   for PKCE code verifiers
    --         "session:<session_id>"   for serialised AuthSession JSON
    -- CHARACTER SET utf8mb4 ensures arbitrary Unicode identifiers are stored
    -- correctly (e.g. session IDs containing non-ASCII characters).
    cache_key   VARCHAR(255) CHARACTER SET utf8mb4 NOT NULL,

    -- JSON-serialised payload (code verifier string or AuthSession struct).
    -- TEXT uses the connection's default charset (utf8mb4 in this stack).
    cache_value TEXT                               NOT NULL,

    -- Expiry as a Unix timestamp (seconds since the epoch, UTC).
    -- BIGINT (8 bytes) is sufficient for Unix timestamps well beyond 2100.
    -- Rows with expires_at <= UNIX_TIMESTAMP() are treated as expired by the
    -- application (lazy deletion) and are periodically removed by the cleanup
    -- background task.
    expires_at  BIGINT                             NOT NULL,

    PRIMARY KEY (cache_key)

) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  -- ROW_FORMAT=DYNAMIC: efficient variable-length storage for TEXT / VARCHAR
  -- columns; required for large VARCHAR primary keys in InnoDB with
  -- innodb_large_prefix enabled (default in MySQL 8).
  ROW_FORMAT=DYNAMIC
  -- STATS_PERSISTENT=0: keep index statistics in memory only.
  -- Avoids continuous writes to innodb_index_stats / innodb_table_stats for a
  -- table whose row distribution changes constantly.  Statistics are refreshed
  -- by the nightly ANALYZE TABLE job and on every server restart.
  STATS_PERSISTENT=0
  COMMENT='axum-oidc-client session / PKCE cache — managed by axum-oidc-client';

-- ---------------------------------------------------------------------------
-- Index
-- ---------------------------------------------------------------------------

-- The cleanup task issues batched DELETEs filtered by `expires_at < <now>`,
-- and the read path filters with `expires_at > <now>`.  Without this index
-- both operations degrade to full table scans once the table grows beyond a
-- few thousand rows.
--
-- MySQL errors if the index already exists (unlike PostgreSQL's IF NOT EXISTS
-- syntax for indexes), so we guard the CREATE with a DROP … IF EXISTS first.
-- In practice this block only runs once (on first container startup), but the
-- guard makes the script safely re-runnable.
DROP INDEX IF EXISTS idx_oidc_cache_expires ON oidc_cache;
CREATE INDEX idx_oidc_cache_expires ON oidc_cache (expires_at);

-- ---------------------------------------------------------------------------
-- Initial ANALYZE to seed index statistics
-- ---------------------------------------------------------------------------

-- Run ANALYZE TABLE immediately so the optimiser has accurate statistics from
-- the very first query, without waiting for the nightly mysql-optimize-cron job.
ANALYZE TABLE oidc_cache;

-- ---------------------------------------------------------------------------
-- Informational notice
-- ---------------------------------------------------------------------------

SELECT
    'oidc_cache table ready.' AS status,
    'ENGINE=InnoDB'           AS engine,
    'ROW_FORMAT=DYNAMIC'      AS row_format,
    'STATS_PERSISTENT=0'      AS stats,
    'utf8mb4_unicode_ci'      AS collation;
