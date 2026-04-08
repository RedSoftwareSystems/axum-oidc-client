-- 01_oidc_cache.sql
-- PostgreSQL 18 initialisation script for the axum-oidc-client session cache.
--
-- Executed automatically by the official postgres Docker image on the very
-- first container startup (files in /docker-entrypoint-initdb.d are run once,
-- in lexicographic order, when the data directory is empty).
--
-- What this script does
-- ─────────────────────
-- 1. Creates the `oidc_cache` UNLOGGED table that stores PKCE code verifiers
--    (prefix `cv:`) and serialised auth sessions (prefix `session:`).
--
-- 2. Creates an index on `expires_at` so the background cleanup task and the
--    lazy-expiry read filter (`WHERE expires_at > NOW`) stay fast even with
--    millions of rows.
--
-- 3. Applies aggressive per-table autovacuum storage parameters so that dead
--    tuples from high-churn cache deletes are reclaimed much sooner than the
--    conservative global defaults would trigger.
--
-- Why UNLOGGED?
-- ─────────────
-- The table holds *ephemeral* cache data.  If the database crashes, the table
-- is truncated automatically by PostgreSQL during crash recovery — exactly the
-- same behaviour as losing the in-process Moka L1 cache on a restart.  On
-- restart the application simply re-authenticates affected sessions.
-- The benefit is that every INSERT / UPDATE / DELETE skips WAL logging, giving
-- significantly higher write throughput and lower I/O pressure.
--
-- Autovacuum tuning rationale
-- ───────────────────────────
-- PostgreSQL uses MVCC: DELETE marks rows as "dead tuples" that are reclaimed
-- only when VACUUM runs.  On a cache table that is constantly written to and
-- deleted from, dead tuples accumulate rapidly.  The global autovacuum
-- thresholds (20 % of the table) are designed for large business tables and
-- are far too conservative for a small, high-churn cache table.
--
--   autovacuum_vacuum_scale_factor  = 0.01   vacuum after 1 % of rows change
--   autovacuum_analyze_scale_factor = 0.01   analyze after 1 % of rows change
--   autovacuum_vacuum_cost_delay    = 2      ms between I/O bursts (lower ⟹
--                                             faster vacuum, more I/O; 2 ms is
--                                             near full-speed)
--   autovacuum_vacuum_threshold     = 50     minimum dead tuples before vacuum
--                                             (guards against vacuuming a
--                                             near-empty table constantly)
--
-- These settings are stored in `pg_class.reloptions` and override the global
-- GUC values only for this table.  All other tables are unaffected.

-- ---------------------------------------------------------------------------
-- Table
-- ---------------------------------------------------------------------------

CREATE UNLOGGED TABLE IF NOT EXISTS oidc_cache (
    -- Logical cache key.
    -- Format: "cv:<challenge_state>"   for PKCE code verifiers
    --         "session:<session_id>"   for serialised AuthSession JSON
    cache_key   VARCHAR(255) PRIMARY KEY,

    -- JSON-serialised payload (code verifier string or AuthSession struct).
    cache_value TEXT         NOT NULL,

    -- Expiry as a Unix timestamp (seconds since the epoch, UTC).
    -- Rows with expires_at <= NOW() are treated as expired by the application
    -- (lazy deletion) and are periodically removed by the cleanup background
    -- task.
    expires_at  BIGINT       NOT NULL
);

-- ---------------------------------------------------------------------------
-- Index
-- ---------------------------------------------------------------------------

-- The cleanup task deletes rows with `expires_at < <now>` in batches and the
-- read path filters with `expires_at > <now>`.  Without this index both
-- operations become sequential scans once the table grows beyond a few
-- thousand rows.
CREATE INDEX IF NOT EXISTS idx_oidc_cache_expires
    ON oidc_cache (expires_at);

-- ---------------------------------------------------------------------------
-- Per-table autovacuum settings
-- ---------------------------------------------------------------------------
-- ALTER TABLE ... SET (...) stores parameters in pg_class.reloptions.
-- They override the corresponding autovacuum GUC values for this table only.

ALTER TABLE oidc_cache SET (
    -- Trigger VACUUM after 1 % of rows have been updated/deleted
    -- (default: 20 % — far too conservative for a cache table).
    autovacuum_vacuum_scale_factor  = 0.01,

    -- Trigger ANALYZE after 1 % of rows have changed
    -- (default: 20 %).
    autovacuum_analyze_scale_factor = 0.01,

    -- Minimum number of dead tuples before autovacuum kicks in,
    -- regardless of the scale factor.  Avoids vacuuming an almost-empty
    -- table on every single delete during low-traffic periods.
    autovacuum_vacuum_threshold     = 50,

    -- Minimum number of row insertions/updates/deletes before ANALYZE runs.
    autovacuum_analyze_threshold    = 50,

    -- Cost delay between I/O bursts during autovacuum (ms).
    -- 2 ms ≈ near full-speed; the global default is 2 ms in PG 14+ but may
    -- be higher on some distributions.  Being explicit here ensures the
    -- cache table always gets fast vacuums.
    autovacuum_vacuum_cost_delay    = 2
);

-- ---------------------------------------------------------------------------
-- Informational notice
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    RAISE NOTICE
        'oidc_cache table ready. '
        'UNLOGGED=true, autovacuum_vacuum_scale_factor=0.01, '
        'autovacuum_analyze_scale_factor=0.01, '
        'autovacuum_vacuum_cost_delay=2ms';
END;
$$;
