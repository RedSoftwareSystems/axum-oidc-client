//! Background cleanup task for the SQL cache backend.
//!
//! Expired cache entries are never automatically removed by the database itself
//! (unlike Redis TTL keys).  This module provides a lightweight Tokio task that
//! periodically deletes rows whose `expires_at` timestamp is in the past.
//!
//! ## Design
//!
//! The task runs in a `tokio::spawn`ed loop and sleeps between iterations for
//! `cleanup_interval_sec` seconds (configurable via [`super::config::SqlCacheConfig`]).
//! Each wake-up deletes expired rows in bounded batches of
//! [`CLEANUP_BATCH_SIZE`] rows until no more expired rows remain.  Batching
//! prevents a single large `DELETE` from holding a table lock for too long
//! under high-concurrency workloads.
//!
//! The task holds only an `Arc` to the connection pool, so it does not prevent
//! the pool from being dropped if the rest of the application shuts down.  A
//! [`tokio::sync::CancellationToken`] is used for graceful shutdown.
//!
//! ## Lazy deletion
//!
//! `SELECT` queries in [`super::mod`] always include an `expires_at > now`
//! predicate, so expired entries are effectively invisible even before the
//! background task removes them.  The task therefore only needs to run often
//! enough to reclaim storage – correctness does not depend on it.
//!
//! ## PostgreSQL: VACUUM after bulk deletes
//!
//! PostgreSQL uses MVCC (Multi-Version Concurrency Control): a `DELETE`
//! statement does not immediately free disk pages — it marks rows as "dead"
//! tuples that are reclaimed only when a `VACUUM` pass runs over the table.
//! On a high-churn cache table this can cause the table to bloat if dead
//! tuples accumulate faster than `autovacuum` reclaims them.
//!
//! **Autovacuum** (enabled by default in all modern PostgreSQL installations)
//! will eventually reclaim dead tuples automatically, but for a dedicated
//! cache table with high write/delete throughput it is good practice to:
//!
//! 1. **Tune `autovacuum` aggressively** for the cache table so it triggers
//!    more often than on regular tables:
//!
//!    ```sql
//!    -- Run once after creating the table (idempotent — safe to re-apply).
//!    ALTER TABLE oidc_cache SET (
//!        autovacuum_vacuum_scale_factor    = 0.01,  -- vacuum after 1 % of rows change (default 20 %)
//!        autovacuum_analyze_scale_factor   = 0.01,  -- analyze after 1 % of rows change
//!        autovacuum_vacuum_cost_delay      = 2       -- ms; lower = faster vacuum, more I/O
//!    );
//!    ```
//!
//! 2. **Schedule a manual `VACUUM`** outside peak hours to keep the table
//!    lean, especially after large expiry waves (e.g. after a mass logout):
//!
//!    ```sql
//!    -- Reclaim dead tuples without locking the table (safe for production).
//!    VACUUM oidc_cache;
//!
//!    -- Also update planner statistics in the same pass.
//!    VACUUM ANALYZE oidc_cache;
//!
//!    -- Full rewrite — reclaims the most space but takes an exclusive lock.
//!    -- Only use during a maintenance window with no live traffic.
//!    VACUUM FULL oidc_cache;
//!    ```
//!
//!    A typical cron entry (runs `VACUUM ANALYZE` every night at 03:00):
//!
//!    ```text
//!    0 3 * * *  psql -U myuser -d mydb -c "VACUUM ANALYZE oidc_cache;"
//!    ```
//!
//!    Or using `pg_cron` (the PostgreSQL scheduler extension) entirely inside
//!    the database — no external cron job required:
//!
//!    ```sql
//!    -- Install pg_cron once per database cluster (superuser required).
//!    CREATE EXTENSION IF NOT EXISTS pg_cron;
//!
//!    -- Schedule VACUUM ANALYZE every night at 03:00 server time.
//!    SELECT cron.schedule(
//!        'vacuum-oidc-cache',          -- job name (unique)
//!        '0 3 * * *',                  -- cron expression
//!        'VACUUM ANALYZE oidc_cache'   -- SQL to run
//!    );
//!
//!    -- List scheduled jobs.
//!    SELECT * FROM cron.job;
//!
//!    -- Remove the job if no longer needed.
//!    SELECT cron.unschedule('vacuum-oidc-cache');
//!    ```
//!
//! > **Note:** Because the cache table is declared `UNLOGGED`, PostgreSQL
//! > already skips WAL writes for all DML.  `VACUUM` itself is not WAL-logged
//! > either, so the combination of `UNLOGGED` + regular `VACUUM` gives the
//! > best trade-off between write performance, storage efficiency, and query
//! > planner accuracy.

use std::time::Duration;

use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

/// Maximum number of expired rows deleted per database round-trip.
///
/// Keeping this value modest (≤ 1 000) prevents long-running transactions and
/// avoids excessive lock pressure on the cache table.
pub const CLEANUP_BATCH_SIZE: i64 = 1_000;

// ─── PostgreSQL cleanup task ──────────────────────────────────────────────────

#[cfg(feature = "sql-cache-postgres")]
pub(super) fn spawn_postgres(
    pool: sqlx::Pool<sqlx::Postgres>,
    table: String,
    interval_sec: u64,
    token: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    use crate::authentication::sql_cache::queries::cleanup_query;

    tokio::spawn(async move {
        let interval = Duration::from_secs(interval_sec);
        let query_str = cleanup_query(&table);

        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    tracing::debug!("sql-cache postgres cleanup task: shutdown requested");
                    break;
                }
                _ = sleep(interval) => {}
            }

            let now = chrono::Utc::now().timestamp();

            loop {
                match sqlx::query(&query_str)
                    .bind(now)
                    .bind(CLEANUP_BATCH_SIZE)
                    .execute(&pool)
                    .await
                {
                    Ok(result) if result.rows_affected() == 0 => break,
                    Ok(result) => {
                        tracing::trace!(
                            rows = result.rows_affected(),
                            "sql-cache postgres cleanup: deleted expired entries"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "sql-cache postgres cleanup: failed to delete expired entries"
                        );
                        break;
                    }
                }
            }
        }
    })
}

// ─── MySQL / MariaDB cleanup task ─────────────────────────────────────────────

#[cfg(feature = "sql-cache-mysql")]
pub(super) fn spawn_mysql(
    pool: sqlx::Pool<sqlx::MySql>,
    table: String,
    interval_sec: u64,
    token: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    use crate::authentication::sql_cache::queries::mysql_cleanup_query;

    tokio::spawn(async move {
        let interval = Duration::from_secs(interval_sec);
        let query_str = mysql_cleanup_query(&table);

        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    tracing::debug!("sql-cache mysql cleanup task: shutdown requested");
                    break;
                }
                _ = sleep(interval) => {}
            }

            let now = chrono::Utc::now().timestamp();

            loop {
                match sqlx::query(&query_str)
                    .bind(now)
                    .bind(CLEANUP_BATCH_SIZE)
                    .execute(&pool)
                    .await
                {
                    Ok(result) if result.rows_affected() == 0 => break,
                    Ok(result) => {
                        tracing::trace!(
                            rows = result.rows_affected(),
                            "sql-cache mysql cleanup: deleted expired entries"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "sql-cache mysql cleanup: failed to delete expired entries"
                        );
                        break;
                    }
                }
            }
        }
    })
}

// ─── SQLite cleanup task ──────────────────────────────────────────────────────

#[cfg(feature = "sql-cache-sqlite")]
pub(super) fn spawn_sqlite(
    pool: sqlx::Pool<sqlx::Sqlite>,
    table: String,
    interval_sec: u64,
    token: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    use crate::authentication::sql_cache::queries::sqlite_cleanup_query;

    tokio::spawn(async move {
        let interval = Duration::from_secs(interval_sec);
        let query_str = sqlite_cleanup_query(&table);

        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    tracing::debug!("sql-cache sqlite cleanup task: shutdown requested");
                    break;
                }
                _ = sleep(interval) => {}
            }

            let now = chrono::Utc::now().timestamp();

            loop {
                match sqlx::query(&query_str)
                    .bind(now)
                    .bind(CLEANUP_BATCH_SIZE)
                    .execute(&pool)
                    .await
                {
                    Ok(result) if result.rows_affected() == 0 => break,
                    Ok(result) => {
                        tracing::trace!(
                            rows = result.rows_affected(),
                            "sql-cache sqlite cleanup: deleted expired entries"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "sql-cache sqlite cleanup: failed to delete expired entries"
                        );
                        break;
                    }
                }
            }
        }
    })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_batch_size_is_positive() {
        assert!(CLEANUP_BATCH_SIZE > 0);
    }

    #[test]
    fn cleanup_batch_size_is_reasonable() {
        // Ensure the constant stays in a sane range (1 – 10 000).
        assert!(CLEANUP_BATCH_SIZE <= 10_000);
    }

    /// Verify that a `CancellationToken` can be cancelled without blocking.
    ///
    /// This is a smoke-test for the shutdown path; the actual background tasks
    /// are exercised in integration tests that spin up a real database.
    #[tokio::test]
    async fn cancellation_token_cancels_immediately() {
        let token = CancellationToken::new();
        token.cancel();
        assert!(token.is_cancelled());
    }
}
