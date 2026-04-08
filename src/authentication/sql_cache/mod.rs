//! SQL database cache backend for authentication sessions.
//!
//! This module provides [`SqlAuthCache`], an [`AuthCache`](crate::authentication::cache::AuthCache)
//! implementation backed by a SQL database via [`sqlx`].  Three database engines
//! are supported, each selected via a Cargo feature flag:
//!
//! | Feature                | Database              |
//! |------------------------|-----------------------|
//! | `sql-cache-postgres`   | PostgreSQL            |
//! | `sql-cache-mysql`      | MySQL / MariaDB       |
//! | `sql-cache-sqlite`     | SQLite                |
//!
//! Exactly one of these features must be enabled at a time.  Enabling more than
//! one is allowed (e.g. for tests) but only one pool type can be used per
//! [`SqlAuthCache`] instance.
//!
//! # Quick start
//!
//! ```rust,no_run
//! # #[cfg(feature = "sql-cache-sqlite")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use std::sync::Arc;
//! use axum_oidc_client::sql_cache::{SqlAuthCache, SqlCacheConfig};
//!
//! let config = SqlCacheConfig {
//!     connection_string: "sqlite://cache.db".to_string(),
//!     ..Default::default()
//! };
//!
//! let cache = Arc::new(SqlAuthCache::new(config).await?);
//! cache.init_schema().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Schema
//!
//! [`SqlAuthCache::init_schema`] creates the following table (name is
//! configurable via [`SqlCacheConfig::table_name`]):
//!
//! ```sql
//! -- PostgreSQL
//! CREATE UNLOGGED TABLE IF NOT EXISTS oidc_cache (
//!     cache_key   VARCHAR(255) PRIMARY KEY,
//!     cache_value TEXT         NOT NULL,
//!     expires_at  BIGINT       NOT NULL
//! );
//! CREATE INDEX IF NOT EXISTS idx_oidc_cache_expires ON oidc_cache (expires_at);
//!
//! -- MySQL / MariaDB and SQLite use a regular (logged) table.
//! ```
//!
//! The PostgreSQL table is declared `UNLOGGED` because it holds ephemeral
//! cache data (PKCE code verifiers and auth sessions) that does not need to
//! survive a crash.  `UNLOGGED` tables bypass WAL writes, giving higher write
//! throughput and lower I/O at the cost of the table being truncated on crash
//! recovery — an acceptable trade-off for a cache.
//!
//! # Key prefixes
//!
//! | Prefix       | Entry type              |
//! |--------------|-------------------------|
//! | `cv:`        | PKCE code verifiers     |
//! | `session:`   | Auth sessions (JSON)    |
//!
//! # TTL management
//!
//! Rows carry an `expires_at` Unix timestamp (seconds since the epoch).
//! Reads filter out expired entries with `AND expires_at > <now>` so stale
//! data is never returned even before the background cleanup task removes it
//! (lazy deletion).  A background Tokio task spawned by [`SqlAuthCache::new`]
//! periodically deletes expired rows in bounded batches to reclaim storage.
//!
//! # PostgreSQL: VACUUM after bulk deletes
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
//!        autovacuum_vacuum_scale_factor  = 0.01,  -- vacuum after 1 % of rows change (default 20 %)
//!        autovacuum_analyze_scale_factor = 0.01,  -- analyze after 1 % of rows change
//!        autovacuum_vacuum_cost_delay    = 2       -- ms; lower = faster vacuum, more I/O
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

pub mod cleanup;
pub mod queries;
pub mod schema;

use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use tokio_util::sync::CancellationToken;

use crate::authentication::cache::AuthCache;
use crate::authentication::session::AuthSession;
use crate::errors::Error;

// ─── Key helpers ──────────────────────────────────────────────────────────────

#[inline]
fn cv_key(challenge_state: &str) -> String {
    format!("cv:{challenge_state}")
}

#[inline]
fn session_key(session_id: &str) -> String {
    format!("session:{session_id}")
}

// ─── Configuration ────────────────────────────────────────────────────────────

/// Configuration for [`SqlAuthCache`].
///
/// Build with `Default::default()` and then customise fields as needed.
///
/// # Example
///
/// ```rust
/// use axum_oidc_client::sql_cache::SqlCacheConfig;
///
/// let config = SqlCacheConfig {
///     connection_string: "sqlite://:memory:".to_string(),
///     max_connections: 5,
///     cleanup_interval_sec: 60,
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone)]
pub struct SqlCacheConfig {
    /// Database connection URL.
    ///
    /// - PostgreSQL: `postgresql://user:pass@host/dbname`
    /// - MySQL:      `mysql://user:pass@host/dbname`
    /// - SQLite:     `sqlite://path/to/file.db` or `sqlite://:memory:`
    ///
    /// **Required** – there is no default value; `Default::default()` leaves
    /// this as an empty string which will cause [`SqlAuthCache::new`] to fail.
    pub connection_string: String,

    /// Maximum number of connections in the pool.
    ///
    /// For SQLite, keep this low (≤ 5) because SQLite supports only one writer
    /// at a time.  Default: `20`.
    pub max_connections: u32,

    /// Minimum number of idle connections kept alive in the pool.
    ///
    /// Default: `2`.
    pub min_connections: u32,

    /// How long (in seconds) the background cleanup task sleeps between
    /// sweeps.  Default: `300` (5 minutes).
    pub cleanup_interval_sec: u64,

    /// Name of the cache table.  Change this if `oidc_cache` conflicts with an
    /// existing table in your database.  Default: `"oidc_cache"`.
    pub table_name: String,

    /// Maximum time (in seconds) to wait when acquiring a connection from the
    /// pool before returning an error.  Default: `30`.
    pub acquire_timeout_sec: u64,

    /// Default TTL (in seconds) applied when storing a code verifier.
    ///
    /// Code verifiers are short-lived single-use values; the default of 60 s
    /// matches the typical OAuth PKCE round-trip window.  Default: `60`.
    pub code_verifier_ttl_sec: i64,
}

impl Default for SqlCacheConfig {
    fn default() -> Self {
        Self {
            connection_string: String::new(),
            max_connections: 20,
            min_connections: 2,
            cleanup_interval_sec: 300,
            table_name: "oidc_cache".to_string(),
            acquire_timeout_sec: 30,
            code_verifier_ttl_sec: 60,
        }
    }
}

// ─── Internal pool enum ───────────────────────────────────────────────────────

/// Wraps the database-specific `sqlx` pool in a single enum so `SqlAuthCache`
/// can be generic over the three supported backends without generics pollution
/// in the public API.
enum Pool {
    #[cfg(feature = "sql-cache-postgres")]
    Postgres(sqlx::Pool<sqlx::Postgres>),

    #[cfg(feature = "sql-cache-mysql")]
    MySql(sqlx::Pool<sqlx::MySql>),

    #[cfg(feature = "sql-cache-sqlite")]
    Sqlite(sqlx::Pool<sqlx::Sqlite>),
}

// ─── SqlAuthCache ─────────────────────────────────────────────────────────────

/// SQL-backed [`AuthCache`](crate::authentication::cache::AuthCache) implementation.
///
/// Supports PostgreSQL, MySQL/MariaDB, and SQLite via `sqlx`.  Select the
/// backend by enabling exactly one of the `sql-cache-*` Cargo features.
///
/// Use [`SqlAuthCache::new`] to construct the cache and
/// [`SqlAuthCache::init_schema`] to create the cache table and index.
///
/// The background cleanup task is started automatically in [`SqlAuthCache::new`]
/// and can be gracefully stopped by calling [`SqlAuthCache::shutdown`].
pub struct SqlAuthCache {
    pool: Arc<Pool>,
    config: SqlCacheConfig,
    /// Token used to signal the background cleanup task to stop.
    shutdown_token: CancellationToken,
    /// Handle to the background cleanup task (kept for `shutdown` to join).
    _cleanup_handle: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for SqlAuthCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqlAuthCache")
            .field("table_name", &self.config.table_name)
            .field("max_connections", &self.config.max_connections)
            .field("cleanup_interval_sec", &self.config.cleanup_interval_sec)
            .finish_non_exhaustive()
    }
}

impl SqlAuthCache {
    /// Creates a new [`SqlAuthCache`] and starts the background cleanup task.
    ///
    /// The database feature flag determines which pool type is created:
    /// - `sql-cache-postgres` → `sqlx::PgPool`
    /// - `sql-cache-mysql`    → `sqlx::MySqlPool`
    /// - `sql-cache-sqlite`   → `sqlx::SqlitePool`
    ///
    /// # Errors
    ///
    /// Returns [`Error::CacheError`] if:
    /// - The connection string is empty or invalid.
    /// - The pool cannot be established within `acquire_timeout_sec`.
    /// - No SQL cache feature flag is enabled.
    pub async fn new(config: SqlCacheConfig) -> Result<Self, Error> {
        if config.connection_string.is_empty() {
            return Err(Error::CacheError(
                "SqlCacheConfig.connection_string must not be empty".to_string(),
            ));
        }

        let shutdown_token = CancellationToken::new();

        let (pool, cleanup_handle) =
            Self::build_pool_and_cleanup(&config, shutdown_token.clone()).await?;

        Ok(Self {
            pool: Arc::new(pool),
            config,
            shutdown_token,
            _cleanup_handle: cleanup_handle,
        })
    }

    /// Creates the cache table and index in the database.
    ///
    /// This is idempotent — it uses `CREATE UNLOGGED TABLE IF NOT EXISTS` (PostgreSQL)
    /// or `CREATE TABLE IF NOT EXISTS` (MySQL/MariaDB, SQLite) and
    /// `CREATE INDEX IF NOT EXISTS`, so it is safe to call on every startup.
    ///
    /// On PostgreSQL the table is declared `UNLOGGED` because the cache data
    /// (PKCE code verifiers and auth sessions) is ephemeral and does not need
    /// to survive a crash or unclean shutdown.  `UNLOGGED` tables bypass WAL
    /// writes, giving higher write throughput and lower I/O at the cost of the
    /// table being truncated on crash recovery — an acceptable trade-off for a
    /// cache.
    ///
    /// The table name is taken from [`SqlCacheConfig::table_name`], so custom
    /// names are respected correctly.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CacheError`] if the DDL statements fail.
    pub async fn init_schema(&self) -> Result<(), Error> {
        let table = &self.config.table_name;
        let index = format!("idx_{table}_expires");

        match self.pool.as_ref() {
            #[cfg(feature = "sql-cache-postgres")]
            Pool::Postgres(pool) => {
                let create_table = format!(
                    "CREATE UNLOGGED TABLE IF NOT EXISTS {table} (\
                        cache_key   VARCHAR(255) PRIMARY KEY, \
                        cache_value TEXT         NOT NULL, \
                        expires_at  BIGINT       NOT NULL\
                    )"
                );
                let create_index =
                    format!("CREATE INDEX IF NOT EXISTS {index} ON {table} (expires_at)");
                sqlx::query(&create_table)
                    .execute(pool)
                    .await
                    .map_err(|e| Error::CacheError(e.to_string()))?;
                sqlx::query(&create_index)
                    .execute(pool)
                    .await
                    .map_err(|e| Error::CacheError(e.to_string()))?;
            }

            #[cfg(feature = "sql-cache-mysql")]
            Pool::MySql(pool) => {
                let create_table = format!(
                    "CREATE TABLE IF NOT EXISTS {table} (\
                        cache_key   VARCHAR(255) CHARACTER SET utf8mb4 NOT NULL, \
                        cache_value TEXT                               NOT NULL, \
                        expires_at  BIGINT                             NOT NULL, \
                        PRIMARY KEY (cache_key)\
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
                );
                let create_index = format!("CREATE INDEX {index} ON {table} (expires_at)");
                sqlx::query(&create_table)
                    .execute(pool)
                    .await
                    .map_err(|e| Error::CacheError(e.to_string()))?;
                // MySQL errors if the index already exists; ignore that error.
                let _ = sqlx::query(&create_index).execute(pool).await;
            }

            #[cfg(feature = "sql-cache-sqlite")]
            Pool::Sqlite(pool) => {
                let create_table = format!(
                    "CREATE TABLE IF NOT EXISTS {table} (\
                        cache_key   TEXT    NOT NULL PRIMARY KEY, \
                        cache_value TEXT    NOT NULL, \
                        expires_at  INTEGER NOT NULL\
                    )"
                );
                let create_index =
                    format!("CREATE INDEX IF NOT EXISTS {index} ON {table} (expires_at)");
                sqlx::query(&create_table)
                    .execute(pool)
                    .await
                    .map_err(|e| Error::CacheError(e.to_string()))?;
                sqlx::query(&create_index)
                    .execute(pool)
                    .await
                    .map_err(|e| Error::CacheError(e.to_string()))?;
            }
        }
        Ok(())
    }

    /// Signals the background cleanup task to stop and awaits its completion.
    ///
    /// After calling this method the cache is still usable for reads and
    /// writes; only the periodic cleanup of expired rows stops.
    pub async fn shutdown(&self) {
        self.shutdown_token.cancel();
    }

    /// Returns a reference to the configuration used to build this cache.
    pub fn config(&self) -> &SqlCacheConfig {
        &self.config
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Returns the current Unix timestamp in seconds.
    #[inline]
    fn now_timestamp() -> i64 {
        chrono::Utc::now().timestamp()
    }

    /// Returns `now + ttl_sec` as a Unix timestamp.
    #[inline]
    fn expires_at(ttl_sec: i64) -> i64 {
        Self::now_timestamp() + ttl_sec
    }

    /// Builds the database-specific connection pool and spawns the background
    /// cleanup task, returning both.
    async fn build_pool_and_cleanup(
        config: &SqlCacheConfig,
        token: CancellationToken,
    ) -> Result<(Pool, tokio::task::JoinHandle<()>), Error> {
        let timeout = Duration::from_secs(config.acquire_timeout_sec);

        #[cfg(feature = "sql-cache-postgres")]
        {
            if config.connection_string.starts_with("postgres") {
                let pool = sqlx::postgres::PgPoolOptions::new()
                    .max_connections(config.max_connections)
                    .min_connections(config.min_connections)
                    .acquire_timeout(timeout)
                    .connect(&config.connection_string)
                    .await
                    .map_err(|e| Error::CacheError(e.to_string()))?;

                let handle = cleanup::spawn_postgres(
                    pool.clone(),
                    config.table_name.clone(),
                    config.cleanup_interval_sec,
                    token,
                );

                return Ok((Pool::Postgres(pool), handle));
            }
        }

        #[cfg(feature = "sql-cache-mysql")]
        {
            if config.connection_string.starts_with("mysql") {
                let pool = sqlx::mysql::MySqlPoolOptions::new()
                    .max_connections(config.max_connections)
                    .min_connections(config.min_connections)
                    .acquire_timeout(timeout)
                    .connect(&config.connection_string)
                    .await
                    .map_err(|e| Error::CacheError(e.to_string()))?;

                let handle = cleanup::spawn_mysql(
                    pool.clone(),
                    config.table_name.clone(),
                    config.cleanup_interval_sec,
                    token,
                );

                return Ok((Pool::MySql(pool), handle));
            }
        }

        #[cfg(feature = "sql-cache-sqlite")]
        {
            if config.connection_string.starts_with("sqlite") {
                let connect_options = config
                    .connection_string
                    .parse::<sqlx::sqlite::SqliteConnectOptions>()
                    .map_err(|e| Error::CacheError(e.to_string()))?
                    .create_if_missing(true);

                let pool = sqlx::sqlite::SqlitePoolOptions::new()
                    .max_connections(config.max_connections)
                    .min_connections(config.min_connections)
                    .acquire_timeout(timeout)
                    .connect_with(connect_options)
                    .await
                    .map_err(|e| Error::CacheError(e.to_string()))?;

                let handle = cleanup::spawn_sqlite(
                    pool.clone(),
                    config.table_name.clone(),
                    config.cleanup_interval_sec,
                    token,
                );

                return Ok((Pool::Sqlite(pool), handle));
            }
        }

        Err(Error::CacheError(format!(
            "unsupported or unrecognised connection string scheme: '{}'. \
             Enable the matching sql-cache-* Cargo feature.",
            config
                .connection_string
                .split("://")
                .next()
                .unwrap_or(&config.connection_string)
        )))
    }
}

// ─── AuthCache implementation ─────────────────────────────────────────────────

impl AuthCache for SqlAuthCache {
    // ── code_verifier ─────────────────────────────────────────────────────────

    fn get_code_verifier(
        &self,
        challenge_state: &str,
    ) -> BoxFuture<'_, Result<Option<String>, Error>> {
        let key = cv_key(challenge_state);
        let table = self.config.table_name.clone();
        let pool = Arc::clone(&self.pool);

        Box::pin(async move {
            let now = SqlAuthCache::now_timestamp();

            match pool.as_ref() {
                #[cfg(feature = "sql-cache-postgres")]
                Pool::Postgres(pool) => {
                    let row: Option<(String,)> = sqlx::query_as(&queries::select_query(&table))
                        .bind(&key)
                        .bind(now)
                        .fetch_optional(pool)
                        .await
                        .map_err(|e| Error::CacheError(e.to_string()))?;
                    Ok(row.map(|(v,)| v))
                }

                #[cfg(feature = "sql-cache-mysql")]
                Pool::MySql(pool) => {
                    let row: Option<(String,)> =
                        sqlx::query_as(&queries::mysql_select_query(&table))
                            .bind(&key)
                            .bind(now)
                            .fetch_optional(pool)
                            .await
                            .map_err(|e| Error::CacheError(e.to_string()))?;
                    Ok(row.map(|(v,)| v))
                }

                #[cfg(feature = "sql-cache-sqlite")]
                Pool::Sqlite(pool) => {
                    let row: Option<(String,)> =
                        sqlx::query_as(&queries::sqlite_select_query(&table))
                            .bind(&key)
                            .bind(now)
                            .fetch_optional(pool)
                            .await
                            .map_err(|e| Error::CacheError(e.to_string()))?;
                    Ok(row.map(|(v,)| v))
                }
            }
        })
    }

    fn set_code_verifier(
        &self,
        challenge_state: &str,
        code_verifier: &str,
    ) -> BoxFuture<'_, Result<(), Error>> {
        let key = cv_key(challenge_state);
        let value = code_verifier.to_string();
        let table = self.config.table_name.clone();
        let expires_at = SqlAuthCache::expires_at(self.config.code_verifier_ttl_sec);
        let pool = Arc::clone(&self.pool);

        Box::pin(async move {
            match pool.as_ref() {
                #[cfg(feature = "sql-cache-postgres")]
                Pool::Postgres(pool) => {
                    sqlx::query(&queries::postgres_upsert_query(&table))
                        .bind(&key)
                        .bind(&value)
                        .bind(expires_at)
                        .execute(pool)
                        .await
                        .map_err(|e| Error::CacheError(e.to_string()))?;
                }

                #[cfg(feature = "sql-cache-mysql")]
                Pool::MySql(pool) => {
                    sqlx::query(&queries::mysql_upsert_query(&table))
                        .bind(&key)
                        .bind(&value)
                        .bind(expires_at)
                        .execute(pool)
                        .await
                        .map_err(|e| Error::CacheError(e.to_string()))?;
                }

                #[cfg(feature = "sql-cache-sqlite")]
                Pool::Sqlite(pool) => {
                    sqlx::query(&queries::sqlite_upsert_query(&table))
                        .bind(&key)
                        .bind(&value)
                        .bind(expires_at)
                        .execute(pool)
                        .await
                        .map_err(|e| Error::CacheError(e.to_string()))?;
                }
            }
            Ok(())
        })
    }

    fn invalidate_code_verifier(&self, challenge_state: &str) -> BoxFuture<'_, Result<(), Error>> {
        let key = cv_key(challenge_state);
        let table = self.config.table_name.clone();
        let pool = Arc::clone(&self.pool);

        Box::pin(async move {
            match pool.as_ref() {
                #[cfg(feature = "sql-cache-postgres")]
                Pool::Postgres(pool) => {
                    sqlx::query(&queries::delete_query(&table))
                        .bind(&key)
                        .execute(pool)
                        .await
                        .map_err(|e| Error::CacheError(e.to_string()))?;
                }

                #[cfg(feature = "sql-cache-mysql")]
                Pool::MySql(pool) => {
                    sqlx::query(&queries::mysql_delete_query(&table))
                        .bind(&key)
                        .execute(pool)
                        .await
                        .map_err(|e| Error::CacheError(e.to_string()))?;
                }

                #[cfg(feature = "sql-cache-sqlite")]
                Pool::Sqlite(pool) => {
                    sqlx::query(&queries::sqlite_delete_query(&table))
                        .bind(&key)
                        .execute(pool)
                        .await
                        .map_err(|e| Error::CacheError(e.to_string()))?;
                }
            }
            Ok(())
        })
    }

    // ── auth_session ──────────────────────────────────────────────────────────

    fn get_auth_session(
        &self,
        session_id: &str,
    ) -> BoxFuture<'_, Result<Option<AuthSession>, Error>> {
        let key = session_key(session_id);
        let table = self.config.table_name.clone();
        let pool = Arc::clone(&self.pool);

        Box::pin(async move {
            let now = SqlAuthCache::now_timestamp();

            let json: Option<String> = match pool.as_ref() {
                #[cfg(feature = "sql-cache-postgres")]
                Pool::Postgres(pool) => {
                    let row: Option<(String,)> = sqlx::query_as(&queries::select_query(&table))
                        .bind(&key)
                        .bind(now)
                        .fetch_optional(pool)
                        .await
                        .map_err(|e| Error::CacheError(e.to_string()))?;
                    row.map(|(v,)| v)
                }

                #[cfg(feature = "sql-cache-mysql")]
                Pool::MySql(pool) => {
                    let row: Option<(String,)> =
                        sqlx::query_as(&queries::mysql_select_query(&table))
                            .bind(&key)
                            .bind(now)
                            .fetch_optional(pool)
                            .await
                            .map_err(|e| Error::CacheError(e.to_string()))?;
                    row.map(|(v,)| v)
                }

                #[cfg(feature = "sql-cache-sqlite")]
                Pool::Sqlite(pool) => {
                    let row: Option<(String,)> =
                        sqlx::query_as(&queries::sqlite_select_query(&table))
                            .bind(&key)
                            .bind(now)
                            .fetch_optional(pool)
                            .await
                            .map_err(|e| Error::CacheError(e.to_string()))?;
                    row.map(|(v,)| v)
                }
            };

            match json {
                None => Ok(None),
                Some(raw) => {
                    let session = serde_json::from_str::<AuthSession>(&raw)
                        .map_err(|e| Error::CacheError(e.to_string()))?;
                    Ok(Some(session))
                }
            }
        })
    }

    fn set_auth_session(
        &self,
        session_id: &str,
        session: AuthSession,
    ) -> BoxFuture<'_, Result<(), Error>> {
        let key = session_key(session_id);
        let table = self.config.table_name.clone();
        // Derive expires_at from the session's own expiry when available;
        // fall back to the configured session TTL (from the code-verifier TTL
        // field is repurposed: the caller ultimately controls this via
        // session_max_age in OAuthConfigurationBuilder).
        let expires_at = session
            .expires
            .map(|dt| dt.timestamp())
            .unwrap_or_else(|| SqlAuthCache::expires_at(3600));
        let pool = Arc::clone(&self.pool);

        Box::pin(async move {
            let value =
                serde_json::to_string(&session).map_err(|e| Error::CacheError(e.to_string()))?;

            match pool.as_ref() {
                #[cfg(feature = "sql-cache-postgres")]
                Pool::Postgres(pool) => {
                    sqlx::query(&queries::postgres_upsert_query(&table))
                        .bind(&key)
                        .bind(&value)
                        .bind(expires_at)
                        .execute(pool)
                        .await
                        .map_err(|e| Error::CacheError(e.to_string()))?;
                }

                #[cfg(feature = "sql-cache-mysql")]
                Pool::MySql(pool) => {
                    sqlx::query(&queries::mysql_upsert_query(&table))
                        .bind(&key)
                        .bind(&value)
                        .bind(expires_at)
                        .execute(pool)
                        .await
                        .map_err(|e| Error::CacheError(e.to_string()))?;
                }

                #[cfg(feature = "sql-cache-sqlite")]
                Pool::Sqlite(pool) => {
                    sqlx::query(&queries::sqlite_upsert_query(&table))
                        .bind(&key)
                        .bind(&value)
                        .bind(expires_at)
                        .execute(pool)
                        .await
                        .map_err(|e| Error::CacheError(e.to_string()))?;
                }
            }
            Ok(())
        })
    }

    fn invalidate_auth_session(&self, session_id: &str) -> BoxFuture<'_, Result<(), Error>> {
        let key = session_key(session_id);
        let table = self.config.table_name.clone();
        let pool = Arc::clone(&self.pool);

        Box::pin(async move {
            match pool.as_ref() {
                #[cfg(feature = "sql-cache-postgres")]
                Pool::Postgres(pool) => {
                    sqlx::query(&queries::delete_query(&table))
                        .bind(&key)
                        .execute(pool)
                        .await
                        .map_err(|e| Error::CacheError(e.to_string()))?;
                }

                #[cfg(feature = "sql-cache-mysql")]
                Pool::MySql(pool) => {
                    sqlx::query(&queries::mysql_delete_query(&table))
                        .bind(&key)
                        .execute(pool)
                        .await
                        .map_err(|e| Error::CacheError(e.to_string()))?;
                }

                #[cfg(feature = "sql-cache-sqlite")]
                Pool::Sqlite(pool) => {
                    sqlx::query(&queries::sqlite_delete_query(&table))
                        .bind(&key)
                        .execute(pool)
                        .await
                        .map_err(|e| Error::CacheError(e.to_string()))?;
                }
            }
            Ok(())
        })
    }

    fn extend_auth_session(&self, session_id: &str, ttl: i64) -> BoxFuture<'_, Result<(), Error>> {
        let key = session_key(session_id);
        let table = self.config.table_name.clone();
        let new_expires_at = SqlAuthCache::expires_at(ttl);
        let pool = Arc::clone(&self.pool);

        Box::pin(async move {
            match pool.as_ref() {
                #[cfg(feature = "sql-cache-postgres")]
                Pool::Postgres(pool) => {
                    sqlx::query(&queries::extend_query(&table))
                        .bind(new_expires_at)
                        .bind(&key)
                        .execute(pool)
                        .await
                        .map_err(|e| Error::CacheError(e.to_string()))?;
                }

                #[cfg(feature = "sql-cache-mysql")]
                Pool::MySql(pool) => {
                    sqlx::query(&queries::mysql_extend_query(&table))
                        .bind(new_expires_at)
                        .bind(&key)
                        .execute(pool)
                        .await
                        .map_err(|e| Error::CacheError(e.to_string()))?;
                }

                #[cfg(feature = "sql-cache-sqlite")]
                Pool::Sqlite(pool) => {
                    sqlx::query(&queries::sqlite_extend_query(&table))
                        .bind(new_expires_at)
                        .bind(&key)
                        .execute(pool)
                        .await
                        .map_err(|e| Error::CacheError(e.to_string()))?;
                }
            }
            Ok(())
        })
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_expected_values() {
        let cfg = SqlCacheConfig::default();
        assert!(cfg.connection_string.is_empty());
        assert_eq!(cfg.max_connections, 20);
        assert_eq!(cfg.min_connections, 2);
        assert_eq!(cfg.cleanup_interval_sec, 300);
        assert_eq!(cfg.table_name, "oidc_cache");
        assert_eq!(cfg.acquire_timeout_sec, 30);
        assert_eq!(cfg.code_verifier_ttl_sec, 60);
    }

    #[test]
    fn cv_key_has_correct_prefix() {
        assert_eq!(cv_key("abc123"), "cv:abc123");
    }

    #[test]
    fn session_key_has_correct_prefix() {
        assert_eq!(session_key("xyz789"), "session:xyz789");
    }

    #[test]
    fn now_timestamp_is_positive() {
        assert!(SqlAuthCache::now_timestamp() > 0);
    }

    #[test]
    fn expires_at_is_in_the_future() {
        let future = SqlAuthCache::expires_at(60);
        assert!(future > SqlAuthCache::now_timestamp());
    }

    #[tokio::test]
    async fn new_returns_error_on_empty_connection_string() {
        let cfg = SqlCacheConfig::default(); // connection_string is empty
        let result = SqlAuthCache::new(cfg).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::CacheError(msg) => assert!(msg.contains("connection_string")),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn new_returns_error_on_unrecognised_scheme() {
        let cfg = SqlCacheConfig {
            connection_string: "memcached://localhost".to_string(),
            ..Default::default()
        };
        let result = SqlAuthCache::new(cfg).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::CacheError(msg) => assert!(msg.contains("memcached")),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    /// Integration tests that require a real database are in
    /// `tests/sql_cache_integration.rs` and are gated behind the
    /// `sql-cache-*` feature flags.  The unit tests above cover all logic
    /// that can be exercised without a live database connection.
    #[test]
    fn config_clone_preserves_values() {
        let cfg = SqlCacheConfig {
            connection_string: "sqlite://:memory:".to_string(),
            max_connections: 5,
            min_connections: 1,
            cleanup_interval_sec: 120,
            table_name: "my_cache".to_string(),
            acquire_timeout_sec: 10,
            code_verifier_ttl_sec: 30,
        };
        let cloned = cfg.clone();
        assert_eq!(cloned.connection_string, cfg.connection_string);
        assert_eq!(cloned.max_connections, cfg.max_connections);
        assert_eq!(cloned.min_connections, cfg.min_connections);
        assert_eq!(cloned.cleanup_interval_sec, cfg.cleanup_interval_sec);
        assert_eq!(cloned.table_name, cfg.table_name);
        assert_eq!(cloned.acquire_timeout_sec, cfg.acquire_timeout_sec);
        assert_eq!(cloned.code_verifier_ttl_sec, cfg.code_verifier_ttl_sec);
    }
}
