//! Database schema definitions for the SQL cache backend.
//!
//! Each supported database has its own DDL because, while the logical schema is
//! identical, the syntax for index creation and column types differs slightly
//! between PostgreSQL, MySQL/MariaDB, and SQLite.
//!
//! All DDL is intentionally minimal: a single table with three columns plus one
//! index on `expires_at` to keep cleanup queries fast.
//!
//! # Table layout
//!
//! ```text
//! oidc_cache
//! ┌─────────────────────────────────────────────────────────────────┐
//! │ cache_key   VARCHAR(255) PRIMARY KEY                            │
//! │ cache_value TEXT         NOT NULL                               │
//! │ expires_at  BIGINT       NOT NULL  (Unix timestamp, seconds)    │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! Key prefixes used at runtime:
//! - `cv:{challenge_state}` – PKCE code verifier entries
//! - `session:{session_id}` – auth-session entries

// ─── PostgreSQL ───────────────────────────────────────────────────────────────

/// DDL to create the cache table and index on PostgreSQL.
///
/// Uses `IF NOT EXISTS` so it is safe to call on every startup.
/// `BIGINT` maps to an 8-byte integer, sufficient for Unix timestamps well
/// beyond the year 2100.
///
/// The table is declared `UNLOGGED` because it holds ephemeral cache data
/// (PKCE code verifiers and auth sessions) that does not need to survive a
/// crash or server restart.  `UNLOGGED` tables skip WAL writes, which gives
/// significantly higher write throughput and lower I/O at the cost of the
/// table being truncated automatically after a crash recovery.  This is the
/// correct trade-off for a cache: on restart the application simply
/// re-authenticates any affected sessions.
#[cfg(feature = "sql-cache-postgres")]
pub const POSTGRES_CREATE_TABLE: &str = r#"
CREATE UNLOGGED TABLE IF NOT EXISTS oidc_cache (
    cache_key   VARCHAR(255) PRIMARY KEY,
    cache_value TEXT         NOT NULL,
    expires_at  BIGINT       NOT NULL
);
"#;

#[cfg(feature = "sql-cache-postgres")]
pub const POSTGRES_CREATE_INDEX: &str = r#"
CREATE INDEX IF NOT EXISTS idx_oidc_cache_expires
    ON oidc_cache (expires_at);
"#;

// ─── MySQL / MariaDB ──────────────────────────────────────────────────────────

/// DDL to create the cache table and index on MySQL / MariaDB.
///
/// `BIGINT` is 8 bytes on MySQL too.  The charset is set to `utf8mb4` on the
/// `cache_key` column to allow arbitrary Unicode identifiers.  The `TEXT`
/// column uses the connection's default charset (typically `utf8mb4` in modern
/// MySQL configurations).
///
/// `ENGINE=InnoDB` is specified explicitly for row-level locking and ACID
/// semantics under concurrent access.
#[cfg(feature = "sql-cache-mysql")]
pub const MYSQL_CREATE_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS oidc_cache (
    cache_key   VARCHAR(255) CHARACTER SET utf8mb4 NOT NULL,
    cache_value TEXT                               NOT NULL,
    expires_at  BIGINT                             NOT NULL,
    PRIMARY KEY (cache_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"#;

#[cfg(feature = "sql-cache-mysql")]
pub const MYSQL_CREATE_INDEX: &str = r#"
CREATE INDEX idx_oidc_cache_expires ON oidc_cache (expires_at);
"#;

// ─── SQLite ───────────────────────────────────────────────────────────────────

/// DDL to create the cache table and index on SQLite.
///
/// SQLite uses dynamic typing; `BIGINT` and `VARCHAR(255)` are accepted as
/// type affinity hints.  `IF NOT EXISTS` guards both the table and the index.
///
/// For production SQLite deployments, enabling WAL mode via a `PRAGMA` before
/// opening connections is recommended to improve read/write concurrency.
#[cfg(feature = "sql-cache-sqlite")]
pub const SQLITE_CREATE_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS oidc_cache (
    cache_key   TEXT    NOT NULL PRIMARY KEY,
    cache_value TEXT    NOT NULL,
    expires_at  INTEGER NOT NULL
);
"#;

#[cfg(feature = "sql-cache-sqlite")]
pub const SQLITE_CREATE_INDEX: &str = r#"
CREATE INDEX IF NOT EXISTS idx_oidc_cache_expires
    ON oidc_cache (expires_at);
"#;
