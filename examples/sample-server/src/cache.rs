//! Cache construction module.
//!
//! This module exposes a single [`build_cache`] function whose implementation
//! is selected at compile time by the active cache feature flag:
//!
//! | Feature         | Cache type                                | External dependency  |
//! |-----------------|-------------------------------------------|----------------------|
//! | `cache-l2`      | Redis (L2-only)                           | Redis server         |
//! | `cache-l1`      | Moka (L1-only)                            | None                 |
//! | `cache-l1-l2`   | Moka L1 + Redis L2 (two-tier)             | Redis server         |
//! | `cache-pg`      | PostgreSQL (L2-only)                      | PostgreSQL server    |
//! | `cache-l1-pg`   | Moka L1 + PostgreSQL L2 (two-tier)        | PostgreSQL server    |
//! | `cache-mysql`   | MySQL / MariaDB (L2-only)                 | MySQL/MariaDB server |
//! | `cache-l1-mysql`| Moka L1 + MySQL L2 (two-tier)             | MySQL/MariaDB server |
//! | `cache-sqlite`  | SQLite (L2-only)                          | None (file-based)    |
//! | `cache-l1-sqlite`| Moka L1 + SQLite L2 (two-tier)           | None (file-based)    |
//!
//! Enabling both `cache-l1` and `cache-l2` individually produces the same
//! binary as enabling `cache-l1-l2`.  Likewise, enabling both `cache-l1` and
//! `cache-pg` is equivalent to `cache-l1-pg`, enabling both `cache-l1` and
//! `cache-mysql` is equivalent to `cache-l1-mysql`, and enabling both
//! `cache-l1` and `cache-sqlite` is equivalent to `cache-l1-sqlite`.
//!
//! ## Compile-time guard
//!
//! If no cache feature is active the crate will fail to compile with a clear
//! error message pointing to the required feature flags.

// ─── Guard: fail fast when no cache feature is selected ───────────────────────

#[cfg(not(any(
    feature = "cache-l1",
    feature = "cache-l2",
    feature = "cache-pg",
    feature = "cache-mysql",
    feature = "cache-sqlite",
)))]
compile_error!(
    "At least one cache feature must be enabled. Choose one of:\n\
     --features cache-l1        (Moka in-process only - default)\n\
     --features cache-l2        (Redis only)\n\
     --features cache-l1-l2     (Moka L1 + Redis L2)\n\
     --features cache-pg        (PostgreSQL only)\n\
     --features cache-l1-pg     (Moka L1 + PostgreSQL L2)\n\
     --features cache-mysql     (MySQL / MariaDB only)\n\
     --features cache-l1-mysql  (Moka L1 + MySQL L2)\n\
     --features cache-sqlite    (SQLite only)\n\
     --features cache-l1-sqlite (Moka L1 + SQLite L2)"
);

// ─── Imports ──────────────────────────────────────────────────────────────────

use std::sync::Arc;

use axum_oidc_client::auth_cache::AuthCache;

use crate::config::Args;

// ─── Two-tier: Moka L1 + Redis L2 ────────────────────────────────────────────

/// Build a **two-tier** [`AuthCache`] (Moka L1 in front of Redis L2).
///
/// Active when both `cache-l1` **and** `cache-l2` features are enabled
/// (i.e. when `cache-l1-l2` is selected) but neither `cache-pg` nor
/// `cache-mysql` is enabled.
///
/// Read path: L1 → on miss → L2 → populate L1.
/// Write path: L2 first (source of truth), then L1.
#[cfg(all(
    feature = "cache-l1",
    feature = "cache-l2",
    not(feature = "cache-pg"),
    not(feature = "cache-mysql"),
))]
pub fn build_cache(args: &Args) -> Arc<dyn AuthCache + Send + Sync> {
    use axum_oidc_client::cache::{config::TwoTierCacheConfig, TwoTierAuthCache};
    use axum_oidc_client::redis;

    let redis_l2: Arc<dyn AuthCache + Send + Sync> =
        Arc::new(redis::AuthCache::new(&args.redis_url, args.cache_ttl));

    let config = TwoTierCacheConfig {
        l1_max_capacity: args.l1_max_capacity,
        l1_ttl_sec: args.l1_ttl_sec,
        l1_time_to_idle_sec: args.l1_time_to_idle_sec,
        enable_l1: true,
    };

    Arc::new(
        TwoTierAuthCache::new(Some(redis_l2), config)
            .expect("failed to build two-tier cache (Moka L1 + Redis L2)"),
    )
}

// ─── L1-only: Moka in-process cache ──────────────────────────────────────────

/// Build an **L1-only** [`AuthCache`] backed exclusively by Moka.
///
/// Active when `cache-l1` is enabled **without** `cache-l2`, `cache-pg`, or
/// `cache-mysql`.  No external backend is required.
///
/// > **Note:** `extend_auth_session` re-inserts the entry to reset its
/// > wall-clock TTL to the configured `l1_ttl_sec`.  The exact `ttl`
/// > argument cannot be honoured precisely in L1-only mode.
#[cfg(all(
    feature = "cache-l1",
    not(feature = "cache-l2"),
    not(feature = "cache-pg"),
    not(feature = "cache-mysql"),
    not(feature = "cache-sqlite"),
))]
pub fn build_cache(args: &Args) -> Arc<dyn AuthCache + Send + Sync> {
    use axum_oidc_client::cache::{config::TwoTierCacheConfig, TwoTierAuthCache};

    let config = TwoTierCacheConfig {
        l1_max_capacity: args.l1_max_capacity,
        l1_ttl_sec: args.l1_ttl_sec,
        l1_time_to_idle_sec: args.l1_time_to_idle_sec,
        enable_l1: true,
    };

    Arc::new(TwoTierAuthCache::new(None, config).expect("failed to build L1-only cache (Moka)"))
}

// ─── L2-only: Redis ───────────────────────────────────────────────────────────

/// Build an **L2-only** [`AuthCache`] backed by Redis.
///
/// Active when `cache-l2` is enabled **without** `cache-l1`, `cache-pg`, or
/// `cache-mysql`.  Requires an external Redis server.
#[cfg(all(
    feature = "cache-l2",
    not(feature = "cache-l1"),
    not(feature = "cache-pg"),
    not(feature = "cache-mysql"),
))]
pub fn build_cache(args: &Args) -> Arc<dyn AuthCache + Send + Sync> {
    use axum_oidc_client::redis;

    Arc::new(redis::AuthCache::new(&args.redis_url, args.cache_ttl))
}

// ─── PostgreSQL-only: SQL cache ───────────────────────────────────────────────

/// Build a **PostgreSQL-only** [`AuthCache`] backed by a `SqlAuthCache`.
///
/// Active when `cache-pg` is enabled **without** `cache-l1` or `cache-mysql`.
/// Requires a running PostgreSQL server (≥ 12, tested with 18).
///
/// Schema initialisation (`CREATE TABLE IF NOT EXISTS`) is performed
/// immediately after the pool is created so the table is always present on
/// startup without a separate migration step.
#[cfg(all(
    feature = "cache-pg",
    not(feature = "cache-l1"),
    not(feature = "cache-mysql"),
))]
pub fn build_cache(args: &Args) -> Arc<dyn AuthCache + Send + Sync> {
    use axum_oidc_client::sql_cache::{SqlAuthCache, SqlCacheConfig};

    let config = SqlCacheConfig {
        connection_string: args.pg_url.clone(),
        max_connections: args.pg_max_connections,
        cleanup_interval_sec: args.pg_cleanup_interval_sec,
        ..Default::default()
    };

    // Block on async initialisation inside the already-running Tokio runtime.
    let handle = tokio::runtime::Handle::current();
    let cache = handle.block_on(async {
        let c = SqlAuthCache::new(config)
            .await
            .expect("failed to connect to PostgreSQL for cache");
        c.init_schema()
            .await
            .expect("failed to initialise PostgreSQL cache schema");
        c
    });

    Arc::new(cache)
}

// ─── Two-tier: Moka L1 + PostgreSQL L2 ───────────────────────────────────────

/// Build a **two-tier** [`AuthCache`] (Moka L1 in front of PostgreSQL L2).
///
/// Active when both `cache-l1` **and** `cache-pg` features are enabled
/// (i.e. when `cache-l1-pg` is selected) and `cache-mysql` is **not** enabled.
///
/// Read path:  L1 → on miss → PostgreSQL → populate L1.
/// Write path: PostgreSQL first (source of truth), then L1.
///
/// This is the recommended production configuration when you want
/// low-latency reads (served from the in-process Moka cache) with
/// durable, crash-safe storage in PostgreSQL.
#[cfg(all(
    feature = "cache-l1",
    feature = "cache-pg",
    not(feature = "cache-mysql"),
))]
pub fn build_cache(args: &Args) -> Arc<dyn AuthCache + Send + Sync> {
    use axum_oidc_client::cache::{config::TwoTierCacheConfig, TwoTierAuthCache};
    use axum_oidc_client::sql_cache::{SqlAuthCache, SqlCacheConfig};

    let pg_config = SqlCacheConfig {
        connection_string: args.pg_url.clone(),
        max_connections: args.pg_max_connections,
        cleanup_interval_sec: args.pg_cleanup_interval_sec,
        ..Default::default()
    };

    // Block on async initialisation inside the already-running Tokio runtime.
    let handle = tokio::runtime::Handle::current();
    let pg_l2: Arc<dyn AuthCache + Send + Sync> = handle.block_on(async {
        let c = SqlAuthCache::new(pg_config)
            .await
            .expect("failed to connect to PostgreSQL for two-tier cache");
        c.init_schema()
            .await
            .expect("failed to initialise PostgreSQL cache schema");
        Arc::new(c) as Arc<dyn AuthCache + Send + Sync>
    });

    let l1_config = TwoTierCacheConfig {
        l1_max_capacity: args.l1_max_capacity,
        l1_ttl_sec: args.pg_l1_ttl_sec,
        l1_time_to_idle_sec: args.l1_time_to_idle_sec,
        enable_l1: true,
    };

    Arc::new(
        TwoTierAuthCache::new(Some(pg_l2), l1_config)
            .expect("failed to build two-tier cache (Moka L1 + PostgreSQL L2)"),
    )
}

// ─── MySQL-only: SQL cache ────────────────────────────────────────────────────

/// Build a **MySQL-only** [`AuthCache`] backed by a `SqlAuthCache`.
///
/// Active when `cache-mysql` is enabled **without** `cache-l1` or `cache-pg`.
/// Requires a running MySQL (≥ 8.0) or MariaDB (≥ 10.6) server.
///
/// Schema initialisation (`CREATE TABLE IF NOT EXISTS`) is performed
/// immediately after the pool is created.  The `oidc_cache` table uses
/// `ENGINE=InnoDB` with `utf8mb4` charset and a `BIGINT expires_at` column
/// for Unix-timestamp-based TTL management.
///
/// Unlike PostgreSQL's MVCC dead-tuple model, InnoDB reclaims deleted row
/// space via its background **purge thread** automatically.  The companion
/// Docker Compose `optimize-cron` service runs `OPTIMIZE TABLE oidc_cache`
/// and `ANALYZE TABLE oidc_cache` at midnight to defragment InnoDB pages and
/// refresh index statistics after large expiry waves.
#[cfg(all(
    feature = "cache-mysql",
    not(feature = "cache-l1"),
    not(feature = "cache-pg"),
))]
pub fn build_cache(args: &Args) -> Arc<dyn AuthCache + Send + Sync> {
    use axum_oidc_client::sql_cache::{SqlAuthCache, SqlCacheConfig};

    let config = SqlCacheConfig {
        connection_string: args.mysql_url.clone(),
        max_connections: args.mysql_max_connections,
        cleanup_interval_sec: args.mysql_cleanup_interval_sec,
        ..Default::default()
    };

    // Block on async initialisation inside the already-running Tokio runtime.
    let handle = tokio::runtime::Handle::current();
    let cache = handle.block_on(async {
        let c = SqlAuthCache::new(config)
            .await
            .expect("failed to connect to MySQL for cache");
        c.init_schema()
            .await
            .expect("failed to initialise MySQL cache schema");
        c
    });

    Arc::new(cache)
}

// ─── Two-tier: Moka L1 + MySQL L2 ────────────────────────────────────────────

/// Build a **two-tier** [`AuthCache`] (Moka L1 in front of MySQL L2).
///
/// Active when both `cache-l1` **and** `cache-mysql` features are enabled
/// (i.e. when `cache-l1-mysql` is selected) and `cache-pg` is **not** enabled.
///
/// Read path:  L1 → on miss → MySQL → populate L1.
/// Write path: MySQL first (source of truth), then L1.
///
/// The Moka L1 layer absorbs the majority of repeated session reads so that
/// MySQL sees only cold-miss and write traffic.  This significantly reduces
/// connection pool pressure on the database while retaining shared,
/// persistent state across application restarts.
#[cfg(all(
    feature = "cache-l1",
    feature = "cache-mysql",
    not(feature = "cache-pg"),
))]
pub fn build_cache(args: &Args) -> Arc<dyn AuthCache + Send + Sync> {
    use axum_oidc_client::cache::{config::TwoTierCacheConfig, TwoTierAuthCache};
    use axum_oidc_client::sql_cache::{SqlAuthCache, SqlCacheConfig};

    let mysql_config = SqlCacheConfig {
        connection_string: args.mysql_url.clone(),
        max_connections: args.mysql_max_connections,
        cleanup_interval_sec: args.mysql_cleanup_interval_sec,
        ..Default::default()
    };

    // Block on async initialisation inside the already-running Tokio runtime.
    let handle = tokio::runtime::Handle::current();
    let mysql_l2: Arc<dyn AuthCache + Send + Sync> = handle.block_on(async {
        let c = SqlAuthCache::new(mysql_config)
            .await
            .expect("failed to connect to MySQL for two-tier cache");
        c.init_schema()
            .await
            .expect("failed to initialise MySQL cache schema");
        Arc::new(c) as Arc<dyn AuthCache + Send + Sync>
    });

    let l1_config = TwoTierCacheConfig {
        l1_max_capacity: args.l1_max_capacity,
        l1_ttl_sec: args.mysql_l1_ttl_sec,
        l1_time_to_idle_sec: args.l1_time_to_idle_sec,
        enable_l1: true,
    };

    Arc::new(
        TwoTierAuthCache::new(Some(mysql_l2), l1_config)
            .expect("failed to build two-tier cache (Moka L1 + MySQL L2)"),
    )
}

// ─── SQLite-only: SQL cache ───────────────────────────────────────────────────

/// Build a **SQLite-only** [`AuthCache`] backed by a `SqlAuthCache`.
///
/// Active when `cache-sqlite` is enabled **without** `cache-l1`, `cache-pg`,
/// or `cache-mysql`.  No external server is required — SQLite stores data in a
/// local file (or in `:memory:` for testing).
///
/// Schema initialisation (`CREATE TABLE IF NOT EXISTS`) is performed
/// immediately after the pool is created.
///
/// SQLite supports only one writer at a time (WAL mode allows concurrent
/// reads), so keep `sqlite_max_connections` low (≤ 5).  The connection URL
/// can point to a file path (`sqlite:///path/to/cache.db`) or use the special
/// `:memory:` database (`sqlite://:memory:`).
#[cfg(all(
    feature = "cache-sqlite",
    not(feature = "cache-l1"),
    not(feature = "cache-pg"),
    not(feature = "cache-mysql"),
))]
pub fn build_cache(args: &Args) -> Arc<dyn AuthCache + Send + Sync> {
    use axum_oidc_client::sql_cache::{SqlAuthCache, SqlCacheConfig};

    let config = SqlCacheConfig {
        connection_string: args.sqlite_url.clone(),
        max_connections: args.sqlite_max_connections,
        cleanup_interval_sec: args.sqlite_cleanup_interval_sec,
        ..Default::default()
    };

    let handle = tokio::runtime::Handle::current();
    let cache = handle.block_on(async {
        let c = SqlAuthCache::new(config)
            .await
            .expect("failed to connect to SQLite for cache");
        c.init_schema()
            .await
            .expect("failed to initialise SQLite cache schema");
        c
    });

    Arc::new(cache)
}

// ─── Two-tier: Moka L1 + SQLite L2 ───────────────────────────────────────────

/// Build a **two-tier** [`AuthCache`] (Moka L1 in front of SQLite L2).
///
/// Active when both `cache-l1` **and** `cache-sqlite` features are enabled
/// (i.e. when `cache-l1-sqlite` is selected) and neither `cache-pg` nor
/// `cache-mysql` is enabled.
///
/// Read path:  L1 → on miss → SQLite → populate L1.
/// Write path: SQLite first (source of truth), then L1.
///
/// The Moka L1 layer is particularly valuable in front of SQLite because
/// SQLite serialises concurrent writes; absorbing reads in L1 prevents
/// contention on the single writer lock.
#[cfg(all(
    feature = "cache-l1",
    feature = "cache-sqlite",
    not(feature = "cache-pg"),
    not(feature = "cache-mysql"),
))]
pub fn build_cache(args: &Args) -> Arc<dyn AuthCache + Send + Sync> {
    use axum_oidc_client::cache::{config::TwoTierCacheConfig, TwoTierAuthCache};
    use axum_oidc_client::sql_cache::{SqlAuthCache, SqlCacheConfig};

    let sqlite_config = SqlCacheConfig {
        connection_string: args.sqlite_url.clone(),
        max_connections: args.sqlite_max_connections,
        cleanup_interval_sec: args.sqlite_cleanup_interval_sec,
        ..Default::default()
    };

    let handle = tokio::runtime::Handle::current();
    let sqlite_l2: Arc<dyn AuthCache + Send + Sync> = handle.block_on(async {
        let c = SqlAuthCache::new(sqlite_config)
            .await
            .expect("failed to connect to SQLite for two-tier cache");
        c.init_schema()
            .await
            .expect("failed to initialise SQLite cache schema");
        Arc::new(c) as Arc<dyn AuthCache + Send + Sync>
    });

    let l1_config = TwoTierCacheConfig {
        l1_max_capacity: args.l1_max_capacity,
        l1_ttl_sec: args.sqlite_l1_ttl_sec,
        l1_time_to_idle_sec: args.l1_time_to_idle_sec,
        enable_l1: true,
    };

    Arc::new(
        TwoTierAuthCache::new(Some(sqlite_l2), l1_config)
            .expect("failed to build two-tier cache (Moka L1 + SQLite L2)"),
    )
}
