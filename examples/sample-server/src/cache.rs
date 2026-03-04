//! Cache construction module.
//!
//! This module exposes a single [`build_cache`] function whose implementation
//! is selected at compile time by the active cache feature flag:
//!
//! | Feature       | Cache type                          | External dependency |
//! |---------------|-------------------------------------|---------------------|
//! | `cache-l2`    | Redis (L2-only)                     | Redis server        |
//! | `cache-l1`    | Moka (L1-only)                      | None                |
//! | `cache-l1-l2` | Moka L1 + Redis L2 (two-tier)       | Redis server        |
//!
//! Enabling both `cache-l1` and `cache-l2` individually produces the same
//! binary as enabling `cache-l1-l2`.
//!
//! ## Compile-time guard
//!
//! If no cache feature is active the crate will fail to compile with a clear
//! error message pointing to the required feature flags.

// ─── Guard: fail fast when no cache feature is selected ───────────────────────

#[cfg(not(any(feature = "cache-l1", feature = "cache-l2")))]
compile_error!(
    "At least one cache feature must be enabled. Choose one of:\n\
     --features cache-l1      (Moka in-process only - default)\n\
     --features cache-l2      (Redis only)\n\
     --features cache-l1-l2   (Moka L1 + Redis L2)"
);

// ─── Imports ──────────────────────────────────────────────────────────────────

use std::sync::Arc;

use axum_oidc_client::auth_cache::AuthCache;

use crate::config::Args;

// ─── Two-tier: Moka L1 + Redis L2 ────────────────────────────────────────────

/// Build a **two-tier** [`AuthCache`] (Moka L1 in front of Redis L2).
///
/// Active when both `cache-l1` **and** `cache-l2` features are enabled
/// (i.e. when `cache-l1-l2` is selected).
///
/// Read path: L1 → on miss → L2 → populate L1.
/// Write path: L2 first (source of truth), then L1.
#[cfg(all(feature = "cache-l1", feature = "cache-l2"))]
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
/// Active when `cache-l1` is enabled **without** `cache-l2`.
/// No external backend is required.
///
/// > **Note:** `extend_auth_session` re-inserts the entry to reset its
/// > wall-clock TTL to the configured `l1_ttl_sec`.  The exact `ttl`
/// > argument cannot be honoured precisely in L1-only mode.
#[cfg(all(feature = "cache-l1", not(feature = "cache-l2")))]
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
/// Active when `cache-l2` is enabled **without** `cache-l1`.
/// Requires an external Redis server.
#[cfg(all(feature = "cache-l2", not(feature = "cache-l1")))]
pub fn build_cache(args: &Args) -> Arc<dyn AuthCache + Send + Sync> {
    use axum_oidc_client::redis;

    Arc::new(redis::AuthCache::new(&args.redis_url, args.cache_ttl))
}
