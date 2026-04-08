//! Two-tier authentication cache module.
//!
//! This module exposes a two-tier caching system that combines a fast
//! in-process [Moka](https://crates.io/crates/moka) L1 cache with any
//! [`AuthCache`](crate::authentication::cache::AuthCache) implementation as the L2
//! backend (e.g. Redis).
//!
//! ## Overview
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │                 TwoTierAuthCache                    │
//! │                                                     │
//! │   ┌──────────────────┐    ┌─────────────────────┐  │
//! │   │  L1 – Moka       │    │  L2 – AuthCache impl│  │
//! │   │  (in-process)    │───▶│  (e.g. Redis)       │  │
//! │   └──────────────────┘    └─────────────────────┘  │
//! └─────────────────────────────────────────────────────┘
//! ```
//!
//! ## Cache-aside pattern
//!
//! | Operation      | L1 (Moka)                            | L2 (backend)                  |
//! |----------------|--------------------------------------|-------------------------------|
//! | **Read**       | Check first; on miss go to L2        | Read on L1 miss; populate L1  |
//! | **Write**      | Write                                | Write                         |
//! | **Invalidate** | Remove                               | Remove                        |
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use axum_oidc_client::cache::{TwoTierAuthCache, config::TwoTierCacheConfig};
//! use axum_oidc_client::auth_cache::AuthCache;
//!
//! # #[cfg(feature = "redis")]
//! # async fn example() {
//! let redis_cache: Arc<dyn AuthCache + Send + Sync> = Arc::new(
//!     axum_oidc_client::redis::AuthCache::new("redis://127.0.0.1/", 3600)
//! );
//!
//! let config = TwoTierCacheConfig {
//!     l1_max_capacity: 10_000,
//!     l1_ttl_sec: 3600,
//!     l1_time_to_idle_sec: Some(1800),
//!     enable_l1: true,
//! };
//!
//! let cache = Arc::new(
//!     TwoTierAuthCache::new(Some(redis_cache), config)
//!         .expect("failed to build two-tier cache")
//! );
//! # }
//! ```

pub mod config;
pub mod two_tier;

pub use two_tier::TwoTierAuthCache;
