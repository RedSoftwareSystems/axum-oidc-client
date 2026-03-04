//! Cache configuration types.
//!
//! This module defines configuration structs used to tune the behaviour of the
//! two-tier caching system.

/// Configuration for the two-tier (L1 Moka + L2) auth cache.
///
/// # Example
///
/// ```rust
/// use axum_oidc_client::cache::config::TwoTierCacheConfig;
///
/// let config = TwoTierCacheConfig {
///     l1_max_capacity: 5_000,
///     l1_ttl_sec: 1800,
///     l1_time_to_idle_sec: Some(600),
///     enable_l1: true,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct TwoTierCacheConfig {
    /// Maximum number of entries held by the Moka L1 cache.
    ///
    /// When this limit is reached the cache evicts the least-recently-used
    /// entries to make room for new ones.
    ///
    /// Default: `10_000`
    pub l1_max_capacity: u64,

    /// Time-to-live for L1 cache entries, in seconds.
    ///
    /// Entries are evicted after this duration regardless of access patterns.
    /// Should be set to match or slightly exceed the L2 cache TTL so that a
    /// stale L1 hit never shadows a fresher L2 entry for too long.
    ///
    /// Default: `3600` (1 hour)
    pub l1_ttl_sec: u64,

    /// Optional time-to-idle for L1 cache entries, in seconds.
    ///
    /// When `Some`, entries that have not been accessed for this duration are
    /// evicted even if their TTL has not expired yet.  Set to `None` to
    /// disable idle-based eviction.
    ///
    /// Default: `None`
    pub l1_time_to_idle_sec: Option<u64>,

    /// Whether the L1 cache is active.
    ///
    /// Set to `false` to bypass Moka entirely and forward every operation
    /// directly to the L2 cache.  Useful for testing or environments where
    /// an in-process cache is undesirable.
    ///
    /// Default: `true`
    pub enable_l1: bool,
}

impl Default for TwoTierCacheConfig {
    fn default() -> Self {
        Self {
            l1_max_capacity: 10_000,
            l1_ttl_sec: 3600,
            l1_time_to_idle_sec: None,
            enable_l1: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_values() {
        let config = TwoTierCacheConfig::default();
        assert_eq!(config.l1_max_capacity, 10_000);
        assert_eq!(config.l1_ttl_sec, 3600);
        assert_eq!(config.l1_time_to_idle_sec, None);
        assert!(config.enable_l1);
    }

    #[test]
    fn test_custom_values() {
        let config = TwoTierCacheConfig {
            l1_max_capacity: 500,
            l1_ttl_sec: 60,
            l1_time_to_idle_sec: Some(30),
            enable_l1: false,
        };
        assert_eq!(config.l1_max_capacity, 500);
        assert_eq!(config.l1_ttl_sec, 60);
        assert_eq!(config.l1_time_to_idle_sec, Some(30));
        assert!(!config.enable_l1);
    }

    #[test]
    fn test_clone() {
        let original = TwoTierCacheConfig {
            l1_max_capacity: 1_000,
            l1_ttl_sec: 120,
            l1_time_to_idle_sec: Some(60),
            enable_l1: true,
        };
        let cloned = original.clone();
        assert_eq!(cloned.l1_max_capacity, original.l1_max_capacity);
        assert_eq!(cloned.l1_ttl_sec, original.l1_ttl_sec);
        assert_eq!(cloned.l1_time_to_idle_sec, original.l1_time_to_idle_sec);
        assert_eq!(cloned.enable_l1, original.enable_l1);
    }
}
