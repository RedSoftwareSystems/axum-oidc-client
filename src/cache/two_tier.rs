//! Two-tier authentication cache implementation.
//!
//! This module provides [`TwoTierAuthCache`], a cache-aside wrapper that combines
//! a fast in-process Moka L1 cache with an optional [`AuthCache`] implementation
//! as the L2 backend (e.g. Redis).
//!
//! ## Operating modes
//!
//! | `enable_l1` | L2        | Mode         | Behaviour                                      |
//! |-------------|-----------|--------------|------------------------------------------------|
//! | `true`      | `Some(_)` | **Two-tier** | Sessions: L1 first, L2 on miss, write-through  |
//! | `true`      | `None`    | **L1-only**  | Moka only; no external backend                 |
//! | `false`     | `Some(_)` | **L2-only**  | All operations forwarded to the L2 backend     |
//! | `false`     | `None`    | ❌ **Error** | [`TwoTierAuthCache::new`] returns `Err`        |
//!
//! ## Code verifier storage strategy
//!
//! Code verifiers are short-lived, single-use values (TTL ≈ 60 s) consumed
//! entirely within a single OAuth PKCE round-trip.  When **L1 is enabled**,
//! code verifiers are stored **exclusively in Moka** regardless of whether an
//! L2 backend is also present.  This avoids unnecessary round-trips to Redis
//! for data that will never be read from there.
//!
//! | L1 present | Code-verifier storage |
//! |------------|-----------------------|
//! | yes        | L1 only (L2 bypassed) |
//! | no         | L2 only               |
//!
//! ## Auth-session cache-aside pattern (two-tier mode)
//!
//! Auth sessions are long-lived and must survive process restarts, so they
//! continue to use the full cache-aside pattern when two tiers are present.
//!
//! | Operation      | L1 (Moka)                           | L2 (backend)                  |
//! |----------------|-------------------------------------|-------------------------------|
//! | **Read**       | Check first; on miss go to L2       | Read on L1 miss; populate L1  |
//! | **Write**      | Write                               | Write first (source of truth) |
//! | **Invalidate** | Remove                              | Remove                        |
//! | **Extend TTL** | Evict (re-fetched on next read)     | Extend                        |
//!
//! ## L1-only `extend_auth_session` note
//!
//! Moka does not expose a per-entry TTL update API.  In L1-only mode,
//! `extend_auth_session` re-inserts the current entry, which resets its
//! wall-clock TTL to the configured `l1_ttl_sec`.  The `ttl` argument is
//! forwarded to L2 when one is present; in L1-only mode it cannot be
//! honoured precisely and the configured TTL is used instead.

use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use moka::future::Cache as MokaCache;

use crate::auth_cache::AuthCache;
use crate::auth_session::AuthSession;
use crate::errors::Error;

use super::config::TwoTierCacheConfig;

// ─── Internal key helpers ─────────────────────────────────────────────────────

/// Returns the Moka key used for a code-verifier entry.
#[inline]
fn cv_key(challenge_state: &str) -> String {
    format!("cv:{challenge_state}")
}

/// Returns the Moka key used for an auth-session entry.
#[inline]
fn session_key(session_id: &str) -> String {
    format!("session:{session_id}")
}

/// Extracts the bare identifier from a prefixed L1 key.
///
/// L1 keys carry a short type prefix (`cv:` or `session:`) so that both entry
/// types can share a single Moka cache without key collisions.  When forwarding
/// to L2 we strip the prefix because each L2 implementation applies its own
/// prefixing internally (e.g. `code_verifier.{state}` for Redis).
#[inline]
fn key_tail(key: &str) -> &str {
    match key.find(':') {
        Some(pos) => &key[pos + 1..],
        None => key,
    }
}

// ─── L1 storage type ─────────────────────────────────────────────────────────

/// Values stored in the Moka L1 cache.
///
/// Both code verifiers and auth sessions share one bounded `Cache<String, L1Entry>`
/// so that a single capacity and eviction policy governs all in-memory entries.
#[derive(Clone)]
enum L1Entry {
    CodeVerifier(String),
    AuthSession(AuthSession),
}

// ─── TwoTierAuthCache ─────────────────────────────────────────────────────────

/// A two-tier [`AuthCache`] that combines a Moka in-memory L1 cache with an
/// optional L2 backend cache (e.g. Redis).
///
/// At least one tier must be active; construction fails with
/// [`Error::CacheError`] when both are absent/disabled.
///
/// # Example – two-tier (Moka + Redis)
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use axum_oidc_client::cache::{TwoTierAuthCache, config::TwoTierCacheConfig};
/// use axum_oidc_client::auth_cache::AuthCache;
///
/// # #[cfg(feature = "redis")]
/// # async fn example() -> Result<(), axum_oidc_client::errors::Error> {
/// let redis: Arc<dyn AuthCache + Send + Sync> = Arc::new(
///     axum_oidc_client::redis::AuthCache::new("redis://127.0.0.1/", 3600)
/// );
///
/// let config = TwoTierCacheConfig {
///     l1_max_capacity: 10_000,
///     l1_ttl_sec: 3600,
///     l1_time_to_idle_sec: Some(1800),
///     enable_l1: true,
/// };
///
/// let cache = Arc::new(TwoTierAuthCache::new(Some(redis), config)?);
/// # Ok(())
/// # }
/// ```
///
/// # Example – L1-only (Moka, no external backend)
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use axum_oidc_client::cache::{TwoTierAuthCache, config::TwoTierCacheConfig};
///
/// # fn example() -> Result<(), axum_oidc_client::errors::Error> {
/// let config = TwoTierCacheConfig::default(); // enable_l1: true
/// let cache = Arc::new(TwoTierAuthCache::new(None, config)?);
/// # Ok(())
/// # }
/// ```
pub struct TwoTierAuthCache {
    /// Moka async in-memory cache (L1).  `None` when `enable_l1` is `false`.
    l1: Option<MokaCache<String, L1Entry>>,
    /// Optional backing L2 cache (e.g. Redis).  `None` in L1-only mode.
    l2: Option<Arc<dyn AuthCache + Send + Sync>>,
    /// Configuration snapshot kept for introspection.
    config: TwoTierCacheConfig,
}

impl TwoTierAuthCache {
    /// Creates a new `TwoTierAuthCache`.
    ///
    /// # Arguments
    ///
    /// * `l2` – Optional L2 cache backend.  Pass `None` for L1-only operation.
    /// * `config` – Configuration options controlling the L1 cache behaviour.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CacheError`] when `config.enable_l1` is `false` **and**
    /// `l2` is `None`, because no cache tier would be active.
    pub fn new(
        l2: Option<Arc<dyn AuthCache + Send + Sync>>,
        config: TwoTierCacheConfig,
    ) -> Result<Self, Error> {
        if !config.enable_l1 && l2.is_none() {
            return Err(Error::CacheError(
                "at least one cache tier must be configured: \
                 set enable_l1 = true or provide an L2 backend"
                    .to_string(),
            ));
        }

        let l1 = if config.enable_l1 {
            let mut builder = MokaCache::builder()
                .max_capacity(config.l1_max_capacity)
                .time_to_live(Duration::from_secs(config.l1_ttl_sec));

            if let Some(tti) = config.l1_time_to_idle_sec {
                builder = builder.time_to_idle(Duration::from_secs(tti));
            }

            Some(builder.build())
        } else {
            None
        };

        Ok(Self { l1, l2, config })
    }

    /// Returns a reference to the configuration used to build this cache.
    pub fn config(&self) -> &TwoTierCacheConfig {
        &self.config
    }
}

// ─── AuthCache implementation ─────────────────────────────────────────────────

impl AuthCache for TwoTierAuthCache {
    // ── code_verifier ─────────────────────────────────────────────────────────
    //
    // Code verifiers are short-lived, single-use values (TTL ≈ 60 s) that are
    // consumed entirely within a single OAuth PKCE round-trip.  When L1 is
    // present they are stored exclusively in Moka — L2 is never read or
    // written for code verifier operations.  This keeps the hot PKCE path
    // fully in-process and avoids unnecessary network round-trips.
    //
    // When L1 is absent (L2-only mode) L2 is used as before.

    fn get_code_verifier(
        &self,
        challenge_state: &str,
    ) -> BoxFuture<'_, Result<Option<String>, Error>> {
        let key = cv_key(challenge_state);
        Box::pin(async move {
            // L1 present → code verifiers live exclusively in L1; no L2 fallback.
            if let Some(l1) = &self.l1 {
                return Ok(match l1.get(&key).await {
                    Some(L1Entry::CodeVerifier(v)) => Some(v),
                    _ => None,
                });
            }

            // L2-only mode: delegate to L2.
            if let Some(l2) = &self.l2 {
                return l2.get_code_verifier(key_tail(&key)).await;
            }

            Ok(None)
        })
    }

    fn set_code_verifier(
        &self,
        challenge_state: &str,
        code_verifier: &str,
    ) -> BoxFuture<'_, Result<(), Error>> {
        let key = cv_key(challenge_state);
        let value = code_verifier.to_string();
        Box::pin(async move {
            // L1 present → store exclusively in L1; skip L2.
            if let Some(l1) = &self.l1 {
                l1.insert(key, L1Entry::CodeVerifier(value)).await;
                return Ok(());
            }

            // L2-only mode: delegate to L2.
            if let Some(l2) = &self.l2 {
                l2.set_code_verifier(key_tail(&key), &value).await?;
            }

            Ok(())
        })
    }

    fn invalidate_code_verifier(&self, challenge_state: &str) -> BoxFuture<'_, Result<(), Error>> {
        let key = cv_key(challenge_state);
        Box::pin(async move {
            // L1 present → code verifier was stored only in L1; nothing to do on L2.
            if let Some(l1) = &self.l1 {
                l1.invalidate(&key).await;
                return Ok(());
            }

            // L2-only mode: delegate to L2.
            if let Some(l2) = &self.l2 {
                l2.invalidate_code_verifier(key_tail(&key)).await?;
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
        Box::pin(async move {
            // ① Check L1
            if let Some(l1) = &self.l1 {
                if let Some(L1Entry::AuthSession(s)) = l1.get(&key).await {
                    return Ok(Some(s));
                }
            }

            // ② L2 lookup (if present)
            if let Some(l2) = &self.l2 {
                let result = l2.get_auth_session(key_tail(&key)).await?;

                // Populate L1 on L2 hit
                if let (Some(l1), Some(ref s)) = (&self.l1, &result) {
                    l1.insert(key, L1Entry::AuthSession(s.clone())).await;
                }

                return Ok(result);
            }

            Ok(None)
        })
    }

    fn set_auth_session(
        &self,
        session_id: &str,
        session: AuthSession,
    ) -> BoxFuture<'_, Result<(), Error>> {
        let key = session_key(session_id);
        Box::pin(async move {
            // Write to L2 first (source of truth when present)
            if let Some(l2) = &self.l2 {
                l2.set_auth_session(key_tail(&key), session.clone()).await?;
            }

            // Write to L1
            if let Some(l1) = &self.l1 {
                l1.insert(key, L1Entry::AuthSession(session)).await;
            }

            Ok(())
        })
    }

    fn invalidate_auth_session(&self, session_id: &str) -> BoxFuture<'_, Result<(), Error>> {
        let key = session_key(session_id);
        Box::pin(async move {
            if let Some(l1) = &self.l1 {
                l1.invalidate(&key).await;
            }

            if let Some(l2) = &self.l2 {
                l2.invalidate_auth_session(key_tail(&key)).await?;
            }

            Ok(())
        })
    }

    fn extend_auth_session(&self, session_id: &str, ttl: i64) -> BoxFuture<'_, Result<(), Error>> {
        // Strategy depends on which tiers are active:
        //
        // • Two-tier (L1 + L2):
        //     Extend TTL on L2 (source of truth), then evict the L1 entry so
        //     the next read re-fetches from L2 and re-populates L1.
        //
        // • L2-only:
        //     Delegate directly to L2.
        //
        // • L1-only:
        //     Moka does not support per-entry TTL updates.  Re-insert the
        //     current entry to reset its wall-clock TTL to `l1_ttl_sec`.
        //     If the entry is not found in L1 there is nothing to extend.
        let key = session_key(session_id);
        Box::pin(async move {
            if let Some(l2) = &self.l2 {
                // Extend on L2 (covers both two-tier and L2-only modes)
                l2.extend_auth_session(key_tail(&key), ttl).await?;

                // Evict the stale L1 entry; the next read will re-populate it
                if let Some(l1) = &self.l1 {
                    l1.invalidate(&key).await;
                }
            } else if let Some(l1) = &self.l1 {
                // L1-only: re-insert to reset the entry's wall-clock TTL
                if let Some(entry) = l1.get(&key).await {
                    l1.insert(key, entry).await;
                }
                // If the entry is absent there is nothing to extend
            }

            Ok(())
        })
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    // ── Stub L2 cache ─────────────────────────────────────────────────────────

    /// Simple in-memory stub that stands in for a real L2 backend (e.g. Redis).
    /// Kept behind an `Arc` so tests can inspect state after operations.
    #[derive(Default)]
    struct StubL2 {
        code_verifiers: Mutex<HashMap<String, String>>,
        sessions: Mutex<HashMap<String, AuthSession>>,
        /// Records the `ttl` argument passed to `extend_auth_session`.
        session_ttls: Mutex<HashMap<String, i64>>,
    }

    impl StubL2 {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        /// Coerce `Arc<StubL2>` into the trait-object type expected by
        /// `TwoTierAuthCache::new`.
        fn as_dyn(this: &Arc<Self>) -> Arc<dyn AuthCache + Send + Sync> {
            Arc::clone(this) as Arc<dyn AuthCache + Send + Sync>
        }
    }

    impl AuthCache for StubL2 {
        fn get_code_verifier(
            &self,
            challenge_state: &str,
        ) -> BoxFuture<'_, Result<Option<String>, Error>> {
            let result = self
                .code_verifiers
                .lock()
                .unwrap()
                .get(challenge_state)
                .cloned();
            Box::pin(async move { Ok(result) })
        }

        fn set_code_verifier(
            &self,
            challenge_state: &str,
            code_verifier: &str,
        ) -> BoxFuture<'_, Result<(), Error>> {
            self.code_verifiers
                .lock()
                .unwrap()
                .insert(challenge_state.to_string(), code_verifier.to_string());
            Box::pin(async move { Ok(()) })
        }

        fn invalidate_code_verifier(
            &self,
            challenge_state: &str,
        ) -> BoxFuture<'_, Result<(), Error>> {
            self.code_verifiers.lock().unwrap().remove(challenge_state);
            Box::pin(async move { Ok(()) })
        }

        fn get_auth_session(
            &self,
            session_id: &str,
        ) -> BoxFuture<'_, Result<Option<AuthSession>, Error>> {
            let result = self.sessions.lock().unwrap().get(session_id).cloned();
            Box::pin(async move { Ok(result) })
        }

        fn set_auth_session(
            &self,
            session_id: &str,
            session: AuthSession,
        ) -> BoxFuture<'_, Result<(), Error>> {
            self.sessions
                .lock()
                .unwrap()
                .insert(session_id.to_string(), session);
            Box::pin(async move { Ok(()) })
        }

        fn invalidate_auth_session(&self, session_id: &str) -> BoxFuture<'_, Result<(), Error>> {
            self.sessions.lock().unwrap().remove(session_id);
            Box::pin(async move { Ok(()) })
        }

        fn extend_auth_session(
            &self,
            session_id: &str,
            ttl: i64,
        ) -> BoxFuture<'_, Result<(), Error>> {
            self.session_ttls
                .lock()
                .unwrap()
                .insert(session_id.to_string(), ttl);
            Box::pin(async move { Ok(()) })
        }
    }

    // ── Fixture helpers ───────────────────────────────────────────────────────

    fn l1_config() -> TwoTierCacheConfig {
        TwoTierCacheConfig {
            l1_max_capacity: 100,
            l1_ttl_sec: 60,
            l1_time_to_idle_sec: None,
            enable_l1: true,
        }
    }

    fn l2_only_config() -> TwoTierCacheConfig {
        TwoTierCacheConfig {
            l1_max_capacity: 100,
            l1_ttl_sec: 60,
            l1_time_to_idle_sec: None,
            enable_l1: false,
        }
    }

    /// Two-tier cache backed by `stub`.
    fn make_two_tier(stub: &Arc<StubL2>) -> TwoTierAuthCache {
        TwoTierAuthCache::new(Some(StubL2::as_dyn(stub)), l1_config()).unwrap()
    }

    /// L1-only cache (no L2).
    fn make_l1_only() -> TwoTierAuthCache {
        TwoTierAuthCache::new(None, l1_config()).unwrap()
    }

    /// L2-only cache backed by `stub`.
    fn make_l2_only(stub: &Arc<StubL2>) -> TwoTierAuthCache {
        TwoTierAuthCache::new(Some(StubL2::as_dyn(stub)), l2_only_config()).unwrap()
    }

    fn sample_session() -> AuthSession {
        AuthSession {
            id_token: "id_tok".to_string(),
            access_token: "acc_tok".to_string(),
            token_type: "Bearer".to_string(),
            refresh_token: None,
            scope: Some("openid".to_string()),
            expires: None,
        }
    }

    // ── construction ─────────────────────────────────────────────────────────

    #[test]
    fn test_new_fails_when_both_tiers_absent() {
        let result = TwoTierAuthCache::new(None, l2_only_config());
        assert!(
            result.is_err(),
            "expected Err when enable_l1=false and l2=None"
        );
        let err = match result {
            Err(e) => e,
            Ok(_) => unreachable!("expected Err but got Ok"),
        };
        let err_msg = format!("{:?}", err);
        // The error must mention the missing cache configuration
        assert!(
            err_msg.to_lowercase().contains("cache"),
            "error should mention cache: {err_msg}"
        );
    }

    #[test]
    fn test_new_succeeds_l1_only() {
        let cache = TwoTierAuthCache::new(None, l1_config());
        assert!(cache.is_ok());
        let cache = cache.unwrap();
        assert!(cache.l1.is_some());
        assert!(cache.l2.is_none());
    }

    #[test]
    fn test_new_succeeds_l2_only() {
        let stub = StubL2::new();
        let cache = TwoTierAuthCache::new(Some(StubL2::as_dyn(&stub)), l2_only_config());
        assert!(cache.is_ok());
        let cache = cache.unwrap();
        assert!(cache.l1.is_none());
        assert!(cache.l2.is_some());
    }

    #[test]
    fn test_new_succeeds_two_tier() {
        let stub = StubL2::new();
        let cache = TwoTierAuthCache::new(Some(StubL2::as_dyn(&stub)), l1_config());
        assert!(cache.is_ok());
        let cache = cache.unwrap();
        assert!(cache.l1.is_some());
        assert!(cache.l2.is_some());
    }

    // ── config accessor ───────────────────────────────────────────────────────

    #[test]
    fn test_config_accessor() {
        let stub = StubL2::new();
        let config = TwoTierCacheConfig {
            l1_max_capacity: 42,
            l1_ttl_sec: 99,
            l1_time_to_idle_sec: Some(10),
            enable_l1: true,
        };
        let cache = TwoTierAuthCache::new(Some(StubL2::as_dyn(&stub)), config).unwrap();
        assert_eq!(cache.config().l1_max_capacity, 42);
        assert_eq!(cache.config().l1_ttl_sec, 99);
        assert_eq!(cache.config().l1_time_to_idle_sec, Some(10));
        assert!(cache.config().enable_l1);
    }

    // ── key_tail ──────────────────────────────────────────────────────────────

    #[test]
    fn test_key_tail_cv() {
        assert_eq!(key_tail("cv:abc123"), "abc123");
    }

    #[test]
    fn test_key_tail_session() {
        assert_eq!(key_tail("session:uuid-goes-here"), "uuid-goes-here");
    }

    #[test]
    fn test_key_tail_no_prefix() {
        assert_eq!(key_tail("nocolon"), "nocolon");
    }

    // ── two-tier: code_verifier ───────────────────────────────────────────────
    //
    // In two-tier mode code verifiers are stored exclusively in L1 (Moka).
    // L2 is never read or written for code verifier operations.

    #[tokio::test]
    async fn test_two_tier_set_get_code_verifier() {
        let stub = StubL2::new();
        let cache = make_two_tier(&stub);

        cache.set_code_verifier("s1", "v1").await.unwrap();

        // Readable via the cache (served from L1)
        assert_eq!(
            cache.get_code_verifier("s1").await.unwrap(),
            Some("v1".to_string())
        );
        // L2 must NOT have been written to
        assert_eq!(
            stub.get_code_verifier("s1").await.unwrap(),
            None,
            "code verifier must not be written to L2 when L1 is present"
        );
    }

    #[tokio::test]
    async fn test_two_tier_get_code_verifier_miss() {
        let stub = StubL2::new();
        let cache = make_two_tier(&stub);
        assert_eq!(cache.get_code_verifier("ghost").await.unwrap(), None);
    }

    /// A code verifier written directly into L2 must NOT be visible through
    /// the two-tier cache because L2 is bypassed for code verifier reads when
    /// L1 is present.
    #[tokio::test]
    async fn test_two_tier_code_verifier_l2_write_invisible_to_cache() {
        let stub = StubL2::new();

        // Seed L2 directly (simulates a stale / out-of-band write)
        stub.set_code_verifier("s2", "v2").await.unwrap();

        let cache = make_two_tier(&stub);

        // The two-tier cache must return None: L2 is not consulted for CVs.
        assert_eq!(
            cache.get_code_verifier("s2").await.unwrap(),
            None,
            "two-tier cache must not fall back to L2 for code verifiers"
        );

        // L1 must also be empty (no spurious population)
        let l1 = cache.l1.as_ref().unwrap();
        assert!(l1.get(&cv_key("s2")).await.is_none());
    }

    #[tokio::test]
    async fn test_two_tier_invalidate_code_verifier() {
        let stub = StubL2::new();
        let cache = make_two_tier(&stub);

        cache.set_code_verifier("s3", "v3").await.unwrap();
        cache.invalidate_code_verifier("s3").await.unwrap();

        // Gone from the cache
        assert_eq!(cache.get_code_verifier("s3").await.unwrap(), None);
        // L2 was never written so this is trivially true, but assert for clarity
        assert_eq!(stub.get_code_verifier("s3").await.unwrap(), None);
    }

    // ── two-tier: auth_session ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_two_tier_set_get_auth_session() {
        let stub = StubL2::new();
        let cache = make_two_tier(&stub);
        let session = sample_session();

        cache
            .set_auth_session("sess1", session.clone())
            .await
            .unwrap();

        assert_eq!(
            cache.get_auth_session("sess1").await.unwrap(),
            Some(session.clone())
        );
        assert_eq!(stub.get_auth_session("sess1").await.unwrap(), Some(session));
    }

    #[tokio::test]
    async fn test_two_tier_get_auth_session_miss() {
        let stub = StubL2::new();
        let cache = make_two_tier(&stub);
        assert_eq!(cache.get_auth_session("ghost").await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_two_tier_get_auth_session_populates_l1_from_l2() {
        let stub = StubL2::new();
        let session = sample_session();
        stub.set_auth_session("sess2", session.clone())
            .await
            .unwrap();

        let cache = make_two_tier(&stub);

        assert_eq!(
            cache.get_auth_session("sess2").await.unwrap(),
            Some(session.clone())
        );

        let l1 = cache.l1.as_ref().unwrap();
        let entry = l1.get(&session_key("sess2")).await;
        assert!(matches!(entry, Some(L1Entry::AuthSession(s)) if s == session));
    }

    #[tokio::test]
    async fn test_two_tier_invalidate_auth_session() {
        let stub = StubL2::new();
        let cache = make_two_tier(&stub);
        let session = sample_session();

        cache.set_auth_session("sess3", session).await.unwrap();
        cache.invalidate_auth_session("sess3").await.unwrap();

        assert_eq!(cache.get_auth_session("sess3").await.unwrap(), None);
        assert_eq!(stub.get_auth_session("sess3").await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_two_tier_extend_evicts_l1_and_delegates_to_l2() {
        let stub = StubL2::new();
        let cache = make_two_tier(&stub);
        let session = sample_session();

        cache.set_auth_session("sess4", session).await.unwrap();

        // Entry must be in L1 after write
        assert!(cache
            .l1
            .as_ref()
            .unwrap()
            .get(&session_key("sess4"))
            .await
            .is_some());

        cache.extend_auth_session("sess4", 7200).await.unwrap();

        // L1 entry must be evicted after extend
        assert!(cache
            .l1
            .as_ref()
            .unwrap()
            .get(&session_key("sess4"))
            .await
            .is_none());

        // TTL extension delegated to L2
        assert_eq!(
            stub.session_ttls.lock().unwrap().get("sess4").cloned(),
            Some(7200)
        );
    }

    // ── L1-only: code_verifier ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_l1_only_set_get_code_verifier() {
        let cache = make_l1_only();

        cache.set_code_verifier("s_l1", "v_l1").await.unwrap();

        assert!(cache.l2.is_none());
        assert_eq!(
            cache.get_code_verifier("s_l1").await.unwrap(),
            Some("v_l1".to_string())
        );
    }

    #[tokio::test]
    async fn test_l1_only_get_code_verifier_miss() {
        let cache = make_l1_only();
        assert_eq!(cache.get_code_verifier("absent").await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_l1_only_invalidate_code_verifier() {
        let cache = make_l1_only();

        cache.set_code_verifier("s_inv", "v_inv").await.unwrap();
        cache.invalidate_code_verifier("s_inv").await.unwrap();

        assert_eq!(cache.get_code_verifier("s_inv").await.unwrap(), None);
    }

    // ── L1-only: auth_session ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_l1_only_set_get_auth_session() {
        let cache = make_l1_only();
        let session = sample_session();

        cache
            .set_auth_session("l1_sess", session.clone())
            .await
            .unwrap();

        assert!(cache.l2.is_none());
        assert_eq!(
            cache.get_auth_session("l1_sess").await.unwrap(),
            Some(session)
        );
    }

    #[tokio::test]
    async fn test_l1_only_get_auth_session_miss() {
        let cache = make_l1_only();
        assert_eq!(cache.get_auth_session("absent").await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_l1_only_invalidate_auth_session() {
        let cache = make_l1_only();
        let session = sample_session();

        cache.set_auth_session("l1_inv", session).await.unwrap();
        cache.invalidate_auth_session("l1_inv").await.unwrap();

        assert_eq!(cache.get_auth_session("l1_inv").await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_l1_only_extend_reinserts_entry() {
        let cache = make_l1_only();
        let session = sample_session();

        cache
            .set_auth_session("l1_ext", session.clone())
            .await
            .unwrap();

        // Entry must be present before extend
        assert!(cache
            .l1
            .as_ref()
            .unwrap()
            .get(&session_key("l1_ext"))
            .await
            .is_some());

        // extend_auth_session should succeed without panicking
        cache.extend_auth_session("l1_ext", 3600).await.unwrap();

        // Entry should still be accessible after re-insertion
        assert_eq!(
            cache.get_auth_session("l1_ext").await.unwrap(),
            Some(session)
        );
    }

    #[tokio::test]
    async fn test_l1_only_extend_absent_entry_is_noop() {
        let cache = make_l1_only();
        // Extending a non-existent entry should not error
        let result = cache.extend_auth_session("nonexistent", 3600).await;
        assert!(result.is_ok());
    }

    // ── L2-only: code_verifier ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_l2_only_set_get_code_verifier() {
        let stub = StubL2::new();
        let cache = make_l2_only(&stub);

        cache.set_code_verifier("s_l2", "v_l2").await.unwrap();

        assert!(cache.l1.is_none());
        assert_eq!(
            cache.get_code_verifier("s_l2").await.unwrap(),
            Some("v_l2".to_string())
        );
        assert_eq!(
            stub.get_code_verifier("s_l2").await.unwrap(),
            Some("v_l2".to_string())
        );
    }

    #[tokio::test]
    async fn test_l2_only_invalidate_code_verifier() {
        let stub = StubL2::new();
        let cache = make_l2_only(&stub);

        cache.set_code_verifier("s_l2_inv", "v").await.unwrap();
        cache.invalidate_code_verifier("s_l2_inv").await.unwrap();

        assert_eq!(cache.get_code_verifier("s_l2_inv").await.unwrap(), None);
    }

    // ── L2-only: auth_session ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_l2_only_set_get_auth_session() {
        let stub = StubL2::new();
        let cache = make_l2_only(&stub);
        let session = sample_session();

        cache
            .set_auth_session("l2_sess", session.clone())
            .await
            .unwrap();

        assert!(cache.l1.is_none());
        assert_eq!(
            cache.get_auth_session("l2_sess").await.unwrap(),
            Some(session.clone())
        );
        assert_eq!(
            stub.get_auth_session("l2_sess").await.unwrap(),
            Some(session)
        );
    }

    #[tokio::test]
    async fn test_l2_only_extend_auth_session() {
        let stub = StubL2::new();
        let cache = make_l2_only(&stub);
        let session = sample_session();

        cache.set_auth_session("l2_ext", session).await.unwrap();
        cache.extend_auth_session("l2_ext", 9000).await.unwrap();

        assert_eq!(
            stub.session_ttls.lock().unwrap().get("l2_ext").cloned(),
            Some(9000)
        );
    }

    // ── TTI configuration ─────────────────────────────────────────────────────

    #[test]
    fn test_cache_with_tti() {
        let config = TwoTierCacheConfig {
            l1_max_capacity: 50,
            l1_ttl_sec: 120,
            l1_time_to_idle_sec: Some(30),
            enable_l1: true,
        };
        // Verify construction succeeds; TTI is enforced by Moka internally.
        let cache = TwoTierAuthCache::new(None, config).unwrap();
        assert!(cache.l1.is_some());
        assert_eq!(cache.config().l1_time_to_idle_sec, Some(30));
    }
}
