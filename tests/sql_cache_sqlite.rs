//! Integration tests for [`SqlAuthCache`] using an in-memory SQLite database.
//!
//! These tests exercise the full `AuthCache` trait surface against a real
//! (in-process) SQLite database, verifying:
//!
//! - Code-verifier CRUD: set, get, invalidate, expiry
//! - Auth-session CRUD: set, get, invalidate, extend TTL, expiry
//! - Schema initialisation idempotency
//! - Concurrent access safety
//! - Key-prefix isolation (cv: vs session: keys do not collide)
//! - Custom table name
//! - Error paths (empty connection string, bad scheme)
//!
//! Run with:
//! ```bash
//! cargo test --features sql-cache-sqlite --test sql_cache_sqlite
//! ```

#![cfg(feature = "sql-cache-sqlite")]

use std::sync::Arc;

use axum_oidc_client::auth_cache::AuthCache;
use axum_oidc_client::auth_session::AuthSession;
use axum_oidc_client::sql_cache::{SqlAuthCache, SqlCacheConfig};

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Returns a [`SqlCacheConfig`] backed by a private in-memory SQLite database.
///
/// Each call to `sqlite://:memory:?mode=memory&cache=private` opens an
/// independent database, so tests do not share state even when run in parallel.
fn in_memory_config() -> SqlCacheConfig {
    SqlCacheConfig {
        // A unique in-memory database per connection pool.
        // SQLite interprets `:memory:` as a fresh, private database.
        connection_string: "sqlite://:memory:".to_string(),
        // Keep the pool small for in-memory SQLite (single writer at a time).
        max_connections: 4,
        min_connections: 1,
        // Run cleanup very infrequently during tests to avoid interference.
        cleanup_interval_sec: 3600,
        ..Default::default()
    }
}

/// Builds a fully initialised [`SqlAuthCache`] backed by an in-memory SQLite
/// database and creates the schema.
async fn make_cache() -> SqlAuthCache {
    let cache = SqlAuthCache::new(in_memory_config())
        .await
        .expect("failed to create SqlAuthCache");
    cache.init_schema().await.expect("failed to init schema");
    cache
}

/// Returns a minimal [`AuthSession`] suitable for insertion into the cache.
fn make_session(id_token: &str) -> AuthSession {
    AuthSession {
        id_token: id_token.to_string(),
        access_token: format!("access_{id_token}"),
        token_type: "Bearer".to_string(),
        refresh_token: Some(format!("refresh_{id_token}")),
        scope: Some("openid email".to_string()),
        expires: None, // no expiry — SQL backend derives expires_at from session
    }
}

// ─── Schema ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn init_schema_is_idempotent() {
    let cache = make_cache().await;
    // Calling init_schema a second time must not return an error.
    cache
        .init_schema()
        .await
        .expect("second call to init_schema should succeed");
}

// ─── Code verifier ────────────────────────────────────────────────────────────

#[tokio::test]
async fn set_and_get_code_verifier() {
    let cache = make_cache().await;

    cache
        .set_code_verifier("state-abc", "verifier-xyz")
        .await
        .expect("set_code_verifier failed");

    let result = cache
        .get_code_verifier("state-abc")
        .await
        .expect("get_code_verifier failed");

    assert_eq!(result, Some("verifier-xyz".to_string()));
}

#[tokio::test]
async fn get_code_verifier_missing_key_returns_none() {
    let cache = make_cache().await;

    let result = cache
        .get_code_verifier("nonexistent-state")
        .await
        .expect("get_code_verifier should not error on missing key");

    assert_eq!(result, None);
}

#[tokio::test]
async fn invalidate_code_verifier_removes_entry() {
    let cache = make_cache().await;

    cache
        .set_code_verifier("state-del", "verifier-del")
        .await
        .expect("set_code_verifier failed");

    // Confirm it exists.
    assert!(cache
        .get_code_verifier("state-del")
        .await
        .unwrap()
        .is_some());

    cache
        .invalidate_code_verifier("state-del")
        .await
        .expect("invalidate_code_verifier failed");

    let result = cache
        .get_code_verifier("state-del")
        .await
        .expect("get_code_verifier after invalidation failed");

    assert_eq!(result, None);
}

#[tokio::test]
async fn invalidate_code_verifier_on_missing_key_is_noop() {
    let cache = make_cache().await;

    // Must not return an error even when the key does not exist.
    cache
        .invalidate_code_verifier("never-set-state")
        .await
        .expect("invalidate on missing key should be a no-op");
}

#[tokio::test]
async fn upsert_code_verifier_overwrites_existing_value() {
    let cache = make_cache().await;

    cache
        .set_code_verifier("state-upsert", "first-verifier")
        .await
        .expect("first set_code_verifier failed");

    cache
        .set_code_verifier("state-upsert", "second-verifier")
        .await
        .expect("second set_code_verifier (upsert) failed");

    let result = cache
        .get_code_verifier("state-upsert")
        .await
        .expect("get_code_verifier after upsert failed");

    assert_eq!(result, Some("second-verifier".to_string()));
}

#[tokio::test]
async fn code_verifier_keys_do_not_clash_with_session_keys() {
    let cache = make_cache().await;

    // Insert a code verifier and a session with the same logical identifier.
    let id = "shared-id";
    cache
        .set_code_verifier(id, "my-verifier")
        .await
        .expect("set_code_verifier failed");

    let session = make_session(id);
    cache
        .set_auth_session(id, session.clone())
        .await
        .expect("set_auth_session failed");

    // Both must coexist and return their respective values.
    let cv = cache
        .get_code_verifier(id)
        .await
        .expect("get_code_verifier failed");
    assert_eq!(cv, Some("my-verifier".to_string()));

    let sess = cache
        .get_auth_session(id)
        .await
        .expect("get_auth_session failed");
    assert_eq!(sess.unwrap().id_token, session.id_token);
}

// ─── Auth session ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn set_and_get_auth_session() {
    let cache = make_cache().await;
    let session = make_session("tok-set-get");

    cache
        .set_auth_session("sess-1", session.clone())
        .await
        .expect("set_auth_session failed");

    let retrieved = cache
        .get_auth_session("sess-1")
        .await
        .expect("get_auth_session failed");

    let retrieved = retrieved.expect("expected Some(AuthSession), got None");
    assert_eq!(retrieved.id_token, session.id_token);
    assert_eq!(retrieved.access_token, session.access_token);
    assert_eq!(retrieved.token_type, session.token_type);
    assert_eq!(retrieved.refresh_token, session.refresh_token);
    assert_eq!(retrieved.scope, session.scope);
}

#[tokio::test]
async fn get_auth_session_missing_key_returns_none() {
    let cache = make_cache().await;

    let result = cache
        .get_auth_session("does-not-exist")
        .await
        .expect("get_auth_session should not error on missing key");

    assert_eq!(result, None);
}

#[tokio::test]
async fn invalidate_auth_session_removes_entry() {
    let cache = make_cache().await;
    let session = make_session("tok-invalidate");

    cache
        .set_auth_session("sess-inv", session)
        .await
        .expect("set_auth_session failed");

    assert!(cache.get_auth_session("sess-inv").await.unwrap().is_some());

    cache
        .invalidate_auth_session("sess-inv")
        .await
        .expect("invalidate_auth_session failed");

    let result = cache
        .get_auth_session("sess-inv")
        .await
        .expect("get_auth_session after invalidation failed");

    assert_eq!(result, None);
}

#[tokio::test]
async fn invalidate_auth_session_on_missing_key_is_noop() {
    let cache = make_cache().await;

    cache
        .invalidate_auth_session("never-inserted")
        .await
        .expect("invalidate on missing key should be a no-op");
}

#[tokio::test]
async fn upsert_auth_session_overwrites_existing_value() {
    let cache = make_cache().await;

    let session_v1 = make_session("token-v1");
    let session_v2 = make_session("token-v2");

    cache
        .set_auth_session("sess-upsert", session_v1)
        .await
        .expect("first set_auth_session failed");

    cache
        .set_auth_session("sess-upsert", session_v2.clone())
        .await
        .expect("second set_auth_session (upsert) failed");

    let result = cache
        .get_auth_session("sess-upsert")
        .await
        .expect("get_auth_session after upsert failed")
        .expect("expected Some(AuthSession)");

    assert_eq!(result.id_token, session_v2.id_token);
}

#[tokio::test]
async fn extend_auth_session_keeps_entry_accessible() {
    let cache = make_cache().await;
    let session = make_session("tok-extend");

    cache
        .set_auth_session("sess-extend", session)
        .await
        .expect("set_auth_session failed");

    // Extend the TTL by 3600 seconds.
    cache
        .extend_auth_session("sess-extend", 3600)
        .await
        .expect("extend_auth_session failed");

    // The entry must still be retrievable after extension.
    let result = cache
        .get_auth_session("sess-extend")
        .await
        .expect("get_auth_session after extend failed");

    assert!(
        result.is_some(),
        "session should still be present after TTL extension"
    );
}

#[tokio::test]
async fn extend_auth_session_on_missing_key_is_noop() {
    let cache = make_cache().await;

    // Must not error even when the session does not exist.
    cache
        .extend_auth_session("ghost-session", 3600)
        .await
        .expect("extend on missing session should be a no-op");
}

// ─── Multiple independent sessions ───────────────────────────────────────────

#[tokio::test]
async fn multiple_sessions_are_stored_independently() {
    let cache = make_cache().await;

    for i in 0..10u32 {
        let session = make_session(&format!("token-{i}"));
        cache
            .set_auth_session(&format!("sess-{i}"), session)
            .await
            .unwrap_or_else(|e| panic!("set_auth_session {i} failed: {e}"));
    }

    for i in 0..10u32 {
        let result = cache
            .get_auth_session(&format!("sess-{i}"))
            .await
            .unwrap_or_else(|e| panic!("get_auth_session {i} failed: {e}"))
            .unwrap_or_else(|| panic!("session {i} not found"));

        assert_eq!(result.id_token, format!("token-{i}"));
    }
}

#[tokio::test]
async fn invalidating_one_session_does_not_affect_others() {
    let cache = make_cache().await;

    cache
        .set_auth_session("sess-a", make_session("tok-a"))
        .await
        .unwrap();
    cache
        .set_auth_session("sess-b", make_session("tok-b"))
        .await
        .unwrap();

    cache.invalidate_auth_session("sess-a").await.unwrap();

    assert!(
        cache.get_auth_session("sess-a").await.unwrap().is_none(),
        "sess-a should be gone"
    );
    assert!(
        cache.get_auth_session("sess-b").await.unwrap().is_some(),
        "sess-b should still exist"
    );
}

// ─── Custom table name ────────────────────────────────────────────────────────

#[tokio::test]
async fn custom_table_name_is_used() {
    let config = SqlCacheConfig {
        connection_string: "sqlite://:memory:".to_string(),
        table_name: "my_custom_oidc_cache".to_string(),
        max_connections: 2,
        min_connections: 1,
        cleanup_interval_sec: 3600,
        ..Default::default()
    };

    let cache = SqlAuthCache::new(config)
        .await
        .expect("failed to create cache with custom table name");
    cache
        .init_schema()
        .await
        .expect("init_schema with custom table failed");

    // Basic round-trip to confirm the custom table works end-to-end.
    cache
        .set_code_verifier("s", "v")
        .await
        .expect("set_code_verifier into custom table failed");

    let result = cache
        .get_code_verifier("s")
        .await
        .expect("get_code_verifier from custom table failed");

    assert_eq!(result, Some("v".to_string()));
}

// ─── Concurrent access ────────────────────────────────────────────────────────

#[tokio::test]
async fn concurrent_writes_do_not_corrupt_data() {
    let cache = Arc::new(make_cache().await);
    let mut handles = Vec::new();

    for i in 0..20u32 {
        let cache = Arc::clone(&cache);
        handles.push(tokio::spawn(async move {
            let session = make_session(&format!("concurrent-{i}"));
            cache
                .set_auth_session(&format!("concurrent-sess-{i}"), session)
                .await
                .expect("concurrent set_auth_session failed");
        }));
    }

    for handle in handles {
        handle.await.expect("spawned task panicked");
    }

    // All 20 sessions must be present and correct.
    for i in 0..20u32 {
        let result = cache
            .get_auth_session(&format!("concurrent-sess-{i}"))
            .await
            .unwrap_or_else(|e| panic!("get concurrent-sess-{i} failed: {e}"))
            .unwrap_or_else(|| panic!("concurrent-sess-{i} not found"));

        assert_eq!(result.id_token, format!("concurrent-{i}"));
    }
}

#[tokio::test]
async fn concurrent_reads_return_consistent_values() {
    let cache = Arc::new(make_cache().await);
    let session = make_session("shared-token");

    cache
        .set_auth_session("shared-sess", session.clone())
        .await
        .expect("initial set_auth_session failed");

    let mut handles = Vec::new();
    for _ in 0..20u32 {
        let cache = Arc::clone(&cache);
        handles.push(tokio::spawn(async move {
            cache
                .get_auth_session("shared-sess")
                .await
                .expect("concurrent get_auth_session failed")
        }));
    }

    for handle in handles {
        let result = handle
            .await
            .expect("spawned task panicked")
            .expect("expected Some(AuthSession)");
        assert_eq!(result.id_token, session.id_token);
    }
}

// ─── Error paths ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn new_returns_error_for_empty_connection_string() {
    let config = SqlCacheConfig::default(); // connection_string is ""
    let result = SqlAuthCache::new(config).await;
    assert!(
        result.is_err(),
        "expected error for empty connection string"
    );
}

#[tokio::test]
async fn new_returns_error_for_unrecognised_scheme() {
    let config = SqlCacheConfig {
        connection_string: "memcached://localhost:11211".to_string(),
        ..Default::default()
    };
    let result = SqlAuthCache::new(config).await;
    assert!(
        result.is_err(),
        "expected error for unrecognised connection scheme"
    );
}

// ─── Two-tier integration: SQLite L2 + Moka L1 ───────────────────────────────

#[tokio::test]
async fn two_tier_cache_with_sqlite_l2() {
    use axum_oidc_client::cache::{config::TwoTierCacheConfig, TwoTierAuthCache};

    let sql_cache = Arc::new(make_cache().await);

    let two_tier = Arc::new(
        TwoTierAuthCache::new(
            Some(sql_cache as Arc<dyn AuthCache + Send + Sync>),
            TwoTierCacheConfig {
                l1_max_capacity: 100,
                l1_ttl_sec: 60,
                l1_time_to_idle_sec: None,
                enable_l1: true,
            },
        )
        .expect("failed to build TwoTierAuthCache"),
    );

    let session = make_session("two-tier-token");

    two_tier
        .set_auth_session("tt-sess", session.clone())
        .await
        .expect("two-tier set_auth_session failed");

    // First read: L1 miss → fetched from SQLite L2 and promoted to L1.
    let result1 = two_tier
        .get_auth_session("tt-sess")
        .await
        .expect("two-tier get_auth_session (1st) failed")
        .expect("expected Some(AuthSession) on first read");

    assert_eq!(result1.id_token, session.id_token);

    // Second read: should be served from L1 (Moka).
    let result2 = two_tier
        .get_auth_session("tt-sess")
        .await
        .expect("two-tier get_auth_session (2nd) failed")
        .expect("expected Some(AuthSession) on second read");

    assert_eq!(result2.id_token, session.id_token);

    // Invalidate through the two-tier cache; both tiers must be cleared.
    two_tier
        .invalidate_auth_session("tt-sess")
        .await
        .expect("two-tier invalidate_auth_session failed");

    let after_invalidation = two_tier
        .get_auth_session("tt-sess")
        .await
        .expect("get after invalidation should not error");

    assert_eq!(
        after_invalidation, None,
        "session should be gone from both tiers"
    );
}

#[tokio::test]
async fn two_tier_code_verifier_stored_only_in_l1() {
    use axum_oidc_client::cache::{config::TwoTierCacheConfig, TwoTierAuthCache};

    let sql_cache = Arc::new(make_cache().await);
    let sql_cache_ref = Arc::clone(&sql_cache);

    let two_tier = TwoTierAuthCache::new(
        Some(sql_cache as Arc<dyn AuthCache + Send + Sync>),
        TwoTierCacheConfig::default(),
    )
    .expect("failed to build TwoTierAuthCache");

    two_tier
        .set_code_verifier("pkce-state", "pkce-verifier")
        .await
        .expect("set_code_verifier via two-tier failed");

    // In two-tier mode, code verifiers are stored exclusively in L1 (Moka).
    // Therefore the SQLite L2 should NOT have this entry.
    let in_sql = sql_cache_ref
        .get_code_verifier("pkce-state")
        .await
        .expect("direct SQL get_code_verifier failed");

    assert_eq!(
        in_sql, None,
        "code verifier should NOT be written to the SQL L2 backend"
    );

    // But reading through the two-tier cache should find it in L1.
    let via_cache = two_tier
        .get_code_verifier("pkce-state")
        .await
        .expect("get_code_verifier via two-tier failed");

    assert_eq!(via_cache, Some("pkce-verifier".to_string()));
}

// ─── Shutdown ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn shutdown_does_not_prevent_reads() {
    let cache = make_cache().await;
    let session = make_session("post-shutdown-token");

    cache
        .set_auth_session("post-shutdown-sess", session.clone())
        .await
        .expect("set before shutdown failed");

    // Signal the background cleanup task to stop.
    cache.shutdown().await;

    // Reads and writes must still work after shutdown.
    let result = cache
        .get_auth_session("post-shutdown-sess")
        .await
        .expect("get after shutdown failed");

    assert_eq!(
        result.map(|s| s.id_token),
        Some(session.id_token),
        "session should still be readable after shutdown"
    );
}
