//! Shared test helpers for `auth_router` and related modules.
//!
//! Centralises the `MockCache` stub and `create_test_config` factory so every
//! test module in the crate can import them instead of duplicating the
//! boilerplate.

use axum_extra::extract::cookie::Key;
use futures_util::future::BoxFuture;

use crate::{
    authentication::{
        CodeChallengeMethod, OAuthConfiguration, cache::AuthCache, session::AuthSession,
    },
    errors::Error,
};

// ── MockCache ─────────────────────────────────────────────────────────────────

/// A no-op [`AuthCache`] for use in unit tests.
///
/// Every method returns the simplest valid value (`None` for reads, `Ok(())`
/// for writes) without touching any real storage.
#[allow(dead_code)]
pub(crate) struct MockCache;

impl AuthCache for MockCache {
    fn get_code_verifier(
        &self,
        _challenge_state: &str,
    ) -> BoxFuture<'_, Result<Option<String>, Error>> {
        Box::pin(async { Ok(None) })
    }

    fn set_code_verifier(
        &self,
        _challenge_state: &str,
        _code_verifier: &str,
    ) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async { Ok(()) })
    }

    fn invalidate_code_verifier(&self, _challenge_state: &str) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async { Ok(()) })
    }

    fn get_auth_session(&self, _id: &str) -> BoxFuture<'_, Result<Option<AuthSession>, Error>> {
        Box::pin(async { Ok(None) })
    }

    fn set_auth_session(
        &self,
        _id: &str,
        _session: AuthSession,
    ) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async { Ok(()) })
    }

    fn invalidate_auth_session(&self, _id: &str) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async { Ok(()) })
    }

    fn extend_auth_session(&self, _id: &str, _ttl: i64) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async { Ok(()) })
    }
}

// ── create_test_config ────────────────────────────────────────────────────────

/// Build a minimal [`OAuthConfiguration`] suitable for unit tests.
///
/// Uses a zero-filled cookie key (acceptable in tests; never use in
/// production) and localhost URLs so tests do not require network access.
/// All optional fields are set to sensible defaults.
pub(crate) fn create_test_config() -> OAuthConfiguration {
    OAuthConfiguration {
        private_cookie_key: Key::from(&[0u8; 64]),
        client_id: "test-client".to_string(),
        client_secret: "test-secret".to_string(),
        redirect_uri: "http://localhost:8080/auth/callback".to_string(),
        token_request_redirect_uri: true,
        authorization_endpoint: "http://localhost/auth".to_string(),
        token_endpoint: "http://localhost/token".to_string(),
        end_session_endpoint: None,
        post_logout_redirect_uri: "/".to_string(),
        scopes: "openid email".to_string(),
        code_challenge_method: CodeChallengeMethod::S256,
        session_max_age: 30,
        token_max_age: Some(60),
        custom_ca_cert: None,
        base_path: "/auth".to_string(),
    }
}
