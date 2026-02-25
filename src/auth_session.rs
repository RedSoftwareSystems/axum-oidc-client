//! Authentication session management module.
//!
//! This module defines the [`AuthSession`] struct which holds all token information
//! for an authenticated user session.

use chrono::prelude::*;
use serde::{Deserialize, Serialize};

/// Authenticated user session containing OAuth2/OIDC tokens.
///
/// This struct holds all the token information obtained from the OAuth2 provider
/// after successful authentication. It is stored in the cache and automatically
/// refreshed when tokens expire.
///
/// # Fields
///
/// * `id_token` - OpenID Connect ID token (JWT) containing user identity claims
/// * `access_token` - OAuth2 access token for API authorization
/// * `token_type` - Token type, typically "Bearer"
/// * `refresh_token` - Optional refresh token for obtaining new access tokens
/// * `scope` - Space-separated list of granted scopes
/// * `expires` - Optional expiration timestamp for the access token; `None` when neither
///   `expires_in` nor `token_max_age` were available at session creation
///
/// # Automatic Token Refresh
///
/// When used as an extractor in route handlers, this session is automatically
/// refreshed if the access token has expired. The refresh process:
///
/// 1. Checks if `expires` is `Some` and in the past; if `expires` is `None` the
///    refresh logic is skipped entirely (no expiry info was available)
/// 2. Uses `refresh_token` to request a new access token (if present)
/// 3. Updates `access_token`, `id_token`, and `expires` with fresh values
/// 4. Persists the updated session to cache
///
/// # Usage as Extractor
///
/// ```rust,no_run
/// use axum_oidc_client::auth_session::AuthSession;
///
/// async fn protected_route(session: AuthSession) -> String {
///     // Session is automatically refreshed if expired
///     let expires = session.expires
///         .map(|e| e.to_string())
///         .unwrap_or_else(|| "(no expiry)".to_string());
///     format!(
///         "Welcome! Your session:\n\
///          Token Type: {}\n\
///          Expires: {}\n\
///          Scopes: {}",
///         session.token_type,
///         expires,
///         session.scope.as_deref().unwrap_or("(none)")
///     )
/// }
/// ```
///
/// # Examples
///
/// ## Accessing Token Information
///
/// ```rust,no_run
/// use axum_oidc_client::auth_session::AuthSession;
///
/// async fn show_session(session: AuthSession) -> String {
///     format!("Access Token: {}", session.access_token)
/// }
/// ```
///
/// ## Making Authenticated API Calls
///
/// ```rust,no_run
/// use axum_oidc_client::auth_session::AuthSession;
/// use reqwest::Client;
///
/// async fn call_api(session: AuthSession) -> Result<String, Box<dyn std::error::Error>> {
///     let client = Client::new();
///     let response = client
///         .get("https://api.example.com/data")
///         .bearer_auth(&session.access_token)
///         .send()
///         .await?;
///     Ok(response.text().await?)
/// }
/// ```
///
/// ## Checking Expiration
///
/// ```rust,no_run
/// use axum_oidc_client::auth_session::AuthSession;
/// use chrono::Local;
///
/// async fn check_session(session: AuthSession) -> String {
///     let now = Local::now();
///     let is_expired = session.expires <= now;
///
///     // Note: When using the extractor, tokens are auto-refreshed
///     // so is_expired will typically be false
///     format!("Token expired: {}", is_expired)
/// }
/// ```
#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct AuthSession {
    /// OpenID Connect ID token (JWT) containing user identity information
    pub id_token: String,
    /// OAuth2 access token for authorizing API requests
    pub access_token: String,
    /// Token type, typically "Bearer"
    pub token_type: String,
    /// Optional refresh token for obtaining new access tokens when they expire.
    /// When absent, expired sessions cannot be refreshed and will require re-authentication.
    pub refresh_token: Option<String>,
    /// Space-separated list of OAuth2 scopes granted to this session
    pub scope: Option<String>,
    /// Optional expiration timestamp for the access token.
    /// `None` means neither `expires_in` nor `token_max_age` were present at session
    /// creation — in that case the token refresh logic is disabled entirely.
    pub expires: Option<DateTime<Local>>,
}

impl AuthSession {
    // Implement methods for the AuthSession struct
}
