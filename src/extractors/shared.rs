use axum::http::{request::Parts, StatusCode};
use axum_extra::extract::PrivateCookieJar;
use chrono::Local;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{
    auth::{calculate_token_expiration, OAuthConfiguration, SESSION_KEY},
    auth_cache::AuthCache,
    auth_session::AuthSession,
    errors::Error,
};

/// Response structure for token refresh requests
#[derive(Debug, Deserialize, Serialize)]
pub struct RefreshTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub id_token: Option<String>,
}

/// Refresh tokens using the refresh token flow
pub async fn refresh_tokens(
    client: &Client,
    configuration: &OAuthConfiguration,
    session: &AuthSession,
) -> Result<RefreshTokenResponse, Error> {
    let params = [
        ("grant_type", "refresh_token"),
        ("refresh_token", &session.refresh_token),
        ("client_id", &configuration.client_id),
    ];

    let url = reqwest::Url::parse(&configuration.token_endpoint)
        .map_err(|_| Error::NotValidUri(configuration.token_endpoint.clone()))?;

    let res = client
        .post(url)
        .form(&params)
        .basic_auth(
            &configuration.client_id,
            if configuration.client_secret.is_empty() {
                None
            } else {
                Some(&configuration.client_secret)
            },
        )
        .send()
        .await?;

    match res.status() {
        StatusCode::OK => {
            let refresh_response = res.json::<RefreshTokenResponse>().await?;
            Ok(refresh_response)
        }
        status => {
            let error_text = res.text().await.unwrap_or_default();
            Err(Error::from_status_code(status, error_text))
        }
    }
}

/// Extract and potentially refresh an authentication session
pub async fn extract_and_refresh_session(
    cache: &Arc<dyn AuthCache + Send + Sync>,
    config: &Arc<OAuthConfiguration>,
    client: &Arc<Client>,
    session_id: &str,
) -> Result<AuthSession, Error> {
    // Retrieve the session from cache
    let mut session = cache
        .get_auth_session(session_id)
        .await
        .map_err(|err| Error::CacheAccessError(format!("{err:?}")))?
        .ok_or_else(|| Error::SessionExpired)?;

    // Check if the token is expired
    let now = Local::now();
    if session.expires <= now {
        // Token is expired, try to refresh it
        match refresh_tokens(client, config, &session).await {
            Ok(refresh_response) => {
                // Update session with new token information
                session.access_token = refresh_response.access_token;
                session.token_type = refresh_response.token_type;

                // Update refresh token if provided
                if let Some(new_refresh_token) = refresh_response.refresh_token {
                    session.refresh_token = new_refresh_token;
                }

                // Update ID token if provided
                if let Some(new_id_token) = refresh_response.id_token {
                    session.id_token = new_id_token;
                }

                // Update scope if provided
                if let Some(new_scope) = refresh_response.scope {
                    session.scope = new_scope;
                }

                // Calculate new expiration time
                session.expires =
                    calculate_token_expiration(refresh_response.expires_in, config.token_max_age);

                // Save the updated session back to cache
                cache
                    .set_auth_session(session_id, session.clone())
                    .await
                    .map_err(|err| Error::SessionUpdateFailed(format!("{err:?}")))?;
            }
            Err(err) => {
                // Token refresh failed, return unauthorized
                return Err(Error::TokenRefreshFailedAuth(format!("{err:?}")));
            }
        }
    }

    Ok(session)
}

/// Shared authentication logic for token extractors
/// This function handles the common session extraction logic
pub async fn extract_auth_session(parts: &mut Parts) -> Result<AuthSession, Error> {
    // Clone everything we need upfront to avoid lifetime issues
    let cache = parts
        .extensions
        .get::<Arc<dyn AuthCache + Send + Sync>>()
        .cloned();

    let config = parts.extensions.get::<Arc<OAuthConfiguration>>().cloned();

    let client = parts.extensions.get::<Arc<Client>>().cloned();

    let headers = parts.headers.clone();

    // Check cache
    let cache = cache.ok_or_else(|| Error::AuthCacheNotConfigured)?;

    // Check config
    let config = config.ok_or_else(|| Error::OAuthConfigNotConfigured)?;

    // Check client
    let client = client.ok_or_else(|| Error::HttpClientNotConfigured)?;

    // Extract the session ID from the private cookie jar
    let jar = PrivateCookieJar::from_headers(&headers, config.private_cookie_key.clone());

    let session_id = jar
        .get(SESSION_KEY)
        .map(|cookie| cookie.value().to_string())
        .ok_or_else(|| Error::SessionNotFound)?;

    // Extract and refresh session if needed
    let session = extract_and_refresh_session(&cache, &config, &client, &session_id).await?;

    Ok(session)
}
