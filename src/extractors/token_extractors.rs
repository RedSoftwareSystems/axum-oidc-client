use axum::{
    extract::FromRequestParts,
    http::request::Parts,
    response::{IntoResponse, Response},
};
use axum_extra::extract::PrivateCookieJar;
use futures_util::future::BoxFuture;
use reqwest::Client;
use std::{ops::Deref, sync::Arc};

use super::shared::extract_and_refresh_session;
use crate::{
    auth::{OAuthConfiguration, SESSION_KEY},
    auth_cache::AuthCache,
    errors::Error,
};

/// Shared extraction logic for refreshable tokens (access_token and id_token only)
async fn extract_refreshable_token<F>(
    parts: &mut Parts,
    field_extractor: F,
) -> Result<String, Error>
where
    F: FnOnce(&crate::auth_session::AuthSession) -> String,
{
    // Clone everything we need upfront to avoid lifetime issues
    let cache = parts
        .extensions
        .get::<Arc<dyn AuthCache + Send + Sync>>()
        .cloned();

    let config = parts.extensions.get::<Arc<OAuthConfiguration>>().cloned();

    let client = parts.extensions.get::<Arc<Client>>().cloned();

    let headers = parts.headers.clone();

    // Check cache, config, and client
    let cache = cache.ok_or_else(|| Error::AuthCacheNotConfigured)?;

    let config = config.ok_or_else(|| Error::OAuthConfigNotConfigured)?;

    let client = client.ok_or_else(|| Error::HttpClientNotConfigured)?;

    // Extract the session ID from the private cookie jar
    let jar = PrivateCookieJar::from_headers(&headers, config.private_cookie_key.clone());

    let session_id = jar
        .get(SESSION_KEY)
        .map(|cookie| cookie.value().to_string())
        .ok_or_else(|| Error::SessionNotFound)?;

    // Use shared logic to extract and refresh session if needed
    let session = extract_and_refresh_session(&cache, &config, &client, &session_id).await?;

    Ok(field_extractor(&session))
}

/// Extractor for access token that can be used in route handlers
/// This extracts the access token from the authenticated user's session
/// and automatically refreshes it if expired using OAuth2 refresh token flow
pub struct AccessToken(String);

impl Deref for AccessToken {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> FromRequestParts<S> for AccessToken
where
    S: Send + Sync,
{
    type Rejection = Response;

    #[allow(refining_impl_trait)]
    fn from_request_parts<'a>(
        parts: &'a mut Parts,
        _state: &S,
    ) -> BoxFuture<'a, Result<Self, Self::Rejection>> {
        Box::pin(async move {
            let token = extract_refreshable_token(parts, |session| session.access_token.clone())
                .await
                .map_err(IntoResponse::into_response)?;
            Ok(AccessToken(token))
        })
    }
}

/// Extractor for ID token that can be used in route handlers
/// This extracts the ID token from the authenticated user's session
/// and automatically refreshes it if expired using OAuth2 refresh token flow
pub struct IdToken(pub String);

impl Deref for IdToken {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> FromRequestParts<S> for IdToken
where
    S: Send + Sync,
{
    type Rejection = Response;

    #[allow(refining_impl_trait)]
    fn from_request_parts<'a>(
        parts: &'a mut Parts,
        _state: &S,
    ) -> BoxFuture<'a, Result<Self, Self::Rejection>> {
        Box::pin(async move {
            let token = extract_refreshable_token(parts, |session| session.id_token.clone())
                .await
                .map_err(IntoResponse::into_response)?;
            Ok(IdToken(token))
        })
    }
}

/// Optional extractor for access token that can be used in route handlers
/// This extracts the access token from the authenticated user's session if present,
/// returning None if the user is not authenticated
pub struct OptionalAccessToken(pub Option<String>);

impl Deref for OptionalAccessToken {
    type Target = Option<String>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> FromRequestParts<S> for OptionalAccessToken
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    #[allow(refining_impl_trait)]
    fn from_request_parts<'a>(
        parts: &'a mut Parts,
        _state: &S,
    ) -> BoxFuture<'a, Result<Self, Self::Rejection>> {
        Box::pin(async move {
            let token = extract_refreshable_token(parts, |session| session.access_token.clone())
                .await
                .ok();
            Ok(OptionalAccessToken(token))
        })
    }
}

/// Optional extractor for ID token that can be used in route handlers
/// This extracts the ID token from the authenticated user's session if present,
/// returning None if the user is not authenticated
pub struct OptionalIdToken(pub Option<String>);

impl Deref for OptionalIdToken {
    type Target = Option<String>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> FromRequestParts<S> for OptionalIdToken
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    #[allow(refining_impl_trait)]
    fn from_request_parts<'a>(
        parts: &'a mut Parts,
        _state: &S,
    ) -> BoxFuture<'a, Result<Self, Self::Rejection>> {
        Box::pin(async move {
            let token = extract_refreshable_token(parts, |session| session.id_token.clone())
                .await
                .ok();
            Ok(OptionalIdToken(token))
        })
    }
}
