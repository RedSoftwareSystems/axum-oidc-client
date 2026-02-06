use axum::{
    extract::FromRequestParts,
    http::request::Parts,
    response::{IntoResponse, Response},
};
use futures_util::future::BoxFuture;
use std::ops::Deref;

use super::shared::extract_auth_session;
use crate::auth_session::AuthSession;

impl<S> FromRequestParts<S> for AuthSession
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
            extract_auth_session(parts)
                .await
                .map_err(IntoResponse::into_response)
        })
    }
}

/// Optional extractor for AuthSession that can be used in route handlers
/// This extracts the authenticated user's session if present,
/// returning None if the user is not authenticated
pub struct OptionalAuthSession(pub Option<AuthSession>);

impl Deref for OptionalAuthSession {
    type Target = Option<AuthSession>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> FromRequestParts<S> for OptionalAuthSession
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
            let session = extract_auth_session(parts).await.ok();
            Ok(OptionalAuthSession(session))
        })
    }
}
