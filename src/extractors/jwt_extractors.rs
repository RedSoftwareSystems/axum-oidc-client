//! JWT claim extractors for Axum route handlers.
//!
//! These extractors read the decoded JWT claims that [`JwtLayer`] injects as a
//! request extension.  They work for any claims type `C` that implements
//! [`serde::de::DeserializeOwned`] + [`Clone`] + [`Send`] + [`Sync`] +
//! `'static` — use [`OidcClaims`] for standard OIDC tokens or a custom struct
//! for application-specific claims.
//!
//! | Extractor | Behaviour when token is absent or invalid |
//! |-----------|------------------------------------------|
//! | [`JwtClaims<C>`] | Returns `401 Unauthorized` |
//! | [`OptionalJwtClaims<C>`] | Returns `None`; never rejects |
//!
//! # Prerequisites
//!
//! The [`JwtLayer`](crate::jwt::JwtLayer) middleware must be applied to the
//! router *before* these extractors are used.  The layer validates the Bearer
//! token and inserts the decoded claims as a request extension; the extractors
//! simply read that extension.
//!
//! [`OidcClaims`]: crate::jwt::OidcClaims

use std::ops::Deref;

use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use futures_util::future::BoxFuture;
use serde::de::DeserializeOwned;

// ── JwtClaims ─────────────────────────────────────────────────────────────────

/// Axum extractor that yields the decoded JWT claims for the current request.
///
/// Returns `401 Unauthorized` when:
/// - no `Authorization: Bearer` header is present, or
/// - the token is invalid (expired, wrong audience, bad signature, …).
///
/// [`JwtLayer`](crate::jwt::JwtLayer) must be applied to the router for this
/// extractor to work.  Use [`OptionalJwtClaims<C>`] on routes that serve both
/// authenticated and anonymous users.
///
/// # Example
///
/// ```rust,no_run
/// use axum_oidc_client::extractors::JwtClaims;
/// use axum_oidc_client::jwt::OidcClaims;
///
/// async fn handler(JwtClaims(claims): JwtClaims<OidcClaims>) -> String {
///     format!("Hello, {}!", claims.sub)
/// }
/// ```
pub struct JwtClaims<C>(pub C);

impl<C> Deref for JwtClaims<C> {
    type Target = C;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S, C> FromRequestParts<S> for JwtClaims<C>
where
    S: Send + Sync,
    C: DeserializeOwned + Clone + Send + Sync + 'static,
{
    type Rejection = Response;

    #[allow(refining_impl_trait)]
    fn from_request_parts<'a>(
        parts: &'a mut Parts,
        _state: &S,
    ) -> BoxFuture<'a, Result<Self, Self::Rejection>> {
        Box::pin(async move {
            parts
                .extensions
                .get::<C>()
                .cloned()
                .map(JwtClaims)
                .ok_or_else(|| {
                    (StatusCode::UNAUTHORIZED, "Missing or invalid Bearer token").into_response()
                })
        })
    }
}

// ── OptionalJwtClaims ─────────────────────────────────────────────────────────

/// Axum extractor that yields `Some(claims)` when a valid Bearer token is
/// present, or `None` for unauthenticated requests.
///
/// Unlike [`JwtClaims<C>`] this extractor never rejects a request, making it
/// suitable for public routes that can optionally display personalised content.
///
/// [`JwtLayer`](crate::jwt::JwtLayer) must be applied to the router for this
/// extractor to find injected claims.
///
/// # Example
///
/// ```rust,no_run
/// use axum_oidc_client::extractors::OptionalJwtClaims;
/// use axum_oidc_client::jwt::OidcClaims;
///
/// async fn handler(OptionalJwtClaims(claims): OptionalJwtClaims<OidcClaims>) -> String {
///     match claims {
///         Some(c) => format!("Hello, {}!", c.sub),
///         None    => "Hello, anonymous!".to_string(),
///     }
/// }
/// ```
pub struct OptionalJwtClaims<C>(pub Option<C>);

impl<C> Deref for OptionalJwtClaims<C> {
    type Target = Option<C>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S, C> FromRequestParts<S> for OptionalJwtClaims<C>
where
    S: Send + Sync,
    C: DeserializeOwned + Clone + Send + Sync + 'static,
{
    type Rejection = std::convert::Infallible;

    #[allow(refining_impl_trait)]
    fn from_request_parts<'a>(
        parts: &'a mut Parts,
        _state: &S,
    ) -> BoxFuture<'a, Result<Self, Self::Rejection>> {
        Box::pin(async move { Ok(OptionalJwtClaims(parts.extensions.get::<C>().cloned())) })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, serde::Deserialize)]
    struct TestClaims {
        sub: String,
    }

    fn parts_with_claims(claims: TestClaims) -> Parts {
        let mut req = axum::http::Request::new(());
        req.extensions_mut().insert(claims);
        req.into_parts().0
    }

    fn parts_empty() -> Parts {
        axum::http::Request::new(()).into_parts().0
    }

    #[tokio::test]
    async fn test_jwt_claims_present() {
        let mut parts = parts_with_claims(TestClaims {
            sub: "user-1".to_string(),
        });

        let result = JwtClaims::<TestClaims>::from_request_parts(&mut parts, &()).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().sub, "user-1");
    }

    #[tokio::test]
    async fn test_jwt_claims_absent_returns_401() {
        let mut parts = parts_empty();

        let result = JwtClaims::<TestClaims>::from_request_parts(&mut parts, &()).await;
        assert!(result.is_err());
        assert_eq!(result.err().unwrap().status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_optional_jwt_claims_present() {
        let mut parts = parts_with_claims(TestClaims {
            sub: "user-2".to_string(),
        });

        let result = OptionalJwtClaims::<TestClaims>::from_request_parts(&mut parts, &()).await;
        assert!(result.is_ok());
        let OptionalJwtClaims(inner) = result.unwrap();
        assert_eq!(inner.unwrap().sub, "user-2");
    }

    #[tokio::test]
    async fn test_optional_jwt_claims_absent_returns_none() {
        let mut parts = parts_empty();

        let result = OptionalJwtClaims::<TestClaims>::from_request_parts(&mut parts, &()).await;
        assert!(result.is_ok());
        let OptionalJwtClaims(inner) = result.unwrap();
        assert!(inner.is_none());
    }

    #[test]
    fn test_jwt_claims_deref() {
        let claims = JwtClaims(TestClaims {
            sub: "deref-test".to_string(),
        });
        assert_eq!(claims.sub, "deref-test");
    }

    #[test]
    fn test_optional_jwt_claims_deref() {
        let claims = OptionalJwtClaims(Some(TestClaims {
            sub: "deref-test".to_string(),
        }));
        assert!(claims.is_some());
    }
}
