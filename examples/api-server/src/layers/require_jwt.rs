//! [`RequireJwtLayer`] — a thin Tower middleware that guards a nested router
//! by checking whether [`OidcClaims`] have already been injected into the
//! request extensions by the outer [`JwtLayer`].
//!
//! # Responsibility split
//!
//! | Layer              | Responsibility                                      |
//! |--------------------|-----------------------------------------------------|
//! | Outer `JwtLayer`   | Decodes and validates the Bearer token; injects     |
//! |                    | `OidcClaims` into extensions on success, silent on  |
//! |                    | failure or absence.                                 |
//! | `RequireJwtLayer`  | Checks that `OidcClaims` is present; returns        |
//! |                    | `401 Unauthorized` immediately if it is not.        |
//!
//! This means `RequireJwtLayer` never touches cryptography — it simply treats
//! the absence of the extension as "not authenticated" and short-circuits
//! before the inner service is called.

use std::task::{Context, Poll};

use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::{IntoResponse, Json, Response},
};
use futures_util::future::BoxFuture;
use serde_json::json;
use tower::{Layer, Service as TowerService};

use axum_oidc_client::jwt::OidcClaims;

// ── RequireJwtLayer ───────────────────────────────────────────────────────────

/// Tower [`Layer`] that rejects requests without injected [`OidcClaims`].
///
/// Apply this to a nested router **after** the outer [`JwtLayer`] is already
/// on the root router.  The outer layer decodes the token; this layer only
/// checks the result.
///
/// ```text
/// Router
/// ├── /api/me              ← outer JwtLayer handles everything (claims optional)
/// └── /protected  ← RequireJwtLayer rejects if no claims → 401
///     ├── /resource1
///     └── /resource2
/// ```
#[derive(Clone)]
pub struct RequireJwtLayer;

impl<S> Layer<S> for RequireJwtLayer {
    type Service = RequireJwtMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequireJwtMiddleware { inner }
    }
}

// ── RequireJwtMiddleware ──────────────────────────────────────────────────────

/// Tower [`Service`] produced by [`RequireJwtLayer`].
#[derive(Clone)]
pub struct RequireJwtMiddleware<S> {
    inner: S,
}

impl<S> TowerService<Request<Body>> for RequireJwtMiddleware<S>
where
    S: TowerService<Request<Body>, Response = Response> + Send + Clone + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Response, S::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        // Check whether the outer JwtLayer successfully injected OidcClaims.
        let authenticated = request.extensions().get::<OidcClaims>().is_some();

        if authenticated {
            let future = self.inner.call(request);
            Box::pin(async move { future.await })
        } else {
            Box::pin(async move {
                Ok((
                    StatusCode::UNAUTHORIZED,
                    Json(json!({ "error": "authentication required" })),
                )
                    .into_response())
            })
        }
    }
}
