//! Protected resource routes under `/protected`.
//!
//! Authentication is enforced by [`RequireJwtLayer`](crate::layers::require_jwt::RequireJwtLayer)
//! applied to the nested router in `main.rs`.  The outer [`JwtLayer`] on the
//! root router decodes the Bearer token; `RequireJwtLayer` rejects with
//! `401 Unauthorized` if no valid claims are present.  Handlers in this module
//! receive requests only when a valid JWT has already been verified.

use axum::response::{IntoResponse, Json};
use serde_json::json;

/// `GET /protected/resource1`
///
/// Returns `{"data": "protected resource 1"}`.
/// Unreachable without a valid Bearer token — `RequireJwtLayer` short-circuits
/// unauthenticated requests with `401` before this handler is called.
pub async fn resource1() -> impl IntoResponse {
    Json(json!({ "data": "protected resource 1" }))
}

/// `GET /protected/resource2`
///
/// Returns `{"data": "protected resource 2"}`.
/// Unreachable without a valid Bearer token — `RequireJwtLayer` short-circuits
/// unauthenticated requests with `401` before this handler is called.
pub async fn resource2() -> impl IntoResponse {
    Json(json!({ "data": "protected resource 2" }))
}
