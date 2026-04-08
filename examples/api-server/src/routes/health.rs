//! Health-check route handler.
//!
//! Provides a public `GET /health` endpoint that load-balancers, container
//! orchestrators (Kubernetes liveness / readiness probes, Docker health-check
//! directives) and monitoring systems can poll to confirm the process is up.
//!
//! # Route
//!
//! - `GET /health`
//!
//! # Authentication
//!
//! This route is intentionally **public** and must be registered **outside**
//! the [`axum_oidc_client::jwt::JwtLayer`] so that it never requires a Bearer
//! token and is never rejected with `401 Unauthorized`.
//!
//! # Response
//!
//! Always returns `200 OK` with `Content-Type: application/json`:
//!
//! ```json
//! {
//!   "status":  "ok",
//!   "service": "axum-api-server",
//!   "version": "0.1.0"
//! }
//! ```
//!
//! The `service` and `version` fields are populated at compile time from the
//! crate's `Cargo.toml` via [`env!`], so they are always accurate and add zero
//! runtime overhead.

use axum::{Json, http::StatusCode, response::IntoResponse};
use serde::Serialize;

/// JSON body returned by `GET /health`.
#[derive(Serialize)]
struct Health {
    /// Always `"ok"`.
    status: &'static str,
    /// Crate name from `Cargo.toml` (`CARGO_PKG_NAME`).
    service: &'static str,
    /// Crate version from `Cargo.toml` (`CARGO_PKG_VERSION`).
    version: &'static str,
}

/// `GET /health` handler.
///
/// Returns `200 OK` with a JSON body describing the service name and version.
/// No authentication is required — register this route outside [`JwtLayer`].
///
/// # Example response
///
/// ```json
/// { "status": "ok", "service": "axum-api-server", "version": "0.1.0" }
/// ```
pub async fn health() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(Health {
            status: "ok",
            service: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        }),
    )
}
