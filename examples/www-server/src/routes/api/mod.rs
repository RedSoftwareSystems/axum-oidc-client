//! API reverse-proxy router.
//!
//! This module mounts a nested `/api` router that forwards every request to an
//! upstream API server, injecting the authenticated user's **ID token** as a
//! `Authorization: Bearer <id_token>` header.
//!
//! # Routes
//!
//! | Method | Path                        | Upstream target                     |
//! |--------|-----------------------------|-------------------------------------|
//! | `GET`  | `/api/me`                   | `{api_server}/me`                   |
//! | `GET`  | `/api/protected/resource1`  | `{api_server}/protected/resource1`  |
//! | `GET`  | `/api/protected/resource2`  | `{api_server}/protected/resource2`  |
//!
//! # Authentication
//!
//! All three routes require a valid [`AuthSession`].  The OIDC **ID token**
//! (not the access token) is forwarded to the upstream service so that it can
//! verify the caller's identity independently.
//!
//! # State
//!
//! A shared [`ApiState`] (holding the upstream base URL and a reused
//! [`reqwest::Client`]) is injected via Axum's [`State`] extractor.  Build it
//! with [`ApiState::new`] and pass the resulting [`axum::Router`] to
//! [`axum::Router::nest`]:
//!
//! ```rust,no_run
//! # use axum::Router;
//! # async fn example() {
//! let api_router = axum_www_server::routes::api::router("http://api-server", None);
//! let app: Router = Router::new().nest("/api", api_router);
//! # }
//! ```
//!
//! # Error handling
//!
//! - If the upstream request fails at the network level the handler returns
//!   `502 Bad Gateway` with a plain-text description.
//! - The upstream HTTP status code and response body are forwarded verbatim to
//!   the client.
//! - Response headers from the upstream that are safe to forward
//!   (`content-type`, `content-length`, `cache-control`, `etag`,
//!   `last-modified`) are preserved.

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderName, HeaderValue, Response, StatusCode},
    response::IntoResponse,
    routing::get,
};
use axum_oidc_client::extractors::OptionalAuthSession;
use reqwest::Client;
use std::sync::Arc;

// ── State ─────────────────────────────────────────────────────────────────────

/// Shared state for the API reverse-proxy router.
///
/// Holds:
/// - The base URL of the upstream API server (no trailing slash).
/// - A reused [`reqwest::Client`] so that connection pools are shared across
///   requests.
///
/// Clone is cheap — both fields are reference-counted / `Arc`-wrapped
/// internally.
#[derive(Clone)]
pub struct ApiState {
    /// Base URL of the upstream API server, e.g. `http://api-server`.
    /// No trailing slash.
    api_server: Arc<String>,
    /// Shared HTTP client for all upstream requests.
    client: Client,
}

impl ApiState {
    /// Create a new [`ApiState`].
    ///
    /// # Arguments
    ///
    /// * `api_server` – Base URL of the upstream API server.  A trailing slash
    ///   is stripped automatically.
    /// * `client`     – Optional pre-built [`reqwest::Client`].  When `None` a
    ///   default client is constructed.
    pub fn new(api_server: &str, client: Option<Client>) -> Self {
        Self {
            api_server: Arc::new(api_server.trim_end_matches('/').to_string()),
            client: client.unwrap_or_default(),
        }
    }
}

// ── Router factory ────────────────────────────────────────────────────────────

/// Build the `/api` nested router.
///
/// # Arguments
///
/// * `api_server` – Base URL of the upstream API server.
/// * `client`     – Optional [`reqwest::Client`].  `None` uses the default.
///
/// # Routes registered
///
/// - `GET /me`
/// - `GET /protected/resource1`
/// - `GET /protected/resource2`
pub fn router(api_server: &str, client: Option<Client>) -> Router {
    let state = ApiState::new(api_server, client);

    Router::new()
        .route("/me", get(me))
        .route("/protected/resource1", get(resource1))
        .route("/protected/resource2", get(resource2))
        .with_state(state)
}

// ── Core proxy helper ─────────────────────────────────────────────────────────

/// Forward a `GET` request to `{api_server}{upstream_path}`, injecting the
/// caller's ID token as an `Authorization: Bearer` header.
///
/// # Forwarded headers
///
/// The following upstream response headers are relayed to the client when
/// present:
///
/// - `content-type`
/// - `content-length`
/// - `cache-control`
/// - `etag`
/// - `last-modified`
///
/// # Errors
///
/// Returns `502 Bad Gateway` when the HTTP request to the upstream fails at
/// the transport layer (DNS failure, connection refused, timeout, …).
async fn proxy_request(
    client: &Client,
    api_server: &str,
    upstream_path: &str,
    id_token: Option<&str>,
) -> Response<Body> {
    let url = format!("{api_server}{upstream_path}");

    let mut request = client.get(&url);
    if let Some(token) = id_token {
        request = request.header("Authorization", format!("Bearer {token}"));
    }
    let result = request.send().await;

    match result {
        Err(err) => {
            let body = format!("Bad Gateway: upstream request to '{url}' failed — {err}");
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header("content-type", "text/plain; charset=utf-8")
                .body(Body::from(body))
                .unwrap_or_else(|_| (StatusCode::BAD_GATEWAY, "Bad Gateway").into_response())
        }
        Ok(upstream) => {
            let status = StatusCode::from_u16(upstream.status().as_u16())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

            // Headers we are willing to relay from the upstream response.
            const RELAY: &[&str] = &[
                "content-type",
                "content-length",
                "cache-control",
                "etag",
                "last-modified",
            ];

            let mut builder = Response::builder().status(status);

            for name in RELAY {
                if let Some(value) = upstream.headers().get(*name) {
                    // SAFETY: the header name literal is always valid.
                    let header_name = HeaderName::from_bytes(name.as_bytes())
                        .expect("static header name is valid");
                    if let Ok(v) = HeaderValue::from_bytes(value.as_bytes()) {
                        builder = builder.header(header_name, v);
                    }
                }
            }

            // Stream the upstream body bytes into an Axum `Body`.
            let bytes = match upstream.bytes().await {
                Ok(b) => b,
                Err(err) => {
                    let msg = format!("Bad Gateway: failed to read upstream body — {err}");
                    return Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .header("content-type", "text/plain; charset=utf-8")
                        .body(Body::from(msg))
                        .unwrap_or_else(|_| {
                            (StatusCode::BAD_GATEWAY, "Bad Gateway").into_response()
                        });
                }
            };

            builder.body(Body::from(bytes)).unwrap_or_else(|_| {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response()
            })
        }
    }
}

// ── Route handlers ────────────────────────────────────────────────────────────

/// `GET /api/me` — proxy to `{api_server}/me`.
///
/// Returns the identity information for the currently authenticated user as
/// provided by the upstream API server.
///
/// # Authentication
///
/// Requires a valid [`AuthSession`].  The ID token is forwarded to the
/// upstream as `Authorization: Bearer <id_token>`.
async fn me(
    State(state): State<ApiState>,
    OptionalAuthSession(session): OptionalAuthSession,
) -> impl IntoResponse {
    proxy_request(
        &state.client,
        &state.api_server,
        "/me",
        session.as_ref().map(|s| s.id_token.as_str()),
    )
    .await
}

/// `GET /api/protected/resource1` — proxy to `{api_server}/protected/resource1`.
///
/// # Authentication
///
/// Requires a valid [`AuthSession`].  The ID token is forwarded to the
/// upstream as `Authorization: Bearer <id_token>`.
async fn resource1(
    State(state): State<ApiState>,
    OptionalAuthSession(session): OptionalAuthSession,
) -> impl IntoResponse {
    proxy_request(
        &state.client,
        &state.api_server,
        "/protected/resource1",
        session.as_ref().map(|s| s.id_token.as_str()),
    )
    .await
}

/// `GET /api/protected/resource2` — proxy to `{api_server}/protected/resource2`.
///
/// # Authentication
///
/// Requires a valid [`AuthSession`].  The ID token is forwarded to the
/// upstream as `Authorization: Bearer <id_token>`.
async fn resource2(
    State(state): State<ApiState>,
    OptionalAuthSession(session): OptionalAuthSession,
) -> impl IntoResponse {
    proxy_request(
        &state.client,
        &state.api_server,
        "/protected/resource2",
        session.as_ref().map(|s| s.id_token.as_str()),
    )
    .await
}
