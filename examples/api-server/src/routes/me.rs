//! `GET /api/me` — return the caller's display name from JWT claims.
//!
//! Resolution order for the display value:
//!   1. `name`  — end-user's full name
//!   2. `email` — end-user's e-mail address
//!   3. `sub`   — subject identifier (always present in a valid JWT)
//!
//! If no valid Bearer token is present [`JwtLayer`] leaves the extension
//! absent; the handler then returns `404 Not Found` with the body `"guest"`.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use axum_oidc_client::extractors::OptionalJwtClaims;
use axum_oidc_client::jwt::OidcClaims;
use serde_json::json;

/// `GET /api/me`
///
/// Returns a plain-text string identifying the caller:
/// - `200 OK`  + display name — when a valid Bearer token is present
/// - `404 Not Found` + `"guest"` — when no token or an invalid token is sent
pub async fn me(OptionalJwtClaims(claims): OptionalJwtClaims<OidcClaims>) -> impl IntoResponse {
    match claims {
        Some(c) => {
            let identity = c
                .name
                .filter(|s| !s.is_empty())
                .or_else(|| c.email.filter(|s| !s.is_empty()))
                .unwrap_or(c.sub);

            (StatusCode::OK, Json(json!({ "identity": identity })))
        }
        None => (StatusCode::NOT_FOUND, Json(json!({ "identity": "guest" }))),
    }
}
