//! Tower [`Layer`] and [`Service`] for JWT validation on every request.
//!
//! # Overview
//!
//! [`JwtLayer<C>`] is a Tower middleware that:
//!
//! 1. Extracts the `Authorization: Bearer <token>` header from every request.
//! 2. Decodes and validates the token against the supplied
//!    [`JwtConfiguration<C>`].
//! 3. Inserts the decoded claims as a request extension so downstream handlers
//!    can extract them with [`JwtClaims<C>`].
//!
//! Requests **without** a `Bearer` token, or with an invalid token, are not
//! rejected by the layer — the extension is simply absent.  Handlers that
//! require authentication should use [`JwtClaims<C>`] directly (which returns
//! `401` when the extension is missing) or the optional variant
//! [`OptionalJwtClaims<C>`] for public routes that can optionally present
//! personalised content.
//!
//! # Examples
//!
//! ```rust,no_run
//! use axum::{Router, routing::get, response::IntoResponse};
//! use axum_oidc_client::jwt::{
//!     JwtLayer, JwtConfigurationBuilder, Algorithm, DecodingKey, OidcClaims,
//! };
//! use axum_oidc_client::extractors::{JwtClaims, OptionalJwtClaims};
//! use std::sync::Arc;
//!
//! async fn protected(JwtClaims(claims): JwtClaims<OidcClaims>) -> impl IntoResponse {
//!     format!("Hello, {}!", claims.sub)
//! }
//!
//! async fn public(OptionalJwtClaims(claims): OptionalJwtClaims<OidcClaims>) -> impl IntoResponse {
//!     match claims {
//!         Some(c) => format!("Hello, {}!", c.sub),
//!         None    => "Hello, anonymous!".to_string(),
//!     }
//! }
//!
//! # async fn example() -> Result<(), axum_oidc_client::errors::Error> {
//! let key = DecodingKey::from_secret(b"my-secret");
//! let config = JwtConfigurationBuilder::<OidcClaims>::new()
//!     .with_decoding_key(key)
//!     .with_algorithm(Algorithm::HS256)
//!     .build()?;
//!
//! let app: Router<()> = Router::new()
//!     .route("/protected", get(protected))
//!     .route("/public",    get(public))
//!     .layer(JwtLayer::new(Arc::new(config)));
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;
use std::task::{Context, Poll};

use axum::{body::Body, http::Request, response::Response};
use futures_util::future::BoxFuture;
use serde::de::DeserializeOwned;
use tower::{Layer, Service};

use crate::jwt::configuration::JwtConfiguration;

// ── JwtLayer ──────────────────────────────────────────────────────────────────

/// Tower [`Layer`] that validates Bearer JWTs on every request.
///
/// Wrap your router with this layer; downstream handlers access the decoded
/// claims via the [`JwtClaims<C>`] extractor.
///
/// See the [module-level documentation](self) for a complete example.
#[derive(Clone)]
pub struct JwtLayer<C>
where
    C: DeserializeOwned + Clone + Send + Sync + 'static,
{
    config: Arc<JwtConfiguration<C>>,
}

impl<C> JwtLayer<C>
where
    C: DeserializeOwned + Clone + Send + Sync + 'static,
{
    /// Create a new [`JwtLayer`] from a shared [`JwtConfiguration`].
    pub fn new(config: Arc<JwtConfiguration<C>>) -> Self {
        Self { config }
    }
}

impl<S, C> Layer<S> for JwtLayer<C>
where
    C: DeserializeOwned + Clone + Send + Sync + 'static,
{
    type Service = JwtMiddleware<S, C>;

    fn layer(&self, inner: S) -> Self::Service {
        JwtMiddleware {
            inner,
            config: self.config.clone(),
        }
    }
}

// ── JwtMiddleware ─────────────────────────────────────────────────────────────

/// Tower [`Service`] produced by [`JwtLayer`].
///
/// You will not normally interact with this type directly; use [`JwtLayer`]
/// to wrap your router instead.
#[derive(Clone)]
pub struct JwtMiddleware<S, C>
where
    C: DeserializeOwned + Clone + Send + Sync + 'static,
{
    inner: S,
    config: Arc<JwtConfiguration<C>>,
}

impl<S, C> Service<Request<Body>> for JwtMiddleware<S, C>
where
    S: Service<Request<Body>, Response = Response> + Send + Clone + 'static,
    S::Future: Send + 'static,
    C: DeserializeOwned + Clone + Send + Sync + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Response, S::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        let config = self.config.clone();
        let mut inner = self.inner.clone();
        Box::pin(async move {
            // Extract the Bearer token from the Authorization header.
            if let Some(token) = bearer_token(request.headers()) {
                // Attempt to decode.  On success inject the claims; on failure
                // leave the extension absent — the extractor decides whether to
                // reject the request.
                if let Ok(claims) = decode_with_config::<C>(&token, &config).await {
                    request.extensions_mut().insert(claims);
                }
            }

            inner.call(request).await
        })
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Extract the raw token string from `Authorization: Bearer <token>`.
fn bearer_token(headers: &axum::http::HeaderMap) -> Option<String> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    value
        .strip_prefix("Bearer ")
        .map(str::trim)
        .map(String::from)
}

/// Decode a JWT using the provided [`JwtConfiguration`].
///
/// When the configuration was built from a JWKS:
/// 1. The `kid` header field selects the matching key from the cached set.
/// 2. If the `kid` is not found in the cache **or** signature verification
///    fails, the JWKS endpoint is re-fetched once (key rotation recovery).
/// 3. The freshly fetched key set is tried before returning an error.
///
/// This handles the common case where a provider (e.g. Google) rotates its
/// signing keys and the cached JWKS no longer contains the key that signed
/// the incoming token.
async fn decode_with_config<C>(
    token: &str,
    config: &JwtConfiguration<C>,
) -> Result<C, crate::errors::Error>
where
    C: DeserializeOwned,
{
    use crate::errors::Error;

    // ── Static key (no JWKS) — straight decode, no refresh logic needed ───────
    let Some(jwks) = &config.jwks else {
        return jsonwebtoken::decode::<C>(token, &config.decoding_key, &config.validation)
            .map(|td| td.claims)
            .map_err(|e| Error::InvalidResponse(format!("JWT validation failed: {e}")));
    };

    // ── JWKS-backed config — kid-matched decode with rotation recovery ─────────

    // Read only the header to extract the kid — no claims deserialisation needed
    // at this step, which avoids any schema-mismatch errors on the partial parse.
    let header = jsonwebtoken::decode_header(token)
        .map_err(|e| Error::InvalidResponse(format!("JWT header decode failed: {e}")))?;
    let kid = header.kid.as_deref().unwrap_or("");

    // Helper: attempt to verify the token against a given key set.
    let try_decode = |jwks: &crate::jwt::configuration::Jwks| {
        jwks.decoding_key_for_kid(kid).and_then(|key| {
            jsonwebtoken::decode::<C>(token, &key, &config.validation)
                .map(|td| td.claims)
                .map_err(|e| Error::InvalidResponse(format!("JWT validation failed: {e}")))
        })
    };

    // Check whether the cached JWKS contains a key for this kid.
    let kid_in_cache = jwks.keys.iter().any(|k| k.kid.as_deref() == Some(kid));

    if kid_in_cache {
        // The cached set has a matching key — try it immediately.
        let first_result = try_decode(jwks);
        if first_result.is_ok() {
            // Fast path: cache hit and valid signature — no refresh needed.
            return first_result;
        }
        // Cache had the kid but verification failed (e.g. the provider rotated
        // and the old key is now stale).  Fall through to refresh.
        tracing::debug!(
            kid = %kid,
            "Cached key present but verification failed; attempting JWKS refresh"
        );
        match config.refresh_jwks().await {
            Some(Ok(fresh_jwks)) => {
                tracing::debug!(
                    kid = %kid,
                    jwks_uri = ?config.jwks_uri,
                    "JWKS refreshed for key rotation recovery"
                );
                // Prefer the fresh-key error over the stale-key error so the
                // caller sees the most up-to-date failure reason.
                try_decode(&fresh_jwks)
            }
            Some(Err(refresh_err)) => {
                tracing::warn!(
                    error = %refresh_err,
                    "JWKS refresh failed; returning original decode error"
                );
                first_result
            }
            None => {
                // No jwks_uri configured — cannot refresh; return the stale error.
                first_result
            }
        }
    } else {
        // The kid is absent from the cache — the provider has almost certainly
        // rotated its keys.  Skip decoding against the stale set (it would
        // always fail) and go straight to a refresh.
        tracing::debug!(
            kid = %kid,
            "kid not found in cached JWKS; refreshing before decode"
        );
        match config.refresh_jwks().await {
            Some(Ok(fresh_jwks)) => {
                tracing::debug!(
                    kid = %kid,
                    jwks_uri = ?config.jwks_uri,
                    "JWKS refreshed; retrying decode with fresh key set"
                );
                try_decode(&fresh_jwks)
            }
            Some(Err(refresh_err)) => {
                tracing::warn!(
                    error = %refresh_err,
                    "JWKS refresh failed; kid not in cache"
                );
                Err(refresh_err)
            }
            None => {
                // No jwks_uri — can't refresh; best-effort decode against the
                // stale set (decoding_key_for_kid falls back to the first key).
                try_decode(jwks)
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::configuration::JwtConfigurationBuilder;
    use crate::jwt::jwt_decoder::{Algorithm, DecodingKey, EncodingKey};
    use crate::jwt::oidc::OidcClaims;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use axum::response::IntoResponse;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tower::ServiceExt;

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn make_token(sub: &str, secret: &[u8]) -> String {
        let claims = OidcClaims {
            sub: sub.to_string(),
            iss: "https://example.com".to_string(),
            aud: vec!["test-client".to_string()],
            exp: now() + 3600,
            iat: now(),
            nbf: None,
            jti: None,
            nonce: None,
            azp: None,
            at_hash: None,
            c_hash: None,
            auth_time: None,
            email: None,
            email_verified: None,
            name: None,
            given_name: None,
            family_name: None,
            picture: None,
            locale: None,
            zoneinfo: None,
            extra: Default::default(),
        };
        let key = EncodingKey::from_secret(secret);
        jsonwebtoken::encode(&jsonwebtoken::Header::default(), &claims, &key).unwrap()
    }

    fn config(secret: &[u8]) -> Arc<JwtConfiguration<OidcClaims>> {
        let cfg = JwtConfigurationBuilder::<OidcClaims>::new()
            .with_decoding_key(DecodingKey::from_secret(secret))
            .with_algorithm(Algorithm::HS256)
            .with_exp_validation(true)
            .build()
            .unwrap();
        Arc::new(cfg)
    }

    /// A minimal inner service that checks whether the OidcClaims extension
    /// is present and returns 200 with the sub, or 401 if absent.
    async fn claims_service(req: Request<Body>) -> Result<Response, std::convert::Infallible> {
        let sub = req.extensions().get::<OidcClaims>().map(|c| c.sub.clone());
        let response = match sub {
            Some(s) => (StatusCode::OK, s).into_response(),
            None => StatusCode::UNAUTHORIZED.into_response(),
        };
        Ok(response)
    }

    #[tokio::test]
    async fn test_valid_bearer_injects_claims() {
        let secret = b"test-secret";
        let token = make_token("alice", secret);

        let svc = JwtLayer::new(config(secret)).layer(tower::service_fn(claims_service));

        let req = Request::builder()
            .uri("/")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_no_header_does_not_inject_claims() {
        let secret = b"test-secret";

        let svc = JwtLayer::new(config(secret)).layer(tower::service_fn(claims_service));

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();

        let resp = svc.oneshot(req).await.unwrap();
        // No extension → inner service returns 401.
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_invalid_token_does_not_inject_claims() {
        let secret = b"test-secret";

        let svc = JwtLayer::new(config(secret)).layer(tower::service_fn(claims_service));

        let req = Request::builder()
            .uri("/")
            .header(header::AUTHORIZATION, "Bearer not.a.valid.token")
            .body(Body::empty())
            .unwrap();

        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_wrong_secret_does_not_inject_claims() {
        let signing_secret = b"correct-secret";
        let verify_secret = b"wrong-secret";
        let token = make_token("bob", signing_secret);

        let svc = JwtLayer::new(config(verify_secret)).layer(tower::service_fn(claims_service));

        let req = Request::builder()
            .uri("/")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_bearer_token_extraction() {
        // Ensure helper strips prefix correctly.
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer my.test.token".parse().unwrap(),
        );
        assert_eq!(bearer_token(&headers).as_deref(), Some("my.test.token"));
    }

    #[test]
    fn test_bearer_token_missing() {
        let headers = axum::http::HeaderMap::new();
        assert!(bearer_token(&headers).is_none());
    }

    #[test]
    fn test_bearer_token_non_bearer_scheme() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Basic dXNlcjpwYXNz".parse().unwrap());
        assert!(bearer_token(&headers).is_none());
    }
}
