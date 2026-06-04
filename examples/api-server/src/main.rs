//! # api-server
//!
//! A minimal Axum API server demonstrating [`JwtLayer`] Bearer token validation
//! via OIDC auto-discovery.
//!
//! ## Routes
//!
//! | Route                       | Auth     | Description                                                     |
//! |-----------------------------|----------|-----------------------------------------------------------------|
//! | `GET /health`               | None     | Health-check — always `200 OK`, no token required               |
//! | `GET /me`                   | Optional | Returns the caller's display name from JWT claims, or `"guest"` |
//! | `GET /protected/resource1`  | Required | Returns `{"data": "protected resource 1"}` — 401 if no token   |
//! | `GET /protected/resource2`  | Required | Returns `{"data": "protected resource 2"}` — 401 if no token   |
//!
//! ## Bearer token resolution (`/me`)
//!
//! Identity is resolved from the decoded JWT claims in priority order:
//!
//! 1. `name`  — the end-user's full name
//! 2. `email` — the end-user's e-mail address
//! 3. `sub`   — the subject identifier (always present)
//!
//! Returns `404 Not Found` with body `"guest"` when no valid Bearer token is present.
//!
//! ## Configuration
//!
//! | Flag / env var                | Default       | Description                                          |
//! |-------------------------------|---------------|------------------------------------------------------|
//! | `--host` / `SERVER_HOST`      | `127.0.0.1`   | Bind address                                         |
//! | `--port` / `SERVER_PORT`      | `8181`        | Bind port                                            |
//! | `--issuer` / `OAUTH_ISSUER`   | *(required)*  | OIDC issuer URL; discovery doc fetched automatically |
//! | `--audience` / `API_OAUTH_AUDIENCE` | *(none)* | Expected JWT `aud` claim                     |
//! | `--custom-ca-cert` / `CUSTOM_CA_CERT` | *(none)* | PEM CA cert for private OIDC providers            |
//! | `DOTENV_FILE`                    | *(none)*      | Dotenv file loaded before CLI/env parsing         |
//!
//! ## Quick start
//!
//! ```bash
//! cargo run -p axum-api-server -- \
//!     --issuer https://accounts.google.com \
//!     --audience my-client-id
//! ```

mod layers;
mod routes;

use std::{env, net::SocketAddr, sync::Arc};

use axum::{Router, routing::get};
use clap::Parser;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

use axum_oidc_client::jwt::{JwtConfigurationBuilder, JwtLayer, OidcClaims};

// ── CLI arguments ─────────────────────────────────────────────────────────────

/// Minimal OIDC JWT-authenticated API server.
#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Args {
    /// Bind host address.
    #[arg(long, env = "SERVER_HOST", default_value = "127.0.0.1")]
    host: String,

    /// Bind port.
    #[arg(long, short, env = "SERVER_PORT", default_value_t = 8181)]
    port: u16,

    /// OIDC issuer URL.  The discovery document is fetched automatically from
    /// `<issuer>/.well-known/openid-configuration` and the JWKS endpoint
    /// is derived from it.  The algorithm is selected from the discovered keys.
    #[arg(long, env = "OAUTH_ISSUER")]
    issuer: String,

    /// Expected OAuth2/OIDC audience in incoming JWTs.
    ///
    /// Resolution order: CLI `--audience`, `API_OAUTH_AUDIENCE`, then legacy
    /// `OAUTH_AUDIENCE`.
    #[arg(long)]
    audience: Option<String>,

    /// Path to a PEM-encoded custom CA certificate for HTTPS requests to the
    /// OIDC issuer.  Only required when the provider uses a private CA.
    #[arg(long, env = "CUSTOM_CA_CERT")]
    custom_ca_cert: Option<String>,
}

impl Args {
    fn load_dotenv() {
        if let Ok(path) = env::var("DOTENV_FILE") {
            let _ = dotenv::from_path(path);
            return;
        }

        let _ = dotenv::from_filename("../.env.local")
            .or_else(|_| dotenv::from_filename(".env.local"))
            .or_else(|_| dotenv::dotenv());
    }

    fn parse_and_load() -> Self {
        Self::load_dotenv();
        Self::parse()
    }

    fn env_non_empty(key: &str) -> Option<String> {
        env::var(key).ok().filter(|value| !value.trim().is_empty())
    }

    fn resolved_audience(&self) -> Option<String> {
        self.audience
            .clone()
            .filter(|value| !value.trim().is_empty())
            .or_else(|| Self::env_non_empty("API_OAUTH_AUDIENCE"))
            .or_else(|| Self::env_non_empty("OAUTH_AUDIENCE"))
    }
}

// ── entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse_and_load();

    // ── Build JwtConfiguration via OIDC auto-discovery ────────────────────────
    info!("Fetching OIDC discovery document from {}", args.issuer);

    let mut builder = JwtConfigurationBuilder::<OidcClaims>::new();

    if let Some(ref path) = args.custom_ca_cert {
        builder = builder.with_custom_ca_cert(path);
    }

    let mut builder = builder.with_issuer(&args.issuer).await.unwrap_or_else(|e| {
        eprintln!("error: OIDC discovery failed for {}: {e}", args.issuer);
        std::process::exit(1);
    });

    if let Some(audience) = args.resolved_audience() {
        info!("Validating JWT audience: {audience}");
        builder = builder.with_audience(vec![audience]);
    } else {
        info!("JWT audience validation disabled; set API_OAUTH_AUDIENCE to enable it");
    }

    let jwt_config = builder.build().unwrap_or_else(|e| {
        eprintln!("error: failed to build JWT configuration: {e}");
        std::process::exit(1);
    });

    // ── Build the router ──────────────────────────────────────────────────────
    //
    // One JwtLayer sits on the root router and decodes the Bearer token for
    // every incoming request, injecting OidcClaims into extensions on success.
    //
    //   • /me      — OptionalJwtClaims reads the extension; returns "guest"
    //                    when absent.
    //   • /protected/* — RequireJwtLayer checks the extension and short-circuits
    //                    with 401 if OidcClaims is absent.  No second decode.
    let jwt_layer = JwtLayer::new(Arc::new(jwt_config));

    let protected = Router::new()
        .route("/resource1", get(routes::protected::resource1))
        .route("/resource2", get(routes::protected::resource2))
        .layer(layers::require_jwt::RequireJwtLayer);

    // /health is on the outer router so it is never seen by JwtLayer and
    // never requires a Bearer token.
    let app = Router::new()
        .route("/health", get(routes::health::health))
        .merge(
            Router::new()
                .nest("/protected", protected)
                .route("/me", get(routes::me::me))
                .layer(jwt_layer),
        );

    // ── Bind and serve ────────────────────────────────────────────────────────
    let addr: SocketAddr = format!("{}:{}", args.host, args.port)
        .parse()
        .expect("invalid bind address");

    info!("🚀  api-server listening on http://{addr}");
    info!("  GET /health              – health-check (always 200, no token required)");
    info!("  GET /me                  – name / email / sub from JWT, or 404 \"guest\"");
    info!("  GET /protected/resource1 – 200 with valid JWT, 401 otherwise");
    info!("  GET /protected/resource2 – 200 with valid JWT, 401 otherwise");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind");

    axum::serve(listener, app).await.expect("server error");
}
