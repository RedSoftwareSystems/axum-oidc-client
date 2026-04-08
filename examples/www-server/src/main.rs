//! # OAuth2 PKCE Sample Server
//!
//! A complete example application demonstrating OAuth2 authentication with PKCE support
//! using the `axum-oidc-client` library.
//!
//! ## Features
//!
//! - OAuth2/OIDC authentication with PKCE (Proof Key for Code Exchange)
//! - Flexible configuration via CLI arguments or environment variables
//! - Support for dotenv files (`.env`, `.env.local`, or custom via `--dotenv-file` / `DOTENV_FILE`)
//! - Feature-selectable cache backends (Redis L2, Moka L1, or two-tier)
//! - Protected and public routes
//! - Configurable logout handlers (default or OIDC)
//!
//! ## Cache Feature Flags
//!
//! The cache backend is selected at **compile time** via Cargo feature flags:
//!
//! | Feature       | Cache type                       | External dependency |
//! |---------------|----------------------------------|---------------------|
//! | `cache-l1`    | Moka in-process only *(default)* | None                |
//! | `cache-l2`    | Redis only                       | Redis server        |
//! | `cache-l1-l2` | Moka L1 + Redis L2 (two-tier)    | Redis server        |
//!
//! ### Selecting a cache backend
//!
//! ```bash
//! # Default: Moka in-process only (no external backend required)
//! cargo run
//!
//! # Explicit Moka in-process only
//! cargo run --no-default-features --features cache-l1
//!
//! # Redis only
//! cargo run --no-default-features --features cache-l2
//!
//! # Two-tier: Moka L1 in front of Redis L2
//! cargo run --no-default-features --features cache-l1-l2
//! ```
//!
//! ## Usage
//!
//! ### Running with OIDC Autodiscovery (recommended)
//!
//! ```bash
//! sample-server \
//!   --issuer https://accounts.google.com \
//!   --client-id YOUR_CLIENT_ID \
//!   --client-secret YOUR_CLIENT_SECRET
//! ```
//!
//! Endpoints, scopes, and the PKCE method are filled in automatically from the
//! provider's `/.well-known/openid-configuration` document.
//!
//! ### Running with Manual Endpoint Configuration
//!
//! ```bash
//! sample-server \
//!   --client-id YOUR_CLIENT_ID \
//!   --client-secret YOUR_CLIENT_SECRET \
//!   --authorization-endpoint https://accounts.google.com/o/oauth2/auth \
//!   --token-endpoint https://oauth2.googleapis.com/token
//! ```
//!
//! ### Running with Environment Variables / Dotenv
//!
//! Create a `.env` file:
//! ```env
//! OAUTH_ISSUER=https://accounts.google.com
//! OAUTH_CLIENT_ID=your_client_id
//! OAUTH_CLIENT_SECRET=your_client_secret
//! ```
//!
//! Then run:
//! ```bash
//! sample-server
//! ```
//!
//! ### Configuration Priority
//!
//! Configuration is loaded in the following order (later sources override earlier ones):
//! 1. OIDC discovery document (when `--issuer` / `OAUTH_ISSUER` is set)
//! 2. Dotenv file (`.env`, `.env.local`, or the path from `--dotenv-file` / `DOTENV_FILE`)
//! 3. Environment variables
//! 4. Command-line arguments
//!
//! ## Available Routes
//!
//! ### Public
//! - `GET /health` - Health-check endpoint (no auth required)
//! - `GET /` - Home page
//! - `GET /home` - Home page (alias)
//!
//! ### Protected (authentication required)
//! - `GET /tokeninfo` - Token info page
//! - `GET /resources` - Resources page (JS fetch of API endpoints)
//! - `GET /api/me` - Proxy → `{api_server}/me`
//! - `GET /api/protected/resource1` - Proxy → `{api_server}/protected/resource1`
//! - `GET /api/protected/resource2` - Proxy → `{api_server}/protected/resource2`
//!
//! ### Auth (automatic)
//! - `GET /auth/callback` - OAuth callback endpoint
//! - `GET /auth/logout` - Logout endpoint
//! - `GET /auth/logout?redirect=/path` - Logout with custom redirect
//!
//! ## Configuration Options
//!
//! Run with `--help` to see all available options:
//! ```bash
//! sample-server --help
//! ```
//!
//! ## Modules
//!
//! - [`cache`]       - Feature-gated cache construction
//! - [`config`]      - Configuration, CLI argument handling, and dotenv loading
//! - [`routes`]      - Application route handlers
//! - [`routes::api`] - Nested `/api` reverse-proxy routes

use axum::{Router, routing::get};

use axum_oidc_client::authentication::{
    AuthLayer, LogoutHandler,
    logout::{handle_default_logout::DefaultLogoutHandler, handle_oidc_logout::OidcLogoutHandler},
};

use std::{net::SocketAddr, sync::Arc};

mod cache;
mod config;
mod routes;

/// Main application entry point.
///
/// This function performs the following steps:
/// 1. Loads environment variables from the dotenv file (via [`config::Args::parse_and_load`])
/// 2. Parses command-line arguments and environment variables
/// 3. Builds OAuth2 configuration (fetching OIDC discovery document if `--issuer` is set)
/// 4. Initializes the auth cache (backend selected by active cargo feature)
/// 5. Sets up the logout handler (OIDC or default)
/// 6. Creates the Axum router with the authentication middleware
/// 7. Starts the HTTP server
///
/// # Cache selection
///
/// The cache backend is chosen at compile time:
///
/// - **`cache-l1`** *(default)* – Moka in-process cache; no external backend required.
/// - **`cache-l2`** – Redis only.
/// - **`cache-l1-l2`** – Two-tier: Moka L1 in front of Redis L2.
///
/// # Panics
///
/// This function will panic if:
/// - OAuth configuration cannot be built
/// - The cache cannot be initialised (e.g. invalid Redis URL)
/// - Socket address cannot be parsed
/// - Server fails to bind to the specified address
#[tokio::main]
async fn main() {
    // Load the dotenv file and parse CLI arguments in one step.
    // Priority for the dotenv path: --dotenv-file / DOTENV_FILE env var > .env.local > .env
    // The dotenv keys are injected into the process environment before clap
    // resolves `env = "…"` annotations, so they act as transparent fallbacks.
    let (args, using_dotenv) = config::Args::parse_and_load();

    // Record which settings came from environment variables (including those
    // sourced from the dotenv file) so we can report them in the startup banner.
    let from_env = config::Args::check_env_sources();

    // Build the OAuth2 / OIDC configuration from the parsed arguments.
    // When --issuer is set this performs an async HTTP fetch of the provider's
    // discovery document before constructing the configuration.
    let config = args
        .build_oauth_config()
        .await
        .expect("Failed to build OAuth configuration");

    // Build the auth cache.  The concrete implementation is chosen at compile
    // time by the active cache feature flag (cache-l2 / cache-l1 / cache-l1-l2).
    let cache = cache::build_cache(&args).await;

    let config_arc = Arc::new(config);

    // Select the appropriate logout handler based on configuration.
    let logout_handler: Arc<dyn LogoutHandler> = match config_arc.end_session_endpoint.as_ref() {
        Some(end_session_endpoint) => Arc::new(OidcLogoutHandler::new(end_session_endpoint)),
        None => Arc::new(DefaultLogoutHandler),
    };

    // Build the /api reverse-proxy sub-router.
    // The ApiState holds the upstream base URL and a shared reqwest::Client.
    let api_router = routes::api::router(&args.api_server, None);

    // Build the application router with authentication middleware.
    // /health is registered on the outer router so it is never intercepted
    // by AuthLayer and never triggers an OIDC redirect.
    let app = Router::new()
        .route("/health", get(routes::health::health))
        .merge(
            Router::new()
                .route("/", get(routes::home::home))
                .route("/home", get(routes::home::home))
                .route("/tokeninfo", get(routes::tokeninfo::tokeninfo))
                .route("/resources", get(routes::resources::resources))
                .nest("/api", api_router)
                .layer(AuthLayer::new(config_arc, cache, logout_handler)),
        );

    // Resolve the bind address from CLI arguments.
    let addr: SocketAddr = format!("{host}:{port}", host = args.host, port = args.port)
        .parse()
        .expect("Failed to parse socket address");

    println!(
        "🚀 Server running on http://{host}:{port}",
        host = args.host,
        port = args.port
    );
    println!("Routes:");
    println!("  - GET /health                        (health-check – public)");
    println!("  - GET /                              (home – public)");
    println!("  - GET /home                          (home – public)");
    println!("  - GET /tokeninfo                     (token info page)");
    println!("  - GET /resources                     (resources page)");
    println!(
        "  - GET /api/me                        (proxy → {}/me)",
        args.api_server
    );
    println!(
        "  - GET /api/protected/resource1       (proxy → {}/protected/resource1)",
        args.api_server
    );
    println!(
        "  - GET /api/protected/resource2       (proxy → {}/protected/resource2)",
        args.api_server
    );
    println!("  - GET /auth/logout                   (logout → home)");
    println!("  - GET /auth/logout?redirect=/path    (logout → custom path)");

    // Display the full configuration including the active cache backend.
    args.print_config();
    config::Args::print_config_sources(&from_env, using_dotenv.as_ref());

    // Start the server.
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind to address");

    axum::serve(listener, app)
        .await
        .expect("Failed to start server");
}
