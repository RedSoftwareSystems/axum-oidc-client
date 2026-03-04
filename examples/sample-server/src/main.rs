//! # OAuth2 PKCE Sample Server
//!
//! A complete example application demonstrating OAuth2 authentication with PKCE support
//! using the `axum-oidc-client` library.
//!
//! ## Features
//!
//! - OAuth2/OIDC authentication with PKCE (Proof Key for Code Exchange)
//! - Flexible configuration via CLI arguments or environment variables
//! - Support for dotenv files (`.env`, `.env.local`, or custom via `DOTENV_FILE`)
//! - Feature-selectable cache backends (Redis L2, Moka L1, or two-tier)
//! - Protected and public routes
//! - Configurable logout handlers (default or OIDC)
//!
//! ## Cache Feature Flags
//!
//! The cache backend is selected at **compile time** via Cargo feature flags:
//!
//! | Feature       | Cache type                    | External dependency |
//! |---------------|-------------------------------|---------------------|
//! | `cache-l1`    | Moka in-process only *(default)* | None             |
//! | `cache-l2`    | Redis only                    | Redis server        |
//! | `cache-l1-l2` | Moka L1 + Redis L2 (two-tier) | Redis server        |
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
//! ### Running with Command-Line Arguments
//!
//! ```bash
//! sample-server \
//!   --client-id YOUR_CLIENT_ID \
//!   --client-secret YOUR_CLIENT_SECRET \
//!   --authorization-endpoint https://accounts.google.com/o/oauth2/auth \
//!   --token-endpoint https://oauth2.googleapis.com/token
//! ```
//!
//! ### Running with Environment Variables
//!
//! Create a `.env` file:
//! ```env
//! OAUTH_CLIENT_ID=your_client_id
//! OAUTH_CLIENT_SECRET=your_client_secret
//! OAUTH_AUTHORIZATION_ENDPOINT=https://accounts.google.com/o/oauth2/auth
//! OAUTH_TOKEN_ENDPOINT=https://oauth2.googleapis.com/token
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
//! 1. Default values (if specified)
//! 2. Dotenv files (`.env`, `.env.local`, or `$DOTENV_FILE`)
//! 3. Environment variables
//! 4. Command-line arguments
//!
//! ## Available Routes
//!
//! - `GET /` - Home page (public)
//! - `GET /home` - Home page (public)
//! - `GET /protected` - Protected route (requires authentication)
//! - `GET /auth/callback` - OAuth callback endpoint (automatically handled)
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
//! - [`cache`]  - Feature-gated cache construction
//! - [`config`] - Configuration and CLI argument handling
//! - [`env`]    - Environment variable loading and management
//! - [`routes`] - Application route handlers

use axum::{routing::get, Router};

use axum_oidc_client::{
    auth::{AuthLayer, LogoutHandler},
    logout::{handle_default_logout::DefaultLogoutHandler, handle_oidc_logout::OidcLogoutHandler},
};
use clap::Parser;
use std::{net::SocketAddr, sync::Arc};

mod cache;
mod config;
mod env;
mod routes;

/// Main application entry point.
///
/// This function performs the following steps:
/// 1. Loads environment variables from dotenv files
/// 2. Parses command-line arguments and environment variables
/// 3. Builds OAuth2 configuration
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
    // Load environment variables from dotenv files.
    // Priority: DOTENV_FILE env var > .env.local > .env
    let using_dotenv = env::load_dotenv();

    // Parse command-line arguments (env vars from the dotenv file are already
    // available as fallbacks at this point).
    let args = config::Args::parse();

    // Record which settings came from environment variables so we can report
    // them to the operator in the startup banner.
    let from_env = env::check_env_sources();

    // Build the OAuth2 / OIDC configuration from the parsed arguments.
    let config = args
        .build_oauth_config()
        .expect("Failed to build OAuth configuration");

    // Build the auth cache.  The concrete implementation is chosen at compile
    // time by the active cache feature flag (cache-l2 / cache-l1 / cache-l1-l2).
    let cache = cache::build_cache(&args);

    let config_arc = Arc::new(config);

    // Select the appropriate logout handler based on configuration.
    let logout_handler: Arc<dyn LogoutHandler> = match config_arc.end_session_endpoint.as_ref() {
        Some(end_session_endpoint) => Arc::new(OidcLogoutHandler::new(end_session_endpoint)),
        None => Arc::new(DefaultLogoutHandler),
    };

    // Build the application router with authentication middleware.
    let app = Router::new()
        .route("/", get(routes::home::home))
        .route("/home", get(routes::home::home))
        .route("/protected", get(routes::protected::protected))
        .layer(AuthLayer::new(config_arc, cache, logout_handler));

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
    println!("  - GET /          (home – public)");
    println!("  - GET /home      (home – public)");
    println!("  - GET /protected (protected route)");
    println!("  - GET /auth/logout                    (logout → home)");
    println!("  - GET /auth/logout?redirect=/path     (logout → custom path)");

    // Display the full configuration including the active cache backend.
    args.print_config();
    env::print_config_sources(&from_env, using_dotenv.as_ref());

    // Start the server.
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind to address");

    axum::serve(listener, app)
        .await
        .expect("Failed to start server");
}
