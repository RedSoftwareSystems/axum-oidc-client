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
//! - Redis-based session caching
//! - Protected and public routes
//! - Configurable logout handlers (default or OIDC)
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
//! - [`config`] - Configuration and CLI argument handling
//! - [`env`] - Environment variable loading and management
//! - [`routes`] - Application route handlers

use axum::{routing::get, Router};

use axum_oidc_client::{
    auth::{AuthLayer, LogoutHandler},
    auth_cache::AuthCache,
    logout::{handle_default_logout::DefaultLogoutHandler, handle_oidc_logout::OidcLogoutHandler},
};
use clap::Parser;
use std::{net::SocketAddr, sync::Arc};

mod config;
mod env;
mod routes;

/// Create a Redis-based authentication cache.
///
/// This function initializes a Redis cache for storing authentication state,
/// session data, and tokens.
///
/// # Configuration
///
/// - **Redis URL**: `redis://127.0.0.1/` (default Redis instance)
/// - **TTL**: 3600 seconds (1 hour)
///
/// # Returns
///
/// An `Arc` containing a thread-safe, sendable cache implementation.
///
/// # Examples
///
/// ```no_run
/// # use axum_oidc_client::auth_cache::AuthCache;
/// # use std::sync::Arc;
/// # fn create_redis_cache() -> Arc<dyn AuthCache + Send + Sync> {
/// #     use axum_oidc_client::redis;
/// #     Arc::new(redis::AuthCache::new("redis://127.0.0.1/", 3600))
/// # }
/// let cache = create_redis_cache();
/// // Use cache with AuthLayer
/// ```
fn create_redis_cache() -> Arc<dyn AuthCache + Send + Sync> {
    use axum_oidc_client::redis;

    Arc::new(redis::AuthCache::new("redis://127.0.0.1/", 3600))
}

/// Main application entry point.
///
/// This function performs the following steps:
/// 1. Loads environment variables from dotenv files
/// 2. Parses command-line arguments and environment variables
/// 3. Builds OAuth2 configuration
/// 4. Initializes Redis cache for session storage
/// 5. Sets up logout handler (OIDC or default)
/// 6. Creates Axum router with authentication middleware
/// 7. Starts the HTTP server
///
/// # Panics
///
/// This function will panic if:
/// - OAuth configuration cannot be built
/// - Socket address cannot be parsed
/// - Server fails to bind to the specified address
/// - Server fails to start
#[tokio::main]
async fn main() {
    // Load environment variables from dotenv files
    // Priority: DOTENV_FILE env var > .env.local > .env
    let using_dotenv = env::load_dotenv();

    // Parse command-line arguments (will use env vars from .env as fallbacks)
    let args = config::Args::parse();

    // Check which settings are from environment variables
    let from_env = env::check_env_sources();

    // Build OAuth configuration from CLI arguments
    let config = args
        .build_oauth_config()
        .expect("Failed to build OAuth configuration");

    let cache = create_redis_cache();
    let config_arc = Arc::new(config);

    // Select appropriate logout handler based on configuration
    let logout_handler: Arc<dyn LogoutHandler> = match config_arc.end_session_endpoint.as_ref() {
        Some(end_session_endpoint) => Arc::new(OidcLogoutHandler::new(end_session_endpoint)),
        None => Arc::new(DefaultLogoutHandler),
    };

    // Build application with routes and authentication layer
    let app = Router::new()
        .route("/", get(routes::home::home))
        .route("/home", get(routes::home::home))
        .route("/protected", get(routes::protected::protected))
        .layer(AuthLayer::new(config_arc, cache, logout_handler));

    // Define the address to bind to from CLI arguments
    let addr: SocketAddr = format!("{host}:{port}", host = args.host, port = args.port)
        .parse()
        .expect("Failed to parse socket address");

    println!(
        "🚀 Server running on http://{host}:{port}",
        host = args.host,
        port = args.port
    );
    println!("Routes:");
    println!("  - GET /         (home)");
    println!("  - GET /home     (home)");
    println!("  - GET /protected (protected route)");
    println!("  - GET /auth/logout (logout and redirect to home)");
    println!("  - GET /auth/logout?redirect=/path (logout and redirect to custom path)");

    // Display configuration information
    args.print_config();
    env::print_config_sources(&from_env, using_dotenv.as_ref());

    // Create and run the server
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind to address");

    axum::serve(listener, app)
        .await
        .expect("Failed to start server");
}
