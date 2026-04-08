//! Configuration module for the OAuth2 sample server.
//!
//! This module handles:
//! - CLI argument parsing using clap
//! - Dotenv file loading (replaces the former `env` module)
//! - OAuth2 configuration building (with optional OIDC autodiscovery)
//! - Cache configuration (feature-gated)
//! - Environment variable integration
//! - Configuration validation and display
//!
//! ## Dotenv loading
//!
//! Call [`Args::parse_and_load`] instead of [`clap::Parser::parse`].  It will:
//!
//! 1. Inspect `DOTENV_FILE` in the process environment.
//! 2. Fall back to `.env.local`, then `.env`.
//! 3. Load the first file found, making its keys available as environment
//!    variables before clap parses `Args`.
//!
//! The path that was actually loaded is returned alongside the parsed `Args`
//! so it can be shown in the startup banner.
//!
//! ## OIDC Autodiscovery
//!
//! Pass `--issuer <URL>` (or `OAUTH_ISSUER=<URL>`) to let the server fetch
//! `<issuer>/.well-known/openid-configuration` and fill in:
//!
//! - `authorization_endpoint`
//! - `token_endpoint`
//! - `end_session_endpoint` (if the provider exposes it)
//! - `scopes` (intersection with the provider's `scopes_supported`)
//! - `code_challenge_method` (`S256` preferred, falls back to `plain`)
//!
//! Any explicitly supplied CLI flag or environment variable overrides the
//! discovered value, so you can mix autodiscovery with manual overrides:
//!
//! ```bash
//! # Discover everything except scopes
//! sample-server \
//!   --issuer https://accounts.google.com \
//!   --client-id YOUR_ID \
//!   --client-secret YOUR_SECRET \
//!   --scopes openid,email
//! ```
//!
//! Without `--issuer` you must supply `--authorization-endpoint` and
//! `--token-endpoint` (or their `OAUTH_*` env-var equivalents) explicitly.
//!
//! ## Cache feature flags
//!
//! The active cache feature controls which CLI arguments and environment
//! variables are available:
//!
//! | Feature          | Extra args                                                                   |
//! |------------------|------------------------------------------------------------------------------|
//! | `cache-l2`       | `--redis-url`, `--cache-ttl`                                                 |
//! | `cache-l1`       | `--l1-max-capacity`, `--l1-ttl-sec`, `--l1-tti-sec`                          |
//! | `cache-l1-l2`    | all of the above                                                             |
//! | `cache-pg`       | `--pg-url`, `--pg-max-connections`, `--pg-cleanup-interval-sec`              |
//! | `cache-l1-pg`    | all of `cache-l1` above + all of `cache-pg` above                           |
//! | `cache-mysql`    | `--mysql-url`, `--mysql-max-connections`, `--mysql-cleanup-interval-sec`     |
//! | `cache-l1-mysql` | all of `cache-l1` above + all of `cache-mysql` above                        |
//! | `cache-sqlite`   | `--sqlite-url`, `--sqlite-max-connections`, `--sqlite-cleanup-interval-sec`  |
//! | `cache-l1-sqlite`| all of `cache-l1` above + all of `cache-sqlite` above                       |

use axum_oidc_client::authentication::{
    CodeChallengeMethod, OAuthConfiguration, builder::OAuthConfigurationBuilder,
};
use clap::Parser;
use std::{env, path::PathBuf};

/// OAuth2 PKCE Sample Server
///
/// This application demonstrates OAuth2 authentication with PKCE support.
/// Configuration can be provided via command-line arguments or environment variables.
///
/// # Quick start — OIDC autodiscovery (recommended)
///
/// ```bash
/// sample-server \
///   --issuer https://accounts.google.com \
///   --client-id YOUR_ID \
///   --client-secret YOUR_SECRET
/// ```
///
/// Endpoints, scopes, and the PKCE method are fetched automatically from the
/// provider's `.well-known/openid-configuration` document.
///
/// # Manual endpoint configuration
///
/// ```bash
/// sample-server \
///   --authorization-endpoint https://provider.com/oauth/authorize \
///   --token-endpoint https://provider.com/oauth/token \
///   --client-id YOUR_ID \
///   --client-secret YOUR_SECRET
/// ```
///
/// # Environment variables / dotenv
///
/// ```bash
/// # .env
/// OAUTH_ISSUER=https://accounts.google.com
/// OAUTH_CLIENT_ID=your_id
/// OAUTH_CLIENT_SECRET=your_secret
/// ```
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    // ── Dotenv ────────────────────────────────────────────────────────────────
    /// Path to a dotenv file whose contents are loaded as environment variables.
    ///
    /// When provided the file is loaded **before** all other arguments are
    /// resolved, so any key defined inside it acts as a fallback for the
    /// corresponding CLI flag.
    ///
    /// If omitted the loader tries `.env.local` and then `.env` in the current
    /// working directory.
    #[arg(
        long,
        env = "DOTENV_FILE",
        help = "Path to a dotenv file to load before resolving other arguments"
    )]
    pub dotenv_file: Option<PathBuf>,

    // ── OIDC autodiscovery ────────────────────────────────────────────────────
    /// OIDC issuer URL for endpoint autodiscovery.
    ///
    /// When set, the server fetches `<issuer>/.well-known/openid-configuration`
    /// and uses the returned document to populate `authorization_endpoint`,
    /// `token_endpoint`, `end_session_endpoint`, `scopes`, and
    /// `code_challenge_method`.
    ///
    /// Any of those fields that are supplied explicitly on the command line
    /// (or via environment variables) override the discovered values.
    ///
    /// When `--issuer` is **not** set you must supply `--authorization-endpoint`
    /// and `--token-endpoint` manually.
    ///
    /// # Examples
    ///
    /// ```bash
    /// # Google
    /// --issuer https://accounts.google.com
    ///
    /// # Keycloak
    /// --issuer https://keycloak.example.com/realms/myrealm
    ///
    /// # Azure AD
    /// --issuer https://login.microsoftonline.com/{tenant}/v2.0
    /// ```
    #[arg(long, env = "OAUTH_ISSUER")]
    pub issuer: Option<String>,

    // ── OAuth2 / OIDC endpoints ───────────────────────────────────────────────
    /// OAuth2 authorization endpoint URL.
    ///
    /// Required when `--issuer` is not provided.  Ignored (but still accepted)
    /// when autodiscovery is active — the discovered value is used instead
    /// unless this flag is given explicitly on the command line.
    #[arg(long, env = "OAUTH_AUTHORIZATION_ENDPOINT")]
    pub authorization_endpoint: Option<String>,

    /// OAuth2 token endpoint URL.
    ///
    /// Required when `--issuer` is not provided.  Same override semantics as
    /// `--authorization-endpoint`.
    #[arg(long, env = "OAUTH_TOKEN_ENDPOINT")]
    pub token_endpoint: Option<String>,

    /// OIDC end session (logout) endpoint URL.
    ///
    /// Only needed for providers that support RP-Initiated Logout (Keycloak,
    /// Azure AD, Okta, Auth0 …).  Do **not** set for Google or GitHub.
    ///
    /// When `--issuer` is used and the discovery document exposes
    /// `end_session_endpoint`, this field is populated automatically.
    #[arg(long, env = "OAUTH_END_SESSION_ENDPOINT")]
    pub end_session_endpoint: Option<String>,

    /// Post-logout redirect URI.
    ///
    /// Where to redirect users after a successful logout.  Defaults to `"/"`.
    #[arg(long, env = "POST_LOGOUT_REDIRECT_URI")]
    pub post_logout_redirect_uri: Option<String>,

    // ── Credentials ───────────────────────────────────────────────────────────
    /// OAuth2 client ID.
    #[arg(long, env = "OAUTH_CLIENT_ID")]
    pub client_id: String,

    /// OAuth2 client secret.
    #[arg(long, env = "OAUTH_CLIENT_SECRET")]
    pub client_secret: String,

    // ── URIs & keys ───────────────────────────────────────────────────────────
    /// OAuth2 redirect (callback) URI.
    #[arg(
        long,
        env = "OAUTH_REDIRECT_URI",
        default_value = "http://localhost:8080/auth/callback"
    )]
    pub redirect_uri: String,

    /// Private cookie key for session encryption.
    #[arg(long, env = "PRIVATE_COOKIE_KEY", default_value = "private_cookie_key")]
    pub private_cookie_key: String,

    /// OAuth2 scopes (comma-separated).
    ///
    /// When `--issuer` is used and this flag is **not** supplied, the scopes
    /// are derived automatically from the intersection of
    /// `["openid", "email", "profile"]` with the provider's
    /// `scopes_supported` list.
    #[arg(
        long,
        env = "OAUTH_SCOPES",
        default_value = "openid,email,profile",
        value_delimiter = ','
    )]
    pub scopes: Vec<String>,

    /// Custom CA certificate path (PEM).
    ///
    /// Useful when the identity provider uses a private / self-signed CA.
    /// The certificate is loaded before the autodiscovery HTTP request is made,
    /// so it applies to both the discovery fetch and subsequent token calls.
    #[arg(long, env = "CUSTOM_CA_CERT")]
    pub custom_ca_cert: Option<String>,

    /// PKCE code challenge method (`S256` or `plain`).
    ///
    /// When `--issuer` is used and this flag is **not** supplied, the method
    /// is chosen automatically: `S256` if the provider lists it in
    /// `code_challenge_methods_supported`, otherwise `plain`.
    #[arg(
        long,
        env = "CODE_CHALLENGE_METHOD",
        default_value = "S256",
        value_parser = parse_code_challenge_method
    )]
    pub code_challenge_method: CodeChallengeMethod,

    /// Base path for authentication routes (e.g. `/auth`).
    #[arg(long, env = "OAUTH_BASE_PATH", default_value = "/auth")]
    pub base_path: String,

    // ── Server ────────────────────────────────────────────────────────────────
    /// Server host address.
    #[arg(long, env = "SERVER_HOST", default_value = "127.0.0.1")]
    pub host: String,

    /// Server port.
    #[arg(short, long, env = "SERVER_PORT", default_value = "8080")]
    pub port: u16,

    /// Upstream API server base URL (forwarded to route handlers).
    #[arg(long, env = "API_SERVER", default_value = "http://api-server")]
    pub api_server: String,

    // ── L2 cache: Redis ───────────────────────────────────────────────────────
    /// Redis connection URL.
    ///
    /// Used when the `cache-l2` or `cache-l1-l2` feature is enabled.
    #[cfg(feature = "cache-l2")]
    #[arg(
        long,
        env = "REDIS_URL",
        default_value = "redis://127.0.0.1/",
        help = "Redis connection URL [cache-l2 / cache-l1-l2]"
    )]
    pub redis_url: String,

    /// Time-to-live for Redis cache entries (seconds).
    #[cfg(feature = "cache-l2")]
    #[arg(
        long,
        env = "CACHE_TTL",
        default_value = "3600",
        help = "Redis cache TTL in seconds [cache-l2 / cache-l1-l2]"
    )]
    pub cache_ttl: u64,

    // ── L1 cache: Moka ────────────────────────────────────────────────────────
    /// Maximum number of entries in the Moka L1 cache.
    #[cfg(feature = "cache-l1")]
    #[arg(
        long,
        env = "L1_MAX_CAPACITY",
        default_value = "10000",
        help = "Moka L1 cache max capacity (entries) [cache-l1 / cache-l1-l2]"
    )]
    pub l1_max_capacity: u64,

    /// Time-to-live for Moka L1 cache entries (seconds).
    ///
    /// Should match or slightly exceed the L2 TTL so that stale L1 hits never
    /// shadow a fresher L2 entry for too long.
    #[cfg(feature = "cache-l1")]
    #[arg(
        long,
        env = "L1_TTL_SEC",
        default_value = "3600",
        help = "Moka L1 cache TTL in seconds [cache-l1 / cache-l1-l2]"
    )]
    pub l1_ttl_sec: u64,

    /// Time-to-idle for Moka L1 cache entries (seconds).
    ///
    /// When set, entries not accessed for this duration are evicted before
    /// their TTL expires.  Leave unset to disable idle-eviction.
    #[cfg(feature = "cache-l1")]
    #[arg(
        long,
        env = "L1_TIME_TO_IDLE_SEC",
        help = "Moka L1 cache time-to-idle in seconds (optional) [cache-l1 / cache-l1-l2]"
    )]
    pub l1_time_to_idle_sec: Option<u64>,

    // ── L2 cache: PostgreSQL ──────────────────────────────────────────────────
    /// PostgreSQL connection URL.
    ///
    /// Example: `postgresql://oidc_user:secret@localhost:5432/oidc_cache`
    #[cfg(feature = "cache-pg")]
    #[arg(
        long,
        env = "PG_URL",
        default_value = "postgresql://oidc_user:oidc_pass@localhost:5432/oidc_cache",
        help = "PostgreSQL connection URL [cache-pg / cache-l1-pg]"
    )]
    pub pg_url: String,

    /// Maximum connections in the PostgreSQL pool.
    #[cfg(feature = "cache-pg")]
    #[arg(
        long,
        env = "PG_MAX_CONNECTIONS",
        default_value = "20",
        help = "PostgreSQL pool max connections [cache-pg / cache-l1-pg]"
    )]
    pub pg_max_connections: u32,

    /// How often (seconds) the background task sweeps expired rows from the
    /// PostgreSQL cache table.
    #[cfg(feature = "cache-pg")]
    #[arg(
        long,
        env = "PG_CLEANUP_INTERVAL_SEC",
        default_value = "300",
        help = "PostgreSQL cache cleanup interval in seconds [cache-pg / cache-l1-pg]"
    )]
    pub pg_cleanup_interval_sec: u64,

    /// TTL (seconds) for the Moka L1 layer when used in front of PostgreSQL.
    #[cfg(feature = "cache-l1")]
    #[cfg(feature = "cache-pg")]
    #[arg(
        long,
        env = "PG_L1_TTL_SEC",
        default_value = "1800",
        help = "Moka L1 TTL in seconds when used in front of PostgreSQL [cache-l1-pg]"
    )]
    pub pg_l1_ttl_sec: u64,

    // ── L2 cache: MySQL / MariaDB ─────────────────────────────────────────────
    /// MySQL / MariaDB connection URL.
    ///
    /// Example: `mysql://oidc_user:oidc_pass@localhost:3306/oidc_cache`
    #[cfg(feature = "cache-mysql")]
    #[arg(
        long,
        env = "MYSQL_URL",
        default_value = "mysql://oidc_user:oidc_pass@localhost:3306/oidc_cache",
        help = "MySQL / MariaDB connection URL [cache-mysql / cache-l1-mysql]"
    )]
    pub mysql_url: String,

    /// Maximum connections in the MySQL pool.
    #[cfg(feature = "cache-mysql")]
    #[arg(
        long,
        env = "MYSQL_MAX_CONNECTIONS",
        default_value = "20",
        help = "MySQL pool max connections [cache-mysql / cache-l1-mysql]"
    )]
    pub mysql_max_connections: u32,

    /// How often (seconds) the background task sweeps expired rows from the
    /// MySQL cache table.
    #[cfg(feature = "cache-mysql")]
    #[arg(
        long,
        env = "MYSQL_CLEANUP_INTERVAL_SEC",
        default_value = "300",
        help = "MySQL cache cleanup interval in seconds [cache-mysql / cache-l1-mysql]"
    )]
    pub mysql_cleanup_interval_sec: u64,

    /// TTL (seconds) for the Moka L1 layer when used in front of MySQL.
    #[cfg(feature = "cache-l1")]
    #[cfg(feature = "cache-mysql")]
    #[arg(
        long,
        env = "MYSQL_L1_TTL_SEC",
        default_value = "1800",
        help = "Moka L1 TTL in seconds when used in front of MySQL [cache-l1-mysql]"
    )]
    pub mysql_l1_ttl_sec: u64,

    // ── L2 cache: SQLite ──────────────────────────────────────────────────────
    /// SQLite connection URL.
    ///
    /// Use a file path (`sqlite:///path/to/cache.db`) or `:memory:` for an
    /// ephemeral in-process database (`sqlite://:memory:`).
    /// The parent directory must exist and be writable; SQLite creates the
    /// file automatically when it does not exist.
    #[cfg(feature = "cache-sqlite")]
    #[arg(
        long,
        env = "SQLITE_URL",
        default_value = "sqlite:///tmp/oidc_cache.db",
        help = "SQLite connection URL [cache-sqlite / cache-l1-sqlite]"
    )]
    pub sqlite_url: String,

    /// Maximum connections in the SQLite pool.
    ///
    /// SQLite allows only one concurrent writer; keep this low (1–5) to avoid
    /// lock contention.
    #[cfg(feature = "cache-sqlite")]
    #[arg(
        long,
        env = "SQLITE_MAX_CONNECTIONS",
        default_value = "5",
        help = "SQLite pool max connections [cache-sqlite / cache-l1-sqlite]"
    )]
    pub sqlite_max_connections: u32,

    /// How often (seconds) the background task sweeps expired rows from the
    /// SQLite cache table.
    #[cfg(feature = "cache-sqlite")]
    #[arg(
        long,
        env = "SQLITE_CLEANUP_INTERVAL_SEC",
        default_value = "300",
        help = "SQLite cache cleanup interval in seconds [cache-sqlite / cache-l1-sqlite]"
    )]
    pub sqlite_cleanup_interval_sec: u64,

    /// TTL (seconds) for the Moka L1 layer when used in front of SQLite.
    #[cfg(feature = "cache-l1")]
    #[cfg(feature = "cache-sqlite")]
    #[arg(
        long,
        env = "SQLITE_L1_TTL_SEC",
        default_value = "1800",
        help = "Moka L1 TTL in seconds when used in front of SQLite [cache-l1-sqlite]"
    )]
    pub sqlite_l1_ttl_sec: u64,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Parse a PKCE code-challenge method from a string.
///
/// Accepts `"S256"` or `"plain"` (case-insensitive).
fn parse_code_challenge_method(s: &str) -> Result<CodeChallengeMethod, String> {
    match s.to_uppercase().as_str() {
        "S256" => Ok(CodeChallengeMethod::S256),
        "PLAIN" => Ok(CodeChallengeMethod::Plain),
        _ => Err(format!(
            "Invalid code challenge method '{}'. Use 'S256' or 'plain'",
            s
        )),
    }
}

/// Load environment variables from a dotenv file.
///
/// Search order:
/// 1. `DOTENV_FILE` already set in the OS environment (shell-provided).
/// 2. `.env.local` in the current working directory.
/// 3. `.env` in the current working directory.
///
/// Only the first candidate that exists on disk is loaded.
///
/// # Returns
///
/// `Some(path)` of the file that was loaded, or `None` if no file was found.
pub fn load_dotenv() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(custom) = env::var("DOTENV_FILE") {
        candidates.push(PathBuf::from(custom));
    }
    candidates.push(PathBuf::from(".env.local"));
    candidates.push(PathBuf::from(".env"));

    for path in candidates {
        if path.exists() {
            let _ = dotenv::from_path(&path);
            return Some(path);
        }
    }
    None
}

// ── impl Args ─────────────────────────────────────────────────────────────────

impl Args {
    // ── Construction ─────────────────────────────────────────────────────────

    /// Load a dotenv file and then parse command-line arguments.
    ///
    /// This is the **preferred entry-point** instead of calling
    /// [`clap::Parser::parse`] directly.  It ensures that any key/value pairs
    /// stored in the dotenv file are available as environment variables when
    /// clap resolves `env = "…"` annotations on each field.
    ///
    /// # Resolution order
    ///
    /// 1. `DOTENV_FILE` in the current OS environment (shell-set).
    /// 2. `.env.local` in the current working directory.
    /// 3. `.env` in the current working directory.
    ///
    /// The first file found is loaded; subsequent candidates are ignored.
    ///
    /// # Returns
    ///
    /// `(Args, Option<PathBuf>)` — the parsed arguments and the path of the
    /// dotenv file that was loaded (if any).
    pub fn parse_and_load() -> (Self, Option<PathBuf>) {
        let loaded = load_dotenv();
        let args = Self::parse();
        (args, loaded)
    }

    // ── Configuration building ────────────────────────────────────────────────

    /// Build an [`OAuthConfiguration`] from the parsed arguments.
    ///
    /// When `--issuer` (or `OAUTH_ISSUER`) is set the builder fetches the
    /// provider's OIDC discovery document and fills in:
    ///
    /// | Discovery field              | Overridable by CLI / env?                  |
    /// |------------------------------|--------------------------------------------|
    /// | `authorization_endpoint`     | Yes — `--authorization-endpoint`           |
    /// | `token_endpoint`             | Yes — `--token-endpoint`                   |
    /// | `end_session_endpoint`       | Yes — `--end-session-endpoint`             |
    /// | `scopes_supported`           | Yes — `--scopes`                           |
    /// | `code_challenge_methods_supported` | Yes — `--code-challenge-method`      |
    ///
    /// Without `--issuer` you must supply at least `--authorization-endpoint`
    /// and `--token-endpoint`; the builder will return an error otherwise.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` if:
    /// - The issuer URL is invalid or the discovery request fails.
    /// - Required fields (`client_id`, `client_secret`, `redirect_uri`,
    ///   `authorization_endpoint`, `token_endpoint`) are missing.
    pub async fn build_oauth_config(&self) -> Result<OAuthConfiguration, String> {
        let mut b = OAuthConfigurationBuilder::default();

        // ── Custom CA cert (must be set first so it applies to the
        //    autodiscovery HTTP request as well) ──────────────────────────────
        if let Some(ca) = self.custom_ca_cert.as_deref() {
            b = b.with_custom_ca_cert(ca);
        }

        // ── OIDC autodiscovery ───────────────────────────────────────────────
        if let Some(issuer) = self.issuer.as_deref() {
            b = b
                .with_issuer(issuer)
                .await
                .map_err(|e| format!("OIDC autodiscovery failed for '{issuer}': {e:?}"))?;
        }

        // ── Explicit endpoint overrides (take priority over discovery) ───────
        if let Some(ep) = self.authorization_endpoint.as_deref() {
            b = b.with_authorization_endpoint(ep);
        }
        if let Some(ep) = self.token_endpoint.as_deref() {
            b = b.with_token_endpoint(ep);
        }
        if let Some(ep) = self.end_session_endpoint.as_deref() {
            b = b.with_end_session_endpoint(ep);
        }
        // Default to "/" when not supplied — the builder requires this field.
        b = b
            .with_post_logout_redirect_uri(self.post_logout_redirect_uri.as_deref().unwrap_or("/"));

        // ── Credentials & static settings ────────────────────────────────────
        b = b
            .with_client_id(&self.client_id)
            .with_client_secret(&self.client_secret)
            .with_private_cookie_key(&self.private_cookie_key)
            .with_redirect_uri(&self.redirect_uri)
            .with_session_max_age(30)
            .with_token_max_age(1)
            .with_scopes(self.scopes.iter().map(String::as_str).collect())
            .with_code_challenge_method(self.code_challenge_method.clone())
            .with_base_path(&self.base_path);

        b.build()
            .map_err(|e| format!("Failed to build OAuth configuration: {e:?}"))
    }

    // ── Diagnostic output ─────────────────────────────────────────────────────

    /// Check which configuration-related environment variables are currently set.
    ///
    /// Call this **after** [`parse_and_load`](Self::parse_and_load) so that
    /// variables sourced from the dotenv file are included in the result.
    ///
    /// # Returns
    ///
    /// A `Vec<String>` of environment variable names that are currently set.
    pub fn check_env_sources() -> Vec<String> {
        let mut sources = Vec::new();

        for var in &[
            "OAUTH_ISSUER",
            "OAUTH_CLIENT_ID",
            "OAUTH_CLIENT_SECRET",
            "OAUTH_AUTHORIZATION_ENDPOINT",
            "OAUTH_TOKEN_ENDPOINT",
            "OAUTH_END_SESSION_ENDPOINT",
            "OAUTH_REDIRECT_URI",
            "POST_LOGOUT_REDIRECT_URI",
            "PRIVATE_COOKIE_KEY",
            "CUSTOM_CA_CERT",
            "OAUTH_BASE_PATH",
            "OAUTH_SCOPES",
            "CODE_CHALLENGE_METHOD",
            "SERVER_HOST",
            "SERVER_PORT",
            "API_SERVER",
        ] {
            if env::var(var).is_ok() {
                sources.push(var.to_string());
            }
        }

        // ── Cache: L2 (Redis) ─────────────────────────────────────────────
        #[cfg(feature = "cache-l2")]
        for var in &["REDIS_URL", "CACHE_TTL"] {
            if env::var(var).is_ok() {
                sources.push(var.to_string());
            }
        }

        // ── Cache: L1 (Moka) ─────────────────────────────────────────────
        #[cfg(feature = "cache-l1")]
        for var in &["L1_MAX_CAPACITY", "L1_TTL_SEC", "L1_TIME_TO_IDLE_SEC"] {
            if env::var(var).is_ok() {
                sources.push(var.to_string());
            }
        }

        // ── Cache: PostgreSQL ─────────────────────────────────────────────
        #[cfg(feature = "cache-pg")]
        for var in &["PG_URL", "PG_MAX_CONNECTIONS", "PG_CLEANUP_INTERVAL_SEC"] {
            if env::var(var).is_ok() {
                sources.push(var.to_string());
            }
        }

        // ── Cache: Moka L1 + PostgreSQL ───────────────────────────────────
        #[cfg(all(feature = "cache-l1", feature = "cache-pg"))]
        if env::var("PG_L1_TTL_SEC").is_ok() {
            sources.push("PG_L1_TTL_SEC".to_string());
        }

        // ── Cache: MySQL / MariaDB ────────────────────────────────────────
        #[cfg(feature = "cache-mysql")]
        for var in &[
            "MYSQL_URL",
            "MYSQL_MAX_CONNECTIONS",
            "MYSQL_CLEANUP_INTERVAL_SEC",
        ] {
            if env::var(var).is_ok() {
                sources.push(var.to_string());
            }
        }

        // ── Cache: Moka L1 + MySQL ────────────────────────────────────────
        #[cfg(all(feature = "cache-l1", feature = "cache-mysql"))]
        if env::var("MYSQL_L1_TTL_SEC").is_ok() {
            sources.push("MYSQL_L1_TTL_SEC".to_string());
        }

        // ── Cache: SQLite ─────────────────────────────────────────────────
        #[cfg(feature = "cache-sqlite")]
        for var in &[
            "SQLITE_URL",
            "SQLITE_MAX_CONNECTIONS",
            "SQLITE_CLEANUP_INTERVAL_SEC",
        ] {
            if env::var(var).is_ok() {
                sources.push(var.to_string());
            }
        }

        // ── Cache: Moka L1 + SQLite ───────────────────────────────────────
        #[cfg(all(feature = "cache-l1", feature = "cache-sqlite"))]
        if env::var("SQLITE_L1_TTL_SEC").is_ok() {
            sources.push("SQLITE_L1_TTL_SEC".to_string());
        }

        sources
    }

    /// Print information about configuration sources to stdout.
    ///
    /// Displays a human-readable summary of:
    /// - Which dotenv file was loaded (if any).
    /// - Which environment variables contributed to the configuration.
    /// - Whether command-line arguments were explicitly supplied.
    ///
    /// # Arguments
    ///
    /// * `from_env`    – Slice of env-var names from [`Self::check_env_sources`].
    /// * `dotenv_path` – Optional path returned by [`Self::parse_and_load`].
    pub fn print_config_sources(from_env: &[String], dotenv_path: Option<&PathBuf>) {
        if let Some(path) = dotenv_path {
            println!("📄 Loaded configuration from {}", path.display());
        }

        println!("\n⚙️  Configuration Sources:");
        if !from_env.is_empty() {
            println!("  ✓ Environment variables: {}", from_env.join(", "));
        }
        if env::args().len() > 1 {
            println!("  ✓ Command-line arguments provided");
        }

        println!("\n💡 Tip: Use --help to see all configuration options");
    }

    /// Print the active OAuth2 / OIDC configuration to stdout.
    pub fn print_config(&self) {
        println!("\n📋 OAuth2 Configuration:");

        if let Some(ref issuer) = self.issuer {
            println!("  - Issuer (autodiscovery): {}", issuer);
        }
        match self.authorization_endpoint.as_deref() {
            Some(ep) => println!("  - Authorization: {}", ep),
            None if self.issuer.is_some() => {
                println!("  - Authorization: <from discovery>")
            }
            None => println!("  - Authorization: (not set)"),
        }
        match self.token_endpoint.as_deref() {
            Some(ep) => println!("  - Token: {}", ep),
            None if self.issuer.is_some() => println!("  - Token: <from discovery>"),
            None => println!("  - Token: (not set)"),
        }
        match self.end_session_endpoint.as_deref() {
            Some(ep) => println!("  - End Session: {}", ep),
            None if self.issuer.is_some() => {
                println!("  - End Session: <from discovery (if supported)>")
            }
            None => {}
        }
        if let Some(ref post_logout) = self.post_logout_redirect_uri {
            println!("  - Post Logout Redirect: {}", post_logout);
        }
        println!("  - Client ID: {}", self.client_id);
        println!("  - Redirect URI: {}", self.redirect_uri);
        println!("  - Base Path: {}", self.base_path);
        println!("  - Scopes: {:?}", self.scopes);

        self.print_cache_config();
    }

    /// Print the active cache configuration to stdout.
    ///
    /// Output is controlled by the active cache feature flag:
    ///
    /// - `cache-l1-l2`     → Two-tier: Moka L1 + Redis L2
    /// - `cache-l1`        → L1-only (Moka in-process)
    /// - `cache-l2`        → L2-only (Redis)
    /// - `cache-pg`        → PostgreSQL-only
    /// - `cache-l1-pg`     → Two-tier: Moka L1 + PostgreSQL L2
    /// - `cache-mysql`     → MySQL-only
    /// - `cache-l1-mysql`  → Two-tier: Moka L1 + MySQL L2
    /// - `cache-sqlite`    → SQLite-only
    /// - `cache-l1-sqlite` → Two-tier: Moka L1 + SQLite L2
    pub fn print_cache_config(&self) {
        // ── Mode banner ───────────────────────────────────────────────────
        #[cfg(all(
            feature = "cache-l1",
            feature = "cache-l2",
            not(feature = "cache-pg"),
            not(feature = "cache-mysql"),
            not(feature = "cache-sqlite"),
        ))]
        println!("\n🗄️  Cache: Two-tier (Moka L1 + Redis L2)");

        #[cfg(all(
            feature = "cache-l1",
            not(feature = "cache-l2"),
            not(feature = "cache-pg"),
            not(feature = "cache-mysql"),
            not(feature = "cache-sqlite"),
        ))]
        println!("\n🗄️  Cache: L1-only (Moka in-process, no external backend)");

        #[cfg(all(
            feature = "cache-l2",
            not(feature = "cache-l1"),
            not(feature = "cache-pg"),
            not(feature = "cache-mysql"),
            not(feature = "cache-sqlite"),
        ))]
        println!("\n🗄️  Cache: L2-only (Redis)");

        #[cfg(all(
            feature = "cache-pg",
            feature = "cache-l1",
            not(feature = "cache-mysql"),
            not(feature = "cache-sqlite"),
        ))]
        println!("\n🗄️  Cache: Two-tier (Moka L1 + PostgreSQL L2)");

        #[cfg(all(
            feature = "cache-pg",
            not(feature = "cache-l1"),
            not(feature = "cache-mysql"),
            not(feature = "cache-sqlite"),
        ))]
        println!("\n🗄️  Cache: PostgreSQL-only (no in-process L1 layer)");

        #[cfg(all(
            feature = "cache-mysql",
            feature = "cache-l1",
            not(feature = "cache-pg"),
            not(feature = "cache-sqlite"),
        ))]
        println!("\n🗄️  Cache: Two-tier (Moka L1 + MySQL L2)");

        #[cfg(all(
            feature = "cache-mysql",
            not(feature = "cache-l1"),
            not(feature = "cache-pg"),
            not(feature = "cache-sqlite"),
        ))]
        println!("\n🗄️  Cache: MySQL-only (no in-process L1 layer)");

        #[cfg(all(
            feature = "cache-sqlite",
            feature = "cache-l1",
            not(feature = "cache-pg"),
            not(feature = "cache-mysql"),
        ))]
        println!("\n🗄️  Cache: Two-tier (Moka L1 + SQLite L2)");

        #[cfg(all(
            feature = "cache-sqlite",
            not(feature = "cache-l1"),
            not(feature = "cache-pg"),
            not(feature = "cache-mysql"),
        ))]
        println!("\n🗄️  Cache: SQLite-only (no in-process L1 layer)");

        // ── Redis settings ────────────────────────────────────────────────
        #[cfg(all(
            feature = "cache-l2",
            not(feature = "cache-pg"),
            not(feature = "cache-mysql"),
            not(feature = "cache-sqlite"),
        ))]
        {
            println!("  - Redis URL: {}", self.redis_url);
            println!("  - Cache TTL: {}s", self.cache_ttl);
        }

        // ── Moka L1 settings (Redis or standalone) ────────────────────────
        #[cfg(all(
            feature = "cache-l1",
            not(feature = "cache-pg"),
            not(feature = "cache-mysql"),
            not(feature = "cache-sqlite"),
        ))]
        {
            println!("  - L1 Max Capacity: {} entries", self.l1_max_capacity);
            println!("  - L1 TTL: {}s", self.l1_ttl_sec);
            match self.l1_time_to_idle_sec {
                Some(tti) => println!("  - L1 Time-to-Idle: {}s", tti),
                None => println!("  - L1 Time-to-Idle: disabled"),
            }
        }

        // ── PostgreSQL settings ───────────────────────────────────────────
        #[cfg(all(
            feature = "cache-pg",
            not(feature = "cache-mysql"),
            not(feature = "cache-sqlite"),
        ))]
        {
            println!("  - PG URL: {}", self.pg_url);
            println!("  - PG Max Connections: {}", self.pg_max_connections);
            println!("  - PG Cleanup Interval: {}s", self.pg_cleanup_interval_sec);
        }

        // ── Moka L1 settings (PostgreSQL two-tier) ────────────────────────
        #[cfg(all(
            feature = "cache-l1",
            feature = "cache-pg",
            not(feature = "cache-mysql"),
            not(feature = "cache-sqlite"),
        ))]
        {
            println!("  - L1 Max Capacity: {} entries", self.l1_max_capacity);
            println!("  - L1 TTL (PG): {}s", self.pg_l1_ttl_sec);
            match self.l1_time_to_idle_sec {
                Some(tti) => println!("  - L1 Time-to-Idle: {}s", tti),
                None => println!("  - L1 Time-to-Idle: disabled"),
            }
        }

        // ── MySQL settings ────────────────────────────────────────────────
        #[cfg(all(
            feature = "cache-mysql",
            not(feature = "cache-pg"),
            not(feature = "cache-sqlite"),
        ))]
        {
            println!("  - MySQL URL: {}", self.mysql_url);
            println!("  - MySQL Max Connections: {}", self.mysql_max_connections);
            println!(
                "  - MySQL Cleanup Interval: {}s",
                self.mysql_cleanup_interval_sec
            );
        }

        // ── Moka L1 settings (MySQL two-tier) ─────────────────────────────
        #[cfg(all(
            feature = "cache-l1",
            feature = "cache-mysql",
            not(feature = "cache-pg"),
            not(feature = "cache-sqlite"),
        ))]
        {
            println!("  - L1 Max Capacity: {} entries", self.l1_max_capacity);
            println!("  - L1 TTL (MySQL): {}s", self.mysql_l1_ttl_sec);
            match self.l1_time_to_idle_sec {
                Some(tti) => println!("  - L1 Time-to-Idle: {}s", tti),
                None => println!("  - L1 Time-to-Idle: disabled"),
            }
        }

        // ── SQLite settings ───────────────────────────────────────────────
        #[cfg(all(
            feature = "cache-sqlite",
            not(feature = "cache-pg"),
            not(feature = "cache-mysql"),
        ))]
        {
            println!("  - SQLite URL: {}", self.sqlite_url);
            println!(
                "  - SQLite Max Connections: {}",
                self.sqlite_max_connections
            );
            println!(
                "  - SQLite Cleanup Interval: {}s",
                self.sqlite_cleanup_interval_sec
            );
        }

        // ── Moka L1 settings (SQLite two-tier) ────────────────────────────
        #[cfg(all(
            feature = "cache-l1",
            feature = "cache-sqlite",
            not(feature = "cache-pg"),
            not(feature = "cache-mysql"),
        ))]
        {
            println!("  - L1 Max Capacity: {} entries", self.l1_max_capacity);
            println!("  - L1 TTL (SQLite): {}s", self.sqlite_l1_ttl_sec);
            match self.l1_time_to_idle_sec {
                Some(tti) => println!("  - L1 Time-to-Idle: {}s", tti),
                None => println!("  - L1 Time-to-Idle: disabled"),
            }
        }
    }
}
