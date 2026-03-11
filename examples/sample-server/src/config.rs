//! Configuration module for the OAuth2 sample server.
//!
//! This module handles:
//! - CLI argument parsing using clap
//! - OAuth2 configuration building
//! - Cache configuration (feature-gated)
//! - Environment variable integration
//! - Configuration validation and display
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

use axum_oidc_client::{
    auth::{CodeChallengeMethod, OAuthConfiguration},
    auth_builder::OAuthConfigurationBuilder,
};
use clap::Parser;

/// OAuth2 PKCE Sample Server
///
/// This application demonstrates OAuth2 authentication with PKCE support.
/// Configuration can be provided via command-line arguments or environment variables.
///
/// # Examples
///
/// Run with default Google OAuth endpoints:
/// ```bash
/// sample-server --client-id YOUR_ID --client-secret YOUR_SECRET
/// ```
///
/// Run with custom OAuth provider:
/// ```bash
/// sample-server \
///   --authorization-endpoint https://provider.com/oauth/authorize \
///   --token-endpoint https://provider.com/oauth/token \
///   --client-id YOUR_ID \
///   --client-secret YOUR_SECRET
/// ```
///
/// Use environment variables (via .env file):
/// ```bash
/// # Create .env file with:
/// # OAUTH_CLIENT_ID=your_id
/// # OAUTH_CLIENT_SECRET=your_secret
/// sample-server
/// ```
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// OAuth2 authorization endpoint URL
    #[arg(
        long,
        env = "OAUTH_AUTHORIZATION_ENDPOINT",
        default_value = "https://accounts.google.com/o/oauth2/auth"
    )]
    pub authorization_endpoint: String,

    /// OAuth2 token endpoint URL
    #[arg(
        long,
        env = "OAUTH_TOKEN_ENDPOINT",
        default_value = "https://oauth2.googleapis.com/token"
    )]
    pub token_endpoint: String,

    /// OIDC end session endpoint URL (optional)
    /// Only set this if your OAuth provider supports OIDC RP-Initiated Logout
    /// (e.g., Keycloak, Azure AD, Okta, Auth0)
    /// Do NOT set for Google or GitHub as they don't support OIDC logout
    #[arg(long, env = "OAUTH_END_SESSION_ENDPOINT")]
    pub end_session_endpoint: Option<String>,

    /// Post-logout redirect URI (optional)
    /// Where to redirect users after logout (default: "/")
    #[arg(long, env = "POST_LOGOUT_REDIRECT_URI")]
    pub post_logout_redirect_uri: Option<String>,

    /// OAuth2 client ID
    #[arg(long, env = "OAUTH_CLIENT_ID")]
    pub client_id: String,

    /// OAuth2 client secret
    #[arg(long, env = "OAUTH_CLIENT_SECRET")]
    pub client_secret: String,

    /// OAuth2 redirect URI
    #[arg(
        long,
        env = "OAUTH_REDIRECT_URI",
        default_value = "http://localhost:8080/auth/callback"
    )]
    pub redirect_uri: String,

    /// Private cookie key for session encryption
    #[arg(long, env = "PRIVATE_COOKIE_KEY", default_value = "private_cookie_key")]
    pub private_cookie_key: String,

    /// OAuth2 scopes (comma-separated)
    #[arg(
        long,
        env = "OAUTH_SCOPES",
        default_value = "openid,email,profile",
        value_delimiter = ','
    )]
    pub scopes: Vec<String>,

    /// Custom CA certificate path (optional)
    #[arg(long, env = "CUSTOM_CA_CERT")]
    pub custom_ca_cert: Option<String>,

    /// Code challenge method (S256 or plain)
    #[arg(
        long,
        env = "CODE_CHALLENGE_METHOD",
        default_value = "S256",
        value_parser = parse_code_challenge_method
    )]
    pub code_challenge_method: CodeChallengeMethod,

    /// Base path for authentication routes
    #[arg(long, env = "OAUTH_BASE_PATH", default_value = "/auth")]
    pub base_path: String,

    /// Server host address
    #[arg(long, env = "SERVER_HOST", default_value = "127.0.0.1")]
    pub host: String,

    /// Server port
    #[arg(short, long, env = "SERVER_PORT", default_value = "8080")]
    pub port: u16,

    // ── L2 cache (Redis) args ─────────────────────────────────────────────────
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
    ///
    /// Used when the `cache-l2` or `cache-l1-l2` feature is enabled.
    #[cfg(feature = "cache-l2")]
    #[arg(
        long,
        env = "CACHE_TTL",
        default_value = "3600",
        help = "Redis cache TTL in seconds [cache-l2 / cache-l1-l2]"
    )]
    pub cache_ttl: u64,

    // ── L1 cache (Moka) args ──────────────────────────────────────────────────
    /// Maximum number of entries held by the Moka L1 cache.
    ///
    /// Used when the `cache-l1` or `cache-l1-l2` feature is enabled.
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
    ///
    /// Used when the `cache-l1` or `cache-l1-l2` feature is enabled.
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
    /// When set, entries that have not been accessed for this duration are
    /// evicted even if their TTL has not expired yet.  Leave unset to
    /// disable idle-based eviction.
    ///
    /// Used when the `cache-l1` or `cache-l1-l2` feature is enabled.
    #[cfg(feature = "cache-l1")]
    #[arg(
        long,
        env = "L1_TIME_TO_IDLE_SEC",
        help = "Moka L1 cache time-to-idle in seconds (optional) [cache-l1 / cache-l1-l2]"
    )]
    pub l1_time_to_idle_sec: Option<u64>,

    // ── PostgreSQL cache args ──────────────────────────────────────────────────
    /// PostgreSQL connection URL.
    ///
    /// Used when the `cache-pg` or `cache-l1-pg` feature is enabled.
    /// Example: `postgresql://oidc_user:secret@localhost:5432/oidc_cache`
    #[cfg(feature = "cache-pg")]
    #[arg(
        long,
        env = "PG_URL",
        default_value = "postgresql://oidc_user:oidc_pass@localhost:5432/oidc_cache",
        help = "PostgreSQL connection URL [cache-pg / cache-l1-pg]"
    )]
    pub pg_url: String,

    /// Maximum number of connections in the PostgreSQL connection pool.
    ///
    /// Used when the `cache-pg` or `cache-l1-pg` feature is enabled.
    #[cfg(feature = "cache-pg")]
    #[arg(
        long,
        env = "PG_MAX_CONNECTIONS",
        default_value = "20",
        help = "PostgreSQL pool max connections [cache-pg / cache-l1-pg]"
    )]
    pub pg_max_connections: u32,

    /// How often (seconds) the background cleanup task sweeps expired rows
    /// from the `oidc_cache` table.
    ///
    /// Used when the `cache-pg` or `cache-l1-pg` feature is enabled.
    #[cfg(feature = "cache-pg")]
    #[arg(
        long,
        env = "PG_CLEANUP_INTERVAL_SEC",
        default_value = "300",
        help = "PostgreSQL cache cleanup interval in seconds [cache-pg / cache-l1-pg]"
    )]
    pub pg_cleanup_interval_sec: u64,

    /// TTL (seconds) for the Moka L1 layer when used in front of PostgreSQL.
    ///
    /// Should match or slightly exceed the session max-age so that stale L1
    /// entries never outlive valid PostgreSQL rows.
    ///
    /// Only relevant when `cache-l1-pg` is enabled.
    #[cfg(feature = "cache-l1")]
    #[cfg(feature = "cache-pg")]
    #[arg(
        long,
        env = "PG_L1_TTL_SEC",
        default_value = "1800",
        help = "Moka L1 TTL in seconds when used in front of PostgreSQL [cache-l1-pg]"
    )]
    pub pg_l1_ttl_sec: u64,

    // ── MySQL / MariaDB cache args ─────────────────────────────────────────────
    /// MySQL / MariaDB connection URL.
    ///
    /// Used when the `cache-mysql` or `cache-l1-mysql` feature is enabled.
    /// Example: `mysql://oidc_user:oidc_pass@localhost:3306/oidc_cache`
    #[cfg(feature = "cache-mysql")]
    #[arg(
        long,
        env = "MYSQL_URL",
        default_value = "mysql://oidc_user:oidc_pass@localhost:3306/oidc_cache",
        help = "MySQL / MariaDB connection URL [cache-mysql / cache-l1-mysql]"
    )]
    pub mysql_url: String,

    /// Maximum number of connections in the MySQL connection pool.
    ///
    /// Used when the `cache-mysql` or `cache-l1-mysql` feature is enabled.
    #[cfg(feature = "cache-mysql")]
    #[arg(
        long,
        env = "MYSQL_MAX_CONNECTIONS",
        default_value = "20",
        help = "MySQL pool max connections [cache-mysql / cache-l1-mysql]"
    )]
    pub mysql_max_connections: u32,

    /// How often (seconds) the background cleanup task sweeps expired rows
    /// from the `oidc_cache` table.
    ///
    /// Used when the `cache-mysql` or `cache-l1-mysql` feature is enabled.
    #[cfg(feature = "cache-mysql")]
    #[arg(
        long,
        env = "MYSQL_CLEANUP_INTERVAL_SEC",
        default_value = "300",
        help = "MySQL cache cleanup interval in seconds [cache-mysql / cache-l1-mysql]"
    )]
    pub mysql_cleanup_interval_sec: u64,

    /// TTL (seconds) for the Moka L1 layer when used in front of MySQL.
    ///
    /// Should be <= the session max-age so that a stale L1 hit never returns
    /// a session that has already been invalidated in MySQL.
    ///
    /// Only relevant when `cache-l1-mysql` is enabled.
    #[cfg(feature = "cache-l1")]
    #[cfg(feature = "cache-mysql")]
    #[arg(
        long,
        env = "MYSQL_L1_TTL_SEC",
        default_value = "1800",
        help = "Moka L1 TTL in seconds when used in front of MySQL [cache-l1-mysql]"
    )]
    pub mysql_l1_ttl_sec: u64,

    // ── SQLite cache args ──────────────────────────────────────────────────────
    /// SQLite connection URL.
    ///
    /// Used when the `cache-sqlite` or `cache-l1-sqlite` feature is enabled.
    /// Use a file path (`sqlite:///path/to/cache.db`) or `:memory:` for an
    /// ephemeral in-process database (`sqlite://:memory:`).
    ///
    /// The parent directory must exist and be writable before the server starts.
    /// With `sqlite:///data/oidc_cache.db` SQLite creates the file automatically
    /// if it does not exist.
    #[cfg(feature = "cache-sqlite")]
    #[arg(
        long,
        env = "SQLITE_URL",
        default_value = "sqlite:///tmp/oidc_cache.db",
        help = "SQLite connection URL [cache-sqlite / cache-l1-sqlite]"
    )]
    pub sqlite_url: String,

    /// Maximum number of connections in the SQLite connection pool.
    ///
    /// SQLite supports only one concurrent writer.  Keep this value low
    /// (1 – 5) to avoid lock contention.  Default: `5`.
    ///
    /// Used when the `cache-sqlite` or `cache-l1-sqlite` feature is enabled.
    #[cfg(feature = "cache-sqlite")]
    #[arg(
        long,
        env = "SQLITE_MAX_CONNECTIONS",
        default_value = "5",
        help = "SQLite pool max connections [cache-sqlite / cache-l1-sqlite]"
    )]
    pub sqlite_max_connections: u32,

    /// How often (seconds) the background cleanup task sweeps expired rows
    /// from the `oidc_cache` table.
    ///
    /// Used when the `cache-sqlite` or `cache-l1-sqlite` feature is enabled.
    #[cfg(feature = "cache-sqlite")]
    #[arg(
        long,
        env = "SQLITE_CLEANUP_INTERVAL_SEC",
        default_value = "300",
        help = "SQLite cache cleanup interval in seconds [cache-sqlite / cache-l1-sqlite]"
    )]
    pub sqlite_cleanup_interval_sec: u64,

    /// TTL (seconds) for the Moka L1 layer when used in front of SQLite.
    ///
    /// Should be <= the session max-age so that a stale L1 hit never returns
    /// a session that has already been invalidated in SQLite.
    ///
    /// Only relevant when `cache-l1-sqlite` is enabled.
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

/// Parse a code challenge method from a string.
///
/// # Arguments
///
/// * `s` - A string slice that should be either "S256" or "plain" (case-insensitive)
///
/// # Returns
///
/// * `Ok(CodeChallengeMethod)` - The parsed method
/// * `Err(String)` - An error message if the input is invalid
///
/// # Examples
///
/// ```
/// # use axum_oidc_client::auth::CodeChallengeMethod;
/// # fn parse_code_challenge_method(s: &str) -> Result<CodeChallengeMethod, String> {
/// #     match s.to_uppercase().as_str() {
/// #         "S256" => Ok(CodeChallengeMethod::S256),
/// #         "PLAIN" => Ok(CodeChallengeMethod::Plain),
/// #         _ => Err(format!("Invalid code challenge method '{}'", s)),
/// #     }
/// # }
/// assert!(parse_code_challenge_method("S256").is_ok());
/// assert!(parse_code_challenge_method("plain").is_ok());
/// assert!(parse_code_challenge_method("invalid").is_err());
/// ```
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

impl Args {
    /// Build an OAuth configuration from the parsed arguments.
    ///
    /// This method constructs a complete [`OAuthConfiguration`] using the values
    /// provided via command-line arguments or environment variables.
    ///
    /// # Session and Token Configuration
    ///
    /// - Session max age: 30 minutes
    /// - Token max age: 1 minute
    ///
    /// # Returns
    ///
    /// * `Ok(OAuthConfiguration)` - A fully configured OAuth configuration
    /// * `Err(String)` - An error message if the configuration is invalid
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use clap::Parser;
    /// # #[derive(Parser)]
    /// # struct Args {
    /// #     client_id: String,
    /// #     client_secret: String,
    /// # }
    /// # impl Args {
    /// #     fn build_oauth_config(&self) -> Result<(), String> { Ok(()) }
    /// # }
    /// let args = Args::parse();
    /// let config = args.build_oauth_config()
    ///     .expect("Failed to build configuration");
    /// ```
    pub fn build_oauth_config(&self) -> Result<OAuthConfiguration, String> {
        let mut configuration_builder = OAuthConfigurationBuilder::default();

        configuration_builder = configuration_builder
            .with_code_challenge_method(self.code_challenge_method.clone())
            .with_authorization_endpoint(&self.authorization_endpoint)
            .with_token_endpoint(&self.token_endpoint)
            .with_client_id(&self.client_id)
            .with_client_secret(&self.client_secret)
            .with_private_cookie_key(&self.private_cookie_key)
            .with_redirect_uri(&self.redirect_uri)
            .with_session_max_age(30)
            .with_token_max_age(1)
            .with_scopes(self.scopes.iter().map(|s| s.as_str()).collect())
            .with_base_path(&self.base_path);

        // Add end session endpoint if provided
        if let Some(end_session_endpoint) = self.end_session_endpoint.as_ref() {
            configuration_builder =
                configuration_builder.with_end_session_endpoint(end_session_endpoint);
        }

        // Add post logout redirect URI if provided
        if let Some(post_logout_redirect_uri) = self.post_logout_redirect_uri.as_ref() {
            configuration_builder =
                configuration_builder.with_post_logout_redirect_uri(post_logout_redirect_uri);
        }

        // Add custom CA cert if provided
        if let Some(ca_cert_path) = self.custom_ca_cert.as_ref() {
            configuration_builder = configuration_builder.with_custom_ca_cert(ca_cert_path);
        }

        configuration_builder
            .build()
            .map_err(|e| format!("Failed to build OAuth configuration: {:?}", e))
    }

    /// Print the OAuth configuration to stdout.
    ///
    /// This displays all OAuth2 settings including:
    /// - Authorization endpoint
    /// - Token endpoint
    /// - End session endpoint (if configured)
    /// - Post logout redirect URI (if configured)
    /// - Client ID
    /// - Redirect URI
    /// - Requested scopes
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use clap::Parser;
    /// # #[derive(Parser)]
    /// # struct Args {}
    /// # impl Args {
    /// #     fn print_config(&self) {}
    /// # }
    /// let args = Args::parse();
    /// args.print_config();
    /// // Outputs formatted configuration information
    /// ```
    pub fn print_config(&self) {
        println!("\n📋 OAuth2 Configuration:");
        println!("  - Authorization: {}", self.authorization_endpoint);
        println!("  - Token: {}", self.token_endpoint);
        if let Some(ref end_session_endpoint) = self.end_session_endpoint {
            println!("  - End Session: {}", end_session_endpoint);
        }
        if let Some(ref post_logout_redirect_uri) = self.post_logout_redirect_uri {
            println!("  - Post Logout Redirect: {}", post_logout_redirect_uri);
        }
        println!("  - Client ID: {}", self.client_id);
        println!("  - Redirect URI: {}", self.redirect_uri);
        println!("  - Base Path: {}", self.base_path);
        println!("  - Scopes: {:?}", self.scopes);
        self.print_cache_config();
    }

    /// Print the active cache configuration to stdout.
    ///
    /// The output is controlled by the active cache feature flag:
    ///
    /// - `cache-l1-l2`    → Two-tier (Moka L1 + Redis L2) with all settings
    /// - `cache-l1`       → L1-only (Moka) with L1 settings
    /// - `cache-l2`       → L2-only (Redis) with Redis settings
    /// - `cache-pg`       → PostgreSQL-only with PG settings
    /// - `cache-l1-pg`    → Two-tier (Moka L1 + PostgreSQL L2) with all settings
    /// - `cache-mysql`    → MySQL-only with MySQL settings
    /// - `cache-l1-mysql` → Two-tier (Moka L1 + MySQL L2) with all settings
    pub fn print_cache_config(&self) {
        // ── Mode banner ───────────────────────────────────────────────────────
        #[cfg(all(
            feature = "cache-l1",
            feature = "cache-l2",
            not(feature = "cache-pg"),
            not(feature = "cache-mysql"),
        ))]
        println!("\n🗄️  Cache: Two-tier (Moka L1 + Redis L2)");

        #[cfg(all(
            feature = "cache-l1",
            not(feature = "cache-l2"),
            not(feature = "cache-pg"),
            not(feature = "cache-mysql"),
        ))]
        println!("\n🗄️  Cache: L1-only (Moka in-process, no external backend)");

        #[cfg(all(
            feature = "cache-l2",
            not(feature = "cache-l1"),
            not(feature = "cache-pg"),
            not(feature = "cache-mysql"),
        ))]
        println!("\n🗄️  Cache: L2-only (Redis)");

        #[cfg(all(
            feature = "cache-pg",
            feature = "cache-l1",
            not(feature = "cache-mysql")
        ))]
        println!("\n🗄️  Cache: Two-tier (Moka L1 + PostgreSQL L2)");

        #[cfg(all(
            feature = "cache-pg",
            not(feature = "cache-l1"),
            not(feature = "cache-mysql")
        ))]
        println!("\n🗄️  Cache: PostgreSQL-only (no in-process L1 layer)");

        #[cfg(all(
            feature = "cache-mysql",
            feature = "cache-l1",
            not(feature = "cache-pg")
        ))]
        println!("\n🗄️  Cache: Two-tier (Moka L1 + MySQL L2)");

        #[cfg(all(
            feature = "cache-mysql",
            not(feature = "cache-l1"),
            not(feature = "cache-pg")
        ))]
        println!("\n🗄️  Cache: MySQL-only (no in-process L1 layer)");

        // ── L2 (Redis) settings ───────────────────────────────────────────────
        #[cfg(all(
            feature = "cache-l2",
            not(feature = "cache-pg"),
            not(feature = "cache-mysql")
        ))]
        {
            println!("  - Redis URL: {}", self.redis_url);
            println!("  - Cache TTL: {}s", self.cache_ttl);
        }

        // ── L1 (Moka) settings – Redis or standalone ──────────────────────────
        #[cfg(all(
            feature = "cache-l1",
            not(feature = "cache-pg"),
            not(feature = "cache-mysql"),
        ))]
        {
            println!("  - L1 Max Capacity: {} entries", self.l1_max_capacity);
            println!("  - L1 TTL: {}s", self.l1_ttl_sec);
            match self.l1_time_to_idle_sec {
                Some(tti) => println!("  - L1 Time-to-Idle: {}s", tti),
                None => println!("  - L1 Time-to-Idle: disabled"),
            }
        }

        // ── PostgreSQL settings ───────────────────────────────────────────────
        #[cfg(all(feature = "cache-pg", not(feature = "cache-mysql")))]
        {
            println!("  - PG URL: {}", self.pg_url);
            println!("  - PG Max Connections: {}", self.pg_max_connections);
            println!("  - PG Cleanup Interval: {}s", self.pg_cleanup_interval_sec);
        }

        // ── L1 (Moka) settings – PostgreSQL two-tier ──────────────────────────
        #[cfg(all(
            feature = "cache-l1",
            feature = "cache-pg",
            not(feature = "cache-mysql")
        ))]
        {
            println!("  - L1 Max Capacity: {} entries", self.l1_max_capacity);
            println!("  - L1 TTL (PG): {}s", self.pg_l1_ttl_sec);
            match self.l1_time_to_idle_sec {
                Some(tti) => println!("  - L1 Time-to-Idle: {}s", tti),
                None => println!("  - L1 Time-to-Idle: disabled"),
            }
        }

        // ── MySQL settings ────────────────────────────────────────────────────
        #[cfg(feature = "cache-mysql")]
        {
            println!("  - MySQL URL: {}", self.mysql_url);
            println!("  - MySQL Max Connections: {}", self.mysql_max_connections);
            println!(
                "  - MySQL Cleanup Interval: {}s",
                self.mysql_cleanup_interval_sec
            );
        }

        // ── L1 (Moka) settings – MySQL two-tier ───────────────────────────────
        #[cfg(all(feature = "cache-l1", feature = "cache-mysql"))]
        {
            println!("  - L1 Max Capacity: {} entries", self.l1_max_capacity);
            println!("  - L1 TTL (MySQL): {}s", self.mysql_l1_ttl_sec);
            match self.l1_time_to_idle_sec {
                Some(tti) => println!("  - L1 Time-to-Idle: {}s", tti),
                None => println!("  - L1 Time-to-Idle: disabled"),
            }
        }

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

        // ── SQLite settings ───────────────────────────────────────────────────
        #[cfg(feature = "cache-sqlite")]
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

        // ── L1 (Moka) settings – SQLite two-tier ──────────────────────────────
        #[cfg(all(feature = "cache-l1", feature = "cache-sqlite"))]
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
