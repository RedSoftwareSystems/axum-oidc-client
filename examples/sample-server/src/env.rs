//! Environment variable handling module for the OAuth2 sample server.
//!
//! This module provides utilities for:
//! - Loading environment variables from dotenv files
//! - Checking which configuration comes from environment variables
//! - Displaying configuration source information to users
//!
//! # Dotenv File Priority
//!
//! Files are loaded in the following priority order:
//! 1. File specified in `DOTENV_FILE` environment variable
//! 2. `.env.local` (for local development overrides)
//! 3. `.env` (for shared defaults)
//!
//! Only the first file found is loaded.
//!
//! # Cache-related environment variables
//!
//! Additional variables are recognised depending on the active cache feature:
//!
//! | Variable                      | Feature                          | Description                              |
//! |-------------------------------|----------------------------------|------------------------------------------|
//! | `REDIS_URL`                   | `cache-l2`/`cache-l1-l2`        | Redis connection URL                     |
//! | `CACHE_TTL`                   | `cache-l2`/`cache-l1-l2`        | Redis entry TTL in seconds               |
//! | `L1_MAX_CAPACITY`             | `cache-l1`/`cache-l1-l2`        | Moka max entries                         |
//! | `L1_TTL_SEC`                  | `cache-l1`/`cache-l1-l2`        | Moka entry TTL in seconds                |
//! | `L1_TIME_TO_IDLE_SEC`         | `cache-l1`/`cache-l1-l2`        | Moka idle-eviction timeout               |
//! | `PG_URL`                      | `cache-pg`/`cache-l1-pg`        | PostgreSQL connection URL                |
//! | `PG_MAX_CONNECTIONS`          | `cache-pg`/`cache-l1-pg`        | PostgreSQL pool max connections          |
//! | `PG_CLEANUP_INTERVAL_SEC`     | `cache-pg`/`cache-l1-pg`        | Expired-row cleanup interval (sec)      |
//! | `PG_L1_TTL_SEC`               | `cache-l1-pg`                   | Moka L1 TTL when used in front of PG    |
//! | `MYSQL_URL`                   | `cache-mysql`/`cache-l1-mysql`  | MySQL/MariaDB connection URL             |
//! | `MYSQL_MAX_CONNECTIONS`       | `cache-mysql`/`cache-l1-mysql`  | MySQL pool max connections               |
//! | `MYSQL_CLEANUP_INTERVAL_SEC`  | `cache-mysql`/`cache-l1-mysql`  | Expired-row cleanup interval (sec)      |
//! | `MYSQL_L1_TTL_SEC`            | `cache-l1-mysql`                | Moka L1 TTL when used in front of MySQL |

use std::{env, path::PathBuf};

/// Check which OAuth2-related environment variables are currently set.
///
/// This function scans for all environment variables used by the sample server
/// and returns a list of those that are currently defined.
///
/// # Checked Variables
///
/// OAuth2 Configuration:
/// - `OAUTH_AUTHORIZATION_ENDPOINT`
/// - `OAUTH_TOKEN_ENDPOINT`
/// - `OAUTH_END_SESSION_ENDPOINT` (only for OIDC-compliant providers like Keycloak, Azure AD)
/// - `POST_LOGOUT_REDIRECT_URI`
/// - `OAUTH_CLIENT_ID`
/// - `OAUTH_CLIENT_SECRET`
/// - `OAUTH_REDIRECT_URI`
/// - `OAUTH_BASE_PATH`
/// - `OAUTH_SCOPES`
/// - `PRIVATE_COOKIE_KEY`
/// - `CUSTOM_CA_CERT`
/// - `CODE_CHALLENGE_METHOD`
///
/// Server Configuration:
/// - `SERVER_HOST`
/// - `SERVER_PORT`
///
/// Cache Configuration (feature-gated):
/// - `REDIS_URL` *(cache-l2 / cache-l1-l2)*
/// - `CACHE_TTL` *(cache-l2 / cache-l1-l2)*
/// - `L1_MAX_CAPACITY` *(cache-l1 / cache-l1-l2)*
/// - `L1_TTL_SEC` *(cache-l1 / cache-l1-l2)*
/// - `L1_TIME_TO_IDLE_SEC` *(cache-l1 / cache-l1-l2)*
/// - `PG_URL` *(cache-pg / cache-l1-pg)*
/// - `PG_MAX_CONNECTIONS` *(cache-pg / cache-l1-pg)*
/// - `PG_CLEANUP_INTERVAL_SEC` *(cache-pg / cache-l1-pg)*
/// - `PG_L1_TTL_SEC` *(cache-l1-pg)*
/// - `MYSQL_URL` *(cache-mysql / cache-l1-mysql)*
/// - `MYSQL_MAX_CONNECTIONS` *(cache-mysql / cache-l1-mysql)*
/// - `MYSQL_CLEANUP_INTERVAL_SEC` *(cache-mysql / cache-l1-mysql)*
/// - `MYSQL_L1_TTL_SEC` *(cache-l1-mysql)*
///
/// # Returns
///
/// A vector of environment variable names that are currently set.
///
/// # Examples
///
/// ```no_run
/// # fn check_env_sources() -> Vec<String> { vec![] }
/// let sources = check_env_sources();
/// if !sources.is_empty() {
///     println!("Configuration from env: {}", sources.join(", "));
/// }
/// ```
pub fn check_env_sources() -> Vec<String> {
    let mut sources = Vec::new();

    if env::var("OAUTH_AUTHORIZATION_ENDPOINT").is_ok() {
        sources.push("OAUTH_AUTHORIZATION_ENDPOINT".to_string());
    }
    if env::var("OAUTH_TOKEN_ENDPOINT").is_ok() {
        sources.push("OAUTH_TOKEN_ENDPOINT".to_string());
    }
    if env::var("OAUTH_END_SESSION_ENDPOINT").is_ok() {
        sources.push("OAUTH_END_SESSION_ENDPOINT".to_string());
    }
    if env::var("POST_LOGOUT_REDIRECT_URI").is_ok() {
        sources.push("POST_LOGOUT_REDIRECT_URI".to_string());
    }
    if env::var("OAUTH_CLIENT_ID").is_ok() {
        sources.push("OAUTH_CLIENT_ID".to_string());
    }
    if env::var("OAUTH_CLIENT_SECRET").is_ok() {
        sources.push("OAUTH_CLIENT_SECRET".to_string());
    }
    if env::var("OAUTH_REDIRECT_URI").is_ok() {
        sources.push("OAUTH_REDIRECT_URI".to_string());
    }
    if env::var("PRIVATE_COOKIE_KEY").is_ok() {
        sources.push("PRIVATE_COOKIE_KEY".to_string());
    }
    if env::var("OAUTH_SCOPES").is_ok() {
        sources.push("OAUTH_SCOPES".to_string());
    }
    if env::var("CUSTOM_CA_CERT").is_ok() {
        sources.push("CUSTOM_CA_CERT".to_string());
    }
    if env::var("CODE_CHALLENGE_METHOD").is_ok() {
        sources.push("CODE_CHALLENGE_METHOD".to_string());
    }
    if env::var("OAUTH_BASE_PATH").is_ok() {
        sources.push("OAUTH_BASE_PATH".to_string());
    }
    if env::var("SERVER_HOST").is_ok() {
        sources.push("SERVER_HOST".to_string());
    }
    if env::var("SERVER_PORT").is_ok() {
        sources.push("SERVER_PORT".to_string());
    }

    // ── Cache: L2 (Redis) ─────────────────────────────────────────────────────
    #[cfg(feature = "cache-l2")]
    {
        if env::var("REDIS_URL").is_ok() {
            sources.push("REDIS_URL".to_string());
        }
        if env::var("CACHE_TTL").is_ok() {
            sources.push("CACHE_TTL".to_string());
        }
    }

    // ── Cache: L1 (Moka) ─────────────────────────────────────────────────────
    #[cfg(feature = "cache-l1")]
    {
        if env::var("L1_MAX_CAPACITY").is_ok() {
            sources.push("L1_MAX_CAPACITY".to_string());
        }
        if env::var("L1_TTL_SEC").is_ok() {
            sources.push("L1_TTL_SEC".to_string());
        }
        if env::var("L1_TIME_TO_IDLE_SEC").is_ok() {
            sources.push("L1_TIME_TO_IDLE_SEC".to_string());
        }
    }

    // ── Cache: PostgreSQL ─────────────────────────────────────────────────────
    #[cfg(feature = "cache-pg")]
    {
        if env::var("PG_URL").is_ok() {
            sources.push("PG_URL".to_string());
        }
        if env::var("PG_MAX_CONNECTIONS").is_ok() {
            sources.push("PG_MAX_CONNECTIONS".to_string());
        }
        if env::var("PG_CLEANUP_INTERVAL_SEC").is_ok() {
            sources.push("PG_CLEANUP_INTERVAL_SEC".to_string());
        }
    }

    // ── Cache: Moka L1 TTL specific to PG two-tier ───────────────────────────
    #[cfg(all(feature = "cache-l1", feature = "cache-pg"))]
    {
        if env::var("PG_L1_TTL_SEC").is_ok() {
            sources.push("PG_L1_TTL_SEC".to_string());
        }
    }

    // ── Cache: MySQL / MariaDB ────────────────────────────────────────────────
    #[cfg(feature = "cache-mysql")]
    {
        if env::var("MYSQL_URL").is_ok() {
            sources.push("MYSQL_URL".to_string());
        }
        if env::var("MYSQL_MAX_CONNECTIONS").is_ok() {
            sources.push("MYSQL_MAX_CONNECTIONS".to_string());
        }
        if env::var("MYSQL_CLEANUP_INTERVAL_SEC").is_ok() {
            sources.push("MYSQL_CLEANUP_INTERVAL_SEC".to_string());
        }
    }

    // ── Cache: Moka L1 TTL specific to MySQL two-tier ────────────────────────
    #[cfg(all(feature = "cache-l1", feature = "cache-mysql"))]
    {
        if env::var("MYSQL_L1_TTL_SEC").is_ok() {
            sources.push("MYSQL_L1_TTL_SEC".to_string());
        }
    }

    sources
}

/// Try loading environment variables from dotenv files.
///
/// This function attempts to load environment variables from dotenv files
/// in the following priority order:
/// 1. File specified by `DOTENV_FILE` environment variable
/// 2. `.env.local` (for local development overrides)
/// 3. `.env` (for shared defaults)
///
/// Only the first existing file is loaded. Subsequent files are ignored.
///
/// # Returns
///
/// * `Some(PathBuf)` - The path of the dotenv file that was loaded
/// * `None` - No dotenv file was found or loaded
///
/// # Examples
///
/// ```no_run
/// # use std::path::PathBuf;
/// # fn load_dotenv() -> Option<PathBuf> { None }
/// if let Some(path) = load_dotenv() {
///     println!("Loaded configuration from: {}", path.display());
/// } else {
///     println!("No dotenv file found, using defaults");
/// }
/// ```
///
/// # Environment Variables
///
/// Set `DOTENV_FILE` to specify a custom dotenv file location:
/// ```bash
/// DOTENV_FILE=/path/to/custom.env cargo run
/// ```
pub fn load_dotenv() -> Option<PathBuf> {
    // Build search list
    let mut candidates = Vec::new();
    if let Ok(custom) = env::var("DOTENV_FILE") {
        candidates.push(PathBuf::from(custom));
    }
    candidates.push(PathBuf::from(".env.local"));
    candidates.push(PathBuf::from(".env"));

    // Pick first that exists and load it
    for path in candidates {
        if path.exists() {
            let _ = dotenv::from_path(&path);
            return Some(path);
        }
    }
    None
}

/// Print information about configuration sources to stdout.
///
/// This function displays a formatted summary of where configuration
/// values are being loaded from, helping users understand the active
/// configuration.
///
/// # Arguments
///
/// * `from_env` - A slice of environment variable names that are currently set
/// * `dotenv_path` - Optional path to the dotenv file that was loaded
///
/// # Output
///
/// The function prints:
/// - Which dotenv file was loaded (if any)
/// - List of environment variables being used
/// - Whether command-line arguments were provided
/// - A helpful tip about using --help
///
/// # Examples
///
/// ```no_run
/// # use std::path::PathBuf;
/// # fn print_config_sources(from_env: &[String], dotenv_path: Option<&PathBuf>) {}
/// let env_vars = vec!["OAUTH_CLIENT_ID".to_string(), "OAUTH_CLIENT_SECRET".to_string()];
/// let dotenv_file = Some(PathBuf::from(".env.local"));
///
/// print_config_sources(&env_vars, dotenv_file.as_ref());
/// // Outputs:
/// // 📄 Loaded configuration from .env.local file
/// //
/// // ⚙️  Configuration Sources:
/// //   ✓ Environment variables: OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET
/// //   ✓ Command-line arguments provided
/// //
/// // 💡 Tip: Use --help to see all configuration options
/// ```
pub fn print_config_sources(from_env: &[String], dotenv_path: Option<&PathBuf>) {
    if let Some(path) = dotenv_path {
        println!("📄 Loaded configuration from {} file", path.display());
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
