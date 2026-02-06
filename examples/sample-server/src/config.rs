//! Configuration module for the OAuth2 sample server.
//!
//! This module handles:
//! - CLI argument parsing using clap
//! - OAuth2 configuration building
//! - Environment variable integration
//! - Configuration validation and display

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
    }
}
