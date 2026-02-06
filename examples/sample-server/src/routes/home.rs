//! Home route handler module.
//!
//! Provides a public home page that displays different content based on
//! whether the user is authenticated or not.

use std::collections::HashMap;

use axum::{
    http::HeaderMap,
    response::{Html, IntoResponse},
};
use axum_oidc_client::extractors::OptionalIdToken;
use jsonwebtoken::dangerous::insecure_decode;

/// Extract the user's email from an ID token JWT.
///
/// This function performs an insecure decode of the JWT to extract the email
/// claim without verifying the signature. This is acceptable for display
/// purposes only since the token was already validated by the authentication
/// layer.
///
/// # Arguments
///
/// * `id_token` - The JWT ID token as a string
///
/// # Returns
///
/// * `Some(String)` - The email address from the token's claims
/// * `None` - If the token cannot be decoded or has no email claim
///
/// # Security Note
///
/// This uses `insecure_decode` which does NOT verify the token signature.
/// The token should have already been validated by the authentication middleware.
///
/// # Examples
///
/// ```no_run
/// # fn extract_name_from_id_token(id_token: &str) -> Option<String> { None }
/// let token = "eyJhbGc..."; // Valid JWT token
/// if let Some(email) = extract_name_from_id_token(token) {
///     println!("User email: {}", email);
/// }
/// ```
fn extract_name_from_id_token(id_token: &str) -> Option<String> {
    let decoded_token = insecure_decode::<HashMap<String, serde_json::Value>>(id_token);
    match decoded_token {
        Ok(token) => {
            let claims = token.claims;
            claims
                .get("email")
                .and_then(serde_json::Value::as_str)
                .map(String::from)
        }
        Err(err) => {
            eprintln!("Failed to decode ID token: {}", err);
            None
        }
    }
}

/// Home route handler.
///
/// Displays a public home page with different content based on authentication status.
/// - **Authenticated users**: Shows welcome message with their email and logout link
/// - **Unauthenticated users**: Shows generic welcome and login link
///
/// # Route
///
/// - `GET /` or `GET /home`
///
/// # Authentication
///
/// This is a public route that works for both authenticated and unauthenticated users.
/// Uses [`OptionalIdToken`] extractor to optionally get the user's ID token.
///
/// # Response
///
/// Returns an HTML page with:
/// - Welcome message (personalized if authenticated)
/// - Navigation links appropriate to authentication state
/// - Cache-Control header set to "no-cache"
///
/// # Examples
///
/// When accessed by an unauthenticated user:
/// - Shows "Welcome to the Axum server running on port 8080!"
/// - Displays "Login with OAuth2" link
///
/// When accessed by an authenticated user:
/// - Shows "Welcome, user@example.com!"
/// - Displays "View Protected Resource" and "Logout" links
pub async fn home(OptionalIdToken(id_token): OptionalIdToken) -> impl IntoResponse {
    let is_authenticated = id_token.is_some();

    let user_name = match id_token {
        Some(token) => extract_name_from_id_token(&token),
        _ => None,
    };
    let welcome_message = if let Some(name) = user_name {
        format!("Welcome, {}!", html_escape(&name))
    } else {
        "Welcome to the Axum server running on port 8080!".to_string()
    };

    // Show different links based on login state
    let auth_links = if is_authenticated {
        r#"
                    <a href="/protected">View Protected Resource</a>
                    <a href="/auth/logout">Logout</a>
        "#
    } else {
        r#"
                    <a href="/auth">Login with OAuth2</a>
        "#
    };

    let mut headers = HeaderMap::new();
    headers.insert("Cache-Control", "no-cache".parse().unwrap());
    (
        headers,
        Html(format!(
            r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Home</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    max-width: 800px;
                    margin: 50px auto;
                    padding: 20px;
                }}
                h1 {{ color: #333; }}
                a {{
                    color: #0066cc;
                    text-decoration: none;
                    margin-right: 20px;
                }}
                a:hover {{ text-decoration: underline; }}
                .container {{
                    background: #f5f5f5;
                    padding: 30px;
                    border-radius: 10px;
                }}
                .welcome {{
                    font-size: 1.1em;
                    color: #28a745;
                    margin-bottom: 20px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🏠 Home Page</h1>
                <p class="welcome">{welcome_message}</p>
                <p>
                    <a href="/home">Home</a>
                    {auth_links}
                </p>
            </div>
        </body>
        </html>
        "#,
        )),
    )
}

/// Simple HTML escape function to prevent XSS attacks.
///
/// Escapes common HTML special characters to their HTML entity equivalents.
///
/// # Arguments
///
/// * `s` - The string to escape
///
/// # Returns
///
/// A new string with HTML special characters escaped.
///
/// # Escaped Characters
///
/// - `&` → `&amp;`
/// - `<` → `&lt;`
/// - `>` → `&gt;`
/// - `"` → `&quot;`
/// - `'` → `&#x27;`
///
/// # Examples
///
/// ```
/// # fn html_escape(s: &str) -> String {
/// #     s.replace('&', "&amp;")
/// #         .replace('<', "&lt;")
/// #         .replace('>', "&gt;")
/// #         .replace('"', "&quot;")
/// #         .replace('\'', "&#x27;")
/// # }
/// assert_eq!(html_escape("<script>alert('xss')</script>"),
///            "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;");
/// assert_eq!(html_escape("user@example.com"), "user@example.com");
/// ```
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}
