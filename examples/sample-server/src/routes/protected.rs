//! Protected route handler module.
//!
//! Provides a protected route that requires authentication and displays
//! the user's session information and tokens.

use axum::response::Html;
use axum_oidc_client::auth_session::AuthSession;
use chrono::Local;

/// Protected route handler.
///
/// This route is only accessible to authenticated users. It displays detailed
/// session information including tokens, expiration times, and scopes.
///
/// # Route
///
/// - `GET /protected`
///
/// # Authentication
///
/// This route requires authentication. The [`AuthSession`] extractor will
/// automatically redirect unauthenticated users to the OAuth2 authorization
/// endpoint.
///
/// # Arguments
///
/// * `session` - The authenticated user's session containing tokens and metadata
///
/// # Response
///
/// Returns an HTML page displaying:
/// - Token type (usually "Bearer")
/// - Current server time
/// - Token expiration time (in seconds)
/// - Granted OAuth scopes
/// - Access token (full JWT)
/// - ID token (full JWT)
///
/// # Security Note
///
/// This route displays sensitive token information for demonstration purposes.
/// In a production application, you should never expose raw tokens to users.
///
/// # Examples
///
/// When accessed by an authenticated user, displays:
/// - Session metadata (token type, expiration, scopes)
/// - Full access token
/// - Full ID token
/// - Link to return to home page
pub async fn protected(session: AuthSession) -> Html<String> {
    let token_type = &session.token_type;
    let now = Local::now();
    let expires = session
        .expires
        .map(|e| e.to_string())
        .unwrap_or_else(|| "(no expiry)".to_string());
    let scope = session.scope.as_deref().unwrap_or("(none)");
    let access_token_session = &session.access_token;
    let id_token = &session.id_token;

    Html(format!(
        r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Protected</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    max-width: 800px;
                    margin: 50px auto;
                    padding: 20px;
                }}
                h1 {{ color: #28a745; }}
                a {{
                    color: #0066cc;
                    text-decoration: none;
                }}
                a:hover {{ text-decoration: underline; }}
                .container {{
                    background: #f5f5f5;
                    padding: 30px;
                    border-radius: 10px;
                    border-left: 5px solid #28a745;
                }}
                .token {{
                    background: #f0f0f0;
                    padding: 10px;
                    border-radius: 5px;
                    word-break: break-all;
                    margin: 10px 0;
                    font-family: monospace;
                    font-size: 12px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔒 Protected Route</h1>
                <p>You have successfully accessed the protected content!</p>

                <h2>Session Information</h2>
                <p><strong>Token Type:</strong> {token_type}</p>
                <p><strong>Now:</strong> {now}</p>
                <p><strong>Expires:</strong> {expires} seconds</p>
                <p><strong>Scopes:</strong> {scope}</p>

                <h3>Access Token</h3>
                <div class="token">{access_token_session}</div>

                <h3>ID Token</h3>
                <div class="token">{id_token}</div>

                <p><a href="/">← Back to Home</a></p>
            </div>
        </body>
        </html>
        "#
    ))
}
