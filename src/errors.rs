use axum::response::IntoResponse;

#[cfg(feature = "redis")]
use redis::RedisError;

#[derive(Debug)]
pub enum Error {
    MissingCodeVerifier,
    MissingPatameter(String),
    NotValidUri(String),
    Request(reqwest::Error),
    InvalidCodeResponse(serde_html_form::de::Error),
    InvalidTokenResponse(serde_json::Error),
    InvalidResponse(String),
    CacheError(String),
    TokenRefreshFailed(String),
    // HTTP Status Code specific errors
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    NotFound(String),
    TooManyRequests(String),
    InternalServerError(String),
    BadGateway(String),
    ServiceUnavailable(String),
    UnknownStatusCode(u16, String),
    // Configuration errors
    AuthCacheNotConfigured,
    OAuthConfigNotConfigured,
    HttpClientNotConfigured,
    // Session and authentication errors
    SessionNotFound,
    SessionExpired,
    CacheAccessError(String),
    SessionUpdateFailed(String),
    TokenRefreshFailedAuth(String),
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        match self {
            Error::InvalidResponse(res) => {
                let message = format!("Invalid response {res}");
                (axum::http::StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
            }

            Error::MissingCodeVerifier => {
                let message = "Missing code verifier";
                (axum::http::StatusCode::BAD_REQUEST, message).into_response()
            }
            Error::MissingPatameter(param) => {
                let message = format!("Missing parameter: {param}");
                (axum::http::StatusCode::BAD_REQUEST, message).into_response()
            }
            Error::NotValidUri(uri) => {
                let message = format!("Not a valid URI: {uri}");
                (axum::http::StatusCode::BAD_REQUEST, message).into_response()
            }
            Error::Request(err) => {
                let message = format!("Reqwest error: {err}");
                (axum::http::StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
            }
            Error::InvalidCodeResponse(err) => {
                let message = format!("Invalid code response: {err}");
                (axum::http::StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
            }
            Error::InvalidTokenResponse(err) => {
                let message = format!("Invalid token response: {err}");
                (axum::http::StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
            }
            Error::CacheError(err) => {
                let message = format!("Cache error: {err}");
                (axum::http::StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
            }
            Error::TokenRefreshFailed(err) => {
                let message = format!("Token refresh failed: {err}");
                (axum::http::StatusCode::UNAUTHORIZED, message).into_response()
            }
            // HTTP Status Code specific errors
            Error::BadRequest(msg) => (axum::http::StatusCode::BAD_REQUEST, msg).into_response(),
            Error::Unauthorized(msg) => (axum::http::StatusCode::UNAUTHORIZED, msg).into_response(),
            Error::Forbidden(msg) => (axum::http::StatusCode::FORBIDDEN, msg).into_response(),
            Error::NotFound(msg) => (axum::http::StatusCode::NOT_FOUND, msg).into_response(),
            Error::TooManyRequests(msg) => {
                (axum::http::StatusCode::TOO_MANY_REQUESTS, msg).into_response()
            }
            Error::InternalServerError(msg) => {
                (axum::http::StatusCode::INTERNAL_SERVER_ERROR, msg).into_response()
            }
            Error::BadGateway(msg) => (axum::http::StatusCode::BAD_GATEWAY, msg).into_response(),
            Error::ServiceUnavailable(msg) => {
                (axum::http::StatusCode::SERVICE_UNAVAILABLE, msg).into_response()
            }
            Error::UnknownStatusCode(code, msg) => {
                let message = format!("HTTP {code}: {msg}");
                (axum::http::StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
            }
            // Configuration errors
            Error::AuthCacheNotConfigured => {
                let message = "AuthCache not configured. Make sure to add it to your app with Extension(cache).";
                (axum::http::StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
            }
            Error::OAuthConfigNotConfigured => {
                let message = "OAuthConfiguration not configured. Make sure to add it to your app with Extension(config).";
                (axum::http::StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
            }
            Error::HttpClientNotConfigured => {
                let message = "HTTP Client not configured. Make sure to use AuthLayer middleware.";
                (axum::http::StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
            }
            // Session and authentication errors
            Error::SessionNotFound => {
                let message = "No active session found. Please log in.";
                (axum::http::StatusCode::UNAUTHORIZED, message).into_response()
            }
            Error::SessionExpired => {
                let message = "Session expired or not found. Please log in again.";
                (axum::http::StatusCode::UNAUTHORIZED, message).into_response()
            }
            Error::CacheAccessError(msg) => {
                let message = format!("Cache error: {msg}");
                (axum::http::StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
            }
            Error::SessionUpdateFailed(msg) => {
                let message = format!("Failed to update session in cache: {msg}");
                (axum::http::StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
            }
            Error::TokenRefreshFailedAuth(msg) => {
                let message =
                    format!("Token expired and refresh failed. Please log in again: {msg}");
                (axum::http::StatusCode::UNAUTHORIZED, message).into_response()
            }
        }
    }
}

impl Error {
    /// Convert HTTP status code and response text to appropriate Error variant
    pub fn from_status_code(status: axum::http::StatusCode, response_text: String) -> Self {
        match status {
            axum::http::StatusCode::BAD_REQUEST => Error::BadRequest(response_text),
            axum::http::StatusCode::UNAUTHORIZED => Error::Unauthorized(response_text),
            axum::http::StatusCode::FORBIDDEN => Error::Forbidden(response_text),
            axum::http::StatusCode::NOT_FOUND => Error::NotFound(response_text),
            axum::http::StatusCode::TOO_MANY_REQUESTS => Error::TooManyRequests(response_text),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR => {
                Error::InternalServerError(response_text)
            }
            axum::http::StatusCode::BAD_GATEWAY => Error::BadGateway(response_text),
            axum::http::StatusCode::SERVICE_UNAVAILABLE => Error::ServiceUnavailable(response_text),
            _ => Error::UnknownStatusCode(status.as_u16(), response_text),
        }
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Error::Request(err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::InvalidTokenResponse(err)
    }
}

impl From<serde_html_form::de::Error> for Error {
    fn from(err: serde_html_form::de::Error) -> Self {
        Error::InvalidCodeResponse(err)
    }
}

#[cfg(feature = "redis")]
impl From<RedisError> for Error {
    fn from(err: RedisError) -> Self {
        Error::CacheError(err.to_string())
    }
}
