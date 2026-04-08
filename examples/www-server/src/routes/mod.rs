//! Application route handlers module.
//!
//! This module contains all HTTP route handlers for the sample server.
//! Routes are organized by their purpose and access level.
//!
//! # Module Structure
//!
//! - [`health`]    - Public health-check endpoint (`GET /health`)
//! - [`home`]      - Public home page route, accessible to all users
//! - [`tokeninfo`] - Token info route requiring authentication
//! - [`resources`] - Resources page (JS fetch of API endpoints)
//! - [`api`]       - Nested `/api` reverse-proxy routes (authentication required)
//!
//! # Route Overview
//!
//! ## Public Routes
//!
//! - `GET /health` - Health-check endpoint (see [`health::health`])
//! - `GET /`       - Home page (see [`home::home`])
//! - `GET /home`   - Alternative home page path (see [`home::home`])
//!
//! ## Protected Routes
//!
//! - `GET /tokeninfo`  - Token info resource (see [`tokeninfo::tokeninfo`])
//! - `GET /resources`  - Resources page: JS fetch of `/api/me`, `/api/protected/resource1`,
//!                       `/api/protected/resource2` (see [`resources::resources`])
//!
//! ## API Reverse-Proxy Routes (nested under `/api`)
//!
//! All routes below require authentication.  The authenticated user's OIDC
//! **ID token** is forwarded to the upstream API server as
//! `Authorization: Bearer <id_token>`.
//!
//! | Route                          | Upstream target                    |
//! |--------------------------------|------------------------------------|
//! | `GET /api/me`                  | `{api_server}/me`                  |
//! | `GET /api/protected/resource1` | `{api_server}/protected/resource1` |
//! | `GET /api/protected/resource2` | `{api_server}/protected/resource2` |
//!
//! ## Automatic Routes
//!
//! The following routes are automatically added by the
//! [`axum_oidc_client::authentication::AuthLayer`]:
//!
//! - `GET /auth`                      - Initiates OAuth2 authorization flow
//! - `GET /auth/callback`             - OAuth2 callback endpoint
//! - `GET /auth/logout`               - Logout endpoint
//! - `GET /auth/logout?redirect=/path`- Logout with custom redirect
//!
//! # Authentication Flow
//!
//! 1. User visits a protected route
//! 2. If not authenticated, they are redirected to `/auth`
//! 3. User is redirected to the OAuth2 provider for authentication
//! 4. Provider redirects back to `/auth/callback` with authorization code
//! 5. Application exchanges code for tokens and creates a session
//! 6. User is redirected back to the originally requested route
//!
//! # Examples
//!
//! ## Adding a New Public Route
//!
//! ```rust,no_run
//! use axum::{Router, routing::get};
//!
//! async fn my_public_handler() -> &'static str {
//!     "This is public!"
//! }
//!
//! # fn example(app: Router) -> Router {
//! app.route("/public", get(my_public_handler))
//! # }
//! ```
//!
//! ## Adding a New Protected Route
//!
//! ```rust,no_run
//! use axum::{Router, routing::get};
//! use axum_oidc_client::auth_session::AuthSession;
//!
//! async fn my_protected_handler(session: AuthSession) -> String {
//!     format!("Hello, authenticated user!")
//! }
//!
//! # fn example(app: Router) -> Router {
//! app.route("/my-protected", get(my_protected_handler))
//! # }
//! ```
//!
//! The route will automatically require authentication when using the
//! [`AuthSession`](axum_oidc_client::auth_session::AuthSession) extractor.

pub mod api;
pub mod health;
pub mod home;
pub mod resources;
pub mod tokeninfo;
