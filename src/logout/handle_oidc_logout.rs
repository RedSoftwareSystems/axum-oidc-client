use axum::response::{Html, IntoResponse, Redirect, Response};
use axum_extra::extract::{cookie::Cookie, PrivateCookieJar};
use futures_util::future::BoxFuture;
use http::request::Parts;
use std::sync::Arc;
use urlencoding::encode;

use crate::{
    auth::{LogoutHandler, OAuthConfiguration, SESSION_KEY},
    auth_cache::AuthCache,
    errors::Error,
};

/// Default logout handler implementation
#[derive(Clone)]
pub struct OidcLogoutHandler {
    oidc_logout_endpoint: String,
}

impl OidcLogoutHandler {
    pub fn new(oidc_logout_endpoint: &str) -> Self {
        Self {
            oidc_logout_endpoint: oidc_logout_endpoint.to_string(),
        }
    }
}

impl LogoutHandler for OidcLogoutHandler {
    fn handle_logout<'a>(
        &'a self,
        parts: &'a mut Parts,
        configuration: Arc<OAuthConfiguration>,
        cache: Arc<dyn AuthCache + Send + Sync>,
    ) -> BoxFuture<'a, Result<Response, Error>> {
        Box::pin(async move {
            let OAuthConfiguration {
                private_cookie_key,
                post_logout_redirect_uri,
                ..
            } = configuration.as_ref();

            let jar = PrivateCookieJar::from_headers(&parts.headers, private_cookie_key.to_owned());

            let mut id_token: Option<String> = None;

            // Get session ID from cookie
            if let Some(session_cookie) = jar.get(SESSION_KEY) {
                let session_id = session_cookie.value();

                // Get the auth session to retrieve the ID token
                if let Ok(Some(auth_session)) = cache.get_auth_session(session_id).await {
                    id_token = Some(auth_session.id_token.clone());
                }

                // Invalidate the session in cache
                cache.invalidate_auth_session(session_id).await?;
            }

            // Remove the session cookie
            let jar = jar.remove(
                Cookie::build(SESSION_KEY)
                    .path("/")
                    .http_only(true)
                    .same_site(axum_extra::extract::cookie::SameSite::Strict)
                    .secure(true),
            );

            // If OIDC end session endpoint is configured, redirect there with id_token_hint
            if let Some(id_token_value) = id_token {
                let logout_url = format!(
                    "{}?id_token_hint={}&post_logout_redirect_uri={}",
                    self.oidc_logout_endpoint,
                    encode(&id_token_value),
                    encode(post_logout_redirect_uri)
                );

                return Ok((jar, Redirect::temporary(&logout_url)).into_response());
            }

            Ok((
                jar,
                Html(format!(
                    "
        <head>
          <meta http-equiv=\"Refresh\" content=\"0; URL={}\" />
        </head>",
                    post_logout_redirect_uri
                )),
            )
                .into_response())
        })
    }
}
