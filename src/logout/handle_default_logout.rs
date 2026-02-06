use crate::{
    auth::{LogoutHandler, OAuthConfiguration, SESSION_KEY},
    auth_cache::AuthCache,
    errors::Error,
};
use axum::response::{Html, IntoResponse, Response};
use axum_extra::extract::{cookie::Cookie, PrivateCookieJar};
use futures_util::future::BoxFuture;
use http::request::Parts;
use std::sync::Arc;

/// Default logout handler implementation
#[derive(Clone)]
pub struct DefaultLogoutHandler;

impl LogoutHandler for DefaultLogoutHandler {
    fn handle_logout<'a>(
        &'a self,
        parts: &'a mut Parts,
        configuration: Arc<OAuthConfiguration>,
        cache: Arc<dyn AuthCache + Send + Sync>,
    ) -> BoxFuture<'a, Result<Response, Error>> {
        Box::pin(async move {
            let jar = PrivateCookieJar::from_headers(
                &parts.headers,
                configuration.private_cookie_key.to_owned(),
            );

            // Get session ID from cookie
            if let Some(session_cookie) = jar.get(SESSION_KEY) {
                let session_id = session_cookie.value();

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

            Ok((
                jar,
                Html(format!(
                    "
        <head>
          <meta http-equiv=\"Refresh\" content=\"0; URL={}\" />
        </head>",
                    &configuration.post_logout_redirect_uri
                )),
            )
                .into_response())
        })
    }
}
