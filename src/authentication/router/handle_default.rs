use axum::response::{IntoResponse, Response};
use axum_extra::extract::{PrivateCookieJar, cookie::Key};
use futures_util::future::BoxFuture;
use time::Duration;

use crate::authentication::{
    OAuthConfiguration, SESSION_KEY, cache::AuthCache, cookies::build_session_cookie,
};

use std::sync::Arc;

pub fn handle_default<F, E>(
    configuration: Arc<OAuthConfiguration>,
    cache: Arc<dyn AuthCache + Send + Sync>,
    jar: PrivateCookieJar<Key>,
    session_id: Option<String>,
    future: F,
) -> BoxFuture<'static, Result<Response, E>>
where
    F: Future<Output = Result<Response, E>> + Send + 'static,
{
    Box::pin(async move {
        let response = future.await?;
        let session_max_age = Duration::minutes(configuration.session_max_age_minutes);
        let jar = match session_id {
            Some(id) => {
                // `AuthCache::extend_auth_session` takes its `ttl` in seconds
                // (it maps directly onto Redis `EXPIRE`, SQL `expires_at`,
                // and moka TTLs), while `session_max_age` is configured in
                // minutes — convert explicitly at this boundary.
                if let Err(err) = cache
                    .extend_auth_session(&id, session_max_age.whole_seconds())
                    .await
                {
                    return Ok(err.into_response());
                }
                // Renewal still extends the server-side session (above); the
                // cookie itself omits Max-Age in session-cookie mode so it stays
                // a browser-session cookie across renewals too.
                let cookie_max_age = if configuration.session_cookie {
                    None
                } else {
                    Some(session_max_age)
                };
                jar.add(build_session_cookie(
                    SESSION_KEY,
                    Some(id),
                    configuration.lax_same_site,
                    configuration.secure_cookies,
                    cookie_max_age,
                ))
            }
            None => jar,
        };

        Ok((jar, response).into_response())
    })
}
