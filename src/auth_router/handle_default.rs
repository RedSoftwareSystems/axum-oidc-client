use axum::response::{IntoResponse, Response};
use axum_extra::extract::{
    cookie::{Cookie, Key},
    PrivateCookieJar,
};
use futures_util::future::BoxFuture;
use time::Duration;

use crate::{
    auth::{OAuthConfiguration, SESSION_KEY},
    auth_cache::AuthCache,
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
    F: std::future::Future<Output = Result<Response, E>> + Send + 'static,
{
    let session_max_age = configuration.session_max_age;

    Box::pin(async move {
        let response = future.await?;

        let jar = match session_id {
            Some(id) => {
                if let Err(err) = cache.extend_auth_session(&id, session_max_age).await {
                    return Ok(err.into_response());
                }
                jar.add(
                    Cookie::build((SESSION_KEY, id))
                        .path("/")
                        .http_only(true)
                        .secure(true)
                        .same_site(axum_extra::extract::cookie::SameSite::Strict)
                        .max_age(Duration::minutes(session_max_age)),
                )
            }
            None => jar,
        };

        Ok((jar, response).into_response())
    })
}
