use axum::response::{Html, IntoResponse, Response};
use axum_extra::extract::{PrivateCookieJar, cookie::Cookie};

use http::{StatusCode, Uri, request::Parts};
use reqwest::{self, Client};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use time::Duration;
use uuid::Uuid;

use crate::{
    authentication::{
        cache::AuthCache,
        session::AuthSession,
        {OAuthConfiguration, SESSION_KEY},
    },
    errors::Error,
};

#[derive(Debug, Deserialize, PartialEq)]
struct CodeExchange {
    code: String,
    state: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct AccessTokenResponse {
    pub id_token: String,
    pub access_token: String,
    pub token_type: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expires_in: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub scope: Option<String>,
}

async fn get_auth_tokens(
    configuration: Arc<OAuthConfiguration>,
    cache: Arc<dyn AuthCache + Send + Sync>,
    client: Arc<Client>,
    uri: &Uri,
) -> Result<(AccessTokenResponse, Option<String>), Error> {
    let querystring = uri.query();
    let query = querystring
        .map(|qs| serde_html_form::from_str::<CodeExchange>(qs).map_err(Error::InvalidCodeResponse))
        .ok_or(Error::MissingPatameter("code".to_owned()))
        .flatten()?;

    // Split the state into the cache key (UUID) and optional post-login redirect path.
    // Format: "<uuid>" or "<uuid>|<path>".
    let (state_key, post_login_redirect) = if let Some((key, path)) = query.state.split_once('|') {
        (key.to_string(), Some(path.to_string()))
    } else {
        (query.state.clone(), None)
    };

    let OAuthConfiguration {
        redirect_uri,
        client_id,
        token_endpoint,
        client_secret,
        token_request_redirect_uri,
        ..
    } = configuration.as_ref();

    let verifier = cache
        .get_code_verifier(&state_key)
        .await?
        .ok_or(Error::MissingCodeVerifier)?;

    // Invalidate immediately after retrieval — the verifier is single-use.
    // This runs before the token exchange so that a network error or a
    // rejected exchange cannot be retried with the same verifier.
    cache.invalidate_code_verifier(&state_key).await?;

    let mut params: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", &query.code),
        ("client_id", client_id),
        ("code_verifier", &verifier),
    ];
    if *token_request_redirect_uri {
        params.push(("redirect_uri", redirect_uri));
    }

    let url = reqwest::Url::parse(token_endpoint)
        .map_err(|_| Error::NotValidUri(token_endpoint.to_string()))?;

    let res = client
        .post(url)
        .form(&params)
        .basic_auth(
            client_id,
            if client_secret.is_empty() {
                None
            } else {
                Some(client_secret.to_string())
            },
        )
        .send()
        .await?;

    match res.status() {
        StatusCode::OK => {
            let auth_session = res.json::<AccessTokenResponse>().await?;

            Ok((auth_session, post_login_redirect))
        }
        status => {
            let err = res.text().await?;
            Err(Error::from_status_code(status, err))
        }
    }
}

pub async fn handle_callback(parts: &mut Parts, uri: Uri) -> Result<Response, Error> {
    let configuration = parts
        .extensions
        .get::<Arc<OAuthConfiguration>>()
        .cloned()
        .ok_or_else(|| Error::CacheAccessError("OAuthConfiguration not configured".to_string()))?;

    let cache = parts
        .extensions
        .get::<Arc<dyn AuthCache + Send + Sync>>()
        .cloned()
        .ok_or_else(|| Error::CacheAccessError("AuthCache not configured".to_string()))?;

    let client = parts
        .extensions
        .get::<Arc<Client>>()
        .cloned()
        .ok_or_else(|| Error::CacheAccessError("HTTP Client not configured".to_string()))?;

    let OAuthConfiguration {
        private_cookie_key, ..
    } = configuration.as_ref();

    let jar = PrivateCookieJar::from_headers(&parts.headers, private_cookie_key.to_owned());

    let id = Uuid::new_v4().to_string();

    let (token_response, post_login_redirect) =
        get_auth_tokens(configuration.clone(), cache.clone(), client.clone(), &uri).await?;

    cache
        .set_auth_session(&id, AuthSession::new(&token_response, &configuration))
        .await?;

    let jar = jar.add(
        Cookie::build((SESSION_KEY, id.clone()))
            .path("/")
            .http_only(true)
            .same_site(axum_extra::extract::cookie::SameSite::Strict)
            .secure(true)
            .max_age(Duration::minutes(60)),
    );

    // Belt-and-suspenders validation: re-check the redirect path even though
    // handle_auth already validated it before embedding it in the state.  The
    // provider echoes the state back verbatim, but a defensive check here
    // prevents any open-redirect if the state were somehow tampered with.
    let redirect_to = match post_login_redirect {
        Some(path) if path.starts_with('/') && !path.starts_with("//") => path,
        _ => "/".to_string(),
    };

    Ok((
        jar,
        Html(format!(
            r#"<head><meta http-equiv="Refresh" content="0; URL={redirect_to}" /></head>"#
        )),
    )
        .into_response())
}
