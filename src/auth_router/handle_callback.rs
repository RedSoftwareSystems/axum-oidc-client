use axum::response::{Html, IntoResponse, Response};
use axum_extra::extract::{cookie::Cookie, PrivateCookieJar};

use http::{request::Parts, StatusCode, Uri};
use reqwest::{self, Client};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use time::Duration;
use uuid::Uuid;

use crate::{
    auth::{OAuthConfiguration, SESSION_KEY},
    auth_cache::AuthCache,
    auth_session::AuthSession,
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
    pub expires_in: i64,
    pub refresh_token: String,
    pub scope: String,
}

async fn get_auth_tokens(
    configuration: Arc<OAuthConfiguration>,
    cache: Arc<dyn AuthCache + Send + Sync>,
    client: Arc<Client>,
    uri: &Uri,
) -> Result<AccessTokenResponse, Error> {
    let querystring = uri.query();
    let query = querystring
        .map(|qs| serde_html_form::from_str::<CodeExchange>(qs).map_err(Error::InvalidCodeResponse))
        .ok_or(Error::MissingPatameter("code".to_owned()))
        .flatten()?;

    let OAuthConfiguration {
        redirect_uri,
        client_id,
        token_endpoint,
        client_secret,
        ..
    } = configuration.as_ref();

    let verifier = cache
        .get_code_verifier(&query.state)
        .await?
        .ok_or(Error::MissingCodeVerifier)?;

    let params = [
        ("grant_type", "authorization_code"),
        ("code", &query.code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", &verifier),
    ];

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

            Ok(auth_session)
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

    let token_response =
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
    Ok((
        jar,
        Html(
            r#"
        <head>
          <meta http-equiv="Refresh" content="0; URL=/" />
        </head>"#,
        ),
    )
        .into_response())
}
