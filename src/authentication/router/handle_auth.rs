use axum::response::{IntoResponse, Redirect, Response};
use pkce_std::{Challenge, Code, Length, Method};
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    authentication::{OAuthConfiguration, cache::AuthCache},
    errors::Error,
};

fn create_auth_request(
    configuration: &OAuthConfiguration,
    code_challenge: &Challenge,
    state: &str,
) -> Result<String, Error> {
    let OAuthConfiguration {
        client_id,
        redirect_uri,
        authorization_endpoint,
        scopes,
        code_challenge_method,
        ..
    } = configuration;

    let params = [
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("access_type", "offline"),
        ("prompt", "consent"),
        ("state", state),
        ("scope", scopes),
        ("code_challenge", &code_challenge.to_string()),
        ("code_challenge_method", &format!("{code_challenge_method}")),
    ];

    let url = reqwest::Url::parse_with_params(authorization_endpoint, &params)
        .map_err(|_| Error::NotValidUri(authorization_endpoint.to_string()))?;
    Ok(url.to_string())
}

pub async fn handle_auth(
    configuration: Arc<OAuthConfiguration>,
    cache: Arc<dyn AuthCache + Send + Sync>,
    post_login_redirect: Option<String>,
) -> Result<Response, Error> {
    let code_challenge_method: Method = configuration.code_challenge_method.to_owned().into();
    let (code_verifier, code_challenge) =
        Code::generate_using(code_challenge_method, Length::MAX).into_pair();

    let verifier = code_verifier.get().to_string();
    let state = Uuid::new_v4().to_string();

    // Encode a safe redirect path into the state so the callback can recover it
    // after the provider round-trip.  The `|` separator never appears in a UUID
    // or a valid relative path, making splitting unambiguous.
    //
    // Security: only relative paths that start with `/` (but not `//`, which
    // would be treated as a protocol-relative URL) are accepted.  Anything else
    // is silently dropped in favour of the default `/` redirect.
    let state_with_redirect = match post_login_redirect {
        Some(path) if path.starts_with('/') && !path.starts_with("//") => {
            format!("{}|{}", state, path)
        }
        _ => state.clone(),
    };

    cache.set_code_verifier(&state, &verifier).await?;
    let url = create_auth_request(&configuration, &code_challenge, &state_with_redirect)?;

    Ok(Redirect::temporary(&url).into_response())
}
