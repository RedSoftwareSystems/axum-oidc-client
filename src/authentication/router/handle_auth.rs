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
        audience,
        prompt_consent,
        ..
    } = configuration;

    let code_challenge = code_challenge.to_string();
    let code_challenge_method = format!("{code_challenge_method}");
    let mut params = vec![
        ("response_type", "code"),
        ("client_id", client_id.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("access_type", "offline"),
        ("state", state),
        ("scope", scopes.as_str()),
        ("code_challenge", code_challenge.as_str()),
        ("code_challenge_method", code_challenge_method.as_str()),
    ];

    // Only force a consent re-prompt when explicitly configured; otherwise omit
    // `prompt` so the provider can silently reuse an existing SSO session.
    if *prompt_consent {
        params.push(("prompt", "consent"));
    }

    if let Some(audience) = audience {
        params.push(("audience", audience.as_str()));
    }

    let url = reqwest::Url::parse_with_params(authorization_endpoint, params)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authentication::router::test_helpers::create_test_config;

    #[test]
    fn create_auth_request_includes_audience_when_configured() {
        let mut configuration = create_test_config();
        configuration.audience = Some("https://api.example.com".to_string());
        let method: Method = configuration.code_challenge_method.to_owned().into();
        let (_, code_challenge) = Code::generate_using(method, Length::MAX).into_pair();

        let url = create_auth_request(&configuration, &code_challenge, "test-state")
            .expect("auth URL should be valid");
        let url = reqwest::Url::parse(&url).expect("auth URL should parse");
        let audience = url
            .query_pairs()
            .find_map(|(key, value)| (key == "audience").then_some(value.into_owned()));

        assert_eq!(audience.as_deref(), Some("https://api.example.com"));
    }

    fn prompt_param(url: &str) -> Option<String> {
        let url = reqwest::Url::parse(url).expect("auth URL should parse");
        url.query_pairs()
            .find_map(|(key, value)| (key == "prompt").then_some(value.into_owned()))
    }

    #[test]
    fn create_auth_request_omits_prompt_by_default() {
        let configuration = create_test_config();
        let method: Method = configuration.code_challenge_method.to_owned().into();
        let (_, code_challenge) = Code::generate_using(method, Length::MAX).into_pair();

        let url = create_auth_request(&configuration, &code_challenge, "test-state")
            .expect("auth URL should be valid");

        assert_eq!(prompt_param(&url), None);
        assert!(url.contains("access_type=offline"));
    }

    #[test]
    fn create_auth_request_includes_prompt_when_enabled() {
        let mut configuration = create_test_config();
        configuration.prompt_consent = true;
        let method: Method = configuration.code_challenge_method.to_owned().into();
        let (_, code_challenge) = Code::generate_using(method, Length::MAX).into_pair();

        let url = create_auth_request(&configuration, &code_challenge, "test-state")
            .expect("auth URL should be valid");

        assert_eq!(prompt_param(&url).as_deref(), Some("consent"));
        assert!(url.contains("access_type=offline"));
    }
}
