//! Standard OIDC/JWT claims type.
//!
//! # `aud` field — single string or array
//!
//! [RFC 7519 §4.1.3](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3) allows
//! `aud` to be either a single JSON string **or** a JSON array of strings.
//! Google (and some other providers) always emit a single string even though the
//! spec permits both forms.  The [`deserialize_aud`] helper handles both.
//!
//! This module owns [`OidcClaims`], the default claims struct used with
//! [`decode_jwt`](crate::jwt::decode_jwt) and [`JwtLayer`](crate::jwt::JwtLayer).
//! It covers the full set of registered claims from
//! [RFC 7519 §4.1](https://www.rfc-editor.org/rfc/rfc7519#section-4.1) plus the
//! most common OIDC ID-token claims defined in
//! [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#IDToken).
//!
//! Extra provider-specific claims are collected into [`OidcClaims::extra`] via
//! `#[serde(flatten)]` so that no information is silently discarded.
//!
//! For custom claims types, implement [`serde::de::DeserializeOwned`] on your
//! own struct and use it as the generic parameter `C` on
//! [`JwtConfiguration<C>`](crate::jwt::JwtConfiguration) and
//! [`JwtLayer<C>`](crate::jwt::JwtLayer).

use serde::{Deserialize, Deserializer, Serialize};

/// Standard OIDC/JWT claims.
///
/// Covers the full set of registered claims from
/// [RFC 7519 §4.1](https://www.rfc-editor.org/rfc/rfc7519#section-4.1) plus the
/// most common OIDC ID-token claims defined in
/// [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#IDToken).
///
/// Extra provider-specific claims are collected into [`extra`](Self::extra) via
/// `#[serde(flatten)]` so that no information is silently discarded.
///
/// # Examples
///
/// ```rust,no_run
/// use axum_oidc_client::jwt::{OidcClaims, decode_jwt, DecodingKey, Algorithm, Validation};
///
/// # fn example() -> Result<(), axum_oidc_client::errors::Error> {
/// let key = DecodingKey::from_secret(b"secret");
/// let validation = Validation::new(Algorithm::HS256);
/// let data = decode_jwt("eyJ...", &key, &validation)?;
///
/// let claims: &OidcClaims = &data.claims;
/// println!("sub={} iss={}", claims.sub, claims.iss);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OidcClaims {
    // ── RFC 7519 registered claims ────────────────────────────────────────────
    /// `sub` – Subject: identifier for the principal that is the subject of
    /// the JWT.
    pub sub: String,

    /// `iss` – Issuer: identifies the principal that issued the JWT.
    pub iss: String,

    /// `aud` – Audience: recipients that the JWT is intended for.
    ///
    /// Per [RFC 7519 §4.1.3](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3)
    /// this can be either a single JSON string **or** a JSON array of strings.
    /// Google and several other providers emit a bare string; the custom
    /// deserialiser [`deserialize_aud`] normalises both forms into a `Vec`.
    #[serde(deserialize_with = "deserialize_aud")]
    pub aud: Vec<String>,

    /// `exp` – Expiration time (seconds since Unix epoch).
    pub exp: u64,

    /// `iat` – Issued-at time (seconds since Unix epoch).
    pub iat: u64,

    /// `nbf` – Not-before time (optional, seconds since Unix epoch).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub nbf: Option<u64>,

    /// `jti` – JWT ID: unique identifier for this token (optional).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub jti: Option<String>,

    // ── OIDC ID-token claims ──────────────────────────────────────────────────
    /// `nonce` – Value used to associate a client session with an ID token and
    /// to mitigate replay attacks (optional).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub nonce: Option<String>,

    /// `azp` – Authorised party: client ID of the party to which the ID token
    /// was issued (optional).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub azp: Option<String>,

    /// `at_hash` – Access token hash (optional).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub at_hash: Option<String>,

    /// `c_hash` – Code hash (optional).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub c_hash: Option<String>,

    /// `auth_time` – Time when the end-user authentication occurred (optional,
    /// seconds since Unix epoch).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub auth_time: Option<u64>,

    // ── Common profile / email claims ─────────────────────────────────────────
    /// `email` – End-user's preferred e-mail address (optional).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub email: Option<String>,

    /// `email_verified` – `true` if the provider has verified the email
    /// address (optional).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub email_verified: Option<bool>,

    /// `name` – End-user's full name (optional).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,

    /// `given_name` – Given name(s) or first name(s) (optional).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub given_name: Option<String>,

    /// `family_name` – Surname(s) or last name(s) (optional).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub family_name: Option<String>,

    /// `picture` – URL of the end-user's profile picture (optional).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub picture: Option<String>,

    /// `locale` – End-user's locale, e.g. `"en-US"` (optional).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub locale: Option<String>,

    /// `zoneinfo` – End-user's time zone, e.g. `"Europe/Paris"` (optional).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub zoneinfo: Option<String>,

    /// Any additional provider-specific claims not covered by the fields above.
    ///
    /// Captured via `#[serde(flatten)]` so deserialisation never silently
    /// drops unknown fields.
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Deserialise the `aud` claim from either a single JSON string or a JSON
/// array of strings into a `Vec<String>`.
///
/// [RFC 7519 §4.1.3](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3)
/// states that `aud` *"can be a single case-sensitive string containing a
/// StringOrURI value, or, if the JWT has multiple audiences, a JSON array"*.
/// Google always uses the single-string form; this deserialiser normalises
/// both representations so `OidcClaims` works with any conformant provider.
fn deserialize_aud<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::{self, SeqAccess, Visitor};
    use std::fmt;

    struct AudVisitor;

    impl<'de> Visitor<'de> for AudVisitor {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a string or an array of strings")
        }

        // Single-string form — e.g. Google: "aud": "client-id"
        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(vec![v.to_owned()])
        }

        fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
            Ok(vec![v])
        }

        // Array form — e.g. Keycloak: "aud": ["account", "client-id"]
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut values = Vec::with_capacity(seq.size_hint().unwrap_or(1));
            while let Some(v) = seq.next_element::<String>()? {
                values.push(v);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_any(AudVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_claims_json(aud: serde_json::Value) -> String {
        serde_json::json!({
            "sub":  "user-123",
            "iss":  "https://accounts.google.com",
            "aud":  aud,
            "exp":  9999999999u64,
            "iat":  1700000000u64
        })
        .to_string()
    }

    #[test]
    fn test_aud_single_string() {
        let json = make_claims_json(serde_json::json!("client-id-abc"));
        let claims: OidcClaims = serde_json::from_str(&json).expect("should deserialise");
        assert_eq!(claims.aud, vec!["client-id-abc"]);
    }

    #[test]
    fn test_aud_array_of_strings() {
        let json = make_claims_json(serde_json::json!(["account", "client-id-abc"]));
        let claims: OidcClaims = serde_json::from_str(&json).expect("should deserialise");
        assert_eq!(claims.aud, vec!["account", "client-id-abc"]);
    }

    #[test]
    fn test_aud_array_single_element() {
        let json = make_claims_json(serde_json::json!(["only-one"]));
        let claims: OidcClaims = serde_json::from_str(&json).expect("should deserialise");
        assert_eq!(claims.aud, vec!["only-one"]);
    }

    #[test]
    fn test_aud_google_real_world_shape() {
        // Google emits a bare string that matches the client ID exactly.
        let client_id = "729554681507-78l426haerr5kd1sbmpugn6ju3a5tem3.apps.googleusercontent.com";
        let json = make_claims_json(serde_json::json!(client_id));
        let claims: OidcClaims = serde_json::from_str(&json).expect("should deserialise");
        assert_eq!(claims.aud, vec![client_id]);
    }

    #[test]
    fn test_extra_claims_preserved() {
        let json = serde_json::json!({
            "sub":  "u1",
            "iss":  "https://example.com",
            "aud":  "c1",
            "exp":  9999999999u64,
            "iat":  1700000000u64,
            "hd":   "example.com",
            "email": "user@example.com"
        })
        .to_string();
        let claims: OidcClaims = serde_json::from_str(&json).expect("should deserialise");
        assert_eq!(claims.email.as_deref(), Some("user@example.com"));
        // "hd" is not a named field — should land in extra
        assert!(claims.extra.contains_key("hd"), "hd should be in extra");
    }

    #[test]
    fn test_aud_invalid_type_returns_error() {
        // A number is not a valid aud value.
        let json = make_claims_json(serde_json::json!(42));
        let result = serde_json::from_str::<OidcClaims>(&json);
        assert!(result.is_err(), "numeric aud should fail deserialisation");
    }
}
