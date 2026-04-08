//! JWT decoding and validation implementation.
//!
//! Contains [`decode_jwt`] and [`decode_jwt_unverified`].
//! [`OidcClaims`] lives in [`crate::jwt::oidc`] and is re-exported here for convenience.
//! All public items are re-exported from the parent [`crate::jwt`] module.

// ── Re-exports ────────────────────────────────────────────────────────────────

/// Re-export of [`jsonwebtoken::Algorithm`].
pub use jsonwebtoken::Algorithm;

/// Re-export of [`jsonwebtoken::DecodingKey`].
pub use jsonwebtoken::DecodingKey;

/// Re-export of [`jsonwebtoken::EncodingKey`].
pub use jsonwebtoken::EncodingKey;

/// Re-export of [`jsonwebtoken::Header`].
pub use jsonwebtoken::Header;

/// Re-export of [`jsonwebtoken::TokenData`].
pub use jsonwebtoken::TokenData;

/// Re-export of [`jsonwebtoken::Validation`].
pub use jsonwebtoken::Validation;

// ── Standard OIDC claims ──────────────────────────────────────────────────────

pub use crate::jwt::oidc::OidcClaims;

// ── decode_jwt ────────────────────────────────────────────────────────────────

use crate::errors::Error;

/// Decode and validate a compact JWT string, returning the header and
/// [`OidcClaims`] on success.
///
/// This is a thin wrapper around [`jsonwebtoken::decode`] that maps
/// `jsonwebtoken::errors::Error` to [`Error::InvalidResponse`] so callers
/// stay within the crate's error type.
///
/// # Arguments
///
/// * `token` – The compact JWT string (`header.payload.signature`).
/// * `key` – The [`DecodingKey`] to verify the signature with.
/// * `validation` – A [`Validation`] instance specifying the algorithm,
///   expected audience, issuer checks, etc.
///
/// # Errors
///
/// Returns [`Error::InvalidResponse`] when:
/// - The token is malformed or cannot be base64-decoded.
/// - The signature does not verify against `key`.
/// - Any enabled validation check fails (`exp`, `nbf`, `aud`, `iss`).
/// - The claims JSON cannot be deserialised into [`OidcClaims`].
///
/// # Examples
///
/// ```rust,no_run
/// use axum_oidc_client::jwt::{decode_jwt, DecodingKey, Algorithm, Validation};
///
/// # fn example() -> Result<(), axum_oidc_client::errors::Error> {
/// let key = DecodingKey::from_secret(b"my-secret");
/// let mut validation = Validation::new(Algorithm::HS256);
/// // Disable audience check for this example.
/// validation.validate_aud = false;
///
/// let token_data = decode_jwt("eyJ...", &key, &validation)?;
/// println!("sub: {}", token_data.claims.sub);
/// # Ok(())
/// # }
/// ```
pub fn decode_jwt(
    token: &str,
    key: &DecodingKey,
    validation: &Validation,
) -> Result<TokenData<OidcClaims>, Error> {
    jsonwebtoken::decode::<OidcClaims>(token, key, validation)
        .map_err(|e| Error::InvalidResponse(format!("JWT validation failed: {e}")))
}

// ── decode_jwt_unverified ─────────────────────────────────────────────────────

/// Decode a JWT's header and claims **without** verifying the signature.
///
/// # ⚠ Security warning
///
/// This function performs **no cryptographic verification**.  Use it only when
/// you need to inspect a token before you have the appropriate key available
/// (e.g. to read the `kid` header field and then look up the corresponding
/// JWK), or in tests.  Never trust the claims returned by this function for
/// authorization decisions.
///
/// # Errors
///
/// Returns [`Error::InvalidResponse`] if the token is malformed or the claims
/// cannot be deserialised.
///
/// # Examples
///
/// ```rust,no_run
/// use axum_oidc_client::jwt::decode_jwt_unverified;
///
/// # fn example() -> Result<(), axum_oidc_client::errors::Error> {
/// let (header, claims) = decode_jwt_unverified("eyJ...")?;
/// // Use header.kid to fetch the matching JWK, then call decode_jwt.
/// println!("kid: {:?}", header.kid);
/// # Ok(())
/// # }
/// ```
pub fn decode_jwt_unverified(token: &str) -> Result<(Header, OidcClaims), Error> {
    let header = jsonwebtoken::decode_header(token)
        .map_err(|e| Error::InvalidResponse(format!("JWT header decode failed: {e}")))?;

    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(Error::InvalidResponse(
            "JWT does not have three dot-separated parts".to_string(),
        ));
    }

    use base64::Engine as _;
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| Error::InvalidResponse(format!("JWT payload base64 decode failed: {e}")))?;

    let claims: OidcClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| Error::InvalidResponse(format!("JWT claims deserialisation failed: {e}")))?;

    Ok((header, claims))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn make_claims(sub: &str) -> OidcClaims {
        OidcClaims {
            sub: sub.to_string(),
            iss: "https://example.com".to_string(),
            aud: vec!["test-client".to_string()],
            exp: now_secs() + 3600,
            iat: now_secs(),
            nbf: None,
            jti: None,
            nonce: None,
            azp: None,
            at_hash: None,
            c_hash: None,
            auth_time: None,
            email: Some("user@example.com".to_string()),
            email_verified: Some(true),
            name: None,
            given_name: None,
            family_name: None,
            picture: None,
            locale: None,
            zoneinfo: None,
            extra: Default::default(),
        }
    }

    fn encode_hs256(claims: &OidcClaims, secret: &[u8]) -> String {
        let key = EncodingKey::from_secret(secret);
        jsonwebtoken::encode(&Header::default(), claims, &key).unwrap()
    }

    #[test]
    fn test_decode_jwt_valid_hs256() {
        let secret = b"test-secret-key";
        let claims = make_claims("user-123");
        let token = encode_hs256(&claims, secret);

        let key = DecodingKey::from_secret(secret);
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&["test-client"]);

        let result = decode_jwt(&token, &key, &validation);
        assert!(result.is_ok(), "valid token should decode successfully");

        let decoded = result.unwrap();
        assert_eq!(decoded.claims.sub, "user-123");
        assert_eq!(decoded.claims.email, Some("user@example.com".to_string()));
        assert_eq!(decoded.claims.email_verified, Some(true));
    }

    #[test]
    fn test_decode_jwt_wrong_secret() {
        let claims = make_claims("user-123");
        let token = encode_hs256(&claims, b"correct-secret");

        let key = DecodingKey::from_secret(b"wrong-secret");
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_aud = false;

        let result = decode_jwt(&token, &key, &validation);
        assert!(
            matches!(result, Err(Error::InvalidResponse(_))),
            "wrong secret should return InvalidResponse"
        );
    }

    #[test]
    fn test_decode_jwt_expired() {
        let mut claims = make_claims("user-123");
        // Set exp well in the past, beyond jsonwebtoken's default 60 s leeway.
        claims.exp = now_secs() - 120;

        let secret = b"test-secret-key";
        let token = encode_hs256(&claims, secret);

        let key = DecodingKey::from_secret(secret);
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_aud = false;

        let result = decode_jwt(&token, &key, &validation);
        assert!(
            matches!(result, Err(Error::InvalidResponse(_))),
            "expired token should return InvalidResponse"
        );
    }

    #[test]
    fn test_decode_jwt_wrong_audience() {
        let claims = make_claims("user-123");
        let secret = b"test-secret-key";
        let token = encode_hs256(&claims, secret);

        let key = DecodingKey::from_secret(secret);
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&["different-client"]);

        let result = decode_jwt(&token, &key, &validation);
        assert!(
            matches!(result, Err(Error::InvalidResponse(_))),
            "wrong audience should return InvalidResponse"
        );
    }

    #[test]
    fn test_decode_jwt_unverified_reads_claims() {
        let claims = make_claims("user-unverified");
        let token = encode_hs256(&claims, b"any-secret");

        let result = decode_jwt_unverified(&token);
        assert!(result.is_ok(), "unverified decode should succeed");

        let (_header, decoded_claims) = result.unwrap();
        assert_eq!(decoded_claims.sub, "user-unverified");
        assert_eq!(decoded_claims.iss, "https://example.com");
    }

    #[test]
    fn test_decode_jwt_unverified_reads_header() {
        let claims = make_claims("user-header");
        let token = encode_hs256(&claims, b"secret");

        let (header, _) = decode_jwt_unverified(&token).unwrap();
        assert_eq!(header.alg, Algorithm::HS256);
    }

    #[test]
    fn test_decode_jwt_malformed_token() {
        let result = decode_jwt_unverified("not.a.valid.jwt.at.all");
        assert!(
            matches!(result, Err(Error::InvalidResponse(_))),
            "malformed token should return InvalidResponse"
        );
    }

    #[test]
    fn test_oidc_claims_extra_fields_preserved() {
        let json = serde_json::json!({
            "sub": "user-extra",
            "iss": "https://example.com",
            "aud": ["client"],
            "exp": now_secs() + 3600,
            "iat": now_secs(),
            "custom_claim": "custom_value",
        });

        let claims: OidcClaims = serde_json::from_value(json).unwrap();
        assert_eq!(
            claims.extra.get("custom_claim").and_then(|v| v.as_str()),
            Some("custom_value"),
            "extra provider-specific claims should be preserved"
        );
    }
}
