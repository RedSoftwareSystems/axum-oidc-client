#[cfg(feature = "server")]
pub mod configuration;
pub mod jwt_decoder;

#[cfg(feature = "server")]
pub mod layer;
pub mod oidc;

// ── Re-exports from oidc ──────────────────────────────────────────────────────

pub use oidc::OidcClaims;

// ── Re-exports from jwt_decoder ───────────────────────────────────────────────

pub use jwt_decoder::{
    Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation, decode_jwt,
    decode_jwt_unverified,
};

// ── Re-exports from configuration ─────────────────────────────────────────────
#[cfg(feature = "server")]
pub use configuration::{Jwk, Jwks, JwtConfiguration, JwtConfigurationBuilder};

// ── Re-exports from layer ─────────────────────────────────────────────────────
#[cfg(feature = "server")]
pub use layer::{JwtLayer, JwtMiddleware};
