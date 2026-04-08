pub mod configuration;
pub mod jwt_decoder;
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

pub use configuration::{Jwk, Jwks, JwtConfiguration, JwtConfigurationBuilder};

// ── Re-exports from layer ─────────────────────────────────────────────────────

pub use layer::{JwtLayer, JwtMiddleware};
