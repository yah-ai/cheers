//! Apple Sign In — ES256 `client_secret` (R013-T1), form-post redirect
//! callback (R013-T2), native iOS id-token verification (R013-T3), and the
//! JWKS cache that backs both verifiers (R013-T4).
//!
//! Each leaf is wired in as its sub-ticket lands; this `mod.rs` only ties
//! them together and re-exports the public surface.

pub mod client_secret;
pub mod jwks_cache;
pub mod native;
pub mod redirect;

pub use client_secret::{
    AppleClientSecret, ClientSecretError, APPLE_AUDIENCE, APPLE_MAX_TTL_SECONDS,
    DEFAULT_REFRESH_MARGIN_SECONDS, DEFAULT_TOKEN_TTL_SECONDS,
};
pub use jwks_cache::{
    AppleJwksCache, HttpJwksFetcher, JwksError, JwksFetcher, DEFAULT_REFRESH_AFTER_SECONDS,
};
pub use native::{AppleNativeError, AppleNativeVerifier};
pub use redirect::{
    apple_provider_metadata, AppleCallbackForm, AppleRedirectError, AppleRedirectProvider,
    AppleVerified, FirstLoginName, APPLE_AUTHORIZATION_ENDPOINT, APPLE_DEFAULT_SCOPES,
    APPLE_ISSUER, APPLE_JWKS_URI, APPLE_TOKEN_ENDPOINT,
};
