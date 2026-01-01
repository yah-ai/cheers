//! Identity providers — OIDC (P5), Apple (P6), passkey (P7), LAN-pair (P10).
//!
//! Each leaf module is gated behind the feature that owns its dependencies.
//! [`oidc_generic`] ships the generic OIDC Authorization Code + PKCE
//! consumer; concrete providers (Google, Apple, …) layer on top.

#[cfg(feature = "apple")]
pub mod apple;
#[cfg(feature = "google")]
pub mod google;
// `oidc_generic` is the shared core that both `google` and `apple` build on —
// its types (`OidcFlowStore`, `OidcFlowState`, `VerifiedIdToken`, errors) are
// re-used as-is by `apple::redirect`, so the gate is the union of the
// providers that need it.
#[cfg(any(feature = "google", feature = "apple"))]
pub mod oidc_generic;
