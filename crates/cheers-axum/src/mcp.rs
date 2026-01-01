//! Bearer-token authentication for MCP-call endpoints.
//!
//! Mirrors [`me::authenticate`](crate::me::authenticate) but verifies the
//! `v4.public` MCP-token shape (`McpClaims`) instead of the session-token
//! shape (`Claims`) — same PASETO envelope, distinct additional-claim key
//! (the structural guard that keeps the two shapes from being confused at
//! the verify edge, see
//! [`PasetoV4PublicVerifier::verify_mcp_at`](cheers_verify::PasetoV4PublicVerifier::verify_mcp_at)).
//!
//! ## State
//!
//! [`McpAuthState`] holds the concrete [`PasetoV4PublicVerifier`] for now.
//! The session-side [`MeAuthState`](crate::me::MeAuthState) is generic over a
//! [`TokenVerifier`](cheers_core::TokenVerifier) trait; the MCP path doesn't
//! have a peer trait yet (`verify_mcp_at` is an inherent method on the
//! verifier). When a `McpTokenVerifier` trait lands, this state shrinks to a
//! one-line generic-ification.
//!
//! ## Scope guard
//!
//! [`McpClaimsExt::require_scope`] is the per-handler authorization check
//! that runs after authentication: "the principal is who they say they are,
//! but does this token carry the scope I need?". Returns
//! [`RouteError::InsufficientScope`] (403) on miss — a 403 because the
//! principal IS authenticated, the request is just not authorized. Distinct
//! from the unauthenticated 401 that authentication failure surfaces.
//!
//! ## Wiring
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use cheers_axum::mcp::McpAuthState;
//! # use cheers_server::PasetoV4SecretMinter;
//! # let (_minter, verifier) = PasetoV4SecretMinter::generate().unwrap();
//! let state = Arc::new(McpAuthState::new(verifier));
//! // Hand `state` to a router that nests POST /ownership, /audit/ingest, etc.
//! ```

use std::sync::Arc;

use axum::http::HeaderMap;

use cheers_core::{McpClaims, Scope};
use cheers_server::PasetoV4PublicVerifier;

use crate::error::RouteError;
use crate::me::bearer_from_headers;

/// State held by MCP-token-authenticated handlers.
///
/// Holds the verify-only Ed25519 public key. There is no minter here — the
/// edge tier is verify-only by construction (same property the
/// [`EdgeVerifier`](cheers_server::EdgeVerifier) holds), so mounting this
/// router cannot mint MCP tokens.
#[derive(Clone)]
pub struct McpAuthState {
    pub verifier: Arc<PasetoV4PublicVerifier>,
}

impl McpAuthState {
    pub fn new(verifier: PasetoV4PublicVerifier) -> Self {
        Self {
            verifier: Arc::new(verifier),
        }
    }
}

impl std::fmt::Debug for McpAuthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpAuthState").finish_non_exhaustive()
    }
}

/// Pull the bearer header, run [`PasetoV4PublicVerifier::verify_mcp_at`] over
/// the token at `now`, and return the verified [`McpClaims`]. Maps
/// verification failures to [`RouteError::Unauthorized`] (401) — bad
/// signature / expired / malformed all collapse, by design, so a probe can't
/// distinguish them.
pub fn authenticate_mcp(
    headers: &HeaderMap,
    verifier: &PasetoV4PublicVerifier,
    now: i64,
) -> Result<McpClaims, RouteError> {
    let token = bearer_from_headers(headers)?;
    verifier
        .verify_mcp_at(token, now)
        .map_err(|_| RouteError::Unauthorized)
}

/// Scope-guard helper on [`McpClaims`].
///
/// Adds [`require_scope`](Self::require_scope) so handlers can write
/// `claims.require_scope(Scope::OwnershipWrite)?;` before any side-effect.
/// Lives on an extension trait because [`McpClaims`] is in `cheers-core`
/// and the rejection ([`RouteError`]) is in this crate — keeping the
/// dependency direction crate-core → crate-http intact.
pub trait McpClaimsExt {
    /// `Ok(())` iff the claims's scope list contains `required`; otherwise
    /// [`RouteError::InsufficientScope`].
    fn require_scope(&self, required: Scope) -> Result<(), RouteError>;
}

impl McpClaimsExt for McpClaims {
    fn require_scope(&self, required: Scope) -> Result<(), RouteError> {
        if self.scope.contains(&required) {
            Ok(())
        } else {
            Err(RouteError::InsufficientScope { required })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{header, HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use cheers_core::{AuthStrength, McpClaims, PrincipalId};
    use cheers_server::PasetoV4SecretMinter;

    fn rig() -> (PasetoV4SecretMinter, PasetoV4PublicVerifier) {
        PasetoV4SecretMinter::generate().unwrap()
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        h
    }

    fn sample_claims(jti: &str) -> McpClaims {
        McpClaims::new(
            "https://cheers.example",
            "https://constable.example",
            PrincipalId::user("alice"),
            1_000,
            1_600,
            jti,
            vec![Scope::CloudDeploy, Scope::CloudRead],
        )
        .with_auth_strength(AuthStrength::UserFresh)
    }

    // ---- authenticate_mcp --------------------------------------------------

    #[test]
    fn authenticate_mcp_verifies_valid_token_and_returns_claims() {
        let (minter, verifier) = rig();
        let claims = sample_claims("jti-1");
        let token = minter.mint_mcp(&claims).unwrap();
        let headers = bearer(&token);
        let back = authenticate_mcp(&headers, &verifier, 1_100).unwrap();
        assert_eq!(back, claims);
    }

    #[test]
    fn authenticate_mcp_rejects_expired_as_unauthorized() {
        let (minter, verifier) = rig();
        let claims = sample_claims("jti-exp");
        let token = minter.mint_mcp(&claims).unwrap();
        // now == exp → expired.
        let err = authenticate_mcp(&bearer(&token), &verifier, 1_600).unwrap_err();
        assert!(matches!(err, RouteError::Unauthorized));
    }

    #[test]
    fn authenticate_mcp_rejects_bad_signature_as_unauthorized() {
        let (minter, _verifier) = rig();
        let (_other_minter, other_verifier) = rig();
        let token = minter.mint_mcp(&sample_claims("jti-bad")).unwrap();
        // Verify under a different keypair's public verifier — signature
        // mismatch collapses to Unauthorized (same outcome as expiry from the
        // caller's POV, by design).
        let err = authenticate_mcp(&bearer(&token), &other_verifier, 1_100).unwrap_err();
        assert!(matches!(err, RouteError::Unauthorized));
    }

    #[test]
    fn authenticate_mcp_rejects_malformed_bearer() {
        let (_minter, verifier) = rig();
        let mut headers = HeaderMap::new();
        // Wrong scheme — bearer_from_headers reuse surfaces MalformedBearer.
        headers.insert(header::AUTHORIZATION, "Basic xyz".parse().unwrap());
        let err = authenticate_mcp(&headers, &verifier, 1_100).unwrap_err();
        assert!(matches!(err, RouteError::MalformedBearer));
    }

    #[test]
    fn authenticate_mcp_rejects_missing_bearer() {
        let (_minter, verifier) = rig();
        let err = authenticate_mcp(&HeaderMap::new(), &verifier, 1_100).unwrap_err();
        assert!(matches!(err, RouteError::MissingBearer));
    }

    #[test]
    fn authenticate_mcp_rejects_session_token_as_unauthorized() {
        // A session-shape token (with the "cheers" additional claim) hitting
        // the MCP verify path is structurally rejected — verify_mcp_at reads
        // the "mcp" key, which is absent. The two shapes can't be confused
        // even with valid signatures.
        use cheers_core::{Claims, DeviceBinding, DeviceId, TokenMinter, UserId};
        let (minter, verifier) = rig();
        let session_claims = Claims::new(
            UserId::new("alice"),
            DeviceId::new("dev"),
            DeviceBinding::Passkey,
            1_000,
            1_600,
        );
        let session_token = minter.mint(&session_claims).unwrap();
        let err = authenticate_mcp(&bearer(&session_token), &verifier, 1_100).unwrap_err();
        assert!(matches!(err, RouteError::Unauthorized));
    }

    // ---- McpClaimsExt::require_scope ---------------------------------------

    #[test]
    fn require_scope_accepts_held_scope() {
        let claims = sample_claims("jti");
        // CloudDeploy is in the sample claims.
        claims.require_scope(Scope::CloudDeploy).unwrap();
        claims.require_scope(Scope::CloudRead).unwrap();
    }

    #[test]
    fn require_scope_rejects_missing_scope() {
        let claims = sample_claims("jti");
        let err = claims.require_scope(Scope::OwnershipWrite).unwrap_err();
        match err {
            RouteError::InsufficientScope { required } => {
                assert_eq!(required, Scope::OwnershipWrite);
            }
            other => panic!("expected InsufficientScope, got {other:?}"),
        }
    }

    #[test]
    fn insufficient_scope_responds_403_with_stable_code() {
        let err = RouteError::InsufficientScope {
            required: Scope::OwnershipWrite,
        };
        let (status, code) = err.status_and_code();
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(code, "insufficient_scope");
        // The IntoResponse path emits the same status.
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
