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
//! Alongside the verifier, [`McpAuthState`] also carries the trust context
//! `verify_mcp_at` / [`authenticate_mcp`] check a bearer against:
//! `expected_kid` (which published key this surface trusts — R592-B7's
//! kid-in-footer requirement) and `expected_iss` / `expected_aud` (which
//! cheers issuer + which resource identity a token must be minted for).
//! Mirrors `cloud-admin`'s `CheersAuth`
//! (`crates/yah/cloud-admin/src/auth.rs`) — a cryptographically valid MCP
//! token minted for a DIFFERENT resource by the SAME issuer key must still
//! be rejected before scope is even consulted.
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
//! let state = Arc::new(McpAuthState::new(
//!     verifier,
//!     "platform-kid-1",
//!     "https://cheers.example",
//!     "https://cheers.example",
//! ));
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
///
/// `expected_kid` / `expected_iss` / `expected_aud` are the trust context
/// [`authenticate_mcp`] validates every verified token against — same shape
/// as `cloud-admin`'s `CheersAuth` (`crates/yah/cloud-admin/src/auth.rs`):
/// `expected_kid` selects which published key this surface trusts (R592-B7),
/// `expected_iss`/`expected_aud` reject a cryptographically valid token
/// minted for a different issuer or a different resource by the same issuer
/// key.
#[derive(Clone)]
pub struct McpAuthState {
    pub verifier: Arc<PasetoV4PublicVerifier>,
    pub expected_kid: String,
    pub expected_iss: String,
    pub expected_aud: String,
}

impl McpAuthState {
    pub fn new(
        verifier: PasetoV4PublicVerifier,
        expected_kid: impl Into<String>,
        expected_iss: impl Into<String>,
        expected_aud: impl Into<String>,
    ) -> Self {
        Self {
            verifier: Arc::new(verifier),
            expected_kid: expected_kid.into(),
            expected_iss: expected_iss.into(),
            expected_aud: expected_aud.into(),
        }
    }
}

impl std::fmt::Debug for McpAuthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpAuthState")
            .field("expected_kid", &self.expected_kid)
            .field("expected_iss", &self.expected_iss)
            .field("expected_aud", &self.expected_aud)
            .finish_non_exhaustive()
    }
}

/// Pull the bearer header, run [`PasetoV4PublicVerifier::verify_mcp_at`] over
/// the token at `now` against `state.expected_kid`, then check the verified
/// claims' `iss`/`aud` against `state.expected_iss`/`state.expected_aud`
/// BEFORE returning — a token minted by a different issuer, or minted for a
/// different audience by the SAME issuer key, is rejected here, before any
/// handler consults scope (mirrors `cloud-admin`'s
/// `viewer_from_claims`). Maps verification and iss/aud failures alike to
/// [`RouteError::Unauthorized`] (401) — bad signature / expired / malformed /
/// wrong-kid / wrong-iss / wrong-aud all collapse, by design, so a probe
/// can't distinguish them.
pub fn authenticate_mcp(
    headers: &HeaderMap,
    state: &McpAuthState,
    now: i64,
) -> Result<McpClaims, RouteError> {
    let token = bearer_from_headers(headers)?;
    let claims = state
        .verifier
        .verify_mcp_at(token, now, &state.expected_kid)
        .map_err(|_| RouteError::Unauthorized)?;
    if claims.iss != state.expected_iss || claims.aud != state.expected_aud {
        return Err(RouteError::Unauthorized);
    }
    Ok(claims)
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

    /// `kid` / `iss` / `aud` [`rig`] wires into its [`McpAuthState`] — tests
    /// that mint a token expecting acceptance must match these; tests
    /// exercising the R592-B8-style kid/iss/aud rejection deliberately mint
    /// against a DIFFERENT value than one of these.
    const TEST_KID: &str = "mcp-test-kid-1";
    const TEST_ISS: &str = "https://cheers.example";
    const TEST_AUD: &str = "https://kamaji.example";

    fn rig() -> (PasetoV4SecretMinter, McpAuthState) {
        let (minter, verifier) = PasetoV4SecretMinter::generate().unwrap();
        let state = McpAuthState::new(verifier, TEST_KID, TEST_ISS, TEST_AUD);
        (minter, state)
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
            TEST_ISS,
            TEST_AUD,
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
        let (minter, state) = rig();
        let claims = sample_claims("jti-1");
        let token = minter.mint_mcp(&claims, TEST_KID).unwrap();
        let headers = bearer(&token);
        let back = authenticate_mcp(&headers, &state, 1_100).unwrap();
        assert_eq!(back, claims);
    }

    #[test]
    fn authenticate_mcp_rejects_expired_as_unauthorized() {
        let (minter, state) = rig();
        let claims = sample_claims("jti-exp");
        let token = minter.mint_mcp(&claims, TEST_KID).unwrap();
        // now == exp → expired.
        let err = authenticate_mcp(&bearer(&token), &state, 1_600).unwrap_err();
        assert!(matches!(err, RouteError::Unauthorized));
    }

    #[test]
    fn authenticate_mcp_rejects_bad_signature_as_unauthorized() {
        let (minter, _state) = rig();
        let (_other_minter, other_state) = rig();
        let token = minter.mint_mcp(&sample_claims("jti-bad"), TEST_KID).unwrap();
        // Verify under a different keypair's public verifier — signature
        // mismatch collapses to Unauthorized (same outcome as expiry from the
        // caller's POV, by design).
        let err = authenticate_mcp(&bearer(&token), &other_state, 1_100).unwrap_err();
        assert!(matches!(err, RouteError::Unauthorized));
    }

    #[test]
    fn authenticate_mcp_rejects_malformed_bearer() {
        let (_minter, state) = rig();
        let mut headers = HeaderMap::new();
        // Wrong scheme — bearer_from_headers reuse surfaces MalformedBearer.
        headers.insert(header::AUTHORIZATION, "Basic xyz".parse().unwrap());
        let err = authenticate_mcp(&headers, &state, 1_100).unwrap_err();
        assert!(matches!(err, RouteError::MalformedBearer));
    }

    #[test]
    fn authenticate_mcp_rejects_missing_bearer() {
        let (_minter, state) = rig();
        let err = authenticate_mcp(&HeaderMap::new(), &state, 1_100).unwrap_err();
        assert!(matches!(err, RouteError::MissingBearer));
    }

    #[test]
    fn authenticate_mcp_rejects_session_token_as_unauthorized() {
        // A session-shape token (with the "cheers" additional claim) hitting
        // the MCP verify path is structurally rejected — verify_mcp_at reads
        // the "mcp" key, which is absent. The two shapes can't be confused
        // even with valid signatures.
        use cheers_core::{Claims, DeviceBinding, DeviceId, TokenMinter, UserId};
        let (minter, state) = rig();
        let session_claims = Claims::new(
            UserId::new("alice"),
            DeviceId::new("dev"),
            DeviceBinding::Passkey,
            1_000,
            1_600,
        );
        let session_token = minter.mint(&session_claims).unwrap();
        let err = authenticate_mcp(&bearer(&session_token), &state, 1_100).unwrap_err();
        assert!(matches!(err, RouteError::Unauthorized));
    }

    // ---- authenticate_mcp: kid / iss / aud (R592-B7/B8 closure) ------------

    #[test]
    fn authenticate_mcp_rejects_wrong_kid_as_unauthorized() {
        // Correctly signed, correct iss/aud, but stamped with a kid the
        // state doesn't trust — R592-B7's key-selection check.
        let (minter, state) = rig();
        let token = minter
            .mint_mcp(&sample_claims("jti-wrong-kid"), "some-other-kid")
            .unwrap();
        let err = authenticate_mcp(&bearer(&token), &state, 1_100).unwrap_err();
        assert!(matches!(err, RouteError::Unauthorized));
    }

    #[test]
    fn authenticate_mcp_rejects_wrong_iss_as_unauthorized() {
        // Valid signature + kid + aud, but minted by a DIFFERENT issuer than
        // this state trusts — R592-B8 closure: a cryptographically valid MCP
        // token from an unrelated issuer must not be accepted just because
        // it happens to verify under the configured key.
        let (minter, state) = rig();
        let claims = McpClaims::new(
            "https://not-cheers.example",
            TEST_AUD,
            PrincipalId::user("alice"),
            1_000,
            1_600,
            "jti-wrong-iss",
            vec![Scope::CloudDeploy],
        )
        .with_auth_strength(AuthStrength::UserFresh);
        let token = minter.mint_mcp(&claims, TEST_KID).unwrap();
        let err = authenticate_mcp(&bearer(&token), &state, 1_100).unwrap_err();
        assert!(matches!(err, RouteError::Unauthorized));
    }

    #[test]
    fn authenticate_mcp_rejects_wrong_aud_as_unauthorized() {
        // Valid signature + kid + iss, but minted for a DIFFERENT audience —
        // the same-issuer-different-resource case R592-B8 closes: a token
        // scoped to some other resource must not authenticate here just
        // because the same cheers issuer signed it.
        let (minter, state) = rig();
        let claims = McpClaims::new(
            TEST_ISS,
            "https://unrelated-resource.example",
            PrincipalId::user("alice"),
            1_000,
            1_600,
            "jti-wrong-aud",
            vec![Scope::CloudDeploy],
        )
        .with_auth_strength(AuthStrength::UserFresh);
        let token = minter.mint_mcp(&claims, TEST_KID).unwrap();
        let err = authenticate_mcp(&bearer(&token), &state, 1_100).unwrap_err();
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
