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
//! [`McpAuthState`] holds a [`KeySetVerifier`] (R731-F6, §D5): the footer
//! `kid` selects a key from a key set and the key's role decides what it may
//! sign (issuer: anything; assertion: never here; self-signer: its own `sub`
//! within a cheers-issued ceiling). [`McpAuthState::new`] builds the static
//! one-issuer-key set an in-process cheers surface uses;
//! [`McpAuthState::from_key_set`] takes any verifier, e.g. one backed by a
//! live [`JwksCache`](cheers_verify::JwksCache).
//!
//! Alongside the verifier, [`McpAuthState`] carries `expected_iss` /
//! `expected_aud` (which cheers issuer + which resource identity a token must
//! be minted for).
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
use cheers_verify::KeySetVerifier;

use crate::error::RouteError;
use crate::me::bearer_from_headers;

/// State held by MCP-token-authenticated handlers.
///
/// Holds the verify-only Ed25519 public key. There is no minter here — the
/// edge tier is verify-only by construction (same property the
/// [`EdgeVerifier`](cheers_server::EdgeVerifier) holds), so mounting this
/// router cannot mint MCP tokens.
///
/// `expected_iss` / `expected_aud` are the trust context
/// [`authenticate_mcp`] validates every verified token against — same shape
/// as `cloud-admin`'s `CheersAuth` (`crates/yah/cloud-admin/src/auth.rs`):
/// key selection is the key set's (R592-B7 footer kid), and
/// `expected_iss`/`expected_aud` reject a cryptographically valid token
/// minted for a different issuer or a different resource by the same issuer
/// key.
#[derive(Clone)]
pub struct McpAuthState {
    pub verifier: Arc<KeySetVerifier>,
    pub expected_iss: String,
    pub expected_aud: String,
}

impl McpAuthState {
    /// Static key set: `verifier`'s key as the single issuer-role key under
    /// `kid`, owned by `expected_iss`.
    pub fn new(
        verifier: PasetoV4PublicVerifier,
        kid: impl Into<String>,
        expected_iss: impl Into<String>,
        expected_aud: impl Into<String>,
    ) -> Self {
        let expected_iss = expected_iss.into();
        let key: [u8; 32] = verifier
            .public_key()
            .as_bytes()
            .try_into()
            .expect("Ed25519 public key is 32 bytes");
        let keys = KeySetVerifier::from_issuer_key(kid, &key, expected_iss.clone());
        Self::from_key_set(keys, expected_iss, expected_aud)
    }

    /// Any key set — e.g. [`KeySetVerifier::from_cache`] over a remote JWKS.
    pub fn from_key_set(
        verifier: KeySetVerifier,
        expected_iss: impl Into<String>,
        expected_aud: impl Into<String>,
    ) -> Self {
        Self {
            verifier: Arc::new(verifier),
            expected_iss: expected_iss.into(),
            expected_aud: expected_aud.into(),
        }
    }
}

impl std::fmt::Debug for McpAuthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpAuthState")
            .field("expected_iss", &self.expected_iss)
            .field("expected_aud", &self.expected_aud)
            .finish_non_exhaustive()
    }
}

/// Pull the bearer header, verify the token at `now` against the state's key
/// set (kid lookup + role rules), then check the verified
/// claims' `iss`/`aud` against `state.expected_iss`/`state.expected_aud`
/// BEFORE returning — a token minted by a different issuer, or minted for a
/// different audience by the SAME issuer key, is rejected here, before any
/// handler consults scope (mirrors `cloud-admin`'s
/// `viewer_from_claims`). Maps verification and iss/aud failures alike to
/// [`RouteError::Unauthorized`] (401) — bad signature / expired / malformed /
/// wrong-kid / wrong-iss / wrong-aud all collapse, by design, so a probe
/// can't distinguish them.
pub async fn authenticate_mcp(
    headers: &HeaderMap,
    state: &McpAuthState,
    now: i64,
) -> Result<McpClaims, RouteError> {
    verify_mcp_bearer(
        headers,
        &state.verifier,
        &state.expected_iss,
        Some(state.expected_aud.as_str()),
        now,
    )
    .await
}

/// The body of [`authenticate_mcp`], with the audience policy lifted into a
/// parameter — one verification path, two postures, so a second admitting
/// surface cannot drift from this one.
///
/// `expected_aud: Some(a)` is the ordinary resource-server posture: a token
/// minted for a different `aud` by the same issuer key is rejected before any
/// handler consults scope.
///
/// `expected_aud: None` accepts a token minted for **any** audience, and is
/// only correct where the route grants no authority *at* an audience —
/// [`tokens`](crate::tokens)'s list / revoke / rotate, which read and remove
/// the caller's own credentials and can widen nobody (R728-F2). Do not reach
/// for it anywhere the handler acts on a resource.
///
/// Every failure — missing kid, unknown kid, key role refused, bad signature,
/// expired, wrong `iss`, wrong `aud` — collapses into [`RouteError::Unauthorized`], so a
/// probe cannot distinguish them.
pub async fn verify_mcp_bearer(
    headers: &HeaderMap,
    verifier: &KeySetVerifier,
    expected_iss: &str,
    expected_aud: Option<&str>,
    now: i64,
) -> Result<McpClaims, RouteError> {
    let token = bearer_from_headers(headers)?;
    verifier
        .verify_mcp(token, now, expected_iss, expected_aud)
        .await
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
    use cheers_core::yah_scopes;
    use axum::http::{header, HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use cheers_core::{AuthStrength, McpClaims, PrincipalId};
    use cheers_server::PasetoV4SecretMinter;

    /// Sync shim over the async [`super::authenticate_mcp`] for these tests.
    fn authenticate_mcp(h: &HeaderMap, s: &McpAuthState, now: i64) -> Result<McpClaims, RouteError> {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(super::authenticate_mcp(h, s, now))
    }

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
            vec![yah_scopes::CLOUD_DEPLOY, yah_scopes::CLOUD_READ],
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
            vec![yah_scopes::CLOUD_DEPLOY],
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
            vec![yah_scopes::CLOUD_DEPLOY],
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
        claims.require_scope(yah_scopes::CLOUD_DEPLOY).unwrap();
        claims.require_scope(yah_scopes::CLOUD_READ).unwrap();
    }

    #[test]
    fn require_scope_rejects_missing_scope() {
        let claims = sample_claims("jti");
        let err = claims.require_scope(yah_scopes::AUDIT_WRITE).unwrap_err();
        match err {
            RouteError::InsufficientScope { required } => {
                assert_eq!(required, yah_scopes::AUDIT_WRITE);
            }
            other => panic!("expected InsufficientScope, got {other:?}"),
        }
    }

    #[test]
    fn insufficient_scope_responds_403_with_stable_code() {
        let err = RouteError::InsufficientScope {
            required: yah_scopes::AUDIT_WRITE,
        };
        let (status, code) = err.status_and_code();
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(code, "insufficient_scope");
        // The IntoResponse path emits the same status.
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
