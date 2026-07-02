//! R592-F3 — golden-token fixture consumption for cheers-verify.
//!
//! Before R592-B7 this file characterized an INCOMPATIBILITY: every golden
//! fixture — including the two VALID ones — failed against
//! `PasetoV4PublicVerifier::verify_mcp_at`, because cheers-verify's codec
//! went through pasetors' high-level `Claims` wrapper, which hard-rejects a
//! numeric (i64) `exp`/`iat`. After R592-B7, `verify_mcp_at` speaks the same
//! low-level, footer-kid wire convention as kamaji-bin's verifier /
//! cheers-mock / yubaba's minter, so every fixture now asserts INTEROP:
//! valid fixtures verify and return the exact pinned claim values; invalid
//! fixtures are rejected with the specific error class their corruption
//! should produce.
//!
//! ## Scope note — `iss`/`aud` are NOT checked here
//!
//! `PasetoV4PublicVerifier::verify_mcp_at` deliberately does not validate
//! `iss`/`aud` against any "expected" value — that policy varies per
//! consumer (which issuer/audience a given deployment expects) and R592-B7
//! places it at the caller, e.g. `cloud-admin`'s `viewer_from_claims` (which
//! gained its own wrong-iss/wrong-aud rejection tests in the same ticket).
//! So `wrong_aud.token` / `wrong_iss.token` verify SUCCESSFULLY here — the
//! signature is valid, the kid matches, the token isn't expired — and the
//! tests below assert that the returned claims faithfully carry the
//! "wrong" `iss`/`aud` values verbatim, proving cheers-verify doesn't
//! silently launder them. Rejecting on iss/aud mismatch is exercised at the
//! cloud-admin layer, not here.

use cheers_core::CodecError;
use cheers_test_support::fixtures;
use cheers_verify::PasetoV4PublicVerifier;

fn golden_verifier() -> PasetoV4PublicVerifier {
    PasetoV4PublicVerifier::from_public_key(&fixtures::fixture_public_key_bytes())
        .expect("pinned seed is a valid V4 public key")
}

#[test]
fn golden_valid_user_token_verifies() {
    let verifier = golden_verifier();
    let claims = verifier
        .verify_mcp_at(
            fixtures::VALID_USER_TOKEN.trim(),
            fixtures::FIXTURE_NOW,
            fixtures::FIXTURE_KID,
        )
        .expect("golden valid_user fixture must verify");
    assert_eq!(claims.sub.to_string(), "user:alice-fixture");
    assert_eq!(claims.iss, fixtures::FIXTURE_ISS);
    assert_eq!(claims.aud, fixtures::FIXTURE_AUD);
    assert_eq!(claims.jti, "fixture-user-1");
}

#[test]
fn golden_valid_svc_token_verifies_self_scoped() {
    // yubaba's ownership-write pattern: `aud == iss`. cheers-verify doesn't
    // police this either way — it just returns the claims as pinned.
    let verifier = golden_verifier();
    let claims = verifier
        .verify_mcp_at(
            fixtures::VALID_SVC_TOKEN.trim(),
            fixtures::FIXTURE_NOW,
            fixtures::FIXTURE_KID,
        )
        .expect("golden valid_svc fixture must verify");
    assert_eq!(claims.sub.to_string(), "svc:yubaba-fixture-1");
    assert_eq!(claims.aud, claims.iss, "svc fixture is self-scoped: aud == iss");
}

#[test]
fn golden_expired_token_is_rejected() {
    let verifier = golden_verifier();
    let err = verifier
        .verify_mcp_at(
            fixtures::EXPIRED_TOKEN.trim(),
            fixtures::FIXTURE_NOW,
            fixtures::FIXTURE_KID,
        )
        .expect_err("expired fixture must not verify");
    assert!(matches!(err, CodecError::Expired), "got {err:?}");
}

/// `wrong_aud.token` is cryptographically valid, correctly kid'd, and not
/// expired — cheers-verify has no configured "expected aud" to compare
/// against, so it verifies successfully. The `aud` mismatch is a policy
/// concern for the caller (see module doc); this test pins that
/// cheers-verify faithfully surfaces the (wrong) `aud` rather than silently
/// substituting or hiding it.
#[test]
fn golden_wrong_aud_token_verifies_and_surfaces_the_mismatched_aud() {
    let verifier = golden_verifier();
    let claims = verifier
        .verify_mcp_at(
            fixtures::WRONG_AUD_TOKEN.trim(),
            fixtures::FIXTURE_NOW,
            fixtures::FIXTURE_KID,
        )
        .expect("cheers-verify does not police aud; the fixture is otherwise structurally valid");
    assert_ne!(claims.aud, fixtures::FIXTURE_AUD);
    assert_eq!(claims.aud, "https://wrong-resource.fixture.test");
}

/// Same reasoning as the `aud` case above, for `iss`.
#[test]
fn golden_wrong_iss_token_verifies_and_surfaces_the_mismatched_iss() {
    let verifier = golden_verifier();
    let claims = verifier
        .verify_mcp_at(
            fixtures::WRONG_ISS_TOKEN.trim(),
            fixtures::FIXTURE_NOW,
            fixtures::FIXTURE_KID,
        )
        .expect("cheers-verify does not police iss; the fixture is otherwise structurally valid");
    assert_ne!(claims.iss, fixtures::FIXTURE_ISS);
    assert_eq!(claims.iss, "https://wrong-issuer.fixture.test");
}

#[test]
fn golden_tampered_sig_token_is_rejected() {
    let verifier = golden_verifier();
    let err = verifier
        .verify_mcp_at(
            fixtures::TAMPERED_SIG_TOKEN.trim(),
            fixtures::FIXTURE_NOW,
            fixtures::FIXTURE_KID,
        )
        .expect_err("tampered signature must not verify");
    assert!(matches!(err, CodecError::SignatureMismatch), "got {err:?}");
}

#[test]
fn golden_unknown_kid_token_is_rejected() {
    // Signed under FIXTURE_UNKNOWN_KID's footer with the SAME secret key —
    // signature would verify fine, but this verifier only trusts
    // FIXTURE_KID, so it's rejected before the crypto check even runs.
    let verifier = golden_verifier();
    let err = verifier
        .verify_mcp_at(
            fixtures::UNKNOWN_KID_TOKEN.trim(),
            fixtures::FIXTURE_NOW,
            fixtures::FIXTURE_KID,
        )
        .expect_err("unrecognized kid must not verify");
    assert!(
        matches!(err, CodecError::UnknownKid(ref k) if k == fixtures::FIXTURE_UNKNOWN_KID),
        "got {err:?}"
    );
}

#[test]
fn golden_no_footer_token_is_rejected() {
    let verifier = golden_verifier();
    let err = verifier
        .verify_mcp_at(
            fixtures::NO_FOOTER_TOKEN.trim(),
            fixtures::FIXTURE_NOW,
            fixtures::FIXTURE_KID,
        )
        .expect_err("footer-less token must not verify");
    assert!(matches!(err, CodecError::MissingKid), "got {err:?}");
}

#[test]
fn golden_footer_missing_kid_token_is_rejected() {
    let verifier = golden_verifier();
    let err = verifier
        .verify_mcp_at(
            fixtures::FOOTER_MISSING_KID_TOKEN.trim(),
            fixtures::FIXTURE_NOW,
            fixtures::FIXTURE_KID,
        )
        .expect_err("footer without a kid field must not verify");
    assert!(matches!(err, CodecError::Malformed), "got {err:?}");
}

/// The failure mode of a tampered payload is upstream of any claim-shape
/// question: verifying it as a SESSION-claims token (`verify_at`) fails for
/// an unrelated reason (the high-level `Claims::from_string` rejects the
/// numeric `exp`/`iat`) — the two codec paths were never wire-compatible
/// with each other and still aren't; `verify_mcp_at` is the wire-convention
/// path, `verify_at` remains cheers's own session-token codec.
#[test]
fn golden_valid_user_is_not_a_session_claims_token() {
    use cheers_core::TokenVerifier;
    let verifier = golden_verifier();
    let err = verifier
        .verify_at(fixtures::VALID_USER_TOKEN.trim(), fixtures::FIXTURE_NOW)
        .expect_err("wire-convention MCP fixture must not verify as a session-claims token");
    assert!(
        matches!(err, CodecError::Crypto(ref msg) if msg.contains("InvalidClaim")),
        "got {err:?}"
    );
}
