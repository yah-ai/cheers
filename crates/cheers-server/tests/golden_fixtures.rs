//! R592-F3 — golden-token fixture consumption for cheers-server.
//!
//! Proves the interop contract R592-B7 establishes: cheers-server's
//! `PasetoV4SecretMinter::mint_mcp` / cheers-verify's
//! `PasetoV4PublicVerifier::verify_mcp_at` now speak the SAME wire envelope
//! as kamaji-bin's verifier, cheers-mock, and yubaba's minter — flat
//! top-level JSON, i64 `exp`/`iat`, `kid` in the PASETO footer, low-level
//! `PublicToken::sign`/`verify`. Before R592-B7 this file characterized an
//! INCOMPATIBILITY (McpClaims rode nested under an `"mcp"` additional claim
//! via pasetors' high-level `Claims` wrapper, no footer/kid ever stamped);
//! now it asserts the opposite — byte-for-byte interop with the golden
//! fixtures pinned in `cheers_test_support::fixtures`.

use cheers_core::{Actor, AuthStrength, CodecError, McpClaims, Owns, PrincipalId, Scope};
use cheers_server::PasetoV4SecretMinter;
use cheers_test_support::fixtures;
use cheers_verify::PasetoV4PublicVerifier;

/// The `valid_user` fixture's claim VALUES, expressed as cheers-core's typed
/// `McpClaims` (mirrors `fixtures::valid_user_claims()`'s JSON field for
/// field — see the assertions in `mint_mcp_from_pinned_seed_round_trips_golden_claim_values`
/// for the cross-check against the committed JSON).
fn golden_user_mcp_claims() -> McpClaims {
    let mut owns = Owns::default();
    owns.service = vec!["svc-fixture-a".into()];
    McpClaims::new(
        fixtures::FIXTURE_ISS,
        fixtures::FIXTURE_AUD,
        PrincipalId::user("alice-fixture"),
        1_700_000_000,
        1_700_000_900,
        "fixture-user-1",
        vec![Scope::CloudRead, Scope::CloudDeploy],
    )
    .with_act(Actor::new(PrincipalId::service("agent-claude-fixture")))
    .with_camp_id("camp-fixture-1")
    .with_owns(owns)
    .with_auth_strength(AuthStrength::UserFresh)
}

#[test]
fn mint_mcp_from_pinned_seed_round_trips_golden_claim_values() {
    let minter = PasetoV4SecretMinter::from_secret_key(&fixtures::fixture_secret_key_bytes())
        .expect("pinned seed is a valid V4 secret key");
    let verifier = PasetoV4PublicVerifier::from_public_key(&fixtures::fixture_public_key_bytes())
        .expect("pinned seed is a valid V4 public key");

    let claims = golden_user_mcp_claims();
    let token = minter
        .mint_mcp(&claims, fixtures::FIXTURE_KID)
        .expect("mint succeeds");
    let verified = verifier
        .verify_mcp_at(&token, fixtures::FIXTURE_NOW, fixtures::FIXTURE_KID)
        .expect("verify succeeds under the SAME pinned key");

    assert_eq!(
        verified, claims,
        "pinned-seed mint→verify round trip must reproduce the golden claim values exactly"
    );

    // Cross-check against the committed JSON fixture's field values, so drift
    // in either this test's construction or the fixture file itself shows up
    // here (not just internal self-consistency against `claims` above).
    let golden_json = fixtures::valid_user_claims();
    assert_eq!(verified.sub.to_string(), golden_json["sub"].as_str().unwrap());
    assert_eq!(verified.iss, golden_json["iss"].as_str().unwrap());
    assert_eq!(verified.aud, golden_json["aud"].as_str().unwrap());
    assert_eq!(verified.jti, golden_json["jti"].as_str().unwrap());
    assert_eq!(verified.exp, golden_json["exp"].as_i64().unwrap());
    assert_eq!(verified.iat, golden_json["iat"].as_i64().unwrap());
}

/// INTEROP (1/2): cheers-server's OWN `mint_mcp`, given the exact golden
/// claim values + the pinned secret key + `FIXTURE_KID`, produces a token
/// that byte-matches the committed `valid_user.token` fixture — not just
/// "verifies under the same key" (which a differently-shaped envelope could
/// also achieve), but the literal wire bytes kamaji-bin / cheers-mock /
/// yubaba already agree on. Before R592-B7 this was impossible even in
/// principle: mint_mcp stamped no footer at all and wrapped claims under an
/// `"mcp"` additional claim via the high-level `Claims` encoder, so the
/// output could never match a flat, footer-stamped, low-level-signed token
/// byte for byte.
#[test]
fn mint_mcp_from_pinned_seed_byte_matches_golden_wire_token() {
    let minter = PasetoV4SecretMinter::from_secret_key(&fixtures::fixture_secret_key_bytes())
        .expect("pinned seed is a valid V4 secret key");

    let token = minter
        .mint_mcp(&golden_user_mcp_claims(), fixtures::FIXTURE_KID)
        .expect("mint succeeds");

    assert_eq!(
        token,
        fixtures::VALID_USER_TOKEN.trim_end(),
        "cheers-server's mint_mcp must reproduce the golden wire token byte-for-byte from the \
         pinned seed + FIXTURE_KID — any divergence here means cheers-server's envelope drifted \
         from the wire convention kamaji-bin/cheers-mock/yubaba already share"
    );
}

/// INTEROP (2/2), the reverse direction: cheers-verify's `verify_mcp_at`
/// accepts the WIRE-CONVENTION golden token (signed independently by
/// `cheers_test_support::fixtures::sign_fixture`, not by cheers-server's own
/// minter) and returns the exact claim values the fixture pins. Before
/// R592-B7 this failed at claim-TYPE validation — pasetors' high-level
/// `Claims::from_string` hard-rejects the numeric `exp`/`iat` this wire
/// convention requires (see `cheers-verify/tests/golden_fixtures.rs` for the
/// full characterization that used to apply here).
#[test]
fn wire_convention_golden_token_is_verify_mcp_at_compatible() {
    let verifier = PasetoV4PublicVerifier::from_public_key(&fixtures::fixture_public_key_bytes())
        .expect("pinned seed is a valid V4 public key");

    let claims = verifier
        .verify_mcp_at(
            fixtures::VALID_USER_TOKEN.trim(),
            fixtures::FIXTURE_NOW,
            fixtures::FIXTURE_KID,
        )
        .expect("wire-convention golden fixture must verify under verify_mcp_at");

    assert_eq!(claims, golden_user_mcp_claims());
}

/// cheers-server's `mint_mcp` now stamps a `kid` footer on every token — the
/// prerequisite for kamaji-bin's `AuthVerifier` (footer-kid JWKS lookup) to
/// accept it at all. Before R592-B7 this footer was always empty, so
/// kamaji-bin rejected every cheers-server-minted MCP token with `MissingKid`
/// before it ever reached a signature check.
#[test]
fn cheers_server_mint_mcp_output_carries_the_kid_footer() {
    let minter = PasetoV4SecretMinter::from_secret_key(&fixtures::fixture_secret_key_bytes())
        .expect("pinned seed is a valid V4 secret key");
    let token = minter
        .mint_mcp(&golden_user_mcp_claims(), fixtures::FIXTURE_KID)
        .expect("mint succeeds");

    let untrusted = pasetors::token::UntrustedToken::<
        pasetors::token::Public,
        pasetors::version4::V4,
    >::try_from(token.as_str())
    .expect("well-formed v4.public token");
    let footer = untrusted.untrusted_footer();
    assert!(!footer.is_empty(), "mint_mcp must stamp a non-empty footer");
    let footer_str = std::str::from_utf8(footer).unwrap();
    assert!(
        footer_str.contains(&format!(r#""kid":"{}""#, fixtures::FIXTURE_KID)),
        "footer must carry the kid mint_mcp was called with, got: {footer_str}"
    );
}

/// A token minted under a DIFFERENT kid string is rejected by a verifier
/// configured to expect `FIXTURE_KID` — `UnknownKid`, not a signature
/// failure (the signature is perfectly valid; the verifier just doesn't
/// trust that kid).
#[test]
fn mint_mcp_under_different_kid_is_rejected_as_unknown_kid() {
    let minter = PasetoV4SecretMinter::from_secret_key(&fixtures::fixture_secret_key_bytes())
        .expect("pinned seed is a valid V4 secret key");
    let verifier = PasetoV4PublicVerifier::from_public_key(&fixtures::fixture_public_key_bytes())
        .expect("pinned seed is a valid V4 public key");

    let token = minter
        .mint_mcp(&golden_user_mcp_claims(), "some-other-kid")
        .expect("mint succeeds");
    let err = verifier
        .verify_mcp_at(&token, fixtures::FIXTURE_NOW, fixtures::FIXTURE_KID)
        .expect_err("kid mismatch must be rejected");
    assert!(
        matches!(err, CodecError::UnknownKid(ref k) if k == "some-other-kid"),
        "got {err:?}"
    );
}
