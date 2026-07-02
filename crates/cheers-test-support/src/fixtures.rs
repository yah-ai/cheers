//! Golden-token fixtures — the shared PASETO v4.public + JWKS contract every
//! cheers-family minter and verifier is checked against (R592-F3).
//!
//! ## Envelope
//!
//! One PASETO v4.public envelope convention is now shared across the whole
//! tree (R592-B7 hard-cut the second, incompatible one — see below): raw
//! JSON payload signed via pasetors' *low-level* `pasetors::version4::
//! PublicToken::sign` (so `exp`/`iat` stay i64 Unix seconds, not RFC3339
//! strings), `kid` carried in the PASETO footer. This is what kamaji-bin's
//! `auth::verifier` verifies, what `cheers-mock` mints, what yubaba's
//! `cheers_client::mint_ownership_write_token` mints (see the R427 handoff
//! notes in `oss/yubaba/crates/yubaba/src/identity.rs`), and — as of
//! R592-B7 — what cheers-server's `PasetoV4SecretMinter::mint_mcp` /
//! cheers-verify's `PasetoV4PublicVerifier::verify_mcp_at` mint/verify too.
//! This module pins that convention; `cheers-server/tests/golden_fixtures.rs`
//! and `cheers-verify/tests/golden_fixtures.rs` are the executable proof
//! (byte-for-byte for the mint side, accept/reject-with-the-right-error for
//! the verify side) — neither can be produced/consumed here in
//! cheers-test-support without depending on cheers-server/cheers-verify
//! circularly for a second time.
//!
//! Before R592-B7, cheers-core/cheers-verify's `McpClaims` codec path went
//! through pasetors' *high-level* `Claims` wrapper instead: the claims JSON
//! rode nested under an additional `"mcp"` claim (not flattened to the top
//! level), `iat`/`nbf` became RFC3339 strings, and no footer/kid was ever
//! stamped. That path was internally self-consistent (mint_mcp ⇄
//! verify_mcp_at round-tripped) but was NOT wire-compatible with the
//! fixtures here or with kamaji-bin/cheers-mock/yubaba — R592-B7 hard-cut
//! it (no coexistence, no shim) in favor of the shared convention above.
//!
//! ## Pinned seed + clock strategy
//!
//! [`FIXTURE_SEED`] is a fixed, obviously-non-random 32-byte Ed25519 seed
//! (sequential bytes, TEST-ONLY — never use outside this module). The keypair
//! it derives is fully deterministic ([`fixture_secret_key`] /
//! [`fixture_public_key`]), so every fixture token is byte-reproducible from
//! source — verified by the `regenerate` test module below, which re-signs
//! every fixture from the pinned seed and asserts a byte-for-byte match
//! against the committed file. Drift in the signing convention (this module)
//! shows up there; drift in any *consuming* minter shows up in that crate's
//! own golden test (cheers-server, cheers-mock) instead.
//!
//! All verifiers in this tree take an explicit `now: i64` rather than reading
//! the wall clock (`TokenVerifier::verify_at`, `AuthVerifier::verify`,
//! `MockIssuer`'s consumers, …), so there is no "far future" timestamp trick
//! needed to keep fixtures valid for decades: [`FIXTURE_NOW`] is the pinned
//! instant every "valid" fixture is valid AT and every "expired" fixture is
//! already expired AT. Pass `FIXTURE_NOW` (or a small offset from it) as the
//! `now` argument when exercising these fixtures; don't use the wall clock.
//!
//! ## Fixture inventory
//!
//! | file                       | proves                                                          |
//! |-----------------------------|------------------------------------------------------------------|
//! | `valid_user.token`          | canonical `user:<id>` MCP-call shape: scope + owns + camp_id + act + auth_strength, `aud` = kamaji resource (≠ `iss`) |
//! | `valid_svc.token`           | canonical `svc:<id>` service-principal shape (yubaba's ownership-write pattern): `scope=["ownership:write"]`, `aud == iss` self-scoping, no owns/camp_id/act |
//! | `expired.token`             | `exp` before [`FIXTURE_NOW`] — must be rejected as expired      |
//! | `wrong_aud.token`           | `aud` doesn't match the verifier's configured resource          |
//! | `wrong_iss.token`           | `iss` doesn't match the verifier's configured issuer            |
//! | `tampered_sig.token`        | last payload byte flipped after signing — signature must fail   |
//! | `unknown_kid.token`         | footer `kid` not present in [`JWKS_JSON`]                        |
//! | `no_footer.token`           | no footer at all — kid-less token                                |
//! | `footer_missing_kid.token`  | footer present but has no `kid` field                            |
//! | `jwks.json`                 | published JWKS doc for [`FIXTURE_KID`] / [`fixture_public_key_bytes`] |
//!
//! `tampered_sig` / `unknown_kid` / `no_footer` / `footer_missing_kid` all
//! carry `valid_user`'s claim values (`fixtures/valid_user.claims.json`) —
//! only the envelope (signature bytes / footer) differs, so a verifier
//! failing on the CLAIMS rather than the envelope would be a bug in the
//! fixture, not the consumer under test.

use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_compact::{KeyPair, Seed};
use pasetors::keys::{AsymmetricPublicKey, AsymmetricSecretKey};
use pasetors::version4::{PublicToken, V4};
use serde_json::Value;

/// TEST-ONLY Ed25519 seed — sequential bytes, deliberately not
/// cryptographically random. Never reuse outside fixture generation.
pub const FIXTURE_SEED: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

/// `kid` published in [`JWKS_JSON`] and stamped into every valid fixture's
/// footer.
pub const FIXTURE_KID: &str = "cheers-test-1";

/// A `kid` that is deliberately absent from [`JWKS_JSON`] — the
/// `unknown_kid` fixture is signed under this footer value with the SAME
/// pinned secret key (the point under test is JWKS lookup failure, not a bad
/// signature).
pub const FIXTURE_UNKNOWN_KID: &str = "ghost-kid-not-in-jwks";

/// Cheers issuer URL baked into every fixture's `iss`.
pub const FIXTURE_ISS: &str = "https://cheers.fixture.test";

/// Kamaji resource URI — the `aud` of the `user:*` MCP-call fixtures
/// (`valid_user`, `expired`, `wrong_aud`, `wrong_iss`, and the envelope-game
/// fixtures that share `valid_user`'s claims).
pub const FIXTURE_AUD: &str = "https://kamaji.fixture.test";

/// The pinned verification instant. Every "valid" fixture is valid when
/// checked against this `now`; every "expired" fixture is already expired
/// against it. Pass this (or a small offset) as the verifier's `now` —
/// fixtures are not wall-clock dependent.
pub const FIXTURE_NOW: i64 = 1_700_000_000;

// ── committed fixture files ─────────────────────────────────────────────────

pub const VALID_USER_CLAIMS_JSON: &str = include_str!("../fixtures/valid_user.claims.json");
pub const VALID_USER_TOKEN: &str = include_str!("../fixtures/valid_user.token");

pub const VALID_SVC_CLAIMS_JSON: &str = include_str!("../fixtures/valid_svc.claims.json");
pub const VALID_SVC_TOKEN: &str = include_str!("../fixtures/valid_svc.token");

pub const EXPIRED_CLAIMS_JSON: &str = include_str!("../fixtures/expired.claims.json");
pub const EXPIRED_TOKEN: &str = include_str!("../fixtures/expired.token");

pub const WRONG_AUD_CLAIMS_JSON: &str = include_str!("../fixtures/wrong_aud.claims.json");
pub const WRONG_AUD_TOKEN: &str = include_str!("../fixtures/wrong_aud.token");

pub const WRONG_ISS_CLAIMS_JSON: &str = include_str!("../fixtures/wrong_iss.claims.json");
pub const WRONG_ISS_TOKEN: &str = include_str!("../fixtures/wrong_iss.token");

/// Envelope-game fixtures — all carry `valid_user`'s claim VALUES; only the
/// signature/footer differ.
pub const TAMPERED_SIG_TOKEN: &str = include_str!("../fixtures/tampered_sig.token");
pub const UNKNOWN_KID_TOKEN: &str = include_str!("../fixtures/unknown_kid.token");
pub const NO_FOOTER_TOKEN: &str = include_str!("../fixtures/no_footer.token");
pub const FOOTER_MISSING_KID_TOKEN: &str = include_str!("../fixtures/footer_missing_kid.token");

/// Published JWKS document — one active key, [`FIXTURE_KID`].
pub const JWKS_JSON: &str = include_str!("../fixtures/jwks.json");

// ── parsed accessors ─────────────────────────────────────────────────────────

pub fn valid_user_claims() -> Value {
    serde_json::from_str(VALID_USER_CLAIMS_JSON).expect("valid_user.claims.json parses")
}

pub fn valid_svc_claims() -> Value {
    serde_json::from_str(VALID_SVC_CLAIMS_JSON).expect("valid_svc.claims.json parses")
}

pub fn expired_claims() -> Value {
    serde_json::from_str(EXPIRED_CLAIMS_JSON).expect("expired.claims.json parses")
}

pub fn wrong_aud_claims() -> Value {
    serde_json::from_str(WRONG_AUD_CLAIMS_JSON).expect("wrong_aud.claims.json parses")
}

pub fn wrong_iss_claims() -> Value {
    serde_json::from_str(WRONG_ISS_CLAIMS_JSON).expect("wrong_iss.claims.json parses")
}

// ── pinned keypair ───────────────────────────────────────────────────────────

/// Deterministically derive the Ed25519 keypair from [`FIXTURE_SEED`]. Same
/// derivation pasetors uses internally to validate a V4 secret key
/// (`ed25519_compact::KeyPair::from_seed`) — see
/// `oss/cheers/crates/cheers-server/src/camp.rs`'s `keypair_from_seed` test
/// helper for the same house idiom.
fn fixture_keypair() -> KeyPair {
    KeyPair::from_seed(Seed::from_slice(&FIXTURE_SEED).expect("32-byte seed"))
}

/// The 64-byte PASETO V4 secret key (`seed || pubkey`) derived from
/// [`FIXTURE_SEED`].
pub fn fixture_secret_key_bytes() -> [u8; 64] {
    let kp = fixture_keypair();
    let mut out = [0u8; 64];
    out.copy_from_slice(kp.sk.as_ref());
    out
}

/// The 32-byte Ed25519 public key derived from [`FIXTURE_SEED`].
pub fn fixture_public_key_bytes() -> [u8; 32] {
    let kp = fixture_keypair();
    let mut out = [0u8; 32];
    out.copy_from_slice(kp.pk.as_ref());
    out
}

pub fn fixture_secret_key() -> AsymmetricSecretKey<V4> {
    AsymmetricSecretKey::<V4>::from(&fixture_secret_key_bytes())
        .expect("pinned seed produces a valid V4 secret key")
}

pub fn fixture_public_key() -> AsymmetricPublicKey<V4> {
    AsymmetricPublicKey::<V4>::from(&fixture_public_key_bytes())
        .expect("pinned seed produces a valid V4 public key")
}

// ── signing helpers ──────────────────────────────────────────────────────────

/// Footer bytes carrying `{"kid": "<kid>"}` — the shape kamaji-bin /
/// cheers-mock / yubaba all stamp.
pub fn kid_footer(kid: &str) -> Vec<u8> {
    format!(r#"{{"kid":"{kid}"}}"#).into_bytes()
}

/// Sign `claims` as a PASETO v4.public token under the pinned fixture secret
/// key, via the shared LOW-LEVEL wire convention (raw JSON payload bytes, not
/// pasetors' high-level `Claims` wrapper). `footer` rides verbatim (or is
/// omitted when `None`).
pub fn sign_fixture(claims: &Value, footer: Option<&[u8]>) -> String {
    let secret = fixture_secret_key();
    let payload = serde_json::to_vec(claims).expect("claims serialize");
    PublicToken::sign(&secret, &payload, footer, None).expect("pinned key signs")
}

/// Flip the last character of a token's payload segment (the base64url blob
/// right before the footer, or at the very end when there's no footer) —
/// corrupts the trailing byte(s) of the Ed25519 signature, which
/// deterministically fails verification. Used to derive `tampered_sig` from
/// `valid_user`.
pub fn tamper_signature(token: &str) -> String {
    let (body, footer) = token.rsplit_once('.').expect("token has a footer segment");
    let mut chars: Vec<char> = body.chars().collect();
    let last_idx = chars.len() - 1;
    chars[last_idx] = if chars[last_idx] == 'A' { 'B' } else { 'A' };
    let mutated_body: String = chars.into_iter().collect();
    format!("{mutated_body}.{footer}")
}

/// Rebuild the JWKS document JSON (pretty-printed, matching [`JWKS_JSON`]'s
/// committed formatting) from the pinned public key.
pub fn build_jwks_json() -> String {
    let x = Base64UrlUnpadded::encode_string(&fixture_public_key_bytes());
    let doc = serde_json::json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x,
            "kid": FIXTURE_KID,
            "use": "sig",
            "alg": "EdDSA",
        }]
    });
    serde_json::to_string_pretty(&doc).expect("jwks doc serializes")
}

#[cfg(test)]
mod regenerate {
    //! Byte-for-byte regeneration: re-mint every fixture from
    //! [`super::FIXTURE_SEED`] and assert it matches the committed file. A
    //! change to the signing convention above — or hand-editing a fixture
    //! file without regenerating — fails here first.

    use super::*;

    fn assert_token_matches(claims: &Value, footer: Option<&[u8]>, committed: &str) {
        let regenerated = sign_fixture(claims, footer);
        assert_eq!(
            regenerated,
            committed.trim_end(),
            "fixture drift — regenerate the committed token from FIXTURE_SEED"
        );
    }

    #[test]
    fn valid_user_token_matches_pinned_seed() {
        assert_token_matches(
            &valid_user_claims(),
            Some(&kid_footer(FIXTURE_KID)),
            VALID_USER_TOKEN,
        );
    }

    #[test]
    fn valid_svc_token_matches_pinned_seed() {
        assert_token_matches(
            &valid_svc_claims(),
            Some(&kid_footer(FIXTURE_KID)),
            VALID_SVC_TOKEN,
        );
    }

    #[test]
    fn expired_token_matches_pinned_seed() {
        assert_token_matches(
            &expired_claims(),
            Some(&kid_footer(FIXTURE_KID)),
            EXPIRED_TOKEN,
        );
    }

    #[test]
    fn wrong_aud_token_matches_pinned_seed() {
        assert_token_matches(
            &wrong_aud_claims(),
            Some(&kid_footer(FIXTURE_KID)),
            WRONG_AUD_TOKEN,
        );
    }

    #[test]
    fn wrong_iss_token_matches_pinned_seed() {
        assert_token_matches(
            &wrong_iss_claims(),
            Some(&kid_footer(FIXTURE_KID)),
            WRONG_ISS_TOKEN,
        );
    }

    #[test]
    fn tampered_sig_token_is_valid_user_with_flipped_last_byte() {
        let regenerated = tamper_signature(VALID_USER_TOKEN.trim_end());
        assert_eq!(regenerated, TAMPERED_SIG_TOKEN.trim_end());
        // And it must actually be a DIFFERENT string from the untampered one.
        assert_ne!(TAMPERED_SIG_TOKEN.trim_end(), VALID_USER_TOKEN.trim_end());
    }

    #[test]
    fn unknown_kid_token_matches_pinned_seed() {
        assert_token_matches(
            &valid_user_claims(),
            Some(&kid_footer(FIXTURE_UNKNOWN_KID)),
            UNKNOWN_KID_TOKEN,
        );
    }

    #[test]
    fn no_footer_token_matches_pinned_seed() {
        assert_token_matches(&valid_user_claims(), None, NO_FOOTER_TOKEN);
    }

    #[test]
    fn footer_missing_kid_token_matches_pinned_seed() {
        assert_token_matches(
            &valid_user_claims(),
            Some(br#"{"other":"x"}"#),
            FOOTER_MISSING_KID_TOKEN,
        );
    }

    #[test]
    fn jwks_json_matches_pinned_seed() {
        assert_eq!(build_jwks_json(), JWKS_JSON.trim_end());
    }

    /// Cheap sanity check that regeneration actually produced a real
    /// v4.public token (catches an empty/placeholder fixture file). The
    /// executable proof that this envelope is NOT compatible with
    /// cheers-server/cheers-verify's `McpClaims` codec path lives where it
    /// belongs — in `cheers-server/tests/golden_fixtures.rs` and
    /// `cheers-verify/tests/golden_fixtures.rs`, which depend on THIS crate
    /// (a dependency the other direction would be circular).
    #[test]
    fn valid_user_token_is_not_a_bare_paseto_local_or_garbage() {
        assert!(VALID_USER_TOKEN.trim_end().starts_with("v4.public."));
        assert!(VALID_SVC_TOKEN.trim_end().starts_with("v4.public."));
    }
}
