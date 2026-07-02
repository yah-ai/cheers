//! Concrete session-token codecs — **origin-side**.
//!
//! Three impls of the [`cheers_core`] capability traits:
//!
//! - [`PasetoV4Codec`] — PASETO v4.local (XChaCha20-Poly1305 + BLAKE2b).
//!   Encrypted *and* authenticated claims, opaque to whoever holds the cookie.
//!   Symmetric, so it impls **both** [`TokenMinter`] and [`TokenVerifier`] —
//!   origin-only verification (decrypting needs the secret key).
//! - [`HmacBlobCodec`] — JSON payload + HMAC-SHA256 tag, base64url-encoded.
//!   Cleartext-readable; authenticated, not encrypted. Symmetric (both traits).
//! - [`PasetoV4SecretMinter`] — PASETO v4.public (Ed25519) **mint only**. The
//!   matching verify-only [`PasetoV4PublicVerifier`](cheers_verify::PasetoV4PublicVerifier)
//!   lives in `cheers-verify`; the origin signs, the edge verifies.
//!
//! The symmetric codecs impl both traits on one type, so they MUST live here in
//! `cheers-server`, never in `cheers-verify` — putting them there would re-grant
//! mint to the edge through the back door.
//!
//! ```
//! use cheers_core::{Claims, DeviceBinding, DeviceId, TokenMinter, TokenVerifier, UserId};
//! use cheers_server::HmacBlobCodec;
//!
//! let codec = HmacBlobCodec::new([0u8; 32]);
//! let claims = Claims::new(
//!     UserId::new("u1"),
//!     DeviceId::new("d1"),
//!     DeviceBinding::Passkey,
//!     1_700_000_000,
//!     i64::MAX, // far-future expiry for the doctest
//! );
//! let token = codec.mint(&claims).unwrap();
//! let back = codec.verify(&token).unwrap();
//! assert_eq!(back, claims);
//! ```
//!
//! @yah:ticket(R020-T15, "McpClaims mint/verify helpers on PasetoV4 codecs (cheers-server)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-04T18:25:48Z)
//! @yah:status(review)
//! @yah:phase(P2)
//! @yah:parent(R020)
//! @yah:verify("cargo test -p cheers-server (round-trip: mint_mcp → verify_mcp_at returns the same McpClaims; expired token → CodecError::Expired; wrong-key sig → SignatureMismatch).")
//! @yah:verify("cargo test -p cheers-verify (no regression: existing Claims-typed verify path still passes).")
//! @yah:gotcha("TokenMinter::mint / TokenVerifier::verify_at are hard-coded to cheers_core::Claims (session contract). McpClaims is a peer shape (R020-F3) — do NOT change the existing trait signatures; add sibling inherent methods instead. Generalising the traits is a deeper refactor that should wait for a second MCP-style claim shape to land.")
//! @arch:see(.yah/docs/working/mcp-auth-and-ownership.md)
//! @yah:next("R020-F6/F7 mint paths now have: (a) expand_scopes (F5) → (b) validate_grant per expanded Scope (defense in depth) → (c) McpClaims::new + with_* builders (F3) → (d) PasetoV4SecretMinter::mint_mcp (this ticket). All ingredients present — F6 (user-passkey) and F7 (camp-bootstrap) compose them differently around the principal lookup + bundle resolution.")
//! @yah:next("When R020-T16 (Bearer/McpClaims middleware in cheers-axum) lands, the edge will call verify_mcp_at and surface Malformed for cross-shape tokens — wire it as a 401, not 500.")
//! @yah:handoff("Landed: PasetoV4SecretMinter::mint_mcp(&McpClaims) -> Result<String, CodecError> in cheers-server/src/codec.rs as an inherent sibling to TokenMinter::mint — same v4.public sign path. PasetoV4PublicVerifier::verify_mcp_at(token, now) -> Result<McpClaims, CodecError> in cheers-verify/src/public_verifier.rs.")
//! @yah:handoff("Key separation is structural: MCP_CLAIM_KEY = \"mcp\" (exported from cheers-verify so the server-side minter uses the same identifier) vs the session-claim \"cheers\". Cross-shape mix-ups surface as CodecError::Malformed at the get_claim() step — verified by mcp_token_not_verifiable_under_session_verify_at and session_token_not_verifiable_under_mcp_verify_at.")
//! @yah:handoff("Kept TokenMinter/TokenVerifier trait signatures untouched (still Claims-typed) — the generalisation refactor waits for a 2nd MCP-style claim shape, per the in-source gotcha.")
//! @yah:handoff("Caller owns iat/exp in McpClaims (parity with the Claims path); TTL policy belongs upstream (R020-F6/F7's mint paths will set per-call lifetime per the doc §TTLs).")
//! @yah:handoff("Owns is #[non_exhaustive] in cheers-core so the test fixture uses Owns::default() + field assignment (struct literal blocked outside the defining crate).")
//! @yah:handoff("Verified GREEN: cargo test -p cheers-core (no change), cheers-server 49 → 55 unit tests incl. 6 new mcp-codec tests, cheers-verify unchanged. Bundle work from R020-F5 still green.")

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use pasetors::claims::{Claims as PasetoClaims, ClaimsValidationRules};
use pasetors::keys::{AsymmetricPublicKey, AsymmetricSecretKey, SymmetricKey};
use pasetors::token::UntrustedToken;
use pasetors::version4::{PublicToken, V4};
use pasetors::{local, public};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use cheers_core::{Claims, CodecError, McpClaims, TokenMinter, TokenVerifier};
use cheers_verify::{codec_err, PasetoV4PublicVerifier};

type HmacSha256 = Hmac<Sha256>;

// ----------------------------------------------------------------------------
// PasetoV4Codec — v4.local (encrypted + authenticated)
// ----------------------------------------------------------------------------

/// PASETO v4.local codec. Encrypts and authenticates with a 32-byte symmetric key.
pub struct PasetoV4Codec {
    key: SymmetricKey<V4>,
}

impl PasetoV4Codec {
    /// Build from a 32-byte symmetric key.
    pub fn new(key_bytes: &[u8; 32]) -> Result<Self, CodecError> {
        let key = SymmetricKey::<V4>::from(key_bytes)
            .map_err(|e| CodecError::Crypto(format!("{e:?}")))?;
        Ok(Self { key })
    }
}

impl TokenMinter for PasetoV4Codec {
    fn mint(&self, claims: &Claims) -> Result<String, CodecError> {
        // pasetors's standard `exp` claim is validated against the wall
        // clock and we want `verify_at(now)` to own that decision — so we
        // store the full cheers payload under one additional key and mark
        // the token as non-expiring at the PASETO layer.
        let mut p = PasetoClaims::new_expires_in(&core::time::Duration::ZERO)
            .map_err(|e| CodecError::Crypto(format!("{e:?}")))?;
        p.non_expiring();
        let cheers_value = serde_json::to_value(claims)?;
        p.add_additional("cheers", cheers_value)
            .map_err(|e| CodecError::Crypto(format!("{e:?}")))?;
        local::encrypt(&self.key, &p, None, None).map_err(codec_err)
    }
}

impl TokenVerifier for PasetoV4Codec {
    fn verify_at(&self, token: &str, now: i64) -> Result<Claims, CodecError> {
        let untrusted = UntrustedToken::<pasetors::token::Local, V4>::try_from(token)
            .map_err(|_| CodecError::Malformed)?;
        // Skip pasetors's wall-clock validation; we enforce `now` ourselves
        // for testability and consistency with HmacBlobCodec.
        let mut rules = ClaimsValidationRules::new();
        rules.allow_non_expiring();
        let trusted = local::decrypt(&self.key, &untrusted, &rules, None, None)
            .map_err(codec_err)?;
        let pclaims = trusted.payload_claims().ok_or(CodecError::Malformed)?;
        let v = pclaims
            .get_claim("cheers")
            .ok_or(CodecError::Malformed)?
            .clone();
        let out: Claims = serde_json::from_value(v)?;
        if out.is_expired_at(now) {
            return Err(CodecError::Expired);
        }
        Ok(out)
    }
}

// ----------------------------------------------------------------------------
// PasetoV4SecretMinter — v4.public (Ed25519: signed, NOT encrypted)
// ----------------------------------------------------------------------------

/// PASETO v4.public **minter** — signs claims with an Ed25519 secret key.
///
/// Origin-only: holding the secret key *is* minting power. Pair it with a
/// [`PasetoV4PublicVerifier`] (the matching public key) at the edge. Because
/// v4.public is signed but **not** encrypted, only mint non-secret claims this
/// way — anyone holding the token can read them.
pub struct PasetoV4SecretMinter {
    secret: AsymmetricSecretKey<V4>,
}

impl PasetoV4SecretMinter {
    /// Build from a 64-byte Ed25519 secret key in PASETO's `seed || public_key`
    /// layout (the V4 secret-key size). Rejects a key whose trailing public half
    /// doesn't match the seed.
    pub fn from_secret_key(bytes: &[u8; 64]) -> Result<Self, CodecError> {
        let secret = AsymmetricSecretKey::<V4>::from(bytes)
            .map_err(|e| CodecError::Crypto(format!("{e:?}")))?;
        Ok(Self { secret })
    }

    /// Generate a fresh Ed25519 keypair, returning the origin minter and its
    /// matching edge [`PasetoV4PublicVerifier`].
    pub fn generate() -> Result<(Self, PasetoV4PublicVerifier), CodecError> {
        use pasetors::keys::{AsymmetricKeyPair, Generate};
        let kp = AsymmetricKeyPair::<V4>::generate()
            .map_err(|e| CodecError::Crypto(format!("{e:?}")))?;
        Ok((
            Self { secret: kp.secret },
            PasetoV4PublicVerifier::from_key(kp.public),
        ))
    }

    /// Derive the matching public verifier — e.g. to publish the verify key to
    /// an edge while the secret never leaves the origin.
    pub fn verifier(&self) -> Result<PasetoV4PublicVerifier, CodecError> {
        let public = AsymmetricPublicKey::<V4>::try_from(&self.secret)
            .map_err(|e| CodecError::Crypto(format!("{e:?}")))?;
        Ok(PasetoV4PublicVerifier::from_key(public))
    }

    /// Raw bytes of the underlying PASETO V4 secret key — 64 bytes in the
    /// `seed || public_key` layout.
    ///
    /// **Origin-only, single-use affordance.** The
    /// [`ServicePrincipalAuthority`](crate::service_principal::ServicePrincipalAuthority)
    /// returns these bytes to a service-principal install flow exactly once
    /// at provision/rotate time (see
    /// `.yah/docs/working/mcp-auth-and-ownership.md` §Service principal
    /// bootstrap). Cheers's *own* session signing key never reaches this
    /// accessor — it is constructed once at startup and never extracted —
    /// so leaking the cheers secret half is impossible by construction
    /// (the symmetric codecs don't expose this affordance at all).
    pub fn secret_key_bytes(&self) -> &[u8] {
        self.secret.as_bytes()
    }

    /// Sign an MCP-call token carrying [`McpClaims`].
    ///
    /// **Wire convention** (R592-B7) — the same envelope kamaji-bin's
    /// verifier, `cheers-mock`, and yubaba's `mint_ownership_write_token`
    /// already agree on (pinned byte-for-byte in
    /// `cheers_test_support::fixtures`): `claims` serializes directly as the
    /// token's FLAT top-level JSON payload — no wrapping claim key, `exp`/
    /// `iat` stay i64 Unix seconds — signed via pasetors' LOW-LEVEL
    /// [`PublicToken::sign`], never the high-level `Claims` wrapper (which
    /// hard-rejects non-string registered claims). `kid` rides in the PASETO
    /// footer as `{"kid":"<kid>"}`; the matching
    /// [`PasetoV4PublicVerifier::verify_mcp_at`] requires it.
    ///
    /// The caller owns `iat`/`exp` (mirrors the session-claim path) — TTL
    /// policy for MCP tokens belongs upstream of this primitive. `kid`
    /// identifies which published key this mint used — same string a
    /// verifier's JWKS/footer lookup keys off of.
    ///
    /// Serializes via `serde_json::Value` rather than serializing `claims`
    /// directly: every reference wire producer (yubaba's
    /// `mint_ownership_write_token`, cheers-mock's `MockIssuer::mint`,
    /// `cheers_test_support::fixtures::sign_fixture`) builds its payload as a
    /// `Value`/`json!{}` map, whose default (non-`preserve_order`)
    /// `BTreeMap`-backed key order is alphabetical — NOT the struct's
    /// field-declaration order `#[derive(Serialize)]` would emit. Routing
    /// through `Value` here reproduces that same alphabetical byte layout,
    /// which is what makes `mint_mcp`'s output byte-identical to the golden
    /// fixtures (verified in `cheers-server/tests/golden_fixtures.rs`).
    /// Deserialization is unaffected either way (JSON objects key-match by
    /// name), but the mint side has to match on the wire.
    pub fn mint_mcp(&self, claims: &McpClaims, kid: &str) -> Result<String, CodecError> {
        let value = serde_json::to_value(claims)?;
        let payload = serde_json::to_vec(&value)?;
        let footer = format!(r#"{{"kid":"{kid}"}}"#).into_bytes();
        PublicToken::sign(&self.secret, &payload, Some(&footer), None).map_err(codec_err)
    }
}

impl TokenMinter for PasetoV4SecretMinter {
    fn mint(&self, claims: &Claims) -> Result<String, CodecError> {
        let mut p = PasetoClaims::new_expires_in(&core::time::Duration::ZERO)
            .map_err(|e| CodecError::Crypto(format!("{e:?}")))?;
        p.non_expiring();
        let cheers_value = serde_json::to_value(claims)?;
        p.add_additional("cheers", cheers_value)
            .map_err(|e| CodecError::Crypto(format!("{e:?}")))?;
        public::sign(&self.secret, &p, None, None).map_err(codec_err)
    }
}

// ----------------------------------------------------------------------------
// HmacBlobCodec — `b64url(json).b64url(hmac)`
// ----------------------------------------------------------------------------

/// HMAC-SHA256 blob codec. Cleartext payload, authenticated only.
///
/// Wire format: `b64url(json(claims)) + "." + b64url(hmac_sha256(json(claims)))`.
/// The payload is *not* encrypted; anyone who has the token can read the
/// claims. Pick [`PasetoV4Codec`] when that matters.
pub struct HmacBlobCodec {
    key: [u8; 32],
}

impl HmacBlobCodec {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }
}

impl TokenMinter for HmacBlobCodec {
    fn mint(&self, claims: &Claims) -> Result<String, CodecError> {
        let payload = serde_json::to_vec(claims)?;
        let mut mac =
            HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(&payload);
        let tag = mac.finalize().into_bytes();
        let mut out = String::with_capacity(payload.len() * 2 + 64);
        out.push_str(&URL_SAFE_NO_PAD.encode(&payload));
        out.push('.');
        out.push_str(&URL_SAFE_NO_PAD.encode(tag));
        Ok(out)
    }
}

impl TokenVerifier for HmacBlobCodec {
    fn verify_at(&self, token: &str, now: i64) -> Result<Claims, CodecError> {
        let (payload_b64, tag_b64) = token.split_once('.').ok_or(CodecError::Malformed)?;
        let payload = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| CodecError::Malformed)?;
        let tag = URL_SAFE_NO_PAD
            .decode(tag_b64)
            .map_err(|_| CodecError::Malformed)?;
        let mut mac =
            HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(&payload);
        let expected = mac.finalize().into_bytes();
        if expected.ct_eq(&tag).unwrap_u8() != 1 {
            return Err(CodecError::SignatureMismatch);
        }
        let claims: Claims = serde_json::from_slice(&payload)?;
        if claims.is_expired_at(now) {
            return Err(CodecError::Expired);
        }
        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cheers_core::{DeviceBinding, DeviceId, UserId};

    fn sample_claims(exp: i64) -> Claims {
        Claims::new(
            UserId::new("u1"),
            DeviceId::new("d1"),
            DeviceBinding::OidcGoogle,
            1_000,
            exp,
        )
    }

    // ---- HmacBlobCodec ------------------------------------------------------

    #[test]
    fn hmac_blob_roundtrip() {
        let codec = HmacBlobCodec::new([7u8; 32]);
        let c = sample_claims(10_000);
        let tok = codec.mint(&c).unwrap();
        assert!(tok.contains('.'));
        let back = codec.verify_at(&tok, 5_000).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn hmac_blob_rejects_expired() {
        let codec = HmacBlobCodec::new([7u8; 32]);
        let c = sample_claims(100);
        let tok = codec.mint(&c).unwrap();
        let err = codec.verify_at(&tok, 200).unwrap_err();
        assert!(matches!(err, CodecError::Expired));
    }

    #[test]
    fn hmac_blob_rejects_wrong_key() {
        let a = HmacBlobCodec::new([1u8; 32]);
        let b = HmacBlobCodec::new([2u8; 32]);
        let tok = a.mint(&sample_claims(10_000)).unwrap();
        let err = b.verify_at(&tok, 5_000).unwrap_err();
        assert!(matches!(err, CodecError::SignatureMismatch));
    }

    #[test]
    fn hmac_blob_rejects_tampered_payload() {
        let codec = HmacBlobCodec::new([7u8; 32]);
        let tok = codec.mint(&sample_claims(10_000)).unwrap();
        let (payload, tag) = tok.split_once('.').unwrap();
        // Re-encode an *altered* payload while keeping the original tag.
        let altered = {
            let mut bytes = URL_SAFE_NO_PAD.decode(payload).unwrap();
            let last = bytes.len() - 1;
            bytes[last] ^= 0x01;
            URL_SAFE_NO_PAD.encode(bytes)
        };
        let bad = format!("{altered}.{tag}");
        let err = codec.verify_at(&bad, 5_000).unwrap_err();
        assert!(matches!(err, CodecError::SignatureMismatch));
    }

    #[test]
    fn hmac_blob_rejects_malformed() {
        let codec = HmacBlobCodec::new([7u8; 32]);
        assert!(matches!(
            codec.verify_at("no-dot", 0).unwrap_err(),
            CodecError::Malformed
        ));
        assert!(matches!(
            codec.verify_at("not_base64!.also_not", 0).unwrap_err(),
            CodecError::Malformed
        ));
    }

    // ---- PasetoV4Codec ------------------------------------------------------

    #[test]
    fn paseto_v4_roundtrip() {
        let codec = PasetoV4Codec::new(&[42u8; 32]).unwrap();
        let c = sample_claims(10_000);
        let tok = codec.mint(&c).unwrap();
        assert!(tok.starts_with("v4.local."));
        let back = codec.verify_at(&tok, 5_000).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn paseto_v4_rejects_expired() {
        let codec = PasetoV4Codec::new(&[42u8; 32]).unwrap();
        let c = sample_claims(100);
        let tok = codec.mint(&c).unwrap();
        let err = codec.verify_at(&tok, 200).unwrap_err();
        assert!(matches!(err, CodecError::Expired));
    }

    #[test]
    fn paseto_v4_rejects_wrong_key() {
        let a = PasetoV4Codec::new(&[1u8; 32]).unwrap();
        let b = PasetoV4Codec::new(&[2u8; 32]).unwrap();
        let tok = a.mint(&sample_claims(10_000)).unwrap();
        let err = b.verify_at(&tok, 5_000).unwrap_err();
        // Wrong key fails AEAD decryption; pasetors maps that to TokenValidation.
        assert!(matches!(err, CodecError::SignatureMismatch));
    }

    #[test]
    fn paseto_v4_rejects_malformed() {
        let codec = PasetoV4Codec::new(&[42u8; 32]).unwrap();
        assert!(matches!(
            codec.verify_at("not-a-paseto", 0).unwrap_err(),
            CodecError::Malformed
        ));
    }

    // ---- PasetoV4Public (asymmetric: secret minter / public verifier) -------

    fn v4_public_pair() -> (PasetoV4SecretMinter, PasetoV4PublicVerifier) {
        PasetoV4SecretMinter::generate().unwrap()
    }

    #[test]
    fn paseto_v4_public_roundtrip() {
        let (minter, verifier) = v4_public_pair();
        let c = sample_claims(10_000);
        let tok = minter.mint(&c).unwrap();
        assert!(tok.starts_with("v4.public."));
        let back = verifier.verify_at(&tok, 5_000).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn paseto_v4_public_rejects_expired() {
        let (minter, verifier) = v4_public_pair();
        let c = sample_claims(100);
        let tok = minter.mint(&c).unwrap();
        let err = verifier.verify_at(&tok, 200).unwrap_err();
        assert!(matches!(err, CodecError::Expired));
    }

    #[test]
    fn paseto_v4_public_rejects_wrong_key() {
        let (minter, _) = v4_public_pair();
        let (_, other_verifier) = v4_public_pair();
        let tok = minter.mint(&sample_claims(10_000)).unwrap();
        // A signature minted by one secret key must not verify under an
        // unrelated public key.
        let err = other_verifier.verify_at(&tok, 5_000).unwrap_err();
        assert!(matches!(err, CodecError::SignatureMismatch));
    }

    #[test]
    fn paseto_v4_public_verifier_derives_from_minter() {
        // The origin can hand the edge a verify-only key derived from its
        // secret, and tokens minted by that secret verify under it.
        let (minter, _) = v4_public_pair();
        let derived = minter.verifier().unwrap();
        let c = sample_claims(10_000);
        let tok = minter.mint(&c).unwrap();
        assert_eq!(derived.verify_at(&tok, 5_000).unwrap(), c);
    }

    #[test]
    fn paseto_v4_public_round_trips_through_key_bytes() {
        // Generate a pair, then reconstruct the verifier from its serialized
        // 32-byte public key — the shape a deployment uses (origin loads the
        // secret, edge loads the published public key).
        let (minter, verifier) = v4_public_pair();
        let c = sample_claims(10_000);
        let tok = minter.mint(&c).unwrap();
        let pub_bytes: [u8; 32] = verifier
            .public_key()
            .as_bytes()
            .try_into()
            .expect("v4 public key is 32 bytes");
        let rebuilt = PasetoV4PublicVerifier::from_public_key(&pub_bytes).unwrap();
        assert_eq!(rebuilt.verify_at(&tok, 5_000).unwrap(), c);
    }

    // ---- PasetoV4 v4.public — McpClaims mint/verify (wire convention) ------
    //
    // R592-B7: mint_mcp/verify_mcp_at now speak the SAME envelope as
    // kamaji-bin's verifier / cheers-mock / yubaba's minter — flat top-level
    // JSON, i64 exp/iat, kid in the footer, low-level PublicToken sign/verify.
    // A cross-shape token (session vs MCP) is no longer distinguished by an
    // additional-claim key; it's distinguished by footer presence (session
    // tokens never stamp one) and by claims deserialization (each shape's
    // required fields differ).

    use cheers_core::{
        Actor, AuthStrength, McpClaims, Owns, PrincipalId, Scope,
    };

    const TEST_KID: &str = "codec-test-kid-1";

    fn sample_mcp_claims(exp: i64) -> McpClaims {
        // Owns is #[non_exhaustive] in cheers-core, so build via Default +
        // field assignment from this crate.
        let mut owns = Owns::default();
        owns.service = vec!["svc-a".into()];
        owns.arch_doc = vec!["doc-1".into()];

        McpClaims::new(
            "https://cheers.example",
            "https://kamaji.camp.example",
            PrincipalId::user("alice"),
            1_000,
            exp,
            "jti-mcp-1",
            vec![Scope::CloudDeploy, Scope::CloudRead],
        )
        .with_act(Actor::new(PrincipalId::service("agent-claude")))
        .with_camp_id("camp-xyz")
        .with_owns(owns)
        .with_auth_strength(AuthStrength::UserFresh)
    }

    #[test]
    fn paseto_v4_public_mcp_roundtrip() {
        let (minter, verifier) = v4_public_pair();
        let c = sample_mcp_claims(10_000);
        let tok = minter.mint_mcp(&c, TEST_KID).unwrap();
        assert!(tok.starts_with("v4.public."));
        let back = verifier.verify_mcp_at(&tok, 5_000, TEST_KID).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn paseto_v4_public_mcp_rejects_expired() {
        let (minter, verifier) = v4_public_pair();
        let c = sample_mcp_claims(100);
        let tok = minter.mint_mcp(&c, TEST_KID).unwrap();
        let err = verifier.verify_mcp_at(&tok, 200, TEST_KID).unwrap_err();
        assert!(matches!(err, CodecError::Expired));
    }

    #[test]
    fn paseto_v4_public_mcp_rejects_wrong_key() {
        let (minter, _) = v4_public_pair();
        let (_, other_verifier) = v4_public_pair();
        let tok = minter.mint_mcp(&sample_mcp_claims(10_000), TEST_KID).unwrap();
        let err = other_verifier.verify_mcp_at(&tok, 5_000, TEST_KID).unwrap_err();
        assert!(matches!(err, CodecError::SignatureMismatch));
    }

    #[test]
    fn paseto_v4_public_mcp_rejects_unknown_kid() {
        // Same key, but the verifier only trusts TEST_KID — a token minted
        // under a different kid string is rejected before signature check.
        let (minter, verifier) = v4_public_pair();
        let tok = minter
            .mint_mcp(&sample_mcp_claims(10_000), "some-other-kid")
            .unwrap();
        let err = verifier.verify_mcp_at(&tok, 5_000, TEST_KID).unwrap_err();
        assert!(
            matches!(err, CodecError::UnknownKid(ref k) if k == "some-other-kid"),
            "got {err:?}"
        );
    }

    #[test]
    fn mcp_token_not_verifiable_under_session_verify_at() {
        // An MCP token is flat top-level JSON with i64 exp/iat — verify_at's
        // high-level pasetors::public::verify parses the payload through
        // Claims::from_string, which hard-rejects a numeric registered claim.
        // The two shapes can't be confused even though both are valid
        // v4.public signatures from the same key.
        let (minter, verifier) = v4_public_pair();
        let tok = minter.mint_mcp(&sample_mcp_claims(10_000), TEST_KID).unwrap();
        let err = verifier.verify_at(&tok, 5_000).unwrap_err();
        assert!(
            matches!(err, CodecError::Crypto(ref msg) if msg.contains("InvalidClaim")),
            "got {err:?}"
        );
    }

    #[test]
    fn session_token_not_verifiable_under_mcp_verify_at() {
        // The inverse: a session token never stamps a footer at all, so
        // verify_mcp_at's kid-in-footer requirement rejects it up front.
        let (minter, verifier) = v4_public_pair();
        let tok = minter.mint(&sample_claims(10_000)).unwrap();
        let err = verifier.verify_mcp_at(&tok, 5_000, TEST_KID).unwrap_err();
        assert!(matches!(err, CodecError::MissingKid), "got {err:?}");
    }

    #[test]
    fn paseto_v4_public_mcp_verifier_derives_from_minter() {
        // Parity with the session path: the derived verifier verifies what the
        // same minter produces.
        let (minter, _) = v4_public_pair();
        let derived = minter.verifier().unwrap();
        let c = sample_mcp_claims(10_000);
        let tok = minter.mint_mcp(&c, TEST_KID).unwrap();
        assert_eq!(derived.verify_mcp_at(&tok, 5_000, TEST_KID).unwrap(), c);
    }
}
