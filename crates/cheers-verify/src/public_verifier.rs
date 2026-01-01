//! PASETO v4.public **verifier** — the edge-safe half of the asymmetric codec.
//!
//! The origin holds the secret-key minter (`cheers_server::PasetoV4SecretMinter`);
//! the edge holds *only* the public-key verifier here, which can check a
//! signature but is physically unable to forge one. Both reuse the v4.local
//! payload convention — the cheers [`Claims`] ride under a single `"cheers"`
//! additional claim, with PASETO's own `exp` left non-expiring so that
//! `verify_at(now)` owns the expiry decision (parity with the symmetric impls).
//!
//! v4.public signs the payload in the clear, so anything minted this way is
//! readable by whoever holds the token: only non-secret claims (identity +
//! expiry + jti) belong in an access token.

use cheers_core::{Claims, CodecError, McpClaims, TokenVerifier};
use pasetors::claims::ClaimsValidationRules;
use pasetors::keys::AsymmetricPublicKey;
use pasetors::public;
use pasetors::token::UntrustedToken;
use pasetors::version4::V4;

/// Additional-claim key under which [`McpClaims`] ride a PASETO v4.public token.
///
/// Distinct from the session-claim key (`"cheers"`) so a verifier can't
/// silently deserialize the wrong shape: an MCP token has no `"cheers"` claim,
/// a session token has no `"mcp"` claim, and either mix-up surfaces as
/// [`CodecError::Malformed`]. Exported so the matching origin minter in
/// `cheers-server` writes under the same key.
pub const MCP_CLAIM_KEY: &str = "mcp";

/// Map a `pasetors` crypto-library error into the shared [`CodecError`].
///
/// Lives here rather than as `impl From<pasetors::errors::Error> for CodecError`
/// because the orphan rule would force that impl into `cheers-core`, dragging
/// pasetors into the keyless contract crate. `cheers-server`'s symmetric codecs
/// reuse this via `cheers_verify::codec_err`.
pub fn codec_err(e: pasetors::errors::Error) -> CodecError {
    use pasetors::errors::Error as P;
    match e {
        P::TokenValidation => CodecError::SignatureMismatch,
        P::ClaimValidation(_) => CodecError::Expired,
        other => CodecError::Crypto(format!("{other:?}")),
    }
}

/// PASETO v4.public **verifier** — checks signatures with an Ed25519 public key.
///
/// The edge-safe half of v4.public: a public key can *verify* a token but is
/// physically unable to *mint* one. It is the only [`TokenVerifier`] in the
/// cheers tree that doesn't also carry minting power (the symmetric codecs in
/// `cheers-server` are [`Codec`](cheers_core::Codec)s, so they do) — which is
/// exactly what lets an edge (e.g. a CF Worker) authenticate sessions without the
/// forge-any-session blast radius of holding a minting key. Pair with a
/// `cheers_server::PasetoV4SecretMinter` at the origin.
pub struct PasetoV4PublicVerifier {
    public: AsymmetricPublicKey<V4>,
}

impl PasetoV4PublicVerifier {
    /// Build from a 32-byte Ed25519 public key (the V4 public-key size).
    pub fn from_public_key(bytes: &[u8; 32]) -> Result<Self, CodecError> {
        let public = AsymmetricPublicKey::<V4>::from(bytes)
            .map_err(|e| CodecError::Crypto(format!("{e:?}")))?;
        Ok(Self { public })
    }

    /// Wrap an already-parsed Ed25519 public key — e.g. the half a minter derives
    /// from its secret key (`cheers_server::PasetoV4SecretMinter::verifier`).
    pub fn from_key(public: AsymmetricPublicKey<V4>) -> Self {
        Self { public }
    }

    /// The underlying public key, e.g. to serialize the 32 bytes for publishing
    /// to an edge.
    pub fn public_key(&self) -> &AsymmetricPublicKey<V4> {
        &self.public
    }

    /// Verify an MCP-call token signed by `cheers_server::PasetoV4SecretMinter::mint_mcp`,
    /// returning the embedded [`McpClaims`].
    ///
    /// Sibling to the session-token [`verify_at`](Self::verify_at) path: same
    /// PASETO v4.public signature check, but reads the `"mcp"` additional claim
    /// instead of `"cheers"` and parses it into [`McpClaims`]. Expiry is owned
    /// by [`McpClaims::is_expired_at`] (parity with the session-claim path) —
    /// `exp <= now` is [`CodecError::Expired`].
    ///
    /// A token minted for the session shape (`"cheers"` claim, no `"mcp"`)
    /// surfaces here as [`CodecError::Malformed`] — the key separation is the
    /// structural guard against confusing the two claim shapes.
    pub fn verify_mcp_at(&self, token: &str, now: i64) -> Result<McpClaims, CodecError> {
        let untrusted = UntrustedToken::<pasetors::token::Public, V4>::try_from(token)
            .map_err(|_| CodecError::Malformed)?;
        let mut rules = ClaimsValidationRules::new();
        rules.allow_non_expiring();
        let trusted = public::verify(&self.public, &untrusted, &rules, None, None)
            .map_err(codec_err)?;
        let pclaims = trusted.payload_claims().ok_or(CodecError::Malformed)?;
        let v = pclaims
            .get_claim(MCP_CLAIM_KEY)
            .ok_or(CodecError::Malformed)?
            .clone();
        let out: McpClaims = serde_json::from_value(v)?;
        if out.is_expired_at(now) {
            return Err(CodecError::Expired);
        }
        Ok(out)
    }
}

impl TokenVerifier for PasetoV4PublicVerifier {
    fn verify_at(&self, token: &str, now: i64) -> Result<Claims, CodecError> {
        let untrusted = UntrustedToken::<pasetors::token::Public, V4>::try_from(token)
            .map_err(|_| CodecError::Malformed)?;
        // Skip pasetors's wall-clock validation; enforce `now` ourselves for
        // testability and parity with the symmetric impls.
        let mut rules = ClaimsValidationRules::new();
        rules.allow_non_expiring();
        let trusted = public::verify(&self.public, &untrusted, &rules, None, None)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_malformed() {
        let verifier = PasetoV4PublicVerifier::from_public_key(&[0u8; 32]).unwrap();
        assert!(matches!(
            verifier.verify_at("not-a-paseto", 0).unwrap_err(),
            CodecError::Malformed
        ));
    }

    #[test]
    fn codec_err_maps_token_validation_to_signature_mismatch() {
        let e = codec_err(pasetors::errors::Error::TokenValidation);
        assert!(matches!(e, CodecError::SignatureMismatch));
    }

    // The full mint -> verify -> expiry round-trip lives in cheers-server's
    // tests: minting needs the secret key, which is origin-only and therefore
    // not reachable from this verify-only crate (the property under test).
}
