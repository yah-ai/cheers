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
//!
//! @yah:ticket(R731-F6, "JWKS-backed verifier with key roles in cheers-verify; McpAuthState holds a key set (D5)")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:at(2026-10-06T23:20:54Z)
//! @yah:phase(P2)
//! @yah:parent(R731)
//! @yah:next("Doc D5. Lift the W159 cache from kamaji (oss/kamaji/crates/kamaji-bin/src/auth/jwks.rs: first fetch, atomic refresh, rate-limited kid-miss refetch, restart from disk) into cheers-verify, then move kamaji onto it.")
//! @yah:next("Enforce key roles: issuer signs any sub; assertion is never valid here; self-signer only for sub = its own svc and within a cheers-issued ceiling shaped like UserDelegation (cheers-core/src/delegation.rs). Build the enforcement now with zero self-signers.")
//! @yah:next("cheers already caches Apple JWKS (crates/cheers/src/providers/apple/jwks_cache.rs); check for reuse before writing a third cache.")
//! @yah:tier(Warrior)
//! @yah:gotcha("Scheduling edge (leader, 2026-10-06): F6 edits cheers-verify, and F2 rewrites McpClaims.scope there, so F6 waits for F2 too.")
//! @yah:depends_on(R731-B1)
//! @yah:depends_on(R731-F2)
//! @yah:handoff("cheers-core: new ceiling.rs — ServiceCeiling {principal (must be svc), audiences, scopes: Vec<Scope>, issued_at, expires_at} + CeilingError, validated on new() and on deserialize; helpers is_expired_at/allows_audience/covers. McpClaims gains `ceiling: Option<String>` (serde default + skip_serializing_if None, golden fixtures unchanged) and with_ceiling(). McpClaims is #[non_exhaustive], so the only cheers literal was McpClaims::new; kamaji's ~15 literals are kamaji's OWN McpClaims type and needed no field (the role view reads `ceiling` from the raw payload).")
//! @yah:handoff("cheers-verify: new jwks.rs = kamaji's W159 cache MOVED (JwkKey, JwksDoc, KeyEntry{public_key,principal,role}, KeySet, JwksError, JwksSource trait, JwksCacheConfig, JwksCache::boot/refresh/keys/keys_for, load_from_disk/write_atomic with format-2 discard rule and per-writer staging names). HttpJwksSource behind new feature `jwks-http` (default off; reqwest optional). No tokio in cheers-verify: std locks, sync file I/O; the periodic tick stays with the caller (kamaji spawns it). New deps: base64, serde, thiserror, tracing; dev tempfile.")
//! @yah:handoff("cheers-verify: new key_set.rs — KeySetVerifier (from_key_set / from_cache / from_issuer_key) with async verify<T>(token, now, expected_iss, expected_aud: Option) and verify_mcp. Footer kid -> entry; assertion role refused before crypto; signature; iss/aud/exp; self-signer: sub == key principal, ceiling present, ceiling kid is an issuer-role key in the same set, ceiling sig valid, principal == sub, unexpired, aud in audiences, scopes subset. VerifyError replaces kamaji's (NotIssuerKey -> KeyRoleRejected{kid,role,reason}).")
//! @yah:handoff("cheers-axum: McpAuthState is {verifier: Arc<KeySetVerifier>, expected_iss, expected_aud}; new(PasetoV4PublicVerifier, kid, iss, aud) builds the static one-issuer-key set, from_key_set(KeySetVerifier, iss, aud) takes a JwksCache-backed one. authenticate_mcp and verify_mcp_bearer are now async (expected_kid param dropped); .await added at audit.rs x2, ownership.rs x3, camps.rs, tokens.rs. ApiTokenTrust likewise holds a KeySetVerifier (expected_kid field removed). cheers-axum gains a direct cheers-verify dep.")
//! @yah:handoff("kamaji-bin: auth/jwks.rs DELETED; AuthVerifier now wraps cheers_verify::JwksCache (HttpJwksSource) + KeySetVerifier, keeping boot(AuthConfig)/verify/refresh/spawn_refresh_task; with_jwks -> jwks() returning Arc<KeySet>. error.rs re-exports cheers_verify::{JwksError, VerifyError}; AuthError renamed JwksError (config.rs, lib.rs). deny.rs/audit record.rs map KeyRoleRejected (audit tag now `key_role_rejected`, was `not_issuer_key`). Cargo: cheers-verify path dep with jwks-http; base64ct dropped; pasetors moved to dev-deps. claim/policy/deny layers unchanged.")
//! @yah:handoff("Apple JWKS cache (crates/cheers/src/providers/apple/jwks_cache.rs, RS256) left alone: different key type and crate. Moving kamaji's cache keeps the count of JWKS caches at two, not three.")
//! @yah:handoff("Tests: cheers workspace 683 passed / 0 failed / 3 ignored (baseline 652/0/3; +23 are mine: 3 ceiling, 11 jwks, 9 key_set incl. the six required role cases; remainder presumably peer F3). kamaji-bin auth 63 passed (baseline 72; the 9 jwks/kid-miss tests moved to cheers-verify, none lost). kamaji-bin --test mock_issuer_boot 2/2. No git writes (policy defer).")
//! @yah:verify("cd oss/cheers && cargo test --workspace (683/0/3)")
//! @yah:verify("cd oss/cheers && cargo test -p cheers-verify --all-features (key_set::tests: issuer ok, assertion rejected, self-signer no ceiling / wrong sub / over-ceiling / non-issuer ceiling / expired ceiling / foreign aud rejected, within ceiling accepted)")
//! @yah:verify("cd oss/kamaji && cargo test -p kamaji-bin auth (63) && cargo test -p kamaji-bin --test mock_issuer_boot (2)")
//! @yah:assumes("Self-signed tokens must carry iss == the verifier's expected cheers issuer (same rule as issuer-signed); the ceiling, not iss, carries cheers's authority. Revisit if F5 mints self-signed tokens with iss = svc.")
//! @yah:verify("Leader re-verify 2026-10-06: cargo test -p kamaji-bin (full, not just auth) 242 pass / 0 fail; cheers workspace 686 pass / 0 fail / 3 ignored, no build skew.")

use cheers_core::{Claims, CodecError, McpClaims, SignedArtifact, TokenVerifier};
use pasetors::claims::ClaimsValidationRules;
use pasetors::keys::AsymmetricPublicKey;
use pasetors::public;
use pasetors::token::UntrustedToken;
use pasetors::version4::{PublicToken, V4};

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

/// Derive the `kid` for a 32-byte Ed25519 public key: the first 16 bytes of its
/// SHA-256, base64url-unpadded.
///
/// *Derived* rather than random, so the minting side and every verifier compute
/// the same value from the key alone and a key rotation changes it for free. A
/// hand-copied kid would silently go stale on rotation; compute it here.
pub fn kid_for(public_key: &[u8; 32]) -> String {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(public_key);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..16])
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

    /// Verify an MCP-call token signed by
    /// `cheers_server::PasetoV4SecretMinter::mint_mcp`, returning the
    /// embedded [`McpClaims`].
    ///
    /// **Wire convention** (R592-B7) — the shape kamaji-bin's verifier,
    /// `cheers-mock`, and yubaba's minter already share: `claims` is the
    /// token's FLAT top-level JSON payload (no wrapping claim key), verified
    /// via pasetors' LOW-LEVEL [`PublicToken::verify`] — never the high-level
    /// `public::verify`, which hard-rejects the i64 `exp`/`iat` this shape
    /// carries.
    ///
    /// `kid` is REQUIRED in the PASETO footer: an empty footer is
    /// [`CodecError::MissingKid`]; a footer that doesn't parse or has no
    /// `kid` field is [`CodecError::Malformed`]; a `kid` that doesn't match
    /// `expected_kid` is [`CodecError::UnknownKid`] (this verifier holds a
    /// single trusted `(kid, public key)` pair — it has no JWKS of its own,
    /// so "does the footer's kid match the one caller I trust" is the whole
    /// key-selection check here; a full JWKS lookup across many kids is a
    /// consumer's job, e.g. kamaji-bin's `AuthVerifier`).
    ///
    /// Expiry is owned by [`McpClaims::is_expired_at`] (parity with the
    /// session-claim path) — `exp <= now` is [`CodecError::Expired`].
    /// `iss`/`aud` are NOT checked here — that policy varies per consumer
    /// (which issuer/audience a caller expects), so it lives at the caller
    /// (e.g. `cloud-admin`'s `viewer_from_claims`), not in this shared
    /// primitive.
    pub fn verify_mcp_at(
        &self,
        token: &str,
        now: i64,
        expected_kid: &str,
    ) -> Result<McpClaims, CodecError> {
        let untrusted = UntrustedToken::<pasetors::token::Public, V4>::try_from(token)
            .map_err(|_| CodecError::Malformed)?;

        // Footer/kid check BEFORE the crypto check — cheap, and it's the
        // key-selection signal a real multi-kid verifier would need anyway.
        // The footer bytes are bound into the signature regardless of when
        // we read them, so this ordering doesn't weaken anything.
        let footer_bytes = untrusted.untrusted_footer();
        if footer_bytes.is_empty() {
            return Err(CodecError::MissingKid);
        }
        let footer: serde_json::Value =
            serde_json::from_slice(footer_bytes).map_err(|_| CodecError::Malformed)?;
        let kid = footer
            .get("kid")
            .and_then(|v| v.as_str())
            .ok_or(CodecError::Malformed)?;
        if kid != expected_kid {
            return Err(CodecError::UnknownKid(kid.to_string()));
        }

        let trusted = PublicToken::verify(&self.public, &untrusted, None, None).map_err(codec_err)?;
        let out: McpClaims = serde_json::from_str(trusted.payload())?;
        if out.is_expired_at(now) {
            return Err(CodecError::Expired);
        }
        Ok(out)
    }

    /// Verify a [`SignedArtifact`] (R732-F6) under this pinned key and return
    /// its payload.
    ///
    /// A pinned key is the issuer key by configuration, so there is no kid or
    /// role to check; the signature must carry `T::IMPLICIT_ASSERTION`, which
    /// is what keeps an access token from verifying here and an artifact from
    /// verifying as one. The payload's issuer is the caller's to check (see
    /// `IssuerTrust`). No clock: artifacts have no edge-enforced expiry.
    pub fn verify_artifact<T: SignedArtifact>(&self, token: &str) -> Result<T, CodecError> {
        let untrusted = UntrustedToken::<pasetors::token::Public, V4>::try_from(token)
            .map_err(|_| CodecError::Malformed)?;
        let trusted = PublicToken::verify(&self.public, &untrusted, None, Some(T::IMPLICIT_ASSERTION))
            .map_err(codec_err)?;
        Ok(serde_json::from_str(trusted.payload())?)
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
    fn kid_for_is_stable_distinct_and_22_chars() {
        let k = [7u8; 32];
        assert_eq!(kid_for(&k), kid_for(&k));
        assert_ne!(kid_for(&k), kid_for(&[8u8; 32]));
        assert_eq!(kid_for(&k).len(), 22);
    }

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
