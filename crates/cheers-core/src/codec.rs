//! Session-token **capability traits** and the shared [`CodecError`].
//!
//! Tokens split along the **mint/verify capability axis** (R019): [`TokenMinter`]
//! can forge sessions (origin-only); [`TokenVerifier`] only checks them
//! (edge-safe). Whether one key does both jobs is the codec's defining property.
//!
//! This module is the **keyless** half of that split — only the trait
//! *definitions* and the shared error type. No keys, no crypto: the concrete
//! codecs live in crates layered above `cheers-core`, so a verify-only consumer
//! never compiles a minter:
//!
//! - **Symmetric** ([`Codec`]) — one key both mints *and* verifies, so any holder
//!   can forge. `PasetoV4Codec` (v4.local, encrypted) and `HmacBlobCodec`
//!   (HMAC-SHA256, cleartext) live in `cheers-server`, origin-side.
//! - **Asymmetric** (Ed25519, v4.public) — mint and verify are *different* keys,
//!   so the edge can verify without the power to mint. `PasetoV4SecretMinter`
//!   lives in `cheers-server`; the matching `PasetoV4PublicVerifier` lives in
//!   `cheers-verify` — the only [`TokenVerifier`] that *cannot* also mint, which
//!   is exactly what makes edge verification safe.
//!
//! All impls reject expired tokens during `verify`, enforced against the caller's
//! `now` in `verify_at` rather than the crypto layer's wall clock. A runnable
//! mint/verify round-trip lives in `cheers-server`'s codec module — `cheers-core`
//! ships no concrete codec to exercise.
//!
//! @yah:relay(R019, "Edge-verifiable session auth: mint/verify split + asymmetric codec + access/refresh tiers + revocation")
//! @yah:at(2026-05-26T17:51:47Z)
//! @yah:status(open)
//! @yah:next("Full design, the locality contract, and the five implementation moves are in .yah/docs/working/edge-verifiable-auth.md; each move is filed as a child feature under this relay.")
//! @yah:next("Suggested quest placement: foundation (Q002) owns the core codec/claims/store changes; the driver is the yah-platform edge deployment (Q005). Filed standalone to avoid presuming where it slots — maintainers reparent.")
//! @yah:gotcha("The current Codec (PasetoV4Codec v4.local / HmacBlobCodec) is SYMMETRIC — the same key mints AND verifies. Edge verification therefore can't be done without shipping minting power to the CF edge (forge-any-session blast radius). The asymmetric codec is the prerequisite for ANY edge verification; do not edge-verify the symmetric token.")
//! @yah:gotcha("cheers is pre-launch, so splitting the Codec trait can be a breaking change; a blanket impl keeps PasetoV4Codec/HmacBlobCodec working as both minter and verifier.")
//! @yah:gotcha("Consumer mapping (yah side): mesofact CF Worker (yah R327) = EdgeVerifier; mesofact axum SSR origin = SessionAuthority; Warden backs RefreshStore + RevocationWriter.")
//! @yah:assumes("Auth has no cross-session OLTP (every check validates one session) — that licenses a stateless/global access token and an eventually-consistent revocation set. Only refresh replay-detection needs consistency, and it's homed (origin/Warden) on the cold path.")
//! @arch:see(.yah/docs/working/edge-verifiable-auth.md)
//!
//! @yah:ticket(R019-F1, "Split Codec into TokenMinter + TokenVerifier traits")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-05-26T17:52:34Z)
//! @yah:status(review)
//! @yah:parent(R019)
//! @yah:next("Split the Codec trait (codec.rs) into TokenVerifier { verify_at(&str, now) -> Claims } and TokenMinter { mint(&Claims) -> String }.")
//! @yah:next("Impl BOTH traits on PasetoV4Codec and HmacBlobCodec (symmetric: one key mints+verifies) so existing callers keep working AND so the type signature documents that a symmetric codec at the edge carries minting power.")
//! @yah:next("Keystone for the relay: the edge depends only on TokenVerifier; the sole way to satisfy it verify-but-can't-mint is the asymmetric verifier (sibling: asymmetric PasetoV4Public codec).")
//! @yah:verify("cd external/cheers && cargo test -p cheers-core")
//! @yah:verify("cd external/cheers && cargo check --workspace --all-features")
//! @arch:see(.yah/docs/working/edge-verifiable-auth.md)
//! @yah:handoff("Codec split landed (codec.rs). TokenMinter { mint } + TokenVerifier { verify_at, verify default }; both impl'd on PasetoV4Codec + HmacBlobCodec. Kept `Codec: TokenMinter + TokenVerifier` with blanket `impl<T: TokenMinter+TokenVerifier> Codec for T {}` so existing dyn Codec / impl Codec callers are unchanged. Exported both new traits from lib.rs. Updated codec doctest + proptest imports + a claims.rs doc ref. Verified: cargo test -p cheers-core (34 unit + 6 proptest + 3 doctest) and cargo check --workspace --all-features both green.")
//! @yah:handoff("Cross-camp: re-ran the R009 mesofact consumer (in review) after the split — ZERO source changes needed (supertrait methods resolve through Box<dyn Codec>); full mesofact suite green. So the R009 'needs a trait-import swap' next-note was conservative; the symmetric path is fully back-compat. The edge re-point happens at F2 (asymmetric verifier), not here.")
//! @yah:handoff("Next in relay: F2 (asymmetric PasetoV4Public minter/verifier) is unblocked — depends_on R019-F1, now satisfied. Edge code should name TokenVerifier, never Codec.")
//!
//! @yah:ticket(R019-F2, "Asymmetric access-token codec: PasetoV4Public (Ed25519) — verify-only public key, mint-only secret key")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-05-26T17:52:46Z)
//! @yah:status(review)
//! @yah:parent(R019)
//! @yah:next("Add PasetoV4PublicVerifier (impl TokenVerifier, holds AsymmetricPublicKey<V4>) and PasetoV4SecretMinter (impl TokenMinter, holds AsymmetricSecretKey<V4>) over pasetors' `public` module (V4 = Ed25519). Origin mints with the secret key; edge verifies with the public key ONLY.")
//! @yah:next("v4.public is signed-not-encrypted, so claims are client-readable — document that only non-secret claims (identity + expiry + jti) belong in the access token, and reposition v4.local as 'encrypted claims, origin-only verification'.")
//! @yah:next("verify_at must enforce `now` itself (mirror the symmetric impls' allow_non_expiring + is_expired_at pattern) rather than relying on pasetors' wall-clock validation.")
//! @yah:verify("cd external/cheers && cargo test -p cheers-core")
//! @yah:verify("cd external/cheers && cargo deny --all-features check")
//! @arch:see(.yah/docs/working/edge-verifiable-auth.md)
//! @yah:depends_on(R019-F1)
//! @yah:handoff("Landed PasetoV4SecretMinter (impl TokenMinter, AsymmetricSecretKey<V4>) + PasetoV4PublicVerifier (impl TokenVerifier ONLY, AsymmetricPublicKey<V4>) over pasetors::public (v4.public/Ed25519). Both reuse the v4.local payload convention (Claims under a 'cheers' additional claim, PASETO exp left non_expiring so verify_at(now) owns expiry). Exported both from lib.rs.")
//! @yah:handoff("Constructors: from_secret_key(&[u8;64] seed||pk), from_public_key(&[u8;32]), SecretMinter::generate()->(minter,verifier), SecretMinter::verifier() derives the public half. Edge gets verify-but-can't-mint: PasetoV4PublicVerifier does NOT impl TokenMinter.")
//! @yah:handoff("Verified GREEN: cargo test -p cheers-core (40 unit + 9 proptest + 3 doctest) and cargo check --workspace --all-features.")
//! @yah:handoff("Next: F3 can now assemble SessionAuthority{minter:PasetoV4SecretMinter,...} + EdgeVerifier{verifier:PasetoV4PublicVerifier,...}.")
//!
//! @yah:ticket(R019-F6, "Carve cheers-verify (PublicVerifier + RevocationReader + EdgeVerifier) into a verify-only crate; minter/symmetric-codecs/stores stay server-side")
//! @yah:at(2026-05-27T06:37:41Z)
//! @yah:status(review)
//! @yah:parent(R019)
//! @yah:next("Create cheers-verify holding PasetoV4PublicVerifier + RevocationReader + the EdgeVerifier facade. Depends on cheers-core (types + traits) and NOT on any minter — the edge consumes only this crate.")
//! @yah:next("Move PasetoV4SecretMinter + the symmetric codecs (PasetoV4Codec, HmacBlobCodec) + UserStore/RefreshStore/RevocationWriter + SessionAuthority into a cheers-server crate that depends on cheers-verify. The one load-bearing arrow: cheers-server -> cheers-verify, never the reverse.")
//! @yah:next("Capability boundary is enforced by the DAG, not a feature flag (a feature is additive and unifiable; a missing dep edge is a compile error). Full target topology in the design doc Crate topology section.")
//! @yah:verify("cd external/cheers && cargo tree -p cheers-verify shows no PasetoV4SecretMinter path and no UserStore/RefreshStore (verify-only)")
//! @yah:verify("cd external/cheers && cargo check --workspace --all-features")
//! @yah:gotcha("The symmetric codecs impl BOTH TokenMinter AND TokenVerifier on one type — they MUST land in cheers-server, never cheers-verify, or the edge regains mint power through the back door (the trap codec.rs already warns about in prose).")
//! @yah:gotcha("Does NOT fix wasm: pasetors sits in cheers-verify too and pulls getrandom via ed25519-compact even on the verify-only path. wasm32-unknown-unknown still needs getrandom wasm_js backend enabled (both 0.3 and 0.4 majors). Orthogonal to this split.")
//! @yah:assumes("R019-F3 (EdgeVerifier facade) and R019-F4 (RevocationReader) land first or alongside — cheers-verify is where they live, so this carve-out assembles their output.")
//! @arch:see(.yah/docs/working/edge-verifiable-auth.md)
//! @yah:depends_on(R019-F3)
//! @yah:depends_on(R019-F4)
//! @yah:handoff("Carve done. 3-crate DAG: cheers-server -> cheers-verify -> cheers-core. cheers-core slimmed to the keyless contract (no crypto deps at all); the F5 `server` feature + optional crypto deps are GONE — the crate boundary replaced the feature gate, exactly as F5's handoff predicted.")
//! @yah:handoff("cheers-core now holds: claims (identity types), the full error vocabulary (CodecError/StoreError/RefreshError/Error/Result — all keyless), CredentialStore, and the TokenMinter/TokenVerifier/Codec traits + blanket impl. Nothing else.")
//! @yah:handoff("cheers-verify (-> cheers-core, pasetors, NO minter): PasetoV4PublicVerifier, RevocationReader, EdgeVerifier, plus `pub fn codec_err(pasetors::errors::Error)->CodecError`. cargo tree -p cheers-verify confirms cheers-core+pasetors but NO cheers-server path — the edge is minter-free by DAG, not by feature.")
//! @yah:handoff("cheers-server (-> cheers-verify -> cheers-core): PasetoV4SecretMinter + symmetric PasetoV4Codec/HmacBlobCodec, refresh rotation (RefreshToken/ChainId/Rotated/RefreshRotator), UserStore/RefreshStore/RefreshTokenRecord/ProviderKey/NewUser, RevocationWriter, SessionAuthority/SessionPolicy/NewSession. Re-exports EdgeVerifier/PasetoV4PublicVerifier/RevocationReader so an origin assembles both tiers from one crate.")
//! @yah:handoff("Two forced calls: (a) `From<pasetors::errors::Error> for CodecError` cannot live in keyless core (orphan rule) -> it is now `cheers_verify::codec_err`; cheers/email/magic_link.rs was RELYING on that From impl (not caught by a name grep — it used CodecError::from/.into()) and got a local `map_paseto_err`. (b) RefreshError stays in core (keyless) so the Error umbrella is unchanged and both facades still return cheers_core::Error.")
//! @yah:handoff("Verified GREEN: cargo check --workspace --all-features; cargo test --workspace (cheers 119+9doc, core 16+1doc, server 34+9proptest+2doc, verify 4); cargo tree -p cheers-verify (no cheers-server). Annotation blocks for R019/F1/F2/F4/F6 preserved across the codec.rs rewrite + store.rs trim.")
//! @yah:handoff("Concurrent work: cheers-store (device CredentialStore over OS keyring) landed mid-ticket and is now a workspace member. It depends on cheers-core with default-features=false — still correct, but post-F6 that flag is a redundant no-op (core has no features) and its Cargo.toml comment about core's 'default-on server feature' is now stale. Left untouched to avoid clobbering in-flight edits; trivial follow-up.")
//! @yah:handoff("Cross-camp (NOT this workspace): mesofact consumes cheers-core's Codec/PasetoV4Codec. Moving codec impls out of core WILL break mesofact's imports — it must add cheers-server (axum SSR / SessionAuthority) + cheers-verify (CF Worker / EdgeVerifier) per the consumer mapping. File under yah R327.")

use crate::claims::Claims;

/// Errors returned by [`TokenMinter::mint`] and [`TokenVerifier::verify`].
///
/// A coarse-grained shape: callers usually only care whether the token was
/// rejected, not why. `R007-T4` lands the workspace-wide error hierarchy and
/// this enum is re-exported from there. The crypto-library mapping (a
/// `pasetors::errors::Error` → `CodecError`) lives with the concrete codecs in
/// `cheers-verify`/`cheers-server`, since the orphan rule forbids it here without
/// pulling a crypto dependency into this keyless crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CodecError {
    /// Token bytes did not parse as the expected format.
    #[error("malformed token")]
    Malformed,
    /// Signature / MAC / AEAD tag did not verify against the key.
    #[error("signature mismatch")]
    SignatureMismatch,
    /// Token parsed and verified but `expires_at` has passed.
    #[error("token expired")]
    Expired,
    /// Underlying crypto library failure (key invalid, RNG, …).
    #[error("crypto: {0}")]
    Crypto(String),
    /// JSON (de)serialization of the claim payload failed.
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Mint session tokens carrying [`Claims`].
///
/// **Origin-only capability.** A type that can mint can forge *any* session, so
/// this is the trait the session authority (origin) holds — never the edge.
/// Splitting it out from [`TokenVerifier`] is the keystone of edge-verifiable
/// auth (R019): the edge depends on `TokenVerifier` alone, and the only way to
/// satisfy verify-but-can't-mint is an asymmetric *public* verifier
/// (`cheers_verify::PasetoV4PublicVerifier`).
pub trait TokenMinter {
    fn mint(&self, claims: &Claims) -> Result<String, CodecError>;
}

/// Verify session tokens into [`Claims`].
///
/// **The capability the edge depends on.** An asymmetric public verifier
/// (`cheers_verify::PasetoV4PublicVerifier`) satisfies this while being
/// physically unable to mint; a symmetric codec (`cheers_server`'s
/// `PasetoV4Codec` / `HmacBlobCodec`) satisfies it too, but only because it
/// *also* holds minting power — see [`Codec`].
pub trait TokenVerifier {
    /// Verify a token against `now` (unix seconds). Reject if `expires_at <= now`.
    fn verify_at(&self, token: &str, now: i64) -> Result<Claims, CodecError>;

    /// Convenience wrapper using the system clock.
    fn verify(&self, token: &str) -> Result<Claims, CodecError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.verify_at(token, now)
    }
}

/// A **symmetric** codec: one key both mints *and* verifies.
///
/// Blanket-impl'd for any type that is both a [`TokenMinter`] and a
/// [`TokenVerifier`], so existing `dyn Codec` / `impl Codec` callers keep
/// working unchanged. The supertrait bound makes the dual capability explicit
/// in the type: holding a `Codec` at the edge carries minting power — exactly
/// the property the asymmetric split designs out. Edge code should name
/// [`TokenVerifier`], not `Codec`.
///
/// The two built-in symmetric impls (`cheers_server`'s `PasetoV4Codec` and
/// `HmacBlobCodec`) guarantee that `verify(mint(c))` round-trips a non-expired
/// `c`, and that any single-bit tamper on the token causes `verify` to fail.
pub trait Codec: TokenMinter + TokenVerifier {}

impl<T: TokenMinter + TokenVerifier> Codec for T {}
