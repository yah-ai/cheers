//! # cheers-core — auth contract surface
//!
//! Pure types and traits shared between cheers's providers and downstream
//! consumers (mesofact, yah-platform, …). No I/O, no platform code.
//!
//! See the design doc at `.yah/docs/working/cheers.md` and the build plan at
//! `.yah/docs/working/cheers-plan.md`.
//!
//! @yah:ticket(R019-F3, "SessionAuthority (origin) + EdgeVerifier (edge) facades + SessionPolicy TTL defaults + jti in Claims")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-05-26T17:52:52Z)
//! @yah:status(review)
//! @yah:parent(R019)
//! @yah:next("Add SessionAuthority { minter, refresh: RefreshStore, users: UserStore, revoke: RevocationWriter } (origin) and EdgeVerifier { verifier: TokenVerifier, revoked: RevocationReader } (edge). EdgeVerifier takes a TokenVerifier so it physically cannot mint.")
//! @yah:next("Add SessionPolicy with sane TTL defaults (access ≈ minutes, refresh ≈ days) so consumers don't pick the wrong durations.")
//! @yah:next("Add a jti field to Claims (claims.rs, #[non_exhaustive] — additive) so the revocation set has a key.")
//! @yah:next("Do AFTER the trait split (R019-F1), the asymmetric codec, and the revocation traits — it assembles all three into the two deployment-tier facades.")
//! @yah:verify("cd external/cheers && cargo test -p cheers-core")
//! @yah:verify("cd external/cheers && cargo check --workspace --all-features")
//! @yah:gotcha("Claims (claims.rs) is the documented mesofact<->cheers contract and #[non_exhaustive]; adding jti is additive but coordinate with the R009/R011 mesofact resolver swap so the cookie format stays in sync.")
//! @arch:see(.yah/docs/working/edge-verifiable-auth.md)
//! @yah:depends_on(R019-F1)
//! @yah:depends_on(R019-F4)
//! @yah:handoff("Landed both facades in new session.rs (exported from lib.rs): SessionAuthority<M,R,U,W>{minter,refresh,users,revoke,policy} (origin) and EdgeVerifier<V,Rd>{verifier,revoked} (edge). Generic, not dyn, so the assembled capability set — and crucially the ABSENCE of a minter in EdgeVerifier — is a fact about the type, not a runtime convention. EdgeVerifier::new takes a TokenVerifier; there is no code path to mint.")
//! @yah:handoff("SessionPolicy: access_ttl=15min, refresh_ttl=30d defaults + const DEFAULT_*_TTL_SECONDS + with_access_ttl/with_refresh_ttl builders. SessionAuthority methods: establish (mint access w/ fresh jti + mint_root refresh chain), rotate (RefreshRotator::rotate + fresh access, binding passed in since the refresh record doesn't carry it), revoke_session(jti) -> RevocationWriter::revoke, revoke_device -> UserStore::revoke_device. EdgeVerifier::verify_at = signature-verify (gates the read) THEN is_revoked check -> Error::Revoked.")
//! @yah:handoff("Depends on R019-F4 (RevocationReader/RevocationWriter) which I did first per maintainer ordering — it's in review. jti landed under F4 (its revocation key); this ticket assembles it. Added Error::Refresh(#[from] RefreshError) + Error::Revoked variants (additive, #[non_exhaustive]).")
//! @yah:handoff("Verified GREEN: cargo test -p cheers-core (51 unit incl. 6 session-facade tests covering establish/rotate/edge-accept-then-revoke/expired-before-revocation/policy-defaults/revoke_device, 9 proptest, 3 doctest) + cargo check --workspace --all-features. cargo doc has no new broken intra-doc links (the asymmetric/symmetric forward refs from F4 now resolve).")
//!
//! @yah:ticket(R019-F5, "Factor the no-crypto client surface (Claims + CredentialStore) so device targets do not compile the codec")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-05-27T06:02:55Z)
//! @yah:status(review)
//! @yah:parent(R019)
//! @yah:verify("cd external/cheers && cargo tree -p <client-crate> shows no pasetors/hmac/getrandom (or: cargo check -p cheers-core --no-default-features after gating)")
//! @yah:verify("cd external/cheers && cargo check --workspace --all-features")
//! @yah:gotcha("apple/native.rs AppleNativeVerifier is SERVER-side despite \"native\" in the name. \"Native\" = the native-platform Apple Sign In flow (no code exchange), not \"runs on device\". The device just invokes ASAuthorizationController and POSTs the id_token up; the origin verifies. Do not let the filename pull verification onto the client.")
//! @yah:gotcha("A browser needs ~zero cheers Rust: OAuth redirect / navigator.credentials / form-POST are JS, and the session lands in an httpOnly cookie the page cannot read. The real client-Rust consumer is iOS/Android/desktop native apps (Tauri/uniffi).")
//! @yah:gotcha("P8/P9/P10 impls are not written yet (no cheers/src/store or native dir) — set the crate boundary NOW, before there is anything to migrate. Pre-launch is the cheapest this will ever be.")
//! @yah:assumes("The device tier touches no token bytes — it acquires an opaque token and stores it, never minting or verifying. That absence is the license to give it a crypto-free dependency.")
//! @arch:see(.yah/docs/working/edge-verifiable-auth.md)
//! @yah:next("cheers-core is monolithic and un-feature-gated: any consumer (including a browser/iOS/Android client that only acquires + stores an opaque token) compiles in pasetors/hmac/sha2/subtle/getrandom — the entire mint/verify/refresh machinery it never calls.")
//! @yah:next("Option A (clean): extract Claims + Credential + CredentialStore into a thin no-crypto crate (cheers-client or cheers-types) with zero crypto deps; have cheers-core depend on it for the shared types. Option B (cheaper): feature-gate cheers-core so default-features=false yields only the identity types + CredentialStore, with codec/refresh/UserStore/RefreshStore behind a \"server\" feature.")
//! @yah:next("Device-Rust surface = CredentialStore (local keychain) + identity types + the planned P9 native passkey UX glue. It needs zero codec/verify/mint/openidconnect/argon2/webauthn-rs. This is the third, thinnest tier below the edge — pairs with the R019-F3 SessionAuthority/EdgeVerifier facades.")
//! @yah:next("LEAD PLATFORM: Android is the first dogfood consumer (Android -> authenticate into a yah camp), so cheers-android (Credential Manager + native UX, target_os=android) + cheers-store are the first client crates to build, ahead of cheers-apple/iOS. iOS is harder due to background-execution + Local Network privacy, not traversal. Transport rides xlb-net/iroh; see edge-verifiable-auth.md Crate topology.")
//! @yah:handoff("Feature-gated cheers-core (Option B). Crypto deps (pasetors/hmac/sha2/subtle/base64/getrandom) are now optional, pulled only by a default-on `server` feature. --no-default-features yields the no-crypto client surface.")
//! @yah:handoff("Always-compiled (no-crypto) surface: claims (identity types), store traits (CredentialStore/UserStore/RefreshStore + records), revocation traits (RevocationReader/Writer), and the keyless codec traits TokenMinter/TokenVerifier/Codec + CodecError + Error/Result. A device crate can hold a `dyn TokenVerifier` without compiling a codec.")
//! @yah:handoff("Behind `server`: codec concrete impls (PasetoV4Codec, HmacBlobCodec, PasetoV4SecretMinter, PasetoV4PublicVerifier) + the pasetors From impl, the whole refresh and session modules, and error.rs's Refresh(RefreshError) variant. codec_proptests.rs is #![cfg(feature=server)].")
//! @yah:handoff("Verified GREEN: cargo check -p cheers-core --no-default-features (crypto-free tree confirmed via cargo tree); cargo test -p cheers-core (default); cargo check --workspace + --all-features. cheers consumer needed no changes (depends on cheers-core default = server).")
//! @yah:handoff("For F6: the server/non-server feature boundary IS the target crate boundary. Promote the `server`-gated modules into cheers-verify (PublicVerifier+RevocationReader+EdgeVerifier) and cheers-server (SecretMinter+symmetric codecs+stores+SessionAuthority); the keyless traits stay in cheers-core so cheers-verify can name TokenVerifier.")
//!
//! @yah:relay(R020, "MCP auth and ownership — principal kinds, ownership table, mint paths, audit")
//! @yah:at(2026-06-04T01:34:48Z)
//! @yah:status(open)
//! @yah:next("Resolve wire-envelope open question (PASETO v4.public vs JWT/Ed25519) in the -S1 spike before any mint-path ticket starts.")
//! @yah:next("Land foundation tickets (principal kinds, scope vocab, ownership table) in cheers-core/cheers-server before mint paths.")
//! @yah:next("Mint paths, admin endpoints, JWKS, audit can ship in parallel once the foundation is in.")
//! @yah:verify("cargo test -p cheers-core && cargo test -p cheers-server && cargo test -p cheers-verify")
//! @yah:gotcha("This relay PRODUCES the wire contract that yah's constable consumes. Any wire-shape change here is a coordinated change with yah's R426/R427/R428 — flag the yah-side relay in any handoff.")
//! @yah:gotcha("ownership:write and audit:write are kind=service ONLY. The grant API must reject (principal_kind=user, scope=ownership:write|audit:write) at write time, not just at mint.")
//! @yah:assumes("R019-F5/F6 crate split is effectively landed (in review) — MCP-token mint paths bolt onto cheers-server's signer; cheers-verify verifies them unchanged.")
//! @yah:assumes("yah-side consumer spec (W159) keeps the wire claim shapes verbatim with this doc (act, owns, camp_id, auth_strength).")
//! @arch:see(.yah/docs/working/mcp-auth-and-ownership.md)
//! @arch:see(.yah/docs/working/edge-verifiable-auth.md)
//! @yah:depends_on(R019-F6)

pub mod claims;
pub mod codec;
pub mod delegation;
pub mod error;
pub mod mcp;
pub mod principal;
pub mod store;

pub use claims::{Claims, Credential, DeviceBinding, DeviceId, User, UserId};
pub use delegation::{DelegationError, UserDelegation};
// The keyless capability traits + the codec error. The verify/mint impls that
// satisfy these live in cheers-verify / cheers-server — cheers-core ships only
// the contract, so a device or verify-only consumer can name `TokenVerifier`
// (e.g. hold a `dyn TokenVerifier`) without compiling any crypto.
pub use codec::{Codec, CodecError, TokenMinter, TokenVerifier};
pub use error::{Error, RefreshError, Result};
pub use mcp::{
    validate_grant, Actor, AuthStrength, GrantError, McpClaims, Owns, Scope, ScopeParseError,
};
pub use principal::{
    Principal, PrincipalError, PrincipalId, PrincipalIdParseError, PrincipalKind, PrincipalStatus,
};
pub use store::{CredentialStore, StoreError};
