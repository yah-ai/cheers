//! Email magic-link tokens — PASETO v4.local with single-use enforcement.
//!
//! The flow has three moving pieces:
//!
//! - [`MagicLinkCodec`] — encrypts/authenticates a [`MagicLinkClaims`] payload
//!   under a 32-byte symmetric key. The payload pins `purpose: "magic-link"`
//!   so a session token can never be smuggled into a verify-magic-link call
//!   (and vice versa) even if the same key were reused.
//! - [`MagicLinkUrlBuilder`] — assembles the click-through URL the mailer
//!   will embed. The token rides the query string; the email is *inside* the
//!   token's claims, never as a separate query param. (See gotcha below.)
//! - [`UsedJtiStore`] — opaque single-use blacklist keyed by the token's
//!   `jti`. [`MagicLinkProvider::redeem`] verifies the token then atomically
//!   marks the `jti` as used; replays return [`MagicLinkError::AlreadyUsed`].
//!   A [`MemoryUsedJtiStore`] is provided for tests and dev.
//!
//! # One grant, two tracks, an optional code (CHE-R961, noisetable W275 §4)
//!
//! [`MagicLinkProvider::request`] may carry an S256 `challenge`
//! (`base64url(SHA-256(verifier))`, RFC 7636 §4.2). Every request mints one
//! grant with one `jti`:
//!
//! - `T_open` — today's `{email, jti, purpose, expires_at}`, a bearer token
//!   behind [`MagicLinkRequest::url`].
//! - `T_app` — the same claims plus `challenge` when one was sent (else
//!   `T_app` *is* `T_open`), behind [`MagicLinkRequest::app_url`]. It redeems
//!   only beside the matching `verifier`.
//! - a 6-digit code, only for a challenged request, stored in a
//!   [`MagicLinkCodeStore`] and redeemable beside the same `verifier`.
//!
//! [`MagicLinkProvider::redeem`] takes any of the three. Any successful
//! redemption marks the `jti` used *and* deletes the code row, so both links
//! and the code die together. There is deliberately no audience claim: a
//! public redeem route cannot tell an app from a browser, so `aud` would be a
//! claim nobody can check, whereas `challenge` is enforced by possession of
//! `verifier`.
//!
//! # Gotcha — keep the email *in* the token
//!
//! The verify URL must include the user's email in the token claim, **not**
//! as a separate query param. If the email lives outside the signed payload,
//! an attacker who steals one valid token (e.g. from a leaked email
//! forwarding chain) can re-aim it at any address by editing the URL.
//!
//! # Example
//!
//! ```
//! use cheers::email::magic_link::{
//!     MagicLinkCodec, MagicLinkProvider, MagicLinkRedemption, MagicLinkUrlBuilder,
//!     MemoryMagicLinkCodeStore, MemoryUsedJtiStore,
//! };
//!
//! # pollster::block_on(async {
//! let codec = MagicLinkCodec::new(&[7u8; 32], 15 * 60).unwrap();
//! let urls = MagicLinkUrlBuilder::new("https://app.example/auth/verify");
//! let provider = MagicLinkProvider::new(
//!     codec,
//!     urls,
//!     MemoryUsedJtiStore::new(),
//!     MemoryMagicLinkCodeStore::new(),
//! );
//!
//! let now = 1_700_000_000;
//! let req = provider.request("alice@example.com", None, now).await.unwrap();
//! assert!(req.url.starts_with("https://app.example/auth/verify?token=v4.local."));
//!
//! let open = MagicLinkRedemption::Token { token: &req.token, verifier: None };
//! let claims = provider.redeem(open, now + 30).await.unwrap();
//! assert_eq!(claims.email, "alice@example.com");
//!
//! // Replay rejected.
//! assert!(provider.redeem(open, now + 31).await.is_err());
//! # });
//! ```
//!
//! @yah:relay(R961, "Bound two-track magic-link grant: optional S256 challenge, one jti across two tokens, a 6-digit code store, POST /magic-link/redeem with bound_elsewhere, a two-action email seam (noisetable W275 T1)")
//! @yah:status(review)
//! @yah:at(2026-10-15T23:28:12Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:next("Spec: noisetable .yah/docs/working/W275-two-track-sign-in-email.md §4, §5, §7. Design decided by the operator (forms F1324, F1326); don't reopen. A request may carry challenge = base64url(SHA-256(verifier)) (RFC 7636 S256). One grant per request, one jti: T_open = today's {email, jti, purpose, expires_at}; T_app = the same plus challenge when one was sent, else T_app = T_open. No aud claim.")
//! @yah:next("Code-store trait + cheers-turso impl keyed by challenge: {jti, hash(C), challenge, attempts, expires_at = now + 600}; 6 digits, at most 5 attempts; minted only for a challenged request. Any successful redemption marks the jti in UsedJtiStore and deletes the code row, so both links and the code die together.")
//! @yah:next("POST /api/v1/auth/magic-link/redeem (cheers-axum magic_link.rs), body {token} | {token, verifier} | {code, verifier} per W275 §5's table. Constant-time code compare; a wrong code adds an attempt, the fifth kills the code but not the links. Refusals stay collapsed except bound_elsewhere (the token's challenge doesn't match the verifier). Keep GET .../verify until noisetable deletes /account's ?token= read.")
//! @yah:next("MagicLinkEmail seam in template.rs beside R733's without_greeting: two actions and an optional code line; render() stays the single renderer. Consumer: noisetable R983's account-service ticket, which carries @yah:burst(devcrate:cheers) until this publishes.")
//! @yah:verify("Tests: a challenge-bound token redeems only with the matching verifier and answers bound_elsewhere otherwise; an unbound token redeems with {token}; a code redeems once, then is refused, and is refused after 600 s; five wrong codes kill the code while the token still redeems; any one redemption burns the other two; the template renders two actions, and the code line only when given one.")
//! @yah:next("Noisetable consumers: R983-F3 (account service; carries @yah:burst(devcrate:cheers), and drops it once this ticket's cheers version is on crates.io) and R983-F9 (nt-session client, over HTTP only). Both declare depends_on(cheers/R961), so they open when this lands in review.")
//! @yah:handoff("Landed the bound two-track grant (W275 §4/§5/§7). cheers-core store.rs: MagicLinkCode + MagicLinkCodeStore trait (put / take_attempt / delete_for_jti) + MemoryMagicLinkCodeStore, re-exported from cheers::email::magic_link. take_attempt charges the attempt atomically BEFORE the compare, so concurrent guesses can't exceed 5. The row also carries email + grant_expires_at beyond W275's listed fields: a code redemption has no token to read them from.")
//! @yah:handoff("cheers email/magic_link.rs: MagicLinkClaims.challenge (serde-skipped when None, so T_open's payload is unchanged); MagicLinkProvider<S, C>::new(codec, urls, used, codes).with_app_urls(..); request(email, challenge: Option<&str>, now) mints T_open, T_app and (when challenged) a 6-digit code (hash = sha256(jti:code), rejection-sampled); redeem(MagicLinkRedemption::{Token{token, verifier}, Code{code, verifier}}, now) REPLACES consume(). Any success marks the jti AND deletes the code row. New errors: InvalidChallenge, BoundElsewhere, Refused(collapsed). Exported s256(); constants CODE_TTL_SECONDS=600, CODE_MAX_ATTEMPTS=5, CODE_DIGITS=6. MagicLinkUrlBuilder::in_fragment() puts #token= in the fragment.")
//! @yah:handoff("cheers-axum magic_link.rs: POST /magic-link/redeem (body {token}|{token,verifier}|{code,verifier}, deny_unknown_fields; anything else → magic_link_token); request accepts an optional challenge; GET /verify kept and now routes through redeem. RouteError gains InvalidChallenge (invalid_challenge) and BoundElsewhere (bound_elsewhere); Refused collapses into magic_link_token. MagicLinkAuthState gains a C generic.")
//! @yah:handoff("template.rs: with_app_button_label / with_code_intro / without_fallback. A bound request renders the app action, then the browser action, then the code line, with no paste-URL fallback. An unbound request renders the browser action only, even when the provider builds an app URL (F1326: unbound T_app is a bearer token). render() stays the single renderer.")
//! @yah:handoff("cheers-turso: TursoMagicLinkCodeStore (UPDATE … RETURNING for take_attempt, plus gc) + AccountStores::magic_link_codes(); migration 0019_magic_link_codes.sql copied byte-identically into cheers-sqlx/migrations/sqlite (migrations_match_cheers_sqlx green). The number is 0019 because @Ashguard:campfire's CHE-R962 took 0018 (passkey_credential_id). We settled that in chat after we crossed renames twice. Don't renumber either one.")
//! @yah:verify("cargo test --features passkey email (crates/cheers): 52 passed, including bound_token_redeems_only_with_matching_verifier, unbound_request_has_one_token_and_no_code, code_redeems_once, code_is_refused_after_600_seconds, five_wrong_codes_kill_the_code_but_not_the_links, any_one_redemption_burns_the_other_two, s256_matches_rfc7636_appendix_b, template bound/unbound render tests")
//! @yah:verify("cargo test -p cheers-axum --all-features --test main magic_link: 10 passed (5 new redeem/challenge HTTP tests incl. bound_elsewhere + code burns both links)")
//! @yah:verify("cargo test -p cheers-turso -p cheers-sqlx -p cheers-test-identity -p cheers-core: all green, incl. bound_grant_code_state_survives_reopening_turso_stores and migrations_match_cheers_sqlx")
//! @yah:verify("cargo test -p cheers-axum -p cheers-providers --all-features --no-fail-fast: everything green except discovery::tests::scopes_supported_equals_the_registry (24 vs 19). That test is outside this diff: no changes to discovery.rs or scope files")
//! @yah:gotcha("Pre-existing, not from this ticket: cheers-axum discovery::tests::scopes_supported_equals_the_registry fails (left 24, right 19); clippy -D warnings on cheers-providers fails on providers/apple/redirect.rs:581 doc_lazy_continuation. The magic-link handlers now carry clippy type_complexity warnings (7 generics), the same as passkey.rs:636.")
//! @yah:cleanup("cheers-sqlx has the 0019 migration but no SqliteMagicLinkCodeStore impl. Add one beside SqliteUsedJtiStore if a sqlx-backed product needs codes (noisetable uses cheers-turso AccountStores).")
//! @yah:cleanup("Delete GET /magic-link/verify (cheers-axum magic_link.rs verify + VerifyQuery) once noisetable drops /account's ?token= read.")
//! @yah:cleanup("noisetable R983-F3 wiring: MagicLinkProvider::new(.., stores.used_jti(), stores.magic_link_codes()).with_app_urls(MagicLinkUrlBuilder::new(\"https://link.noisetable.com/sign-in\").in_fragment()), browser urls also .in_fragment(); call TursoMagicLinkCodeStore::gc on a timer. Drop @yah:burst(devcrate:cheers) once this cheers version publishes.")
//! @yah:handoff("2026-10-16 (Glimmerstone, noisetable R983 courier). Both children landed and are in review. R961-F1: MagicLinkUrlBuilder::build(token, code) gives the app link #token=<T_app>&code=<C>; a code always rides the fragment, even when the token uses the query. R961-F2: EmailMessage.headers + with_header, which LettreMailer emits via raw_header; it refuses modelled, recipient and framing names and CR/LF values. Tests: cheers-providers --all-features 190/190 lib; cheers-axum --test main 122/122; cheers-server/-turso/-core/-test-identity all green; cheers-sqlx sqlite 30/30. NOT PUBLISHED. Operator form F004 first chose a cheers-only 0.8.47 bump, then withdrew it ('I'll do a full release at yah camp'). The bump was staged, then reverted by hand: every oss/cheers manifest and the root Cargo.lock cheers-* entries are back to 0.8.46. Full train release = cargo xtask release 0.8.47; its dry-run plans 284 edits, and 4 literal 0.8.46 pins are reported as not bumped. Then commit, then bash scripts/oss-publish.sh oss/cheers (step publish-cheers of yah qed run oss-publish).")
//! @yah:gotcha("RELEASE TRAP: commit-oss.sh commits ONLY the files the bump touched, but R961, R961-F1/F2 and R962 are all uncommitted. Untracked: cheers-turso/src/magic_link_code_store.rs, migrations 0018_passkey_credential_id.sql (sqlx pg+sqlite, turso) and 0019_magic_link_codes.sql (sqlx sqlite, turso). oss-publish.sh runs cargo publish without --allow-dirty, so these must be committed BEFORE publishing, or publish-cheers refuses the dirty tree. Root resolution (cargo tree -p yah --depth 0) and cargo hakari generate+verify were clean at a cheers 0.8.47 path version; noisetable takes cheers-* as ^0.8.46 (registry, plus a devcrate path patch), so 0.8.47 satisfies it unchanged.")

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cheers_core::CodecError;
pub use cheers_core::{
    MagicLinkCode, MagicLinkCodeStore, MemoryMagicLinkCodeStore, MemoryUsedJtiStore,
    UsedJtiStore,
};
use pasetors::claims::{Claims as PasetoClaims, ClaimsValidationRules};
use pasetors::keys::SymmetricKey;
use pasetors::local;
use pasetors::token::{Local, UntrustedToken};
use pasetors::version4::V4;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Wire-level value of the [`MagicLinkClaims::purpose`] field.
///
/// Mismatched purpose → [`MagicLinkError::WrongPurpose`].
pub const PURPOSE_MAGIC_LINK: &str = "magic-link";

/// PASETO additional-claim key under which the magic-link payload is stored.
///
/// Kept distinct from cheers-core's session codec key (`"cheers"`) so the two
/// payload shapes can never be confused at the JSON level even with shared
/// keys.
const ADDITIONAL_KEY: &str = "cheers_magic";

/// Default query parameter name for the token in [`MagicLinkUrlBuilder`].
pub const DEFAULT_TOKEN_PARAM: &str = "token";

/// Fragment parameter under which [`MagicLinkUrlBuilder::build`] carries a
/// sign-in code.
pub const CODE_PARAM: &str = "code";

/// Recommended TTL for magic-link tokens (15 minutes, per cheers-plan §P3).
pub const DEFAULT_TTL_SECONDS: i64 = 15 * 60;

/// How long a sign-in code lives (R705-F36's number, W275 §4).
pub const CODE_TTL_SECONDS: i64 = 600;

/// Attempts a sign-in code allows, the successful one included. The last
/// wrong attempt kills the code; the grant's links keep working.
pub const CODE_MAX_ATTEMPTS: u32 = 5;

/// Digits in a sign-in code.
pub const CODE_DIGITS: usize = 6;

// ---------------------------------------------------------------------------
// Claims + errors
// ---------------------------------------------------------------------------

/// Verified magic-link payload — what [`MagicLinkProvider::redeem`] returns
/// on success.
///
/// `jti` is the single-use identifier; the redeem path remembers it via
/// [`UsedJtiStore`] so the token cannot be replayed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MagicLinkClaims {
    /// Email this token was issued to. The whole point of including it in
    /// the signed payload is to bind the click to one address.
    pub email: String,
    /// Single-use identifier (CSPRNG, 16 bytes → 22 char b64url).
    pub jti: String,
    /// Always [`PURPOSE_MAGIC_LINK`]. Verifier rejects anything else.
    pub purpose: String,
    pub issued_at: i64,
    pub expires_at: i64,
    /// S256 challenge the token is bound to. Present only on `T_app` of a
    /// challenged request; absent, the claim is not serialized at all, so
    /// `T_open` keeps today's exact payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
}

impl MagicLinkClaims {
    pub fn is_expired_at(&self, now: i64) -> bool {
        self.expires_at <= now
    }
}

/// Errors surfaced by the magic-link flow.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MagicLinkError {
    /// Token failed PASETO decryption / shape validation. Wraps
    /// [`CodecError`] so the underlying cause is preserved — all SEVEN of
    /// `Malformed` / `SignatureMismatch` / `Expired` / `Crypto` / `Serde` /
    /// `MissingKid` / `UnknownKid`, each carrying a distinct `Display` string.
    /// `cheers-axum` deliberately collapses them into the single client code
    /// `magic_link_token`; the per-cause text survives in its
    /// `cheers-axum route error` warn line.
    #[error("codec: {0}")]
    Codec(#[from] CodecError),
    /// The token decoded but its `purpose` claim wasn't `magic-link`.
    /// Surfaces session-token-in-magic-link-slot mistakes loudly.
    #[error("wrong token purpose: expected '{}', got '{got}'", PURPOSE_MAGIC_LINK)]
    WrongPurpose { got: String },
    /// The `jti` was already consumed — replay attempt.
    #[error("magic-link token already used")]
    AlreadyUsed,
    /// The supplied email did not pass the cheap shape check
    /// (must contain `@` with non-empty local + domain parts).
    #[error("invalid email")]
    InvalidEmail,
    /// A request's `challenge` was not `base64url(SHA-256(..))`-shaped
    /// (43 unpadded base64url characters decoding to 32 bytes).
    #[error("invalid challenge")]
    InvalidChallenge,
    /// The token is bound to a challenge the presented `verifier` does not
    /// match. The one refusal [`MagicLinkProvider::redeem`] does not
    /// collapse (W275 §5): only a token holder can provoke it, it says
    /// nothing about any account, and the app needs it to send the person to
    /// the code on the device that asked.
    #[error("magic-link token is bound to another device")]
    BoundElsewhere,
    /// Every other refusal of a redemption that got past token decoding: a
    /// bound token presented without a verifier, or a code that is wrong,
    /// expired, exhausted, or was never minted. Collapsed on purpose; the
    /// string is for logs only.
    #[error("magic-link redemption refused: {0}")]
    Refused(&'static str),
    /// Underlying [`UsedJtiStore`] / [`MagicLinkCodeStore`] backend failed.
    #[error("magic-link store: {0}")]
    Store(String),
}

// ---------------------------------------------------------------------------
// MagicLinkCodec
// ---------------------------------------------------------------------------

/// PASETO v4.local codec specialized for magic-link payloads.
///
/// Independent of the session `cheers_server::PasetoV4Codec` so callers can
/// (and should) use a dedicated key — leaking a magic-link key only allows
/// minting magic links, not session tokens.
pub struct MagicLinkCodec {
    key: SymmetricKey<V4>,
    ttl_seconds: i64,
}

impl MagicLinkCodec {
    /// Build from a 32-byte key + token TTL in seconds. Pass
    /// [`DEFAULT_TTL_SECONDS`] for the recommended 15-minute window.
    pub fn new(key_bytes: &[u8; 32], ttl_seconds: i64) -> Result<Self, MagicLinkError> {
        let key = SymmetricKey::<V4>::from(key_bytes)
            .map_err(|e| MagicLinkError::Codec(CodecError::Crypto(format!("{e:?}"))))?;
        Ok(Self { key, ttl_seconds })
    }

    pub fn ttl_seconds(&self) -> i64 {
        self.ttl_seconds
    }

    /// Mint a fresh token for `email`, valid for `ttl_seconds` past `now`.
    /// Returns the token plus the claims that were embedded (handy for
    /// templating + audit logging at the call site).
    pub fn mint(&self, email: &str, now: i64) -> Result<(String, MagicLinkClaims), MagicLinkError> {
        let claims = MagicLinkClaims {
            email: email.to_owned(),
            jti: random_jti(),
            purpose: PURPOSE_MAGIC_LINK.into(),
            issued_at: now,
            expires_at: now.saturating_add(self.ttl_seconds),
            challenge: None,
        };
        let token = self.seal(&claims)?;
        Ok((token, claims))
    }

    /// Verify a token against `now` (unix seconds). Rejects on bad signature,
    /// wrong purpose, or `expires_at <= now`. Single-use enforcement is the
    /// caller's job (use [`MagicLinkProvider`]).
    pub fn verify_at(&self, token: &str, now: i64) -> Result<MagicLinkClaims, MagicLinkError> {
        let untrusted = UntrustedToken::<Local, V4>::try_from(token)
            .map_err(|_| MagicLinkError::Codec(CodecError::Malformed))?;
        // We own the expiry decision (matches PasetoV4Codec convention in
        // cheers-core; testable via verify_at).
        let mut rules = ClaimsValidationRules::new();
        rules.allow_non_expiring();
        let trusted = local::decrypt(&self.key, &untrusted, &rules, None, None)
            .map_err(map_paseto_err)?;
        let pclaims = trusted
            .payload_claims()
            .ok_or(MagicLinkError::Codec(CodecError::Malformed))?;
        let v = pclaims
            .get_claim(ADDITIONAL_KEY)
            .ok_or(MagicLinkError::Codec(CodecError::Malformed))?
            .clone();
        let out: MagicLinkClaims = serde_json::from_value(v).map_err(CodecError::from)?;
        if out.purpose != PURPOSE_MAGIC_LINK {
            return Err(MagicLinkError::WrongPurpose { got: out.purpose });
        }
        if out.is_expired_at(now) {
            return Err(MagicLinkError::Codec(CodecError::Expired));
        }
        Ok(out)
    }

    /// Encrypt `claims` as-is. [`mint`](Self::mint) is the usual entry
    /// point; this is how the provider seals `T_app` over `T_open`'s claims.
    pub fn seal(&self, claims: &MagicLinkClaims) -> Result<String, MagicLinkError> {
        let mut p = PasetoClaims::new_expires_in(&core::time::Duration::ZERO)
            .map_err(|e| MagicLinkError::Codec(CodecError::Crypto(format!("{e:?}"))))?;
        p.non_expiring();
        let value = serde_json::to_value(claims).map_err(CodecError::from)?;
        p.add_additional(ADDITIONAL_KEY, value)
            .map_err(|e| MagicLinkError::Codec(CodecError::Crypto(format!("{e:?}"))))?;
        local::encrypt(&self.key, &p, None, None)
            .map_err(|e| MagicLinkError::Codec(map_paseto_err(e)))
    }
}

/// Map a pasetors crypto error into cheers-core's [`CodecError`].
///
/// `cheers-core` is keyless after R019-F6, so it carries no pasetors dependency
/// and thus no `From<pasetors::errors::Error>` impl (the orphan rule would force
/// that impl into the keyless crate). Each pasetors-using crate maps its own
/// errors; this mirrors `cheers_verify::codec_err`.
fn map_paseto_err(e: pasetors::errors::Error) -> CodecError {
    use pasetors::errors::Error as P;
    match e {
        P::TokenValidation => CodecError::SignatureMismatch,
        P::ClaimValidation(_) => CodecError::Expired,
        other => CodecError::Crypto(format!("{other:?}")),
    }
}

fn random_jti() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("getrandom");
    URL_SAFE_NO_PAD.encode(bytes)
}

// ---------------------------------------------------------------------------
// URL builder
// ---------------------------------------------------------------------------

/// Builds the click-through URL the mailer embeds.
///
/// PASETO v4.local tokens are made up of `[A-Za-z0-9._-]` only — all
/// URL-safe — so the token is appended without percent-encoding.
///
/// By default the token rides the query string. [`in_fragment`] moves it
/// into the fragment (`base#token=…`), which a browser never sends to the
/// server — W275 §3's landing pages read it client-side and POST it to the
/// redeem route, so no secret lands in an access log.
///
/// A code (W275 §3's app link, `#token=<T>&code=<C>`) always rides the
/// fragment, whichever way the token goes: it must never reach a server log.
///
/// [`in_fragment`]: MagicLinkUrlBuilder::in_fragment
pub struct MagicLinkUrlBuilder {
    base_url: String,
    token_param: String,
    fragment: bool,
}

impl MagicLinkUrlBuilder {
    /// Default param name is `token`.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            token_param: DEFAULT_TOKEN_PARAM.into(),
            fragment: false,
        }
    }

    /// Carry the token in the URL fragment instead of the query string.
    pub fn in_fragment(mut self) -> Self {
        self.fragment = true;
        self
    }

    pub fn with_token_param(mut self, param: impl Into<String>) -> Self {
        self.token_param = param.into();
        self
    }

    /// The link for `token`, plus `code` in the fragment when given. Codes
    /// are `[0-9]` only, so they too go in unencoded.
    pub fn build(&self, token: &str, code: Option<&str>) -> String {
        let sep = match (self.fragment, self.base_url.contains('#')) {
            (true, true) => '&',
            (true, false) => '#',
            (false, _) if self.base_url.contains('?') => '&',
            (false, _) => '?',
        };
        let mut url = format!("{}{sep}{}={token}", self.base_url, self.token_param);
        if let Some(code) = code {
            let sep = if url.contains('#') { '&' } else { '#' };
            url.push_str(&format!("{sep}{CODE_PARAM}={code}"));
        }
        url
    }
}

// ---------------------------------------------------------------------------
// UsedJtiStore lives in cheers-core (R727-B1) alongside CredentialStore, the
// other client-facing store trait — re-exported above so
// `cheers::email::magic_link::{UsedJtiStore, MemoryUsedJtiStore}` still
// resolves. Moving it down is what lets cheers-turso and cheers-sqlx (which
// depend on cheers-core but not on this crate) implement it directly.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// MagicLinkProvider — codec + URL builder + replay store
// ---------------------------------------------------------------------------

/// Result of [`MagicLinkProvider::request`] — handed to a [`Mailer`] (R010-T2)
/// through [`MagicLinkEmail::render`].
///
/// [`Mailer`]: crate::email::Mailer
/// [`MagicLinkEmail::render`]: crate::email::MagicLinkEmail::render
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct MagicLinkRequest {
    /// Browser track: `T_open` behind the provider's URL builder.
    pub url: String,
    /// `T_open`.
    pub token: String,
    /// App track: `T_app` behind the app URL builder, when the provider has
    /// one ([`MagicLinkProvider::with_app_urls`]), plus `code` in the
    /// fragment when the request was bound.
    pub app_url: Option<String>,
    /// `T_app`: bound to the request's challenge, or `T_open` when the
    /// request carried none.
    pub app_token: String,
    /// The 6-digit code — `Some` exactly when the request carried a
    /// challenge.
    pub code: Option<String>,
    /// `T_open`'s claims. `T_app` differs only by `challenge`.
    pub claims: MagicLinkClaims,
}

impl MagicLinkRequest {
    /// Whether the request carried a challenge: `T_app` is bound and a code
    /// exists.
    pub fn is_bound(&self) -> bool {
        self.code.is_some()
    }
}

/// What a client presents to [`MagicLinkProvider::redeem`] — the three
/// bodies of W275 §5's table.
#[derive(Debug, Clone, Copy)]
pub enum MagicLinkRedemption<'a> {
    /// `{token}` or `{token, verifier}`. An unbound token ignores the
    /// verifier; a bound one needs the matching one.
    Token {
        token: &'a str,
        verifier: Option<&'a str>,
    },
    /// `{code, verifier}`.
    Code { code: &'a str, verifier: &'a str },
}

/// Glue: mint a grant on request, verify + single-use on redeem.
pub struct MagicLinkProvider<S, C> {
    codec: MagicLinkCodec,
    urls: MagicLinkUrlBuilder,
    app_urls: Option<MagicLinkUrlBuilder>,
    used: S,
    codes: C,
}

impl<S, C> MagicLinkProvider<S, C> {
    /// `urls` builds the browser link; `codes` holds the sign-in codes a
    /// challenged request mints.
    pub fn new(codec: MagicLinkCodec, urls: MagicLinkUrlBuilder, used: S, codes: C) -> Self {
        Self {
            codec,
            urls,
            app_urls: None,
            used,
            codes,
        }
    }

    /// Also build an app link (W275's `T_app` track) for every request.
    pub fn with_app_urls(mut self, app_urls: MagicLinkUrlBuilder) -> Self {
        self.app_urls = Some(app_urls);
        self
    }

    pub fn codec(&self) -> &MagicLinkCodec {
        &self.codec
    }
}

impl<S: UsedJtiStore, C: MagicLinkCodeStore> MagicLinkProvider<S, C> {
    /// Mint one grant for `email`: `T_open`, `T_app`, and — when `challenge`
    /// is given — a code, stored before this returns. The caller hands the
    /// result to a mailer and never back to the requester.
    pub async fn request(
        &self,
        email: &str,
        challenge: Option<&str>,
        now: i64,
    ) -> Result<MagicLinkRequest, MagicLinkError> {
        validate_email(email)?;
        if let Some(ch) = challenge {
            validate_challenge(ch)?;
        }
        let (token, claims) = self.codec.mint(email, now)?;
        let (app_token, code) = match challenge {
            None => (token.clone(), None),
            Some(ch) => {
                let bound = MagicLinkClaims {
                    challenge: Some(ch.to_owned()),
                    ..claims.clone()
                };
                let app_token = self.codec.seal(&bound)?;
                let code = random_code();
                self.codes
                    .put(&MagicLinkCode::new(
                        ch,
                        &claims.jti,
                        email,
                        hash_code(&claims.jti, &code),
                        now.saturating_add(CODE_TTL_SECONDS),
                        claims.expires_at,
                    ))
                    .await
                    .map_err(MagicLinkError::Store)?;
                (app_token, Some(code))
            }
        };
        // The code is minted above, so the app link can carry it beside T_app.
        // The browser link never does: T_open redeems without a verifier.
        Ok(MagicLinkRequest {
            url: self.urls.build(&token, None),
            app_url: self
                .app_urls
                .as_ref()
                .map(|u| u.build(&app_token, code.as_deref())),
            token,
            app_token,
            code,
            claims,
        })
    }

    /// Redeem a token or a code, burning the whole grant on success. Returns
    /// the grant's claims (for a code, reassembled from the code row, with
    /// `challenge` set).
    ///
    /// A token that fails to decode, has expired, or names the wrong purpose
    /// surfaces as before, and nothing is burned. Of the rest, only
    /// [`MagicLinkError::BoundElsewhere`] is distinct; every code refusal is
    /// [`MagicLinkError::Refused`]. A wrong code spends an attempt; the
    /// [`CODE_MAX_ATTEMPTS`]th kills the code but not the links.
    pub async fn redeem(
        &self,
        redemption: MagicLinkRedemption<'_>,
        now: i64,
    ) -> Result<MagicLinkClaims, MagicLinkError> {
        let claims = match redemption {
            MagicLinkRedemption::Token { token, verifier } => {
                let claims = self.codec.verify_at(token, now)?;
                if let Some(ch) = &claims.challenge {
                    let verifier = verifier.ok_or(MagicLinkError::Refused("bound token, no verifier"))?;
                    if !ct_eq_str(&s256(verifier), ch) {
                        return Err(MagicLinkError::BoundElsewhere);
                    }
                }
                claims
            }
            MagicLinkRedemption::Code { code, verifier } => {
                let challenge = s256(verifier);
                let row = self
                    .codes
                    .take_attempt(&challenge, CODE_MAX_ATTEMPTS, now)
                    .await
                    .map_err(MagicLinkError::Store)?
                    .ok_or(MagicLinkError::Refused("no live code"))?;
                if !ct_eq_str(&hash_code(&row.jti, code), &row.code_hash) {
                    if row.attempts >= CODE_MAX_ATTEMPTS {
                        self.codes
                            .delete_for_jti(&row.jti)
                            .await
                            .map_err(MagicLinkError::Store)?;
                    }
                    return Err(MagicLinkError::Refused("wrong code"));
                }
                MagicLinkClaims {
                    email: row.email,
                    jti: row.jti,
                    purpose: PURPOSE_MAGIC_LINK.into(),
                    issued_at: row.grant_expires_at.saturating_sub(self.codec.ttl_seconds),
                    expires_at: row.grant_expires_at,
                    challenge: Some(row.challenge),
                }
            }
        };
        let fresh = self
            .used
            .try_mark_used(&claims.jti, claims.expires_at)
            .await
            .map_err(MagicLinkError::Store)?;
        // Delete the code whichever way the race went: a replayed grant's
        // code must not outlive it either.
        self.codes
            .delete_for_jti(&claims.jti)
            .await
            .map_err(MagicLinkError::Store)?;
        if !fresh {
            return Err(MagicLinkError::AlreadyUsed);
        }
        Ok(claims)
    }
}

/// `base64url(SHA-256(verifier))` — RFC 7636 §4.2's S256 over the
/// verifier's ASCII bytes.
pub fn s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn validate_challenge(ch: &str) -> Result<(), MagicLinkError> {
    match URL_SAFE_NO_PAD.decode(ch) {
        Ok(b) if b.len() == 32 && ch.len() == 43 => Ok(()),
        _ => Err(MagicLinkError::InvalidChallenge),
    }
}

/// Hex SHA-256 of the code, salted with its grant's `jti` so equal codes on
/// two grants never share a digest.
fn hash_code(jti: &str, code: &str) -> String {
    let mut h = Sha256::new();
    h.update(jti.as_bytes());
    h.update(b":");
    h.update(code.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn ct_eq_str(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Uniform 6-digit code, rejection-sampled so no digit string is likelier.
fn random_code() -> String {
    const SPAN: u32 = 1_000_000;
    const LIMIT: u32 = u32::MAX - (u32::MAX % SPAN);
    loop {
        let mut b = [0u8; 4];
        getrandom::fill(&mut b).expect("getrandom");
        let n = u32::from_le_bytes(b);
        if n < LIMIT {
            return format!("{:0width$}", n % SPAN, width = CODE_DIGITS);
        }
    }
}

/// Cheap structural check: must contain exactly one `@` separating
/// non-empty local + domain parts. RFC 5322 compliance is the mailer's job.
fn validate_email(s: &str) -> Result<(), MagicLinkError> {
    let mut parts = s.splitn(2, '@');
    let local = parts.next().unwrap_or("");
    let domain = parts.next().unwrap_or("");
    if local.is_empty() || domain.is_empty() || domain.contains('@') || !domain.contains('.') {
        return Err(MagicLinkError::InvalidEmail);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    type Provider = MagicLinkProvider<MemoryUsedJtiStore, MemoryMagicLinkCodeStore>;

    fn provider() -> Provider {
        let codec = MagicLinkCodec::new(&[42u8; 32], 900).unwrap();
        let urls = MagicLinkUrlBuilder::new("https://app.example/auth/verify");
        MagicLinkProvider::new(
            codec,
            urls,
            MemoryUsedJtiStore::new(),
            MemoryMagicLinkCodeStore::new(),
        )
        .with_app_urls(MagicLinkUrlBuilder::new("https://link.app.example/sign-in").in_fragment())
    }

    fn open(token: &str) -> MagicLinkRedemption<'_> {
        MagicLinkRedemption::Token {
            token,
            verifier: None,
        }
    }

    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    // -- codec ---------------------------------------------------------------

    #[test]
    fn codec_roundtrip_pins_purpose_and_email() {
        let codec = MagicLinkCodec::new(&[1u8; 32], 60).unwrap();
        let (tok, claims) = codec.mint("alice@example.com", 1_000).unwrap();
        assert!(tok.starts_with("v4.local."));
        assert_eq!(claims.purpose, PURPOSE_MAGIC_LINK);
        assert_eq!(claims.email, "alice@example.com");
        assert_eq!(claims.expires_at, 1_060);
        let back = codec.verify_at(&tok, 1_030).unwrap();
        assert_eq!(back, claims);
    }

    #[test]
    fn codec_rejects_expired() {
        let codec = MagicLinkCodec::new(&[1u8; 32], 60).unwrap();
        let (tok, _c) = codec.mint("a@b.co", 1_000).unwrap();
        let err = codec.verify_at(&tok, 1_060).unwrap_err();
        assert!(matches!(err, MagicLinkError::Codec(CodecError::Expired)));
    }

    #[test]
    fn codec_rejects_wrong_key() {
        let a = MagicLinkCodec::new(&[1u8; 32], 60).unwrap();
        let b = MagicLinkCodec::new(&[2u8; 32], 60).unwrap();
        let (tok, _c) = a.mint("a@b.co", 1_000).unwrap();
        let err = b.verify_at(&tok, 1_010).unwrap_err();
        assert!(matches!(
            err,
            MagicLinkError::Codec(CodecError::SignatureMismatch)
        ));
    }

    #[test]
    fn codec_rejects_malformed() {
        let codec = MagicLinkCodec::new(&[1u8; 32], 60).unwrap();
        let err = codec.verify_at("not-a-paseto", 0).unwrap_err();
        assert!(matches!(err, MagicLinkError::Codec(CodecError::Malformed)));
    }

    #[test]
    fn codec_rejects_wrong_purpose() {
        // Hand-craft a token by reusing the codec but stuffing a non-magic
        // purpose into the additional-key payload.
        let codec = MagicLinkCodec::new(&[1u8; 32], 60).unwrap();
        let bogus = MagicLinkClaims {
            email: "a@b.co".into(),
            jti: random_jti(),
            purpose: "session".into(),
            issued_at: 1_000,
            expires_at: 2_000,
            challenge: None,
        };
        let tok = codec.seal(&bogus).unwrap();
        let err = codec.verify_at(&tok, 1_500).unwrap_err();
        match err {
            MagicLinkError::WrongPurpose { got } => assert_eq!(got, "session"),
            other => panic!("expected WrongPurpose, got {other:?}"),
        }
    }

    #[test]
    fn jti_is_unique_across_mints() {
        let codec = MagicLinkCodec::new(&[3u8; 32], 60).unwrap();
        let (_, a) = codec.mint("x@y.co", 1_000).unwrap();
        let (_, b) = codec.mint("x@y.co", 1_000).unwrap();
        assert_ne!(a.jti, b.jti);
    }

    // -- url builder ---------------------------------------------------------

    #[test]
    fn url_builder_appends_with_question_mark() {
        let u = MagicLinkUrlBuilder::new("https://app/verify").build("TOKEN", None);
        assert_eq!(u, "https://app/verify?token=TOKEN");
    }

    #[test]
    fn url_builder_appends_with_ampersand_when_query_already_present() {
        let u = MagicLinkUrlBuilder::new("https://app/verify?foo=1").build("TOKEN", None);
        assert_eq!(u, "https://app/verify?foo=1&token=TOKEN");
    }

    #[test]
    fn url_builder_in_fragment_uses_hash() {
        let u = MagicLinkUrlBuilder::new("https://app/sign-in")
            .in_fragment()
            .build("TOKEN", None);
        assert_eq!(u, "https://app/sign-in#token=TOKEN");
    }

    #[test]
    fn url_builder_honors_custom_param() {
        let u = MagicLinkUrlBuilder::new("https://app/verify")
            .with_token_param("t")
            .build("TOKEN", None);
        assert_eq!(u, "https://app/verify?t=TOKEN");
    }

    #[test]
    fn url_builder_puts_code_beside_token_in_fragment() {
        let u = MagicLinkUrlBuilder::new("https://app/sign-in")
            .in_fragment()
            .build("TOKEN", Some("012345"));
        assert_eq!(u, "https://app/sign-in#token=TOKEN&code=012345");
    }

    #[test]
    fn url_builder_keeps_code_out_of_the_query() {
        let u = MagicLinkUrlBuilder::new("https://app/verify?foo=1").build("TOKEN", Some("012345"));
        assert_eq!(u, "https://app/verify?foo=1&token=TOKEN#code=012345");
    }

    // -- email validation ----------------------------------------------------

    #[test]
    fn email_validation_accepts_simple_addresses() {
        assert!(validate_email("a@b.co").is_ok());
        assert!(validate_email("alice+tag@sub.example.com").is_ok());
    }

    #[test]
    fn email_validation_rejects_obvious_garbage() {
        for bad in ["", "no-at", "@nope.com", "x@", "x@y", "a@@b.co"] {
            assert!(
                validate_email(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    // -- provider (codec + urls + replay) ------------------------------------

    #[test]
    fn provider_request_then_consume_happy_path() {
        pollster::block_on(async {
            let p = provider();
            let req = p.request("alice@example.com", None, 1_000).await.unwrap();
            assert!(req.url.starts_with("https://app.example/auth/verify?token=v4.local."));
            assert_eq!(req.claims.email, "alice@example.com");

            let claims = p.redeem(open(&req.token), 1_300).await.unwrap();
            assert_eq!(claims, req.claims);
        });
    }

    #[test]
    fn provider_consume_replay_rejected_and_chain_marker_persists() {
        pollster::block_on(async {
            let p = provider();
            let req = p.request("a@b.co", None, 1_000).await.unwrap();
            p.redeem(open(&req.token), 1_001).await.unwrap();
            let err = p.redeem(open(&req.token), 1_002).await.unwrap_err();
            assert!(matches!(err, MagicLinkError::AlreadyUsed));
        });
    }

    #[test]
    fn provider_request_rejects_invalid_email() {
        pollster::block_on(async {
            let p = provider();
            let err = p.request("not-an-email", None, 1_000).await.unwrap_err();
            assert!(matches!(err, MagicLinkError::InvalidEmail));
        });
    }

    #[test]
    fn provider_consume_expired_token_does_not_burn_jti() {
        // An expired token is rejected before `try_mark_used` runs, so the
        // jti can't be poisoned by an attacker submitting stale tokens to
        // pre-burn legitimate ones. (Defense-in-depth: jti is CSPRNG.)
        pollster::block_on(async {
            let p = provider();
            let req = p.request("a@b.co", None, 1_000).await.unwrap();
            // ttl=900 → expires at 1_900.
            let err = p.redeem(open(&req.token), 1_900).await.unwrap_err();
            assert!(matches!(err, MagicLinkError::Codec(CodecError::Expired)));
            // No replay-burn happened.
            assert_eq!(p.used.len(), 0);
        });
    }

    // -- bound grant (CHE-R961, W275 §4/§5) ----------------------------------

    #[test]
    fn s256_matches_rfc7636_appendix_b() {
        assert_eq!(s256(VERIFIER), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn unbound_request_has_one_token_and_no_code() {
        pollster::block_on(async {
            let p = provider();
            let req = p.request("a@b.co", None, 1_000).await.unwrap();
            assert!(!req.is_bound());
            assert_eq!(req.app_token, req.token);
            assert_eq!(
                req.app_url.as_deref().unwrap(),
                format!("https://link.app.example/sign-in#token={}", req.token)
            );
            assert!(p.codes.is_empty());
            // An unbound token redeems with {token}, and ignores a verifier.
            p.redeem(open(&req.token), 1_001).await.unwrap();
            let again = p.request("a@b.co", None, 1_000).await.unwrap();
            let with_v = MagicLinkRedemption::Token {
                token: &again.token,
                verifier: Some("anything"),
            };
            p.redeem(with_v, 1_001).await.unwrap();
        });
    }

    #[test]
    fn bound_request_rejects_malformed_challenge() {
        pollster::block_on(async {
            let p = provider();
            for bad in ["", "short", &"A".repeat(44), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw+cM"] {
                let err = p.request("a@b.co", Some(bad), 1_000).await.unwrap_err();
                assert!(matches!(err, MagicLinkError::InvalidChallenge), "{bad:?}");
            }
        });
    }

    #[test]
    fn bound_token_redeems_only_with_matching_verifier() {
        pollster::block_on(async {
            let p = provider();
            let ch = s256(VERIFIER);
            let req = p.request("a@b.co", Some(&ch), 1_000).await.unwrap();
            assert!(req.is_bound());
            assert_ne!(req.app_token, req.token);
            let code = req.code.as_deref().unwrap();
            assert_eq!(code.len(), CODE_DIGITS);
            assert!(code.bytes().all(|b| b.is_ascii_digit()));
            // W275 §3: the app link carries T_app and the code, both in the
            // fragment; the browser link carries T_open alone.
            assert_eq!(
                req.app_url.as_deref().unwrap(),
                format!("https://link.app.example/sign-in#token={}&code={code}", req.app_token)
            );
            assert_eq!(
                req.url,
                format!("https://app.example/auth/verify?token={}", req.token)
            );

            // Wrong verifier: bound_elsewhere, nothing burned.
            let wrong = MagicLinkRedemption::Token {
                token: &req.app_token,
                verifier: Some("not-the-verifier"),
            };
            assert!(matches!(
                p.redeem(wrong, 1_001).await.unwrap_err(),
                MagicLinkError::BoundElsewhere
            ));
            // No verifier at all: collapsed refusal.
            assert!(matches!(
                p.redeem(open(&req.app_token), 1_001).await.unwrap_err(),
                MagicLinkError::Refused(_)
            ));
            assert_eq!(p.used.len(), 0);

            let right = MagicLinkRedemption::Token {
                token: &req.app_token,
                verifier: Some(VERIFIER),
            };
            let claims = p.redeem(right, 1_002).await.unwrap();
            assert_eq!(claims.challenge.as_deref(), Some(ch.as_str()));
            assert_eq!(claims.jti, req.claims.jti);
        });
    }

    #[test]
    fn code_redeems_once() {
        pollster::block_on(async {
            let p = provider();
            let req = p.request("a@b.co", Some(&s256(VERIFIER)), 1_000).await.unwrap();
            let code = req.code.clone().unwrap();
            let by_code = MagicLinkRedemption::Code {
                code: &code,
                verifier: VERIFIER,
            };
            let claims = p.redeem(by_code, 1_100).await.unwrap();
            assert_eq!(claims.email, "a@b.co");
            assert_eq!(claims.jti, req.claims.jti);
            assert_eq!(claims.expires_at, req.claims.expires_at);
            assert!(matches!(
                p.redeem(by_code, 1_101).await.unwrap_err(),
                MagicLinkError::Refused(_)
            ));
        });
    }

    #[test]
    fn code_is_refused_after_600_seconds() {
        pollster::block_on(async {
            let p = provider();
            let req = p.request("a@b.co", Some(&s256(VERIFIER)), 1_000).await.unwrap();
            let code = req.code.clone().unwrap();
            let by_code = MagicLinkRedemption::Code {
                code: &code,
                verifier: VERIFIER,
            };
            assert!(matches!(
                p.redeem(by_code, 1_000 + CODE_TTL_SECONDS).await.unwrap_err(),
                MagicLinkError::Refused(_)
            ));
            // The links outlive the code.
            p.redeem(open(&req.token), 1_000 + CODE_TTL_SECONDS).await.unwrap();
        });
    }

    #[test]
    fn code_needs_the_matching_verifier() {
        pollster::block_on(async {
            let p = provider();
            let req = p.request("a@b.co", Some(&s256(VERIFIER)), 1_000).await.unwrap();
            let code = req.code.clone().unwrap();
            let other = MagicLinkRedemption::Code {
                code: &code,
                verifier: "someone-elses-verifier",
            };
            assert!(matches!(
                p.redeem(other, 1_001).await.unwrap_err(),
                MagicLinkError::Refused(_)
            ));
        });
    }

    #[test]
    fn five_wrong_codes_kill_the_code_but_not_the_links() {
        pollster::block_on(async {
            let p = provider();
            let req = p.request("a@b.co", Some(&s256(VERIFIER)), 1_000).await.unwrap();
            let code = req.code.clone().unwrap();
            let wrong = if code == "000000" { "000001" } else { "000000" };
            for _ in 0..CODE_MAX_ATTEMPTS {
                let guess = MagicLinkRedemption::Code {
                    code: wrong,
                    verifier: VERIFIER,
                };
                assert!(matches!(
                    p.redeem(guess, 1_001).await.unwrap_err(),
                    MagicLinkError::Refused(_)
                ));
            }
            assert!(p.codes.is_empty(), "fifth wrong attempt deletes the code");
            let right = MagicLinkRedemption::Code {
                code: &code,
                verifier: VERIFIER,
            };
            assert!(matches!(
                p.redeem(right, 1_002).await.unwrap_err(),
                MagicLinkError::Refused(_)
            ));
            let app = MagicLinkRedemption::Token {
                token: &req.app_token,
                verifier: Some(VERIFIER),
            };
            p.redeem(app, 1_003).await.unwrap();
        });
    }

    #[test]
    fn four_wrong_codes_leave_the_right_one_working() {
        pollster::block_on(async {
            let p = provider();
            let req = p.request("a@b.co", Some(&s256(VERIFIER)), 1_000).await.unwrap();
            let code = req.code.clone().unwrap();
            let wrong = if code == "000000" { "000001" } else { "000000" };
            for _ in 0..CODE_MAX_ATTEMPTS - 1 {
                let guess = MagicLinkRedemption::Code {
                    code: wrong,
                    verifier: VERIFIER,
                };
                p.redeem(guess, 1_001).await.unwrap_err();
            }
            let right = MagicLinkRedemption::Code {
                code: &code,
                verifier: VERIFIER,
            };
            p.redeem(right, 1_002).await.unwrap();
        });
    }

    #[test]
    fn any_one_redemption_burns_the_other_two() {
        pollster::block_on(async {
            let p = provider();
            let ch = s256(VERIFIER);
            for winner in 0..3 {
                let req = p.request("a@b.co", Some(&ch), 1_000).await.unwrap();
                let code = req.code.clone().unwrap();
                let tracks = [
                    open(&req.token),
                    MagicLinkRedemption::Token {
                        token: &req.app_token,
                        verifier: Some(VERIFIER),
                    },
                    MagicLinkRedemption::Code {
                        code: &code,
                        verifier: VERIFIER,
                    },
                ];
                p.redeem(tracks[winner], 1_001).await.unwrap();
                assert!(p.codes.is_empty(), "winner {winner} left the code row");
                for (i, t) in tracks.iter().enumerate() {
                    if i == winner {
                        continue;
                    }
                    let err = p.redeem(*t, 1_002).await.unwrap_err();
                    assert!(
                        matches!(err, MagicLinkError::AlreadyUsed | MagicLinkError::Refused(_)),
                        "winner {winner}, loser {i}: {err:?}"
                    );
                }
            }
        });
    }

    #[test]
    fn open_token_payload_has_no_challenge_claim() {
        pollster::block_on(async {
            let p = provider();
            let req = p.request("a@b.co", Some(&s256(VERIFIER)), 1_000).await.unwrap();
            assert!(req.claims.challenge.is_none());
            let back = p.codec.verify_at(&req.token, 1_001).unwrap();
            assert!(back.challenge.is_none());
            let json = serde_json::to_value(&back).unwrap();
            assert!(json.get("challenge").is_none());
        });
    }

    // -- memory store --------------------------------------------------------

    #[test]
    fn memory_store_gc_drops_expired_entries() {
        pollster::block_on(async {
            let s = MemoryUsedJtiStore::new();
            assert!(s.try_mark_used("a", 100).await.unwrap());
            assert!(s.try_mark_used("b", 500).await.unwrap());
            assert_eq!(s.len(), 2);
            s.gc(200);
            assert_eq!(s.len(), 1);
            // 'a' entry is gone — so it can be re-marked. (Practically moot
            // because the codec would reject a token with expires_at<=now,
            // but the store contract is honored.)
            assert!(s.try_mark_used("a", 1_000).await.unwrap());
        });
    }
}
