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
//!   `jti`. [`MagicLinkProvider::consume`] verifies the token then atomically
//!   marks the `jti` as used; replays return [`MagicLinkError::AlreadyUsed`].
//!   A [`MemoryUsedJtiStore`] is provided for tests and dev.
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
//!     MagicLinkCodec, MagicLinkProvider, MagicLinkUrlBuilder, MemoryUsedJtiStore,
//! };
//!
//! # pollster::block_on(async {
//! let codec = MagicLinkCodec::new(&[7u8; 32], 15 * 60).unwrap();
//! let urls = MagicLinkUrlBuilder::new("https://app.example/auth/verify");
//! let provider = MagicLinkProvider::new(codec, urls, MemoryUsedJtiStore::new());
//!
//! let now = 1_700_000_000;
//! let req = provider.request("alice@example.com", now).await.unwrap();
//! assert!(req.url.starts_with("https://app.example/auth/verify?token=v4.local."));
//!
//! let claims = provider.consume(&req.token, now + 30).await.unwrap();
//! assert_eq!(claims.email, "alice@example.com");
//!
//! // Replay rejected.
//! assert!(provider.consume(&req.token, now + 31).await.is_err());
//! # });
//! ```

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cheers_core::CodecError;
use pasetors::claims::{Claims as PasetoClaims, ClaimsValidationRules};
use pasetors::keys::SymmetricKey;
use pasetors::local;
use pasetors::token::{Local, UntrustedToken};
use pasetors::version4::V4;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

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

/// Recommended TTL for magic-link tokens (15 minutes, per cheers-plan §P3).
pub const DEFAULT_TTL_SECONDS: i64 = 15 * 60;

// ---------------------------------------------------------------------------
// Claims + errors
// ---------------------------------------------------------------------------

/// Verified magic-link payload — what [`MagicLinkProvider::consume`] returns
/// on success.
///
/// `jti` is the single-use identifier; the consume path remembers it via
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
    /// [`CodecError`] so the underlying cause (Malformed / SignatureMismatch
    /// / Expired / Crypto / Serde) is preserved.
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
    /// Underlying [`UsedJtiStore`] backend failed.
    #[error("used-jti store: {0}")]
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
        };
        let token = self.encrypt(&claims)?;
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

    fn encrypt(&self, claims: &MagicLinkClaims) -> Result<String, MagicLinkError> {
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
pub struct MagicLinkUrlBuilder {
    base_url: String,
    token_param: String,
}

impl MagicLinkUrlBuilder {
    /// Default param name is `token`.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            token_param: DEFAULT_TOKEN_PARAM.into(),
        }
    }

    pub fn with_token_param(mut self, param: impl Into<String>) -> Self {
        self.token_param = param.into();
        self
    }

    pub fn build(&self, token: &str) -> String {
        let sep = if self.base_url.contains('?') { '&' } else { '?' };
        format!("{}{sep}{}={token}", self.base_url, self.token_param)
    }
}

// ---------------------------------------------------------------------------
// UsedJtiStore + memory impl
// ---------------------------------------------------------------------------

/// Single-use tracking for magic-link tokens.
///
/// Implementors should hold each `jti` until at least `expires_at` so a
/// token cannot be replayed before it would have expired anyway. After
/// expiry the entry can be GC'd — the codec's own expiry check will reject
/// any token whose record is missing.
#[async_trait]
pub trait UsedJtiStore: Send + Sync {
    /// Atomically: if `jti` has not been seen, record it (with `expires_at`
    /// for GC) and return `true`. If it has been seen, return `false`.
    /// `Err(_)` is reserved for backend failures, not replay.
    async fn try_mark_used(&self, jti: &str, expires_at: i64) -> Result<bool, String>;
}

/// In-process [`UsedJtiStore`] backed by a `Mutex<HashMap>`. For tests, dev,
/// and single-replica deployments. Production multi-replica deployments
/// want a shared backend (Redis, Postgres, …).
#[derive(Default)]
pub struct MemoryUsedJtiStore {
    inner: Mutex<HashMap<String, i64>>,
}

impl MemoryUsedJtiStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop entries whose `expires_at <= now`. Callers wire this on a timer
    /// if they care about the unbounded-growth case.
    pub fn gc(&self, now: i64) {
        self.inner.lock().unwrap().retain(|_, exp| *exp > now);
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().is_empty()
    }
}

#[async_trait]
impl UsedJtiStore for MemoryUsedJtiStore {
    async fn try_mark_used(&self, jti: &str, expires_at: i64) -> Result<bool, String> {
        let mut g = self.inner.lock().unwrap();
        if g.contains_key(jti) {
            return Ok(false);
        }
        g.insert(jti.to_owned(), expires_at);
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// MagicLinkProvider — codec + URL builder + replay store
// ---------------------------------------------------------------------------

/// Result of [`MagicLinkProvider::request`] — handed to a [`Mailer`] (R010-T2).
///
/// [`Mailer`]: crate::email
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct MagicLinkRequest {
    pub url: String,
    pub token: String,
    pub claims: MagicLinkClaims,
}

/// Glue: mint→URL on request, verify→single-use on consume.
pub struct MagicLinkProvider<S> {
    codec: MagicLinkCodec,
    urls: MagicLinkUrlBuilder,
    used: S,
}

impl<S> MagicLinkProvider<S> {
    pub fn new(codec: MagicLinkCodec, urls: MagicLinkUrlBuilder, used: S) -> Self {
        Self { codec, urls, used }
    }

    pub fn codec(&self) -> &MagicLinkCodec {
        &self.codec
    }
}

impl<S: UsedJtiStore> MagicLinkProvider<S> {
    /// Mint a token for `email`, build its URL. Caller hands the URL to a
    /// mailer; the `token` + `claims` are returned for logging/templating.
    pub async fn request(&self, email: &str, now: i64) -> Result<MagicLinkRequest, MagicLinkError> {
        validate_email(email)?;
        let (token, claims) = self.codec.mint(email, now)?;
        let url = self.urls.build(&token);
        Ok(MagicLinkRequest {
            url,
            token,
            claims,
        })
    }

    /// Verify a token then atomically mark it as used. Returns the verified
    /// claims on success; replay → [`MagicLinkError::AlreadyUsed`].
    pub async fn consume(
        &self,
        token: &str,
        now: i64,
    ) -> Result<MagicLinkClaims, MagicLinkError> {
        let claims = self.codec.verify_at(token, now)?;
        let fresh = self
            .used
            .try_mark_used(&claims.jti, claims.expires_at)
            .await
            .map_err(MagicLinkError::Store)?;
        if !fresh {
            return Err(MagicLinkError::AlreadyUsed);
        }
        Ok(claims)
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

    fn provider() -> MagicLinkProvider<MemoryUsedJtiStore> {
        let codec = MagicLinkCodec::new(&[42u8; 32], 900).unwrap();
        let urls = MagicLinkUrlBuilder::new("https://app.example/auth/verify");
        MagicLinkProvider::new(codec, urls, MemoryUsedJtiStore::new())
    }

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
        };
        let tok = codec.encrypt(&bogus).unwrap();
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
        let u = MagicLinkUrlBuilder::new("https://app/verify").build("TOKEN");
        assert_eq!(u, "https://app/verify?token=TOKEN");
    }

    #[test]
    fn url_builder_appends_with_ampersand_when_query_already_present() {
        let u = MagicLinkUrlBuilder::new("https://app/verify?foo=1").build("TOKEN");
        assert_eq!(u, "https://app/verify?foo=1&token=TOKEN");
    }

    #[test]
    fn url_builder_honors_custom_param() {
        let u = MagicLinkUrlBuilder::new("https://app/verify")
            .with_token_param("t")
            .build("TOKEN");
        assert_eq!(u, "https://app/verify?t=TOKEN");
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
            let req = p.request("alice@example.com", 1_000).await.unwrap();
            assert!(req.url.starts_with("https://app.example/auth/verify?token=v4.local."));
            assert_eq!(req.claims.email, "alice@example.com");

            let claims = p.consume(&req.token, 1_300).await.unwrap();
            assert_eq!(claims, req.claims);
        });
    }

    #[test]
    fn provider_consume_replay_rejected_and_chain_marker_persists() {
        pollster::block_on(async {
            let p = provider();
            let req = p.request("a@b.co", 1_000).await.unwrap();
            p.consume(&req.token, 1_001).await.unwrap();
            let err = p.consume(&req.token, 1_002).await.unwrap_err();
            assert!(matches!(err, MagicLinkError::AlreadyUsed));
        });
    }

    #[test]
    fn provider_request_rejects_invalid_email() {
        pollster::block_on(async {
            let p = provider();
            let err = p.request("not-an-email", 1_000).await.unwrap_err();
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
            let req = p.request("a@b.co", 1_000).await.unwrap();
            // ttl=900 → expires at 1_900.
            let err = p.consume(&req.token, 1_900).await.unwrap_err();
            assert!(matches!(err, MagicLinkError::Codec(CodecError::Expired)));
            // No replay-burn happened.
            let store_len = {
                let p_ref: &MagicLinkProvider<MemoryUsedJtiStore> = &p;
                // Reach into the store via a fresh handle for visibility.
                let _ = p_ref;
                p.used.len()
            };
            assert_eq!(store_len, 0);
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
