//! Argon2id password hashing + HIBP breached-password check.
//!
//! Three moving pieces:
//!
//! - [`PasswordHasher`] — argon2id hash + verify. `verify` returns a
//!   [`VerifyOutcome`] flagging `needs_rehash` when the stored PHC string's
//!   params no longer match the hasher's current target params; the caller
//!   re-hashes on the next successful login.
//! - [`BreachedPasswordChecker`] — async trait for HIBP-style breach lookup.
//!   [`NoopBreachedPasswordChecker`] is for air-gapped deployments;
//!   [`MapBreachedPasswordChecker`] is an in-memory list for tests + curated
//!   deny-lists; [`hibp::HibpClient`] (under `password-hibp`) hits the real
//!   API.
//! - [`PasswordPolicy`] — glue: on `hash_new_password` the password is run
//!   through the checker before hashing, so breached passwords never reach
//!   storage. `verify` is hash-only (don't re-check at login — the user is
//!   already authenticating with what they have).
//!
//! # Default params
//!
//! OWASP's 2026 recommendation for Argon2id is `m=19456 KiB, t=2, p=1`,
//! exposed via [`DEFAULT_MEMORY_KIB`] / [`DEFAULT_TIME_COST`] /
//! [`DEFAULT_PARALLELISM`] and bundled as [`default_params`].
//!
//! # Constant-time comparison
//!
//! Argon2 verification compares the recomputed tag against the stored tag in
//! constant time inside `argon2::password_hash::PasswordHash::verify_password`,
//! so there is no exposed timing oracle for the password material.
//!
//! # Injectable HIBP client
//!
//! `BreachedPasswordChecker` is the seam: tests use
//! [`MapBreachedPasswordChecker`], air-gapped deployments use
//! [`NoopBreachedPasswordChecker`], and `password-hibp` callers use
//! [`hibp::HibpClient`] (configurable base URL so self-hosted equivalents
//! plug in cleanly).
//!
//! # Example
//!
//! ```
//! use cheers::email::password::{
//!     MapBreachedPasswordChecker, PasswordHasher, PasswordPolicy, PasswordError,
//! };
//!
//! # pollster::block_on(async {
//! // Cheap params for the doctest — production callers use `with_default_params()`.
//! let params = argon2::Params::new(8, 1, 1, Some(16)).unwrap();
//! let hasher = PasswordHasher::new(params);
//! let breaches = MapBreachedPasswordChecker::new();
//! breaches.insert("hunter2", 12_345);
//!
//! let policy = PasswordPolicy::new(hasher, breaches);
//!
//! // Breached password is rejected before hashing.
//! assert!(matches!(
//!     policy.hash_new_password("hunter2").await,
//!     Err(PasswordError::Breached { count: 12_345 })
//! ));
//!
//! // Fresh password gets hashed.
//! let phc = policy.hash_new_password("correct horse battery staple").await.unwrap();
//! assert!(phc.starts_with("$argon2id$"));
//!
//! // Right password verifies.
//! let outcome = policy.verify("correct horse battery staple", &phc).unwrap();
//! assert!(!outcome.needs_rehash);
//!
//! // Wrong password rejects.
//! assert!(matches!(
//!     policy.verify("wrong", &phc),
//!     Err(PasswordError::WrongPassword)
//! ));
//! # });
//! ```

use argon2::password_hash::{
    PasswordHash, PasswordHasher as _, PasswordVerifier, SaltString,
};
use argon2::{Algorithm, Argon2, Params, Version};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::RwLock;

// ---------------------------------------------------------------------------
// Default params (OWASP 2026)
// ---------------------------------------------------------------------------

/// Default Argon2id memory cost (KiB) — OWASP's 2026 recommendation.
pub const DEFAULT_MEMORY_KIB: u32 = 19_456;
/// Default Argon2id time cost (iterations) — OWASP's 2026 recommendation.
pub const DEFAULT_TIME_COST: u32 = 2;
/// Default Argon2id parallelism (lanes) — OWASP's 2026 recommendation.
pub const DEFAULT_PARALLELISM: u32 = 1;
/// Default tag length in bytes.
pub const DEFAULT_OUTPUT_LEN: usize = 32;

/// Build a fresh [`Params`] with the [`DEFAULT_MEMORY_KIB`] /
/// [`DEFAULT_TIME_COST`] / [`DEFAULT_PARALLELISM`] / [`DEFAULT_OUTPUT_LEN`]
/// constants.
pub fn default_params() -> Params {
    Params::new(
        DEFAULT_MEMORY_KIB,
        DEFAULT_TIME_COST,
        DEFAULT_PARALLELISM,
        Some(DEFAULT_OUTPUT_LEN),
    )
    .expect("OWASP-recommended params are valid")
}

// ---------------------------------------------------------------------------
// Errors + verify outcome
// ---------------------------------------------------------------------------

/// Errors surfaced by [`PasswordHasher`] and [`PasswordPolicy`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PasswordError {
    /// Argon2 failed to derive a tag. Salt generation OOM, kernel RNG
    /// failure, etc. — should be extremely rare in practice.
    #[error("hash failed: {0}")]
    Hash(String),
    /// The supplied PHC string could not be parsed.
    #[error("malformed PHC string: {0}")]
    Malformed(String),
    /// The password did not match the stored hash. Distinct variant so
    /// callers can map this to a 401 without leaking the underlying argon2
    /// error.
    #[error("password did not match stored hash")]
    WrongPassword,
    /// Argon2 verify failed for a reason other than a wrong password
    /// (e.g. PHC structurally valid but referencing an unsupported algorithm).
    #[error("verify failed: {0}")]
    Verify(String),
    /// The proposed password was found in the breached-password list with
    /// `count` occurrences. Surfaces from
    /// [`PasswordPolicy::hash_new_password`] only — `verify` doesn't check.
    #[error("password appears in {count} known breach records")]
    Breached { count: u64 },
    /// The breached-password checker backend itself failed. Caller decides
    /// fail-open vs. fail-closed; cheers does not impose a default.
    #[error("breached-password checker backend: {0}")]
    Checker(String),
}

/// Returned by [`PasswordHasher::verify`] / [`PasswordPolicy::verify`] on a
/// successful match. `needs_rehash` is `true` if the stored hash's params no
/// longer match the hasher's current target — rehash and overwrite on the
/// next successful login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyOutcome {
    pub needs_rehash: bool,
}

// ---------------------------------------------------------------------------
// PasswordHasher
// ---------------------------------------------------------------------------

/// Argon2id hash / verify keyed to a target [`Params`] set.
///
/// Constructed with [`PasswordHasher::with_default_params`] for the OWASP
/// 2026 recommendation, or [`PasswordHasher::new`] for explicit params (use
/// when migrating away from a previous recommendation — keep the old
/// instance around long enough to verify legacy hashes, then swap to the new
/// one and let `needs_rehash` drive the migration).
pub struct PasswordHasher {
    params: Params,
}

impl PasswordHasher {
    /// Build with explicit Argon2id params.
    pub fn new(params: Params) -> Self {
        Self { params }
    }

    /// Build with the OWASP 2026 default params.
    pub fn with_default_params() -> Self {
        Self::new(default_params())
    }

    pub fn params(&self) -> &Params {
        &self.params
    }

    /// Hash `password` with a fresh CSPRNG salt. Returns the PHC-format
    /// encoded string.
    pub fn hash(&self, password: &[u8]) -> Result<String, PasswordError> {
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, self.params.clone());
        // 16 raw bytes → 22 char base64 salt (well under password-hash's
        // 64-char max). Using getrandom 0.3 keeps the dep tree narrow —
        // password-hash's own `OsRng` is behind a feature flag we'd
        // otherwise have to opt into for one call site.
        let mut salt_bytes = [0u8; 16];
        getrandom::fill(&mut salt_bytes)
            .map_err(|e| PasswordError::Hash(format!("getrandom: {e}")))?;
        let salt = SaltString::encode_b64(&salt_bytes)
            .map_err(|e| PasswordError::Hash(e.to_string()))?;
        let hash = argon
            .hash_password(password, &salt)
            .map_err(|e| PasswordError::Hash(e.to_string()))?;
        Ok(hash.to_string())
    }

    /// Verify `password` against a PHC-format `encoded` string. On a match,
    /// returns [`VerifyOutcome`] with `needs_rehash` set if the stored
    /// params differ from the hasher's current params.
    ///
    /// `Argon2::default()` here is intentional — the verifier reads its
    /// algorithm + params from the PHC string, so the recomputation matches
    /// the stored tag even when the hasher's target params have moved on.
    pub fn verify(&self, password: &[u8], encoded: &str) -> Result<VerifyOutcome, PasswordError> {
        let parsed = PasswordHash::new(encoded)
            .map_err(|e| PasswordError::Malformed(e.to_string()))?;
        let argon = Argon2::default();
        match argon.verify_password(password, &parsed) {
            Ok(()) => {
                let needs_rehash = match Params::try_from(&parsed) {
                    Ok(stored) => stored != self.params,
                    // PHC referenced an unknown variant or params we couldn't
                    // round-trip — safest to rehash with our current shape.
                    Err(_) => true,
                };
                Ok(VerifyOutcome { needs_rehash })
            }
            Err(argon2::password_hash::Error::Password) => Err(PasswordError::WrongPassword),
            Err(e) => Err(PasswordError::Verify(e.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// BreachedPasswordChecker + impls
// ---------------------------------------------------------------------------

/// Pluggable lookup against a known-breached-password list.
///
/// `Ok(Some(count))` → password appears in the list with `count` occurrences.
/// `Ok(None)` → not seen.
/// `Err(_)` → backend failure; caller picks fail-open vs. fail-closed.
#[async_trait]
pub trait BreachedPasswordChecker: Send + Sync {
    async fn check(&self, password: &str) -> Result<Option<u64>, String>;
}

/// Always returns `Ok(None)`. For air-gapped deployments that have opted
/// out of breach checking entirely.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopBreachedPasswordChecker;

#[async_trait]
impl BreachedPasswordChecker for NoopBreachedPasswordChecker {
    async fn check(&self, _password: &str) -> Result<Option<u64>, String> {
        Ok(None)
    }
}

/// In-memory breach list. Useful for tests, curated deny-lists (top 10k
/// passwords shipped with the deployment), and as a layered front for the
/// HTTP-backed [`hibp::HibpClient`] (check local first, fall back to API).
#[derive(Default)]
pub struct MapBreachedPasswordChecker {
    inner: RwLock<HashMap<String, u64>>,
}

impl MapBreachedPasswordChecker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, password: impl Into<String>, count: u64) {
        self.inner.write().unwrap().insert(password.into(), count);
    }

    pub fn remove(&self, password: &str) -> Option<u64> {
        self.inner.write().unwrap().remove(password)
    }

    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().unwrap().is_empty()
    }
}

#[async_trait]
impl BreachedPasswordChecker for MapBreachedPasswordChecker {
    async fn check(&self, password: &str) -> Result<Option<u64>, String> {
        Ok(self.inner.read().unwrap().get(password).copied())
    }
}

// ---------------------------------------------------------------------------
// PasswordPolicy — hasher + checker glue
// ---------------------------------------------------------------------------

/// Combines a [`PasswordHasher`] with a [`BreachedPasswordChecker`]. The
/// checker runs on `hash_new_password` (registration / password change),
/// not on `verify` (login).
pub struct PasswordPolicy<C> {
    hasher: PasswordHasher,
    checker: C,
}

impl<C> PasswordPolicy<C> {
    pub fn new(hasher: PasswordHasher, checker: C) -> Self {
        Self { hasher, checker }
    }

    pub fn hasher(&self) -> &PasswordHasher {
        &self.hasher
    }

    pub fn checker(&self) -> &C {
        &self.checker
    }
}

impl<C: BreachedPasswordChecker> PasswordPolicy<C> {
    /// Reject if breached; otherwise hash. The breach check runs first so a
    /// known-bad password is never even handed to argon2 — and certainly
    /// never persisted.
    pub async fn hash_new_password(&self, password: &str) -> Result<String, PasswordError> {
        match self.checker.check(password).await {
            Ok(None) => self.hasher.hash(password.as_bytes()),
            Ok(Some(count)) => Err(PasswordError::Breached { count }),
            Err(e) => Err(PasswordError::Checker(e)),
        }
    }

    /// Verify a login. Delegates to [`PasswordHasher::verify`] — no breach
    /// check at this stage (the user is presenting credentials, not setting
    /// new ones; whether to force a rotation if the password later appears
    /// in a breach list is a separate workflow).
    pub fn verify(&self, password: &str, encoded: &str) -> Result<VerifyOutcome, PasswordError> {
        self.hasher.verify(password.as_bytes(), encoded)
    }
}

// ---------------------------------------------------------------------------
// HIBP HTTP client (sub-feature)
// ---------------------------------------------------------------------------

/// HIBP-compatible breached-password HTTP client.
///
/// Gated behind the `password-hibp` sub-feature so the trait-only consumer
/// doesn't pull `reqwest` + `tokio` + `rustls`.
#[cfg(feature = "password-hibp")]
pub mod hibp {
    use super::{BreachedPasswordChecker, async_trait};
    use sha1::{Digest, Sha1};
    use std::fmt::Write as _;

    /// Default base URL — Troy Hunt's HIBP "Pwned Passwords" range endpoint.
    pub const HIBP_DEFAULT_BASE_URL: &str = "https://api.pwnedpasswords.com/range";

    /// SHA-1 the password and return its 40-char uppercase hex digest.
    /// HIBP's wire protocol is hex-encoded and case-insensitive on input but
    /// uppercase by convention.
    pub fn sha1_hex_upper(password: &str) -> String {
        let bytes = Sha1::digest(password.as_bytes());
        let mut out = String::with_capacity(40);
        for b in bytes {
            let _ = write!(&mut out, "{:02X}", b);
        }
        out
    }

    /// k-anonymity HIBP client. Sends only the first 5 hex chars of the
    /// SHA-1 digest to the API; matches the suffix locally.
    pub struct HibpClient {
        base_url: String,
        http: reqwest::Client,
    }

    impl HibpClient {
        /// Build pointed at the public HIBP endpoint with a default
        /// `reqwest::Client`.
        pub fn new() -> Self {
            Self::with_base_url(HIBP_DEFAULT_BASE_URL)
        }

        /// Build pointed at `base_url` (e.g. a self-hosted HIBP-compatible
        /// service). `base_url` should *not* include a trailing slash.
        pub fn with_base_url(base_url: impl Into<String>) -> Self {
            Self {
                base_url: base_url.into(),
                http: reqwest::Client::new(),
            }
        }

        /// Build with an explicit `reqwest::Client` — for callers that need
        /// to inject timeouts, proxies, or a connection pool.
        pub fn with_client(base_url: impl Into<String>, http: reqwest::Client) -> Self {
            Self {
                base_url: base_url.into(),
                http,
            }
        }

        pub fn base_url(&self) -> &str {
            &self.base_url
        }
    }

    impl Default for HibpClient {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    impl BreachedPasswordChecker for HibpClient {
        async fn check(&self, password: &str) -> Result<Option<u64>, String> {
            let hex = sha1_hex_upper(password);
            // SHA-1 hex is always 40 chars — split_at(5) is in-bounds.
            let (prefix, suffix) = hex.split_at(5);
            let url = format!("{}/{prefix}", self.base_url);
            let resp = self
                .http
                .get(&url)
                .header("Add-Padding", "true")
                .send()
                .await
                .map_err(|e| e.to_string())?;
            if !resp.status().is_success() {
                return Err(format!("HIBP API returned status {}", resp.status()));
            }
            let body = resp.text().await.map_err(|e| e.to_string())?;
            Ok(scan_hibp_body(&body, suffix))
        }
    }

    /// Scan a HIBP range-response body for `suffix`. Lines are
    /// `SUFFIX:COUNT\r\n`. Returns the count for the first matching line, or
    /// `None` if no line matched. Exposed for tests / custom clients.
    pub fn scan_hibp_body(body: &str, suffix: &str) -> Option<u64> {
        for line in body.lines() {
            let line = line.trim_end_matches('\r');
            let mut parts = line.splitn(2, ':');
            let s = parts.next().unwrap_or("").trim();
            let c = parts.next().unwrap_or("").trim();
            if s.eq_ignore_ascii_case(suffix) {
                // Malformed count → treat as "seen at least once" rather
                // than dropping the match silently.
                let count: u64 = c.parse().unwrap_or(1);
                return Some(count);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn cheap_params() -> Params {
        // Minimum-legal params so tests stay fast.
        Params::new(8, 1, 1, Some(16)).expect("cheap params are legal")
    }

    fn cheap_hasher() -> PasswordHasher {
        PasswordHasher::new(cheap_params())
    }

    // -- hash + verify -------------------------------------------------------

    #[test]
    fn hash_round_trip_succeeds() {
        let h = cheap_hasher();
        let phc = h.hash(b"correct horse battery staple").unwrap();
        assert!(phc.starts_with("$argon2id$"));
        let outcome = h.verify(b"correct horse battery staple", &phc).unwrap();
        assert!(!outcome.needs_rehash);
    }

    #[test]
    fn hash_produces_unique_salt_per_call() {
        let h = cheap_hasher();
        let a = h.hash(b"hunter2").unwrap();
        let b = h.hash(b"hunter2").unwrap();
        assert_ne!(a, b, "same password must hash to different PHC strings");
    }

    #[test]
    fn verify_rejects_wrong_password() {
        let h = cheap_hasher();
        let phc = h.hash(b"swordfish").unwrap();
        let err = h.verify(b"not-swordfish", &phc).unwrap_err();
        assert!(matches!(err, PasswordError::WrongPassword));
    }

    #[test]
    fn verify_rejects_malformed_phc() {
        let h = cheap_hasher();
        let err = h.verify(b"hunter2", "not-a-phc-string").unwrap_err();
        assert!(matches!(err, PasswordError::Malformed(_)));
    }

    #[test]
    fn verify_flags_needs_rehash_when_params_change() {
        let weak = PasswordHasher::new(Params::new(8, 1, 1, Some(16)).unwrap());
        let strong = PasswordHasher::new(Params::new(16, 2, 1, Some(16)).unwrap());
        let phc = weak.hash(b"hunter2").unwrap();
        // The weak hasher recognises its own work as up-to-date.
        let outcome = weak.verify(b"hunter2", &phc).unwrap();
        assert!(!outcome.needs_rehash);
        // The strong hasher verifies successfully *but* asks for a rehash.
        let outcome = strong.verify(b"hunter2", &phc).unwrap();
        assert!(outcome.needs_rehash);
    }

    #[test]
    fn default_params_match_owasp_2026_recommendation() {
        let p = default_params();
        assert_eq!(p.m_cost(), DEFAULT_MEMORY_KIB);
        assert_eq!(p.t_cost(), DEFAULT_TIME_COST);
        assert_eq!(p.p_cost(), DEFAULT_PARALLELISM);
        assert_eq!(p.output_len(), Some(DEFAULT_OUTPUT_LEN));
    }

    // -- known-good / known-bad fixtures ------------------------------------

    /// PHC fixture minted offline with the cheap test params (m=8, t=1, p=1,
    /// output=16) over `"correct horse battery staple"`. Verifying against
    /// this fixture proves we can re-load and validate hashes produced by
    /// any compatible Argon2id implementation, not just this run.
    // Minted with cheap_params() over KNOWN_GOOD_PASSWORD using a
    // deterministic salt — see `examples/argon_gen.rs` for the generator.
    const KNOWN_GOOD_PHC: &str =
        "$argon2id$v=19$m=8,t=1,p=1$ZGV0ZXJtaW5pc3RpY19zYQ$per6Zx3YUNyNqWuJszwazg";
    const KNOWN_GOOD_PASSWORD: &str = "correct horse battery staple";

    #[test]
    fn verify_known_good_hash_succeeds() {
        // Regenerating fixtures: if argon2 ever changes its PHC formatting,
        // this test will fail and the constant above should be regenerated
        // by running `hash(KNOWN_GOOD_PASSWORD)` with cheap_params() and
        // pasting the result.
        let h = cheap_hasher();
        let outcome = h.verify(KNOWN_GOOD_PASSWORD.as_bytes(), KNOWN_GOOD_PHC).unwrap();
        // Same params as the fixture → no rehash needed.
        assert!(!outcome.needs_rehash);
    }

    #[test]
    fn verify_known_good_hash_rejects_wrong_password() {
        let h = cheap_hasher();
        let err = h.verify(b"wrong password", KNOWN_GOOD_PHC).unwrap_err();
        assert!(matches!(err, PasswordError::WrongPassword));
    }

    // -- breached-password checkers -----------------------------------------

    #[test]
    fn noop_checker_returns_none() {
        pollster::block_on(async {
            let c = NoopBreachedPasswordChecker;
            assert_eq!(c.check("anything").await.unwrap(), None);
        });
    }

    #[test]
    fn map_checker_round_trip() {
        pollster::block_on(async {
            let m = MapBreachedPasswordChecker::new();
            assert!(m.is_empty());
            m.insert("hunter2", 12_345);
            m.insert("password", 9_999_999);
            assert_eq!(m.len(), 2);
            assert_eq!(m.check("hunter2").await.unwrap(), Some(12_345));
            assert_eq!(m.check("password").await.unwrap(), Some(9_999_999));
            assert_eq!(m.check("unseen-password").await.unwrap(), None);
            assert_eq!(m.remove("hunter2"), Some(12_345));
            assert_eq!(m.check("hunter2").await.unwrap(), None);
        });
    }

    // -- policy glue --------------------------------------------------------

    fn policy_with(map: MapBreachedPasswordChecker) -> PasswordPolicy<MapBreachedPasswordChecker> {
        PasswordPolicy::new(cheap_hasher(), map)
    }

    #[test]
    fn policy_rejects_breached_password_before_hashing() {
        pollster::block_on(async {
            let map = MapBreachedPasswordChecker::new();
            map.insert("hunter2", 100);
            let policy = policy_with(map);
            let err = policy.hash_new_password("hunter2").await.unwrap_err();
            assert!(matches!(err, PasswordError::Breached { count: 100 }));
        });
    }

    #[test]
    fn policy_hashes_fresh_password() {
        pollster::block_on(async {
            let policy = policy_with(MapBreachedPasswordChecker::new());
            let phc = policy
                .hash_new_password("a-novel-passphrase-2026")
                .await
                .unwrap();
            assert!(phc.starts_with("$argon2id$"));
            let outcome = policy.verify("a-novel-passphrase-2026", &phc).unwrap();
            assert!(!outcome.needs_rehash);
        });
    }

    #[test]
    fn policy_propagates_checker_backend_failure() {
        pollster::block_on(async {
            struct Boom;
            #[async_trait]
            impl BreachedPasswordChecker for Boom {
                async fn check(&self, _: &str) -> Result<Option<u64>, String> {
                    Err("transport down".into())
                }
            }
            let policy = PasswordPolicy::new(cheap_hasher(), Boom);
            let err = policy.hash_new_password("anything").await.unwrap_err();
            match err {
                PasswordError::Checker(msg) => assert!(msg.contains("transport down")),
                other => panic!("expected Checker, got {other:?}"),
            }
        });
    }

    #[test]
    fn policy_verify_does_not_invoke_checker() {
        // Use a checker that would panic if invoked, then hash + verify and
        // confirm we reach the success path without ever calling check().
        struct PanicChecker;
        #[async_trait]
        impl BreachedPasswordChecker for PanicChecker {
            async fn check(&self, _: &str) -> Result<Option<u64>, String> {
                panic!("verify path must not invoke the breach checker");
            }
        }
        let phc = cheap_hasher().hash(b"hunter2").unwrap();
        let policy = PasswordPolicy::new(cheap_hasher(), PanicChecker);
        let outcome = policy.verify("hunter2", &phc).unwrap();
        assert!(!outcome.needs_rehash);
    }

    // -- HIBP sub-feature ---------------------------------------------------

    #[cfg(feature = "password-hibp")]
    mod hibp_tests {
        use super::super::hibp::{scan_hibp_body, sha1_hex_upper};

        #[test]
        fn sha1_hex_upper_known_value() {
            // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8.
            // This is the public test vector HIBP itself documents.
            assert_eq!(
                sha1_hex_upper("password"),
                "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
            );
        }

        #[test]
        fn sha1_prefix_is_always_5_chars() {
            for pw in ["", "a", "hunter2", "correct horse battery staple"] {
                let hex = sha1_hex_upper(pw);
                assert_eq!(hex.len(), 40, "sha1 hex must be 40 chars for {pw:?}");
                let (prefix, suffix) = hex.split_at(5);
                assert_eq!(prefix.len(), 5);
                assert_eq!(suffix.len(), 35);
            }
        }

        #[test]
        fn scan_body_returns_count_for_matching_suffix() {
            // Real HIBP response shape (CRLF, uppercase suffix, decimal count).
            let body = "AAAAA:3\r\n\
                        BBBBB:42\r\n\
                        61E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\r\n\
                        ZZZZZ:1\r\n";
            let suffix = "61E4C9B93F3F0682250B6CF8331B7EE68FD8";
            assert_eq!(scan_hibp_body(body, suffix), Some(9_659_365));
        }

        #[test]
        fn scan_body_returns_none_when_suffix_absent() {
            let body = "AAAAA:3\r\nBBBBB:42\r\n";
            assert_eq!(scan_hibp_body(body, "DEADBEEF"), None);
        }

        #[test]
        fn scan_body_is_case_insensitive_on_suffix() {
            let body = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8:5\r\n";
            assert_eq!(
                scan_hibp_body(body, "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"),
                Some(5)
            );
        }

        #[test]
        fn scan_body_handles_missing_count_as_one() {
            let body = "ABCDE:not-a-number\r\n";
            assert_eq!(scan_hibp_body(body, "ABCDE"), Some(1));
        }
    }
}
