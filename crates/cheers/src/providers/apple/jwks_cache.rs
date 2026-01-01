//! Apple JWKS — cached, weekly-refreshed, on-failure-refreshable.
//!
//! Apple publishes the public keys used to sign `id_token`s at
//! [`APPLE_JWKS_URI`]; Apple rotates keys infrequently but does keep
//! several active at once (the JWKS is a set, and the `id_token`'s `kid`
//! header field picks the active one). Verifiers must therefore keep an
//! up-to-date JWKS — every-request fetching is slow and rate-limited; a
//! permanently cached JWKS misses the next rotation.
//!
//! The recommended pattern (Apple's docs, RFC 7517 §4.5 advice for OIDC
//! consumers) is:
//!
//! - Fetch once at process boot.
//! - Refresh on a long timer (Apple's keys live for months; a **weekly**
//!   refresh is conservative; see [`DEFAULT_REFRESH_AFTER_SECONDS`]).
//! - **Also** refresh on demand when an `id_token`'s `kid` isn't in the
//!   cached JWKS — this catches a rotation between scheduled refreshes.
//!
//! [`AppleJwksCache`] implements all three. The caller invokes
//! [`AppleJwksCache::jwks`] each verify; if the cached set is older than
//! `refresh_after_seconds` (or absent), the cache fetches fresh under a
//! `Mutex` and stores. On a verify failure with `kid not in JWKS`, the
//! caller invokes [`AppleJwksCache::invalidate`] before retrying — the
//! next `jwks()` re-fetches.
//!
//! # Pluggable fetcher
//!
//! [`JwksFetcher`] is the trait the cache calls into. [`HttpJwksFetcher`]
//! is the production impl (GET against [`APPLE_JWKS_URI`] via `reqwest`).
//! Tests inject a counting/fixture fetcher to assert the cache's
//! fetch-frequency contract without standing up wiremock.
//!
//! # Concurrency
//!
//! The cache uses `std::sync::Mutex` and holds it **only across the
//! cached-state read/write** — never across the network fetch. Under
//! concurrent verifies the worst case is two simultaneous fetches when
//! the cache is cold; both complete and one of the writes is dropped (the
//! other replaces it). This is the right trade-off — coalescing the
//! concurrent fetch into a single in-flight call would add complexity
//! (tokio `OnceCell` or a `Notify`) for a once-per-week event.
//!
//! # Example
//!
//! ```no_run
//! use std::sync::Arc;
//! use cheers::providers::apple::{
//!     AppleJwksCache, HttpJwksFetcher, APPLE_JWKS_URI,
//! };
//! use openidconnect::{reqwest, JsonWebKeySetUrl};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let http = reqwest::ClientBuilder::new()
//!     .redirect(reqwest::redirect::Policy::none())
//!     .build()?;
//! let fetcher = HttpJwksFetcher::for_apple();
//! let cache = AppleJwksCache::new(fetcher);
//!
//! let now = 1_700_000_000;
//! let jwks = cache.jwks(now, &http).await?;
//! // ...build openidconnect::IdTokenVerifier from (*jwks).clone()...
//!
//! // On `kid not found` from id_token verification, force a refresh:
//! cache.invalidate();
//! let jwks = cache.jwks(now, &http).await?;
//! # drop(jwks); Ok(()) }
//! ```
//!
//! [`APPLE_JWKS_URI`]: super::redirect::APPLE_JWKS_URI

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use openidconnect::core::CoreJsonWebKeySet;
use openidconnect::{reqwest, JsonWebKeySetUrl};

use super::redirect::APPLE_JWKS_URI;

/// Refresh the cached JWKS after this many seconds (≈ 1 week).
///
/// Apple rotates keys on the order of months but does not pre-announce
/// rotations; a weekly poll catches one within ≤7 days even if the
/// rotation lands between two on-demand verifies. The
/// [`AppleJwksCache::invalidate`] path covers the corner case where a
/// rotation lands *and* a verify happens before the weekly timer.
pub const DEFAULT_REFRESH_AFTER_SECONDS: i64 = 7 * 24 * 60 * 60;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JwksError {
    /// HTTP fetch failed (network, DNS, TLS, 4xx/5xx status).
    #[error("jwks http: {0}")]
    Http(String),

    /// HTTP succeeded but the response body wasn't parseable JWKS JSON.
    #[error("jwks parse: {0}")]
    Parse(String),

    /// `JsonWebKeySetUrl::new` rejected the URL string given to
    /// [`HttpJwksFetcher::with_url`].
    #[error("invalid jwks url: {0}")]
    InvalidUrl(String),
}

// ---------------------------------------------------------------------------
// JwksFetcher trait
// ---------------------------------------------------------------------------

/// What [`AppleJwksCache`] calls into on cache miss / refresh.
///
/// Implementors must be `Send + Sync` so the cache can be shared across
/// tasks. Production code uses [`HttpJwksFetcher`]; tests inject a
/// counting/fixture impl.
#[async_trait]
pub trait JwksFetcher: Send + Sync {
    async fn fetch(&self, http: &reqwest::Client) -> Result<CoreJsonWebKeySet, JwksError>;
}

// ---------------------------------------------------------------------------
// HttpJwksFetcher — production impl
// ---------------------------------------------------------------------------

/// Fetches a [`CoreJsonWebKeySet`] over HTTP from a configured URL.
///
/// [`HttpJwksFetcher::for_apple`] bakes in [`APPLE_JWKS_URI`]; use
/// [`HttpJwksFetcher::with_url`] for self-hosted Apple-compatible OPs or
/// test endpoints that don't go through [`AppleJwksCache::with_fetcher`].
#[derive(Debug, Clone)]
pub struct HttpJwksFetcher {
    url: JsonWebKeySetUrl,
}

impl HttpJwksFetcher {
    /// Build pointing at the canonical [`APPLE_JWKS_URI`].
    pub fn for_apple() -> Self {
        Self {
            url: JsonWebKeySetUrl::new(APPLE_JWKS_URI.to_owned())
                .expect("APPLE_JWKS_URI is a const, must parse"),
        }
    }

    /// Build pointing at an arbitrary URL. Used by tests + self-hosted
    /// Apple-compatible deployments. Returns
    /// [`JwksError::InvalidUrl`] if the string can't be parsed.
    pub fn with_url(url: impl Into<String>) -> Result<Self, JwksError> {
        let url = url.into();
        let url = JsonWebKeySetUrl::new(url.clone())
            .map_err(|e| JwksError::InvalidUrl(format!("{url}: {e}")))?;
        Ok(Self { url })
    }

    pub fn url(&self) -> &JsonWebKeySetUrl {
        &self.url
    }
}

#[async_trait]
impl JwksFetcher for HttpJwksFetcher {
    async fn fetch(&self, http: &reqwest::Client) -> Result<CoreJsonWebKeySet, JwksError> {
        let resp = http
            .get(self.url.as_str())
            .send()
            .await
            .map_err(|e| JwksError::Http(format!("{e}")))?
            .error_for_status()
            .map_err(|e| JwksError::Http(format!("{e}")))?;
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| JwksError::Http(format!("{e}")))?;
        serde_json::from_slice::<CoreJsonWebKeySet>(&bytes)
            .map_err(|e| JwksError::Parse(format!("{e}")))
    }
}

// ---------------------------------------------------------------------------
// AppleJwksCache
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct CachedJwks {
    jwks: Arc<CoreJsonWebKeySet>,
    fetched_at: i64,
}

/// Weekly-refreshed Apple JWKS cache.
///
/// Construct once at process boot, share via `Arc<AppleJwksCache<…>>`
/// everywhere an `id_token` is verified. Generic over [`JwksFetcher`] so
/// tests can inject a fixture fetcher; in production this defaults to
/// [`HttpJwksFetcher`].
///
/// Concurrency caveat: see the module-level note. Cold-cache concurrent
/// fetches can race, but the worst case is one wasted fetch per such
/// race — production traffic patterns will pin one entry quickly.
pub struct AppleJwksCache<F: JwksFetcher = HttpJwksFetcher> {
    fetcher: F,
    refresh_after_seconds: i64,
    cache: Mutex<Option<CachedJwks>>,
}

impl AppleJwksCache<HttpJwksFetcher> {
    /// Default cache pointed at Apple's published JWKS URI.
    pub fn for_apple() -> Self {
        Self::new(HttpJwksFetcher::for_apple())
    }
}

impl<F: JwksFetcher> AppleJwksCache<F> {
    /// Build with the given fetcher.
    pub fn new(fetcher: F) -> Self {
        Self {
            fetcher,
            refresh_after_seconds: DEFAULT_REFRESH_AFTER_SECONDS,
            cache: Mutex::new(None),
        }
    }

    /// Override the refresh interval. Use shorter values during development
    /// or when integrating with Apple-compatible servers that rotate keys
    /// more often. Must be positive.
    pub fn with_refresh_after_seconds(mut self, seconds: i64) -> Self {
        assert!(
            seconds > 0,
            "refresh_after_seconds must be positive, got {seconds}"
        );
        self.refresh_after_seconds = seconds;
        self
    }

    pub fn refresh_after_seconds(&self) -> i64 {
        self.refresh_after_seconds
    }

    /// Borrow the underlying fetcher. Useful for tests, or for callers
    /// that want to introspect the configured URL.
    pub fn fetcher(&self) -> &F {
        &self.fetcher
    }

    /// Return the current JWKS. Serves cache if fresh; else fetches.
    ///
    /// "Fresh" means `now - fetched_at < refresh_after_seconds`. Callers
    /// pass `now` (unix-seconds) so the cache stays testable; pair with
    /// `SystemTime::now()` in production.
    pub async fn jwks(
        &self,
        now: i64,
        http: &reqwest::Client,
    ) -> Result<Arc<CoreJsonWebKeySet>, JwksError> {
        // Fast path under lock — read cached + check freshness, drop the
        // lock before any async work.
        {
            let guard = self.cache.lock().expect("jwks cache mutex");
            if let Some(c) = guard.as_ref() {
                if self.is_fresh(c.fetched_at, now) {
                    return Ok(Arc::clone(&c.jwks));
                }
            }
        }
        // Slow path — fetch without holding the lock.
        let fresh = self.fetcher.fetch(http).await?;
        let arc = Arc::new(fresh);
        let mut guard = self.cache.lock().expect("jwks cache mutex");
        // Another task may have raced us and refreshed while we were
        // awaiting the fetch — if their entry is fresh, prefer it; we
        // discard ours. Idempotent: both fetches see the same Apple JWKS.
        if let Some(c) = guard.as_ref() {
            if self.is_fresh(c.fetched_at, now) {
                return Ok(Arc::clone(&c.jwks));
            }
        }
        *guard = Some(CachedJwks {
            jwks: Arc::clone(&arc),
            fetched_at: now,
        });
        Ok(arc)
    }

    /// Drop the cached JWKS. Next [`jwks`](Self::jwks) call re-fetches.
    /// Wire this on `kid not found` from `id_token` verification — Apple
    /// rotated a key between scheduled refreshes.
    pub fn invalidate(&self) {
        *self.cache.lock().expect("jwks cache mutex") = None;
    }

    /// Observability: `fetched_at` of the currently cached JWKS, if any.
    pub fn cached_fetched_at(&self) -> Option<i64> {
        self.cache
            .lock()
            .expect("jwks cache mutex")
            .as_ref()
            .map(|c| c.fetched_at)
    }

    /// `true` when something is cached, regardless of freshness.
    pub fn is_cached(&self) -> bool {
        self.cache
            .lock()
            .expect("jwks cache mutex")
            .is_some()
    }

    fn is_fresh(&self, fetched_at: i64, now: i64) -> bool {
        // `now < fetched_at + ttl` keeps the boundary case (now exactly
        // equal to fetched_at + ttl) as "stale, refresh" — same convention
        // as AppleClientSecret's refresh-margin check.
        now.saturating_sub(fetched_at) < self.refresh_after_seconds
    }
}

impl<F: JwksFetcher> std::fmt::Debug for AppleJwksCache<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppleJwksCache")
            .field("refresh_after_seconds", &self.refresh_after_seconds)
            .field("cached_fetched_at", &self.cached_fetched_at())
            .finish()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    //! Fast, network-free tests. Concurrency + freshness logic exercised
    //! through a counting fixture fetcher; the HTTP fetcher itself is
    //! exercised by the redirect.rs wiremock round-trip (it pulls JWKS
    //! via the standard discover_async path).

    use super::*;
    use openidconnect::core::CoreJsonWebKey;
    use openidconnect::JsonWebKey;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Drop-in `reqwest::Client` for tests — `fetch` calls never hit it.
    fn dummy_http() -> reqwest::Client {
        reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest builds")
    }

    /// Counts every call to `fetch`. Always returns a fresh JWKS whose
    /// single key's `kid` echoes the call count — so tests can assert
    /// the cache served a *specific* fetch and not just any.
    struct CountingFetcher {
        calls: AtomicU64,
    }

    impl CountingFetcher {
        fn new() -> Self {
            Self {
                calls: AtomicU64::new(0),
            }
        }
        fn calls(&self) -> u64 {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl JwksFetcher for CountingFetcher {
        async fn fetch(&self, _http: &reqwest::Client) -> Result<CoreJsonWebKeySet, JwksError> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            // Build a CoreJsonWebKey from a parse — easier than wrangling
            // CoreJsonWebKey::new constructor signatures across openidconnect
            // versions. RSA shape borrowed from openidconnect's own test JWK.
            let jwk_json = format!(
                r#"{{
                    "kty": "RSA",
                    "kid": "test-key-{n}",
                    "use": "sig",
                    "alg": "RS256",
                    "n": "sRMj0YYjy7du6v1gWyKSTJx3YjBzZTG0XotRP0IaObw0k-6830dXadjL5jVhSWNdcg9OyMyTGWfdNqfdrS6ppBqlQNgjZJdloIqL9zOLBZrDm7G4-qN4KeZ4_5TyEilq2zOHHGFEzXpOq_UxqVnm3J4fhjqCNaS2nKd7HVVXGBQQ-4-FdVT-MyJXemw5maz2F_h324TQi6XoUPEwUddxBwLQFSOlzWnHYMc4_lcyZJ8MpTXCMPe_YJFNtb9CaikKUdf8x4mzwH7usSf8s2d6R4dQITzKrjrEJ0u3w3eGkBBapoMVFBGPjP3Haz5FsVtHc5VEN3FZVIDF6HrbJH1C4Q",
                    "e": "AQAB"
                }}"#
            );
            let key: CoreJsonWebKey =
                serde_json::from_str(&jwk_json).expect("fixture JWK parses");
            Ok(CoreJsonWebKeySet::new(vec![key]))
        }
    }

    fn kid_of(jwks: &CoreJsonWebKeySet) -> Option<String> {
        // CoreJsonWebKeySet::keys() returns refs; the JsonWebKey trait's
        // key_id() returns Option<&JsonWebKeyId> where JsonWebKeyId is a
        // newtype around String (Display impl), so &**id is the &str.
        jwks.keys()
            .first()
            .and_then(|k| k.key_id())
            .map(|id| id.to_string())
    }

    // -- cold cache & freshness ------------------------------------------------

    #[tokio::test]
    async fn first_call_fetches_and_caches() {
        let cache = AppleJwksCache::new(CountingFetcher::new());
        assert!(!cache.is_cached());
        assert!(cache.cached_fetched_at().is_none());

        let jwks = cache.jwks(1_000, &dummy_http()).await.unwrap();
        assert_eq!(cache.fetcher().calls(), 1);
        assert_eq!(kid_of(&jwks).as_deref(), Some("test-key-1"));
        assert!(cache.is_cached());
        assert_eq!(cache.cached_fetched_at(), Some(1_000));
    }

    #[tokio::test]
    async fn second_call_inside_window_serves_cache() {
        let cache = AppleJwksCache::new(CountingFetcher::new());
        let _ = cache.jwks(1_000, &dummy_http()).await.unwrap();
        let jwks = cache
            .jwks(1_000 + DEFAULT_REFRESH_AFTER_SECONDS - 1, &dummy_http())
            .await
            .unwrap();
        assert_eq!(cache.fetcher().calls(), 1, "cache hit, no refetch");
        // Still the first fetch's JWKS.
        assert_eq!(kid_of(&jwks).as_deref(), Some("test-key-1"));
    }

    #[tokio::test]
    async fn call_at_refresh_boundary_refetches() {
        let cache = AppleJwksCache::new(CountingFetcher::new());
        let _ = cache.jwks(1_000, &dummy_http()).await.unwrap();
        // `now >= fetched_at + ttl` is stale — at exactly the boundary
        // we refresh.
        let jwks = cache
            .jwks(1_000 + DEFAULT_REFRESH_AFTER_SECONDS, &dummy_http())
            .await
            .unwrap();
        assert_eq!(cache.fetcher().calls(), 2);
        assert_eq!(kid_of(&jwks).as_deref(), Some("test-key-2"));
        assert_eq!(
            cache.cached_fetched_at(),
            Some(1_000 + DEFAULT_REFRESH_AFTER_SECONDS)
        );
    }

    #[tokio::test]
    async fn invalidate_forces_refetch_next_call() {
        let cache = AppleJwksCache::new(CountingFetcher::new());
        let _ = cache.jwks(1_000, &dummy_http()).await.unwrap();
        assert_eq!(cache.fetcher().calls(), 1);
        cache.invalidate();
        assert!(!cache.is_cached());
        assert!(cache.cached_fetched_at().is_none());
        let jwks = cache.jwks(1_001, &dummy_http()).await.unwrap();
        assert_eq!(cache.fetcher().calls(), 2);
        assert_eq!(kid_of(&jwks).as_deref(), Some("test-key-2"));
    }

    #[tokio::test]
    async fn with_refresh_after_seconds_overrides_default() {
        let cache = AppleJwksCache::new(CountingFetcher::new())
            .with_refresh_after_seconds(60);
        assert_eq!(cache.refresh_after_seconds(), 60);
        let _ = cache.jwks(1_000, &dummy_http()).await.unwrap();
        let _ = cache.jwks(1_059, &dummy_http()).await.unwrap();
        assert_eq!(cache.fetcher().calls(), 1, "still fresh under 60s");
        let _ = cache.jwks(1_060, &dummy_http()).await.unwrap();
        assert_eq!(cache.fetcher().calls(), 2, "boundary refresh");
    }

    #[test]
    #[should_panic(expected = "refresh_after_seconds must be positive")]
    fn with_refresh_after_seconds_rejects_zero() {
        let _ = AppleJwksCache::new(CountingFetcher::new()).with_refresh_after_seconds(0);
    }

    #[test]
    #[should_panic(expected = "refresh_after_seconds must be positive")]
    fn with_refresh_after_seconds_rejects_negative() {
        let _ = AppleJwksCache::new(CountingFetcher::new()).with_refresh_after_seconds(-1);
    }

    // -- HttpJwksFetcher construction ----------------------------------------

    #[test]
    fn http_fetcher_for_apple_targets_published_uri() {
        let f = HttpJwksFetcher::for_apple();
        assert_eq!(f.url().as_str(), APPLE_JWKS_URI);
    }

    #[test]
    fn http_fetcher_with_url_rejects_garbage() {
        let err = HttpJwksFetcher::with_url("not a url").unwrap_err();
        assert!(matches!(err, JwksError::InvalidUrl(_)));
    }

    #[test]
    fn http_fetcher_with_url_accepts_self_hosted() {
        let f = HttpJwksFetcher::with_url("https://idp.example.invalid/keys").unwrap();
        assert_eq!(f.url().as_str(), "https://idp.example.invalid/keys");
    }

    // -- error propagation ---------------------------------------------------

    /// Always errors — exercises the cache's error path (no entry stored,
    /// next call retries).
    struct FailingFetcher {
        calls: AtomicU64,
    }
    impl FailingFetcher {
        fn new() -> Self {
            Self {
                calls: AtomicU64::new(0),
            }
        }
        fn calls(&self) -> u64 {
            self.calls.load(Ordering::SeqCst)
        }
    }
    #[async_trait]
    impl JwksFetcher for FailingFetcher {
        async fn fetch(&self, _http: &reqwest::Client) -> Result<CoreJsonWebKeySet, JwksError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(JwksError::Http("simulated network failure".into()))
        }
    }

    #[tokio::test]
    async fn fetch_failure_does_not_poison_cache() {
        let cache = AppleJwksCache::new(FailingFetcher::new());
        let err = cache.jwks(1_000, &dummy_http()).await.unwrap_err();
        assert!(matches!(err, JwksError::Http(_)));
        assert!(!cache.is_cached(), "failed fetch must not be stored");
        let _ = cache.jwks(1_001, &dummy_http()).await.unwrap_err();
        // Re-attempt: the cache re-calls the fetcher rather than caching
        // the error and short-circuiting.
        assert_eq!(cache.fetcher().calls(), 2);
    }

    // -- Arc identity --------------------------------------------------------

    #[tokio::test]
    async fn cache_returns_shared_arc_to_same_jwks() {
        let cache = AppleJwksCache::new(CountingFetcher::new());
        let a = cache.jwks(1_000, &dummy_http()).await.unwrap();
        let b = cache.jwks(1_001, &dummy_http()).await.unwrap();
        assert!(
            Arc::ptr_eq(&a, &b),
            "cache hit should return the same Arc, not a clone"
        );
    }

    // -- Send + Sync ---------------------------------------------------------

    #[test]
    fn cache_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AppleJwksCache<HttpJwksFetcher>>();
        assert_send_sync::<AppleJwksCache<CountingFetcher>>();
    }
}
