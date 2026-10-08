//! JWKS document, key set, and the W159 cache (first fetch, atomic refresh,
//! rate-limited kid-miss refetch, restart from disk).
//!
//! Moved here from kamaji-bin's `auth/jwks.rs` + `auth/verifier.rs` (R731-F6,
//! product-scopes-and-authorization.md §D5) so every resource server — kamaji,
//! noisetable's services, cheers-axum's [`McpAuthState`] — shares one cache.
//!
//! W159 §Kamaji startup and JWKS lifecycle pins the behavior:
//!
//! - Boot: no cache on disk + source unreachable is fatal
//!   ([`JwksError::BootFetchFatal`]). A fresh cache serves without fetching; a
//!   stale one is refreshed synchronously, falling back to the stale copy when
//!   `serve_stale_on_failure` is set.
//! - Steady state: serve from RAM. Refresh replaces the whole [`KeySet`] behind
//!   one pointer swap and persists via temp file + rename, so a concurrent
//!   verify never sees a torn key set. The periodic tick is the caller's: this
//!   crate owns no runtime (kamaji spawns it on tokio).
//! - kid-miss: one out-of-band refetch, rate-limited to one per
//!   `kid_miss_rate_limit`, so attacker-chosen kids can't drive the source.
//!
//! Fetching sits behind [`JwksSource`]. The reqwest-backed [`HttpJwksSource`]
//! is behind the `jwks-http` feature, default off, so an edge consumer that
//! holds a static [`KeySet`] links no HTTP client.
//!
//! The JWK shape accepted is OKP+Ed25519 (`kty="OKP"`, `crv="Ed25519"`, `x` =
//! base64url 32-byte key, `kid` required); other key types are skipped. Every
//! entry carries cheers's `principal` + `role` (R731-B1), required on the wire.
//!
//! [`McpAuthState`]: https://docs.rs/cheers-axum

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use cheers_core::KeyRole;

/// One published JWK entry, in JWKS doc form.
///
/// Only `kty`, `principal` and `role` are required so foreign-`kty` entries
/// round-trip even when they omit fields mandatory for their own shape. `x`
/// and `kid` are required for OKP/Ed25519; [`KeySet::from_doc`] enforces that.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwkKey {
    pub kty: String,
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default, rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    /// Owner of the key: cheers's issuer id, or `svc:<id>`.
    pub principal: String,
    /// What the key may sign; enforced by [`KeySetVerifier`](crate::KeySetVerifier).
    pub role: KeyRole,
}

impl JwkKey {
    /// An OKP/Ed25519 signing JWK for `public_key`.
    pub fn ed25519(
        kid: impl Into<String>,
        public_key: &[u8; 32],
        principal: impl Into<String>,
        role: KeyRole,
    ) -> Self {
        Self {
            kty: "OKP".into(),
            crv: Some("Ed25519".into()),
            x: Some(URL_SAFE_NO_PAD.encode(public_key)),
            kid: Some(kid.into()),
            use_: Some("sig".into()),
            alg: Some("EdDSA".into()),
            principal: principal.into(),
            role,
        }
    }
}

/// JWKS document — the wire shape at `/.well-known/jwks.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwksDoc {
    pub keys: Vec<JwkKey>,
}

/// One verifier-ready key: decoded Ed25519 public key, its owner, its role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEntry {
    pub public_key: [u8; 32],
    pub principal: String,
    pub role: KeyRole,
}

/// Decoded key set indexed by `kid`. Immutable; a refresh builds a new one.
#[derive(Debug, Clone)]
pub struct KeySet {
    keys: HashMap<String, KeyEntry>,
    /// The doc it was decoded from — what gets persisted.
    doc: JwksDoc,
}

impl KeySet {
    /// Decode a JWKS doc. Non-Ed25519 entries are skipped; a doc with zero
    /// usable keys is [`JwksError::Parse`] — there is nothing to verify with.
    pub fn from_doc(doc: JwksDoc) -> Result<Self, JwksError> {
        let mut keys = HashMap::with_capacity(doc.keys.len());
        for k in &doc.keys {
            if k.kty != "OKP" || k.crv.as_deref() != Some("Ed25519") {
                continue;
            }
            let kid = k.kid.clone().ok_or_else(|| JwksError::BadKey {
                kid: "<missing>".into(),
                reason: "OKP/Ed25519 entry missing kid".into(),
            })?;
            let x = k.x.as_ref().ok_or_else(|| JwksError::BadKey {
                kid: kid.clone(),
                reason: "OKP/Ed25519 entry missing x".into(),
            })?;
            let bytes = URL_SAFE_NO_PAD.decode(x).map_err(|e| JwksError::BadKey {
                kid: kid.clone(),
                reason: format!("base64url decode: {e}"),
            })?;
            let public_key: [u8; 32] =
                bytes.try_into().map_err(|v: Vec<u8>| JwksError::BadKey {
                    kid: kid.clone(),
                    reason: format!("expected 32 bytes, got {}", v.len()),
                })?;
            keys.insert(
                kid,
                KeyEntry {
                    public_key,
                    principal: k.principal.clone(),
                    role: k.role,
                },
            );
        }
        if keys.is_empty() {
            return Err(JwksError::Parse("JWKS contained no OKP/Ed25519 keys".into()));
        }
        Ok(Self { keys, doc })
    }

    pub fn get(&self, kid: &str) -> Option<&KeyEntry> {
        self.keys.get(kid)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn doc(&self) -> &JwksDoc {
        &self.doc
    }
}

/// JWKS fetch / decode / persist failures.
#[derive(Debug, thiserror::Error)]
pub enum JwksError {
    #[error(
        "insecure cheers issuer {issuer:?}: the JWKS must be fetched over \
         https:// (plaintext http:// is allowed only for loopback hosts)"
    )]
    InsecureIssuer { issuer: String },

    #[error("JWKS source unreachable at boot and no cache present at {cache_path:?}: {source}")]
    BootFetchFatal {
        cache_path: PathBuf,
        #[source]
        source: Box<JwksError>,
    },

    #[error("JWKS fetch failed: {0}")]
    Fetch(String),

    #[error("JWKS parse failed: {0}")]
    Parse(String),

    #[error("JWK {kid:?} has invalid Ed25519 public key: {reason}")]
    BadKey { kid: String, reason: String },

    #[error("JWKS cache I/O failure at {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("JWKS cache serialize failed: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Where a [`JwksCache`] gets its documents from.
#[async_trait::async_trait]
pub trait JwksSource: Send + Sync + std::fmt::Debug {
    async fn fetch(&self) -> Result<JwksDoc, JwksError>;
}

/// reqwest-backed [`JwksSource`]: GET one URL, parse the body as a JWKS doc.
#[cfg(feature = "jwks-http")]
#[derive(Debug, Clone)]
pub struct HttpJwksSource {
    http: reqwest::Client,
    url: String,
}

#[cfg(feature = "jwks-http")]
impl HttpJwksSource {
    /// Fetch from `url` with a 10s timeout. Validating that `url` is https
    /// (or loopback) is the caller's: it knows its issuer config.
    pub fn new(url: impl Into<String>) -> Result<Self, JwksError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| JwksError::Fetch(e.to_string()))?;
        Ok(Self {
            http,
            url: url.into(),
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }
}

#[cfg(feature = "jwks-http")]
#[async_trait::async_trait]
impl JwksSource for HttpJwksSource {
    async fn fetch(&self) -> Result<JwksDoc, JwksError> {
        let fetch = |e: reqwest::Error| JwksError::Fetch(e.to_string());
        self.http
            .get(&self.url)
            .send()
            .await
            .map_err(fetch)?
            .error_for_status()
            .map_err(fetch)?
            .json::<JwksDoc>()
            .await
            .map_err(fetch)
    }
}

/// Tunables for [`JwksCache`]. Defaults match W159.
#[derive(Debug, Clone)]
pub struct JwksCacheConfig {
    /// On-disk cache file (restart resilience).
    pub cache_path: PathBuf,
    /// Age past which a cache is stale (boot refreshes it synchronously) and
    /// the period a caller's refresh tick should use.
    pub refresh_interval: Duration,
    /// Minimum gap between two kid-miss refetches.
    pub kid_miss_rate_limit: Duration,
    /// Serve a stale on-disk cache when the source is unreachable at boot.
    pub serve_stale_on_failure: bool,
}

impl JwksCacheConfig {
    pub fn new(cache_path: impl Into<PathBuf>) -> Self {
        Self {
            cache_path: cache_path.into(),
            refresh_interval: Duration::from_secs(3600),
            kid_miss_rate_limit: Duration::from_secs(1),
            serve_stale_on_failure: true,
        }
    }
}

/// The live W159 cache. Share via `Arc`; every method is `&self`.
#[derive(Debug)]
pub struct JwksCache {
    source: Box<dyn JwksSource>,
    config: JwksCacheConfig,
    current: RwLock<Current>,
    /// Last kid-miss refetch; `None` until the first miss.
    kid_miss_last: Mutex<Option<Instant>>,
}

#[derive(Debug, Clone)]
struct Current {
    keys: Arc<KeySet>,
    last_refresh: SystemTime,
}

impl JwksCache {
    /// Boot per W159 §Restart resilience (see the module docs).
    pub async fn boot(
        source: Box<dyn JwksSource>,
        config: JwksCacheConfig,
    ) -> Result<Self, JwksError> {
        let current = match load_from_disk(&config.cache_path)? {
            Some((keys, last_refresh)) => {
                let stale = last_refresh
                    .elapsed()
                    .map(|age| age > config.refresh_interval)
                    .unwrap_or(true);
                if !stale {
                    Current { keys: Arc::new(keys), last_refresh }
                } else {
                    match fetch_and_persist(source.as_ref(), &config.cache_path).await {
                        Ok(c) => c,
                        Err(e) if config.serve_stale_on_failure => {
                            tracing::warn!(error = ?e, "JWKS source unreachable at boot; serving stale cache");
                            Current { keys: Arc::new(keys), last_refresh }
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
            None => fetch_and_persist(source.as_ref(), &config.cache_path)
                .await
                .map_err(|e| JwksError::BootFetchFatal {
                    cache_path: config.cache_path.clone(),
                    source: Box::new(e),
                })?,
        };
        Ok(Self {
            source,
            config,
            current: RwLock::new(current),
            kid_miss_last: Mutex::new(None),
        })
    }

    pub fn config(&self) -> &JwksCacheConfig {
        &self.config
    }

    /// The key set every verify currently reads.
    pub fn keys(&self) -> Arc<KeySet> {
        self.current.read().expect("jwks lock").keys.clone()
    }

    /// Wall-clock of the last successful fetch (persisted across restarts).
    pub fn last_refresh(&self) -> SystemTime {
        self.current.read().expect("jwks lock").last_refresh
    }

    /// Fetch, persist, then swap. Drive it from a periodic tick; failures
    /// leave the current set in place.
    pub async fn refresh(&self) -> Result<(), JwksError> {
        let next = fetch_and_persist(self.source.as_ref(), &self.config.cache_path).await?;
        *self.current.write().expect("jwks lock") = next;
        Ok(())
    }

    /// The key set to verify a token signed under `kid` with: the current one
    /// if it knows `kid`, else the result of one rate-limited refetch.
    pub async fn keys_for(&self, kid: &str) -> Arc<KeySet> {
        let keys = self.keys();
        if keys.get(kid).is_some() {
            return keys;
        }
        self.try_kid_miss_refresh().await;
        self.keys()
    }

    async fn try_kid_miss_refresh(&self) {
        {
            let mut last = self.kid_miss_last.lock().expect("kid-miss lock");
            let now = Instant::now();
            if let Some(prev) = *last {
                if now.duration_since(prev) < self.config.kid_miss_rate_limit {
                    return;
                }
            }
            *last = Some(now);
        }
        if let Err(e) = self.refresh().await {
            tracing::warn!(error = ?e, "kid-miss JWKS refresh failed");
        }
    }

    #[cfg(test)]
    fn kid_miss_last(&self) -> Option<Instant> {
        *self.kid_miss_last.lock().unwrap()
    }
}

async fn fetch_and_persist(source: &dyn JwksSource, path: &Path) -> Result<Current, JwksError> {
    let keys = KeySet::from_doc(source.fetch().await?)?;
    let last_refresh = SystemTime::now();
    write_atomic(path, &keys, last_refresh)?;
    Ok(Current {
        keys: Arc::new(keys),
        last_refresh,
    })
}

/// On-disk shape: the doc plus the wall-clock of the last fetch. `format` is
/// bumped whenever the shape changes and [`load_from_disk`] discards any other
/// value. Format 2 (R731-B1) added required JWK `principal` + `role`; format-1
/// files carried no `format` key at all.
#[derive(Debug, Serialize, Deserialize)]
struct StoredCache {
    format: u32,
    doc: JwksDoc,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_refresh_secs: Option<u64>,
}

const CACHE_FORMAT: u32 = 2;

#[derive(Deserialize)]
struct CacheHeader {
    format: Option<u32>,
}

/// Load a persisted cache. `Ok(None)` when the file is absent, and also when it
/// is in an older format: that file is deleted, not parsed, so boot refetches.
pub fn load_from_disk(path: &Path) -> Result<Option<(KeySet, SystemTime)>, JwksError> {
    let io = |source| JwksError::Io {
        path: path.to_path_buf(),
        source,
    };
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io(e)),
    };
    let header: CacheHeader = serde_json::from_slice(&bytes)?;
    if header.format != Some(CACHE_FORMAT) {
        tracing::warn!(path = %path.display(), found = ?header.format, expected = CACHE_FORMAT,
            "discarding JWKS cache in an old format; will refetch");
        std::fs::remove_file(path).map_err(io)?;
        return Ok(None);
    }
    let stored: StoredCache = serde_json::from_slice(&bytes)?;
    let keys = KeySet::from_doc(stored.doc)?;
    let last_refresh = stored
        .last_refresh_secs
        .and_then(|s| UNIX_EPOCH.checked_add(Duration::from_secs(s)))
        .unwrap_or(UNIX_EPOCH);
    Ok(Some((keys, last_refresh)))
}

/// Atomic persist: write a per-writer staging file, then rename over `path`.
///
/// The staging name is unique per writer (pid + sequence, R925): a periodic
/// refresh and a kid-miss refresh can overlap, and a shared `jwks.json.tmp`
/// let one truncate the other's file. A failed rename removes the staging
/// file, since a unique name is never reused and would otherwise leak.
pub fn write_atomic(path: &Path, keys: &KeySet, last_refresh: SystemTime) -> Result<(), JwksError> {
    let io = |p: &Path| {
        let p = p.to_path_buf();
        move |source| JwksError::Io { path: p, source }
    };
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(io(parent))?;
    }
    let stored = StoredCache {
        format: CACHE_FORMAT,
        doc: keys.doc.clone(),
        last_refresh_secs: last_refresh.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs()),
    };
    let body = serde_json::to_vec_pretty(&stored)?;
    let tmp = staging_path(path);
    std::fs::write(&tmp, &body).map_err(io(&tmp))?;
    if let Err(source) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(JwksError::Io {
            path: path.to_path_buf(),
            source,
        });
    }
    Ok(())
}

fn staging_path(final_path: &Path) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut name = final_path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp.{}.{seq}", std::process::id()));
    match final_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(name),
        _ => PathBuf::from(name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::AtomicUsize;

    fn doc_with(kid: &str, pubkey: &[u8; 32]) -> JwksDoc {
        JwksDoc {
            keys: vec![JwkKey::ed25519(kid, pubkey, "https://cheers.test", KeyRole::Issuer)],
        }
    }

    #[derive(Debug)]
    struct CountingSource {
        doc: Option<JwksDoc>,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl JwksSource for CountingSource {
        async fn fetch(&self) -> Result<JwksDoc, JwksError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.doc.clone().ok_or_else(|| JwksError::Fetch("unreachable".into()))
        }
    }

    fn source(doc: Option<JwksDoc>) -> Box<CountingSource> {
        counted(doc).0
    }

    fn counted(doc: Option<JwksDoc>) -> (Box<CountingSource>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (Box::new(CountingSource { doc, calls: calls.clone() }), calls)
    }

    #[test]
    fn parses_okp_ed25519_skips_unknown_kty() {
        let known = [7u8; 32];
        let x = URL_SAFE_NO_PAD.encode(known);
        let doc: JwksDoc = serde_json::from_value(json!({"keys": [
            {"kty": "RSA", "n": "...", "e": "AQAB", "kid": "rsa-1", "principal": "i", "role": "issuer"},
            {"kty": "OKP", "crv": "Ed25519", "x": x, "kid": "ed-1", "principal": "svc:a", "role": "self-signer"},
            {"kty": "OKP", "crv": "X25519", "x": "AA", "kid": "x-skip", "principal": "i", "role": "issuer"},
        ]}))
        .unwrap();
        let set = KeySet::from_doc(doc).unwrap();
        assert_eq!(set.len(), 1);
        let e = set.get("ed-1").unwrap();
        assert_eq!((e.public_key, e.principal.as_str(), e.role), (known, "svc:a", KeyRole::SelfSigner));
        assert!(set.get("rsa-1").is_none() && set.get("x-skip").is_none());
    }

    #[test]
    fn rejects_doc_with_no_ed25519_keys() {
        let doc: JwksDoc = serde_json::from_value(json!({"keys": [
            {"kty": "RSA", "kid": "rsa-1", "principal": "i", "role": "issuer"}
        ]}))
        .unwrap();
        assert!(matches!(KeySet::from_doc(doc), Err(JwksError::Parse(_))));
    }

    #[test]
    fn rejects_wrong_length_pubkey() {
        let short = URL_SAFE_NO_PAD.encode([1u8; 16]);
        let doc: JwksDoc = serde_json::from_value(json!({"keys": [
            {"kty": "OKP", "crv": "Ed25519", "x": short, "kid": "ed-bad", "principal": "i", "role": "issuer"}
        ]}))
        .unwrap();
        match KeySet::from_doc(doc).unwrap_err() {
            JwksError::BadKey { kid, .. } => assert_eq!(kid, "ed-bad"),
            other => panic!("expected BadKey, got {other:?}"),
        }
    }

    #[test]
    fn role_is_required_on_the_wire() {
        let x = URL_SAFE_NO_PAD.encode([3u8; 32]);
        let res: Result<JwksDoc, _> = serde_json::from_value(json!({
            "keys": [{"kty": "OKP", "crv": "Ed25519", "x": x, "kid": "k", "principal": "i"}]
        }));
        assert!(res.is_err(), "a role-less JWK must not parse");
    }

    #[test]
    fn atomic_round_trip_through_disk_leaves_no_staging_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nested/jwks.json");
        let set = KeySet::from_doc(doc_with("ed-rt", &[42u8; 32])).unwrap();
        write_atomic(&path, &set, SystemTime::now()).unwrap();
        let staged = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .count();
        assert_eq!(staged, 0);
        let (loaded, _) = load_from_disk(&path).unwrap().unwrap();
        assert_eq!(loaded.get("ed-rt").unwrap().public_key, [42u8; 32]);
    }

    #[test]
    fn old_format_cache_is_discarded_not_parsed() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("jwks.json");
        let x = URL_SAFE_NO_PAD.encode([5u8; 32]);
        let old = json!({
            "doc": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": x, "kid": "old"}]},
            "last_refresh_secs": 1_700_000_000u64,
        });
        std::fs::write(&path, serde_json::to_vec(&old).unwrap()).unwrap();
        assert!(load_from_disk(&path).unwrap().is_none());
        assert!(!path.exists(), "old-format cache file must be removed");
    }

    #[test]
    fn load_from_disk_missing_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(load_from_disk(&tmp.path().join("nope.json")).unwrap().is_none());
    }

    #[test]
    fn boot_no_cache_unreachable_source_is_fatal() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = JwksCacheConfig::new(tmp.path().join("jwks.json"));
        let err = pollster::block_on(JwksCache::boot(source(None), cfg)).unwrap_err();
        assert!(matches!(err, JwksError::BootFetchFatal { .. }));
    }

    #[test]
    fn boot_first_fetch_persists_then_restart_serves_from_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = JwksCacheConfig::new(tmp.path().join("jwks.json"));
        let c = pollster::block_on(JwksCache::boot(source(Some(doc_with("k1", &[1; 32]))), cfg.clone()))
            .unwrap();
        assert!(c.keys().get("k1").is_some());
        // Restart with an unreachable source: the fresh disk cache serves.
        let c2 = pollster::block_on(JwksCache::boot(source(None), cfg)).unwrap();
        assert!(c2.keys().get("k1").is_some());
    }

    #[test]
    fn stale_cache_with_unreachable_source_serves_stale() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = JwksCacheConfig::new(tmp.path().join("jwks.json"));
        let set = KeySet::from_doc(doc_with("old", &[2; 32])).unwrap();
        write_atomic(&cfg.cache_path, &set, UNIX_EPOCH + Duration::from_secs(1)).unwrap();
        let c = pollster::block_on(JwksCache::boot(source(None), cfg.clone())).unwrap();
        assert!(c.keys().get("old").is_some());
        cfg.serve_stale_on_failure = false;
        assert!(pollster::block_on(JwksCache::boot(source(None), cfg)).is_err());
    }

    /// W159: kid-miss refetch is rate-limited so attacker-chosen kids can't
    /// drive the source; the second miss inside the window never fetches.
    #[test]
    fn kid_miss_refresh_is_rate_limited() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = JwksCacheConfig::new(tmp.path().join("jwks.json"));
        let (src, counter) = counted(Some(doc_with("k1", &[1; 32])));
        let c = pollster::block_on(JwksCache::boot(src, cfg)).unwrap();
        let calls = || counter.load(Ordering::SeqCst);
        // Boot's fetch is call 1.
        assert_eq!(calls(), 1);
        assert!(c.kid_miss_last().is_none());
        assert!(pollster::block_on(c.keys_for("unknown")).get("unknown").is_none());
        assert_eq!(calls(), 2);
        let first = c.kid_miss_last().unwrap();
        pollster::block_on(c.keys_for("unknown-2"));
        assert_eq!(calls(), 2, "second miss inside the window must not refetch");
        assert_eq!(c.kid_miss_last(), Some(first));
        // A hit never touches the gate.
        pollster::block_on(c.keys_for("k1"));
        assert_eq!(calls(), 2);
    }
}
