//! [`KeyringStore`] — a [`CredentialStore`] backed by the operating system's
//! secret store (R015-T1, `keyring` feature).
//!
//! Wraps the [`keyring`](https://docs.rs/keyring) crate's `Entry` API, which
//! fronts a different native store per platform — selected at build time by the
//! per-target `keyring` dependency in `Cargo.toml`, so a build only links the
//! store it can use:
//!
//! | Platform     | Backing store                              |
//! |--------------|--------------------------------------------|
//! | macOS / iOS  | Apple Keychain (Security framework)        |
//! | Windows      | Windows Credential Manager                 |
//! | Linux / *BSD | Secret Service (D-Bus; GNOME Keyring, KWallet, …) |
//!
//! ## Key layout
//!
//! [`CredentialStore`] is keyed by a single caller-chosen string; a keyring
//! `Entry` is addressed by a `(service, user)` pair. `KeyringStore` fixes the
//! `service` at construction — a stable per-application namespace, e.g.
//! `"dev.yah.cheers"` — and maps each store key onto the `user` field. Two apps
//! that pick distinct service names never see each other's credentials.
//!
//! ## Blob encoding
//!
//! A [`Credential`] is stored as its `serde_json` encoding via `set_secret` /
//! `get_secret`. The secret API takes arbitrary bytes, so the binary
//! `material` blob survives without a UTF-8 round-trip constraint.
//!
//! ## One cached `Entry` per key
//!
//! The store caches the `Entry` it builds for each key. This is partly a
//! nicety (skip re-resolving the credential handle on every call) and partly a
//! correctness requirement for the in-process mock backend used in tests: the
//! mock has *entry-only* persistence, so a fresh `Entry` is always empty and a
//! store that rebuilt the `Entry` per call could never round-trip a value
//! through it. Real OS backends persist in the store itself, so reusing the
//! handle is equivalent to rebuilding it.
//!
//! ## Runtime availability (the headless-Linux gotcha)
//!
//! The `keyring` crate fails *at runtime, not compile time*, when the backing
//! service is missing — a headless Linux box with no Secret Service provider
//! running, or a locked Keychain. Those surface as [`StoreError::Backend`]
//! carrying the keyring crate's message (e.g. "No storage access: …"). A
//! caller that must degrade gracefully — fall back to the encrypted-file store
//! (R015-T2) — should treat any `Backend` error from a keyring op as "this
//! backend is unavailable here." Tests against the real backend skip on it.
//!
//! ## License / dependency note
//!
//! Cleanup: the `keyring` v3 line is pinned for its classic unified `Entry`
//! API. v4 split the library into `keyring-core` + per-platform `*-keyring-store`
//! crates and turned the umbrella `keyring` crate into a CLI/sample (it pulls
//! `clap`/`rpassword`), which is the wrong shape for a library dependency.
//! When the `keyring-core` ecosystem settles, migrate onto it; everything is
//! insulated behind cheers-core's [`CredentialStore`], so it is a one-file swap.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cheers_core::{Credential, CredentialStore, StoreError};

// The leading `::` disambiguates the external `keyring` crate from this module,
// which shares its name.
use ::keyring::{Entry, Error as KeyringError};

/// A [`CredentialStore`] backed by the operating system's secret store.
///
/// Construct one per application namespace with [`KeyringStore::new`]; see the
/// [module docs](self) for the platform backends, key layout, and the
/// runtime-availability contract.
///
/// # Example
///
/// ```no_run
/// use cheers_store::KeyringStore;
/// use cheers_core::{Credential, CredentialStore, DeviceBinding, DeviceId, UserId};
///
/// # async fn run() -> Result<(), cheers_core::StoreError> {
/// let store = KeyringStore::new("dev.yah.cheers");
/// let cred = Credential::new(
///     UserId::new("u-1"),
///     DeviceId::new("d-1"),
///     DeviceBinding::Passkey,
///     b"opaque-material".to_vec(),
/// );
/// store.put("session", &cred).await?;
/// assert_eq!(store.get("session").await?.as_ref(), Some(&cred));
/// store.delete("session").await?;
/// assert!(store.get("session").await?.is_none());
/// # Ok(())
/// # }
/// # let _ = run();
/// ```
#[derive(Debug)]
pub struct KeyringStore {
    service: String,
    entries: Mutex<HashMap<String, Arc<Entry>>>,
}

impl KeyringStore {
    /// Create a store namespaced under `service` (a stable per-application
    /// identifier, e.g. `"dev.yah.cheers"`).
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// The service namespace this store writes under.
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Get-or-create the cached `Entry` for `key`. The keyring call itself runs
    /// outside the lock — only the cache read/insert is guarded.
    fn entry(&self, key: &str) -> Result<Arc<Entry>, StoreError> {
        let mut entries = self.entries.lock().expect("KeyringStore entry cache poisoned");
        if let Some(entry) = entries.get(key) {
            return Ok(Arc::clone(entry));
        }
        let entry = Arc::new(Entry::new(&self.service, key).map_err(map_keyring_err)?);
        entries.insert(key.to_owned(), Arc::clone(&entry));
        Ok(entry)
    }
}

#[async_trait]
impl CredentialStore for KeyringStore {
    async fn put(&self, key: &str, cred: &Credential) -> Result<(), StoreError> {
        let blob = serde_json::to_vec(cred).map_err(|e| StoreError::Backend(e.to_string()))?;
        let entry = self.entry(key)?;
        entry.set_secret(&blob).map_err(map_keyring_err)
    }

    async fn get(&self, key: &str) -> Result<Option<Credential>, StoreError> {
        let entry = self.entry(key)?;
        match entry.get_secret() {
            Ok(blob) => {
                let cred =
                    serde_json::from_slice(&blob).map_err(|e| StoreError::Backend(e.to_string()))?;
                Ok(Some(cred))
            }
            Err(KeyringError::NoEntry) => Ok(None),
            Err(e) => Err(map_keyring_err(e)),
        }
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        let entry = self.entry(key)?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(KeyringError::NoEntry) => Err(StoreError::NotFound),
            Err(e) => Err(map_keyring_err(e)),
        }
    }
}

/// Map a `keyring` crate error onto the store contract's [`StoreError`].
///
/// `NoEntry` is handled at each call site (it means "absent", not "failed"), so
/// it never reaches here. Everything else — including the backend-unavailable
/// cases `NoStorageAccess` / `PlatformFailure` (a locked Keychain, no Secret
/// Service on a headless box) — collapses to [`StoreError::Backend`] carrying
/// the keyring message. `cheers-core`'s `StoreError` has no typed "unavailable"
/// variant, so a caller that must fall back to another store treats any
/// `Backend` from a keyring op as "this backend isn't usable here."
fn map_keyring_err(err: KeyringError) -> StoreError {
    StoreError::Backend(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cheers_core::{DeviceBinding, DeviceId, UserId};

    /// Route every `Entry` through keyring's in-process mock so tests never
    /// touch a real OS keychain. `set_default_credential_builder` is a plain
    /// `RwLock` set — safe to call from every test, and it never panics. The
    /// mock's entry-only persistence is exactly why [`KeyringStore`] caches an
    /// `Entry` per key (see the module docs).
    fn use_mock() {
        ::keyring::set_default_credential_builder(::keyring::mock::default_credential_builder());
    }

    fn cred(material: &[u8]) -> Credential {
        Credential::new(
            UserId::new("u-1"),
            DeviceId::new("d-1"),
            DeviceBinding::Passkey,
            material.to_vec(),
        )
    }

    #[test]
    fn put_get_delete_round_trip() {
        use_mock();
        let store = KeyringStore::new("test.round-trip");
        pollster::block_on(async {
            let c = cred(b"material-A");
            assert!(store.get("k").await.unwrap().is_none());
            store.put("k", &c).await.unwrap();
            assert_eq!(store.get("k").await.unwrap(), Some(c.clone()));
            store.delete("k").await.unwrap();
            assert!(store.get("k").await.unwrap().is_none());
        });
    }

    #[test]
    fn get_missing_is_none() {
        use_mock();
        let store = KeyringStore::new("test.missing");
        pollster::block_on(async {
            assert!(store.get("never-put").await.unwrap().is_none());
        });
    }

    #[test]
    fn delete_missing_is_not_found() {
        use_mock();
        let store = KeyringStore::new("test.delete-missing");
        pollster::block_on(async {
            assert!(matches!(
                store.delete("absent").await,
                Err(StoreError::NotFound)
            ));
        });
    }

    #[test]
    fn put_overwrites_existing() {
        use_mock();
        let store = KeyringStore::new("test.overwrite");
        pollster::block_on(async {
            store.put("k", &cred(b"v1")).await.unwrap();
            store.put("k", &cred(b"v2")).await.unwrap();
            assert_eq!(store.get("k").await.unwrap().unwrap().material, b"v2");
        });
    }

    #[test]
    fn distinct_keys_do_not_collide() {
        use_mock();
        let store = KeyringStore::new("test.distinct");
        pollster::block_on(async {
            store.put("k1", &cred(b"one")).await.unwrap();
            store.put("k2", &cred(b"two")).await.unwrap();
            assert_eq!(store.get("k1").await.unwrap().unwrap().material, b"one");
            assert_eq!(store.get("k2").await.unwrap().unwrap().material, b"two");
        });
    }

    #[test]
    fn service_accessor() {
        let store = KeyringStore::new("dev.yah.cheers");
        assert_eq!(store.service(), "dev.yah.cheers");
    }

    #[test]
    fn backend_errors_map_to_backend_variant() {
        // Backend-unavailable (NoStorageAccess / PlatformFailure) and other
        // non-NoEntry failures all collapse to StoreError::Backend.
        assert!(matches!(
            map_keyring_err(KeyringError::NoStorageAccess(Box::new(std::io::Error::other(
                "boom"
            )))),
            StoreError::Backend(_)
        ));
        assert!(matches!(
            map_keyring_err(KeyringError::PlatformFailure(Box::new(std::io::Error::other(
                "boom"
            )))),
            StoreError::Backend(_)
        ));
        assert!(matches!(
            map_keyring_err(KeyringError::Invalid("svc".into(), "bad".into())),
            StoreError::Backend(_)
        ));
    }

    #[test]
    fn is_send_sync_and_dyn_compatible() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<KeyringStore>();
        fn _dyn(_: &dyn CredentialStore) {}
        _dyn(&KeyringStore::new("x"));
    }

    /// Smoke test against the *real* OS secret store. Ignored by default
    /// because it touches the live keychain (and can prompt or block on some
    /// hosts) — run explicitly with
    /// `cargo test -p cheers-store --features keyring -- --ignored`.
    ///
    /// Skips cleanly when the backend is unavailable (the headless-Linux
    /// gotcha: keyring fails at runtime, not compile time). NOTE: it relies on
    /// the global credential builder *not* being the mock, so run it in
    /// isolation — the unit tests above set the mock builder process-wide.
    #[test]
    #[ignore = "touches the real OS keychain; run explicitly with --ignored"]
    fn real_backend_round_trip() {
        let store = KeyringStore::new("dev.yah.cheers.test");
        let key = "r015-t1-smoke";
        let c = cred(b"real-material");
        let outcome = pollster::block_on(async {
            store.put(key, &c).await?;
            let got = store.get(key).await?;
            // Best-effort cleanup regardless of the assertion below.
            let _ = store.delete(key).await;
            Ok::<_, StoreError>(got)
        });
        match outcome {
            Ok(got) => assert_eq!(got, Some(c)),
            Err(StoreError::Backend(msg)) => {
                eprintln!("skipping real_backend_round_trip: keyring backend unavailable: {msg}");
            }
            Err(e) => panic!("unexpected store error: {e}"),
        }
    }
}
