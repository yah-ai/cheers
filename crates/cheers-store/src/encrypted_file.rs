//! [`EncryptedFileStore`] — a [`CredentialStore`] backed by an `age`-encrypted
//! file on disk (R015-T2, `headless` feature).
//!
//! For hosts with **no OS keyring** — the headless rpi of the LAN-pair case
//! (P10), a container, a CI box — where [`KeyringStore`](crate::KeyringStore)
//! has no backing service to talk to. Credentials are kept in a single file
//! encrypted with [`age`](https://docs.rs/age) (X25519 recipient stanza +
//! ChaCha20-Poly1305 payload — authenticated, so tampering fails the decrypt
//! rather than silently corrupting a credential).
//!
//! ## Storage model
//!
//! [`CredentialStore`] is a keyed map, so the file holds the *whole* map — a
//! `serde_json` object of `key → Credential`, age-encrypted. Each mutation is a
//! read-decrypt-modify-encrypt-write cycle serialized behind a mutex, and the
//! re-encrypted bytes are written to a sibling temp file then `rename`d over the
//! target so a crash mid-write can't truncate the store. This is sized for the
//! device tier — a handful of credentials, infrequent writes — not a hot path.
//!
//! ## Key management
//!
//! Encryption uses an `age` X25519 identity. [`EncryptedFileStore::open`] takes
//! a `key_path` separate from the data file and, on first run, **generates** an
//! identity and writes it there (mode `0600` on Unix); subsequent runs load it.
//! Keep the key file off the same backup/sync path as the data file — colocating
//! them defeats the encryption.
//!
//! ### TPM sealing (deferred)
//!
//! The build plan calls for sealing the key to a TPM when `/dev/tpm0` is present
//! (so the key never exists in cleartext on disk). That hardening is **not yet
//! implemented**: real TPM sealing pulls a heavyweight, Linux-only dependency
//! (`tss-esapi` over `tpm2-tss`) that can't be exercised on the macOS/CI dev
//! boxes this crate is tested on. [`EncryptedFileStore::open`] is the file-key
//! seam; a future `open_tpm(data_path)` constructor would acquire the same
//! `age::x25519::Identity` from a TPM-sealed blob and the rest of the store is
//! unchanged. [`tpm_device_present`] reports whether the seam *should* be used
//! on this host so a caller can warn when it falls back to a file key.
//!
//! ## Errors
//!
//! Everything — I/O, age encrypt/decrypt, JSON — collapses to
//! [`StoreError::Backend`] carrying a message, except `delete` of an absent key
//! which is [`StoreError::NotFound`] (matching [`KeyringStore`](crate::KeyringStore)).
//! A decrypt failure (wrong key file, tampered data) is a `Backend` error: the
//! authenticated cipher refuses rather than returning garbage.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Mutex;

use async_trait::async_trait;
use cheers_core::{Credential, CredentialStore, StoreError};

/// The Linux TPM character device the build plan keys TPM sealing off of.
const TPM_DEVICE: &str = "/dev/tpm0";

/// Whether a TPM character device is present on this host.
///
/// The build plan wants the encryption key sealed to a TPM when one exists.
/// That path is deferred (see the [module docs](self#tpm-sealing-deferred)); a
/// caller can use this to log a warning when [`EncryptedFileStore::open`] falls
/// back to a file-stored key on a host that has a TPM available.
pub fn tpm_device_present() -> bool {
    Path::new(TPM_DEVICE).exists()
}

/// A [`CredentialStore`] backed by an `age`-encrypted file.
///
/// Construct with [`EncryptedFileStore::open`], giving a data-file path and a
/// separate key-file path; see the [module docs](self) for the storage model,
/// key management, and the deferred TPM-sealing seam.
///
/// # Example
///
/// ```no_run
/// use cheers_store::EncryptedFileStore;
/// use cheers_core::{Credential, CredentialStore, DeviceBinding, DeviceId, UserId};
///
/// # async fn run() -> Result<(), cheers_core::StoreError> {
/// let store = EncryptedFileStore::open("/var/lib/cheers/creds.age", "/var/lib/cheers/key.age")?;
/// let cred = Credential::new(
///     UserId::new("u-1"),
///     DeviceId::new("d-1"),
///     DeviceBinding::LanPair,
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
pub struct EncryptedFileStore {
    data_path: PathBuf,
    identity: age::x25519::Identity,
    recipient: age::x25519::Recipient,
    /// Serializes the read-modify-write cycle so concurrent mutations on one
    /// process can't clobber each other (last-writer-wins on the whole map).
    lock: Mutex<()>,
}

// Hand-written so the secret `identity` never lands in a Debug dump (and
// because `age::x25519::Identity` doesn't implement `Debug` anyway). The
// recipient is public key material — safe to show.
impl std::fmt::Debug for EncryptedFileStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedFileStore")
            .field("data_path", &self.data_path)
            .field("recipient", &self.recipient.to_string())
            .field("identity", &"<redacted>")
            .finish()
    }
}

impl EncryptedFileStore {
    /// Open (or initialize) a store: credentials live in `data_path`, the age
    /// identity in `key_path`.
    ///
    /// If `key_path` doesn't exist, a fresh identity is generated and written
    /// there (mode `0600` on Unix). If `data_path` doesn't exist yet, the store
    /// starts empty and the file is created on the first [`put`](Self::put).
    pub fn open(
        data_path: impl Into<PathBuf>,
        key_path: impl AsRef<Path>,
    ) -> Result<Self, StoreError> {
        let identity = load_or_create_identity(key_path.as_ref())?;
        let recipient = identity.to_public();
        Ok(Self {
            data_path: data_path.into(),
            identity,
            recipient,
            lock: Mutex::new(()),
        })
    }

    /// The data file this store reads and writes.
    pub fn data_path(&self) -> &Path {
        &self.data_path
    }

    /// Decrypt and decode the credential map. A missing or empty data file is
    /// an empty map (the store hasn't been written yet).
    fn load_map(&self) -> Result<BTreeMap<String, Credential>, StoreError> {
        let encrypted = match std::fs::read(&self.data_path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
            Err(e) => return Err(backend("read credential file", &e)),
        };
        if encrypted.is_empty() {
            return Ok(BTreeMap::new());
        }
        let decryptor = age::Decryptor::new(&encrypted[..])
            .map_err(|e| StoreError::Backend(format!("open age file: {e}")))?;
        let mut reader = decryptor
            .decrypt(std::iter::once(&self.identity as &dyn age::Identity))
            .map_err(|e| StoreError::Backend(format!("decrypt credential file: {e}")))?;
        let mut plaintext = Vec::new();
        reader
            .read_to_end(&mut plaintext)
            .map_err(|e| backend("read decrypted stream", &e))?;
        serde_json::from_slice(&plaintext)
            .map_err(|e| StoreError::Backend(format!("decode credential map: {e}")))
    }

    /// Encode, encrypt, and atomically replace the data file.
    fn store_map(&self, map: &BTreeMap<String, Credential>) -> Result<(), StoreError> {
        let plaintext =
            serde_json::to_vec(map).map_err(|e| StoreError::Backend(format!("encode map: {e}")))?;
        let encryptor =
            age::Encryptor::with_recipients(std::iter::once(&self.recipient as &dyn age::Recipient))
                .map_err(|e| StoreError::Backend(format!("build age encryptor: {e}")))?;
        let mut encrypted = Vec::new();
        let mut writer = encryptor
            .wrap_output(&mut encrypted)
            .map_err(|e| StoreError::Backend(format!("wrap age output: {e}")))?;
        writer
            .write_all(&plaintext)
            .map_err(|e| backend("write age payload", &e))?;
        writer
            .finish()
            .map_err(|e| backend("finish age stream", &e))?;
        write_atomic(&self.data_path, &encrypted)
    }
}

#[async_trait]
impl CredentialStore for EncryptedFileStore {
    async fn put(&self, key: &str, cred: &Credential) -> Result<(), StoreError> {
        let _guard = self.lock.lock().expect("EncryptedFileStore lock poisoned");
        let mut map = self.load_map()?;
        map.insert(key.to_owned(), cred.clone());
        self.store_map(&map)
    }

    async fn get(&self, key: &str) -> Result<Option<Credential>, StoreError> {
        let _guard = self.lock.lock().expect("EncryptedFileStore lock poisoned");
        Ok(self.load_map()?.get(key).cloned())
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        let _guard = self.lock.lock().expect("EncryptedFileStore lock poisoned");
        let mut map = self.load_map()?;
        if map.remove(key).is_none() {
            return Err(StoreError::NotFound);
        }
        self.store_map(&map)
    }
}

/// Load the age identity from `path`, or generate + persist one if absent.
fn load_or_create_identity(path: &Path) -> Result<age::x25519::Identity, StoreError> {
    match std::fs::read_to_string(path) {
        Ok(contents) => age::x25519::Identity::from_str(contents.trim()).map_err(|e| {
            StoreError::Backend(format!("parse age identity at {}: {e}", path.display()))
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let identity = age::x25519::Identity::generate();
            match write_key_file(path, &identity) {
                Ok(()) => Ok(identity),
                // Another process created the key between our read and write —
                // adopt theirs rather than racing.
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let contents = std::fs::read_to_string(path)
                        .map_err(|e| backend("re-read raced key file", &e))?;
                    age::x25519::Identity::from_str(contents.trim()).map_err(|e| {
                        StoreError::Backend(format!("parse raced age identity: {e}"))
                    })
                }
                Err(e) => Err(backend("write age identity", &e)),
            }
        }
        Err(e) => Err(backend("read age identity", &e)),
    }
}

/// Write the secret identity to `path`, refusing to clobber an existing file
/// (`create_new`) and restricting it to the owner on Unix.
fn write_key_file(path: &Path, identity: &age::x25519::Identity) -> std::io::Result<()> {
    use age::secrecy::ExposeSecret;
    create_parent(path)?;
    let secret = identity.to_string();
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(secret.expose_secret().as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()
}

/// Write `bytes` to a sibling temp file then rename it over `path`, so a reader
/// never observes a partially written store and a crash leaves the old file
/// intact.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    create_parent(path).map_err(|e| backend("create data dir", &e))?;
    let tmp = path.with_extension("age.tmp");
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&tmp).map_err(|e| backend("open temp file", &e))?;
        file.write_all(bytes)
            .map_err(|e| backend("write temp file", &e))?;
        file.sync_all().map_err(|e| backend("sync temp file", &e))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| backend("rename into place", &e))
}

/// `create_dir_all` the parent of `path`, tolerating a bare filename (no parent).
fn create_parent(path: &Path) -> std::io::Result<()> {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => std::fs::create_dir_all(parent),
        _ => Ok(()),
    }
}

/// Build a [`StoreError::Backend`] from a context string and an I/O error.
fn backend(context: &str, err: &std::io::Error) -> StoreError {
    StoreError::Backend(format!("{context}: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cheers_core::{DeviceBinding, DeviceId, UserId};
    use tempfile::TempDir;

    /// A store rooted in a fresh temp dir, plus the dir guard (kept alive so the
    /// files survive for the test's duration).
    fn store() -> (EncryptedFileStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let store =
            EncryptedFileStore::open(dir.path().join("creds.age"), dir.path().join("key.age"))
                .unwrap();
        (store, dir)
    }

    fn cred(material: &[u8]) -> Credential {
        Credential::new(
            UserId::new("u-1"),
            DeviceId::new("d-1"),
            DeviceBinding::LanPair,
            material.to_vec(),
        )
    }

    #[test]
    fn put_get_delete_round_trip() {
        let (store, _dir) = store();
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
        let (store, _dir) = store();
        pollster::block_on(async {
            assert!(store.get("never-put").await.unwrap().is_none());
        });
    }

    #[test]
    fn delete_missing_is_not_found() {
        let (store, _dir) = store();
        pollster::block_on(async {
            assert!(matches!(
                store.delete("absent").await,
                Err(StoreError::NotFound)
            ));
        });
    }

    #[test]
    fn put_overwrites_existing() {
        let (store, _dir) = store();
        pollster::block_on(async {
            store.put("k", &cred(b"v1")).await.unwrap();
            store.put("k", &cred(b"v2")).await.unwrap();
            assert_eq!(store.get("k").await.unwrap().unwrap().material, b"v2");
        });
    }

    #[test]
    fn distinct_keys_do_not_collide() {
        let (store, _dir) = store();
        pollster::block_on(async {
            store.put("k1", &cred(b"one")).await.unwrap();
            store.put("k2", &cred(b"two")).await.unwrap();
            assert_eq!(store.get("k1").await.unwrap().unwrap().material, b"one");
            assert_eq!(store.get("k2").await.unwrap().unwrap().material, b"two");
        });
    }

    /// Credentials survive dropping and reopening the store against the same
    /// data + key files — the persistence the keyring/memory stores can't offer
    /// a headless host.
    #[test]
    fn persists_across_reopen() {
        let dir = TempDir::new().unwrap();
        let data = dir.path().join("creds.age");
        let key = dir.path().join("key.age");
        let c = cred(b"durable");
        pollster::block_on(async {
            let s1 = EncryptedFileStore::open(&data, &key).unwrap();
            s1.put("k", &c).await.unwrap();
            drop(s1);
            let s2 = EncryptedFileStore::open(&data, &key).unwrap();
            assert_eq!(s2.get("k").await.unwrap(), Some(c.clone()));
        });
    }

    /// The data file is actually encrypted: the cleartext material must not
    /// appear in the bytes on disk.
    #[test]
    fn data_file_is_encrypted_at_rest() {
        let (store, _dir) = store();
        let secret = b"SUPER-SECRET-MATERIAL";
        pollster::block_on(async {
            store.put("k", &cred(secret)).await.unwrap();
        });
        let raw = std::fs::read(store.data_path()).unwrap();
        assert!(!raw.is_empty());
        assert!(
            !raw.windows(secret.len()).any(|w| w == secret),
            "plaintext material leaked into the on-disk file"
        );
        // age files start with the "age-encryption.org/v1" header line.
        assert!(raw.starts_with(b"age-encryption.org/v1"));
    }

    /// A store opened with the wrong key file cannot decrypt — the authenticated
    /// cipher surfaces a `Backend` error, never a wrong/garbage credential.
    #[test]
    fn wrong_key_fails_to_decrypt() {
        let dir = TempDir::new().unwrap();
        let data = dir.path().join("creds.age");
        pollster::block_on(async {
            let good = EncryptedFileStore::open(&data, dir.path().join("key-a.age")).unwrap();
            good.put("k", &cred(b"secret")).await.unwrap();

            let bad = EncryptedFileStore::open(&data, dir.path().join("key-b.age")).unwrap();
            assert!(matches!(bad.get("k").await, Err(StoreError::Backend(_))));
        });
    }

    /// On Unix the generated key file is owner-only (0600).
    #[cfg(unix)]
    #[test]
    fn key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let key = dir.path().join("key.age");
        let _ = EncryptedFileStore::open(dir.path().join("creds.age"), &key).unwrap();
        let mode = std::fs::metadata(&key).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "key file should be 0600, got {mode:o}");
    }

    #[test]
    fn is_send_sync_and_dyn_compatible() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<EncryptedFileStore>();
        fn _dyn(_: &dyn CredentialStore) {}
    }

    #[test]
    fn tpm_device_present_is_false_on_dev_hosts() {
        // The dev/CI boxes this crate is tested on have no /dev/tpm0; this pins
        // the file-key fallback path that the tests exercise.
        assert!(!tpm_device_present());
    }
}
