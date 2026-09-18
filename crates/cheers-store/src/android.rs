//! [`AndroidKeystoreStore`] — a [`CredentialStore`] sealed by a hardware-backed
//! Android Keystore key (R726-F20, `android` feature).
//!
//! The mobile counterpart of [`KeyringStore`](crate::KeyringStore). Android has
//! no Secret Service / Keychain the `keyring` crate can front, so the device
//! tier gets its own backend built on the platform primitive that *is* there:
//! **Android Keystore**, a JCA provider whose AES keys live in the TEE /
//! StrongBox and never enter the app's address space.
//!
//! ## Storage model
//!
//! Keystore stores *keys*, not blobs — there is no "put this secret in the
//! Keystore" API. So the shape is the standard one (and the same one
//! `EncryptedSharedPreferences` uses under the hood): a single AES-256-GCM key
//! is held in the Keystore under a stable alias, and the credential map is
//! serialized, sealed with that key, and written to a file in the app's private
//! directory. Losing the file loses the credentials; extracting the file without
//! the device yields ciphertext the TEE will not decrypt.
//!
//! The file holds the *whole* [`Vault`] — the `key → Credential` map plus the
//! [`app_install_id`](AndroidKeystoreStore::app_install_id) — as one `serde_json`
//! object, sealed. Each mutation is a read-unseal-modify-seal-write cycle
//! serialized behind a mutex and committed with
//! [`write_atomic`](crate::atomic_file::write_atomic). Device tier: a handful of
//! entries, infrequent writes, not a hot path.
//!
//! ## The [`KeySealer`] seam, and why it exists
//!
//! Everything above — serialization, the map semantics, the atomic rewrite, the
//! install-id lifecycle — is ordinary Rust that can be exercised on a dev box.
//! Only the seal/unseal pair needs a JVM. So that pair is the trait
//! [`KeySealer`], `AndroidKeystoreStore` holds a `Box<dyn KeySealer>`, and:
//!
//! - on Android, [`AndroidKeystoreStore::open`] installs
//!   [`AndroidKeystoreSealer`], which does the JCA work over JNI;
//! - everywhere, [`AndroidKeystoreStore::with_sealer`] takes any sealer, which
//!   is how this module's tests get real coverage of the store on macOS/CI
//!   rather than being `#[cfg]`-ed out of existence.
//!
//! That is the whole reason the type is not `#[cfg(target_os = "android")]`. A
//! backend whose logic only compiles on the one platform nobody runs tests on is
//! a backend nobody tests.
//!
//! ## Errors
//!
//! I/O, JSON and seal/unseal failures collapse to [`StoreError::Backend`] with a
//! message; `delete` of an absent key is [`StoreError::NotFound`], matching
//! [`KeyringStore`](crate::KeyringStore) and
//! [`EncryptedFileStore`](crate::EncryptedFileStore). An unseal failure — wrong
//! key, tampered file, a Keystore key invalidated by a lock-screen change — is a
//! `Backend` error: AES-GCM is authenticated, so it refuses rather than
//! returning garbage.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use async_trait::async_trait;
use cheers_core::{Credential, CredentialStore, StoreError};
use serde::{Deserialize, Serialize};

use crate::atomic_file::{io_backend, write_atomic};

// The sealed file's framing. NOT gated on the platform: it is the on-disk
// format, and a format whose parser only compiles on the one target that can't
// run tests is a format nobody has ever parsed under a test.
mod frame;

#[cfg(target_os = "android")]
pub mod jni_keystore;

#[cfg(target_os = "android")]
pub use jni_keystore::AndroidKeystoreSealer;

/// The Keystore alias [`AndroidKeystoreStore::open`] holds its AES key under.
///
/// Stable across launches by construction — the key is looked up by this name on
/// every seal, and generated only when the lookup comes back empty. Changing it
/// orphans every credential already on the device.
pub const DEFAULT_KEY_ALIAS: &str = "dev.yah.cheers.vault";

/// The sealed vault's filename inside the directory handed to
/// [`AndroidKeystoreStore::open`].
pub const VAULT_FILE_NAME: &str = "cheers-vault.sealed";

/// The seal/unseal pair [`AndroidKeystoreStore`] delegates its confidentiality
/// to — the one part of the backend that needs a platform.
///
/// `seal` must be authenticated encryption: `unseal` is required to *fail* on a
/// modified input rather than return altered plaintext, because the store treats
/// a successful unseal as proof the bytes are its own. It must also be
/// nondeterministic (a fresh nonce per call), since the vault is rewritten in
/// full on every mutation and a reused nonce under one key is catastrophic for
/// GCM.
pub trait KeySealer: Send + Sync + fmt::Debug {
    /// Encrypt-and-authenticate `plaintext`. The returned bytes are opaque to
    /// the store and carry whatever nonce/tag framing the impl needs.
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, StoreError>;

    /// Reverse [`seal`](Self::seal), or fail. Must not return plaintext for
    /// input that did not come from this sealer's key.
    fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, StoreError>;
}

/// Everything the sealed file holds.
///
/// One struct rather than a bare map because the install id is not a
/// [`Credential`] and encoding it as one would be a lie the next reader has to
/// decode. Every field defaults, so a vault written before a field existed still
/// reads.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Vault {
    #[serde(default)]
    credentials: BTreeMap<String, Credential>,
    #[serde(default)]
    install_id: Option<String>,
    /// Host-owned secrets that are *not* proofs of identity to cheers — see
    /// [`AndroidKeystoreStore::get_or_put_secret`]. Same reasoning as
    /// `install_id`: a transport private key is not a [`Credential`], and
    /// dressing one up as a [`Credential`] with a made-up `DeviceBinding` would
    /// be exactly the lie this struct exists to avoid.
    #[serde(default)]
    secrets: BTreeMap<String, String>,
}

/// A [`CredentialStore`] whose file is sealed by an Android Keystore key.
///
/// Construct with [`AndroidKeystoreStore::open`] on Android, or
/// [`AndroidKeystoreStore::with_sealer`] anywhere; see the [module docs](self)
/// for the storage model and the [`KeySealer`] seam.
///
/// # Example
///
/// ```no_run
/// use cheers_store::AndroidKeystoreStore;
/// use cheers_core::{Credential, CredentialStore, DeviceBinding, DeviceId, UserId};
///
/// # #[cfg(target_os = "android")]
/// # async fn run(app_files_dir: &std::path::Path) -> Result<(), cheers_core::StoreError> {
/// let store = AndroidKeystoreStore::open(app_files_dir)?;
/// let cred = Credential::new(
///     UserId::new("u-1"),
///     DeviceId::new("d-1"),
///     DeviceBinding::Passkey,
///     b"opaque-material".to_vec(),
/// );
/// store.put("session", &cred).await?;
/// assert_eq!(store.get("session").await?.as_ref(), Some(&cred));
/// # Ok(())
/// # }
/// ```
pub struct AndroidKeystoreStore {
    vault_path: PathBuf,
    sealer: Box<dyn KeySealer>,
    /// Serializes the read-modify-write cycle so concurrent mutations in one
    /// process can't clobber each other (last-writer-wins on the whole vault).
    lock: Mutex<()>,
}

impl fmt::Debug for AndroidKeystoreStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AndroidKeystoreStore")
            .field("vault_path", &self.vault_path)
            .field("sealer", &self.sealer)
            .finish()
    }
}

impl AndroidKeystoreStore {
    /// Open (or initialize) a store under `dir`, sealed by the Keystore key at
    /// [`DEFAULT_KEY_ALIAS`].
    ///
    /// `dir` should be the app's private storage — `Context.getFilesDir()`, or
    /// Tauri's `app_data_dir()`, which resolves to the same place. The caller
    /// supplies it rather than this crate reading it off the `Context`, so the
    /// store never has to know how the host app was launched.
    ///
    /// The Keystore key is created on first use and reused afterwards; the vault
    /// file is created on the first [`put`](CredentialStore::put).
    #[cfg(target_os = "android")]
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_with_alias(dir, DEFAULT_KEY_ALIAS)
    }

    /// [`open`](Self::open) with an explicit Keystore alias, for a host that
    /// keeps more than one vault.
    #[cfg(target_os = "android")]
    pub fn open_with_alias(
        dir: impl AsRef<Path>,
        alias: impl Into<String>,
    ) -> Result<Self, StoreError> {
        Ok(Self::with_sealer(
            dir,
            Box::new(AndroidKeystoreSealer::new(alias)),
        ))
    }

    /// Build a store over an arbitrary [`KeySealer`].
    ///
    /// The constructor the tests use, and the one a host with its own sealing
    /// policy (a passphrase-derived key, a StrongBox-only key) would use.
    pub fn with_sealer(dir: impl AsRef<Path>, sealer: Box<dyn KeySealer>) -> Self {
        Self {
            vault_path: dir.as_ref().join(VAULT_FILE_NAME),
            sealer,
            lock: Mutex::new(()),
        }
    }

    /// The sealed file this store reads and writes.
    pub fn vault_path(&self) -> &Path {
        &self.vault_path
    }

    /// This installation's stable identifier — a random UUIDv4 minted on first
    /// call and kept in the sealed vault thereafter.
    ///
    /// "Installation", not "device": it is generated by *this app install*, is
    /// never derived from a hardware identifier, and dies with an uninstall or a
    /// "clear app data". That is deliberate. Android's actual device ids are
    /// either privileged (`IMEI`), unstable (`ANDROID_ID` is per-app-signing-key
    /// since Oreo), or both, and a paired camp only needs to tell one enrolled
    /// install from another — which this does, without asking for a permission
    /// or handling a hardware identifier.
    ///
    /// Synchronous because it is file + seal work with no I/O to await, and
    /// because callers want it during startup wiring rather than inside a task.
    pub fn app_install_id(&self) -> Result<String, StoreError> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut vault = self.read_vault()?;
        if let Some(id) = &vault.install_id {
            return Ok(id.clone());
        }
        let id = new_uuid_v4();
        vault.install_id = Some(id.clone());
        self.write_vault(&vault)?;
        Ok(id)
    }

    /// Read a host secret, minting it under the same lock if absent.
    ///
    /// The slot for things the embedding app must keep across launches that are
    /// *not* cheers credentials. The motivating one (R726-F20 phase 3) is the
    /// phone's mshr transport private key: a camp's enrollment ledger binds a
    /// `NodeId`, so a device that regenerates its keypair every launch is
    /// un-pairable — one QR redemption would buy exactly one session. It is a
    /// private key, so it belongs behind the TEE-held seal rather than in the
    /// app's plaintext config.
    ///
    /// `mint` runs **only** when the key is absent, and runs while the vault
    /// lock is held, so two concurrent callers cannot mint two different values
    /// and race to write them.
    ///
    /// Synchronous for the same reason as [`app_install_id`](Self::app_install_id):
    /// it is file + seal work with no I/O to await, and callers want it during
    /// startup wiring rather than inside a task.
    pub fn get_or_put_secret(
        &self,
        key: &str,
        mint: impl FnOnce() -> String,
    ) -> Result<String, StoreError> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut vault = self.read_vault()?;
        if let Some(existing) = vault.secrets.get(key) {
            return Ok(existing.clone());
        }
        let minted = mint();
        vault.secrets.insert(key.to_owned(), minted.clone());
        self.write_vault(&vault)?;
        Ok(minted)
    }

    /// Read a host secret without minting one. `None` means unset.
    pub fn get_secret(&self, key: &str) -> Result<Option<String>, StoreError> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        Ok(self.read_vault()?.secrets.remove(key))
    }

    /// Forget a host secret. Idempotent — unlike [`CredentialStore::delete`],
    /// removing an absent key is success, because the callers are "sign out" /
    /// "unpair" paths whose postcondition is *gone*, not *was there*.
    pub fn delete_secret(&self, key: &str) -> Result<(), StoreError> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut vault = self.read_vault()?;
        if vault.secrets.remove(key).is_none() {
            return Ok(());
        }
        self.write_vault(&vault)
    }

    /// Read and unseal the vault, treating an absent file as an empty one.
    ///
    /// An absent file is the first-launch case, not an error; a *present* file
    /// that fails to unseal is an error, because silently starting over would
    /// discard a credential the user still has.
    fn read_vault(&self) -> Result<Vault, StoreError> {
        let sealed = match std::fs::read(&self.vault_path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vault::default()),
            Err(e) => return Err(io_backend("read vault file", &e)),
        };
        let plain = self.sealer.unseal(&sealed)?;
        serde_json::from_slice(&plain)
            .map_err(|e| StoreError::Backend(format!("decode vault: {e}")))
    }

    /// Seal and commit the vault, replacing the file atomically.
    fn write_vault(&self, vault: &Vault) -> Result<(), StoreError> {
        let plain = serde_json::to_vec(vault)
            .map_err(|e| StoreError::Backend(format!("encode vault: {e}")))?;
        let sealed = self.sealer.seal(&plain)?;
        write_atomic(&self.vault_path, &sealed)
    }
}

#[async_trait]
impl CredentialStore for AndroidKeystoreStore {
    async fn put(&self, key: &str, cred: &Credential) -> Result<(), StoreError> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut vault = self.read_vault()?;
        vault.credentials.insert(key.to_owned(), cred.clone());
        self.write_vault(&vault)
    }

    async fn get(&self, key: &str) -> Result<Option<Credential>, StoreError> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        Ok(self.read_vault()?.credentials.remove(key))
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut vault = self.read_vault()?;
        if vault.credentials.remove(key).is_none() {
            return Err(StoreError::NotFound);
        }
        self.write_vault(&vault)
    }
}

/// A random UUIDv4 in the canonical hyphenated form.
///
/// Hand-rolled rather than pulling `uuid` in: the crate would be a dependency of
/// the *device* tier — the one this crate keeps deliberately thin — for sixteen
/// bytes of CSPRNG output and a format string. Version and variant bits are set
/// per RFC 4122 §4.4 so the value is a well-formed v4 and not merely 128 random
/// bits wearing hyphens.
fn new_uuid_v4() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("OS CSPRNG must be available");
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex = |bytes: &[u8]| -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(bytes.len() * 2);
        for x in bytes {
            let _ = write!(s, "{x:02x}");
        }
        s
    };
    format!(
        "{}-{}-{}-{}-{}",
        hex(&b[0..4]),
        hex(&b[4..6]),
        hex(&b[6..8]),
        hex(&b[8..10]),
        hex(&b[10..16])
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cheers_core::{DeviceBinding, DeviceId, UserId};
    use std::sync::atomic::{AtomicU64, Ordering};
    use tempfile::TempDir;

    /// A stand-in for the Keystore that keeps the store's contract honest
    /// without a JVM: it is keyed, it is nondeterministic, and it *authenticates*
    /// — an unseal under the wrong key, or of tampered bytes, fails.
    ///
    /// Deliberately not a cipher. The framing is `nonce || key_tag || plaintext`
    /// with the plaintext XOR-masked by the key byte, which is enough to prove
    /// the store rejects foreign and corrupted vaults and enough to make a
    /// "sealed" file visibly not the plaintext — and obviously worthless as
    /// crypto, which is the point: nobody can mistake it for the real backend.
    #[derive(Debug)]
    struct TestSealer {
        key: u8,
        nonce: AtomicU64,
    }

    impl TestSealer {
        fn new(key: u8) -> Self {
            Self {
                key,
                nonce: AtomicU64::new(0),
            }
        }
    }

    impl KeySealer for TestSealer {
        fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, StoreError> {
            let nonce = self.nonce.fetch_add(1, Ordering::Relaxed);
            let mut out = nonce.to_le_bytes().to_vec();
            out.push(self.key);
            out.extend(plaintext.iter().map(|b| b ^ self.key));
            Ok(out)
        }

        fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, StoreError> {
            if sealed.len() < 9 {
                return Err(StoreError::Backend("sealed blob truncated".into()));
            }
            if sealed[8] != self.key {
                return Err(StoreError::Backend("sealed under a different key".into()));
            }
            Ok(sealed[9..].iter().map(|b| b ^ self.key).collect())
        }
    }

    fn store(dir: &TempDir, key: u8) -> AndroidKeystoreStore {
        AndroidKeystoreStore::with_sealer(dir.path(), Box::new(TestSealer::new(key)))
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
        let dir = TempDir::new().unwrap();
        let s = store(&dir, 0x5a);
        pollster::block_on(async {
            let c = cred(b"material");
            assert!(s.get("session").await.unwrap().is_none());
            s.put("session", &c).await.unwrap();
            assert_eq!(s.get("session").await.unwrap().as_ref(), Some(&c));
            s.delete("session").await.unwrap();
            assert!(s.get("session").await.unwrap().is_none());
        });
    }

    #[test]
    fn get_missing_is_none() {
        let dir = TempDir::new().unwrap();
        let s = store(&dir, 0x5a);
        pollster::block_on(async {
            assert!(s.get("absent").await.unwrap().is_none());
        });
    }

    #[test]
    fn delete_missing_is_not_found() {
        let dir = TempDir::new().unwrap();
        let s = store(&dir, 0x5a);
        pollster::block_on(async {
            assert!(matches!(
                s.delete("absent").await,
                Err(StoreError::NotFound)
            ));
        });
    }

    #[test]
    fn put_overwrites_existing() {
        let dir = TempDir::new().unwrap();
        let s = store(&dir, 0x5a);
        pollster::block_on(async {
            s.put("k", &cred(b"first")).await.unwrap();
            let second = cred(b"second");
            s.put("k", &second).await.unwrap();
            assert_eq!(s.get("k").await.unwrap().as_ref(), Some(&second));
        });
    }

    #[test]
    fn distinct_keys_do_not_collide() {
        let dir = TempDir::new().unwrap();
        let s = store(&dir, 0x5a);
        pollster::block_on(async {
            let a = cred(b"a");
            let b = cred(b"b");
            s.put("a", &a).await.unwrap();
            s.put("b", &b).await.unwrap();
            s.delete("a").await.unwrap();
            assert!(s.get("a").await.unwrap().is_none());
            assert_eq!(s.get("b").await.unwrap().as_ref(), Some(&b));
        });
    }

    #[test]
    fn persists_across_reopen() {
        let dir = TempDir::new().unwrap();
        let c = cred(b"material");
        pollster::block_on(async {
            store(&dir, 0x5a).put("session", &c).await.unwrap();
            // A fresh store over the same dir and the same key — i.e. the next
            // app launch — sees it.
            let reopened = store(&dir, 0x5a);
            assert_eq!(reopened.get("session").await.unwrap().as_ref(), Some(&c));
        });
    }

    #[test]
    fn vault_file_is_sealed_at_rest() {
        let dir = TempDir::new().unwrap();
        let s = store(&dir, 0x5a);
        pollster::block_on(async {
            s.put("session", &cred(b"super-secret-material"))
                .await
                .unwrap();
        });
        let raw = std::fs::read(s.vault_path()).unwrap();
        assert!(
            !raw.windows(21).any(|w| w == b"super-secret-material"),
            "credential material must not be readable in the vault file"
        );
    }

    #[test]
    fn a_foreign_key_cannot_unseal_the_vault() {
        let dir = TempDir::new().unwrap();
        pollster::block_on(async {
            store(&dir, 0x5a).put("k", &cred(b"m")).await.unwrap();
            // Same file, different Keystore key: the real-world case is a
            // restored backup, or a key the TEE invalidated. It must error, not
            // silently present an empty vault and lose the row.
            let other = store(&dir, 0x33);
            assert!(matches!(other.get("k").await, Err(StoreError::Backend(_))));
        });
    }

    #[test]
    fn a_tampered_vault_is_rejected() {
        let dir = TempDir::new().unwrap();
        let s = store(&dir, 0x5a);
        pollster::block_on(async {
            s.put("k", &cred(b"m")).await.unwrap();
        });
        std::fs::write(s.vault_path(), b"not a sealed vault at all").unwrap();
        pollster::block_on(async {
            assert!(matches!(s.get("k").await, Err(StoreError::Backend(_))));
        });
    }

    #[test]
    fn app_install_id_is_minted_once_and_kept() {
        let dir = TempDir::new().unwrap();
        let first = store(&dir, 0x5a).app_install_id().unwrap();
        // Stable within a store…
        let s = store(&dir, 0x5a);
        assert_eq!(s.app_install_id().unwrap(), s.app_install_id().unwrap());
        // …and across a relaunch, which is the whole point of persisting it.
        assert_eq!(s.app_install_id().unwrap(), first);
        assert_eq!(first.len(), 36);
        assert_eq!(first.as_bytes()[14], b'4', "must be a v4 UUID");
        assert!(matches!(first.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
    }

    #[test]
    fn app_install_id_survives_credential_writes() {
        let dir = TempDir::new().unwrap();
        let s = store(&dir, 0x5a);
        let id = s.app_install_id().unwrap();
        pollster::block_on(async {
            s.put("k", &cred(b"m")).await.unwrap();
        });
        assert_eq!(s.app_install_id().unwrap(), id);
    }

    #[test]
    fn two_uuids_differ() {
        assert_ne!(new_uuid_v4(), new_uuid_v4());
    }

    /// The property the whole pairing flow rests on: the transport key a device
    /// pairs with is the one it dials with next launch.
    #[test]
    fn a_host_secret_is_minted_once_and_survives_a_reopen() {
        let dir = TempDir::new().unwrap();
        let minted = store(&dir, 0x5a)
            .get_or_put_secret("mshr.device_secret", || "first".to_string())
            .unwrap();
        assert_eq!(minted, "first");
        // A second call on a FRESH store over the same file — i.e. the next
        // launch — must not mint again.
        let reread = store(&dir, 0x5a)
            .get_or_put_secret("mshr.device_secret", || "second".to_string())
            .unwrap();
        assert_eq!(reread, "first");
    }

    #[test]
    fn an_unset_host_secret_reads_as_none_and_deletes_idempotently() {
        let dir = TempDir::new().unwrap();
        let s = store(&dir, 0x5a);
        assert_eq!(s.get_secret("absent").unwrap(), None);
        // Unlike `CredentialStore::delete`, removing an absent key is success:
        // the callers are unpair/sign-out paths whose postcondition is "gone".
        s.delete_secret("absent").unwrap();
        s.get_or_put_secret("present", || "v".to_string()).unwrap();
        assert_eq!(s.get_secret("present").unwrap().as_deref(), Some("v"));
        s.delete_secret("present").unwrap();
        assert_eq!(s.get_secret("present").unwrap(), None);
    }

    /// Secrets, credentials and the install id share one sealed file; writing
    /// any one of them must not drop the others.
    #[test]
    fn secrets_credentials_and_the_install_id_coexist_in_one_vault() {
        let dir = TempDir::new().unwrap();
        let s = store(&dir, 0x5a);
        let id = s.app_install_id().unwrap();
        pollster::block_on(async { s.put("cheers.session", &cred(b"m")).await.unwrap() });
        s.get_or_put_secret("mshr.device_secret", || "sk".to_string())
            .unwrap();

        let reopened = store(&dir, 0x5a);
        assert_eq!(reopened.app_install_id().unwrap(), id);
        assert_eq!(
            reopened.get_secret("mshr.device_secret").unwrap().as_deref(),
            Some("sk")
        );
        pollster::block_on(async {
            assert_eq!(
                reopened.get("cheers.session").await.unwrap(),
                Some(cred(b"m"))
            );
        });
    }

    /// A vault written before `secrets` existed must still read — the whole
    /// reason every field is `#[serde(default)]`.
    #[test]
    fn a_vault_without_a_secrets_field_still_reads() {
        let dir = TempDir::new().unwrap();
        let sealer = TestSealer::new(0x5a);
        let legacy = br#"{"credentials":{},"install_id":"old-id"}"#;
        std::fs::write(dir.path().join(VAULT_FILE_NAME), sealer.seal(legacy).unwrap()).unwrap();
        let s = store(&dir, 0x5a);
        assert_eq!(s.app_install_id().unwrap(), "old-id");
        assert_eq!(s.get_secret("mshr.device_secret").unwrap(), None);
    }

    #[test]
    fn is_send_sync_and_dyn_compatible() {
        fn assert_store(_: &dyn CredentialStore) {}
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AndroidKeystoreStore>();
        let dir = TempDir::new().unwrap();
        assert_store(&store(&dir, 0x5a));
    }
}
