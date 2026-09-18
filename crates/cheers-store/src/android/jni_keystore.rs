//! [`AndroidKeystoreSealer`] — the [`KeySealer`] that actually talks to Android
//! Keystore, over JNI (R726-F20).
//!
//! Compiled only on `target_os = "android"`. Everything about
//! [`AndroidKeystoreStore`](super::AndroidKeystoreStore) that can be tested on a
//! dev box lives in the parent module; this file is the irreducible platform
//! part, and it is written to be *read* rather than run, because no CI here can
//! execute it.
//!
//! ## What it does, in Java
//!
//! ```java
//! // key, once per install — created lazily, then looked up by alias forever
//! KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
//! ks.load(null);
//! SecretKey key = (SecretKey) ks.getKey(alias, null);
//! if (key == null) {
//!     KeyGenerator kg = KeyGenerator.getInstance("AES", "AndroidKeyStore");
//!     kg.init(new KeyGenParameterSpec.Builder(alias,
//!                 KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
//!             .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
//!             .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
//!             .setKeySize(256)
//!             .build());
//!     key = kg.generateKey();
//! }
//!
//! // seal
//! Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
//! c.init(Cipher.ENCRYPT_MODE, key);
//! byte[] ct = c.doFinal(plaintext);
//! byte[] iv = c.getIV();          // Keystore picks it; we must not
//!
//! // unseal
//! Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
//! c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
//! byte[] pt = c.doFinal(ct);
//! ```
//!
//! The AES key material never leaves the TEE (or StrongBox, where the device has
//! one): `generateKey` returns a *handle*, `doFinal` runs inside the keymaster.
//! Copying the sealed file off the device therefore yields bytes that only that
//! device can open.
//!
//! ### The IV is the platform's to choose
//!
//! `KeyGenParameterSpec` defaults `setRandomizedEncryptionRequired(true)`, which
//! makes `Cipher.init(ENCRYPT_MODE, key)` reject a caller-supplied IV outright.
//! That default is kept deliberately — it is the platform enforcing the nonce
//! uniqueness [`KeySealer`] requires — so the IV is read back off the `Cipher`
//! after init and framed into the output rather than chosen here.
//!
//! ## Frame format
//!
//! `[0x01 version][iv_len: u8][iv][ciphertext || GCM tag]` — see
//! [`frame`](super::frame), which is a separate module precisely so the on-disk
//! format's parser is compiled and tested on hosts that can't run this file.
//!
//! ## Threading
//!
//! Each call attaches the current thread to the JVM and runs inside one local
//! reference frame. No `Global` reference and no cached `SecretKey` handle is
//! held: the alias lookup is re-done per call, which costs a Keystore round trip
//! on a path that runs a handful of times per launch and buys the type an
//! unconditional `Send + Sync` with no reference lifetime to manage.
//!
//! Every class named here is a *platform* class loaded by the bootstrap class
//! loader, which is what makes `FindClass` safe to use from an arbitrary native
//! thread on Android — the documented failure (application classes being
//! invisible off the main thread) does not apply.

use jni::objects::{JByteArray, JObject, JObjectArray, JString, JValue};
use jni::{jni_sig, jni_str, Env, JavaVM};

use cheers_core::StoreError;

use super::frame::{frame, unframe};
use super::KeySealer;

/// The JCA provider name for the hardware-backed store.
const ANDROID_KEY_STORE: &str = "AndroidKeyStore";
/// The transformation both directions run under.
const TRANSFORMATION: &str = "AES/GCM/NoPadding";
/// GCM authentication tag length in bits — the maximum, and what Keystore emits.
const GCM_TAG_BITS: i32 = 128;
/// AES key size in bits.
const KEY_SIZE_BITS: i32 = 256;

/// A [`KeySealer`] backed by an AES-256-GCM key held in Android Keystore.
///
/// Built by [`AndroidKeystoreStore::open`](super::AndroidKeystoreStore::open);
/// construct one directly only to seal something other than a credential vault.
#[derive(Debug, Clone)]
pub struct AndroidKeystoreSealer {
    alias: String,
}

impl AndroidKeystoreSealer {
    /// A sealer over the Keystore key named `alias`, created on first use.
    pub fn new(alias: impl Into<String>) -> Self {
        Self {
            alias: alias.into(),
        }
    }

    /// The Keystore alias this sealer's key lives under.
    pub fn alias(&self) -> &str {
        &self.alias
    }
}

impl KeySealer for AndroidKeystoreSealer {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, StoreError> {
        with_env(|env| {
            let key = get_or_create_key(env, &self.alias)?;

            let cipher_cls = env.find_class(jni_str!("javax/crypto/Cipher"))?;
            let transformation = env.new_string(TRANSFORMATION)?;
            let cipher = env
                .call_static_method(
                    &cipher_cls,
                    jni_str!("getInstance"),
                    const { &jni_sig!((transformation: java.lang.String) -> javax.crypto.Cipher) },
                    &[JValue::Object(&transformation)],
                )?
                .l()?;

            let encrypt_mode = env
                .get_static_field(
                    &cipher_cls,
                    jni_str!("ENCRYPT_MODE"),
                    const { &jni_sig!(jint) },
                )?
                .i()?;
            env.call_method(
                &cipher,
                jni_str!("init"),
                const { &jni_sig!((opmode: jint, key: java.security.Key) -> void) },
                &[JValue::Int(encrypt_mode), JValue::Object(&key)],
            )?
            .v()?;

            let input = env.byte_array_from_slice(plaintext)?;
            let ciphertext = env
                .call_method(
                    &cipher,
                    jni_str!("doFinal"),
                    const { &jni_sig!((input: [jbyte]) -> [jbyte]) },
                    &[JValue::Object(&input)],
                )?
                .l()?;
            let iv = env
                .call_method(
                    &cipher,
                    jni_str!("getIV"),
                    const { &jni_sig!(() -> [jbyte]) },
                    &[],
                )?
                .l()?;

            // `call_method` hands back a JObject; the checked cast is what turns
            // the signature's declared `byte[]` into a typed one we can read.
            let ciphertext = env.cast_local::<JByteArray>(ciphertext)?;
            let iv = env.cast_local::<JByteArray>(iv)?;
            let ciphertext = env.convert_byte_array(&ciphertext)?;
            let iv = env.convert_byte_array(&iv)?;
            Ok(frame(&iv, &ciphertext))
        })
    }

    fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, StoreError> {
        let (iv, ciphertext) = unframe(sealed)?;

        with_env(|env| {
            let key = get_or_create_key(env, &self.alias)?;

            let cipher_cls = env.find_class(jni_str!("javax/crypto/Cipher"))?;
            let transformation = env.new_string(TRANSFORMATION)?;
            let cipher = env
                .call_static_method(
                    &cipher_cls,
                    jni_str!("getInstance"),
                    const { &jni_sig!((transformation: java.lang.String) -> javax.crypto.Cipher) },
                    &[JValue::Object(&transformation)],
                )?
                .l()?;

            let iv_array = env.byte_array_from_slice(iv)?;
            let gcm_spec_cls = env.find_class(jni_str!("javax/crypto/spec/GCMParameterSpec"))?;
            let gcm_spec = env.new_object(
                &gcm_spec_cls,
                const { &jni_sig!((tag_len: jint, iv: [jbyte]) -> void) },
                &[JValue::Int(GCM_TAG_BITS), JValue::Object(&iv_array)],
            )?;

            let decrypt_mode = env
                .get_static_field(
                    &cipher_cls,
                    jni_str!("DECRYPT_MODE"),
                    const { &jni_sig!(jint) },
                )?
                .i()?;
            env.call_method(
                &cipher,
                jni_str!("init"),
                const {
                    &jni_sig!((
                        opmode: jint,
                        key: java.security.Key,
                        params: java.security.spec.AlgorithmParameterSpec
                    ) -> void)
                },
                &[
                    JValue::Int(decrypt_mode),
                    JValue::Object(&key),
                    JValue::Object(&gcm_spec),
                ],
            )?
            .v()?;

            let input = env.byte_array_from_slice(ciphertext)?;
            let plain = env
                .call_method(
                    &cipher,
                    jni_str!("doFinal"),
                    const { &jni_sig!((input: [jbyte]) -> [jbyte]) },
                    &[JValue::Object(&input)],
                )?
                .l()?;
            let plain = env.cast_local::<JByteArray>(plain)?;
            env.convert_byte_array(&plain)
        })
    }
}

/// Look the sealer's AES key up by alias, generating it if this is first use.
///
/// `KeyStore.getKey` returns `null` — not an exception — for an absent alias,
/// which is what makes the lazy-create branch safe to key off a null check.
fn get_or_create_key<'local>(
    env: &mut Env<'local>,
    alias: &str,
) -> jni::errors::Result<JObject<'local>> {
    let keystore_cls = env.find_class(jni_str!("java/security/KeyStore"))?;
    let provider = env.new_string(ANDROID_KEY_STORE)?;
    let keystore = env
        .call_static_method(
            &keystore_cls,
            jni_str!("getInstance"),
            const { &jni_sig!((ty: java.lang.String) -> java.security.KeyStore) },
            &[JValue::Object(&provider)],
        )?
        .l()?;

    // `load(null)` — the LoadStoreParameter overload. AndroidKeyStore has no
    // stream or password to load from, but the store is unusable until it is
    // called.
    let null = JObject::null();
    env.call_method(
        &keystore,
        jni_str!("load"),
        const { &jni_sig!((param: java.security.KeyStore::LoadStoreParameter) -> void) },
        &[JValue::Object(&null)],
    )?
    .v()?;

    let alias_str = env.new_string(alias)?;
    let existing = env
        .call_method(
            &keystore,
            jni_str!("getKey"),
            const { &jni_sig!((alias: java.lang.String, password: [jchar]) -> java.security.Key) },
            &[JValue::Object(&alias_str), JValue::Object(&null)],
        )?
        .l()?;
    if !existing.as_raw().is_null() {
        return Ok(existing);
    }

    generate_key(env, &alias_str)
}

/// Create the AES-256-GCM Keystore key for `alias` and return the fresh handle.
fn generate_key<'local>(
    env: &mut Env<'local>,
    alias: &JString<'_>,
) -> jni::errors::Result<JObject<'local>> {
    let keygen_cls = env.find_class(jni_str!("javax/crypto/KeyGenerator"))?;
    let algorithm = env.new_string("AES")?;
    let provider = env.new_string(ANDROID_KEY_STORE)?;
    let keygen = env
        .call_static_method(
            &keygen_cls,
            jni_str!("getInstance"),
            const {
                &jni_sig!(
                    (algorithm: java.lang.String, provider: java.lang.String)
                        -> javax.crypto.KeyGenerator
                )
            },
            &[JValue::Object(&algorithm), JValue::Object(&provider)],
        )?
        .l()?;

    // The KeyProperties constants are read off the class rather than inlined as
    // 1/2/"GCM"/"NoPadding": they are the platform's own names for these values
    // and a transcription slip here would fail at runtime on a device, which is
    // the one place this code cannot be tested.
    let props_cls = env.find_class(jni_str!("android/security/keystore/KeyProperties"))?;
    let purpose_encrypt = env
        .get_static_field(
            &props_cls,
            jni_str!("PURPOSE_ENCRYPT"),
            const { &jni_sig!(jint) },
        )?
        .i()?;
    let purpose_decrypt = env
        .get_static_field(
            &props_cls,
            jni_str!("PURPOSE_DECRYPT"),
            const { &jni_sig!(jint) },
        )?
        .i()?;
    let block_mode_gcm = env
        .get_static_field(
            &props_cls,
            jni_str!("BLOCK_MODE_GCM"),
            const { &jni_sig!(java.lang.String) },
        )?
        .l()?;
    let padding_none = env
        .get_static_field(
            &props_cls,
            jni_str!("ENCRYPTION_PADDING_NONE"),
            const { &jni_sig!(java.lang.String) },
        )?
        .l()?;

    let builder_cls = env.find_class(jni_str!(
        "android/security/keystore/KeyGenParameterSpec$Builder"
    ))?;
    let builder = env.new_object(
        &builder_cls,
        const { &jni_sig!((alias: java.lang.String, purposes: jint) -> void) },
        &[
            JValue::Object(alias),
            JValue::Int(purpose_encrypt | purpose_decrypt),
        ],
    )?;

    let block_modes = string_array(env, block_mode_gcm)?;
    let builder = env
        .call_method(
            &builder,
            jni_str!("setBlockModes"),
            const {
                &jni_sig!(
                    (modes: [java.lang.String])
                        -> android.security.keystore.KeyGenParameterSpec::Builder
                )
            },
            &[JValue::Object(&block_modes)],
        )?
        .l()?;

    let paddings = string_array(env, padding_none)?;
    let builder = env
        .call_method(
            &builder,
            jni_str!("setEncryptionPaddings"),
            const {
                &jni_sig!(
                    (paddings: [java.lang.String])
                        -> android.security.keystore.KeyGenParameterSpec::Builder
                )
            },
            &[JValue::Object(&paddings)],
        )?
        .l()?;

    let builder = env
        .call_method(
            &builder,
            jni_str!("setKeySize"),
            const {
                &jni_sig!(
                    (bits: jint) -> android.security.keystore.KeyGenParameterSpec::Builder
                )
            },
            &[JValue::Int(KEY_SIZE_BITS)],
        )?
        .l()?;

    let spec = env
        .call_method(
            &builder,
            jni_str!("build"),
            const { &jni_sig!(() -> android.security.keystore.KeyGenParameterSpec) },
            &[],
        )?
        .l()?;

    env.call_method(
        &keygen,
        jni_str!("init"),
        const { &jni_sig!((params: java.security.spec.AlgorithmParameterSpec) -> void) },
        &[JValue::Object(&spec)],
    )?
    .v()?;

    env.call_method(
        &keygen,
        jni_str!("generateKey"),
        const { &jni_sig!(() -> javax.crypto.SecretKey) },
        &[],
    )?
    .l()
}

/// Wrap one `String` in a `String[1]` — the shape `KeyGenParameterSpec.Builder`'s
/// varargs setters take across the JNI boundary.
fn string_array<'local>(
    env: &mut Env<'local>,
    value: JObject<'_>,
) -> jni::errors::Result<JObjectArray<'local>> {
    let string_cls = env.find_class(jni_str!("java/lang/String"))?;
    env.new_object_array(1, &string_cls, &value)
}

/// Attach the current thread to the process's JVM and run `f` against it.
///
/// The `JavaVM` comes from `ndk_context`, which the host app's runtime populates
/// (Tauri's Android entry point does, as does `android-activity`). A null VM
/// there means this ran outside an Android app process, which is a wiring bug
/// rather than a recoverable condition — it is reported as a `Backend` error
/// with that wording rather than being papered over.
fn with_env<T>(f: impl FnOnce(&mut Env) -> jni::errors::Result<T>) -> Result<T, StoreError> {
    let ctx = ndk_context::android_context();
    if ctx.vm().is_null() {
        return Err(StoreError::Backend(
            "no JavaVM in ndk_context — Android Keystore needs an Android app process".into(),
        ));
    }
    // SAFETY: ndk_context hands out the process's real JavaVM pointer, checked
    // non-null above; `from_raw` interns it into jni's process-wide singleton.
    let vm = unsafe { JavaVM::from_raw(ctx.vm().cast()) };
    vm.attach_current_thread(f).map_err(jni_backend)
}

/// Collapse a JNI error onto the store contract's [`StoreError`].
///
/// Everything lands in `Backend`, including the two failures worth recognizing
/// in a bug report: `JavaException` wrapping `AEADBadTagException` (the vault
/// was tampered with or sealed under another key) and one wrapping
/// `KeyPermanentlyInvalidatedException` (the user changed or removed the lock
/// screen, and the TEE dropped the key). Neither is recoverable here — both mean
/// the vault must be re-created by pairing again.
fn jni_backend(err: jni::errors::Error) -> StoreError {
    StoreError::Backend(format!("android keystore: {err}"))
}
