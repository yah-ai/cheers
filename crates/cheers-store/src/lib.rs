//! # cheers-store — device-tier credential storage
//!
//! Concrete [`CredentialStore`](cheers_core::CredentialStore) implementations
//! for native apps (desktop, mobile, the headless rpi in P10) that hold a
//! user's credential locally between launches.
//!
//! This is the **device** tier. It depends on `cheers-core` with
//! `default-features = false`, so it carries the identity types and the
//! `CredentialStore` trait but **no token crypto**: a device that only
//! acquires and stores an opaque credential never compiles a codec, refresh, or
//! session machinery (the no-crypto client surface from R019-F5). The
//! server-side providers — OIDC, Apple Sign In, passkey, email, password — live
//! in the separate `cheers` crate.
//!
//! Each backend is feature-gated, so a build pulls only the platform
//! integration it needs:
//!
//! - [`KeyringStore`] (`keyring` feature) — the OS secret store: Apple
//!   Keychain, Windows Credential Manager, Linux Secret Service. **R015-T1.**
//! - [`EncryptedFileStore`] (`headless` feature) — an `age`-encrypted file for
//!   headless hosts with no OS keyring. **R015-T2.** (TPM-sealed keys are a
//!   deferred seam — see the module docs.)
//! - `MemoryStore` — a process-local map for tests. *R015-T3, pending.*
//!
//! See the design doc at `.yah/docs/working/cheers.md`, the build plan at
//! `.yah/docs/working/cheers-plan.md`, and the crate topology in
//! `.yah/docs/working/edge-verifiable-auth.md`.

#[cfg(feature = "keyring")]
pub mod keyring;

#[cfg(feature = "keyring")]
pub use keyring::KeyringStore;

#[cfg(feature = "headless")]
pub mod encrypted_file;

#[cfg(feature = "headless")]
pub use encrypted_file::{tpm_device_present, EncryptedFileStore};
