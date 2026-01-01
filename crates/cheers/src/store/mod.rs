//! Platform credential stores — implementations of [`cheers_core::store::CredentialStore`].
//!
//! Each backend is feature-gated:
//!
//! | Feature    | Store             | Notes                                      |
//! |------------|-------------------|--------------------------------------------|
//! | `headless` | [`MemoryStore`]   | In-memory; for tests and embedded contexts |
//! | `headless` | `EncryptedFileStore` | age-encrypted file (P8 follow-on)       |
//! | `keyring`  | `KeyringStore`    | System keyring (P8 follow-on)              |

#[cfg(feature = "headless")]
pub mod memory;

#[cfg(feature = "headless")]
pub use memory::MemoryStore;
