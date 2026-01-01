//! # cheers — identity providers + native credential storage
//!
//! Built on [`cheers-core`](../cheers-core). Each provider lives behind a
//! feature flag; nothing is compiled in by default.
//!
//! See the design doc at `.yah/docs/working/cheers.md` and the build plan at
//! `.yah/docs/working/cheers-plan.md`.

#[cfg(any(feature = "headless", feature = "keyring"))]
pub mod store;

#[cfg(feature = "email")]
pub mod email;

#[cfg(feature = "passkey")]
pub mod passkey;

#[cfg(any(feature = "google", feature = "apple"))]
pub mod providers;

#[cfg(any(feature = "macos", feature = "ios"))]
pub mod native;

#[cfg(feature = "lan-pair")]
pub mod lan_pair;
