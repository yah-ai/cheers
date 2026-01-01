//! Workspace-wide typed errors.
//!
//! Per-module errors ([`CodecError`], [`StoreError`]) stay local to the modules
//! that raise them — they describe failures a single subsystem can own. [`Error`]
//! is the umbrella type for functions that touch more than one subsystem (e.g. a
//! sign-in handler that loads a user *and* mints a token); it carries the
//! original typed cause via `#[from]` so callers can downcast when they need to.
//!
//! All the error *types* live here in `cheers-core`, even when the machinery that
//! raises them lives in a higher crate: [`RefreshError`] is produced by
//! `cheers-server`'s refresh rotator, but the type is keyless, so keeping it in
//! the shared contract crate lets the [`Error`] umbrella stay whole (both the
//! `cheers-verify` `EdgeVerifier` and the `cheers-server` `SessionAuthority`
//! return this one `Error`).
//!
//! ```
//! use cheers_core::{CodecError, Error};
//!
//! fn outer() -> Result<(), Error> {
//!     // CodecError -> Error via the From impl.
//!     Err(CodecError::Malformed)?
//! }
//!
//! assert!(matches!(outer(), Err(Error::Codec(CodecError::Malformed))));
//! ```

use crate::codec::CodecError;
use crate::store::StoreError;

/// Errors raised by refresh-token rotation (`cheers-server`'s `RefreshRotator`).
///
/// Keyless, so it lives in the shared contract crate. `#[non_exhaustive]` so
/// future variants don't break callers.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RefreshError {
    /// The presented token isn't in the store.
    #[error("unknown refresh token")]
    Unknown,
    /// `expires_at <= now` for this token.
    #[error("refresh token expired")]
    Expired,
    /// The presented token has already been rotated. The chain is now revoked as
    /// a side effect — every record sharing the chain id has `revoked = true`
    /// after this error returns.
    #[error("replay detected; chain revoked")]
    Replay,
    /// The chain was previously revoked (logout, device revoke, prior replay).
    #[error("chain revoked")]
    ChainRevoked,
    /// Underlying `RefreshStore` failure.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Top-level cheers error. `#[non_exhaustive]` so new variants are non-breaking.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Failure inside the [`Codec`](crate::codec::Codec) layer.
    #[error(transparent)]
    Codec(#[from] CodecError),

    /// Failure inside a [`UserStore`]/[`CredentialStore`](crate::store::CredentialStore)/`RefreshStore`
    /// impl.
    ///
    /// [`UserStore`]: crate::store
    #[error(transparent)]
    Store(#[from] StoreError),

    /// Failure inside refresh-token rotation — surfaced by `cheers-server`'s
    /// `SessionAuthority::rotate`.
    #[error(transparent)]
    Refresh(#[from] RefreshError),

    /// A token verified cryptographically but its `jti` is in the revocation
    /// set — surfaced by `cheers-verify`'s `EdgeVerifier`.
    #[error("session revoked")]
    Revoked,

    /// Caller passed invalid input that no specific subsystem owns
    /// (e.g. an empty subject string, a timestamp outside i64 range).
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

/// Crate-local `Result` alias. Re-exported at the crate root.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_error_converts_via_from() {
        let e: Error = CodecError::Malformed.into();
        assert!(matches!(e, Error::Codec(CodecError::Malformed)));
    }

    #[test]
    fn store_error_converts_via_from() {
        let e: Error = StoreError::NotFound.into();
        assert!(matches!(e, Error::Store(StoreError::NotFound)));
    }

    #[test]
    fn refresh_error_converts_via_from() {
        let e: Error = RefreshError::Replay.into();
        assert!(matches!(e, Error::Refresh(RefreshError::Replay)));
        // RefreshError itself absorbs a StoreError.
        let e: Error = RefreshError::from(StoreError::Conflict).into();
        assert!(matches!(e, Error::Refresh(RefreshError::Store(StoreError::Conflict))));
    }

    #[test]
    fn question_mark_propagates() {
        fn inner() -> Result<()> {
            Err(StoreError::Conflict)?
        }
        assert!(matches!(inner(), Err(Error::Store(StoreError::Conflict))));
    }

    #[test]
    fn invalid_input_displays_message() {
        let e = Error::InvalidInput("subject empty".into());
        assert_eq!(format!("{e}"), "invalid input: subject empty");
    }

    #[test]
    fn error_is_send_sync_static() {
        fn _check<T: Send + Sync + 'static>() {}
        _check::<Error>();
    }
}
