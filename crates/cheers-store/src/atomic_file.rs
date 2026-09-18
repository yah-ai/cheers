//! Crash-safe file replacement, shared by the file-backed stores.
//!
//! Both [`EncryptedFileStore`](crate::EncryptedFileStore) (`headless`) and
//! [`AndroidKeystoreStore`](crate::AndroidKeystoreStore) (`android`) keep the
//! whole credential map in **one** file and rewrite it on every mutation, so
//! both need the same guarantee: a reader never observes a half-written store,
//! and a crash mid-write leaves the previous contents intact.
//!
//! This lived inside `encrypted_file.rs` until the Android backend landed
//! (R726-F20). It is hoisted rather than copied because [`write_atomic`] is
//! security-relevant — the `create_new` (O_EXCL) open and the unpredictable
//! temp-file name are what stop a planted file or symlink from being written
//! through — and a second, drifting copy of that reasoning is exactly the kind
//! of thing that gets "simplified" back into a plain `File::create`.

use std::io::Write;
use std::path::{Path, PathBuf};

use cheers_core::StoreError;

/// Write `bytes` to a sibling temp file then rename it over `path`, so a reader
/// never observes a partially written store and a crash leaves the old file
/// intact.
///
/// The temp file has a unique, unpredictable name (pid + 128 random bits) and is
/// opened `create_new` (O_EXCL): a pre-planted file or symlink at the path can't
/// be followed or clobbered — the open fails instead of writing through it.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    create_parent(path).map_err(|e| io_backend("create data dir", &e))?;
    let tmp = unique_temp_path(path);
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts
            .open(&tmp)
            .map_err(|e| io_backend("open temp file", &e))?;
        file.write_all(bytes)
            .map_err(|e| io_backend("write temp file", &e))?;
        file.sync_all()
            .map_err(|e| io_backend("sync temp file", &e))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| io_backend("rename into place", &e))
}

/// A unique, unpredictable sibling path for the write-then-rename temp file:
/// `<data-file>.<pid>.<random-hex>.tmp`. The 128-bit random suffix (from the OS
/// CSPRNG) makes the name unguessable, so an attacker can't pre-create or
/// symlink the target ahead of the `create_new` (O_EXCL) open in [`write_atomic`].
fn unique_temp_path(path: &Path) -> PathBuf {
    let mut rand = [0u8; 16];
    getrandom::fill(&mut rand).expect("OS CSPRNG must be available");
    let mut suffix = String::with_capacity(rand.len() * 2);
    for b in rand {
        use std::fmt::Write as _;
        let _ = write!(suffix, "{b:02x}");
    }
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.{suffix}.tmp", std::process::id()));
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(name),
        _ => PathBuf::from(name),
    }
}

/// `create_dir_all` the parent of `path`, tolerating a bare filename (no parent).
pub(crate) fn create_parent(path: &Path) -> std::io::Result<()> {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => std::fs::create_dir_all(parent),
        _ => Ok(()),
    }
}

/// Build a [`StoreError::Backend`] from a context string and an I/O error.
pub(crate) fn io_backend(context: &str, err: &std::io::Error) -> StoreError {
    StoreError::Backend(format!("{context}: {err}"))
}
