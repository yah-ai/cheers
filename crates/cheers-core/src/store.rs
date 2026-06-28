//! Client-side persistence contract — [`CredentialStore`] + the shared
//! [`StoreError`].
//!
//! `cheers-core` keeps only the *device-side* store trait: [`CredentialStore`],
//! the opaque-blob credential storage a native client (keyring, encrypted-file,
//! in-memory) implements. The *origin-side* store traits — `UserStore` and
//! `RefreshStore` — moved to `cheers-server` (R019-F6), so a verify-only or
//! device-only consumer never even names them. [`StoreError`] stays here: it's
//! the shared error every store and the revocation traits return.
//!
//! All traits are `async` via [`async_trait`] so they remain dyn-compatible.
//!
//! `StoreError` here is the **adapter-facing** error; R007-T4 lands the
//! workspace-wide error hierarchy and re-exports a unified type.
//!
//! @yah:ticket(R019-F4, "Revocation read/write split: RevocationWriter (origin) + RevocationReader (edge)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-05-26T17:52:56Z)
//! @yah:status(review)
//! @yah:parent(R019)
//! @yah:next("Promote store.rs's 'cheers does not enforce revocation server-side; the product wires up the check' note into two traits: RevocationWriter { revoke(jti | chain) } (origin, Yubaba Redis/gossip) and RevocationReader { is_revoked(jti) } (edge, local replica / CF KV).")
//! @yah:next("Eventually-consistent by documented contract; the short access-token TTL is the stated propagation bound. Wire revoke() into logout + UserStore::revoke_device + RefreshStore::revoke_chain.")
//! @yah:next("Keyed on the token's jti — depends on the Claims.jti field added alongside the facades feature.")
//! @yah:verify("cd external/cheers && cargo test -p cheers-core")
//! @arch:see(.yah/docs/working/edge-verifiable-auth.md)
//! @yah:handoff("Landed RevocationReader{is_revoked(jti)} + RevocationWriter{revoke(jti)} in new revocation.rs, exported from lib.rs. Reader = edge hot path (point membership check), Writer = origin cold path; both async + Send+Sync + dyn-compatible, mirroring the store.rs traits. The read/write split is the same capability-by-type discipline as TokenVerifier/TokenMinter.")
//! @yah:handoff("Settled the 'revoke(jti | chain)' shape: the WRITER is jti-only. Chain/device revocation = RefreshStore::revoke_chain (blocks re-issue on the cold path) composed with per-jti revoke + natural expiry of in-flight access tokens within the access TTL. The module doc owns the full eventually-consistent contract (revoke propagates async; access-token TTL is the staleness bound; sound because auth has no cross-session OLTP). store.rs revoke_device doc promoted to point at the new traits.")
//! @yah:handoff("jti landed on Claims (claims.rs) as F4's revocation key — nominally an F3 line-item, but F4 keys on it so it moved up. #[serde(default, skip_serializing_if=String::is_empty)] keeps the wire/cookie format byte-identical when unset; with_jti() builder; Claims::new() kept at 5 args so existing + cross-camp (mesofact R009) call sites still compile.")
//! @yah:handoff("Verified GREEN: cargo test -p cheers-core (45 unit incl. 4 revocation + jti tests, 9 proptest, 3 doctest) + cargo check --workspace --all-features. NOTE: revocation.rs + store.rs doc-link to crate::session::* (SessionAuthority/EdgeVerifier/SessionPolicy), which land in R019-F3 — forward refs that resolve when F3 lands; cargo test/check don't validate intra-doc links, only cargo doc does.")
//! @yah:handoff("Facade-level wiring (SessionAuthority composing revoke_chain + revoke; EdgeVerifier consulting is_revoked after signature check) is R019-F3 — picked up next per the maintainer's F4-first ordering.")

use async_trait::async_trait;

use crate::claims::Credential;

/// Errors a store impl may return.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    #[error("not found")]
    NotFound,
    /// A unique constraint (e.g. provider+subject already linked, duplicate device).
    #[error("conflict")]
    Conflict,
    /// Underlying backend failure (DB error, I/O, …). String to keep the
    /// trait dyn-compatible without leaking concrete error types.
    #[error("backend: {0}")]
    Backend(String),
}

/// Opaque-blob credential storage, keyed by a caller-chosen string.
///
/// The one store trait the device tier needs: native-client features (P8)
/// implement it over keyring, encrypted-file, or in-memory backends.
/// `Credential::material` is the provider-specific blob; cheers-core does not
/// interpret it. Kept in `cheers-core` (not `cheers-server`) because the client
/// stores credentials without ever touching a token codec.
#[async_trait]
pub trait CredentialStore: Send + Sync {
    async fn put(&self, key: &str, cred: &Credential) -> Result<(), StoreError>;
    async fn get(&self, key: &str) -> Result<Option<Credential>, StoreError>;
    async fn delete(&self, key: &str) -> Result<(), StoreError>;
}

#[cfg(test)]
mod tests {
    //! Trait-shape smoke test via a tiny in-memory impl. The "real" memory impls
    //! live in the `cheers` crate (R015-T3).

    use super::*;
    use crate::claims::{DeviceBinding, DeviceId, UserId};
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemCredentialStore(Mutex<HashMap<String, Credential>>);

    #[async_trait]
    impl CredentialStore for MemCredentialStore {
        async fn put(&self, key: &str, cred: &Credential) -> Result<(), StoreError> {
            self.0.lock().unwrap().insert(key.to_owned(), cred.clone());
            Ok(())
        }
        async fn get(&self, key: &str) -> Result<Option<Credential>, StoreError> {
            Ok(self.0.lock().unwrap().get(key).cloned())
        }
        async fn delete(&self, key: &str) -> Result<(), StoreError> {
            self.0
                .lock()
                .unwrap()
                .remove(key)
                .map(|_| ())
                .ok_or(StoreError::NotFound)
        }
    }

    fn cred(user: &str, device: &str) -> Credential {
        Credential::new(
            UserId::new(user),
            DeviceId::new(device),
            DeviceBinding::Passkey,
            b"material".to_vec(),
        )
    }

    #[test]
    fn credential_store_put_get_delete() {
        let s = MemCredentialStore::default();
        pollster::block_on(async {
            let c = cred("u1", "d1");
            assert!(s.get("k").await.unwrap().is_none());
            s.put("k", &c).await.unwrap();
            assert_eq!(s.get("k").await.unwrap().unwrap(), c);
            s.delete("k").await.unwrap();
            assert!(matches!(s.delete("k").await, Err(StoreError::NotFound)));
        });
    }

    #[test]
    fn trait_is_dyn_compatible() {
        fn _c(_: &dyn CredentialStore) {}
    }
}
