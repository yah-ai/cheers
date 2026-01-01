//! In-memory [`CredentialStore`] for tests and examples.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use cheers_core::store::{CredentialStore, StoreError};
use cheers_core::Credential;

/// In-memory [`CredentialStore`] backed by a `HashMap`.
///
/// Cloning a [`MemoryStore`] shares the same backing map via `Arc`, so test
/// code can hold multiple handles to one logical store (e.g. one to seed
/// state, one as the system-under-test).
///
/// Not suitable for production: no persistence, no encryption, unbounded
/// growth. Use [`super::keyring`] or `super::encrypted_file` for real deployments.
#[derive(Clone, Default)]
pub struct MemoryStore(Arc<RwLock<HashMap<String, Credential>>>);

#[async_trait]
impl CredentialStore for MemoryStore {
    async fn put(&self, key: &str, cred: &Credential) -> Result<(), StoreError> {
        self.0.write().unwrap().insert(key.to_owned(), cred.clone());
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<Credential>, StoreError> {
        Ok(self.0.read().unwrap().get(key).cloned())
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        self.0
            .write()
            .unwrap()
            .remove(key)
            .map(|_| ())
            .ok_or(StoreError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cheers_core::{DeviceBinding, DeviceId, UserId};

    fn cred(user: &str, device: &str) -> Credential {
        Credential::new(
            UserId::new(user),
            DeviceId::new(device),
            DeviceBinding::Passkey,
            b"material".to_vec(),
        )
    }

    #[test]
    fn put_get_delete_round_trip() {
        pollster::block_on(async {
            let s = MemoryStore::default();
            let c = cred("u1", "d1");

            assert!(s.get("k").await.unwrap().is_none());

            s.put("k", &c).await.unwrap();
            assert_eq!(s.get("k").await.unwrap().unwrap(), c);

            s.delete("k").await.unwrap();
            assert!(s.get("k").await.unwrap().is_none());

            assert!(matches!(s.delete("k").await, Err(StoreError::NotFound)));
        });
    }

    #[test]
    fn put_overwrites_existing_key() {
        pollster::block_on(async {
            let s = MemoryStore::default();
            let c1 = cred("u1", "d1");
            let c2 = cred("u2", "d2");

            s.put("k", &c1).await.unwrap();
            s.put("k", &c2).await.unwrap();
            assert_eq!(s.get("k").await.unwrap().unwrap(), c2);
        });
    }

    #[test]
    fn multiple_keys_are_independent() {
        pollster::block_on(async {
            let s = MemoryStore::default();
            let c1 = cred("u1", "d1");
            let c2 = cred("u2", "d2");

            s.put("a", &c1).await.unwrap();
            s.put("b", &c2).await.unwrap();

            assert_eq!(s.get("a").await.unwrap().unwrap(), c1);
            assert_eq!(s.get("b").await.unwrap().unwrap(), c2);
        });
    }

    #[test]
    fn clone_shares_backing_map() {
        pollster::block_on(async {
            let s1 = MemoryStore::default();
            let s2 = s1.clone();
            let c = cred("u1", "d1");

            s1.put("k", &c).await.unwrap();
            assert_eq!(s2.get("k").await.unwrap().unwrap(), c);

            s2.delete("k").await.unwrap();
            assert!(s1.get("k").await.unwrap().is_none());
        });
    }

    #[test]
    fn trait_is_dyn_compatible() {
        fn _accept(_: &dyn CredentialStore) {}
        _accept(&MemoryStore::default());
    }
}
