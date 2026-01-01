//! Minimal in-memory store impls for tests that don't need SQL semantics.
//!
//! These complement [`super::TursoRefreshStore`] — use `TursoRefreshStore`
//! when you need real SQL constraints/ordering; use these for lightweight unit
//! tests where the storage semantics don't matter.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cheers_core::{DeviceId, StoreError, User, UserId};
use cheers_server::store::{NewUser, ProviderKey, RefreshStore, RefreshTokenRecord, UserStore};
use cheers_server::RevocationWriter;
use cheers_verify::RevocationReader;

// ── MemUserStore ─────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct MemUserStore {
    inner: Mutex<MemUserInner>,
}

#[derive(Default)]
struct MemUserInner {
    next_id: u64,
    users: HashMap<UserId, User>,
    links: HashMap<(ProviderKey, String), UserId>,
    devices: HashMap<UserId, Vec<DeviceId>>,
}

#[async_trait]
impl UserStore for MemUserStore {
    async fn find_by_provider(
        &self,
        provider: &ProviderKey,
        subject: &str,
    ) -> Result<Option<User>, StoreError> {
        let g = self.inner.lock().unwrap();
        Ok(g.links
            .get(&(provider.clone(), subject.to_owned()))
            .and_then(|id| g.users.get(id).cloned()))
    }

    async fn create(&self, new_user: NewUser) -> Result<User, StoreError> {
        let mut g = self.inner.lock().unwrap();
        g.next_id += 1;
        let id = UserId::new(format!("u-{}", g.next_id));
        let mut u = User::new(id.clone());
        u.email = new_user.email;
        u.name = new_user.name;
        g.users.insert(id, u.clone());
        Ok(u)
    }

    async fn link_provider(
        &self,
        user_id: &UserId,
        provider: &ProviderKey,
        subject: &str,
    ) -> Result<(), StoreError> {
        let mut g = self.inner.lock().unwrap();
        let key = (provider.clone(), subject.to_owned());
        match g.links.get(&key) {
            Some(existing) if existing == user_id => Ok(()),
            Some(_) => Err(StoreError::Conflict),
            None => {
                g.links.insert(key, user_id.clone());
                Ok(())
            }
        }
    }

    async fn list_devices(&self, user_id: &UserId) -> Result<Vec<DeviceId>, StoreError> {
        let g = self.inner.lock().unwrap();
        Ok(g.devices.get(user_id).cloned().unwrap_or_default())
    }

    async fn revoke_device(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
    ) -> Result<(), StoreError> {
        let mut g = self.inner.lock().unwrap();
        let entry = g.devices.entry(user_id.clone()).or_default();
        entry.retain(|d| d != device_id);
        Ok(())
    }
}

// ── MemRefreshStore ───────────────────────────────────────────────────────────

#[derive(Default)]
pub struct MemRefreshStore(Mutex<HashMap<String, RefreshTokenRecord>>);

#[async_trait]
impl RefreshStore for MemRefreshStore {
    async fn put(&self, record: &RefreshTokenRecord) -> Result<(), StoreError> {
        self.0
            .lock()
            .unwrap()
            .insert(record.token.clone(), record.clone());
        Ok(())
    }
    async fn get(&self, token: &str) -> Result<Option<RefreshTokenRecord>, StoreError> {
        Ok(self.0.lock().unwrap().get(token).cloned())
    }
    async fn mark_consumed(&self, token: &str) -> Result<(), StoreError> {
        let mut g = self.0.lock().unwrap();
        g.get_mut(token).ok_or(StoreError::NotFound)?.consumed = true;
        Ok(())
    }
    async fn revoke_chain(&self, chain_id: &str) -> Result<(), StoreError> {
        let mut g = self.0.lock().unwrap();
        for r in g.values_mut() {
            if r.chain_id == chain_id {
                r.revoked = true;
            }
        }
        Ok(())
    }
}

// ── MemRevocations ────────────────────────────────────────────────────────────

#[derive(Clone, Default)]
pub struct MemRevocations(Arc<Mutex<HashSet<String>>>);

#[async_trait]
impl RevocationReader for MemRevocations {
    async fn is_revoked(&self, jti: &str) -> Result<bool, StoreError> {
        Ok(self.0.lock().unwrap().contains(jti))
    }
}

#[async_trait]
impl RevocationWriter for MemRevocations {
    async fn revoke(&self, jti: &str) -> Result<(), StoreError> {
        self.0.lock().unwrap().insert(jti.to_owned());
        Ok(())
    }
}
