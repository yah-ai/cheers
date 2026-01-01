//! Grant persistence — what scope-or-bundle entries a principal holds against
//! a given audience.
//!
//! See `.yah/docs/working/mcp-auth-and-ownership.md` §Mint flows: the mint
//! path looks up grants by `(principal, aud)` and rejects when the list is
//! empty — composition rule (5), aud-scoping is mandatory.
//!
//! Stored as the mixed [`ScopeOrBundle`] entries that ride into
//! [`expand_scopes`](crate::bundles::expand_scopes) verbatim — bundles are
//! deferred to mint time so an edit to a bundle propagates without rewriting
//! grant rows (rule (2), per the doc §Open questions).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cheers_core::{PrincipalId, StoreError};

use crate::bundles::ScopeOrBundle;

/// Persistence for the grant table.
///
/// One method only at the moment — mint-time lookup. Grant *writes* land on
/// the HTTP grant API (a peer of the ownership writes); that surface enforces
/// composition rule (4) via [`cheers_core::validate_grant`] before persisting.
#[async_trait]
pub trait GrantStore: Send + Sync {
    /// All grant entries the principal holds for `aud`. An empty list means
    /// the principal is not entitled to mint a token for that audience — the
    /// mint path MUST reject. Order is whatever the impl returns; mint-time
    /// expansion dedupes ([`expand_scopes`](crate::bundles::expand_scopes)).
    async fn list_for(
        &self,
        principal: &PrincipalId,
        aud: &str,
    ) -> Result<Vec<ScopeOrBundle>, StoreError>;
}

/// In-memory [`GrantStore`] for tests and single-node bootstrapping before the
/// persistent grant store lands. Cheap to `clone` — shares one backing map.
#[derive(Default, Clone)]
pub struct MemoryGrantStore {
    inner: Arc<Mutex<HashMap<(PrincipalId, String), Vec<ScopeOrBundle>>>>,
}

impl MemoryGrantStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set (or overwrite) the grant entries the principal holds for `aud`.
    pub fn put(
        &self,
        principal: PrincipalId,
        aud: impl Into<String>,
        entries: Vec<ScopeOrBundle>,
    ) {
        self.inner
            .lock()
            .expect("grant store mutex poisoned")
            .insert((principal, aud.into()), entries);
    }
}

#[async_trait]
impl GrantStore for MemoryGrantStore {
    async fn list_for(
        &self,
        principal: &PrincipalId,
        aud: &str,
    ) -> Result<Vec<ScopeOrBundle>, StoreError> {
        Ok(self
            .inner
            .lock()
            .expect("grant store mutex poisoned")
            .get(&(principal.clone(), aud.to_owned()))
            .cloned()
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cheers_core::Scope;
    use pollster::block_on;

    #[test]
    fn memory_store_missing_key_yields_empty_list() {
        let store = MemoryGrantStore::new();
        let entries = block_on(store.list_for(&PrincipalId::user("u1"), "https://aud")).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn memory_store_put_then_list_roundtrip() {
        let store = MemoryGrantStore::new();
        let user = PrincipalId::user("alice");
        store.put(
            user.clone(),
            "https://aud",
            vec![
                ScopeOrBundle::Scope(Scope::CloudRead),
                ScopeOrBundle::Scope(Scope::CloudDeploy),
            ],
        );
        let entries = block_on(store.list_for(&user, "https://aud")).unwrap();
        assert_eq!(
            entries,
            vec![
                ScopeOrBundle::Scope(Scope::CloudRead),
                ScopeOrBundle::Scope(Scope::CloudDeploy),
            ]
        );
    }

    #[test]
    fn memory_store_is_keyed_per_aud() {
        let store = MemoryGrantStore::new();
        let user = PrincipalId::user("alice");
        store.put(
            user.clone(),
            "https://aud-a",
            vec![ScopeOrBundle::Scope(Scope::CloudRead)],
        );
        let other = block_on(store.list_for(&user, "https://aud-b")).unwrap();
        assert!(other.is_empty(), "other aud must not leak: {other:?}");
    }
}
