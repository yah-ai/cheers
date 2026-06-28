//! Role-bundle storage and mint-time expansion.
//!
//! A bundle is a named list of [`Scope`]s — `"camp-operator"`,
//! `"deploy-admin"`, etc. — granted to a principal as a unit. The wire never
//! sees the bundle name: at mint, cheers expands every
//! [`ScopeOrBundle::Bundle`] grant entry into its current [`Scope`] list before
//! signing the token. See `.yah/docs/working/mcp-auth-and-ownership.md` §Scope
//! vocabulary and composition rules — rule (2).
//!
//! Expanding at mint (rather than freezing the list at grant time) means a
//! bundle edit propagates on every principal's *next* token mint, without
//! anyone touching the grant rows. That's the trade the doc takes: one
//! lookup per grant entry at mint, acceptable at SMB scale.
//!
//! The wire-shape invariant — bundle names never reach the token — falls out
//! of the type discipline rather than runtime checks: `McpClaims.scope` is
//! `Vec<Scope>`, and [`Scope`] only deserializes the closed-vocabulary wire
//! strings. A bundle name fed in by mistake would fail to parse before
//! anything is signed. [`expand_scopes`] is the one place a bundle reference
//! crosses into a literal [`Scope`] — everything downstream is `Vec<Scope>`.
//!
//! Bundles hold literal scopes only — no nested bundles. That rules out
//! cycles by construction and keeps expansion a single lookup per entry.

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cheers_core::{Scope, StoreError};
use serde::{Deserialize, Serialize};

/// The handle for a named bundle.
///
/// A newtype around `String`. The distinct type stops it being confused with a
/// wire-form scope (`"cloud:deploy"`) at API boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BundleName(String);

impl BundleName {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for BundleName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for BundleName {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for BundleName {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// A single grant entry — what the grant table stores per row. Mint expands
/// the [`Bundle`](Self::Bundle) variants against the bundle table; the
/// [`Scope`](Self::Scope) variants pass through.
///
/// Wire format is an externally-tagged JSON object — `{"scope": "cloud:deploy"}`
/// or `{"bundle": "camp-operator"}` — so a row can be persisted, audited, and
/// re-loaded without losing the distinction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ScopeOrBundle {
    Scope(Scope),
    Bundle(BundleName),
}

impl From<Scope> for ScopeOrBundle {
    fn from(s: Scope) -> Self {
        Self::Scope(s)
    }
}

impl From<BundleName> for ScopeOrBundle {
    fn from(b: BundleName) -> Self {
        Self::Bundle(b)
    }
}

/// Why an expansion failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BundleExpansionError {
    /// A grant referenced a bundle name with no entry in the store. Surfaces a
    /// stale grant: the bundle was deleted but the grant wasn't cleaned up.
    #[error("unknown bundle '{0}'")]
    Unknown(BundleName),
    /// The backing store failed.
    #[error("store: {0}")]
    Store(#[from] StoreError),
}

/// Persistence for the bundle table.
///
/// Mints read individual bundles by name; cross-call atomicity is not required
/// — every mint takes a fresh snapshot.
#[async_trait]
pub trait BundleStore: Send + Sync {
    /// The literal scope list for `name`, or `None` if no such bundle.
    async fn get(&self, name: &BundleName) -> Result<Option<Vec<Scope>>, StoreError>;

    /// Create or overwrite the bundle named `name` with the supplied scopes.
    async fn put(&self, name: &BundleName, scopes: &[Scope]) -> Result<(), StoreError>;

    /// Remove the bundle named `name`. Grants still referencing it will fail
    /// [`expand_scopes`] with [`BundleExpansionError::Unknown`] until the
    /// stale grants are cleaned up.
    async fn delete(&self, name: &BundleName) -> Result<(), StoreError>;
}

/// Mint-time helper: turn a grant's mixed `Scope`/`Bundle` entries into a
/// deduped, literal [`Scope`] list. The output is what reaches the wire —
/// `McpClaims.scope` is `Vec<Scope>`, and any bundle name fed in by mistake
/// would fail to deserialize on the receive side.
///
/// Insertion order is preserved (first occurrence wins on duplicates); inside
/// a bundle, the order is whatever the bundle was stored with.
pub async fn expand_scopes<S: BundleStore + ?Sized>(
    store: &S,
    entries: &[ScopeOrBundle],
) -> Result<Vec<Scope>, BundleExpansionError> {
    let mut out: Vec<Scope> = Vec::with_capacity(entries.len());
    let mut seen: HashSet<Scope> = HashSet::with_capacity(entries.len());

    for entry in entries {
        match entry {
            ScopeOrBundle::Scope(s) => {
                if seen.insert(*s) {
                    out.push(*s);
                }
            }
            ScopeOrBundle::Bundle(name) => {
                let scopes = store
                    .get(name)
                    .await?
                    .ok_or_else(|| BundleExpansionError::Unknown(name.clone()))?;
                for s in scopes {
                    if seen.insert(s) {
                        out.push(s);
                    }
                }
            }
        }
    }
    Ok(out)
}

/// In-memory [`BundleStore`] for tests and single-node bootstrapping before
/// the persistent store lands.
#[derive(Default, Clone)]
pub struct MemoryBundleStore {
    inner: Arc<Mutex<BTreeMap<String, Vec<Scope>>>>,
}

impl MemoryBundleStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-seed with the doc-named bundles `camp-operator` and `deploy-admin`.
    ///
    /// The exact scope contents are illustrative defaults — an operator-side
    /// decision in production, not a wire contract. They are here so the
    /// in-memory rig and tests have a meaningful starting point.
    pub fn with_defaults() -> Self {
        let store = Self::new();
        let camp_operator = vec![
            Scope::CampRead,
            Scope::CampAdmin,
            Scope::BoardRead,
            Scope::BoardWrite,
            Scope::PartyRead,
            Scope::PartyWrite,
            Scope::SubagentSpawn,
            Scope::SubagentControl,
        ];
        let deploy_admin = vec![Scope::CloudRead, Scope::CloudDeploy, Scope::CloudDestroy];
        {
            let mut g = store.inner.lock().expect("bundle store mutex poisoned");
            g.insert("camp-operator".to_owned(), camp_operator);
            g.insert("deploy-admin".to_owned(), deploy_admin);
        }
        store
    }
}

#[async_trait]
impl BundleStore for MemoryBundleStore {
    async fn get(&self, name: &BundleName) -> Result<Option<Vec<Scope>>, StoreError> {
        Ok(self
            .inner
            .lock()
            .expect("bundle store mutex poisoned")
            .get(name.as_str())
            .cloned())
    }

    async fn put(&self, name: &BundleName, scopes: &[Scope]) -> Result<(), StoreError> {
        self.inner
            .lock()
            .expect("bundle store mutex poisoned")
            .insert(name.as_str().to_owned(), scopes.to_vec());
        Ok(())
    }

    async fn delete(&self, name: &BundleName) -> Result<(), StoreError> {
        self.inner
            .lock()
            .expect("bundle store mutex poisoned")
            .remove(name.as_str());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cheers_core::{McpClaims, PrincipalId};
    use pollster::block_on;

    #[test]
    fn memory_store_get_put_delete_roundtrip() {
        let store = MemoryBundleStore::new();
        let name = BundleName::new("custom");
        block_on(async {
            assert!(store.get(&name).await.unwrap().is_none());
            store.put(&name, &[Scope::CloudRead]).await.unwrap();
            assert_eq!(
                store.get(&name).await.unwrap(),
                Some(vec![Scope::CloudRead])
            );
            store.delete(&name).await.unwrap();
            assert!(store.get(&name).await.unwrap().is_none());
        });
    }

    #[test]
    fn with_defaults_seeds_doc_named_bundles() {
        let store = MemoryBundleStore::with_defaults();
        block_on(async {
            assert!(
                store
                    .get(&BundleName::new("camp-operator"))
                    .await
                    .unwrap()
                    .is_some(),
                "camp-operator must be seeded"
            );
            assert!(
                store
                    .get(&BundleName::new("deploy-admin"))
                    .await
                    .unwrap()
                    .is_some(),
                "deploy-admin must be seeded"
            );
        });
    }

    #[test]
    fn expand_literal_scopes_passes_through_in_order_and_dedups() {
        let store = MemoryBundleStore::new();
        let grants = vec![
            ScopeOrBundle::Scope(Scope::CloudRead),
            ScopeOrBundle::Scope(Scope::CloudDeploy),
            ScopeOrBundle::Scope(Scope::CloudRead),
        ];
        let expanded = block_on(expand_scopes(&store, &grants)).unwrap();
        assert_eq!(expanded, vec![Scope::CloudRead, Scope::CloudDeploy]);
    }

    #[test]
    fn expand_bundle_replaces_name_with_literal_scope_list() {
        // R020-F5 verify: "grant 'camp-operator', mint a token, observe the
        // expanded literal scope list on the wire".
        let store = MemoryBundleStore::with_defaults();
        let grants = vec![ScopeOrBundle::Bundle(BundleName::new("camp-operator"))];
        let expanded = block_on(expand_scopes(&store, &grants)).unwrap();
        assert_eq!(
            expanded,
            vec![
                Scope::CampRead,
                Scope::CampAdmin,
                Scope::BoardRead,
                Scope::BoardWrite,
                Scope::PartyRead,
                Scope::PartyWrite,
                Scope::SubagentSpawn,
                Scope::SubagentControl,
            ]
        );
    }

    #[test]
    fn bundle_edit_propagates_on_next_expand_without_rewriting_grant() {
        // R020-F5 verify: "edit the bundle to remove a scope, re-mint, observe
        // the removal propagates without rewriting the grant."
        let store = MemoryBundleStore::with_defaults();
        let grants = vec![ScopeOrBundle::Bundle(BundleName::new("deploy-admin"))];

        let before = block_on(expand_scopes(&store, &grants)).unwrap();
        assert!(before.contains(&Scope::CloudDestroy));

        // Mutate the bundle: drop CloudDestroy. The grants vector is untouched.
        block_on(store.put(
            &BundleName::new("deploy-admin"),
            &[Scope::CloudRead, Scope::CloudDeploy],
        ))
        .unwrap();

        let after = block_on(expand_scopes(&store, &grants)).unwrap();
        assert!(!after.contains(&Scope::CloudDestroy));
        assert_eq!(after, vec![Scope::CloudRead, Scope::CloudDeploy]);
    }

    #[test]
    fn expand_mixed_scope_and_bundle_dedups_across_both() {
        let store = MemoryBundleStore::with_defaults();
        let grants = vec![
            ScopeOrBundle::Scope(Scope::CloudRead),
            ScopeOrBundle::Bundle(BundleName::new("deploy-admin")),
        ];
        let expanded = block_on(expand_scopes(&store, &grants)).unwrap();
        // CloudRead appears once, in its original position from the literal.
        let count = expanded.iter().filter(|s| **s == Scope::CloudRead).count();
        assert_eq!(count, 1);
        assert_eq!(expanded[0], Scope::CloudRead);
        assert!(expanded.contains(&Scope::CloudDeploy));
        assert!(expanded.contains(&Scope::CloudDestroy));
    }

    #[test]
    fn expand_unknown_bundle_is_typed_error() {
        let store = MemoryBundleStore::new();
        let grants = vec![ScopeOrBundle::Bundle(BundleName::new("does-not-exist"))];
        let err = block_on(expand_scopes(&store, &grants)).unwrap_err();
        match err {
            BundleExpansionError::Unknown(name) => assert_eq!(name.as_str(), "does-not-exist"),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn expanded_scopes_serialize_as_wire_strings_no_bundle_name() {
        // Wire invariant: McpClaims.scope is Vec<Scope>; a bundle name MUST
        // NOT appear in the serialized claim. Vec<Scope> only deserializes
        // literal wire strings, so this property also nails round-trip: the
        // expansion output IS what the wire carries.
        let store = MemoryBundleStore::with_defaults();
        let grants = vec![ScopeOrBundle::Bundle(BundleName::new("camp-operator"))];
        let expanded = block_on(expand_scopes(&store, &grants)).unwrap();

        let claims = McpClaims::new(
            "https://cheers.example",
            "https://kamaji.camp.example",
            PrincipalId::user("alice"),
            1000,
            1300,
            "jti-1",
            expanded,
        );
        let json = serde_json::to_string(&claims).unwrap();
        assert!(
            !json.contains("camp-operator"),
            "bundle name leaked to wire: {json}"
        );
        assert!(
            json.contains(
                r#""scope":["camp:read","camp:admin","board:read","board:write","party:read","party:write","subagent:spawn","subagent:control"]"#
            ),
            "expected literal scope wire list in {json}"
        );
        let back: McpClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(back.scope, claims.scope);
    }

    #[test]
    fn scope_or_bundle_serialize_is_externally_tagged() {
        let s = ScopeOrBundle::Scope(Scope::CloudDeploy);
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, r#"{"scope":"cloud:deploy"}"#);
        let back: ScopeOrBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);

        let b = ScopeOrBundle::Bundle(BundleName::new("camp-operator"));
        let json = serde_json::to_string(&b).unwrap();
        assert_eq!(json, r#"{"bundle":"camp-operator"}"#);
        let back: ScopeOrBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(back, b);
    }

    #[test]
    fn scope_or_bundle_deserialize_rejects_wildcard_inside_scope_variant() {
        // Defense in depth: even if a grant somehow contained a wildcard in the
        // scope slot, deserialization should reject it via Scope's parser.
        let err =
            serde_json::from_str::<ScopeOrBundle>(r#"{"scope":"cloud:*"}"#).unwrap_err();
        assert!(
            err.to_string().contains("wildcard"),
            "expected wildcard rejection: {err}"
        );
    }
}
