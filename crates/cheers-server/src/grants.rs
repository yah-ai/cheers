//! Grant persistence — what scope-or-bundle entries a principal holds against
//! a given audience.
//!
//! See `.yah/docs/working/mcp-auth-and-ownership.md` §Mint flows: the mint
//! path looks up grants by `(principal, aud)` and rejects when the list is
//! empty — composition rule (5), aud-scoping is mandatory.
//!
//! The trait returns mixed [`ScopeOrBundle`] entries that ride into
//! [`expand_scopes`](crate::bundles::expand_scopes) verbatim. cheers' own impl,
//! [`SchemaGrantStore`], is a derived view of the ownership table (R731 §D2):
//! everything a principal holds — its live tuples plus those its subject sets
//! confer ([`SchemaRegistry::held_by`], R732-F2) — expanded through the
//! [`SchemaRegistry`] closure, filtered to the scopes valid at `aud`.
//! Hand-coded impls (noisetable's `PublishGrants`) keep the trait until they
//! migrate.
//!
//! @yah:relay(R731, "Product scopes and authorization — scope registry, relationship schema, machine plane, live grants")
//! @yah:at(2026-10-06T22:41:29Z)
//! @yah:status(open)
//! @yah:next("Plan of record: .yah/docs/working/product-scopes-and-authorization.md. Diligence passed 2026-10-06; operator decided D3 = token exchange (no self-signing for now) and D4 = the right to grant is a relationship.")
//! @yah:next("Wire-shape changes here (Scope type, JWK fields, ownership columns) are coordinated with the yah-side kamaji consumer relays R426/R427/R428 (yah camp) — flag them in every handoff.")
//! @yah:next("First consumer is noisetable (separate camp): its admin-plane, token-migration and R795-T8 work is filed on the noisetable board and waits on this relay.")
//! @yah:next("Supersedes the R020 gotcha that ownership:write and granted_by are service-only; D4 removes both.")
//! @arch:see(.yah/docs/working/product-scopes-and-authorization.md)

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use cheers_core::{Lookup, PrincipalId, SchemaRegistry, ScopeRegistry, StoreError};

use crate::bundles::ScopeOrBundle;
use crate::ownership::{OwnershipStore, OwnershipTuples};

/// Persistence for the grant table.
///
/// One method only at the moment — mint-time lookup. Grant *writes* are
/// ownership-tuple writes; the right to write one is
/// [`SchemaRegistry::may_grant`].
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

/// [`GrantStore`] derived from the ownership table through the schema.
///
/// The principal's holdings are [`SchemaRegistry::held_by`]: its direct live
/// tuples and every tuple a subject set it belongs to confers, within the hop
/// bound. Holdings whose kind has no schema are ignored (camp `owns` rows still
/// feed the owns claim); an undeclared relation on a known kind is skipped
/// with a warning. There is no direct-scope escape hatch: a scope is held only
/// because a relation unlocks it.
pub struct SchemaGrantStore<O> {
    ownership: O,
    schema: Arc<SchemaRegistry>,
    scopes: Arc<ScopeRegistry>,
}

impl<O: OwnershipStore> SchemaGrantStore<O> {
    pub fn new(ownership: O, schema: Arc<SchemaRegistry>, scopes: Arc<ScopeRegistry>) -> Self {
        Self { ownership, schema, scopes }
    }
}

#[async_trait]
impl<O: OwnershipStore> GrantStore for SchemaGrantStore<O> {
    async fn list_for(
        &self,
        principal: &PrincipalId,
        aud: &str,
    ) -> Result<Vec<ScopeOrBundle>, StoreError> {
        let held = self.schema.held_by(&OwnershipTuples::at(&self.ownership, crate::revocation::now_unix()), principal).await?;
        let mut out = BTreeSet::new();
        for (kind, id, relation) in held.iter() {
            match self.schema.lookup(kind, id, relation) {
                Lookup::NoSchema => {}
                Lookup::UnknownRelation => tracing::warn!(
                    %principal,
                    kind,
                    id,
                    relation,
                    "ownership tuple names a relation the schema does not declare; skipped"
                ),
                Lookup::Resolved(res) => out.extend(
                    res.scopes.iter().filter(|s| self.scopes.is_valid_at(s, aud)).cloned(),
                ),
            }
        }
        Ok(out.into_iter().map(ScopeOrBundle::Scope).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ownership::{MemoryOwnershipStore, NewOwnership};
    use cheers_core::{
        scopes, RelationDef, ResourceSchema, Scope, Subject, KIND_RESOURCE,
    };
    use pollster::block_on;

    scopes! {
        DOC_READ = "doc:read" { description: "read", audiences: ["https://a", "https://b"] };
        DOC_EDIT = "doc:edit" { description: "edit", audiences: ["https://a"] };
    }

    const DOC: ResourceSchema = ResourceSchema {
        kind: "doc",
        relations: &[
            RelationDef { name: "reader", membership: true, implies: &[], scopes: &[DOC_READ], grants: &[] },
            RelationDef { name: "editor", membership: true, implies: &["reader"], scopes: &[DOC_EDIT], grants: &[] },
            RelationDef { name: "admin", membership: true, implies: &[], scopes: &[], grants: &["reader"] },
        ],
        kind_relations: &[RelationDef {
            name: "auditor",
            membership: true,
            implies: &[],
            scopes: &[DOC_READ],
            grants: &[],
        }],
    };

    fn store() -> SchemaGrantStore<MemoryOwnershipStore> {
        let scopes = Arc::new(ScopeRegistry::builder().with(DEFS).build().unwrap());
        let schema = Arc::new(SchemaRegistry::build(&[DOC], &scopes).unwrap());
        SchemaGrantStore::new(MemoryOwnershipStore::new(), schema, scopes)
    }

    fn seed(s: &SchemaGrantStore<MemoryOwnershipStore>, p: &PrincipalId, kind: &str, id: &str, rel: &str) -> String {
        seed_subject(s, p.clone().into(), kind, id, rel)
    }

    fn seed_subject(s: &SchemaGrantStore<MemoryOwnershipStore>, who: Subject, kind: &str, id: &str, rel: &str) -> String {
        let n = NewOwnership::new(who, kind, id, rel, PrincipalId::service("seed"), None).unwrap();
        block_on(s.ownership.insert(&n, 1)).unwrap().row.id
    }

    fn scopes_of(s: &SchemaGrantStore<MemoryOwnershipStore>, p: &PrincipalId, aud: &str) -> Vec<Scope> {
        block_on(s.list_for(p, aud))
            .unwrap()
            .into_iter()
            .map(|e| match e {
                ScopeOrBundle::Scope(s) => s,
                other => panic!("schema store yields scopes only: {other:?}"),
            })
            .collect()
    }

    #[test]
    fn no_rows_yields_empty_list() {
        let s = store();
        assert!(scopes_of(&s, &PrincipalId::user("u1"), "https://a").is_empty());
    }

    #[test]
    fn closure_unlocks_implied_scopes_and_aud_filters() {
        let s = store();
        let u = PrincipalId::user("alice");
        seed(&s, &u, "doc", "d1", "editor");
        assert_eq!(scopes_of(&s, &u, "https://a"), vec![DOC_EDIT, DOC_READ]);
        assert_eq!(scopes_of(&s, &u, "https://b"), vec![DOC_READ], "doc:edit is aud-bound");
    }

    #[test]
    fn relation_without_scopes_confers_none() {
        let s = store();
        let u = PrincipalId::user("alice");
        seed(&s, &u, "doc", "d1", "admin");
        assert!(scopes_of(&s, &u, "https://a").is_empty(), "admin grants reader but does not imply it");
    }

    #[test]
    fn unknown_kind_and_relation_are_ignored_and_revoked_rows_confer_nothing() {
        let s = store();
        let u = PrincipalId::user("alice");
        seed(&s, &u, "service", "svc", "owns");
        seed(&s, &u, "doc", "d1", "bogus");
        let id = seed(&s, &u, "doc", "d1", "reader");
        assert_eq!(scopes_of(&s, &u, "https://a"), vec![DOC_READ]);
        block_on(s.ownership.revoke_by_id(&id, 2)).unwrap();
        assert!(scopes_of(&s, &u, "https://a").is_empty());
    }

    #[test]
    fn kind_level_tuple_unlocks_its_scopes() {
        let s = store();
        let u = PrincipalId::service("auditor");
        seed(&s, &u, KIND_RESOURCE, "doc", "auditor");
        assert_eq!(scopes_of(&s, &u, "https://a"), vec![DOC_READ]);
    }

    #[test]
    fn set_tuples_confer_derived_grants_at_mint() {
        let s = store();
        let alice = PrincipalId::user("alice");
        // doc/d1#editor ← team/t1#member ← team/org#member ← alice
        let set_row = seed_subject(&s, Subject::set("team", "t1", "member"), "doc", "d1", "editor");
        seed_subject(&s, Subject::set("team", "org", "member"), "team", "t1", "member");
        assert!(scopes_of(&s, &alice, "https://a").is_empty(), "not a member yet");
        seed(&s, &alice, "team", "org", "member");
        assert_eq!(scopes_of(&s, &alice, "https://a"), vec![DOC_EDIT, DOC_READ]);
        assert_eq!(scopes_of(&s, &alice, "https://b"), vec![DOC_READ]);
        assert!(scopes_of(&s, &PrincipalId::user("bob"), "https://a").is_empty());
        // Revoking the set tuple ends what it conferred.
        block_on(s.ownership.revoke_by_id(&set_row, 2)).unwrap();
        assert!(scopes_of(&s, &alice, "https://a").is_empty());
    }
}
