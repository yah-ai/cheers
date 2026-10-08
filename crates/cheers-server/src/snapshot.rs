//! The issuer half of the **membership snapshot** (R732-F4; noisetable W235
//! §0.1, §2.4, §5).
//!
//! - [`SnapshotIssuer`] — signs a [`SetSnapshot`] of one resource from live
//!   tuples: [`SchemaRegistry::members`] over the ownership store (sets
//!   flattened, closure folded in, user principals only), with the store's
//!   ownership version as the epoch, carrying the revocation key of the
//!   resource and of every `via` resource ([`OwnershipStore::revocation_key`],
//!   R732-T10).
//! - [`revoke_ownership`] — the one ownership revoke for every writer, the D4
//!   door and in-process writers alike: it revokes the tuple and, when that
//!   was the user's last live direct tuple on the resource, records
//!   [`Revoked::Membership`] at the version the revoke produced, so offline
//!   edges drop the user from snapshots they already hold.
//! - [`revoke_principal_ownership`] — the same for the holder cascade
//!   (account deletion): sweep every direct tuple, then record an entry for
//!   every resource the user held.
//!
//! The edge half is `cheers_verify::SnapshotVerifier`; the wire type and the
//! revocation-mask rule are in [`cheers_core::snapshot`].
//!
//! # A consistent mint without a transaction
//!
//! The closure walk is many reads. Every ownership write advances the
//! store-wide version in its own transaction, so the issuer reads the version,
//! walks, and reads it again: equal reads mean no write landed in between and
//! the members are exactly the rows at that version, which becomes the epoch.
//! Unequal reads retry, up to [`SnapshotIssuer::MINT_ATTEMPTS`], then fail
//! with [`Error::SnapshotContended`]. That is what lets an edge treat two
//! snapshots of a resource at one epoch as identical.
//!
//! @yah:ticket(R734-B6, "SnapshotIssuer::mint lists non-membership relations (a name-claim `allow` row) as SetSnapshot members; RelationDef needs an explicit membership flag")
//! @yah:status(review)
//! @yah:at(2026-10-07T18:57:01Z)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:parent(R734)
//! @yah:severity(high)
//! @yah:next("Reported by noisetable R803 leader (session:38d7c93b), pinned in noisetable web/services/account/tests/namespaces.rs::the_snapshot_lists_a_name_claim_allow_row_only_as_the_non_membership_relation (R803-F5 cleanup). SnapshotIssuer::mint (cheers-server snapshot.rs ~:245) flattens SchemaRegistry::members over EVERY principal row, so non-members leak into a members-only signed artifact.")
//! @yah:next("Tier: Warrior. Fix: RelationDef (cheers-core) gains an explicit membership marker with NO default; every definition site must choose (fail closed: a relation not marked membership is never minted). Mint filters on it beside the is_member_kind filter. AdmissionPolicy floor and admitters must name membership relations; refuse otherwise where the policy is written with schema access.")
//! @yah:handoff("API chosen: required field `pub membership: bool` on cheers-core `RelationDef` (schema.rs ~:66). RelationDef has no Default, so every struct literal must state it or fail to compile. Also mirrored on `ResolvedRelation.membership`, which is the relation's own flag and is not folded through the closure. All 45 cheers literal sites now state `membership: true`, which keeps existing behaviour. No shim.")
//! @yah:handoff("`SchemaRegistry::is_membership(kind, relation)` returns false for an unknown kind or relation, so it fails closed. `SchemaRegistry::validate_admission_policy(kind, &AdmissionPolicy) -> Result<(), PolicyError>` refuses a non-membership floor or admitter with the new variant `PolicyError::NotMembership{kind, relation}` (admission.rs, the existing PolicyError enum). cheers has no policy write path with a schema in reach (set_admission_policy is store-only), so validation runs at mint.")
//! @yah:handoff("Mint (cheers-server snapshot.rs SnapshotIssuer::mint): it adds `.filter(|m| self.schema.is_membership(kind, &m.relation))` beside is_member_kind, and `policy.filter(validate_admission_policy ok)` so an invalid policy is minted as None (closed). `members()` already lists one entry per relation in the closure, so a principal whose strongest relation is non-membership is still minted at the implied membership relation.")
//! @yah:handoff("Docs: edge-verifiable-auth.md §8 Wire now says members list only `RelationDef::membership` relations. knock.md has no SetSnapshot member prose to change.")
//! @yah:handoff("noisetable R803 change list: (1) add `membership: <bool>` to every RelationDef literal; set `allow` and `reserved` to false and real membership relations to true. (2) Flip web/services/account/tests/namespaces.rs::the_snapshot_lists_a_name_claim_allow_row_only_as_the_non_membership_relation so it asserts the allow-only principal is ABSENT from the snapshot. (3) Any AdmissionPolicy whose floor or admitters names a non-membership relation now mints as no policy (closed).")
//! @yah:verify("New tests in cheers-server snapshot.rs (fixture NAMESPACE gains non-membership `allow` and `steward` implies guest): a_non_membership_row_is_never_minted, a_non_membership_relation_still_mints_the_membership_one_it_implies, a_subject_set_member_at_a_membership_relation_is_minted, a_policy_naming_a_non_membership_relation_is_minted_as_none (covers both validate errors and the mint-as-None path).")
//! @yah:verify("cargo test --workspace: 900 pass / 0 fail (baseline 896 plus 4 new; all 4 appear in the log). PG: cheers-sqlx pg-integration --test pg: 28 pass / 0 fail. Uncommitted (git policy defer).")
//! @yah:handoff("Leader re-verified (Glimmerstone, session:ead31b87): cargo test --workspace 900 pass / 0 fail / 4 ignored; cheers-sqlx PG 28 pass / 0 fail. Checked that RelationDef (cheers-core schema.rs:60) derives only Debug/Clone/PartialEq/Eq, with no Default and no serde, so the required `membership: bool` is compile-forced at every definition site and nothing can fall back to a default. ResolvedRelation's ..Default at schema.rs:769 copies d.membership explicitly. Uncommitted (git policy defer).")
//! @yah:verify("cd oss/cheers && cargo test --workspace --no-fail-fast (900/0), then DOCKER_HOST=unix://$HOME/.orbstack/run/docker.sock cargo test -p cheers-sqlx --features pg-integration --test pg (28/0). Both re-run by the leader on 2026-10-07.")

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use cheers_core::{
    Error, Lease, PrincipalId, ResourceRevocationKey, Revoked, SchemaRegistry, SetSnapshot, SnapshotMember,
    StoreError, Subject,
};

use crate::codec::PasetoV4SecretMinter;
use crate::ownership::{OwnershipRow, OwnershipStore, OwnershipTuples};
use crate::revocation::RevocationWriter;

/// Revoke ownership row `id` and record what an offline edge needs to stop
/// counting its holder. Returns the ownership version the revoke produced
/// ([`OwnershipStore::revoke_by_id`]).
///
/// Records `Revoked::Membership { kind, id, user, at_epoch }` iff the row's
/// subject is a **user** principal and, once it is revoked, that user holds no
/// other live direct tuple on the same resource. `at_epoch` is the version the
/// revoke produced, so the entry masks exactly the snapshots minted before the
/// removal. Revoking one of several direct relations (a demotion), a
/// subject-set tuple, or a non-user's tuple records nothing: those reach edges
/// only through a newer snapshot (`cheers_core::snapshot`, "The revocation
/// mask").
///
/// Order is tuple first, then the entry. If the entry write fails the error
/// is returned and the tuple is already gone: online checks see the removal
/// at once, but an offline edge keeps the user until a fresher snapshot
/// reaches it. Re-running the call closes the gap — re-revoking the row is a
/// no-op that returns the current version, and the entry is recorded at that
/// version. A bound at or above the removal is always safe: a snapshot below
/// it that still lists the user through this resource predates the removal.
///
/// A writer that calls [`OwnershipStore::revoke_by_id`] directly records
/// nothing; anything whose resources edges hold snapshots of goes through
/// here. The holder cascade's counterpart is [`revoke_principal_ownership`].
pub async fn revoke_ownership<O, W>(store: &O, revocations: &W, id: &str, now: i64) -> Result<u64, StoreError>
where
    O: OwnershipStore + ?Sized,
    W: RevocationWriter + ?Sized,
{
    let row = store.get(id).await?.ok_or(StoreError::NotFound)?;
    let version = store.revoke_by_id(id, now).await?;
    let Subject::Principal(principal) = &row.subject else {
        return Ok(version);
    };
    if !principal.kind.is_member_kind() {
        return Ok(version);
    }
    let still_direct = store
        .list_for_resource(&row.resource_kind, &row.resource_id)
        .await?
        .iter()
        .any(|r| !r.is_revoked() && r.subject.principal() == Some(principal));
    if !still_direct {
        let entry = Revoked::membership(&row.resource_kind, &row.resource_id, principal.clone(), version);
        revocations.revoke(&entry).await?;
    }
    Ok(version)
}

/// Revoke every live direct tuple `principal` holds — the holder cascade,
/// [`OwnershipStore::revoke_by_principal`], which a deletion runs — and record
/// what offline edges need to stop counting it. Returns the ownership version
/// the sweep produced (the current one when nothing was live).
///
/// For a **user or key** principal it then records `Revoked::Membership {
/// kind, id, principal, at_epoch }` at that version for every resource the user has ever
/// held a direct tuple on ([`OwnershipStore::list_history_for_principal`]) and
/// holds none live on once the sweep is done — after a deletion, all of them.
/// A camp or service principal records nothing: snapshots list users and
/// keys only ([`PrincipalKind::is_member_kind`]).
///
/// Order is tuple first, then the entries, as in [`revoke_ownership`], with
/// the same failure gap and the same cure: re-running the call heals it. That
/// is why the resources come from the history read *after* the sweep rather
/// than from the live rows before it: a re-run finds nothing live, but the
/// history still names every resource, so the entries a failed run missed are
/// recorded at the (current) version. An entry for a resource the user left
/// long ago only has its bound raised, which is safe for the reason
/// [`revoke_ownership`] gives: the user holds no live direct tuple there at
/// that version, so a snapshot below it that lists them through it is stale.
/// A tuple written for the user after the sweep (a concurrent re-grant)
/// leaves its resource unrecorded.
pub async fn revoke_principal_ownership<O, W>(
    store: &O,
    revocations: &W,
    principal: &PrincipalId,
    now: i64,
) -> Result<u64, StoreError>
where
    O: OwnershipStore + ?Sized,
    W: RevocationWriter + ?Sized,
{
    let version = store.revoke_by_principal(principal, now).await?;
    if !principal.kind.is_member_kind() {
        return Ok(version);
    }
    let resource = |r: OwnershipRow| (r.resource_kind, r.resource_id);
    let live: BTreeSet<_> = store.list_for_principal(principal).await?.into_iter().map(resource).collect();
    let held: BTreeSet<_> = store.list_history_for_principal(principal).await?.into_iter().map(resource).collect();
    for (kind, id) in held.difference(&live) {
        revocations.revoke(&Revoked::membership(kind.as_str(), id.as_str(), principal.clone(), version)).await?;
    }
    Ok(version)
}

/// A [`SetSnapshot`] and its signed token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedSetSnapshot {
    pub snapshot: SetSnapshot,
    /// PASETO v4.public under the issuer key, with
    /// [`SetSnapshot::IMPLICIT_ASSERTION`](cheers_core::SignedArtifact).
    pub token: String,
}

/// Mints membership snapshots under the issuer key.
///
/// `kid` must be published in the JWKS with the **issuer** role; edges refuse
/// any other. Like a standing binding, a snapshot has no `exp`, so a kid that
/// has signed snapshots stays published until every one of them is superseded
/// (see `cheers_verify::standing`, "Key rotation rule").
pub struct SnapshotIssuer {
    store: Arc<dyn OwnershipStore>,
    schema: Arc<SchemaRegistry>,
    minter: PasetoV4SecretMinter,
    issuer: String,
    kid: String,
    refresh_after_seconds: i64,
}

impl std::fmt::Debug for SnapshotIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotIssuer")
            .field("issuer", &self.issuer)
            .field("kid", &self.kid)
            .field("refresh_after_seconds", &self.refresh_after_seconds)
            .finish_non_exhaustive()
    }
}

impl SnapshotIssuer {
    /// 7 days, like [`StandingBinder`](crate::StandingBinder). Advisory: how
    /// long until a holder that can reach the issuer fetches a fresher
    /// snapshot. It never bounds how long one is valid.
    pub const DEFAULT_REFRESH_AFTER_SECONDS: i64 = 7 * 24 * 60 * 60;

    /// How many times [`mint`](Self::mint) re-walks when a write lands under
    /// it before giving up with [`Error::SnapshotContended`].
    pub const MINT_ATTEMPTS: usize = 5;

    pub fn new(
        store: impl OwnershipStore + 'static,
        schema: Arc<SchemaRegistry>,
        minter: PasetoV4SecretMinter,
        issuer: impl Into<String>,
        kid: impl Into<String>,
    ) -> Self {
        Self {
            store: Arc::new(store),
            schema,
            minter,
            issuer: issuer.into(),
            kid: kid.into(),
            refresh_after_seconds: Self::DEFAULT_REFRESH_AFTER_SECONDS,
        }
    }

    pub fn with_refresh_after(mut self, seconds: i64) -> Self {
        self.refresh_after_seconds = seconds;
        self
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Per principal holding live direct tuples on `(kind, id)` at `now`: the
    /// lease its entries carry, `Some` only when every such tuple is leased
    /// (the latest-expiring one wins), `None` when any is standing.
    async fn member_leases(&self, kind: &str, id: &str, now: i64) -> Result<BTreeMap<PrincipalId, Option<Lease>>, Error> {
        let mut out: BTreeMap<PrincipalId, Option<Lease>> = BTreeMap::new();
        for row in self.store.list_for_resource(kind, id).await? {
            let Some(p) = row.subject.principal().cloned() else { continue };
            if !row.is_live_at(now) {
                continue;
            }
            let lease = row.lease.map(|l| l.lease);
            out.entry(p)
                .and_modify(|held| {
                    *held = match (*held, lease) {
                        (Some(a), Some(b)) => Some(if b.exp() > a.exp() { b } else { a }),
                        _ => None,
                    }
                })
                .or_insert(lease);
        }
        Ok(out)
    }

    /// Snapshot `(kind, id)`'s members from live tuples and sign it. The
    /// epoch is the ownership version the walk read at (module docs).
    pub async fn mint(&self, kind: &str, id: &str, now: i64) -> Result<SignedSetSnapshot, Error> {
        for _ in 0..Self::MINT_ATTEMPTS {
            let before = self.store.current_version().await?;
            let members = self.schema.members(&OwnershipTuples::at(&*self.store, now), kind, id).await?;
            // The policy is a versioned row too: read inside the bracket.
            let policy = self.store.admission_policy(kind, id).await?;
            // A policy naming a non-membership relation could never be
            // honoured at the edge; mint it as no policy (closed).
            let policy = policy.filter(|p| self.schema.validate_admission_policy(kind, p).is_ok());
            if self.store.current_version().await? != before {
                continue;
            }
            let leases = self.member_leases(kind, id, now).await?;
            let here = [(kind.to_owned(), id.to_owned())];
            let members: Vec<SnapshotMember> = members
                .into_iter()
                .filter(|m| m.principal.kind.is_member_kind())
                // Members only (R734-B6): a non-membership relation (a
                // name-claim `allow`) is never listed. `members` lists every
                // relation in the closure, so an implied membership relation
                // survives even when the strongest one held does not.
                .filter(|m| self.schema.is_membership(kind, &m.relation))
                .map(|m| {
                    let via: Vec<(String, String)> = m.via.into_iter().collect();
                    // Only an entry resting on this resource's tuples alone
                    // can carry their lease; anything also derived elsewhere
                    // stands by that other route.
                    let lease = if via[..] == here[..] { leases.get(&m.principal).copied().flatten() } else { None };
                    SnapshotMember { principal: m.principal, relation: m.relation, via, lease }
                })
                .collect();
            // Keys are immutable once created, so reading them outside the
            // version bracket cannot skew the snapshot.
            let mut resources: BTreeSet<(String, String)> = members.iter().flat_map(|m| m.via.iter().cloned()).collect();
            resources.insert((kind.to_owned(), id.to_owned()));
            let mut keys = Vec::with_capacity(resources.len());
            for (k, i) in resources {
                let key = self.store.revocation_key(&k, &i).await?;
                keys.push(ResourceRevocationKey { kind: k, id: i, key });
            }
            let lease = Lease::new(now, now.saturating_add(self.refresh_after_seconds), None)?;
            let snapshot = SetSnapshot::new(&self.issuer, kind, id, before, members, keys, now, lease).with_policy(policy);
            let token = self.minter.mint_artifact(&snapshot, &self.kid)?;
            return Ok(SignedSetSnapshot { snapshot, token });
        }
        Err(Error::SnapshotContended {
            kind: kind.to_owned(),
            id: id.to_owned(),
            attempts: Self::MINT_ATTEMPTS,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cheers_core::LeaseState;
    use crate::ownership::{Inserted, MemoryOwnershipStore, NewOwnership};
    use crate::revocation::{MemoryRevocationStore, RevocationPublisher, RevocationSnapshot};
    use async_trait::async_trait;
    use cheers_core::{RelationDef, ResourceSchema, ScopeRegistry};
    use cheers_verify::{IssuerTrust, ReplicatedRevocations, SnapshotVerifier, VerifiedSnapshot};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const ISS: &str = "https://c.test";

    /// W235 §2.4's namespace schema.
    const NAMESPACE: ResourceSchema = ResourceSchema {
        kind: "namespace",
        relations: &[
            RelationDef {
                name: "owner",
                membership: true,
                implies: &["admin"],
                scopes: &[],
                grants: &["owner", "admin", "publisher", "member", "guest"],
            },
            RelationDef {
                name: "admin",
                membership: true,
                implies: &["publisher"],
                scopes: &[],
                grants: &["admin", "publisher", "member", "guest"],
            },
            RelationDef { name: "publisher", membership: true, implies: &["member"], scopes: &[], grants: &[] },
            RelationDef { name: "member", membership: true, implies: &["guest"], scopes: &[], grants: &[] },
            RelationDef { name: "guest", membership: true, implies: &[], scopes: &[], grants: &[] },
            // Non-membership relations (R734-B6): a name-claim hold, and one
            // that implies a membership relation.
            RelationDef { name: "allow", membership: false, implies: &[], scopes: &[], grants: &[] },
            RelationDef { name: "steward", membership: false, implies: &["guest"], scopes: &[], grants: &[] },
        ],
        kind_relations: &[],
    };

    fn schema() -> Arc<SchemaRegistry> {
        let scopes = ScopeRegistry::builder().build().unwrap();
        Arc::new(SchemaRegistry::build(&[NAMESPACE], &scopes).unwrap())
    }

    fn ns(who: impl Into<Subject>, id: &str, rel: &str) -> NewOwnership {
        NewOwnership::new(who, "namespace", id, rel, PrincipalId::service("noisetable-account"), None).unwrap()
    }

    fn user(id: &str) -> PrincipalId {
        PrincipalId::user(id)
    }

    /// The institution preset's inheritance: `ed#admin ← museum#admin`,
    /// `ed#guest ← museum#member`.
    async fn institution(store: &MemoryOwnershipStore) {
        store.insert(&ns(Subject::set("namespace", "museum", "admin"), "ed", "admin"), 10).await.unwrap();
        store.insert(&ns(Subject::set("namespace", "museum", "member"), "ed", "guest"), 10).await.unwrap();
    }

    struct Rig {
        store: MemoryOwnershipStore,
        revocations: MemoryRevocationStore,
        issuer: SnapshotIssuer,
        publisher: RevocationPublisher<MemoryRevocationStore>,
        replica: Arc<ReplicatedRevocations>,
        edge: SnapshotVerifier<Arc<ReplicatedRevocations>>,
    }

    impl Rig {
        /// Publish the issuer's current revocation set to the edge's replica.
        async fn gossip(&self, now: i64) {
            let set = self.publisher.current(now).await.unwrap();
            self.replica.adopt(&set.token).await.unwrap();
        }
    }

    fn rig() -> Rig {
        let (minter, verifier) = PasetoV4SecretMinter::generate().unwrap();
        let store = MemoryOwnershipStore::new();
        let revocations = MemoryRevocationStore::new();
        let key: &[u8; 64] = minter.secret_key_bytes().try_into().unwrap();
        let same_key = PasetoV4SecretMinter::from_secret_key(key).unwrap();
        let issuer = SnapshotIssuer::new(store.clone(), schema(), minter, ISS, "k1").with_refresh_after(60);
        let publisher = RevocationPublisher::new(revocations.clone(), Arc::new(store.clone()), same_key, ISS, "k1");
        let trust = IssuerTrust::pinned(ISS, verifier);
        let replica = Arc::new(ReplicatedRevocations::new(trust.clone()));
        Rig {
            edge: SnapshotVerifier::new(trust, replica.clone()),
            store,
            revocations,
            issuer,
            publisher,
            replica,
        }
    }

    fn admitted(v: &VerifiedSnapshot) -> Vec<String> {
        v.admitted.iter().map(|m| format!("{}#{}", m.principal.id, m.relation)).collect()
    }

    #[test]
    fn mint_lists_users_closure_expanded_with_via_at_the_store_version() {
        pollster::block_on(async {
            let r = rig();
            institution(&r.store).await;
            r.store.insert(&ns(user("alice"), "museum", "member"), 100).await.unwrap();
            r.store.insert(&ns(user("carol"), "ed", "admin"), 100).await.unwrap();
            // A service principal is no member of the snapshot.
            r.store.insert(&ns(PrincipalId::service("bot"), "ed", "member"), 100).await.unwrap();
            let version = r.store.current_version().await.unwrap();

            let s = r.issuer.mint("namespace", "ed", 1_000).await.unwrap();
            assert_eq!(s.snapshot.epoch, version);
            assert_eq!((s.snapshot.iat, s.snapshot.lease.refresh_after()), (1_000, 1_060));
            let listed: Vec<_> = s
                .snapshot
                .members
                .iter()
                .map(|m| (m.principal.id.as_str(), m.relation.as_str(), m.via.clone()))
                .collect();
            let ed = || vec![("namespace".to_owned(), "ed".to_owned())];
            let museum = || vec![("namespace".to_owned(), "museum".to_owned())];
            assert_eq!(
                listed,
                vec![
                    ("alice", "guest", museum()),
                    ("carol", "admin", ed()),
                    ("carol", "guest", ed()),
                    ("carol", "member", ed()),
                    ("carol", "publisher", ed()),
                ]
            );
            // The resource's own key and every via resource's, from the store.
            let carried: Vec<_> =
                s.snapshot.revocation_keys.iter().map(|k| (k.kind.as_str(), k.id.as_str(), k.key.clone())).collect();
            assert_eq!(
                carried,
                vec![
                    ("namespace", "ed", r.store.revocation_key("namespace", "ed").await.unwrap()),
                    ("namespace", "museum", r.store.revocation_key("namespace", "museum").await.unwrap()),
                ]
            );
            let ok = r.edge.verify_snapshot_at(&s.token, 1_000).await.unwrap();
            assert!(ok.holds(&PrincipalId::user("alice"), "guest"));
            assert!(!ok.holds(&PrincipalId::user("alice"), "member"));
            assert_eq!(ok.lease, LeaseState::Current);
        });
    }

    fn listed(s: &SignedSetSnapshot) -> Vec<String> {
        s.snapshot.members.iter().map(|m| format!("{}#{}", m.principal.id, m.relation)).collect()
    }

    #[test]
    fn a_non_membership_row_is_never_minted() {
        pollster::block_on(async {
            let r = rig();
            r.store.insert(&ns(user("alice"), "ed", "member"), 100).await.unwrap();
            r.store.insert(&ns(user("bob"), "ed", "allow"), 100).await.unwrap();
            let s = r.issuer.mint("namespace", "ed", 1_000).await.unwrap();
            assert_eq!(listed(&s), vec!["alice#guest", "alice#member"]);
        });
    }

    #[test]
    fn a_non_membership_relation_still_mints_the_membership_one_it_implies() {
        pollster::block_on(async {
            let r = rig();
            r.store.insert(&ns(user("sam"), "ed", "steward"), 100).await.unwrap();
            let s = r.issuer.mint("namespace", "ed", 1_000).await.unwrap();
            assert_eq!(listed(&s), vec!["sam#guest"]);
        });
    }

    #[test]
    fn a_subject_set_member_at_a_membership_relation_is_minted() {
        pollster::block_on(async {
            let r = rig();
            institution(&r.store).await;
            r.store.insert(&ns(user("alice"), "museum", "member"), 100).await.unwrap();
            // A non-membership hold on the parent confers nothing on ed.
            r.store.insert(&ns(user("bob"), "museum", "allow"), 100).await.unwrap();
            let s = r.issuer.mint("namespace", "ed", 1_000).await.unwrap();
            assert_eq!(listed(&s), vec!["alice#guest"]);
        });
    }

    #[test]
    fn a_policy_naming_a_non_membership_relation_is_minted_as_none() {
        use cheers_core::{AdmissionMode, AdmissionPolicy, PolicyError};
        let reg = schema();
        let ok = AdmissionPolicy::new(AdmissionMode::Knock, "guest").with_admitters(["admin"]);
        assert_eq!(reg.validate_admission_policy("namespace", &ok), Ok(()));
        let bad_floor = AdmissionPolicy::new(AdmissionMode::Open, "allow");
        let bad_admitter = AdmissionPolicy::new(AdmissionMode::Knock, "guest").with_admitters(["admin", "steward"]);
        assert_eq!(
            reg.validate_admission_policy("namespace", &bad_floor),
            Err(PolicyError::NotMembership { kind: "namespace".into(), relation: "allow".into() })
        );
        assert_eq!(
            reg.validate_admission_policy("namespace", &bad_admitter),
            Err(PolicyError::NotMembership { kind: "namespace".into(), relation: "steward".into() })
        );
        pollster::block_on(async {
            let r = rig();
            for (p, want) in [(&bad_floor, None), (&bad_admitter, None), (&ok, Some(&ok))] {
                r.store.set_admission_policy("namespace", "ed", Some(p), 1_000).await.unwrap();
                let s = r.issuer.mint("namespace", "ed", 1_000).await.unwrap();
                assert_eq!(s.snapshot.policy.as_ref(), want);
            }
        });
    }

    #[test]
    fn the_policy_row_is_minted_and_its_change_advances_the_epoch() {
        use cheers_core::{AdmissionMode, AdmissionPolicy};
        pollster::block_on(async {
            let r = rig();
            institution(&r.store).await;
            let bare = r.issuer.mint("namespace", "ed", 1_000).await.unwrap();
            assert_eq!(bare.snapshot.policy, None);
            let open = AdmissionPolicy::new(AdmissionMode::Open, "guest");
            let v = r.store.set_admission_policy("namespace", "ed", Some(&open), 1_000).await.unwrap();
            assert!(v > bare.snapshot.epoch);
            let s = r.issuer.mint("namespace", "ed", 1_000).await.unwrap();
            assert_eq!((s.snapshot.epoch, s.snapshot.policy.as_ref()), (v, Some(&open)));
            let ok = r.edge.verify_snapshot_at(&s.token, 1_000).await.unwrap();
            assert_eq!(ok.admission_policy(), Some(&open));
            // Deleting the row is a change too, and reads as no policy.
            let v2 = r.store.set_admission_policy("namespace", "ed", None, 1_000).await.unwrap();
            let s = r.issuer.mint("namespace", "ed", 1_000).await.unwrap();
            assert_eq!((s.snapshot.epoch, s.snapshot.policy), (v2, None));
            assert!(v2 > v);
        });
    }

    #[test]
    fn a_key_principal_is_minted_held_and_revoked_like_a_user() {
        pollster::block_on(async {
            let r = rig();
            institution(&r.store).await;
            let k = PrincipalId::from_public_key(&[0x4b; 32]);
            let tuple = r.store.insert(&ns(k.clone(), "ed", "member"), 100).await.unwrap();
            let held = r.issuer.mint("namespace", "ed", 1_000).await.unwrap();
            assert!(held.snapshot.lists(&k, "member"));
            let ok = r.edge.verify_snapshot_at(&held.token, 1_000).await.unwrap();
            assert!(ok.holds(&k, "member") && ok.holds(&k, "guest"));
            assert!(!ok.holds(&PrincipalId::user(k.id.clone()), "member"));

            // Losing the key's last direct tuple records a membership entry
            // for the key, which masks the held snapshot at the edge.
            let v = revoke_ownership(&r.store, &r.revocations, &tuple.row.id, 2_000).await.unwrap();
            assert!(r.revocations.snapshot().await.unwrap().revoked.contains(&Revoked::membership("namespace", "ed", k.clone(), v)));
            r.gossip(2_000).await;
            let ok = r.edge.verify_snapshot_at(&held.token, 2_000).await.unwrap();
            assert!(!ok.holds(&k, "member"));
        });
    }

    #[test]
    fn removal_from_the_parent_drops_an_inherited_member_and_keeps_a_direct_one() {
        pollster::block_on(async {
            let r = rig();
            institution(&r.store).await;
            let alice = r.store.insert(&ns(user("alice"), "museum", "member"), 100).await.unwrap();
            let bob = r.store.insert(&ns(user("bob"), "museum", "member"), 100).await.unwrap();
            r.store.insert(&ns(user("bob"), "ed", "member"), 100).await.unwrap();
            let held = r.issuer.mint("namespace", "ed", 1_000).await.unwrap();
            let ok = r.edge.verify_snapshot_at(&held.token, 1_000).await.unwrap();
            assert_eq!(admitted(&ok), ["alice#guest", "bob#guest", "bob#member"]);

            // Both leave the museum. Each was their last direct museum tuple.
            let va = revoke_ownership(&r.store, &r.revocations, &alice.row.id, 2_000).await.unwrap();
            let vb = revoke_ownership(&r.store, &r.revocations, &bob.row.id, 2_000).await.unwrap();
            assert!(va > held.snapshot.epoch && vb > va);
            r.gossip(2_000).await;

            // The held (older) snapshot: alice was guest only via the museum
            // and is dropped; bob is still a direct member of ed.
            let ok = r.edge.verify_snapshot_at(&held.token, 2_000).await.unwrap();
            assert_eq!(admitted(&ok), ["bob#guest", "bob#member"]);
            assert_eq!(ok.snapshot.members.len(), 3, "the signed list itself is untouched");

            // A fresh snapshot no longer lists alice and supersedes the held one.
            let fresh = r.issuer.mint("namespace", "ed", 2_000).await.unwrap();
            assert_eq!(fresh.snapshot.epoch, vb);
            assert_eq!(admitted(&r.edge.verify_snapshot_at(&fresh.token, 2_000).await.unwrap()), [
                "bob#guest",
                "bob#member"
            ]);
            assert!(r.edge.verify_snapshot_at(&held.token, 2_000).await.is_err());

            // Re-added later: the old entry stays at va, the new snapshot is
            // above it, so alice is admitted again.
            r.store.insert(&ns(user("alice"), "museum", "member"), 3_000).await.unwrap();
            let readded = r.issuer.mint("namespace", "ed", 3_000).await.unwrap();
            let ok = r.edge.verify_snapshot_at(&readded.token, 3_000).await.unwrap();
            assert!(ok.holds(&PrincipalId::user("alice"), "guest"));
        });
    }

    #[test]
    fn recording_fires_only_when_the_last_direct_tuple_goes() {
        pollster::block_on(async {
            let r = rig();
            institution(&r.store).await;
            let owner = r.store.insert(&ns(user("carol"), "ed", "owner"), 100).await.unwrap();
            let member = r.store.insert(&ns(user("carol"), "ed", "member"), 100).await.unwrap();
            let bot = r.store.insert(&ns(PrincipalId::service("bot"), "ed", "member"), 100).await.unwrap();
            let set_rows = r.store.list_for_subject_set("namespace", "museum").await.unwrap();
            let epoch = || async { r.revocations.snapshot().await.unwrap() };

            // Demotion: carol keeps a direct tuple on ed, so nothing is recorded.
            revoke_ownership(&r.store, &r.revocations, &owner.row.id, 200).await.unwrap();
            assert!(epoch().await.revoked.is_empty());
            // A subject-set tuple and a service's tuple record nothing.
            revoke_ownership(&r.store, &r.revocations, &set_rows[0].id, 200).await.unwrap();
            revoke_ownership(&r.store, &r.revocations, &bot.row.id, 200).await.unwrap();
            assert!(epoch().await.revoked.is_empty());

            // Her last direct tuple on ed: recorded at the version it produced.
            let v = revoke_ownership(&r.store, &r.revocations, &member.row.id, 200).await.unwrap();
            assert_eq!(epoch().await.revoked, vec![Revoked::membership("namespace", "ed", PrincipalId::user("carol"), v)]);

            // Re-running is a safe no-op on the tuple and records at the
            // current version (here unchanged).
            assert_eq!(revoke_ownership(&r.store, &r.revocations, &member.row.id, 300).await.unwrap(), v);
            assert!(matches!(
                revoke_ownership(&r.store, &r.revocations, "ghost", 300).await,
                Err(StoreError::NotFound)
            ));
        });
    }

    /// R732-F4 residual: the deletion cascade. A user with tuples on two
    /// resources is deleted; an offline edge holding pre-deletion snapshots of
    /// both drops them from each, and nobody else.
    #[test]
    fn deleting_a_user_drops_them_from_every_held_snapshot() {
        pollster::block_on(async {
            let r = rig();
            institution(&r.store).await;
            // dana: a direct member of the band, and a guest of ed through the museum.
            r.store.insert(&ns(user("dana"), "band", "member"), 100).await.unwrap();
            r.store.insert(&ns(user("dana"), "museum", "member"), 100).await.unwrap();
            r.store.insert(&ns(user("erin"), "band", "member"), 100).await.unwrap();
            r.store.insert(&ns(user("erin"), "museum", "member"), 100).await.unwrap();
            let band = r.issuer.mint("namespace", "band", 1_000).await.unwrap();
            let ed = r.issuer.mint("namespace", "ed", 1_000).await.unwrap();
            for held in [&band, &ed] {
                let ok = r.edge.verify_snapshot_at(&held.token, 1_000).await.unwrap();
                assert!(admitted(&ok).iter().any(|m| m.starts_with("dana#")));
            }

            let v = revoke_principal_ownership(&r.store, &r.revocations, &user("dana"), 2_000).await.unwrap();
            assert!(r.store.list_for_principal(&user("dana")).await.unwrap().is_empty());
            let mut recorded = r.revocations.snapshot().await.unwrap().revoked;
            recorded.sort_by(|a, b| a.identity().cmp(&b.identity()));
            assert_eq!(
                recorded,
                vec![
                    Revoked::membership("namespace", "band", PrincipalId::user("dana"), v),
                    Revoked::membership("namespace", "museum", PrincipalId::user("dana"), v),
                ]
            );
            r.gossip(2_000).await;

            // Offline, the held snapshots still verify, without dana.
            assert_eq!(admitted(&r.edge.verify_snapshot_at(&band.token, 2_000).await.unwrap()), ["erin#guest", "erin#member"]);
            assert_eq!(admitted(&r.edge.verify_snapshot_at(&ed.token, 2_000).await.unwrap()), ["erin#guest"]);

            // A camp or service principal's cascade records nothing.
            r.store.insert(&ns(PrincipalId::service("bot"), "band", "admin"), 3_000).await.unwrap();
            revoke_principal_ownership(&r.store, &r.revocations, &PrincipalId::service("bot"), 3_000).await.unwrap();
            assert_eq!(r.revocations.snapshot().await.unwrap().revoked.len(), 2);
        });
    }

    /// A revocation log that refuses its first `failures` writes.
    struct Flaky {
        inner: MemoryRevocationStore,
        failures: AtomicUsize,
    }

    #[async_trait]
    impl RevocationWriter for Flaky {
        async fn revoke(&self, entry: &Revoked) -> Result<(), StoreError> {
            if self.failures.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1)).is_ok() {
                return Err(StoreError::Backend("revocation log unavailable".into()));
            }
            self.inner.revoke(entry).await
        }
        async fn snapshot(&self) -> Result<RevocationSnapshot, StoreError> {
            self.inner.snapshot().await
        }
    }

    #[test]
    fn a_failed_cascade_recording_is_healed_by_re_running_it() {
        pollster::block_on(async {
            let store = MemoryOwnershipStore::new();
            store.insert(&ns(user("dana"), "band", "member"), 100).await.unwrap();
            store.insert(&ns(user("dana"), "ed", "admin"), 100).await.unwrap();
            let log = Flaky { inner: MemoryRevocationStore::new(), failures: AtomicUsize::new(1) };

            // The sweep lands, the first entry write fails: an error, rows gone,
            // nothing recorded.
            assert!(revoke_principal_ownership(&store, &log, &user("dana"), 2_000).await.is_err());
            assert!(store.list_for_principal(&user("dana")).await.unwrap().is_empty());
            assert!(log.snapshot().await.unwrap().revoked.is_empty());

            // Nothing is live any more, yet the re-run records both resources.
            let v = revoke_principal_ownership(&store, &log, &user("dana"), 3_000).await.unwrap();
            assert_eq!(v, store.current_version().await.unwrap());
            let mut recorded = log.snapshot().await.unwrap().revoked;
            recorded.sort_by(|a, b| a.identity().cmp(&b.identity()));
            assert_eq!(
                recorded,
                vec![
                    Revoked::membership("namespace", "band", PrincipalId::user("dana"), v),
                    Revoked::membership("namespace", "ed", PrincipalId::user("dana"), v),
                ]
            );
        });
    }

    /// An ownership store a "concurrent writer" writes to while the issuer is
    /// mid-walk, `writes` times.
    struct Racing {
        inner: MemoryOwnershipStore,
        writes: AtomicUsize,
    }

    #[async_trait]
    impl OwnershipStore for Racing {
        async fn insert(&self, o: &NewOwnership, now: i64) -> Result<Inserted, StoreError> {
            self.inner.insert(o, now).await
        }
        async fn get(&self, id: &str) -> Result<Option<OwnershipRow>, StoreError> {
            self.inner.get(id).await
        }
        async fn revoke_by_id(&self, id: &str, now: i64) -> Result<u64, StoreError> {
            self.inner.revoke_by_id(id, now).await
        }
        async fn revoke_by_principal(&self, p: &PrincipalId, now: i64) -> Result<u64, StoreError> {
            self.inner.revoke_by_principal(p, now).await
        }
        async fn list_history_for_principal(&self, p: &PrincipalId) -> Result<Vec<OwnershipRow>, StoreError> {
            self.inner.list_history_for_principal(p).await
        }
        async fn current_version(&self) -> Result<u64, StoreError> {
            self.inner.current_version().await
        }
        async fn list_for_principal(&self, p: &PrincipalId) -> Result<Vec<OwnershipRow>, StoreError> {
            self.inner.list_for_principal(p).await
        }
        async fn list_for_resource(&self, kind: &str, id: &str) -> Result<Vec<OwnershipRow>, StoreError> {
            let rows = self.inner.list_for_resource(kind, id).await;
            if self.writes.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1)).is_ok() {
                let n = self.writes.load(Ordering::SeqCst);
                self.inner.insert(&ns(user(&format!("late-{n}")), "ed", "member"), 500).await?;
            }
            rows
        }
        async fn list_for_subject_set(&self, kind: &str, id: &str) -> Result<Vec<OwnershipRow>, StoreError> {
            self.inner.list_for_subject_set(kind, id).await
        }
        async fn list_for_kind(&self, kind: &str) -> Result<Vec<OwnershipRow>, StoreError> {
            self.inner.list_for_kind(kind).await
        }
        async fn revocation_key(&self, kind: &str, id: &str) -> Result<cheers_core::RevocationKey, StoreError> {
            self.inner.revocation_key(kind, id).await
        }
        async fn admission_policy(&self, kind: &str, id: &str) -> Result<Option<cheers_core::AdmissionPolicy>, StoreError> {
            self.inner.admission_policy(kind, id).await
        }
        async fn set_admission_policy(
            &self,
            kind: &str,
            id: &str,
            policy: Option<&cheers_core::AdmissionPolicy>,
            now: i64,
        ) -> Result<u64, StoreError> {
            self.inner.set_admission_policy(kind, id, policy, now).await
        }
    }

    fn racing_issuer(writes: usize) -> (MemoryOwnershipStore, SnapshotIssuer) {
        let inner = MemoryOwnershipStore::new();
        let (minter, _) = PasetoV4SecretMinter::generate().unwrap();
        let store = Racing { inner: inner.clone(), writes: AtomicUsize::new(writes) };
        (inner, SnapshotIssuer::new(store, schema(), minter, ISS, "k1"))
    }

    #[test]
    fn a_write_under_the_walk_retries_and_mints_the_later_state() {
        pollster::block_on(async {
            let (store, issuer) = racing_issuer(2);
            store.insert(&ns(user("alice"), "ed", "member"), 100).await.unwrap();
            let s = issuer.mint("namespace", "ed", 1_000).await.unwrap();
            // Two walks were interrupted; the third saw both late writes.
            assert_eq!(s.snapshot.epoch, store.current_version().await.unwrap());
            let users: Vec<_> = s.snapshot.members.iter().map(|m| m.principal.id.as_str()).collect();
            assert!(users.contains(&"late-0") && users.contains(&"late-1"), "{users:?}");
        });
    }

    #[test]
    fn a_walk_that_never_settles_is_refused() {
        pollster::block_on(async {
            let (store, issuer) = racing_issuer(usize::MAX);
            store.insert(&ns(user("alice"), "ed", "member"), 100).await.unwrap();
            match issuer.mint("namespace", "ed", 1_000).await {
                Err(Error::SnapshotContended { attempts, .. }) => assert_eq!(attempts, SnapshotIssuer::MINT_ATTEMPTS),
                other => panic!("expected SnapshotContended, got {other:?}"),
            }
        });
    }
}
