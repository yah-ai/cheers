//! Relationship schema — per resource kind, the relations a principal can
//! hold, what each implies, the scopes each unlocks, and which relations a
//! holder may grant and revoke on the same resource (R731 §D2, §D4).
//!
//! Products declare [`ResourceSchema`]s as const data beside their
//! [`scopes!`](crate::scopes) set; the deployment builds one
//! [`SchemaRegistry`] at startup against its [`ScopeRegistry`]. The build
//! refuses a bad schema (unknown target, cycle, unregistered scope,
//! duplicate) and precomputes each relation's implies-closure, so the mint
//! path and the authority check are plain lookups.
//!
//! Nothing is implied unless declared: `admin` does not unlock `read`'s
//! scopes unless `admin` lists `read` in `implies`. The closure carries BOTH
//! scopes and grant rights — a holder of `admin` where `admin` implies
//! `triager` gets `triager`'s scopes and may grant what `triager` may grant.
//!
//! Kind-level relations (the yubaba provisioner case) are tuples on the
//! reserved resource kind [`KIND_RESOURCE`] with `resource_id` = the kind name,
//! e.g. `kind/service#provisioner`. A kind relation's grants apply to every
//! resource of that kind; its scopes unlock as usual.
//!
//! A tuple's holder may be a **subject set** ([`Subject::Set`]): everyone who
//! holds `kind/id#relation`, through the implies-closure, holds the tuple's
//! relation (noisetable W235 §2.1). The set-aware checks read tuples through
//! a [`TupleSource`] and follow sets for at most [`MAX_SET_HOPS`] hops with a
//! visited set, so cycles terminate and the bound refuses rather than errs
//! (W235 §3 `effective(P, resource, rel)`). There are two walks over the same
//! rule, and they agree by construction (a test cross-checks them):
//!
//! - **Down**, from a resource toward principals: [`SchemaRegistry::holds`],
//!   [`may_grant`](SchemaRegistry::may_grant) and
//!   [`members`](SchemaRegistry::members) — the door's point checks and the
//!   membership enumeration.
//! - **Up**, from a principal's direct tuples toward the resources sets
//!   confer: [`SchemaRegistry::held_by`] — mint-time derivation of everything
//!   one principal holds.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::admission::{AdmissionPolicy, PolicyError};
use crate::principal::PrincipalId;
use crate::scope::{Scope, ScopeRegistry};
use crate::store::StoreError;

/// The reserved `resource_kind` kind-level tuples live under.
pub const KIND_RESOURCE: &str = "kind";

/// How many subject-set hops a check follows (noisetable W235 §3: depth ≤ 4).
/// A direct tuple is hop 0; `issue/x#reader ← team/t#member` held through a
/// direct `team/t#member` is hop 1. A holding reachable only past the bound is
/// **not held** — never an error. Implies steps are not hops: the closure is
/// precomputed at [`SchemaRegistry::build`].
pub const MAX_SET_HOPS: usize = 4;

/// One relation on a resource kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationDef {
    pub name: &'static str,
    /// Whether holding this relation makes the holder a **member** of the
    /// resource (R734-B6). Required, with no default: a relation that is not
    /// marked membership (a name-claim `allow`, a `reserved` hold) is never
    /// listed in a minted [`SetSnapshot`](crate::SetSnapshot), so forgetting
    /// to decide fails closed instead of leaking a non-member onto the edge.
    pub membership: bool,
    /// Relations (in the same list) a holder of this one also holds.
    pub implies: &'static [&'static str],
    /// Scopes this relation unlocks at mint.
    pub scopes: &'static [Scope],
    /// Relations on the same resource a holder may grant and revoke. For a
    /// kind relation these name the kind's per-resource `relations`.
    pub grants: &'static [&'static str],
}

/// A product's declaration for one resource kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceSchema {
    pub kind: &'static str,
    pub relations: &'static [RelationDef],
    /// Relations held on the kind itself (`kind/<kind>#<name>`).
    pub kind_relations: &'static [RelationDef],
}

/// A schema [`SchemaRegistry::build`] refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SchemaError {
    #[error("resource kind '{0}' is reserved for kind-level relations")]
    ReservedKind(String),
    #[error("resource kind '{0}' is declared more than once")]
    DuplicateKind(String),
    #[error("relation '{relation}' is declared more than once on kind '{kind}'")]
    DuplicateRelation { kind: String, relation: String },
    #[error("relation '{relation}' on kind '{kind}' references undeclared relation '{target}'")]
    UnknownTarget { kind: String, relation: String, target: String },
    #[error("relation '{relation}' on kind '{kind}' is part of an implies cycle")]
    Cycle { kind: String, relation: String },
    #[error("relation '{relation}' on kind '{kind}' unlocks unregistered scope '{scope}'")]
    UnregisteredScope { kind: String, relation: String, scope: Scope },
}

/// Who holds an ownership tuple (noisetable W235 §2.1).
///
/// Either one principal, or a **subject set** (Zanzibar's "userset"): every
/// holder of `relation` on the resource `(kind, id)` holds the tuple's
/// relation. `issues/x#reader ← namespace/n#member` is the tuple
/// `(issues, x, reader)` with subject `Set { kind: "namespace", id: "n",
/// relation: "member" }`.
///
/// Serialized flat, in the ownership table's column names, so a principal
/// subject keeps the `principal_id` key it always had on the wire:
/// `{"principal_id": "user:alice"}` or `{"subject_kind": "namespace",
/// "subject_id": "n", "subject_relation": "member"}` — exactly one form.
/// Meant to be `#[serde(flatten)]`ed into the row that carries it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "SubjectWire", into = "SubjectWire")]
pub enum Subject {
    Principal(PrincipalId),
    Set { kind: String, id: String, relation: String },
}

/// Both subject forms populated, or neither — the one-form rule the
/// ownership table's CHECK also enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "a subject is either principal_id or all of subject_kind/subject_id/subject_relation, \
     never both and never neither"
)]
pub struct SubjectFormError;

impl Subject {
    pub fn set(kind: impl Into<String>, id: impl Into<String>, relation: impl Into<String>) -> Self {
        Self::Set { kind: kind.into(), id: id.into(), relation: relation.into() }
    }

    /// The holder, when the subject is one principal.
    pub fn principal(&self) -> Option<&PrincipalId> {
        match self {
            Self::Principal(p) => Some(p),
            Self::Set { .. } => None,
        }
    }

    /// `(kind, id, relation)`, when the subject is a set.
    pub fn as_set(&self) -> Option<(&str, &str, &str)> {
        match self {
            Self::Principal(_) => None,
            Self::Set { kind, id, relation } => Some((kind, id, relation)),
        }
    }

    /// Rebuild from the four nullable subject fields (table columns, wire
    /// keys). Exactly one form must be complete: the principal alone, or all
    /// three set fields alone.
    pub fn from_parts(
        principal_id: Option<PrincipalId>,
        kind: Option<String>,
        id: Option<String>,
        relation: Option<String>,
    ) -> Result<Self, SubjectFormError> {
        match (principal_id, kind, id, relation) {
            (Some(p), None, None, None) => Ok(Self::Principal(p)),
            (None, Some(kind), Some(id), Some(relation)) => Ok(Self::Set { kind, id, relation }),
            _ => Err(SubjectFormError),
        }
    }
}

impl From<PrincipalId> for Subject {
    fn from(p: PrincipalId) -> Self {
        Self::Principal(p)
    }
}

impl std::fmt::Display for Subject {
    /// `user:alice`, or `namespace/n#member` for a set.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Principal(p) => write!(f, "{p}"),
            Self::Set { kind, id, relation } => write!(f, "{kind}/{id}#{relation}"),
        }
    }
}

/// [`Subject`]'s flat serde shape.
#[derive(Serialize, Deserialize)]
struct SubjectWire {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    principal_id: Option<PrincipalId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    subject_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    subject_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    subject_relation: Option<String>,
}

impl TryFrom<SubjectWire> for Subject {
    type Error = SubjectFormError;
    fn try_from(w: SubjectWire) -> Result<Self, SubjectFormError> {
        Self::from_parts(w.principal_id, w.subject_kind, w.subject_id, w.subject_relation)
    }
}

impl From<Subject> for SubjectWire {
    fn from(s: Subject) -> Self {
        match s {
            Subject::Principal(p) => Self {
                principal_id: Some(p),
                subject_kind: None,
                subject_id: None,
                subject_relation: None,
            },
            Subject::Set { kind, id, relation } => Self {
                principal_id: None,
                subject_kind: Some(kind),
                subject_id: Some(id),
                subject_relation: Some(relation),
            },
        }
    }
}

/// One ownership tuple as the schema reads it. Implemented by the server's
/// `OwnershipRow`; kept as a trait so cheers-core stays storage-free.
pub trait RelationTuple {
    /// Who holds the tuple — one principal, or a subject set.
    fn subject(&self) -> &Subject;
    fn resource_kind(&self) -> &str;
    fn resource_id(&self) -> &str;
    fn relation(&self) -> &str;
    /// `false` once the row is revoked — a dead row confers nothing.
    fn is_live(&self) -> bool;
}

/// Where the set-aware checks read tuples. Implemented by cheers-server over
/// its ownership store; a trait so cheers-core stays storage-free.
///
/// Sources return live rows; the walks re-check [`RelationTuple::is_live`]
/// anyway, so a row a source leaks after revocation confers nothing.
#[async_trait]
pub trait TupleSource: Send + Sync {
    type Tuple: RelationTuple + Send + Sync;

    /// Tuples whose subject is exactly `principal` — no set rows.
    async fn list_for_principal(
        &self,
        principal: &PrincipalId,
    ) -> Result<Vec<Self::Tuple>, StoreError>;

    /// Tuples on resource `(kind, id)`, either subject form.
    async fn list_for_resource(&self, kind: &str, id: &str)
        -> Result<Vec<Self::Tuple>, StoreError>;

    /// Tuples whose subject is a set on `(kind, id)`, any subject relation.
    async fn list_for_subject_set(
        &self,
        kind: &str,
        id: &str,
    ) -> Result<Vec<Self::Tuple>, StoreError>;
}

/// Everything one principal holds ([`SchemaRegistry::held_by`]): direct and
/// set-derived tuples, implies-closure folded in, by resource.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Holdings(BTreeMap<(String, String), BTreeSet<String>>);

impl Holdings {
    pub fn contains(&self, kind: &str, id: &str, relation: &str) -> bool {
        self.0
            .get(&(kind.to_owned(), id.to_owned()))
            .is_some_and(|rels| rels.contains(relation))
    }

    /// Every held `(kind, id, relation)`, sorted.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str, &str)> + '_ {
        self.0.iter().flat_map(|((kind, id), rels)| {
            rels.iter().map(move |r| (kind.as_str(), id.as_str(), r.as_str()))
        })
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// `true` when the holding is new.
    fn insert(&mut self, kind: &str, id: &str, relation: &str) -> bool {
        self.0.entry((kind.to_owned(), id.to_owned())).or_default().insert(relation.to_owned())
    }
}

/// One entry of [`SchemaRegistry::members`]: `principal` holds `relation` on
/// the resource, implies-closure folded in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub principal: PrincipalId,
    pub relation: String,
    /// `(kind, id)` of every resource where one of `principal`'s own direct
    /// tuples sits from which `relation` derives: the resource itself for a
    /// direct holder, the set's resource (a parent namespace) for an
    /// inherited one. Never empty. A membership snapshot's revocation mask
    /// keys on it (`cheers_core::snapshot`).
    pub via: BTreeSet<(String, String)>,
}

/// `(kind, id, relation)` — one node of a set walk: "holds `relation` on
/// `kind/id`".
type Node = (String, String, String);

/// A walk's per-check memo of source reads, keyed by `(kind, id)`, so a
/// resource reached by several paths or for several relations is read once.
type RowCache<T> = HashMap<(String, String), Vec<T>>;

/// A relation with its implies-closure folded in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedRelation {
    /// The relation itself and every relation it implies, transitively — what
    /// a holder of it holds on the same resource.
    pub relations: BTreeSet<&'static str>,
    /// Every scope unlocked by the relation or anything it implies.
    pub scopes: BTreeSet<Scope>,
    /// Every relation the holder may grant, by the same closure.
    pub grants: BTreeSet<&'static str>,
    /// The relation's own [`RelationDef::membership`] (not folded through
    /// the closure: each implied relation answers for itself).
    pub membership: bool,
}

/// How a tuple resolves against the schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup<'a> {
    /// The tuple's kind has no schema — derivation ignores it (e.g. camp
    /// `owns` rows that only feed the owns claim).
    NoSchema,
    /// The kind is known but the relation is not declared on it.
    UnknownRelation,
    Resolved(&'a ResolvedRelation),
}

#[derive(Debug, Clone, Default)]
struct KindEntry {
    relations: HashMap<&'static str, ResolvedRelation>,
    kind_relations: HashMap<&'static str, ResolvedRelation>,
}

/// The deployment's relationship schema, built once at startup.
#[derive(Debug, Clone, Default)]
pub struct SchemaRegistry {
    kinds: HashMap<&'static str, KindEntry>,
}

impl SchemaRegistry {
    pub fn build(schemas: &[ResourceSchema], scopes: &ScopeRegistry) -> Result<Self, SchemaError> {
        let mut kinds = HashMap::with_capacity(schemas.len());
        for s in schemas {
            if s.kind == KIND_RESOURCE {
                return Err(SchemaError::ReservedKind(s.kind.to_owned()));
            }
            let rel_names: BTreeSet<&str> = s.relations.iter().map(|r| r.name).collect();
            let entry = KindEntry {
                relations: resolve_list(s.kind, s.relations, &rel_names, scopes)?,
                kind_relations: resolve_list(s.kind, s.kind_relations, &rel_names, scopes)?,
            };
            if kinds.insert(s.kind, entry).is_some() {
                return Err(SchemaError::DuplicateKind(s.kind.to_owned()));
            }
        }
        Ok(Self { kinds })
    }

    /// Resolve one tuple's `(resource_kind, resource_id, relation)`.
    pub fn lookup(&self, resource_kind: &str, resource_id: &str, relation: &str) -> Lookup<'_> {
        let list = if resource_kind == KIND_RESOURCE {
            match self.kinds.get(resource_id) {
                Some(e) => &e.kind_relations,
                None => return Lookup::NoSchema,
            }
        } else {
            match self.kinds.get(resource_kind) {
                Some(e) => &e.relations,
                None => return Lookup::NoSchema,
            }
        };
        match list.get(relation) {
            Some(r) => Lookup::Resolved(r),
            None => Lookup::UnknownRelation,
        }
    }

    /// Is `relation` a membership relation on `kind` (R734-B6)? Unknown
    /// kinds and relations are not: only what the schema marks is minted.
    pub fn is_membership(&self, kind: &str, relation: &str) -> bool {
        self.kinds.get(kind).and_then(|e| e.relations.get(relation)).is_some_and(|r| r.membership)
    }

    /// An [`AdmissionPolicy`] is only usable at the edge when its `floor` and
    /// every `admitters` entry are membership relations on `kind`: the edge
    /// sees approvers and floor holders only through the snapshot, which
    /// lists membership relations alone (R734-B6).
    pub fn validate_admission_policy(&self, kind: &str, policy: &AdmissionPolicy) -> Result<(), PolicyError> {
        for rel in std::iter::once(&policy.floor).chain(policy.admitters.iter()) {
            if !self.is_membership(kind, rel) {
                return Err(PolicyError::NotMembership { kind: kind.to_owned(), relation: rel.clone() });
            }
        }
        Ok(())
    }

    /// W235 §3 `effective(P, resource, rel)`: does `principal` hold
    /// `relation` on `(kind, id)` — by a direct tuple, through the
    /// implies-closure, or through subject sets within [`MAX_SET_HOPS`]?
    /// A store error is an error, never "not held".
    pub async fn holds<S: TupleSource + ?Sized>(
        &self,
        source: &S,
        principal: &PrincipalId,
        kind: &str,
        id: &str,
        relation: &str,
    ) -> Result<bool, StoreError> {
        let root = (kind.to_owned(), id.to_owned(), relation.to_owned());
        self.reaches(source, principal, vec![root]).await
    }

    /// The D4 authority check: may `principal` grant (or revoke) `relation` on
    /// `(kind, id)`? True iff it [holds](Self::holds) a relation on
    /// `(kind, id)` whose closure grants `relation`, or such a kind-level
    /// relation on `(KIND_RESOURCE, kind)` — directly or through sets.
    pub async fn may_grant<S: TupleSource + ?Sized>(
        &self,
        source: &S,
        principal: &PrincipalId,
        kind: &str,
        id: &str,
        relation: &str,
    ) -> Result<bool, StoreError> {
        let roots = self.grant_roots(kind, id, |g| g.contains(relation));
        self.reaches(source, principal, roots).await
    }

    /// The D4 door rule for revoking `tuple`: a holder may always revoke the
    /// tuple it holds (leaving), else the caller needs grant rights on the
    /// tuple's relation ([`may_grant`](Self::may_grant)). Only a *direct*
    /// principal subject counts as holding; a set-subject tuple is not
    /// revocable by a member of the set on that basis.
    pub async fn may_revoke<S: TupleSource + ?Sized, T: RelationTuple>(
        &self,
        source: &S,
        principal: &PrincipalId,
        tuple: &T,
    ) -> Result<bool, StoreError> {
        if matches!(tuple.subject(), Subject::Principal(p) if p == principal) {
            return Ok(true);
        }
        self.may_grant(source, principal, tuple.resource_kind(), tuple.resource_id(), tuple.relation())
            .await
    }

    /// May `principal` grant *any* relation on `(kind, id)`? The gate on
    /// reading a resource's rows through the grant door (D4).
    pub async fn may_grant_any<S: TupleSource + ?Sized>(
        &self,
        source: &S,
        principal: &PrincipalId,
        kind: &str,
        id: &str,
    ) -> Result<bool, StoreError> {
        let roots = self.grant_roots(kind, id, |g| !g.is_empty());
        self.reaches(source, principal, roots).await
    }

    /// Everything `principal` holds — the up-walk. Starts from its direct
    /// tuples; each holding `kind/id#rel` then confers the relations of every
    /// tuple whose subject is the set `kind/id#rel`, one hop per level, up to
    /// [`MAX_SET_HOPS`]. Agrees with [`holds`](Self::holds):
    /// `held_by(P).contains(k, i, r) == holds(P, k, i, r)`.
    pub async fn held_by<S: TupleSource + ?Sized>(
        &self,
        source: &S,
        principal: &PrincipalId,
    ) -> Result<Holdings, StoreError> {
        let mut held = Holdings::default();
        let mut frontier = Vec::new();
        for row in source.list_for_principal(principal).await?.iter().filter(|r| r.is_live()) {
            self.hold(&mut held, &mut frontier, row);
        }
        let mut cache: RowCache<S::Tuple> = HashMap::new();
        for _hop in 1..=MAX_SET_HOPS {
            let mut next = Vec::new();
            for (kind, id, relation) in &frontier {
                let key = (kind.clone(), id.clone());
                if !cache.contains_key(&key) {
                    let rows = source.list_for_subject_set(kind, id).await?;
                    cache.insert(key.clone(), rows);
                }
                let subject = Some((kind.as_str(), id.as_str(), relation.as_str()));
                for row in cache[&key].iter().filter(|r| r.is_live()) {
                    if row.subject().as_set() == subject {
                        self.hold(&mut held, &mut next, row);
                    }
                }
            }
            if next.is_empty() {
                break;
            }
            frontier = next;
        }
        Ok(held)
    }

    /// Every [`Member`] of `(kind, id)`: each `(principal, relation)` with
    /// sets flattened and the implies-closure folded in, plus its provenance
    /// `via`, sorted by `(principal, relation)`. The down-walk enumerated:
    /// `(P, r)` is listed iff [`holds`](Self::holds)`(P, kind, id, r)`, and
    /// `via` is every resource where one of P's direct tuples sits that the
    /// walk reached for `r` — so revoking P's direct tuples on exactly the
    /// `via` resources is what ends `(P, r)`. This is what a membership
    /// snapshot (R732-F4) mints from. Kind-level tuples are not members of
    /// the resources of their kind.
    pub async fn members<S: TupleSource + ?Sized>(
        &self,
        source: &S,
        kind: &str,
        id: &str,
    ) -> Result<Vec<Member>, StoreError> {
        let mut out: Credits = HashMap::new();
        // Per node: the relations on (kind, id) its holders were credited with.
        let mut seen: HashMap<Node, BTreeSet<String>> = HashMap::new();
        let mut frontier: HashMap<Node, BTreeSet<String>> = HashMap::new();
        for row in source.list_for_resource(kind, id).await?.iter().filter(|r| r.is_live()) {
            let conferred: BTreeSet<String> =
                self.closure(kind, id, row.relation()).into_iter().collect();
            credit(row.subject(), (kind, id), &conferred, &mut out, &mut seen, &mut frontier, true);
        }
        let mut cache: RowCache<S::Tuple> = HashMap::new();
        for hop in 1..=MAX_SET_HOPS {
            let mut next = HashMap::new();
            for ((nk, ni, nrel), conferred) in &frontier {
                let key = (nk.clone(), ni.clone());
                if !cache.contains_key(&key) {
                    let rows = source.list_for_resource(nk, ni).await?;
                    cache.insert(key.clone(), rows);
                }
                for row in cache[&key].iter().filter(|r| r.is_live()) {
                    if self.confers(nk, ni, row.relation(), nrel) {
                        let deeper = hop < MAX_SET_HOPS;
                        let at = (nk.as_str(), ni.as_str());
                        credit(row.subject(), at, conferred, &mut out, &mut seen, &mut next, deeper);
                    }
                }
            }
            if next.is_empty() {
                break;
            }
            frontier = next;
        }
        let mut out: Vec<Member> = out
            .into_iter()
            .map(|((principal, relation), via)| Member { principal, relation, via })
            .collect();
        out.sort_by_cached_key(|m| (m.principal.to_string(), m.relation.clone()));
        Ok(out)
    }

    /// The down-walk: does `principal` hold any of `roots`? Breadth-first
    /// through set subjects, one level per hop, so each node is first reached
    /// at its fewest hops and a single visited set is exact under the bound.
    async fn reaches<S: TupleSource + ?Sized>(
        &self,
        source: &S,
        principal: &PrincipalId,
        roots: Vec<Node>,
    ) -> Result<bool, StoreError> {
        let mut visited: HashSet<Node> = roots.iter().cloned().collect();
        let mut frontier = roots;
        let mut cache: RowCache<S::Tuple> = HashMap::new();
        for hop in 0..=MAX_SET_HOPS {
            let mut next = Vec::new();
            for (kind, id, wanted) in &frontier {
                let key = (kind.clone(), id.clone());
                if !cache.contains_key(&key) {
                    let rows = source.list_for_resource(kind, id).await?;
                    cache.insert(key.clone(), rows);
                }
                for row in cache[&key].iter().filter(|r| r.is_live()) {
                    if !self.confers(kind, id, row.relation(), wanted) {
                        continue;
                    }
                    match row.subject() {
                        Subject::Principal(p) if p == principal => return Ok(true),
                        Subject::Principal(_) => {}
                        Subject::Set { kind: sk, id: si, relation: srel } => {
                            let node = (sk.clone(), si.clone(), srel.clone());
                            if hop < MAX_SET_HOPS && visited.insert(node.clone()) {
                                next.push(node);
                            }
                        }
                    }
                }
            }
            if next.is_empty() {
                break;
            }
            frontier = next;
        }
        Ok(false)
    }

    /// The relations whose holders may grant per `pred` on `(kind, id)`: those
    /// on the resource, and the kind-level ones on `(KIND_RESOURCE, kind)`. On
    /// a kind-level resource itself, its kind's kind relations.
    fn grant_roots(
        &self,
        kind: &str,
        id: &str,
        pred: impl Fn(&BTreeSet<&'static str>) -> bool,
    ) -> Vec<Node> {
        let mut roots = Vec::new();
        let mut add = |rk: &str, ri: &str, rels: &HashMap<&'static str, ResolvedRelation>| {
            roots.extend(
                rels.iter()
                    .filter(|(_, r)| pred(&r.grants))
                    .map(|(name, _)| (rk.to_owned(), ri.to_owned(), (*name).to_owned())),
            );
        };
        if kind == KIND_RESOURCE {
            if let Some(e) = self.kinds.get(id) {
                add(KIND_RESOURCE, id, &e.kind_relations);
            }
        } else if let Some(e) = self.kinds.get(kind) {
            add(kind, id, &e.relations);
            add(KIND_RESOURCE, kind, &e.kind_relations);
        }
        roots
    }

    /// Does holding `held` on `(kind, id)` mean holding `wanted` there — the
    /// same relation, or one its closure implies?
    fn confers(&self, kind: &str, id: &str, held: &str, wanted: &str) -> bool {
        held == wanted
            || matches!(self.lookup(kind, id, held), Lookup::Resolved(r) if r.relations.contains(wanted))
    }

    /// `relation` and everything it implies on `(kind, id)`. A relation the
    /// schema does not resolve (no schema for the kind, or undeclared on it)
    /// implies only itself.
    fn closure(&self, kind: &str, id: &str, relation: &str) -> Vec<String> {
        match self.lookup(kind, id, relation) {
            Lookup::Resolved(r) => r.relations.iter().map(|r| (*r).to_owned()).collect(),
            _ => vec![relation.to_owned()],
        }
    }

    /// Record that the walking principal holds `row`'s relation, closure
    /// folded in, on its resource; queue each new holding in `fresh`.
    fn hold<T: RelationTuple>(&self, held: &mut Holdings, fresh: &mut Vec<Node>, row: &T) {
        let (kind, id) = (row.resource_kind(), row.resource_id());
        for rel in self.closure(kind, id, row.relation()) {
            if held.insert(kind, id, &rel) {
                fresh.push((kind.to_owned(), id.to_owned(), rel));
            }
        }
    }
}

/// [`SchemaRegistry::members`]' accumulator: `(principal, relation)` → `via`.
type Credits = HashMap<(PrincipalId, String), BTreeSet<(String, String)>>;

/// [`SchemaRegistry::members`]' step over one live tuple on resource `at`: a
/// principal subject is credited with `conferred`, via `at` (where its direct
/// tuple sits); a set subject passes on what it has not already passed on,
/// when the walk may still go `deeper`.
///
/// Passing a relation through a set node once is enough for `via` too: a
/// later arrival of the same relation at the same node would credit the same
/// principals via the same resources.
fn credit(
    subject: &Subject,
    at: (&str, &str),
    conferred: &BTreeSet<String>,
    out: &mut Credits,
    seen: &mut HashMap<Node, BTreeSet<String>>,
    next: &mut HashMap<Node, BTreeSet<String>>,
    deeper: bool,
) {
    match subject {
        Subject::Principal(p) => {
            for r in conferred {
                out.entry((p.clone(), r.clone()))
                    .or_default()
                    .insert((at.0.to_owned(), at.1.to_owned()));
            }
        }
        Subject::Set { kind, id, relation } if deeper => {
            let node = (kind.clone(), id.clone(), relation.clone());
            let seen = seen.entry(node.clone()).or_default();
            let fresh: Vec<String> = conferred.iter().filter(|r| seen.insert((*r).clone())).cloned().collect();
            if !fresh.is_empty() {
                next.entry(node).or_default().extend(fresh);
            }
        }
        Subject::Set { .. } => {}
    }
}

fn resolve_list(
    kind: &str,
    defs: &'static [RelationDef],
    grant_targets: &BTreeSet<&str>,
    scopes: &ScopeRegistry,
) -> Result<HashMap<&'static str, ResolvedRelation>, SchemaError> {
    let mut by_name: HashMap<&'static str, &'static RelationDef> = HashMap::new();
    for d in defs {
        if by_name.insert(d.name, d).is_some() {
            return Err(SchemaError::DuplicateRelation {
                kind: kind.to_owned(),
                relation: d.name.to_owned(),
            });
        }
    }
    for d in defs {
        let err = |target: &str| SchemaError::UnknownTarget {
            kind: kind.to_owned(),
            relation: d.name.to_owned(),
            target: target.to_owned(),
        };
        if let Some(t) = d.implies.iter().find(|t| !by_name.contains_key(*t)) {
            return Err(err(t));
        }
        if let Some(t) = d.grants.iter().find(|t| !grant_targets.contains(*t)) {
            return Err(err(t));
        }
        if let Some(s) = d.scopes.iter().find(|s| !scopes.contains(s)) {
            return Err(SchemaError::UnregisteredScope {
                kind: kind.to_owned(),
                relation: d.name.to_owned(),
                scope: s.clone(),
            });
        }
    }
    // Acyclicity: three-colour DFS over the implies graph.
    fn visit(
        name: &'static str,
        by_name: &HashMap<&'static str, &'static RelationDef>,
        state: &mut HashMap<&'static str, bool>, // false = on stack, true = done
    ) -> Result<(), &'static str> {
        match state.get(name) {
            Some(true) => return Ok(()),
            Some(false) => return Err(name),
            None => {}
        }
        state.insert(name, false);
        for t in by_name[name].implies {
            visit(t, by_name, state)?;
        }
        state.insert(name, true);
        Ok(())
    }
    let mut state = HashMap::new();
    for d in defs {
        visit(d.name, &by_name, &mut state).map_err(|r| SchemaError::Cycle {
            kind: kind.to_owned(),
            relation: r.to_owned(),
        })?;
    }
    let mut out = HashMap::with_capacity(defs.len());
    for d in defs {
        let mut res = ResolvedRelation { membership: d.membership, ..Default::default() };
        let mut stack = vec![d];
        let mut seen = BTreeSet::new();
        while let Some(cur) = stack.pop() {
            if !seen.insert(cur.name) {
                continue;
            }
            res.relations.insert(cur.name);
            res.scopes.extend(cur.scopes.iter().cloned());
            res.grants.extend(cur.grants.iter().copied());
            stack.extend(cur.implies.iter().map(|t| by_name[t]));
        }
        out.insert(d.name, res);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ScopeDef;
    use pollster::block_on;

    crate::scopes! {
        // Bound at startup, like yah's.
        ISSUE_READ = "issue:read" { description: "read" };
        ISSUE_TRIAGE = "issue:triage" { description: "triage" };
        ISSUE_ADMIN = "issue:admin" { description: "admin" };
        SVC_DEPLOY = "svc:deploy" { description: "deploy" };
    }

    fn scopes() -> ScopeRegistry {
        ScopeRegistry::builder()
            .with(DEFS)
            .bind_audiences("issue", ["https://issues".to_owned()])
            .bind_audiences("svc", ["https://svc".to_owned()])
            .build()
            .unwrap()
    }

    const ISSUE: ResourceSchema = ResourceSchema {
        kind: "issue",
        relations: &[
            RelationDef { name: "reader", membership: true, implies: &[], scopes: &[ISSUE_READ], grants: &[] },
            RelationDef {
                name: "triager",
                membership: true,
                implies: &[],
                scopes: &[ISSUE_TRIAGE],
                grants: &["reader"],
            },
            // admin implies triager, NOT reader.
            RelationDef {
                name: "admin",
                membership: true,
                implies: &["triager"],
                scopes: &[ISSUE_ADMIN],
                grants: &["admin"],
            },
        ],
        kind_relations: &[],
    };

    const SERVICE: ResourceSchema = ResourceSchema {
        kind: "service",
        relations: &[RelationDef { name: "owns", membership: true, implies: &[], scopes: &[SVC_DEPLOY], grants: &[] }],
        kind_relations: &[RelationDef {
            name: "provisioner",
            membership: true,
            implies: &[],
            scopes: &[],
            grants: &["owns"],
        }],
    };

    /// `team`: no scopes, only membership. `owner` implies `member`.
    const TEAM: ResourceSchema = ResourceSchema {
        kind: "team",
        relations: &[
            RelationDef { name: "owner", membership: true, implies: &["member"], scopes: &[], grants: &["member"] },
            RelationDef { name: "member", membership: true, implies: &[], scopes: &[], grants: &[] },
        ],
        kind_relations: &[],
    };

    #[derive(Clone)]
    struct Row(&'static str, &'static str, &'static str, bool, Subject);
    fn row(kind: &'static str, id: &'static str, rel: &'static str, live: bool) -> Row {
        Row(kind, id, rel, live, PrincipalId::user("caller").into())
    }
    /// `kind/id#rel` held directly by `user:<who>`.
    fn direct(kind: &'static str, id: &'static str, rel: &'static str, who: &str) -> Row {
        Row(kind, id, rel, true, PrincipalId::user(who).into())
    }
    /// `kind/id#rel ← sk/si#srel`.
    fn via(
        kind: &'static str,
        id: &'static str,
        rel: &'static str,
        sk: &str,
        si: &str,
        srel: &str,
    ) -> Row {
        Row(kind, id, rel, true, Subject::set(sk, si, srel))
    }

    /// An in-memory [`TupleSource`]. It returns revoked rows too, so the tests
    /// pin that the walks re-check liveness themselves.
    struct Mem(Vec<Row>);

    #[async_trait]
    impl TupleSource for Mem {
        type Tuple = Row;
        async fn list_for_principal(&self, p: &PrincipalId) -> Result<Vec<Row>, StoreError> {
            Ok(self.0.iter().filter(|r| r.4.principal() == Some(p)).cloned().collect())
        }
        async fn list_for_resource(&self, kind: &str, id: &str) -> Result<Vec<Row>, StoreError> {
            Ok(self.0.iter().filter(|r| r.0 == kind && r.1 == id).cloned().collect())
        }
        async fn list_for_subject_set(&self, kind: &str, id: &str) -> Result<Vec<Row>, StoreError> {
            Ok(self
                .0
                .iter()
                .filter(|r| r.4.as_set().is_some_and(|(k, i, _)| k == kind && i == id))
                .cloned()
                .collect())
        }
    }

    fn holds(r: &SchemaRegistry, m: &Mem, who: &str, kind: &str, id: &str, rel: &str) -> bool {
        block_on(r.holds(m, &PrincipalId::user(who), kind, id, rel)).unwrap()
    }
    fn may_grant(r: &SchemaRegistry, m: &Mem, who: &str, kind: &str, id: &str, rel: &str) -> bool {
        block_on(r.may_grant(m, &PrincipalId::user(who), kind, id, rel)).unwrap()
    }
    fn held_by(r: &SchemaRegistry, m: &Mem, who: &str) -> Holdings {
        block_on(r.held_by(m, &PrincipalId::user(who))).unwrap()
    }
    fn members(r: &SchemaRegistry, m: &Mem, kind: &str, id: &str) -> Vec<(String, String)> {
        block_on(r.members(m, kind, id))
            .unwrap()
            .into_iter()
            .map(|m| (m.principal.to_string(), m.relation))
            .collect()
    }
    /// `members` with provenance: `principal#relation` -> `via` as `kind/id`.
    fn members_via(r: &SchemaRegistry, m: &Mem, kind: &str, id: &str) -> Vec<(String, Vec<String>)> {
        block_on(r.members(m, kind, id))
            .unwrap()
            .into_iter()
            .map(|m| {
                let via = m.via.iter().map(|(k, i)| format!("{k}/{i}")).collect();
                (format!("{}#{}", m.principal, m.relation), via)
            })
            .collect()
    }
    impl RelationTuple for Row {
        fn subject(&self) -> &Subject {
            &self.4
        }
        fn resource_kind(&self) -> &str {
            self.0
        }
        fn resource_id(&self) -> &str {
            self.1
        }
        fn relation(&self) -> &str {
            self.2
        }
        fn is_live(&self) -> bool {
            self.3
        }
    }

    fn reg() -> SchemaRegistry {
        SchemaRegistry::build(&[ISSUE, SERVICE, TEAM], &scopes()).unwrap()
    }

    fn resolved<'a>(r: &'a SchemaRegistry, k: &str, id: &str, rel: &str) -> &'a ResolvedRelation {
        match r.lookup(k, id, rel) {
            Lookup::Resolved(x) => x,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn admin_does_not_imply_read_unless_declared() {
        let r = reg();
        let admin = resolved(&r, "issue", "i1", "admin");
        assert!(admin.scopes.contains(&ISSUE_ADMIN));
        assert!(admin.scopes.contains(&ISSUE_TRIAGE));
        assert!(!admin.scopes.contains(&ISSUE_READ));
    }

    #[test]
    fn implied_relations_carry_their_grants() {
        let r = reg();
        let admin = resolved(&r, "issue", "i1", "admin");
        // `reader` comes only from triager's grants, via admin -> triager.
        assert!(admin.grants.contains("reader"));
        assert!(admin.grants.contains("admin"));
        assert_eq!(admin.relations, BTreeSet::from(["admin", "triager"]));
        let m = Mem(vec![row("issue", "i1", "admin", true)]);
        assert!(may_grant(&r, &m, "caller", "issue", "i1", "reader"));
    }

    #[test]
    fn lookup_distinguishes_no_schema_and_unknown_relation() {
        let r = reg();
        assert_eq!(r.lookup("camp", "c", "owns"), Lookup::NoSchema);
        assert_eq!(r.lookup("issue", "i", "bogus"), Lookup::UnknownRelation);
        assert_eq!(r.lookup(KIND_RESOURCE, "nope", "provisioner"), Lookup::NoSchema);
        assert!(matches!(r.lookup(KIND_RESOURCE, "service", "provisioner"), Lookup::Resolved(_)));
    }

    #[test]
    fn may_revoke_rules() {
        let r = reg();
        let may_revoke = |m: &Mem, t: &Row| {
            block_on(r.may_revoke(m, &PrincipalId::user("caller"), t)).unwrap()
        };
        let none = Mem(vec![]);
        // A holder may revoke its own tuple with no grant rights at all.
        assert!(may_revoke(&none, &direct("issue", "i1", "triager", "caller")));
        // A non-holder without grant rights may not.
        assert!(!may_revoke(&none, &direct("issue", "i1", "triager", "someone")));
        // Grant rights still authorise revoking another's tuple.
        let triager = Mem(vec![row("issue", "i1", "triager", true)]);
        assert!(may_revoke(&triager, &direct("issue", "i1", "reader", "someone")));
        // A set-subject tuple is not self-revocable by a member of the set.
        let member = Mem(vec![direct("team", "t1", "member", "caller")]);
        assert!(!may_revoke(&member, &via("issue", "i1", "reader", "team", "t1", "member")));
    }

    #[test]
    fn may_grant_rules() {
        let r = reg();
        let triager = Mem(vec![row("issue", "i1", "triager", true)]);
        assert!(may_grant(&r, &triager, "caller", "issue", "i1", "reader"));
        assert!(!may_grant(&r, &triager, "caller", "issue", "i1", "triager"));
        assert!(!may_grant(&r, &triager, "caller", "issue", "i2", "reader"), "other resource");
        assert!(!may_grant(&r, &triager, "someone", "issue", "i1", "reader"), "other principal");
        let revoked = Mem(vec![row("issue", "i1", "admin", false)]);
        assert!(!may_grant(&r, &revoked, "caller", "issue", "i1", "reader"), "revoked row grants nothing");
        assert!(!may_grant(&r, &Mem(vec![]), "caller", "issue", "i1", "reader"));
    }

    #[test]
    fn may_grant_kind_level() {
        let r = reg();
        let prov = Mem(vec![row(KIND_RESOURCE, "service", "provisioner", true)]);
        assert!(may_grant(&r, &prov, "caller", "service", "svc-a", "owns"));
        assert!(may_grant(&r, &prov, "caller", "service", "svc-b", "owns"));
        assert!(!may_grant(&r, &prov, "caller", "issue", "i1", "reader"), "other kind");
        let dead = Mem(vec![row(KIND_RESOURCE, "service", "provisioner", false)]);
        assert!(!may_grant(&r, &dead, "caller", "service", "svc-a", "owns"));
    }

    #[test]
    fn holds_a_direct_tuple_and_nothing_else() {
        let r = reg();
        let m = Mem(vec![direct("issue", "i1", "reader", "alice")]);
        assert!(holds(&r, &m, "alice", "issue", "i1", "reader"));
        assert!(!holds(&r, &m, "alice", "issue", "i1", "triager"));
        assert!(!holds(&r, &m, "alice", "issue", "i2", "reader"));
        assert!(!holds(&r, &m, "bob", "issue", "i1", "reader"));
        // A kind with no schema holds exactly the named relation.
        let m = Mem(vec![direct("node", "n1", "owns", "alice")]);
        assert!(holds(&r, &m, "alice", "node", "n1", "owns"));
        // A revoked tuple holds nothing, even when the source returns it.
        let m = Mem(vec![Row("issue", "i1", "reader", false, PrincipalId::user("alice").into())]);
        assert!(!holds(&r, &m, "alice", "issue", "i1", "reader"));
    }

    #[test]
    fn holds_through_the_implies_closure() {
        let r = reg();
        let m = Mem(vec![direct("issue", "i1", "admin", "alice")]);
        assert!(holds(&r, &m, "alice", "issue", "i1", "admin"));
        assert!(holds(&r, &m, "alice", "issue", "i1", "triager"), "admin implies triager");
        assert!(!holds(&r, &m, "alice", "issue", "i1", "reader"), "admin does not imply reader");
    }

    #[test]
    fn holds_through_a_one_hop_set() {
        let r = reg();
        let m = Mem(vec![
            via("issue", "i1", "reader", "team", "t1", "member"),
            direct("team", "t1", "member", "alice"),
            // owner implies member, so an owner is in the set too.
            direct("team", "t1", "owner", "olga"),
            // A different relation on the set's resource is a different set.
            via("issue", "i1", "admin", "team", "t1", "owner"),
        ]);
        assert!(holds(&r, &m, "alice", "issue", "i1", "reader"));
        assert!(!holds(&r, &m, "alice", "issue", "i1", "admin"));
        assert!(holds(&r, &m, "olga", "issue", "i1", "reader"));
        assert!(holds(&r, &m, "olga", "issue", "i1", "admin"));
        // The set's relation confers its closure: admin implies triager.
        assert!(holds(&r, &m, "olga", "issue", "i1", "triager"));
        assert!(!holds(&r, &m, "bob", "issue", "i1", "reader"));
        // A revoked set tuple confers nothing.
        let m = Mem(vec![
            Row("issue", "i1", "reader", false, Subject::set("team", "t1", "member")),
            direct("team", "t1", "member", "alice"),
        ]);
        assert!(!holds(&r, &m, "alice", "issue", "i1", "reader"));
    }

    #[test]
    fn holds_through_a_multi_hop_set() {
        let r = reg();
        // issue/i1#reader <- team/eng#member <- team/org#member <- alice
        let m = Mem(vec![
            via("issue", "i1", "reader", "team", "eng", "member"),
            via("team", "eng", "member", "team", "org", "member"),
            direct("team", "org", "member", "alice"),
        ]);
        assert!(holds(&r, &m, "alice", "issue", "i1", "reader"));
        assert!(holds(&r, &m, "alice", "team", "eng", "member"));
        assert!(!holds(&r, &m, "alice", "team", "eng", "owner"));
    }

    #[test]
    fn a_set_cycle_terminates() {
        let r = reg();
        // team/a#member ⊇ team/b#member ⊇ team/a#member
        let cycle = vec![
            via("team", "a", "member", "team", "b", "member"),
            via("team", "b", "member", "team", "a", "member"),
            via("issue", "i1", "reader", "team", "a", "member"),
        ];
        let m = Mem(cycle.clone());
        assert!(!holds(&r, &m, "alice", "team", "a", "member"));
        assert!(!holds(&r, &m, "alice", "issue", "i1", "reader"));
        assert!(held_by(&r, &m, "alice").is_empty());
        assert!(members(&r, &m, "issue", "i1").is_empty());

        let mut rows = cycle;
        rows.push(direct("team", "b", "member", "alice"));
        let m = Mem(rows);
        assert!(holds(&r, &m, "alice", "team", "a", "member"));
        assert!(holds(&r, &m, "alice", "issue", "i1", "reader"));
        let held = held_by(&r, &m, "alice");
        assert!(held.contains("team", "a", "member"));
        assert!(held.contains("issue", "i1", "reader"));
        assert_eq!(members(&r, &m, "team", "a"), vec![("user:alice".into(), "member".into())]);
    }

    /// `issue/i1#reader ← team/t1#member ← … ← team/t<hops>#member ← alice`:
    /// alice holds reader on i1 through exactly `hops` set hops.
    fn chain(hops: usize) -> Mem {
        const TEAMS: [&str; 6] = ["t1", "t2", "t3", "t4", "t5", "t6"];
        let mut rows = vec![via("issue", "i1", "reader", "team", TEAMS[0], "member")];
        for w in TEAMS[..hops].windows(2) {
            rows.push(via("team", w[0], "member", "team", w[1], "member"));
        }
        rows.push(direct("team", TEAMS[hops - 1], "member", "alice"));
        Mem(rows)
    }

    #[test]
    fn the_depth_bound_holds_hop_four_and_refuses_hop_five() {
        assert_eq!(MAX_SET_HOPS, 4);
        let r = reg();
        for hops in 1..=MAX_SET_HOPS {
            let m = chain(hops);
            assert!(holds(&r, &m, "alice", "issue", "i1", "reader"), "{hops} hops");
            assert!(held_by(&r, &m, "alice").contains("issue", "i1", "reader"), "{hops} hops");
            assert_eq!(members(&r, &m, "issue", "i1"), vec![("user:alice".into(), "reader".into())]);
        }
        // Hop 5 is past the bound: not held, and not an error.
        let m = chain(MAX_SET_HOPS + 1);
        assert!(!holds(&r, &m, "alice", "issue", "i1", "reader"));
        assert!(!held_by(&r, &m, "alice").contains("issue", "i1", "reader"));
        assert!(held_by(&r, &m, "alice").contains("team", "t1", "member"), "t1 is 4 hops");
        assert!(members(&r, &m, "issue", "i1").is_empty());
    }

    #[test]
    fn may_grant_honours_set_derived_rights() {
        let r = reg();
        let m = Mem(vec![
            via("issue", "i1", "admin", "team", "t1", "member"),
            direct("team", "t1", "member", "alice"),
            via(KIND_RESOURCE, "service", "provisioner", "team", "ops", "member"),
            direct("team", "ops", "member", "olga"),
        ]);
        // admin grants admin, and through triager, reader.
        assert!(may_grant(&r, &m, "alice", "issue", "i1", "reader"));
        assert!(may_grant(&r, &m, "alice", "issue", "i1", "admin"));
        assert!(!may_grant(&r, &m, "alice", "issue", "i2", "reader"));
        assert!(!may_grant(&r, &m, "bob", "issue", "i1", "reader"));
        assert!(block_on(r.may_grant_any(&m, &PrincipalId::user("alice"), "issue", "i1")).unwrap());
        assert!(!block_on(r.may_grant_any(&m, &PrincipalId::user("bob"), "issue", "i1")).unwrap());
        // A kind-level relation held through a set grants on every resource of the kind.
        assert!(may_grant(&r, &m, "olga", "service", "svc-a", "owns"));
        assert!(!may_grant(&r, &m, "alice", "service", "svc-a", "owns"));
    }

    #[test]
    fn held_by_and_members_flatten_sets_and_fold_the_closure() {
        let r = reg();
        let m = Mem(vec![
            via("issue", "i1", "admin", "team", "t1", "owner"),
            via("issue", "i1", "reader", "team", "t1", "member"),
            direct("team", "t1", "owner", "olga"),
            direct("team", "t1", "member", "alice"),
            direct("issue", "i1", "reader", "bob"),
            direct(KIND_RESOURCE, "service", "provisioner", "olga"),
        ]);
        let held: Vec<_> = held_by(&r, &m, "olga")
            .iter()
            .map(|(k, i, rel)| format!("{k}/{i}#{rel}"))
            .collect();
        assert_eq!(
            held,
            [
                "issue/i1#admin",
                "issue/i1#reader",
                "issue/i1#triager",
                "kind/service#provisioner",
                "team/t1#member",
                "team/t1#owner",
            ]
        );
        let pairs = |v: &[(&str, &str)]| -> Vec<(String, String)> {
            v.iter().map(|(p, r)| ((*p).into(), (*r).into())).collect()
        };
        assert_eq!(
            members(&r, &m, "issue", "i1"),
            pairs(&[
                ("user:alice", "reader"),
                ("user:bob", "reader"),
                ("user:olga", "admin"),
                ("user:olga", "reader"),
                ("user:olga", "triager"),
            ])
        );
    }

    const USERS: [&str; 3] = ["u1", "u2", "u3"];
    const RESOURCES: [(&str, &str); 8] = [
        ("team", "a"),
        ("team", "b"),
        ("team", "c"),
        ("team", "d"),
        ("team", "e"),
        ("issue", "i1"),
        ("issue", "i2"),
        ("node", "n1"),
    ];
    fn relations(kind: &str) -> &'static [&'static str] {
        match kind {
            "team" => &["owner", "member"],
            "issue" => &["reader", "triager", "admin"],
            _ => &["owns"],
        }
    }

    /// `count` random small graphs over [`RESOURCES`] and [`USERS`] from a
    /// fixed seed: cycles, chains past the bound, a no-schema kind, and ~10%
    /// revoked rows.
    fn random_graphs(count: usize) -> Vec<Mem> {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut rand = move |n: usize| -> usize {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % n as u64) as usize
        };
        (0..count)
            .map(|_| {
                let mut rows = Vec::new();
                for _ in 0..(4 + rand(12)) {
                    let (kind, id) = RESOURCES[rand(RESOURCES.len())];
                    let rel = relations(kind)[rand(relations(kind).len())];
                    let subject = if rand(3) == 0 {
                        PrincipalId::user(USERS[rand(USERS.len())]).into()
                    } else {
                        let (sk, si) = RESOURCES[rand(RESOURCES.len())];
                        Subject::set(sk, si, relations(sk)[rand(relations(sk).len())])
                    };
                    rows.push(Row(kind, id, rel, rand(10) != 0, subject));
                }
                Mem(rows)
            })
            .collect()
    }

    /// The up-walk and both down-walks must agree on every question, cycles
    /// and over-deep chains included.
    #[test]
    fn up_and_down_walks_agree_on_random_graphs() {
        let r = reg();
        // Holdings with no direct tuple on the resource: only sets explain them.
        let mut set_derived = 0;
        for m in random_graphs(300) {
            let members_of: HashMap<_, _> =
                RESOURCES.iter().map(|&(k, i)| ((k, i), members(&r, &m, k, i))).collect();
            for user in USERS {
                let held = held_by(&r, &m, user);
                for &(kind, id) in &RESOURCES {
                    for &rel in relations(kind) {
                        let down = holds(&r, &m, user, kind, id, rel);
                        assert_eq!(down, held.contains(kind, id, rel), "{user} {kind}/{id}#{rel}");
                        let listed = members_of[&(kind, id)]
                            .contains(&(format!("user:{user}"), rel.to_owned()));
                        assert_eq!(down, listed, "members {user} {kind}/{id}#{rel}");
                        let p = PrincipalId::user(user);
                        let direct = m.0.iter().any(|t| {
                            t.0 == kind && t.1 == id && t.3 && t.4.principal() == Some(&p)
                        });
                        if down && !direct {
                            set_derived += 1;
                        }
                    }
                }
            }
        }
        assert!(set_derived > 100, "the graphs barely exercise sets: {set_derived}");
    }

    /// R732-F4: `via` names the resources of a member's own direct tuples the
    /// relation derives from — the child itself for a direct member, the
    /// parent for an inherited one, both when both hold.
    #[test]
    fn members_carry_the_direct_tuples_they_derive_from() {
        let r = reg();
        let m = Mem(vec![
            via("team", "child", "member", "team", "parent", "member"),
            direct("team", "parent", "member", "alice"),
            direct("team", "parent", "owner", "bob"),
            direct("team", "child", "member", "bob"),
            direct("team", "child", "owner", "carol"),
            // Revoked: confers nothing, so dave is no member.
            Row("team", "child", "owner", false, PrincipalId::user("dave").into()),
        ]);
        let v = |s: &[&str]| -> Vec<String> { s.iter().map(|x| (*x).to_owned()).collect() };
        assert_eq!(
            members_via(&r, &m, "team", "child"),
            vec![
                ("user:alice#member".to_owned(), v(&["team/parent"])),
                ("user:bob#member".to_owned(), v(&["team/child", "team/parent"])),
                ("user:carol#member".to_owned(), v(&["team/child"])),
                ("user:carol#owner".to_owned(), v(&["team/child"])),
            ]
        );
    }

    /// The property a snapshot's revocation mask rests on: revoking a user's
    /// direct tuples on every `via` resource ends `(user, relation)`, and
    /// sparing any one of them keeps it — over the same random graphs.
    #[test]
    fn via_is_exactly_the_direct_tuples_whose_loss_ends_a_member() {
        let r = reg();
        let without = |m: &Mem, user: &PrincipalId, gone: &[&(String, String)]| -> Mem {
            Mem(m
                .0
                .iter()
                .cloned()
                .map(|mut t| {
                    let hit = gone.iter().any(|(k, i)| t.0 == k && t.1 == i);
                    if hit && t.4.principal() == Some(user) {
                        t.3 = false;
                    }
                    t
                })
                .collect())
        };
        let mut multi_via = 0;
        for m in random_graphs(300) {
            for &(kind, id) in &RESOURCES {
                for member in block_on(r.members(&m, kind, id)).unwrap() {
                    let (p, rel) = (&member.principal, member.relation.as_str());
                    assert!(!member.via.is_empty());
                    let all: Vec<_> = member.via.iter().collect();
                    let gone = without(&m, p, &all);
                    let still = block_on(r.holds(&gone, p, kind, id, rel)).unwrap();
                    assert!(!still, "{p} {kind}/{id}#{rel} survives losing every via {all:?}");
                    if all.len() > 1 {
                        multi_via += 1;
                    }
                    for spared in &all {
                        let rest: Vec<_> = all.iter().copied().filter(|v| v != spared).collect();
                        let kept = without(&m, p, &rest);
                        let held = block_on(r.holds(&kept, p, kind, id, rel)).unwrap();
                        assert!(held, "{p} {kind}/{id}#{rel} lost although {spared:?} was spared");
                    }
                }
            }
        }
        assert!(multi_via > 20, "the graphs barely exercise multi-via members: {multi_via}");
    }

    #[test]
    fn subject_serializes_flat_in_column_names() {
        let p: Subject = PrincipalId::user("alice").into();
        assert_eq!(serde_json::to_value(&p).unwrap(), serde_json::json!({"principal_id": "user:alice"}));
        let s = Subject::set("namespace", "n1", "member");
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"subject_kind": "namespace", "subject_id": "n1", "subject_relation": "member"})
        );
        assert_eq!(serde_json::from_value::<Subject>(v).unwrap(), s);
        assert_eq!(s.to_string(), "namespace/n1#member");
        assert_eq!(s.as_set(), Some(("namespace", "n1", "member")));
        assert_eq!(p.principal(), Some(&PrincipalId::user("alice")));
    }

    #[test]
    fn subject_requires_exactly_one_form() {
        for bad in [
            serde_json::json!({}),
            serde_json::json!({"subject_kind": "namespace", "subject_id": "n1"}),
            serde_json::json!({
                "principal_id": "user:alice",
                "subject_kind": "namespace", "subject_id": "n1", "subject_relation": "member"
            }),
        ] {
            assert!(serde_json::from_value::<Subject>(bad.clone()).is_err(), "{bad}");
        }
        assert_eq!(
            Subject::from_parts(Some(PrincipalId::user("a")), Some("k".into()), None, None),
            Err(SubjectFormError)
        );
    }

    fn leak(rels: Vec<RelationDef>) -> &'static [RelationDef] {
        Box::leak(rels.into_boxed_slice())
    }

    fn one(rels: &'static [RelationDef]) -> Result<SchemaRegistry, SchemaError> {
        SchemaRegistry::build(
            &[ResourceSchema { kind: "k", relations: rels, kind_relations: &[] }],
            &scopes(),
        )
    }

    fn rel(name: &'static str, implies: &'static [&'static str]) -> RelationDef {
        RelationDef { name, membership: true, implies, scopes: &[], grants: &[] }
    }

    #[test]
    fn build_refuses_bad_schemas() {
        assert!(matches!(
            one(leak(vec![rel("a", &["b"]), rel("b", &["a"])])),
            Err(SchemaError::Cycle { .. })
        ));
        assert!(matches!(one(leak(vec![rel("a", &["a"])])), Err(SchemaError::Cycle { .. })));
        assert!(matches!(
            one(leak(vec![rel("a", &["zz"])])),
            Err(SchemaError::UnknownTarget { .. })
        ));
        assert!(matches!(
            one(leak(vec![RelationDef { name: "a", membership: true, implies: &[], scopes: &[], grants: &["zz"] }])),
            Err(SchemaError::UnknownTarget { .. })
        ));
        assert!(matches!(
            one(leak(vec![rel("a", &[]), rel("a", &[])])),
            Err(SchemaError::DuplicateRelation { .. })
        ));
        static UNREG: [Scope; 1] = [Scope::from_static("other:thing")];
        assert!(matches!(
            one(leak(vec![RelationDef { name: "a", membership: true, implies: &[], scopes: &UNREG, grants: &[] }])),
            Err(SchemaError::UnregisteredScope { .. })
        ));
        assert!(matches!(
            SchemaRegistry::build(&[ISSUE, ISSUE], &scopes()),
            Err(SchemaError::DuplicateKind(_))
        ));
        assert!(matches!(
            SchemaRegistry::build(
                &[ResourceSchema { kind: KIND_RESOURCE, relations: &[], kind_relations: &[] }],
                &scopes()
            ),
            Err(SchemaError::ReservedKind(_))
        ));
        // diamond is fine (not a cycle)
        assert!(one(leak(vec![
            rel("a", &["b", "c"]),
            rel("b", &["d"]),
            rel("c", &["d"]),
            rel("d", &[])
        ]))
        .is_ok());
        let _: &[ScopeDef] = DEFS;
    }
}
