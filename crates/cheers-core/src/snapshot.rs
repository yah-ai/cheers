//! The **membership snapshot** wire type (R732-F4; noisetable W235 §0.1, §2.4,
//! §5, C4).
//!
//! An offline edge admits a member of a namespace (or any resource) by the
//! issuer's signed answer to "who holds what on it": a [`SetSnapshot`]. It is
//! the result of the online lookup, signed — membership never enters the
//! session token. Like the standing node binding it has **no `exp`** (W235
//! §0.1: offline admission lasts until revoked). It stops counting in exactly
//! two ways:
//!
//! - **supersession** — the edge has seen a snapshot of the same resource with
//!   a higher [`epoch`](SetSnapshot::epoch);
//! - **revocation** — for one member: a [`Revoked::Membership`](crate::Revoked)
//!   entry on every resource in the member's [`via`](SnapshotMember::via)
//!   (the rule below).
//!
//! `refresh_after` only tells the holder when to fetch a fresher snapshot if
//! the issuer is reachable; an edge never refuses a snapshot for age.
//!
//! # Epoch
//!
//! `epoch` is the issuer's **store-wide** `ownership_version`: one counter
//! that every ownership write advances to `max(v + 1, now)` in the write's own
//! transaction. Store-wide rather than per resource because subject sets make
//! one resource's flattened membership depend on others' tuples — removing
//! someone from a parent namespace changes the child's members without
//! touching a child row. With one counter, two snapshots of a resource at the
//! same epoch have the same members, so an edge may treat an equal epoch as
//! unchanged. The issuer mints from a closure walk bracketed by two reads of
//! the version and retries if they differ.
//!
//! # Members
//!
//! Members are closure-expanded and sets are flattened: one
//! [`SnapshotMember`] per relation a **principal** effectively holds on the
//! resource (an owner is listed as owner, admin, publisher, member and guest),
//! so an edge checks `member` with an exact lookup and never needs the schema.
//! Users and [`Key`](crate::PrincipalKind::Key) principals (knock.md) are
//! listed in their wire form (`user:alice`, `key:<base64url>`); services and
//! camps are not. Sorted by `(principal, relation)`.
//!
//! # The revocation mask (accepted rule)
//!
//! `via` lists every resource where the user's own **direct** tuple sits and
//! from which the relation derives: the resource itself for a direct member,
//! the parent namespace for one who holds it through `child#guest ←
//! parent#member`. The issuer records `Revoked::Membership { kind, id,
//! principal, at_epoch }` when a principal's last live direct tuple on `(kind, id)` is
//! revoked, with `at_epoch` = the ownership version that removal produced.
//! An edge drops a member entry iff **every** `(kind, id)` in its `via` is
//! revoked for that user at an `at_epoch` above the snapshot's epoch. So a
//! user removed from the parent org but still a direct member of the child
//! stays admitted.
//!
//! Only the loss of a user's last direct tuple on a resource is recorded.
//! **Structural changes** — a subject-set tuple removed, one of several
//! direct relations revoked (a demotion) — reach an edge only through a newer
//! snapshot. That is the accepted rule: revocation entries end a person's
//! place, snapshots carry the shape.
//!
//! # Wire shape
//!
//! The PASETO v4.public payload is the JSON of [`SetSnapshot`], signed with
//! [`SetSnapshot::IMPLICIT_ASSERTION`](crate::SignedArtifact) and a
//! `{"kid": ...}` footer:
//!
//! ```json
//! {"issuer":"https://cheers.example","kind":"namespace","id":"museum-ed",
//!  "epoch":1791234567,"members":[
//!    {"principal":"user:alice","relation":"guest","via":[["namespace","museum"],["namespace","museum-ed"]]},
//!    {"principal":"user:alice","relation":"member","via":[["namespace","museum-ed"]]}],
//!  "revocation_keys":[{"kind":"namespace","id":"museum","key":"..."},
//!    {"kind":"namespace","id":"museum-ed","key":"..."}],
//!  "iat":1791234567,"refresh_after":1791839367}
//! ```
//!
//! # Revocation keys (R732-T10)
//!
//! Published membership entries are tagged, not plaintext
//! ([`crate::revocation`], "Membership privacy"). `revocation_keys` carries the
//! [`RevocationKey`] of the snapshot's own resource and of every resource any
//! member's `via` names, so an edge can compute the tag of every `(kind, id,
//! principal)` the mask needs. The keys are secret: a snapshot is never served on
//! an unauthenticated route.

use serde::{Deserialize, Serialize};

use crate::admission::AdmissionPolicy;
use crate::artifact::SignedArtifact;
use crate::lease::Lease;
use crate::principal::PrincipalId;
use crate::revocation::RevocationKey;

/// The membership-revocation key of one resource (module docs, "Revocation
/// keys").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceRevocationKey {
    pub kind: String,
    pub id: String,
    pub key: RevocationKey,
}

/// One relation one principal effectively holds on the snapshot's resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotMember {
    /// Any principal kind: a user, or a [`Key`](crate::PrincipalKind::Key)
    /// admitted with no account. Wire form `user:alice` / `key:<base64url>`.
    pub principal: PrincipalId,
    /// A relation on the snapshot's resource, closure already folded in.
    pub relation: String,
    /// `(kind, id)` of every resource where `principal`'s own direct tuple sits and
    /// from which `relation` derives (module docs, "The revocation mask").
    /// Sorted, never empty.
    pub via: Vec<(String, String)>,
    /// The lease of a guest admitted for a while (R734-F4): the `Admit`'s
    /// lease, kept by the reconciled tuple. `None` for a standing member, and
    /// then omitted from the wire, so snapshots without leased members are
    /// byte-identical to those minted before leases existed. An edge drops
    /// the entry once it reads `Expired` and surfaces `Warning` before that.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<Lease>,
}

/// An issuer's signed membership of one resource at one ownership epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetSnapshot {
    /// The issuer that signed it; must equal the signing key's owner.
    pub issuer: String,
    /// The resource's kind, e.g. `namespace`.
    pub kind: String,
    /// The resource's id.
    pub id: String,
    /// The issuer's store-wide ownership version the members were read at. A
    /// higher epoch for the same resource supersedes this snapshot.
    pub epoch: u64,
    /// Sorted by `(principal, relation)`.
    pub members: Vec<SnapshotMember>,
    /// The key of the resource itself and of every resource in any member's
    /// `via` (module docs, "Revocation keys"). Sorted by `(kind, id)`.
    pub revocation_keys: Vec<ResourceRevocationKey>,
    /// When it was minted (Unix seconds). Informational: nothing orders or
    /// expires snapshots by it.
    pub iat: i64,
    /// When the holder should fetch a fresher snapshot if it can reach the
    /// issuer ([`Lease`]). **Advisory**: a snapshot past it still verifies. On
    /// the wire it flattens to `refresh_after` (and `exp`, when set).
    /// The resource's admission policy (R734-F3, `knock.md` "The dial").
    /// `None` reads as closed for offline admits, and is omitted from the
    /// wire so a snapshot of a resource with no policy row is byte-identical
    /// to one minted before policies existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<AdmissionPolicy>,
    #[serde(flatten)]
    pub lease: Lease,
}

impl SetSnapshot {
    /// Build a snapshot, sorting `members` by `(principal, relation)`, each
    /// member's `via`, and `revocation_keys` by `(kind, id)`, so equal
    /// memberships always encode to equal bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        issuer: impl Into<String>,
        kind: impl Into<String>,
        id: impl Into<String>,
        epoch: u64,
        mut members: Vec<SnapshotMember>,
        mut revocation_keys: Vec<ResourceRevocationKey>,
        iat: i64,
        lease: Lease,
    ) -> Self {
        for m in &mut members {
            m.via.sort();
            m.via.dedup();
        }
        members.sort_by(|a, b| (&a.principal, &a.relation).cmp(&(&b.principal, &b.relation)));
        revocation_keys.sort_by(|a, b| (&a.kind, &a.id).cmp(&(&b.kind, &b.id)));
        revocation_keys.dedup_by(|later, kept| later.kind == kept.kind && later.id == kept.id);
        Self {
            issuer: issuer.into(),
            kind: kind.into(),
            id: id.into(),
            epoch,
            members,
            revocation_keys,
            iat,
            policy: None,
            lease,
        }
    }

    /// Attach the resource's admission policy.
    pub fn with_policy(mut self, policy: Option<AdmissionPolicy>) -> Self {
        self.policy = policy;
        self
    }

    /// `true` if the snapshot lists `principal` with `relation`. Ignores
    /// revocation — an edge asks `cheers_verify::VerifiedSnapshot::holds`.
    pub fn lists(&self, principal: &PrincipalId, relation: &str) -> bool {
        self.members.iter().any(|m| &m.principal == principal && m.relation == relation)
    }

    /// The revocation key the snapshot carries for `(kind, id)`.
    pub fn revocation_key(&self, kind: &str, id: &str) -> Option<&RevocationKey> {
        self.revocation_keys
            .binary_search_by(|k| (k.kind.as_str(), k.id.as_str()).cmp(&(kind, id)))
            .ok()
            .map(|i| &self.revocation_keys[i].key)
    }
}

impl SignedArtifact for SetSnapshot {
    const IMPLICIT_ASSERTION: &'static [u8] = b"urn:cheers:artifact:set-snapshot:v1";

    fn issuer(&self) -> &str {
        &self.issuer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease::LeaseState;
    use crate::{RevocationSet, StandingBinding};

    fn member(user: &str, relation: &str, via: &[(&str, &str)]) -> SnapshotMember {
        SnapshotMember {
            principal: PrincipalId::user(user),
            relation: relation.into(),
            via: via.iter().map(|(k, i)| ((*k).into(), (*i).into())).collect(),
            lease: None,
        }
    }

    fn key(kind: &str, id: &str, b: u8) -> ResourceRevocationKey {
        ResourceRevocationKey { kind: kind.into(), id: id.into(), key: RevocationKey::from_bytes([b; 32]) }
    }

    fn snapshot() -> SetSnapshot {
        SetSnapshot::new(
            "https://c.example",
            "namespace",
            "ed",
            42,
            vec![
                member("bob", "member", &[("namespace", "ed")]),
                member("alice", "member", &[("namespace", "ed")]),
                member("alice", "guest", &[("namespace", "ed"), ("namespace", "museum")]),
            ],
            vec![key("namespace", "museum", 2), key("namespace", "ed", 1)],
            1_000,
            Lease::new(1_000, 2_000, None).unwrap(),
        )
    }

    #[test]
    fn wire_shape_has_no_exp_and_round_trips() {
        let v = serde_json::to_value(snapshot()).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "issuer": "https://c.example",
                "kind": "namespace",
                "id": "ed",
                "epoch": 42,
                "members": [
                    {"principal": "user:alice", "relation": "guest", "via": [["namespace", "ed"], ["namespace", "museum"]]},
                    {"principal": "user:alice", "relation": "member", "via": [["namespace", "ed"]]},
                    {"principal": "user:bob", "relation": "member", "via": [["namespace", "ed"]]},
                ],
                "revocation_keys": [
                    {"kind": "namespace", "id": "ed", "key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"},
                    {"kind": "namespace", "id": "museum", "key": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"},
                ],
                "iat": 1_000,
                "refresh_after": 2_000,
            })
        );
        let back: SetSnapshot = serde_json::from_value(v).unwrap();
        assert_eq!(back, snapshot());
    }

    #[test]
    fn new_sorts_members_and_via_deterministically() {
        let a = snapshot();
        let mut shuffled = a.members.clone();
        shuffled.reverse();
        shuffled[0].via.reverse();
        let mut keys = a.revocation_keys.clone();
        keys.reverse();
        let b = SetSnapshot::new(&a.issuer, &a.kind, &a.id, a.epoch, shuffled, keys, a.iat, a.lease);
        assert_eq!(serde_json::to_vec(&a).unwrap(), serde_json::to_vec(&b).unwrap());
        assert!(a.lists(&PrincipalId::user("alice"), "guest"));
        assert!(!a.lists(&PrincipalId::user("bob"), "guest"));
        assert_eq!(a.revocation_key("namespace", "museum"), Some(&RevocationKey::from_bytes([2; 32])));
        assert_eq!(a.revocation_key("namespace", "nope"), None);
    }

    #[test]
    fn refresh_after_is_advisory() {
        let s = snapshot();
        assert_eq!(s.lease.state_at(1_999), LeaseState::Current);
        assert_eq!(s.lease.state_at(2_000), LeaseState::Warning { exp: None });
    }

    #[test]
    fn key_principal_is_a_member_in_wire_form() {
        let k = PrincipalId::from_public_key(&[9; 32]);
        let mut members = snapshot().members;
        members.push(SnapshotMember { principal: k.clone(), relation: "guest".into(), via: vec![("namespace".into(), "ed".into())], lease: None });
        let s = SetSnapshot::new("https://c.example", "namespace", "ed", 42, members, vec![key("namespace", "ed", 1)], 1_000, Lease::new(1_000, 2_000, None).unwrap());
        assert!(s.lists(&k, "guest"));
        assert!(!s.lists(&PrincipalId::user(k.id.clone()), "guest"));
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["members"][3]["principal"], serde_json::json!(k.to_string()));
        assert_eq!(serde_json::from_value::<SetSnapshot>(v).unwrap(), s);
    }

    /// Bytes the pre-`Lease` struct (`refresh_after: i64` as its last field)
    /// serialized to; the flattened lease must reproduce them exactly.
    const GOLDEN: &str = r#"{"issuer":"https://c.example","kind":"namespace","id":"ed","epoch":42,"members":[],"revocation_keys":[],"iat":1000,"refresh_after":2000}"#;

    #[test]
    fn flattened_lease_is_byte_identical_to_the_old_wire() {
        let s = SetSnapshot::new("https://c.example", "namespace", "ed", 42, vec![], vec![], 1_000, Lease::new(1_000, 2_000, None).unwrap());
        assert_eq!(serde_json::to_string(&s).unwrap(), GOLDEN);
        let back: SetSnapshot = serde_json::from_str(GOLDEN).unwrap();
        assert_eq!(back, s);
        assert_eq!(serde_json::to_string(&back).unwrap(), GOLDEN);
    }

    #[test]
    fn exp_rides_the_flattened_lease() {
        let lease = Lease::new(1_000, 1_500, Some(2_000)).unwrap();
        let s = SetSnapshot::new("i", "namespace", "ed", 1, vec![], vec![], 1_000, lease);
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.ends_with(r#""iat":1000,"refresh_after":1500,"exp":2000}"#), "{json}");
        assert_eq!(serde_json::from_str::<SetSnapshot>(&json).unwrap(), s);
    }

    #[test]
    fn policy_rides_the_wire_only_when_present() {
        use crate::admission::AdmissionMode;
        let s = SetSnapshot::new("https://c.example", "namespace", "ed", 42, vec![], vec![], 1_000, Lease::new(1_000, 2_000, None).unwrap());
        assert_eq!(serde_json::to_string(&s.clone().with_policy(None)).unwrap(), GOLDEN);
        let p = AdmissionPolicy::new(AdmissionMode::Knock, "guest");
        let with = s.with_policy(Some(p.clone()));
        let json = serde_json::to_string(&with).unwrap();
        assert!(json.contains(r#""policy":{"mode":"knock","floor":"guest""#), "{json}");
        let back: SetSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.policy, Some(p));
        assert_eq!(back, with);
    }

    #[test]
    fn a_member_lease_rides_the_wire_only_when_present() {
        // The pre-lease member wire, as F1 left it.
        let golden = r#"{"principal":"user:alice","relation":"guest","via":[["namespace","ed"]]}"#;
        let m = member("alice", "guest", &[("namespace", "ed")]);
        assert_eq!(serde_json::to_string(&m).unwrap(), golden);
        assert_eq!(serde_json::from_str::<SnapshotMember>(golden).unwrap(), m);
        let leased = SnapshotMember { lease: Some(Lease::new(1_000, 1_500, Some(2_000)).unwrap()), ..m };
        let json = serde_json::to_string(&leased).unwrap();
        assert!(json.ends_with(r#""lease":{"refresh_after":1500,"exp":2000}}"#), "{json}");
        assert_eq!(serde_json::from_str::<SnapshotMember>(&json).unwrap(), leased);
    }

    #[test]
    fn implicit_assertion_is_its_own() {
        assert_ne!(SetSnapshot::IMPLICIT_ASSERTION, RevocationSet::IMPLICIT_ASSERTION);
        assert_ne!(SetSnapshot::IMPLICIT_ASSERTION, StandingBinding::IMPLICIT_ASSERTION);
    }
}
