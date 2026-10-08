//! [`SnapshotVerifier`] — the edge check for a membership snapshot (R732-F4;
//! noisetable W235 §0.1, §5).
//!
//! A [`SetSnapshot`] has no expiry. The edge accepts one when:
//!
//! 1. it is signed for the trusted issuer ([`IssuerTrust`]: a pinned key, or a
//!    JWKS **issuer**-role key) under the snapshot's own implicit assertion,
//!    so no access token, standing binding or revocation set verifies here and
//!    no snapshot verifies as one of them;
//! 2. no snapshot of the same resource with a higher epoch has been seen
//!    ([`SnapshotLedger`]).
//!
//! It then **admits** each member entry unless the revocation set masks it:
//! an entry is dropped iff, for every `(kind, id)` in its `via`,
//! [`RevocationReader::is_membership_revoked`]`(key, kind, id, user, epoch)`
//! holds, `key` being the snapshot's own [`RevocationKey`] for `(kind, id)`
//! (`cheers_core::snapshot`, "The revocation mask"). A user removed from the
//! parent org but still a direct member of the child stays admitted. An entry
//! with an empty `via` — which cheers never mints — is dropped, since nothing
//! could ever revoke it.
//!
//! `refresh_after` is advisory: it sets [`VerifiedSnapshot::lease`] and
//! never refuses. The clock is used for nothing else.
//!
//! # Supersession
//!
//! The epoch is the issuer's store-wide ownership version, so an equal epoch
//! means equal members and a higher one is newer. The ledger keeps the highest
//! epoch seen per `(kind, id)` from **any** genuine snapshot — presented, or
//! heard by gossip ([`SnapshotVerifier::adopt`]) — and never lowers it.
//!
//! # Offline restart
//!
//! As for standing bindings (`crate::standing`, "Offline restart"): persist
//! [`IssuerTrust::export`], [`SnapshotLedger::export`] and
//! `ReplicatedRevocations::export` beside the held snapshot tokens and rebuild
//! from them at boot. The key rotation rule there covers snapshots too.

use std::collections::{BTreeMap, HashMap};
use std::sync::{PoisonError, RwLock};

use serde::{Deserialize, Serialize};

use cheers_core::{LeaseError, LeaseState, PrincipalId, SetSnapshot, SnapshotMember, StoreError};

use crate::artifact::IssuerTrust;
use crate::key_set::VerifyError;
use crate::revocation::RevocationReader;
use crate::standing::ForeignLedger;

/// Why [`SnapshotVerifier::verify_snapshot_at`] refused a snapshot. A masked
/// member is not a refusal — it is absent from [`VerifiedSnapshot::admitted`].
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    /// Not a membership snapshot signed for the trusted issuer: bad signature,
    /// another artifact or an access token offered as one, a non-issuer-role
    /// key, a foreign issuer.
    #[error("membership snapshot refused: {0}")]
    Verify(#[from] VerifyError),

    /// A snapshot of the same resource with a higher epoch exists.
    #[error("snapshot of {kind}/{id} is superseded: epoch {offered} is below {newest}")]
    Superseded { kind: String, id: String, newest: u64, offered: u64 },

    /// A member's `via` names a resource whose revocation key the snapshot
    /// does not carry, so its entries could not be tested. Refused rather than
    /// admitted: a missing key would make revocation fail open (R732-T10).
    #[error("snapshot carries no revocation key for {kind}/{id}")]
    MissingRevocationKey { kind: String, id: String },

    /// Signed, but its lease breaks the invariant (`cheers_core::Lease`).
    #[error("membership snapshot refused: {0}")]
    Lease(#[from] LeaseError),

    /// The revocation reader failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// An accepted snapshot and the members it still admits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSnapshot {
    /// Exactly as signed.
    pub snapshot: SetSnapshot,
    /// `snapshot.members` minus every entry the revocation set masks, in the
    /// same order.
    pub admitted: Vec<SnapshotMember>,
    /// The snapshot's lease at the verification instant: on `Warning`, fetch a
    /// fresher snapshot when the issuer is reachable. Advisory — the snapshot
    /// was accepted either way (it carries no `exp` today).
    pub lease: LeaseState,
}

impl VerifiedSnapshot {
    /// `true` if an admitted entry gives `principal` exactly `relation`.
    /// Members are closure-expanded, so "is a member" is
    /// `holds(principal, "member")`. Any principal kind, a `Key` included.
    pub fn holds(&self, principal: &PrincipalId, relation: &str) -> bool {
        self.admitted.iter().any(|m| &m.principal == principal && m.relation == relation)
    }

    /// Where `principal`'s `relation` stands: `None` for a standing member
    /// (or none at all), the lease state for a leased guest, so an edge can
    /// surface `Warning` on reconciled guests (R734-F4).
    pub fn member_lease(&self, principal: &PrincipalId, relation: &str, now: i64) -> Option<LeaseState> {
        self.admitted
            .iter()
            .find(|m| &m.principal == principal && m.relation == relation)
            .and_then(|m| m.lease)
            .map(|l| l.state_at(now))
    }

    /// The admission policy this snapshot carries; `None` reads as closed.
    /// Feed it to [`cheers_core::evaluate_admit`] for every held `Admit`:
    /// the policy held now, not the one an `Admit` was minted under.
    pub fn admission_policy(&self) -> Option<&cheers_core::AdmissionPolicy> {
        self.snapshot.policy.as_ref()
    }
}

/// A persisted [`SnapshotLedger`]: the highest epoch seen per resource, as
/// `kind -> id -> epoch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotLedgerDoc {
    pub issuer: String,
    pub newest: BTreeMap<String, BTreeMap<String, u64>>,
}

/// The highest snapshot epoch seen per `(kind, id)`, for one issuer.
///
/// Like [`BindingLedger`](crate::BindingLedger) it holds only high-water
/// marks, needs no key to restore, and only ever rises: adopting a lower epoch
/// after a higher one, or importing an older export, cannot un-supersede.
#[derive(Debug)]
pub struct SnapshotLedger {
    issuer: String,
    newest: RwLock<HashMap<(String, String), u64>>,
}

impl SnapshotLedger {
    pub fn new(issuer: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            newest: RwLock::new(HashMap::new()),
        }
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The highest epoch seen for `(kind, id)`.
    pub fn newest(&self, kind: &str, id: &str) -> Option<u64> {
        self.newest
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(kind.to_owned(), id.to_owned()))
            .copied()
    }

    /// Record that a genuine snapshot of `(kind, id)` at `epoch` exists and
    /// return the resource's highest epoch afterwards. Never lowers it.
    pub fn observe(&self, kind: &str, id: &str, epoch: u64) -> u64 {
        let mut newest = self.newest.write().unwrap_or_else(PoisonError::into_inner);
        let held = newest.entry((kind.to_owned(), id.to_owned())).or_insert(epoch);
        *held = (*held).max(epoch);
        *held
    }

    /// Every high-water mark, for an edge to persist.
    pub fn export(&self) -> SnapshotLedgerDoc {
        let mut out: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
        for ((kind, id), epoch) in self.newest.read().unwrap_or_else(PoisonError::into_inner).iter() {
            out.entry(kind.clone()).or_default().insert(id.clone(), *epoch);
        }
        SnapshotLedgerDoc {
            issuer: self.issuer.clone(),
            newest: out,
        }
    }

    /// Merge a persisted ledger in, keeping the higher epoch per resource.
    pub fn import(&self, doc: &SnapshotLedgerDoc) -> Result<(), ForeignLedger> {
        if doc.issuer != self.issuer {
            return Err(ForeignLedger {
                expected: self.issuer.clone(),
                got: doc.issuer.clone(),
            });
        }
        for (kind, ids) in &doc.newest {
            for (id, epoch) in ids {
                self.observe(kind, id, *epoch);
            }
        }
        Ok(())
    }
}

/// The edge facade for membership snapshots: trust, revocation replica and
/// supersession ledger for one issuer. Holds no minter.
pub struct SnapshotVerifier<Rd> {
    trust: IssuerTrust,
    revoked: Rd,
    ledger: SnapshotLedger,
}

impl<Rd> std::fmt::Debug for SnapshotVerifier<Rd> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotVerifier")
            .field("trust", &self.trust)
            .field("ledger", &self.ledger)
            .finish_non_exhaustive()
    }
}

impl<Rd: RevocationReader> SnapshotVerifier<Rd> {
    /// A verifier with an empty ledger; [`import`](SnapshotLedger::import) a
    /// persisted one through [`ledger`](Self::ledger) after a restart.
    pub fn new(trust: IssuerTrust, revoked: Rd) -> Self {
        let ledger = SnapshotLedger::new(trust.issuer());
        Self { trust, revoked, ledger }
    }

    pub fn trust(&self) -> &IssuerTrust {
        &self.trust
    }

    pub fn revocations(&self) -> &Rd {
        &self.revoked
    }

    pub fn ledger(&self) -> &SnapshotLedger {
        &self.ledger
    }

    /// Verify a snapshot that arrived by gossip (or the edge's own persisted
    /// one at boot) and record its epoch, so it supersedes older snapshots of
    /// its resource. Checks the signature only.
    pub async fn adopt(&self, token: &str) -> Result<SetSnapshot, VerifyError> {
        let snapshot: SetSnapshot = self.trust.verify(token).await?;
        self.ledger.observe(&snapshot.kind, &snapshot.id, snapshot.epoch);
        Ok(snapshot)
    }

    /// Accept `token` as a membership snapshot and work out who it still
    /// admits.
    ///
    /// In order: signature (recording the epoch in the ledger), supersession,
    /// then one revocation read per member `via` — the only I/O. `now`
    /// decides [`VerifiedSnapshot::lease`] and nothing else: there is no
    /// expiry.
    pub async fn verify_snapshot_at(&self, token: &str, now: i64) -> Result<VerifiedSnapshot, SnapshotError> {
        let snapshot: SetSnapshot = self.trust.verify(token).await?;
        snapshot.lease.validate(snapshot.iat)?;
        let newest = self.ledger.observe(&snapshot.kind, &snapshot.id, snapshot.epoch);
        if newest > snapshot.epoch {
            return Err(SnapshotError::Superseded {
                kind: snapshot.kind,
                id: snapshot.id,
                newest,
                offered: snapshot.epoch,
            });
        }
        let mut admitted = Vec::with_capacity(snapshot.members.len());
        for member in &snapshot.members {
            // A leased guest past its exp is gone, whatever snapshot still
            // lists it (R734-F4).
            if member.lease.is_some_and(|l| l.state_at(now) == LeaseState::Expired) {
                continue;
            }
            if !self.is_masked(&snapshot, member).await? {
                admitted.push(member.clone());
            }
        }
        let lease = snapshot.lease.state_at(now);
        Ok(VerifiedSnapshot { snapshot, admitted, lease })
    }

    /// The mask: every resource the entry derives from is revoked for its
    /// user above `epoch`. Stops at the first `via` still standing.
    async fn is_masked(&self, snapshot: &SetSnapshot, member: &SnapshotMember) -> Result<bool, SnapshotError> {
        for (kind, id) in &member.via {
            let key = snapshot.revocation_key(kind, id).ok_or_else(|| SnapshotError::MissingRevocationKey {
                kind: kind.clone(),
                id: id.clone(),
            })?;
            if !self.revoked.is_membership_revoked(key, kind, id, &member.principal, snapshot.epoch).await? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cheers_core::{Lease, UserId};
    use crate::jwks::{JwkKey, JwksDoc, KeySet};
    use crate::key_set::KeySetVerifier;
    use crate::public_verifier::PasetoV4PublicVerifier;
    use crate::revocation::{revocation_entry, test_revocation_key, ReplicatedRevocations};
    use crate::standing::{StandingError, StandingVerifier};
    use cheers_core::{
        Claims, DeviceBinding, DeviceId, KeyRole, McpClaims, PeerKey, PrincipalId, ResourceRevocationKey, RevocationSet, Revoked,
        SignedArtifact, StandingBinding, TokenVerifier,
    };
    use pasetors::keys::{AsymmetricKeyPair, AsymmetricSecretKey, Generate};
    use pasetors::version4::{PublicToken, V4};
    use std::sync::Arc;

    const ISS: &str = "https://cheers.test";
    const IAT: i64 = 1_000;
    /// Ten years on: far past any access-token window.
    const YEARS_LATER: i64 = IAT + 10 * 365 * 24 * 60 * 60;

    fn kp() -> AsymmetricKeyPair<V4> {
        AsymmetricKeyPair::<V4>::generate().unwrap()
    }

    fn pub_bytes(k: &AsymmetricKeyPair<V4>) -> [u8; 32] {
        k.public.as_bytes().try_into().unwrap()
    }

    fn sign_with(secret: &AsymmetricSecretKey<V4>, kid: &str, payload: &impl Serialize, ia: Option<&[u8]>) -> String {
        let body = serde_json::to_vec(payload).unwrap();
        let footer = format!(r#"{{"kid":"{kid}"}}"#);
        PublicToken::sign(secret, &body, Some(footer.as_bytes()), ia).unwrap()
    }

    fn member(user: &str, relation: &str, via: &[&str]) -> SnapshotMember {
        SnapshotMember {
            principal: PrincipalId::user(user),
            relation: relation.into(),
            via: via.iter().map(|i| ("namespace".to_owned(), (*i).to_owned())).collect(),
            lease: None,
        }
    }

    /// `ed` at `epoch`: alice is a guest only through the museum; bob is a
    /// direct member and also a guest through the museum.
    fn ed(epoch: u64) -> SetSnapshot {
        SetSnapshot::new(
            ISS,
            "namespace",
            "ed",
            epoch,
            vec![
                member("alice", "guest", &["museum"]),
                member("bob", "guest", &["ed", "museum"]),
                member("bob", "member", &["ed"]),
            ],
            ["ed", "museum"]
                .map(|id| ResourceRevocationKey {
                    kind: "namespace".into(),
                    id: id.into(),
                    key: test_revocation_key("namespace", id),
                })
                .to_vec(),
            IAT,
            Lease::new(IAT, IAT + 7 * 24 * 60 * 60, None).unwrap(),
        )
    }

    struct Rig {
        issuer: AsymmetricKeyPair<V4>,
        assertion: AsymmetricKeyPair<V4>,
        doc: JwksDoc,
        replica: Arc<ReplicatedRevocations>,
        edge: SnapshotVerifier<Arc<ReplicatedRevocations>>,
    }

    impl Rig {
        fn sign(&self, s: &SetSnapshot) -> String {
            sign_with(&self.issuer.secret, "iss-1", s, Some(SetSnapshot::IMPLICIT_ASSERTION))
        }

        fn revoke(&self, epoch: u64, revoked: Vec<Revoked>) {
            let entries = revoked.iter().map(|e| revocation_entry(e, test_revocation_key)).collect();
            let set = RevocationSet::new(ISS, epoch, entries);
            let token = sign_with(&self.issuer.secret, "iss-1", &set, Some(RevocationSet::IMPLICIT_ASSERTION));
            pollster::block_on(self.replica.adopt(&token)).unwrap();
        }

        fn verify(&self, token: &str, now: i64) -> Result<VerifiedSnapshot, SnapshotError> {
            pollster::block_on(self.edge.verify_snapshot_at(token, now))
        }

        fn admitted(&self, token: &str) -> Vec<String> {
            let ok = self.verify(token, IAT).unwrap();
            ok.admitted.iter().map(|m| format!("{}#{}", m.principal.id, m.relation)).collect()
        }
    }

    fn rig() -> Rig {
        let (issuer, assertion) = (kp(), kp());
        let doc = JwksDoc {
            keys: vec![
                JwkKey::ed25519("iss-1", &pub_bytes(&issuer), ISS, KeyRole::Issuer),
                JwkKey::ed25519("asr-1", &pub_bytes(&assertion), "svc:issues", KeyRole::Assertion),
            ],
        };
        let keys = KeySetVerifier::from_key_set(KeySet::from_doc(doc.clone()).unwrap());
        let trust = IssuerTrust::key_set(ISS, keys);
        let replica = Arc::new(ReplicatedRevocations::new(trust.clone()));
        Rig {
            edge: SnapshotVerifier::new(trust, replica.clone()),
            replica,
            issuer,
            assertion,
            doc,
        }
    }

    #[test]
    fn a_lease_past_its_midpoint_is_refused() {
        let r = rig();
        let mut v = serde_json::to_value(ed(10)).unwrap();
        v["refresh_after"] = (IAT + 600).into();
        v["exp"] = (IAT + 1_000).into();
        let forged: SetSnapshot = serde_json::from_value(v).unwrap();
        let err = r.verify(&r.sign(&forged), IAT).unwrap_err();
        assert!(matches!(err, SnapshotError::Lease(_)), "got {err:?}");
    }

    #[test]
    fn a_snapshot_verifies_years_after_iat_and_past_refresh_after() {
        let r = rig();
        let s = ed(10);
        let token = r.sign(&s);
        let ra = s.lease.refresh_after();
        let ok = r.verify(&token, ra - 1).unwrap();
        assert_eq!(ok.lease, LeaseState::Current);
        assert_eq!(ok.snapshot, s);
        assert_eq!(ok.admitted, s.members);
        assert_eq!(r.verify(&token, ra).unwrap().lease, LeaseState::Warning { exp: None });
        let later = r.verify(&token, YEARS_LATER).unwrap();
        assert_eq!(later.lease, LeaseState::Warning { exp: None });
        assert!(later.holds(&PrincipalId::user("bob"), "member"));
        assert!(!later.holds(&PrincipalId::user("alice"), "member"));
    }

    #[test]
    fn a_key_principal_is_held_and_masked_like_a_user() {
        let r = rig();
        let k = PrincipalId::from_public_key(&[5; 32]);
        let mut s = ed(10);
        s.members.push(SnapshotMember { principal: k.clone(), relation: "guest".into(), via: vec![("namespace".into(), "ed".into())], lease: None });
        let s = SetSnapshot::new(ISS, "namespace", "ed", 10, s.members, s.revocation_keys, s.iat, s.lease);
        let token = r.sign(&s);
        let ok = r.verify(&token, IAT).unwrap();
        assert!(ok.holds(&k, "guest"));
        // The same id string as a user holds nothing.
        assert!(!ok.holds(&PrincipalId::user(k.id.clone()), "guest"));
        // A user revocation under the key's id string does not mask the key;
        // the key's own revocation does.
        r.revoke(1, vec![Revoked::membership("namespace", "ed", PrincipalId::user(k.id.clone()), 20)]);
        assert!(r.verify(&token, IAT).unwrap().holds(&k, "guest"));
        r.revoke(2, vec![Revoked::membership("namespace", "ed", k.clone(), 20)]);
        assert!(!r.verify(&token, IAT).unwrap().holds(&k, "guest"));
    }

    #[test]
    fn a_higher_epoch_supersedes_and_nothing_lower_unsupersedes() {
        let r = rig();
        let old = r.sign(&ed(10));
        let new = r.sign(&ed(12));
        r.verify(&old, IAT).unwrap();
        // Same epoch again: unchanged, still accepted.
        r.verify(&old, IAT).unwrap();
        r.verify(&new, IAT).unwrap();
        match r.verify(&old, IAT) {
            Err(SnapshotError::Superseded { kind, id, newest: 12, offered: 10 }) => {
                assert_eq!((kind.as_str(), id.as_str()), ("namespace", "ed"));
            }
            other => panic!("expected Superseded, got {other:?}"),
        }
        // Gossip alone supersedes; a lower epoch adopted later lowers nothing.
        pollster::block_on(r.edge.adopt(&r.sign(&ed(15)))).unwrap();
        pollster::block_on(r.edge.adopt(&r.sign(&ed(11)))).unwrap();
        assert_eq!(r.edge.ledger().newest("namespace", "ed"), Some(15));
        assert!(matches!(r.verify(&new, IAT), Err(SnapshotError::Superseded { newest: 15, .. })));
        // Neither does a stale ledger import.
        let stale = SnapshotLedgerDoc {
            issuer: ISS.into(),
            newest: [("namespace".to_owned(), [("ed".to_owned(), 3)].into_iter().collect())].into_iter().collect(),
        };
        r.edge.ledger().import(&stale).unwrap();
        assert_eq!(r.edge.ledger().newest("namespace", "ed"), Some(15));
        // Other resources are untouched.
        let mut other = ed(1);
        other.id = "band".into();
        r.verify(&r.sign(&other), IAT).unwrap();
    }

    #[test]
    fn an_older_epoch_with_a_looser_policy_is_refused() {
        use cheers_core::{evaluate_admit, AdmissionMode, AdmissionPath, AdmissionPolicy, AdmitFacts, Confirmation};
        let r = rig();
        let open = r.sign(&ed(10).with_policy(Some(AdmissionPolicy::new(AdmissionMode::Open, "guest"))));
        let closed = r.sign(&ed(12).with_policy(Some(AdmissionPolicy::new(AdmissionMode::Closed, "guest"))));
        let admit = AdmitFacts { relation: "guest", path: AdmissionPath::Knock, confirmation: Some(Confirmation::Accept), requester_is_user: false };
        let held = r.verify(&open, IAT).unwrap();
        assert!(evaluate_admit(held.admission_policy(), &admit, IAT, None).is_ok());
        let held = r.verify(&closed, IAT).unwrap();
        assert!(evaluate_admit(held.admission_policy(), &admit, IAT, None).is_err());
        // Replaying the looser, older snapshot does not reopen the dial.
        assert!(matches!(r.verify(&open, IAT), Err(SnapshotError::Superseded { newest: 12, offered: 10, .. })));
        // A snapshot with no policy still verifies, and reads as closed.
        let bare = r.verify(&r.sign(&ed(13)), IAT).unwrap();
        assert_eq!(bare.admission_policy(), None);
        assert!(evaluate_admit(bare.admission_policy(), &admit, IAT, None).is_err());
    }

    #[test]
    fn a_leased_guest_warns_then_drops_at_exp() {
        let r = rig();
        let k = PrincipalId::from_public_key(&[6; 32]);
        let mut s = ed(10);
        let lease = Lease::new(IAT, IAT + 100, Some(IAT + 300)).unwrap();
        s.members.push(SnapshotMember { principal: k.clone(), relation: "guest".into(), via: vec![("namespace".into(), "ed".into())], lease: Some(lease) });
        let s = SetSnapshot::new(ISS, "namespace", "ed", 10, s.members, s.revocation_keys, s.iat, s.lease);
        let token = r.sign(&s);
        let ok = r.verify(&token, IAT).unwrap();
        assert_eq!(ok.member_lease(&k, "guest", IAT), Some(LeaseState::Current));
        assert_eq!(ok.member_lease(&k, "guest", IAT + 100), Some(LeaseState::Warning { exp: Some(IAT + 300) }));
        assert_eq!(ok.member_lease(&PrincipalId::user("bob"), "member", IAT), None);
        let late = r.verify(&token, IAT + 300).unwrap();
        assert!(!late.holds(&k, "guest"));
        assert!(late.holds(&PrincipalId::user("bob"), "member"));
    }

    #[test]
    fn a_membership_revoked_at_v_masks_below_v_only() {
        let r = rig();
        // bob loses his last direct tuple on ed at version 20.
        r.revoke(1, vec![Revoked::membership("namespace", "ed", PrincipalId::user("bob"), 20)]);
        // Below 20: his entry derived only from ed is dropped; his guest entry
        // still stands through the museum.
        assert_eq!(r.admitted(&r.sign(&ed(19))), ["alice#guest", "bob#guest"]);
        // At or above 20 the entry does not apply (a snapshot that new no
        // longer lists him through ed, or lists a re-added bob).
        assert_eq!(r.admitted(&r.sign(&ed(20))), ["alice#guest", "bob#guest", "bob#member"]);
        assert_eq!(r.admitted(&r.sign(&ed(30))), ["alice#guest", "bob#guest", "bob#member"]);
    }

    #[test]
    fn an_entry_is_dropped_only_when_every_via_is_revoked() {
        let r = rig();
        // Both leave the museum at 20.
        r.revoke(
            1,
            vec![
                Revoked::membership("namespace", "museum", PrincipalId::user("alice"), 20),
                Revoked::membership("namespace", "museum", PrincipalId::user("bob"), 20),
            ],
        );
        let held = r.sign(&ed(10));
        // alice was a guest only through the museum: dropped. bob is still a
        // direct member of ed: both his entries stand.
        assert_eq!(r.admitted(&held), ["bob#guest", "bob#member"]);
        // Then bob leaves ed too: now every via of his guest entry is gone.
        r.revoke(2, vec![
            Revoked::membership("namespace", "museum", PrincipalId::user("alice"), 20),
            Revoked::membership("namespace", "museum", PrincipalId::user("bob"), 20),
            Revoked::membership("namespace", "ed", PrincipalId::user("bob"), 25),
        ]);
        assert!(r.admitted(&held).is_empty());
        // Other users' and other resources' entries never mask.
        let r = rig();
        r.revoke(1, vec![
            Revoked::membership("namespace", "museum", PrincipalId::user("carol"), 99),
            Revoked::membership("namespace", "band", PrincipalId::user("alice"), 99),
        ]);
        assert_eq!(r.admitted(&r.sign(&ed(10))).len(), 3);
        // An entry with no via cannot be revoked by anything, so it is dropped.
        let mut s = ed(10);
        s.members.push(member("zed", "guest", &[]));
        assert!(!r.admitted(&r.sign(&s)).contains(&"zed#guest".to_owned()));
    }

    #[test]
    fn a_via_without_its_revocation_key_refuses_the_snapshot() {
        let r = rig();
        let mut s = ed(10);
        s.members.push(member("zed", "guest", &["band"]));
        match r.verify(&r.sign(&s), IAT) {
            Err(SnapshotError::MissingRevocationKey { kind, id }) => assert_eq!((kind.as_str(), id.as_str()), ("namespace", "band")),
            other => panic!("expected MissingRevocationKey, got {other:?}"),
        }
    }

    #[test]
    fn a_snapshot_is_refused_as_every_other_credential() {
        let r = rig();
        let token = r.sign(&ed(10));
        // As an access token.
        let keys = KeySetVerifier::from_key_set(KeySet::from_doc(r.doc.clone()).unwrap());
        let as_value = pollster::block_on(keys.verify::<serde_json::Value>(&token, IAT, ISS, None));
        assert!(matches!(as_value, Err(VerifyError::SignatureMismatch)));
        let pinned = PasetoV4PublicVerifier::from_public_key(&pub_bytes(&r.issuer)).unwrap();
        assert!(pinned.verify_mcp_at(&token, IAT, "iss-1").is_err());
        assert!(pinned.verify_at(&token, IAT).is_err());
        // As a standing binding.
        let standing = StandingVerifier::new(r.edge.trust().clone(), r.replica.clone());
        assert!(matches!(
            pollster::block_on(standing.verify_standing_at(&token, &PeerKey::ed25519([1; 32]), IAT)),
            Err(StandingError::Verify(VerifyError::SignatureMismatch))
        ));
        // As a revocation set.
        assert!(pollster::block_on(r.replica.adopt(&token)).is_err());
        assert_eq!(r.replica.epoch(), None);
    }

    #[test]
    fn every_other_credential_is_refused_as_a_snapshot() {
        let r = rig();
        // The snapshot's own payload under the access-token (empty) assertion.
        let unasserted = sign_with(&r.issuer.secret, "iss-1", &ed(10), None);
        assert!(matches!(
            r.verify(&unasserted, IAT),
            Err(SnapshotError::Verify(VerifyError::SignatureMismatch))
        ));
        // ... and under the binding's and the revocation set's assertions.
        for ia in [StandingBinding::IMPLICIT_ASSERTION, RevocationSet::IMPLICIT_ASSERTION] {
            let cross = sign_with(&r.issuer.secret, "iss-1", &ed(10), Some(ia));
            assert!(matches!(r.verify(&cross, IAT), Err(SnapshotError::Verify(VerifyError::SignatureMismatch))));
        }
        // A real binding, a real revocation set, an MCP token and a session token.
        let binding = StandingBinding {
            issuer: ISS.into(),
            sub: UserId::new("alice"),
            device: DeviceId::new("node:a"),
            peer_key: PeerKey::ed25519([1; 32]),
            seq: 5,
            iat: IAT,
            jti: "b".into(),
            lease: Lease::new(IAT, IAT + 60, None).unwrap(),
        };
        let binding = sign_with(&r.issuer.secret, "iss-1", &binding, Some(StandingBinding::IMPLICIT_ASSERTION));
        let set = RevocationSet::new(ISS, 3, vec![]);
        let set = sign_with(&r.issuer.secret, "iss-1", &set, Some(RevocationSet::IMPLICIT_ASSERTION));
        let mcp = McpClaims::new(ISS, "https://aud.test", PrincipalId::user("alice"), IAT, IAT + 900, "j", vec![]);
        let mcp = sign_with(&r.issuer.secret, "iss-1", &mcp, None);
        let claims = Claims::new(UserId::new("alice"), DeviceId::new("node:a"), DeviceBinding::LanPair, IAT, IAT + 900);
        let session = sign_with(&r.issuer.secret, "iss-1", &serde_json::json!({ "cheers": claims }), None);
        for token in [binding, set, mcp, session] {
            assert!(matches!(r.verify(&token, IAT), Err(SnapshotError::Verify(_))));
        }
        // A non-issuer-role key, and a snapshot claiming a foreign issuer.
        let by_assertion = sign_with(&r.assertion.secret, "asr-1", &ed(10), Some(SetSnapshot::IMPLICIT_ASSERTION));
        assert!(matches!(
            r.verify(&by_assertion, IAT),
            Err(SnapshotError::Verify(VerifyError::KeyRoleRejected { .. }))
        ));
        let mut foreign = ed(10);
        foreign.issuer = "https://elsewhere.test".into();
        assert!(matches!(
            r.verify(&r.sign(&foreign), IAT),
            Err(SnapshotError::Verify(VerifyError::BadIssuer { .. }))
        ));
        assert_eq!(r.edge.ledger().newest("namespace", "ed"), None, "nothing refused reached the ledger");
    }

    #[test]
    fn ledger_export_import_round_trips_and_refuses_a_foreign_issuer() {
        let ledger = SnapshotLedger::new(ISS);
        ledger.observe("namespace", "ed", 9);
        ledger.observe("namespace", "band", 4);
        ledger.observe("team", "t", 2);
        let json = serde_json::to_string(&ledger.export()).unwrap();
        let back: SnapshotLedgerDoc = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ledger.export());
        let restored = SnapshotLedger::new(ISS);
        restored.import(&back).unwrap();
        assert_eq!(restored.export(), ledger.export());

        let other = SnapshotLedger::new(ISS);
        other.observe("namespace", "ed", 12);
        other.observe("namespace", "band", 1);
        restored.import(&other.export()).unwrap();
        assert_eq!(restored.newest("namespace", "ed"), Some(12));
        assert_eq!(restored.newest("namespace", "band"), Some(4));
        assert!(restored.import(&SnapshotLedger::new("https://elsewhere.test").export()).is_err());
    }
}
