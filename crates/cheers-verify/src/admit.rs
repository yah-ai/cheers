//! Offline admission (R734-F2; `knock.md`, "Offline verification").
//!
//! [`AdmitAuthority`] answers one question: does key A hold the admit ability
//! on resource R, according to what this edge holds? [`IssuerAdmitAuthority`]
//! answers it rooted in the cheers issuer, from two artifacts that verify
//! offline:
//!
//! 1. the approver's standing binding (§7), proving which user A belongs to,
//!    unless A itself holds an issuer tuple on R; and
//! 2. the snapshot of R this edge holds **now** (§8), showing that user (or
//!    the key) holds a relation carrying the admit ability.
//!
//! [`verify_admit_with`] then checks the [`Admit`] itself against that answer,
//! over any [`AdmitAuthority`] (R734-F7): the [`Approval`] carries the policy
//! and epoch it was read under, so a root other than the issuer (noisetable:
//! the creator-signed room roster) runs the same chain.
//! [`IssuerAdmitAuthority::verify_admit_at`] is that chain over the issuer.
//! The chain is re-checked against the currently held snapshot on every call,
//! so an approver demoted in a newer snapshot takes every admit they had not
//! uploaded with them.
//!
//! **Delegation is one hop** (invariant 4). The authority never consults
//! other admits: a key admitted offline has no issuer tuple and no binding to
//! a user who holds the ability, so it is not an approver until the issuer
//! records it.

use std::collections::BTreeMap;
use std::sync::{PoisonError, RwLock};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use pasetors::token::UntrustedToken;
use pasetors::version4::V4;
use sha2::{Digest, Sha256};

use cheers_core::{
    evaluate_admit, Admit, AdmissionPolicy, AdmissionRefusal, AdmitFacts, CodecError, DeviceSigned, KnockError, LeaseRequest, LeaseState, PeerKey, PrincipalId, PrincipalKind, StoreError, UserId,
};

use crate::key_set::VerifyError;
use crate::public_verifier::PasetoV4PublicVerifier;
use crate::revocation::RevocationReader;
use crate::snapshot::{SnapshotError, SnapshotVerifier, VerifiedSnapshot};
use crate::standing::{StandingError, StandingVerifier};

/// Verify a [`DeviceSigned`] artifact under the key its own payload names.
///
/// The payload is read untrusted only to learn the signer, which must be a
/// `key:` principal; the signature is then checked under exactly that key
/// with `T::IMPLICIT_ASSERTION`, so a token signed by any other key, or for
/// another artifact kind, is refused.
pub fn verify_device_artifact<T: DeviceSigned>(token: &str) -> Result<T, CodecError> {
    let untrusted = UntrustedToken::<pasetors::token::Public, V4>::try_from(token).map_err(|_| CodecError::Malformed)?;
    let claimed: T = serde_json::from_slice(untrusted.untrusted_payload())?;
    let signer = claimed.signer();
    if signer.kind != PrincipalKind::Key {
        return Err(CodecError::Malformed);
    }
    let key = key_bytes(signer).ok_or(CodecError::Malformed)?;
    PasetoV4PublicVerifier::from_public_key(&key)?.verify_artifact(token)
}

/// The raw Ed25519 key of a `key:` principal.
fn key_bytes(p: &PrincipalId) -> Option<[u8; 32]> {
    if p.kind != PrincipalKind::Key {
        return None;
    }
    URL_SAFE_NO_PAD.decode(p.id.as_bytes()).ok()?.try_into().ok()
}

/// What an [`Admit`]'s `source` names: base64url-no-pad SHA-256 of the
/// [`Knock`](cheers_core::Knock) or [`Offer`](cheers_core::Offer) token.
pub fn artifact_hash(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

/// Why an approver or an [`Admit`] was refused.
#[derive(Debug, thiserror::Error)]
pub enum AdmitError {
    /// Bad signature, wrong artifact kind, or a signer that is not a key.
    #[error("admit refused: {0}")]
    Signature(#[from] CodecError),
    /// Decoded, but breaks an artifact invariant (lease, key principals).
    #[error("admit refused: {0}")]
    Invalid(#[from] KnockError),
    /// Past its lease's `exp`.
    #[error("admit expired at {exp}")]
    Expired { exp: i64 },
    /// Checked under an issuer this edge does not trust.
    #[error("admit names authority {got}, expected {expected}")]
    WrongAuthority { expected: String, got: String },
    /// This edge holds no snapshot of the resource.
    #[error("no snapshot held for {kind}/{id}")]
    NoSnapshot { kind: String, id: String },
    /// The held snapshot no longer verifies (superseded, revocation key).
    #[error(transparent)]
    Snapshot(#[from] SnapshotError),
    /// The approver's standing binding was refused.
    #[error(transparent)]
    Standing(#[from] StandingError),
    /// The key has no issuer-rooted path to the admit ability on the resource.
    #[error("{approver} does not hold the admit ability on {kind}/{id}")]
    NotAnApprover { approver: PrincipalId, kind: String, id: String },
    /// The admit's own `jti` is revoked (refused at reconciliation).
    #[error("admit {jti} is revoked")]
    Revoked { jti: String },
    /// The admission policy held now does not permit this admit: the mode,
    /// a confirmation below the relation's minimum, or a lease past the
    /// path maximum (`cheers_core::evaluate_admit`).
    #[error("admission policy refuses admit {jti}: {reason}")]
    PolicyRefused { jti: String, reason: AdmissionRefusal },
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<VerifyError> for AdmitError {
    fn from(e: VerifyError) -> Self {
        AdmitError::Snapshot(SnapshotError::Verify(e))
    }
}

/// An approver the authority vouches for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    /// The user the key's standing binding names; `None` when the key holds
    /// the relation through its own issuer tuple.
    pub user: Option<UserId>,
    /// The admit-bearing relation the approver holds.
    pub relation: String,
    /// The admission policy the authority holds now for the resource; `None`
    /// reads as closed. [`verify_admit_with`] evaluates every admit against
    /// it, not against the policy the admit was minted under.
    pub policy: Option<AdmissionPolicy>,
    /// The epoch of the authority state the approval was read from (the
    /// issuer: the held snapshot's epoch).
    pub epoch: u64,
}

/// Does key `approver` hold the admit ability on `(kind, id)`, according to
/// what this edge holds now? Implemented over the issuer by
/// [`IssuerAdmitAuthority`]; a consumer roots it elsewhere (noisetable: the
/// creator-signed room roster). [`verify_admit_with`] runs the offline chain
/// over any implementation.
#[async_trait::async_trait]
pub trait AdmitAuthority: Send + Sync {
    async fn approval_at(
        &self,
        approver: &PrincipalId,
        approver_binding: Option<&str>,
        kind: &str,
        id: &str,
        now: i64,
    ) -> Result<Approval, AdmitError>;

    /// The user a requester's standing `binding` names, verified for
    /// `requester`'s key at `now`. Asked only when the [`Admit`] carries a
    /// `requester_binding` (`users` mode admits only these).
    async fn requester_user_at(&self, requester: &PeerKey, binding: &str, now: i64) -> Result<UserId, AdmitError>;
}

/// Verify an offline [`Admit`] token at `now` over `authority`, re-checking
/// the whole chain against what it holds now.
///
/// In order: device signature, artifact invariants (key principals, a lease
/// with `exp`, the midpoint), the admit naming `trusted_authority`, expiry,
/// the admit's `jti` against `revocations`, the approver's path
/// ([`AdmitAuthority::approval_at`]), the requester's standing binding when it
/// carries one ([`AdmitAuthority::requester_user_at`]), then the admission
/// policy the approval carries (no policy reads as closed).
pub async fn verify_admit_with(
    authority: &dyn AdmitAuthority,
    trusted_authority: &str,
    revocations: &dyn RevocationReader,
    token: &str,
    now: i64,
) -> Result<VerifiedAdmit, AdmitError> {
    let admit: Admit = verify_device_artifact(token)?;
    admit.validate()?;
    if admit.authority != trusted_authority {
        return Err(AdmitError::WrongAuthority { expected: trusted_authority.to_owned(), got: admit.authority });
    }
    let lease = admit.lease.state_at(now);
    if lease == LeaseState::Expired {
        return Err(AdmitError::Expired { exp: admit.lease.exp().unwrap_or(now) });
    }
    if revocations.is_revoked(&admit.jti).await? {
        return Err(AdmitError::Revoked { jti: admit.jti });
    }
    let approval = authority
        .approval_at(&admit.approver, admit.approver_binding.as_deref(), &admit.kind, &admit.id, now)
        .await?;
    let requester_user = match &admit.requester_binding {
        Some(binding) => {
            let key = key_bytes(&admit.requester).ok_or(KnockError::NotAKey(admit.requester.clone()))?;
            Some(authority.requester_user_at(&PeerKey::ed25519(key), binding, now).await?)
        }
        None => None,
    };
    let facts = AdmitFacts {
        relation: &admit.relation,
        path: admit.path(),
        confirmation: Some(admit.confirmation),
        requester_is_user: requester_user.is_some(),
    };
    if let Err(reason) = evaluate_admit(approval.policy.as_ref(), &facts, admit.iat, Some(LeaseRequest::Exact(admit.lease))) {
        return Err(AdmitError::PolicyRefused { jti: admit.jti, reason });
    }
    Ok(VerifiedAdmit { admit, approval, requester_user, lease })
}

/// A verified [`Admit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAdmit {
    pub admit: Admit,
    pub approval: Approval,
    /// The user the requester's standing binding names, when the Admit
    /// carried one (`users` mode admits only these).
    pub requester_user: Option<UserId>,
    /// The admit's lease at the verification instant; never `Expired`.
    pub lease: LeaseState,
}

/// [`AdmitAuthority`] rooted in the cheers issuer (§7 + §8).
pub struct IssuerAdmitAuthority<Rd> {
    standing: StandingVerifier<Rd>,
    snapshots: SnapshotVerifier<Rd>,
    /// The snapshot token held per `(kind, id)`: the newest adopted.
    held: RwLock<BTreeMap<(String, String), (u64, String)>>,
}

impl<Rd> std::fmt::Debug for IssuerAdmitAuthority<Rd> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuerAdmitAuthority").finish_non_exhaustive()
    }
}

impl<Rd: RevocationReader> IssuerAdmitAuthority<Rd> {
    /// Both verifiers must trust the same issuer. Which relations carry the
    /// admit ability is read from the held snapshot's
    /// [`AdmissionPolicy::admitters`](cheers_core::AdmissionPolicy::admitters).
    pub fn new(standing: StandingVerifier<Rd>, snapshots: SnapshotVerifier<Rd>) -> Self {
        Self {
            standing,
            snapshots,
            held: RwLock::new(BTreeMap::new()),
        }
    }

    pub fn standing(&self) -> &StandingVerifier<Rd> {
        &self.standing
    }

    pub fn snapshots(&self) -> &SnapshotVerifier<Rd> {
        &self.snapshots
    }

    /// Adopt a snapshot (signature only) and hold it for its resource if it
    /// is at least as new as the one held. Returns the epoch now held.
    pub async fn hold_snapshot(&self, token: &str) -> Result<u64, VerifyError> {
        let snapshot = self.snapshots.adopt(token).await?;
        let mut held = self.held.write().unwrap_or_else(PoisonError::into_inner);
        let slot = held.entry((snapshot.kind, snapshot.id)).or_insert((0, String::new()));
        if snapshot.epoch >= slot.0 {
            *slot = (snapshot.epoch, token.to_owned());
        }
        Ok(slot.0)
    }

    fn held_token(&self, kind: &str, id: &str) -> Option<String> {
        let held = self.held.read().unwrap_or_else(PoisonError::into_inner);
        held.get(&(kind.to_owned(), id.to_owned())).map(|(_, t)| t.clone())
    }

    /// Verify an offline [`Admit`] token at `now` with [`verify_admit_with`],
    /// rooted in this issuer: the admit must name it, its `jti` is checked
    /// against the snapshot verifier's revocation set, and the approver
    /// against the snapshot held now.
    pub async fn verify_admit_at(&self, token: &str, now: i64) -> Result<VerifiedAdmit, AdmitError> {
        verify_admit_with(self, self.snapshots.trust().issuer(), self.snapshots.revocations(), token, now).await
    }

    fn admit_relation(&self, snapshot: &VerifiedSnapshot, principal: &PrincipalId) -> Option<String> {
        // The policy held now names the admit ability (R734-F4); no policy,
        // or no admitters, means nobody may admit.
        let admitters = &snapshot.admission_policy()?.admitters;
        admitters.iter().find(|r| snapshot.holds(principal, r)).cloned()
    }
}

#[async_trait::async_trait]
impl<Rd: RevocationReader + Send + Sync> AdmitAuthority for IssuerAdmitAuthority<Rd> {
    async fn approval_at(
        &self,
        approver: &PrincipalId,
        approver_binding: Option<&str>,
        kind: &str,
        id: &str,
        now: i64,
    ) -> Result<Approval, AdmitError> {
        let not_an_approver = || AdmitError::NotAnApprover {
            approver: approver.clone(),
            kind: kind.to_owned(),
            id: id.to_owned(),
        };
        if approver.kind != PrincipalKind::Key {
            return Err(not_an_approver());
        }
        let token = self.held_token(kind, id).ok_or_else(|| AdmitError::NoSnapshot {
            kind: kind.to_owned(),
            id: id.to_owned(),
        })?;
        let snapshot = self.snapshots.verify_snapshot_at(&token, now).await?;

        let approval = |user, relation| Approval {
            user,
            relation,
            policy: snapshot.admission_policy().cloned(),
            epoch: snapshot.snapshot.epoch,
        };
        // The key's own issuer tuple.
        if let Some(relation) = self.admit_relation(&snapshot, approver) {
            return Ok(approval(None, relation));
        }
        // Otherwise a standing binding to a user who holds the ability.
        let Some(binding) = approver_binding else {
            return Err(not_an_approver());
        };
        let key = key_bytes(approver).ok_or_else(not_an_approver)?;
        let standing = self.standing.verify_standing_at(binding, &PeerKey::ed25519(key), now).await?;
        let user = standing.binding.sub;
        match self.admit_relation(&snapshot, &PrincipalId::from(&user)) {
            Some(relation) => Ok(approval(Some(user), relation)),
            None => Err(not_an_approver()),
        }
    }

    async fn requester_user_at(&self, requester: &PeerKey, binding: &str, now: i64) -> Result<UserId, AdmitError> {
        Ok(self.standing.verify_standing_at(binding, requester, now).await?.binding.sub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::IssuerTrust;
    use crate::jwks::{JwkKey, JwksDoc, KeySet};
    use crate::key_set::KeySetVerifier;
    use crate::revocation::{revocation_entry, test_revocation_key, ReplicatedRevocations};
    use cheers_core::{
        AdmissionMode, AdmissionPolicy, AdmitSource, Confirmation, DeviceId, Knock, KeyRole, Lease, ResourceRevocationKey, RevocationKey, RevocationSet, Revoked,
        SetSnapshot, SignedArtifact, SnapshotMember, StandingBinding,
    };
    use pasetors::keys::{AsymmetricKeyPair, AsymmetricSecretKey, Generate};
    use pasetors::version4::PublicToken;
    use serde::Serialize;
    use std::sync::Arc;

    const ISS: &str = "https://cheers.test";
    const IAT: i64 = 1_000;
    const DAY: i64 = 24 * 60 * 60;

    fn kp() -> AsymmetricKeyPair<V4> {
        AsymmetricKeyPair::<V4>::generate().unwrap()
    }

    fn pub_bytes(k: &AsymmetricKeyPair<V4>) -> [u8; 32] {
        k.public.as_bytes().try_into().unwrap()
    }

    fn key_of(k: &AsymmetricKeyPair<V4>) -> PrincipalId {
        PrincipalId::from_public_key(&pub_bytes(k))
    }

    fn sign_with(secret: &AsymmetricSecretKey<V4>, kid: &str, payload: &impl Serialize, ia: &[u8]) -> String {
        let body = serde_json::to_vec(payload).unwrap();
        let footer = format!(r#"{{"kid":"{kid}"}}"#);
        PublicToken::sign(secret, &body, Some(footer.as_bytes()), Some(ia)).unwrap()
    }

    fn member(principal: PrincipalId, relation: &str) -> SnapshotMember {
        SnapshotMember { principal, relation: relation.into(), via: vec![("namespace".into(), "ed".into())], lease: None }
    }

    struct Rig {
        issuer: AsymmetricKeyPair<V4>,
        replica: Arc<ReplicatedRevocations>,
        auth: IssuerAdmitAuthority<Arc<ReplicatedRevocations>>,
        /// alice's device key, bound to user alice.
        device: AsymmetricKeyPair<V4>,
        binding: String,
    }

    impl Rig {
        fn snapshot(&self, epoch: u64, members: Vec<SnapshotMember>) {
            self.snapshot_with(epoch, members, Some(AdmissionPolicy::new(AdmissionMode::Knock, "guest")));
        }

        /// As [`Self::snapshot_exact`], with `owner` as the admit relation.
        fn snapshot_with(&self, epoch: u64, members: Vec<SnapshotMember>, policy: Option<AdmissionPolicy>) {
            self.snapshot_exact(epoch, members, policy.map(|p| p.with_admitters(["owner"])));
        }

        fn snapshot_exact(&self, epoch: u64, members: Vec<SnapshotMember>, policy: Option<AdmissionPolicy>) {
            let s = SetSnapshot::new(
                ISS,
                "namespace",
                "ed",
                epoch,
                members,
                vec![ResourceRevocationKey {
                    kind: "namespace".into(),
                    id: "ed".into(),
                    key: test_revocation_key("namespace", "ed"),
                }],
                IAT,
                Lease::new(IAT, IAT + 7 * DAY, None).unwrap(),
            )
            .with_policy(policy);
            let t = sign_with(&self.issuer.secret, "iss-1", &s, SetSnapshot::IMPLICIT_ASSERTION);
            pollster::block_on(self.auth.hold_snapshot(&t)).unwrap();
        }

        fn admit(&self, signer: &AsymmetricKeyPair<V4>, binding: Option<&str>, level: Confirmation) -> Admit {
            Admit {
                approver: key_of(signer),
                approver_binding: binding.map(str::to_owned),
                authority: ISS.into(),
                requester: key_of(&kp()),
                requester_binding: None,
                kind: "namespace".into(),
                id: "ed".into(),
                relation: "guest".into(),
                source: AdmitSource::Knock(artifact_hash("knock-token")),
                confirmation: level,
                epoch: 10,
                jti: "admit-1".into(),
                iat: IAT,
                lease: Lease::new(IAT, IAT + DAY, Some(IAT + 7 * DAY)).unwrap(),
            }
        }

        /// A standing binding for `user` on node key `peer`, signed by `by`.
        fn bind(&self, by: &AsymmetricSecretKey<V4>, user: &str, peer: &AsymmetricKeyPair<V4>) -> String {
            let b = StandingBinding {
                issuer: ISS.into(),
                sub: UserId::new(user),
                device: DeviceId::new(format!("node:{user}")),
                peer_key: PeerKey::ed25519(pub_bytes(peer)),
                seq: 1,
                iat: IAT,
                jti: format!("bind-{user}"),
                lease: Lease::new(IAT, IAT + 7 * DAY, None).unwrap(),
            };
            sign_with(by, "iss-1", &b, StandingBinding::IMPLICIT_ASSERTION)
        }

        fn sign(&self, signer: &AsymmetricKeyPair<V4>, a: &Admit) -> String {
            sign_with(&signer.secret, "dev", a, Admit::IMPLICIT_ASSERTION)
        }

        fn verify(&self, token: &str, now: i64) -> Result<VerifiedAdmit, AdmitError> {
            pollster::block_on(self.auth.verify_admit_at(token, now))
        }
    }

    fn rig() -> Rig {
        let issuer = kp();
        let doc = JwksDoc { keys: vec![JwkKey::ed25519("iss-1", &pub_bytes(&issuer), ISS, KeyRole::Issuer)] };
        let trust = IssuerTrust::key_set(ISS, KeySetVerifier::from_key_set(KeySet::from_doc(doc).unwrap()));
        let replica = Arc::new(ReplicatedRevocations::new(trust.clone()));
        let auth = IssuerAdmitAuthority::new(
            StandingVerifier::new(trust.clone(), replica.clone()),
            SnapshotVerifier::new(trust, replica.clone()),
        );
        let device = kp();
        let b = StandingBinding {
            issuer: ISS.into(),
            sub: UserId::new("alice"),
            device: DeviceId::new("node:alice"),
            peer_key: PeerKey::ed25519(pub_bytes(&device)),
            seq: 1,
            iat: IAT,
            jti: "bind-1".into(),
            lease: Lease::new(IAT, IAT + 7 * DAY, None).unwrap(),
        };
        let binding = sign_with(&issuer.secret, "iss-1", &b, StandingBinding::IMPLICIT_ASSERTION);
        let r = Rig { issuer, replica, auth, device, binding };
        r.snapshot(10, vec![member(PrincipalId::user("alice"), "owner")]);
        r
    }

    #[test]
    fn a_valid_chain_admits() {
        let r = rig();
        let a = r.admit(&r.device, Some(&r.binding), Confirmation::Compare);
        let ok = r.verify(&r.sign(&r.device, &a), IAT + 1).unwrap();
        assert_eq!(ok.admit, a);
        assert_eq!(ok.approval.user, Some(UserId::new("alice")));
        assert_eq!(ok.approval.relation, "owner");
        assert_eq!(ok.lease, LeaseState::Current);
    }

    #[test]
    fn a_key_with_its_own_issuer_tuple_admits_without_a_binding() {
        let r = rig();
        let k = kp();
        r.snapshot(11, vec![member(key_of(&k), "owner")]);
        let a = r.admit(&k, None, Confirmation::Accept);
        assert_eq!(r.verify(&r.sign(&k, &a), IAT).unwrap().approval.user, None);
    }

    #[test]
    fn a_demoted_approver_loses_unreconciled_admits() {
        let r = rig();
        let token = r.sign(&r.device, &r.admit(&r.device, Some(&r.binding), Confirmation::Accept));
        assert!(r.verify(&token, IAT).is_ok());
        r.snapshot(11, vec![member(PrincipalId::user("alice"), "guest")]);
        assert!(matches!(r.verify(&token, IAT).unwrap_err(), AdmitError::NotAnApprover { .. }));
    }

    #[test]
    fn a_two_hop_chain_is_refused() {
        let r = rig();
        // alice admits guest key G offline; G then admits H.
        let g = kp();
        let mut first = r.admit(&r.device, Some(&r.binding), Confirmation::Accept);
        first.requester = key_of(&g);
        assert!(r.verify(&r.sign(&r.device, &first), IAT).is_ok());
        let second = r.admit(&g, None, Confirmation::Accept);
        let err = r.verify(&r.sign(&g, &second), IAT).unwrap_err();
        assert!(matches!(err, AdmitError::NotAnApprover { .. }), "got {err:?}");
        // Borrowing alice's binding does not help: it names alice's key, not G.
        let borrowed = r.admit(&g, Some(&r.binding), Confirmation::Accept);
        let err = r.verify(&r.sign(&g, &borrowed), IAT).unwrap_err();
        assert!(matches!(err, AdmitError::Standing(StandingError::PeerKeyMismatch)), "got {err:?}");
    }

    #[test]
    fn the_policy_held_now_decides() {
        let r = rig();
        let members = || vec![member(PrincipalId::user("alice"), "owner")];
        let token = r.sign(&r.device, &r.admit(&r.device, Some(&r.binding), Confirmation::Compare));
        assert!(r.verify(&token, IAT).is_ok());
        // Below the relation's minimum confirmation.
        let strict = AdmissionPolicy::new(AdmissionMode::Knock, "guest").with_min_confirmation("guest", Confirmation::Scan);
        r.snapshot_with(11, members(), Some(strict));
        let err = r.verify(&token, IAT).unwrap_err();
        assert!(
            matches!(err, AdmitError::PolicyRefused { reason: AdmissionRefusal::BelowConfirmation { .. }, .. }),
            "got {err:?}"
        );
        // No policy row reads as closed, and names no admitters, so the
        // approver is refused before the dial is even read; `users` makes
        // this key-only admit inert.
        r.snapshot_with(12, members(), None);
        assert!(matches!(r.verify(&token, IAT).unwrap_err(), AdmitError::NotAnApprover { .. }));
        r.snapshot_with(13, members(), Some(AdmissionPolicy::new(AdmissionMode::Users, "guest")));
        assert!(matches!(r.verify(&token, IAT).unwrap_err(), AdmitError::PolicyRefused { .. }));
        // Moving the dial back restores it.
        r.snapshot(14, members());
        assert!(r.verify(&token, IAT).is_ok());
    }

    #[test]
    fn the_admit_ability_comes_from_the_held_policy() {
        let r = rig();
        let members = || vec![member(PrincipalId::user("alice"), "owner")];
        let token = r.sign(&r.device, &r.admit(&r.device, Some(&r.binding), Confirmation::Accept));
        // A policy naming no admitters fails closed even for an owner.
        r.snapshot_exact(20, members(), Some(AdmissionPolicy::new(AdmissionMode::Knock, "guest")));
        assert!(matches!(r.verify(&token, IAT).unwrap_err(), AdmitError::NotAnApprover { .. }));
        // Naming the owner's relation restores it.
        r.snapshot(21, members());
        assert!(r.verify(&token, IAT).is_ok());
    }

    #[test]
    fn a_lease_past_the_path_maximum_is_refused() {
        let r = rig();
        let mut a = r.admit(&r.device, Some(&r.binding), Confirmation::Accept);
        a.lease = Lease::new(IAT, IAT + DAY, Some(IAT + 8 * DAY)).unwrap();
        let err = r.verify(&r.sign(&r.device, &a), IAT).unwrap_err();
        assert!(matches!(err, AdmitError::PolicyRefused { reason: AdmissionRefusal::LeaseOverMax { .. }, .. }), "got {err:?}");
    }

    #[test]
    fn a_lease_past_its_midpoint_is_refused() {
        let r = rig();
        let mut v = serde_json::to_value(r.admit(&r.device, Some(&r.binding), Confirmation::Accept)).unwrap();
        v["refresh_after"] = (IAT + 4 * DAY).into();
        let forged: Admit = serde_json::from_value(v).unwrap();
        let err = r.verify(&r.sign(&r.device, &forged), IAT).unwrap_err();
        assert!(matches!(err, AdmitError::Invalid(KnockError::Lease(_))), "got {err:?}");
    }

    #[test]
    fn lease_state_through_exp_then_refused() {
        let r = rig();
        let token = r.sign(&r.device, &r.admit(&r.device, Some(&r.binding), Confirmation::Accept));
        let (ra, exp) = (IAT + DAY, IAT + 7 * DAY);
        assert_eq!(r.verify(&token, ra - 1).unwrap().lease, LeaseState::Current);
        assert_eq!(r.verify(&token, ra).unwrap().lease, LeaseState::Warning { exp: Some(exp) });
        assert_eq!(r.verify(&token, exp - 1).unwrap().lease, LeaseState::Warning { exp: Some(exp) });
        assert!(matches!(r.verify(&token, exp).unwrap_err(), AdmitError::Expired { .. }));
    }

    #[test]
    fn tampered_and_wrong_assertion_artifacts_are_refused() {
        let r = rig();
        let a = r.admit(&r.device, Some(&r.binding), Confirmation::Accept);
        // Signed by a key other than the one the payload names.
        let other = kp();
        assert!(matches!(r.verify(&r.sign(&other, &a), IAT).unwrap_err(), AdmitError::Signature(_)));
        // A flipped signature byte.
        let token = r.sign(&r.device, &a);
        let mut bytes = token.into_bytes();
        let i = bytes.len() - 10;
        bytes[i] = if bytes[i] == b'A' { b'B' } else { b'A' };
        assert!(r.verify(&String::from_utf8(bytes).unwrap(), IAT).is_err());
        // The right key, the wrong artifact kind.
        let as_knock = sign_with(&r.device.secret, "dev", &a, Knock::IMPLICIT_ASSERTION);
        assert!(matches!(r.verify(&as_knock, IAT).unwrap_err(), AdmitError::Signature(_)));
    }

    /// Publish a revocation set naming `jti` to the rig's replica.
    fn revoke(r: &Rig, jti: &str) {
        let entries = [Revoked::Jti { jti: jti.into(), exp: Some(IAT + 7 * DAY) }]
            .iter()
            .map(|e| revocation_entry(e, test_revocation_key))
            .collect();
        let set = RevocationSet::new(ISS, 5, entries);
        let t = sign_with(&r.issuer.secret, "iss-1", &set, RevocationSet::IMPLICIT_ASSERTION);
        pollster::block_on(r.replica.adopt(&t)).unwrap();
    }

    #[test]
    fn a_revoked_admit_jti_is_refused() {
        let r = rig();
        let token = r.sign(&r.device, &r.admit(&r.device, Some(&r.binding), Confirmation::Accept));
        revoke(&r, "admit-1");
        assert!(matches!(r.verify(&token, IAT).unwrap_err(), AdmitError::Revoked { .. }));
    }

    /// One admit that breaks every link at once, repaired a link at a time:
    /// each repair surfaces the next check, so the issuer path refuses in
    /// chain order with the same variants (R734-F7).
    #[test]
    fn refusals_keep_the_chain_order() {
        let r = rig();
        let k = kp();
        let users = |epoch, alice: &str| {
            let policy = AdmissionPolicy::new(AdmissionMode::Users, "guest");
            r.snapshot_with(epoch, vec![member(PrincipalId::user("alice"), alice)], Some(policy));
        };
        users(11, "guest");
        revoke(&r, "admit-1");
        let mut a = r.admit(&r.device, Some(&r.binding), Confirmation::Accept);
        a.authority = "https://rogue.test".into();
        a.requester = key_of(&k);
        a.requester_binding = Some(r.bind(&r.issuer.secret, "bob", &kp()));
        a.lease = Lease::new(IAT, IAT + DAY, Some(IAT + 8 * DAY)).unwrap();
        let exp = IAT + 8 * DAY;
        let refuse = |a: &Admit, now| r.verify(&r.sign(&r.device, a), now).unwrap_err();

        let err = refuse(&a, exp);
        assert!(matches!(err, AdmitError::WrongAuthority { .. }), "got {err:?}");
        a.authority = ISS.into();
        let err = refuse(&a, exp);
        assert!(matches!(err, AdmitError::Expired { .. }), "got {err:?}");
        let err = refuse(&a, IAT);
        assert!(matches!(err, AdmitError::Revoked { .. }), "got {err:?}");
        a.jti = "admit-2".into();
        let err = refuse(&a, IAT);
        assert!(matches!(err, AdmitError::NotAnApprover { .. }), "got {err:?}");
        users(12, "owner");
        let err = refuse(&a, IAT);
        assert!(matches!(err, AdmitError::Standing(StandingError::PeerKeyMismatch)), "got {err:?}");
        a.requester_binding = Some(r.bind(&r.issuer.secret, "bob", &k));
        let err = refuse(&a, IAT);
        assert!(matches!(err, AdmitError::PolicyRefused { reason: AdmissionRefusal::LeaseOverMax { .. }, .. }), "got {err:?}");
        a.lease = Lease::new(IAT, IAT + DAY, Some(IAT + 7 * DAY)).unwrap();
        let ok = r.verify(&r.sign(&r.device, &a), IAT).unwrap();
        assert_eq!(ok.requester_user, Some(UserId::new("bob")));
        assert_eq!(ok.approval.epoch, 12);
    }

    /// A root other than the issuer: a roster of device keys held under its
    /// own root key, the way noisetable roots a room in its creator. `enroll`
    /// carries the admit ability; it binds no users.
    #[derive(Clone)]
    struct Roster {
        root: String,
        members: BTreeMap<PrincipalId, String>,
        policy: Option<AdmissionPolicy>,
        epoch: u64,
    }

    #[async_trait::async_trait]
    impl AdmitAuthority for Roster {
        async fn approval_at(
            &self,
            approver: &PrincipalId,
            _approver_binding: Option<&str>,
            kind: &str,
            id: &str,
            _now: i64,
        ) -> Result<Approval, AdmitError> {
            let not_an_approver = || AdmitError::NotAnApprover { approver: approver.clone(), kind: kind.into(), id: id.into() };
            if (kind, id) != ("room", self.root.as_str()) {
                return Err(not_an_approver());
            }
            let relation = self.members.get(approver).filter(|r| *r == "enroll").cloned().ok_or_else(not_an_approver)?;
            Ok(Approval { user: None, relation, policy: self.policy.clone(), epoch: self.epoch })
        }

        async fn requester_user_at(&self, _requester: &PeerKey, _binding: &str, _now: i64) -> Result<UserId, AdmitError> {
            Err(AdmitError::Standing(StandingError::PeerKeyMismatch))
        }
    }

    /// Revocations a non-issuer root keeps itself: a plain jti set.
    struct Jtis(std::collections::BTreeSet<String>);

    #[async_trait::async_trait]
    impl RevocationReader for Jtis {
        async fn is_revoked(&self, jti: &str) -> Result<bool, StoreError> {
            Ok(self.0.contains(jti))
        }

        async fn is_device_revoked(&self, _device: &DeviceId, _seq: u64) -> Result<bool, StoreError> {
            Ok(false)
        }

        async fn is_membership_revoked(
            &self,
            _key: &RevocationKey,
            _kind: &str,
            _id: &str,
            _principal: &PrincipalId,
            _snapshot_epoch: u64,
        ) -> Result<bool, StoreError> {
            Ok(false)
        }
    }

    #[test]
    fn a_non_issuer_root_verifies_an_offline_admit() {
        let (root, enroller, stranger) = (kp(), kp(), kp());
        let room = URL_SAFE_NO_PAD.encode(pub_bytes(&root));
        let authority = format!("room:{room}");
        let roster = Roster {
            root: room.clone(),
            members: BTreeMap::from([(key_of(&enroller), "enroll".to_owned()), (key_of(&stranger), "guest".to_owned())]),
            policy: Some(AdmissionPolicy::new(AdmissionMode::Knock, "guest")),
            epoch: 3,
        };
        let none = Jtis(Default::default());
        let admit = |signer: &AsymmetricKeyPair<V4>, authority: &str| {
            let a = Admit {
                approver: key_of(signer),
                approver_binding: None,
                authority: authority.into(),
                requester: key_of(&kp()),
                requester_binding: None,
                kind: "room".into(),
                id: room.clone(),
                relation: "guest".into(),
                source: AdmitSource::Knock(artifact_hash("knock-token")),
                confirmation: Confirmation::Compare,
                epoch: 3,
                jti: "room-admit-1".into(),
                iat: IAT,
                lease: Lease::new(IAT, IAT + DAY, Some(IAT + 7 * DAY)).unwrap(),
            };
            let token = sign_with(&signer.secret, "dev", &a, Admit::IMPLICIT_ASSERTION);
            (a, token)
        };
        let verify = |roster: &Roster, revocations: &Jtis, token: &str| {
            pollster::block_on(verify_admit_with(roster, &authority, revocations, token, IAT + 1))
        };

        let (a, token) = admit(&enroller, &authority);
        let ok = verify(&roster, &none, &token).unwrap();
        assert_eq!(ok.admit, a);
        assert_eq!(ok.approval, Approval { user: None, relation: "enroll".into(), policy: roster.policy.clone(), epoch: 3 });
        assert_eq!(ok.requester_user, None);
        assert_eq!(ok.lease, LeaseState::Current);

        // The admit must name this root, not the cheers issuer.
        let (_, token) = admit(&enroller, ISS);
        let err = verify(&roster, &none, &token).unwrap_err();
        assert!(matches!(&err, AdmitError::WrongAuthority { expected, .. } if *expected == authority), "got {err:?}");
        // A key the roster holds without the admit ability.
        let (_, token) = admit(&stranger, &authority);
        let err = verify(&roster, &none, &token).unwrap_err();
        assert!(matches!(err, AdmitError::NotAnApprover { .. }), "got {err:?}");
        // The root's own revocations.
        let (_, token) = admit(&enroller, &authority);
        let revoked = Jtis(["room-admit-1".to_owned()].into());
        let err = verify(&roster, &revoked, &token).unwrap_err();
        assert!(matches!(err, AdmitError::Revoked { .. }), "got {err:?}");
        // The policy the roster holds now decides: `users` refuses a key-only admit.
        let users = Roster { policy: Some(AdmissionPolicy::new(AdmissionMode::Users, "guest")), ..roster.clone() };
        let err = verify(&users, &none, &token).unwrap_err();
        assert!(matches!(err, AdmitError::PolicyRefused { .. }), "got {err:?}");
    }

    /// alice admits key `k`, presenting `binding` as k's standing binding,
    /// under a `users`-mode policy.
    fn users_mode_admit(r: &Rig, k: &AsymmetricKeyPair<V4>, binding: String) -> String {
        r.snapshot_with(
            11,
            vec![member(PrincipalId::user("alice"), "owner")],
            Some(AdmissionPolicy::new(AdmissionMode::Users, "guest")),
        );
        let mut a = r.admit(&r.device, Some(&r.binding), Confirmation::Accept);
        a.requester = key_of(k);
        a.requester_binding = Some(binding);
        r.sign(&r.device, &a)
    }

    #[test]
    fn users_mode_admits_a_requester_with_its_own_binding() {
        let r = rig();
        let k = kp();
        let token = users_mode_admit(&r, &k, r.bind(&r.issuer.secret, "bob", &k));
        let ok = r.verify(&token, IAT).unwrap();
        assert_eq!(ok.requester_user, Some(UserId::new("bob")));
        assert_eq!(ok.admit.requester, key_of(&k));
    }

    #[test]
    fn a_requester_binding_for_another_key_is_refused() {
        let r = rig();
        let (k, other) = (kp(), kp());
        let token = users_mode_admit(&r, &k, r.bind(&r.issuer.secret, "bob", &other));
        let err = r.verify(&token, IAT).unwrap_err();
        assert!(matches!(err, AdmitError::Standing(StandingError::PeerKeyMismatch)), "got {err:?}");
    }

    #[test]
    fn a_requester_binding_from_an_untrusted_issuer_is_refused() {
        let r = rig();
        let k = kp();
        let rogue = kp();
        let token = users_mode_admit(&r, &k, r.bind(&rogue.secret, "bob", &k));
        let err = r.verify(&token, IAT).unwrap_err();
        assert!(matches!(err, AdmitError::Standing(StandingError::Verify(_))), "got {err:?}");
    }

    #[test]
    fn a_knock_verifies_under_its_requester_key() {
        let k = kp();
        let knock = Knock {
            requester: key_of(&k),
            kind: "namespace".into(),
            id: "ed".into(),
            relation: "guest".into(),
            nonce: "n".into(),
            label: "Ann's phone".into(),
            standing: None,
            renews: Some("admit-1".into()),
            iat: IAT,
        };
        let t = sign_with(&k.secret, "dev", &knock, Knock::IMPLICIT_ASSERTION);
        assert_eq!(verify_device_artifact::<Knock>(&t).unwrap(), knock);
        assert!(verify_device_artifact::<Admit>(&t).is_err());
    }
}
