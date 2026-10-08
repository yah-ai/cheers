//! [`StandingVerifier`] — the edge check for a standing node binding
//! (R732-F5; noisetable W235 §0.1, §5).
//!
//! A [`StandingBinding`] has no expiry. The edge admits one when:
//!
//! 1. it is signed for the trusted issuer ([`IssuerTrust`]: a pinned key, or a
//!    JWKS **issuer**-role key) under the binding's own implicit assertion, so
//!    no access token verifies here and no binding verifies as one;
//! 2. its `peer_key` is the key the connecting peer proved in its transport
//!    handshake;
//! 3. no newer binding for the same device has been seen ([`BindingLedger`]);
//! 4. neither its `jti` nor its `device` at its `seq` is revoked ([`RevocationReader`] —
//!    `ReplicatedRevocations` on an offline edge).
//!
//! `refresh_after` is advisory: it sets [`VerifiedStanding::lease`] and
//! never refuses. The clock is used for nothing else.
//!
//! # Supersession
//!
//! The issuer stamps every binding with a per-device `seq` that only rises
//! (`max(prev + 1, now)`, clock-floored like the revocation epoch). The ledger
//! keeps the highest `seq` seen per device from **any** genuine binding —
//! presented by a peer or heard by gossip ([`StandingVerifier::adopt`]) — and
//! never lowers it, whatever order bindings arrive in. A binding below its
//! device's highest is superseded. Nothing compares `iat`.
//!
//! # Offline restart
//!
//! An edge persists three documents beside the binding tokens it holds:
//! [`IssuerTrust::export`] (the keys), [`BindingLedger::export`] (the
//! supersession high-water marks) and `ReplicatedRevocations::export` (the
//! revocation set). At boot it rebuilds the trust with
//! [`IssuerTrust::from_doc`] — never from a JWKS fetch it may not be able to
//! make — imports the ledger, re-adopts the set, and verifies as before.
//!
//! **Key rotation rule.** Pre-publish a new issuer kid in the JWKS before it
//! signs anything, and keep a retired kid published (verify-only) until every
//! standing binding it signed has been superseded or revoked. Removing a kid
//! from the JWKS means "this key is compromised" and deliberately invalidates
//! every binding it signed. Under that rule a fetched JWKS never lacks a kid a
//! held credential needs, so an edge may always replace its persisted trust
//! with what it fetched; an edge that cannot fetch keeps verifying against what
//! it persisted. Retiring a kid therefore never strands a working offline edge.

use std::collections::{BTreeMap, HashMap};
use std::sync::{PoisonError, RwLock};

use serde::{Deserialize, Serialize};

use cheers_core::{DeviceId, LeaseError, LeaseState, PeerKey, StandingBinding, StoreError};

use crate::artifact::IssuerTrust;
use crate::key_set::VerifyError;
use crate::revocation::RevocationReader;

/// Why [`StandingVerifier::verify_standing_at`] refused a binding. Collapse to
/// one refusal on the wire; the variants are for logs and audit.
#[derive(Debug, thiserror::Error)]
pub enum StandingError {
    /// Not a standing binding signed for the trusted issuer: bad signature, an
    /// access token or other artifact offered as one, a non-issuer-role key, a
    /// foreign issuer.
    #[error("standing binding refused: {0}")]
    Verify(#[from] VerifyError),

    /// Genuine, but it names a different node key than the peer proved.
    #[error("standing binding is not bound to the presented peer key")]
    PeerKeyMismatch,

    /// A newer binding for the same device exists.
    #[error("standing binding for device {device:?} is superseded: seq {offered} is below {newest}")]
    Superseded { device: DeviceId, newest: u64, offered: u64 },

    /// The binding's own `jti` is in the revocation set.
    #[error("standing binding {jti:?} is revoked")]
    Revoked { jti: String },

    /// The binding's device is in the revocation set.
    #[error("device {device:?} is revoked")]
    DeviceRevoked { device: DeviceId },

    /// Signed, but its lease breaks the invariant (`cheers_core::Lease`).
    #[error("standing binding refused: {0}")]
    Lease(#[from] LeaseError),

    /// The revocation reader failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// An admitted binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedStanding {
    pub binding: StandingBinding,
    /// The binding's lease at the verification instant: on `Warning`, fetch a
    /// successor when the issuer is reachable. Advisory — the binding was
    /// admitted either way (it carries no `exp` today).
    pub lease: LeaseState,
}

/// A ledger import ([`BindingLedger`], `SnapshotLedger`) that names a
/// different issuer.
#[derive(Debug, thiserror::Error)]
#[error("ledger belongs to issuer {got:?}, not {expected:?}")]
pub struct ForeignLedger {
    pub expected: String,
    pub got: String,
}

/// A persisted [`BindingLedger`]: the highest `seq` seen per device id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerDoc {
    pub issuer: String,
    pub newest: BTreeMap<String, u64>,
}

/// The highest binding `seq` seen per device, for one issuer.
///
/// Holds only high-water marks — never a token — so it stays one integer per
/// device however many bindings pass through, and it needs no key to restore:
/// a key rotation cannot erase what it knows. Every update is a `max`, so
/// adopting a lower `seq` after a higher one, or importing an older export,
/// cannot un-supersede anything.
#[derive(Debug)]
pub struct BindingLedger {
    issuer: String,
    newest: RwLock<HashMap<DeviceId, u64>>,
}

impl BindingLedger {
    pub fn new(issuer: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            newest: RwLock::new(HashMap::new()),
        }
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The highest `seq` seen for `device`.
    pub fn newest(&self, device: &DeviceId) -> Option<u64> {
        self.newest
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(device)
            .copied()
    }

    /// Record that a genuine binding with `seq` exists for `device` and return
    /// the device's highest `seq` afterwards. Never lowers it.
    pub fn observe(&self, device: &DeviceId, seq: u64) -> u64 {
        let mut newest = self.newest.write().unwrap_or_else(PoisonError::into_inner);
        let held = newest.entry(device.clone()).or_insert(seq);
        *held = (*held).max(seq);
        *held
    }

    /// Every high-water mark, for an edge to persist.
    pub fn export(&self) -> LedgerDoc {
        let newest = self.newest.read().unwrap_or_else(PoisonError::into_inner);
        LedgerDoc {
            issuer: self.issuer.clone(),
            newest: newest.iter().map(|(d, s)| (d.as_str().to_owned(), *s)).collect(),
        }
    }

    /// Merge a persisted ledger in, keeping the higher `seq` per device.
    pub fn import(&self, doc: &LedgerDoc) -> Result<(), ForeignLedger> {
        if doc.issuer != self.issuer {
            return Err(ForeignLedger {
                expected: self.issuer.clone(),
                got: doc.issuer.clone(),
            });
        }
        for (device, seq) in &doc.newest {
            self.observe(&DeviceId::new(device.clone()), *seq);
        }
        Ok(())
    }
}

/// The edge facade for standing node bindings: trust, revocation replica and
/// supersession ledger for one issuer. Like `EdgeVerifier` it holds no minter.
pub struct StandingVerifier<Rd> {
    trust: IssuerTrust,
    revoked: Rd,
    ledger: BindingLedger,
}

impl<Rd> std::fmt::Debug for StandingVerifier<Rd> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StandingVerifier")
            .field("trust", &self.trust)
            .field("ledger", &self.ledger)
            .finish_non_exhaustive()
    }
}

impl<Rd: RevocationReader> StandingVerifier<Rd> {
    /// A verifier with an empty ledger; [`import`](BindingLedger::import) a
    /// persisted one through [`ledger`](Self::ledger) after a restart.
    pub fn new(trust: IssuerTrust, revoked: Rd) -> Self {
        let ledger = BindingLedger::new(trust.issuer());
        Self { trust, revoked, ledger }
    }

    pub fn trust(&self) -> &IssuerTrust {
        &self.trust
    }

    pub fn revocations(&self) -> &Rd {
        &self.revoked
    }

    pub fn ledger(&self) -> &BindingLedger {
        &self.ledger
    }

    /// Verify a binding that arrived without a peer — by gossip, or the edge's
    /// own persisted one at boot — and record its `seq`, so it supersedes
    /// older bindings for its device. Checks the signature only: whether the
    /// binding is revoked or names this peer does not change that the issuer
    /// minted it.
    pub async fn adopt(&self, token: &str) -> Result<StandingBinding, VerifyError> {
        let binding: StandingBinding = self.trust.verify(token).await?;
        self.ledger.observe(&binding.device, binding.seq);
        Ok(binding)
    }

    /// Admit `token` as a standing binding for the peer that proved
    /// `presented` in its handshake.
    ///
    /// In order, cheapest and most local first: signature (recording the
    /// binding's `seq` in the ledger), peer key, supersession, then the
    /// revocation reads (`jti`, then device) — the only I/O. `now` decides
    /// [`VerifiedStanding::lease`] and nothing else: there is no expiry.
    pub async fn verify_standing_at(
        &self,
        token: &str,
        presented: &PeerKey,
        now: i64,
    ) -> Result<VerifiedStanding, StandingError> {
        let binding: StandingBinding = self.trust.verify(token).await?;
        binding.lease.validate(binding.iat)?;
        let newest = self.ledger.observe(&binding.device, binding.seq);
        if !binding.is_bound_to(presented) {
            return Err(StandingError::PeerKeyMismatch);
        }
        if newest > binding.seq {
            return Err(StandingError::Superseded {
                device: binding.device,
                newest,
                offered: binding.seq,
            });
        }
        if self.revoked.is_revoked(&binding.jti).await? {
            return Err(StandingError::Revoked { jti: binding.jti });
        }
        if self.revoked.is_device_revoked(&binding.device, binding.seq).await? {
            return Err(StandingError::DeviceRevoked { device: binding.device });
        }
        let lease = binding.lease.state_at(now);
        Ok(VerifiedStanding { binding, lease })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cheers_core::Lease;
    use crate::artifact::{AnchorDoc, TrustDoc};
    use crate::jwks::{JwkKey, JwksDoc, KeySet};
    use crate::key_set::KeySetVerifier;
    use crate::public_verifier::PasetoV4PublicVerifier;
    use crate::revocation::ReplicatedRevocations;
    use cheers_core::{
        Claims, DeviceBinding, KeyRole, McpClaims, PrincipalId, RevocationSet, Revoked, SignedArtifact, TokenVerifier,
        UserId,
    };
    use pasetors::keys::{AsymmetricKeyPair, AsymmetricSecretKey, Generate};
    use pasetors::version4::{PublicToken, V4};
    use std::sync::Arc;

    const ISS: &str = "https://cheers.test";
    const DEVICE: &str = "node:a";
    const IAT: i64 = 1_000;
    /// Ten years on: far past any access-token window.
    const YEARS_LATER: i64 = IAT + 10 * 365 * 24 * 60 * 60;

    fn kp() -> AsymmetricKeyPair<V4> {
        AsymmetricKeyPair::<V4>::generate().unwrap()
    }

    fn pub_bytes(k: &AsymmetricKeyPair<V4>) -> [u8; 32] {
        k.public.as_bytes().try_into().unwrap()
    }

    fn node(b: u8) -> PeerKey {
        PeerKey::ed25519([b; 32])
    }

    /// Sign `payload` the way `PasetoV4SecretMinter::mint_artifact` does.
    fn sign_with(secret: &AsymmetricSecretKey<V4>, kid: &str, payload: &impl Serialize, ia: Option<&[u8]>) -> String {
        let body = serde_json::to_vec(payload).unwrap();
        let footer = format!(r#"{{"kid":"{kid}"}}"#);
        PublicToken::sign(secret, &body, Some(footer.as_bytes()), ia).unwrap()
    }

    fn binding(seq: u64, key: PeerKey) -> StandingBinding {
        StandingBinding {
            issuer: ISS.into(),
            sub: UserId::new("alice"),
            device: DeviceId::new(DEVICE),
            peer_key: key,
            seq,
            iat: IAT,
            jti: format!("bind-{seq}"),
            lease: Lease::new(IAT, IAT + 7 * 24 * 60 * 60, None).unwrap(),
        }
    }

    struct Rig {
        issuer: AsymmetricKeyPair<V4>,
        assertion: AsymmetricKeyPair<V4>,
        selfsig: AsymmetricKeyPair<V4>,
        doc: JwksDoc,
        replica: Arc<ReplicatedRevocations>,
        edge: StandingVerifier<Arc<ReplicatedRevocations>>,
    }

    impl Rig {
        fn sign(&self, b: &StandingBinding) -> String {
            sign_with(&self.issuer.secret, "iss-1", b, Some(StandingBinding::IMPLICIT_ASSERTION))
        }

        fn revoke(&self, epoch: u64, revoked: Vec<Revoked>) {
            let entries = revoked.iter().map(|e| crate::revocation_entry(e, crate::test_revocation_key)).collect();
            let set = RevocationSet::new(ISS, epoch, entries);
            let token = sign_with(&self.issuer.secret, "iss-1", &set, Some(RevocationSet::IMPLICIT_ASSERTION));
            pollster::block_on(self.replica.adopt(&token)).unwrap();
        }

        fn verify(&self, token: &str, key: &PeerKey, now: i64) -> Result<VerifiedStanding, StandingError> {
            pollster::block_on(self.edge.verify_standing_at(token, key, now))
        }
    }

    fn rig() -> Rig {
        let (issuer, assertion, selfsig) = (kp(), kp(), kp());
        let doc = JwksDoc {
            keys: vec![
                JwkKey::ed25519("iss-1", &pub_bytes(&issuer), ISS, KeyRole::Issuer),
                JwkKey::ed25519("asr-1", &pub_bytes(&assertion), "svc:issues", KeyRole::Assertion),
                JwkKey::ed25519("self-1", &pub_bytes(&selfsig), "svc:issues", KeyRole::SelfSigner),
            ],
        };
        let keys = KeySetVerifier::from_key_set(KeySet::from_doc(doc.clone()).unwrap());
        let trust = IssuerTrust::key_set(ISS, keys.clone());
        let replica = Arc::new(ReplicatedRevocations::new(trust.clone()));
        Rig {
            edge: StandingVerifier::new(trust, replica.clone()),
            replica,
            issuer,
            assertion,
            selfsig,
            doc,
        }
    }

    #[test]
    fn a_binding_verifies_years_after_any_access_window() {
        let r = rig();
        let token = r.sign(&binding(5, node(1)));
        let ok = r.verify(&token, &node(1), YEARS_LATER).unwrap();
        assert_eq!(ok.binding, binding(5, node(1)));
        assert_eq!(ok.lease, LeaseState::Warning { exp: None });
    }

    #[test]
    fn refresh_after_in_the_past_still_verifies() {
        let r = rig();
        let b = binding(5, node(1));
        let token = r.sign(&b);
        let ra = b.lease.refresh_after();
        let warn = LeaseState::Warning { exp: None };
        assert_eq!(r.verify(&token, &node(1), ra - 1).unwrap().lease, LeaseState::Current);
        assert_eq!(r.verify(&token, &node(1), ra).unwrap().lease, warn);
        assert_eq!(r.verify(&token, &node(1), ra + 1).unwrap().lease, warn);
    }

    #[test]
    fn a_lease_past_its_midpoint_is_refused() {
        let r = rig();
        // Forged past the midpoint: only deserialization can build it.
        let mut v = serde_json::to_value(binding(5, node(1))).unwrap();
        v["refresh_after"] = (IAT + 600).into();
        v["exp"] = (IAT + 1_000).into();
        let forged: StandingBinding = serde_json::from_value(v).unwrap();
        let token = r.sign(&forged);
        let err = r.verify(&token, &node(1), IAT).unwrap_err();
        assert!(matches!(err, StandingError::Lease(_)), "got {err:?}");
        // At the midpoint it verifies and reports the window.
        let mut v = serde_json::to_value(binding(5, node(1))).unwrap();
        v["refresh_after"] = (IAT + 500).into();
        v["exp"] = (IAT + 1_000).into();
        let ok: StandingBinding = serde_json::from_value(v).unwrap();
        let token = r.sign(&ok);
        assert_eq!(r.verify(&token, &node(1), IAT + 500).unwrap().lease, LeaseState::Warning { exp: Some(IAT + 1_000) });
    }

    #[test]
    fn a_wrong_peer_key_is_refused() {
        let r = rig();
        let token = r.sign(&binding(5, node(1)));
        assert!(matches!(r.verify(&token, &node(2), IAT), Err(StandingError::PeerKeyMismatch)));
    }

    #[test]
    fn a_revoked_jti_is_refused() {
        let r = rig();
        let token = r.sign(&binding(5, node(1)));
        r.verify(&token, &node(1), IAT).unwrap();
        r.revoke(1, vec![Revoked::jti("bind-5", None)]);
        match r.verify(&token, &node(1), IAT) {
            Err(StandingError::Revoked { jti }) => assert_eq!(jti, "bind-5"),
            other => panic!("expected Revoked, got {other:?}"),
        }
    }

    #[test]
    fn a_revoked_device_is_refused() {
        let r = rig();
        let token = r.sign(&binding(5, node(1)));
        r.revoke(1, vec![Revoked::device("node:other", 100)]);
        r.verify(&token, &node(1), IAT).unwrap();
        // A revoke at seq 5 masks bindings below 5 only; this one is at 5.
        r.revoke(2, vec![Revoked::device(DEVICE, 5)]);
        r.verify(&token, &node(1), IAT).unwrap();
        r.revoke(3, vec![Revoked::device(DEVICE, 6)]);
        match r.verify(&token, &node(1), YEARS_LATER) {
            Err(StandingError::DeviceRevoked { device }) => assert_eq!(device.as_str(), DEVICE),
            other => panic!("expected DeviceRevoked, got {other:?}"),
        }
        // Re-enrolling the machine mints a seq above the revoke: admitted.
        let reenrolled = r.sign(&binding(7, node(1)));
        r.verify(&reenrolled, &node(1), YEARS_LATER).unwrap();
    }

    #[test]
    fn a_superseded_binding_is_refused_and_its_successor_accepted() {
        let r = rig();
        let old = r.sign(&binding(5, node(1)));
        // Re-enrolled under a new node key: higher seq, same device.
        let new = r.sign(&binding(7, node(2)));
        r.verify(&old, &node(1), IAT).unwrap();
        r.verify(&new, &node(2), IAT).unwrap();
        match r.verify(&old, &node(1), IAT) {
            Err(StandingError::Superseded { device, newest: 7, offered: 5 }) => assert_eq!(device.as_str(), DEVICE),
            other => panic!("expected Superseded, got {other:?}"),
        }
        r.verify(&new, &node(2), YEARS_LATER).unwrap();
        // Other devices are untouched.
        let mut elsewhere = binding(1, node(3));
        elsewhere.device = DeviceId::new("node:b");
        r.verify(&r.sign(&elsewhere), &node(3), IAT).unwrap();
    }

    #[test]
    fn a_successor_heard_by_gossip_supersedes_without_being_presented() {
        let r = rig();
        let old = r.sign(&binding(5, node(1)));
        pollster::block_on(r.edge.adopt(&r.sign(&binding(6, node(1))))).unwrap();
        assert!(matches!(r.verify(&old, &node(1), IAT), Err(StandingError::Superseded { .. })));
    }

    #[test]
    fn a_lower_sequence_adopted_after_a_higher_one_does_not_unsupersede() {
        let r = rig();
        let middle = r.sign(&binding(7, node(1)));
        pollster::block_on(r.edge.adopt(&r.sign(&binding(9, node(1))))).unwrap();
        pollster::block_on(r.edge.adopt(&r.sign(&binding(3, node(1))))).unwrap();
        assert_eq!(r.edge.ledger().newest(&DeviceId::new(DEVICE)), Some(9));
        assert!(matches!(
            r.verify(&middle, &node(1), IAT),
            Err(StandingError::Superseded { newest: 9, offered: 7, .. })
        ));
        // An older persisted ledger imported later cannot lower it either.
        let stale = LedgerDoc {
            issuer: ISS.into(),
            newest: [(DEVICE.to_owned(), 2)].into_iter().collect(),
        };
        r.edge.ledger().import(&stale).unwrap();
        assert_eq!(r.edge.ledger().newest(&DeviceId::new(DEVICE)), Some(9));
    }

    #[test]
    fn a_binding_is_refused_as_an_access_token() {
        let r = rig();
        let token = r.sign(&binding(5, node(1)));
        let keys = KeySetVerifier::from_key_set(KeySet::from_doc(r.doc.clone()).unwrap());
        let as_mcp = pollster::block_on(keys.verify::<serde_json::Value>(&token, IAT, ISS, None));
        assert!(matches!(as_mcp, Err(VerifyError::SignatureMismatch)));
        let pinned = PasetoV4PublicVerifier::from_public_key(&pub_bytes(&r.issuer)).unwrap();
        assert!(pinned.verify_mcp_at(&token, IAT, "iss-1").is_err());
        assert!(pinned.verify_at(&token, IAT).is_err());
    }

    #[test]
    fn an_access_token_or_other_artifact_is_refused_as_a_binding() {
        let r = rig();
        // The binding's own payload, signed with the access-token (empty) assertion.
        let unasserted = sign_with(&r.issuer.secret, "iss-1", &binding(5, node(1)), None);
        assert!(matches!(
            r.verify(&unasserted, &node(1), IAT),
            Err(StandingError::Verify(VerifyError::SignatureMismatch))
        ));
        // A real MCP access token.
        let mcp = McpClaims::new(ISS, "https://aud.test", PrincipalId::user("alice"), IAT, IAT + 900, "j", vec![]);
        let mcp = sign_with(&r.issuer.secret, "iss-1", &mcp, None);
        assert!(matches!(r.verify(&mcp, &node(1), IAT), Err(StandingError::Verify(_))));
        // A v4.public session token in the `cheers` claim convention.
        let claims = Claims::new(UserId::new("alice"), DeviceId::new(DEVICE), DeviceBinding::LanPair, IAT, IAT + 900)
            .with_peer_key(node(1));
        let session = sign_with(&r.issuer.secret, "iss-1", &serde_json::json!({ "cheers": claims }), None);
        assert!(matches!(r.verify(&session, &node(1), IAT), Err(StandingError::Verify(_))));
        // Another artifact kind's assertion over a binding payload.
        let cross = sign_with(&r.issuer.secret, "iss-1", &binding(5, node(1)), Some(RevocationSet::IMPLICIT_ASSERTION));
        assert!(matches!(
            r.verify(&cross, &node(1), IAT),
            Err(StandingError::Verify(VerifyError::SignatureMismatch))
        ));
        assert_eq!(r.edge.ledger().newest(&DeviceId::new(DEVICE)), None);
    }

    #[test]
    fn a_non_issuer_role_key_is_refused() {
        let r = rig();
        let b = binding(5, node(1));
        let ia = Some(StandingBinding::IMPLICIT_ASSERTION);
        for (secret, kid) in [(&r.assertion.secret, "asr-1"), (&r.selfsig.secret, "self-1")] {
            let token = sign_with(secret, kid, &b, ia);
            assert!(matches!(
                r.verify(&token, &node(1), IAT),
                Err(StandingError::Verify(VerifyError::KeyRoleRejected { .. }))
            ));
        }
        // A binding claiming a foreign issuer, signed by the trusted key.
        let mut foreign = b;
        foreign.issuer = "https://elsewhere.test".into();
        assert!(matches!(
            r.verify(&r.sign(&foreign), &node(1), IAT),
            Err(StandingError::Verify(VerifyError::BadIssuer { .. }))
        ));
        assert_eq!(r.edge.ledger().newest(&DeviceId::new(DEVICE)), None);
    }

    #[test]
    fn ledger_export_import_round_trips() {
        let r = rig();
        let ledger = r.edge.ledger();
        ledger.observe(&DeviceId::new("node:a"), 9);
        ledger.observe(&DeviceId::new("node:b"), 4);
        let json = serde_json::to_string(&ledger.export()).unwrap();

        let back: LedgerDoc = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ledger.export());
        let restored = BindingLedger::new(ISS);
        restored.import(&back).unwrap();
        assert_eq!(restored.export(), ledger.export());
        assert_eq!(restored.newest(&DeviceId::new("node:a")), Some(9));
        assert_eq!(restored.newest(&DeviceId::new("node:c")), None);

        // Merge keeps the higher mark per device.
        let other = BindingLedger::new(ISS);
        other.observe(&DeviceId::new("node:a"), 12);
        other.observe(&DeviceId::new("node:b"), 1);
        restored.import(&other.export()).unwrap();
        assert_eq!(restored.newest(&DeviceId::new("node:a")), Some(12));
        assert_eq!(restored.newest(&DeviceId::new("node:b")), Some(4));

        let foreign = BindingLedger::new("https://elsewhere.test");
        assert!(restored.import(&foreign.export()).is_err());
    }

    #[test]
    fn an_offline_restart_verifies_against_the_persisted_key_set() {
        let r = rig();
        let held = r.sign(&binding(7, node(1)));
        let old = r.sign(&binding(5, node(1)));
        r.verify(&held, &node(1), IAT).unwrap();
        r.revoke(3, vec![Revoked::jti("bind-other", None)]);

        // What the edge writes to disk.
        let trust_json = serde_json::to_string(&r.edge.trust().export()).unwrap();
        let ledger_json = serde_json::to_string(&r.edge.ledger().export()).unwrap();
        let set = r.replica.export().unwrap();
        drop(r.edge);

        // Meanwhile the issuer rotated: a freshly fetched JWKS no longer has
        // iss-1, so verifying against it would strand the node.
        let rotated = JwksDoc {
            keys: vec![JwkKey::ed25519("iss-2", &pub_bytes(&kp()), ISS, KeyRole::Issuer)],
        };
        let fetched = IssuerTrust::key_set(ISS, KeySetVerifier::from_key_set(KeySet::from_doc(rotated).unwrap()));
        assert!(matches!(
            pollster::block_on(fetched.verify::<StandingBinding>(&held)),
            Err(VerifyError::UnknownKid(_))
        ));

        // Restart offline from the persisted documents alone.
        let doc: TrustDoc = serde_json::from_str(&trust_json).unwrap();
        assert!(matches!(doc.anchor, AnchorDoc::KeySet(_)));
        let trust = IssuerTrust::from_doc(doc).unwrap();
        let replica = Arc::new(ReplicatedRevocations::new(trust.clone()));
        pollster::block_on(replica.adopt(&set)).unwrap();
        let edge = StandingVerifier::new(trust, replica);
        edge.ledger().import(&serde_json::from_str(&ledger_json).unwrap()).unwrap();

        let ok = pollster::block_on(edge.verify_standing_at(&held, &node(1), YEARS_LATER)).unwrap();
        assert_eq!(ok.binding.seq, 7);
        // Supersession and the role rules survived the restart.
        assert!(matches!(
            pollster::block_on(edge.verify_standing_at(&old, &node(1), YEARS_LATER)),
            Err(StandingError::Superseded { newest: 7, offered: 5, .. })
        ));
        let by_assertion = sign_with(&r.assertion.secret, "asr-1", &binding(8, node(1)), Some(StandingBinding::IMPLICIT_ASSERTION));
        assert!(matches!(
            pollster::block_on(edge.verify_standing_at(&by_assertion, &node(1), IAT)),
            Err(StandingError::Verify(VerifyError::KeyRoleRejected { .. }))
        ));
    }

    #[test]
    fn a_pinned_trust_round_trips_through_its_document() {
        let issuer = kp();
        let pinned = IssuerTrust::pinned(ISS, PasetoV4PublicVerifier::from_public_key(&pub_bytes(&issuer)).unwrap());
        let json = serde_json::to_string(&pinned.export()).unwrap();
        let back = IssuerTrust::from_doc(serde_json::from_str(&json).unwrap()).unwrap();
        let token = sign_with(&issuer.secret, "any", &binding(1, node(1)), Some(StandingBinding::IMPLICIT_ASSERTION));
        let edge = StandingVerifier::new(back, Arc::new(ReplicatedRevocations::new(pinned)));
        pollster::block_on(edge.verify_standing_at(&token, &node(1), YEARS_LATER)).unwrap();

        let short = TrustDoc {
            issuer: ISS.into(),
            anchor: AnchorDoc::Pinned("AAAA".into()),
        };
        assert!(IssuerTrust::from_doc(short).is_err());
    }
}
