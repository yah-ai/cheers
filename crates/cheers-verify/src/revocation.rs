//! The **read** side of the revocation split.
//!
//! Revocation has two physically distinct sides, and edge-verifiable auth (R019)
//! depends on keeping them apart. This crate holds the edge half:
//!
//! - [`RevocationReader`] — the **hot path**, run at the edge on every request.
//!   Point membership checks — a `jti`, a device, a `(resource, user)`
//!   membership — against a locally-replicated, read-mostly set (CF KV / a
//!   gossip replica).
//! - [`ReplicatedRevocations`] — the offline replica (R732-F6): it adopts
//!   issuer-signed [`RevocationSet`]s, keeps the highest epoch it has seen, and
//!   answers [`RevocationReader`] from it.
//! - The **cold path** writer (`RevocationWriter`) lives in `cheers-server` —
//!   keeping it out of this crate means a verify-only edge consumer can check
//!   revocation without holding the power to revoke anyone else's sessions, the
//!   same capability-by-type discipline as the `TokenVerifier` / `TokenMinter`
//!   split.
//!
//! # The consistency contract
//!
//! The set is **eventually consistent** by design. A `revoke` at the origin
//! propagates to edge readers asynchronously (KV replication / gossip), so an
//! edge reader may briefly answer `false` for an entry the origin has already
//! revoked. What bounds that lag depends on the credential:
//!
//! - **Access tokens** (15-min `exp`): a revoked-but-not-yet-propagated token
//!   outlives its revocation by at most one access TTL, then expires on its own
//!   signature.
//! - **Standing credentials** (membership snapshots, node bindings — noisetable
//!   W235 §5.1): no edge-enforced expiry, so **revocation is the only bound**.
//!   A removed member keeps a fully offline LAN until a set naming them reaches
//!   it. That cost is accepted (W235 §0.1).
//!
//! This is sound because auth has no cross-session OLTP — every check validates
//! *one* session, so the global hot path never needs a consistent view across
//! sessions. Revocation membership is the *only* shared auth state the edge
//! reads, and it tolerates lag.

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};

use async_trait::async_trait;

use cheers_core::{DeviceId, MembershipTag, PrincipalId, RevocationEntry, RevocationKey, RevocationSet, Revoked, StoreError};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::artifact::IssuerTrust;
use crate::key_set::VerifyError;

/// Domain separation for [`membership_tag`].
const MEMBERSHIP_TAG_CONTEXT: &[u8] = b"urn:cheers:revocation:membership-tag:v2";

/// The published name of `principal`'s membership revocation on `(kind, id)`:
/// `HMAC-SHA256(key, ctx || len-prefixed kind, id, principal)`, each length a
/// big-endian `u64` so no two triples share an input. `principal` enters in
/// its kind-prefixed wire form (`user:x`, `key:x`), so a user and a key with
/// one id string never share a tag (ctx `v2`; `v1` hashed a bare user id). `key` is the resource's
/// [`RevocationKey`]; see `cheers_core::revocation`, "Membership privacy".
/// The issuer computes it on publish, an edge on lookup.
pub fn membership_tag(key: &RevocationKey, kind: &str, id: &str, principal: &PrincipalId) -> MembershipTag {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_bytes()).expect("HMAC takes any key length");
    mac.update(MEMBERSHIP_TAG_CONTEXT);
    let principal = principal.to_string();
    for part in [kind, id, principal.as_str()] {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part.as_bytes());
    }
    MembershipTag::from_bytes(mac.finalize().into_bytes().into())
}

/// The published form of a store entry: a membership becomes its
/// [`membership_tag`] under `key_of(kind, id)`; a jti or device is copied (and
/// `key_of` is not called).
pub fn revocation_entry(entry: &Revoked, key_of: impl FnOnce(&str, &str) -> RevocationKey) -> RevocationEntry {
    match entry {
        Revoked::Jti { jti, exp } => RevocationEntry::Jti { jti: jti.clone(), exp: *exp },
        Revoked::Device { device, at_seq } => RevocationEntry::Device { device: device.clone(), at_seq: *at_seq },
        Revoked::Membership { kind, id, principal, at_epoch } => RevocationEntry::Membership {
            tag: membership_tag(&key_of(kind, id), kind, id, principal),
            at_epoch: *at_epoch,
        },
    }
}

/// A deterministic per-resource key for tests on either side of the wire.
#[doc(hidden)]
pub fn test_revocation_key(kind: &str, id: &str) -> RevocationKey {
    use sha2::Digest as _;
    RevocationKey::from_bytes(Sha256::digest(format!("test-key/{kind}/{id}")).into())
}

/// Edge-side revocation check. The verify-only consumer depends on *this* — it
/// can ask whether something is revoked but holds no power to revoke.
///
/// A `false` answer is never a *proof* of liveness — only that the revocation,
/// if any, has not yet reached this replica (see the module contract).
///
/// `async` + dyn-compatible (via [`async_trait`]) to match the rest of the store
/// surface, so an edge can hold a `dyn RevocationReader` backed by CF KV.
#[async_trait]
pub trait RevocationReader: Send + Sync {
    /// `true` if the credential with this `jti` has been revoked
    /// ([`Revoked::Jti`]). Cryptographic expiry is enforced separately by the
    /// [`TokenVerifier`](cheers_core::TokenVerifier).
    ///
    /// A jti entry whose `exp` has passed may read as unrevoked: the
    /// credential is dead on its own signature by then.
    async fn is_revoked(&self, jti: &str) -> Result<bool, StoreError>;

    /// `true` if a standing binding of `device` at sequence `seq` is revoked:
    /// a [`Revoked::Device`] entry exists with `seq < at_seq` — the check a
    /// standing node binding (R732-F5) makes. A binding minted after the
    /// revoke (re-enrollment) carries a higher seq and reads `false`.
    async fn is_device_revoked(&self, device: &DeviceId, seq: u64) -> Result<bool, StoreError>;

    /// `true` if `principal`'s membership of resource `(kind, id)` in a
    /// snapshot at `snapshot_epoch` is revoked: a membership entry exists with
    /// `snapshot_epoch < at_epoch` — the check a membership snapshot (R732-F4)
    /// makes per member. Any principal kind, a `Key` included.
    ///
    /// `key` is `(kind, id)`'s [`RevocationKey`], taken from the snapshot
    /// being checked. A replica of the published set holds only tags and
    /// looks up [`membership_tag`]`(key, kind, id, principal)`; an origin store
    /// holding plaintext rows may ignore it.
    async fn is_membership_revoked(
        &self,
        key: &RevocationKey,
        kind: &str,
        id: &str,
        principal: &PrincipalId,
        snapshot_epoch: u64,
    ) -> Result<bool, StoreError>;
}

/// One replica shared by a gossip task and a verifier.
#[async_trait]
impl<T: RevocationReader + ?Sized> RevocationReader for Arc<T> {
    async fn is_revoked(&self, jti: &str) -> Result<bool, StoreError> {
        (**self).is_revoked(jti).await
    }

    async fn is_device_revoked(&self, device: &DeviceId, seq: u64) -> Result<bool, StoreError> {
        (**self).is_device_revoked(device, seq).await
    }

    async fn is_membership_revoked(
        &self,
        key: &RevocationKey,
        kind: &str,
        id: &str,
        principal: &PrincipalId,
        snapshot_epoch: u64,
    ) -> Result<bool, StoreError> {
        (**self).is_membership_revoked(key, kind, id, principal, snapshot_epoch).await
    }
}

/// What [`ReplicatedRevocations::adopt`] did with a verified set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Adopted {
    /// The set replaced the held one (`from: None` when nothing was held).
    Advanced { from: Option<u64>, to: u64 },
    /// The set carried the epoch already held. Equal epochs carry equal
    /// contents, so this is a no-op.
    Unchanged { epoch: u64 },
}

/// Why [`ReplicatedRevocations::adopt`] refused a set.
#[derive(Debug, thiserror::Error)]
pub enum AdoptError {
    /// Not a revocation set signed for the trusted issuer: bad signature, an
    /// access token offered as a set, a non-issuer-role key, a foreign issuer.
    #[error("revocation set refused: {0}")]
    Verify(#[from] VerifyError),

    /// A genuine set, but older than the one held. Gossip delivers sets out of
    /// order, so callers should treat this as routine, not as an attack.
    #[error("stale revocation set: epoch {offered} is below the held epoch {held}")]
    Stale { held: u64, offered: u64 },
}

/// The held set, indexed identity -> bound for point lookups.
struct Held {
    epoch: u64,
    token: String,
    jtis: HashMap<String, Option<i64>>,
    devices: HashMap<DeviceId, u64>,
    memberships: HashMap<MembershipTag, u64>,
}

impl Held {
    fn new(set: RevocationSet, token: &str) -> Self {
        let mut held = Self {
            epoch: set.epoch,
            token: token.to_owned(),
            jtis: HashMap::new(),
            devices: HashMap::new(),
            memberships: HashMap::new(),
        };
        // A signed set is canonical (one entry per identity), but a set built
        // by hand need not be: keep the greatest bound either way.
        for entry in set.revoked {
            match entry {
                RevocationEntry::Jti { jti, exp } => {
                    let kept = held.jtis.entry(jti).or_insert(exp);
                    *kept = match (*kept, exp) {
                        (Some(a), Some(b)) => Some(a.max(b)),
                        _ => None,
                    };
                }
                RevocationEntry::Device { device, at_seq } => {
                    let kept = held.devices.entry(device).or_insert(at_seq);
                    *kept = (*kept).max(at_seq);
                }
                RevocationEntry::Membership { tag, at_epoch } => {
                    let kept = held.memberships.entry(tag).or_insert(at_epoch);
                    *kept = (*kept).max(at_epoch);
                }
            }
        }
        held
    }
}

/// An offline replica of one issuer's revocation set (R732-F6).
///
/// [`adopt`](Self::adopt) verifies a signed set against the [`IssuerTrust`]
/// (pinned key, or JWKS with only issuer-role keys accepted) and keeps it only
/// if its epoch is higher than the one held. Readers never block on an adopt:
/// the held set is an `Arc` swapped under a short write lock, after the
/// signature work is done.
///
/// **Persistence.** [`export`](Self::export) returns the held set as the signed
/// token itself; an edge writes those bytes to disk and, after a restart, hands
/// them back to [`adopt`](Self::adopt), which re-verifies them. Gossip carries
/// the same bytes between peers. Transport and storage are the consumer's.
pub struct ReplicatedRevocations {
    trust: IssuerTrust,
    held: RwLock<Option<Arc<Held>>>,
}

impl std::fmt::Debug for ReplicatedRevocations {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplicatedRevocations")
            .field("trust", &self.trust)
            .field("epoch", &self.epoch())
            .finish()
    }
}

impl ReplicatedRevocations {
    /// An empty replica. Until a set is adopted every query answers `false`.
    pub fn new(trust: IssuerTrust) -> Self {
        Self {
            trust,
            held: RwLock::new(None),
        }
    }

    pub fn issuer(&self) -> &str {
        self.trust.issuer()
    }

    /// Verify `token` as a [`RevocationSet`] for the trusted issuer and adopt
    /// it if its epoch is higher than the one held.
    ///
    /// An equal epoch is [`Adopted::Unchanged`]; a lower one is
    /// [`AdoptError::Stale`]. Concurrent adopts are linearised on the epoch:
    /// whatever order they finish in, the highest epoch wins.
    pub async fn adopt(&self, token: &str) -> Result<Adopted, AdoptError> {
        let set: RevocationSet = self.trust.verify(token).await?;
        let offered = Held::new(set, token);
        let mut held = self.held.write().unwrap_or_else(PoisonError::into_inner);
        let from = held.as_ref().map(|h| h.epoch);
        match from {
            Some(epoch) if offered.epoch < epoch => Err(AdoptError::Stale {
                held: epoch,
                offered: offered.epoch,
            }),
            Some(epoch) if offered.epoch == epoch => Ok(Adopted::Unchanged { epoch }),
            _ => {
                let to = offered.epoch;
                *held = Some(Arc::new(offered));
                Ok(Adopted::Advanced { from, to })
            }
        }
    }

    /// The held epoch, or `None` before the first adopt.
    pub fn epoch(&self) -> Option<u64> {
        self.held().map(|h| h.epoch)
    }

    /// The held set as the signed token it arrived as — what an edge persists
    /// and gossips. Feed it back through [`adopt`](Self::adopt) to import.
    pub fn export(&self) -> Option<String> {
        self.held().map(|h| h.token.clone())
    }

    fn held(&self) -> Option<Arc<Held>> {
        self.held.read().unwrap_or_else(PoisonError::into_inner).clone()
    }
}

#[async_trait]
impl RevocationReader for ReplicatedRevocations {
    async fn is_revoked(&self, jti: &str) -> Result<bool, StoreError> {
        // The held set is fixed per epoch, so a lapsed jti stays named until
        // a newer set drops it; it masks only a credential that is already
        // dead on its own exp.
        Ok(self.held().is_some_and(|h| h.jtis.contains_key(jti)))
    }

    async fn is_device_revoked(&self, device: &DeviceId, seq: u64) -> Result<bool, StoreError> {
        Ok(self.held().is_some_and(|h| h.devices.get(device).is_some_and(|&at| seq < at)))
    }

    async fn is_membership_revoked(
        &self,
        key: &RevocationKey,
        kind: &str,
        id: &str,
        principal: &PrincipalId,
        snapshot_epoch: u64,
    ) -> Result<bool, StoreError> {
        let Some(held) = self.held() else {
            return Ok(false);
        };
        let tag = membership_tag(key, kind, id, principal);
        Ok(held.memberships.get(&tag).is_some_and(|&at| snapshot_epoch < at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwks::{JwkKey, JwksDoc, KeySet};
    use crate::key_set::KeySetVerifier;
    use crate::public_verifier::PasetoV4PublicVerifier;
    use cheers_core::{KeyRole, McpClaims, PrincipalId, SignedArtifact, TokenVerifier};
    use pasetors::keys::{AsymmetricKeyPair, AsymmetricSecretKey, Generate};
    use pasetors::version4::{PublicToken, V4};

    const ISS: &str = "https://cheers.test";

    fn kp() -> AsymmetricKeyPair<V4> {
        AsymmetricKeyPair::<V4>::generate().unwrap()
    }

    fn pub_bytes(k: &AsymmetricKeyPair<V4>) -> [u8; 32] {
        k.public.as_bytes().try_into().unwrap()
    }

    /// Sign `payload` the way `PasetoV4SecretMinter::mint_artifact` does.
    fn sign_with(secret: &AsymmetricSecretKey<V4>, kid: &str, payload: &impl serde::Serialize, ia: Option<&[u8]>) -> String {
        let body = serde_json::to_vec(payload).unwrap();
        let footer = format!(r#"{{"kid":"{kid}"}}"#);
        PublicToken::sign(secret, &body, Some(footer.as_bytes()), ia).unwrap()
    }

    fn sign_set(secret: &AsymmetricSecretKey<V4>, kid: &str, set: &RevocationSet) -> String {
        sign_with(secret, kid, set, Some(RevocationSet::IMPLICIT_ASSERTION))
    }

    fn set(epoch: u64, revoked: Vec<Revoked>) -> RevocationSet {
        let entries = revoked.iter().map(|e| revocation_entry(e, test_revocation_key)).collect();
        RevocationSet::new(ISS, epoch, entries)
    }

    struct Rig {
        issuer: AsymmetricKeyPair<V4>,
        assertion: AsymmetricKeyPair<V4>,
        selfsig: AsymmetricKeyPair<V4>,
        replica: ReplicatedRevocations,
    }

    fn jwks_rig() -> Rig {
        let (issuer, assertion, selfsig) = (kp(), kp(), kp());
        let doc = JwksDoc {
            keys: vec![
                JwkKey::ed25519("iss-1", &pub_bytes(&issuer), ISS, KeyRole::Issuer),
                JwkKey::ed25519("asr-1", &pub_bytes(&assertion), "svc:issues", KeyRole::Assertion),
                JwkKey::ed25519("self-1", &pub_bytes(&selfsig), "svc:issues", KeyRole::SelfSigner),
            ],
        };
        let keys = KeySetVerifier::from_key_set(KeySet::from_doc(doc).unwrap());
        Rig {
            replica: ReplicatedRevocations::new(IssuerTrust::key_set(ISS, keys)),
            issuer,
            assertion,
            selfsig,
        }
    }

    fn adopt(r: &ReplicatedRevocations, token: &str) -> Result<Adopted, AdoptError> {
        pollster::block_on(r.adopt(token))
    }

    fn jti(r: &ReplicatedRevocations, j: &str) -> bool {
        pollster::block_on(r.is_revoked(j)).unwrap()
    }

    fn device(r: &ReplicatedRevocations, d: &str) -> bool {
        pollster::block_on(r.is_device_revoked(&DeviceId::new(d), 0)).unwrap()
    }

    fn member(r: &ReplicatedRevocations, kind: &str, id: &str, user: &str) -> bool {
        pollster::block_on(r.is_membership_revoked(&test_revocation_key(kind, id), kind, id, &PrincipalId::user(user), 0)).unwrap()
    }

    #[test]
    fn empty_replica_answers_false() {
        let r = jwks_rig();
        assert_eq!(r.replica.epoch(), None);
        assert_eq!(r.replica.export(), None);
        assert!(!jti(&r.replica, "j1"));
        assert!(!device(&r.replica, "phone"));
        assert!(!member(&r.replica, "namespace", "ns-1", "alice"));
    }

    #[test]
    fn adopted_set_answers_jti_device_and_membership_queries() {
        let r = jwks_rig();
        let s = set(
            5,
            vec![
                Revoked::jti("j1", None),
                Revoked::device("phone", 1),
                Revoked::membership("namespace", "ns-1", PrincipalId::user("alice"), 1),
            ],
        );
        assert_eq!(
            adopt(&r.replica, &sign_set(&r.issuer.secret, "iss-1", &s)).unwrap(),
            Adopted::Advanced { from: None, to: 5 }
        );
        assert!(jti(&r.replica, "j1"));
        assert!(!jti(&r.replica, "j2"));
        assert!(device(&r.replica, "phone"));
        assert!(!device(&r.replica, "laptop"));
        assert!(member(&r.replica, "namespace", "ns-1", "alice"));
        // Every coordinate of the membership triple matters.
        assert!(!member(&r.replica, "namespace", "ns-1", "bob"));
        assert!(!member(&r.replica, "namespace", "ns-2", "alice"));
        assert!(!member(&r.replica, "room", "ns-1", "alice"));
        // The wrong resource key finds nothing: the set names tags, not people.
        let wrong = test_revocation_key("namespace", "ns-2");
        let alice = PrincipalId::user("alice");
        assert!(!pollster::block_on(r.replica.is_membership_revoked(&wrong, "namespace", "ns-1", &alice, 0)).unwrap());
        // Kinds don't bleed: a jti named like a device is not a device.
        assert!(!device(&r.replica, "j1"));
    }

    #[test]
    fn a_published_set_names_no_member_in_clear() {
        let s = set(1, vec![Revoked::membership("namespace", "ns-secret", PrincipalId::user("alice-secret"), 3)]);
        let wire = serde_json::to_string(&s).unwrap();
        assert!(!wire.contains("ns-secret") && !wire.contains("alice-secret"), "{wire}");
        assert!(wire.contains("\"tag\""));
    }

    #[test]
    fn tags_are_length_prefixed_so_triples_do_not_collide() {
        let key = test_revocation_key("k", "i");
        assert_ne!(
            membership_tag(&key, "ab", "c", &PrincipalId::user("d")),
            membership_tag(&key, "a", "bc", &PrincipalId::user("d"))
        );
    }

    #[test]
    fn a_user_and_a_key_with_one_id_string_tag_differently() {
        let key = test_revocation_key("namespace", "ns-1");
        let k = PrincipalId::from_public_key(&[3; 32]);
        let u = PrincipalId::user(k.id.clone());
        assert_eq!(u.id, k.id);
        assert_ne!(membership_tag(&key, "namespace", "ns-1", &u), membership_tag(&key, "namespace", "ns-1", &k));

        // And a replica holding the key's revocation does not mask the user.
        let r = jwks_rig();
        let s = set(5, vec![Revoked::membership("namespace", "ns-1", k.clone(), 7)]);
        adopt(&r.replica, &sign_set(&r.issuer.secret, "iss-1", &s)).unwrap();
        let revoked = |p: &PrincipalId| pollster::block_on(r.replica.is_membership_revoked(&key, "namespace", "ns-1", p, 6)).unwrap();
        assert!(revoked(&k));
        assert!(!revoked(&u));
    }

    #[test]
    fn device_and_membership_entries_mask_only_below_their_bound() {
        let r = jwks_rig();
        let s = set(5, vec![Revoked::device("phone", 100), Revoked::membership("namespace", "ns-1", PrincipalId::user("alice"), 7)]);
        adopt(&r.replica, &sign_set(&r.issuer.secret, "iss-1", &s)).unwrap();
        let dev = |seq| pollster::block_on(r.replica.is_device_revoked(&DeviceId::new("phone"), seq)).unwrap();
        assert!(dev(99));
        assert!(!dev(100), "a binding minted at or after the revoke (re-enrollment) is admitted");
        assert!(!dev(101));
        let key = test_revocation_key("namespace", "ns-1");
        let mem = |e| {
            pollster::block_on(r.replica.is_membership_revoked(&key, "namespace", "ns-1", &PrincipalId::user("alice"), e)).unwrap()
        };
        assert!(mem(6));
        assert!(!mem(7));
        assert!(!mem(8));
    }

    #[test]
    fn lower_epoch_is_refused_and_equal_epoch_is_a_no_op() {
        let r = jwks_rig();
        let newer = set(10, vec![Revoked::jti("j1", None), Revoked::jti("j2", None)]);
        adopt(&r.replica, &sign_set(&r.issuer.secret, "iss-1", &newer)).unwrap();

        let older = set(9, vec![Revoked::jti("j1", None)]);
        match adopt(&r.replica, &sign_set(&r.issuer.secret, "iss-1", &older)) {
            Err(AdoptError::Stale { held: 10, offered: 9 }) => {}
            other => panic!("expected Stale, got {other:?}"),
        }
        let same_epoch = set(10, vec![]);
        assert_eq!(
            adopt(&r.replica, &sign_set(&r.issuer.secret, "iss-1", &same_epoch)).unwrap(),
            Adopted::Unchanged { epoch: 10 }
        );
        // Neither touched the held set.
        assert_eq!(r.replica.epoch(), Some(10));
        assert!(jti(&r.replica, "j2"));

        // A higher epoch replaces it wholesale — an entry it drops is lifted.
        let next = set(11, vec![Revoked::jti("j1", None)]);
        assert_eq!(
            adopt(&r.replica, &sign_set(&r.issuer.secret, "iss-1", &next)).unwrap(),
            Adopted::Advanced { from: Some(10), to: 11 }
        );
        assert!(!jti(&r.replica, "j2"));
    }

    #[test]
    fn an_access_token_is_refused_as_a_set() {
        let r = jwks_rig();
        // Issuer-signed with the access-token (empty) implicit assertion.
        let token = sign_with(&r.issuer.secret, "iss-1", &set(1, vec![Revoked::jti("j1", None)]), None);
        assert!(matches!(
            adopt(&r.replica, &token),
            Err(AdoptError::Verify(VerifyError::SignatureMismatch))
        ));
        let mcp = McpClaims::new(ISS, "https://aud.test", PrincipalId::user("alice"), 1, 2, "j", vec![]);
        let token = sign_with(&r.issuer.secret, "iss-1", &mcp, None);
        assert!(matches!(adopt(&r.replica, &token), Err(AdoptError::Verify(_))));
        assert_eq!(r.replica.epoch(), None);
    }

    #[test]
    fn a_set_is_refused_as_an_access_token() {
        let r = jwks_rig();
        let token = sign_set(&r.issuer.secret, "iss-1", &set(1, vec![]));
        let keys = KeySetVerifier::from_issuer_key("iss-1", &pub_bytes(&r.issuer), ISS);
        let res = pollster::block_on(keys.verify_mcp(&token, 0, ISS, None));
        assert!(matches!(res, Err(VerifyError::SignatureMismatch)), "{res:?}");
        let pinned = PasetoV4PublicVerifier::from_public_key(&pub_bytes(&r.issuer)).unwrap();
        assert!(pinned.verify_mcp_at(&token, 0, "iss-1").is_err());
        assert!(pinned.verify_at(&token, 0).is_err());
    }

    #[test]
    fn only_an_issuer_role_key_may_sign_a_set() {
        let r = jwks_rig();
        let s = set(1, vec![]);
        for (secret, kid) in [(&r.assertion.secret, "asr-1"), (&r.selfsig.secret, "self-1")] {
            match adopt(&r.replica, &sign_set(secret, kid, &s)) {
                Err(AdoptError::Verify(VerifyError::KeyRoleRejected { .. })) => {}
                other => panic!("{kid}: expected KeyRoleRejected, got {other:?}"),
            }
        }
        // A forged footer naming the issuer kid fails on the signature instead.
        assert!(matches!(
            adopt(&r.replica, &sign_set(&r.selfsig.secret, "iss-1", &s)),
            Err(AdoptError::Verify(VerifyError::SignatureMismatch))
        ));
        assert_eq!(r.replica.epoch(), None);
    }

    #[test]
    fn a_set_for_another_issuer_is_refused() {
        let r = jwks_rig();
        let foreign = RevocationSet::new("https://evil.test", 1, vec![]);
        assert!(matches!(
            adopt(&r.replica, &sign_set(&r.issuer.secret, "iss-1", &foreign)),
            Err(AdoptError::Verify(VerifyError::BadIssuer { .. }))
        ));
    }

    #[test]
    fn pinned_key_trust_verifies_and_refuses_other_keys() {
        let issuer = kp();
        let pinned = PasetoV4PublicVerifier::from_public_key(&pub_bytes(&issuer)).unwrap();
        let replica = ReplicatedRevocations::new(IssuerTrust::pinned(ISS, pinned));
        let s = set(3, vec![Revoked::device("phone", 1)]);
        assert!(matches!(
            adopt(&replica, &sign_set(&kp().secret, "any", &s)),
            Err(AdoptError::Verify(VerifyError::SignatureMismatch))
        ));
        assert!(matches!(
            adopt(&replica, &sign_with(&issuer.secret, "any", &s, None)),
            Err(AdoptError::Verify(VerifyError::SignatureMismatch))
        ));
        adopt(&replica, &sign_set(&issuer.secret, "any", &s)).unwrap();
        assert!(device(&replica, "phone"));
        let foreign = RevocationSet::new("https://evil.test", 4, vec![]);
        assert!(matches!(
            adopt(&replica, &sign_set(&issuer.secret, "any", &foreign)),
            Err(AdoptError::Verify(VerifyError::BadIssuer { .. }))
        ));
    }

    #[test]
    fn export_import_round_trips_through_a_fresh_replica() {
        let r = jwks_rig();
        let s = set(
            42,
            vec![Revoked::jti("j1", None), Revoked::device("phone", 1), Revoked::membership("band", "b1", PrincipalId::user("carol"), 1)],
        );
        let token = sign_set(&r.issuer.secret, "iss-1", &s);
        adopt(&r.replica, &token).unwrap();
        let bytes = r.replica.export().expect("held set exports");
        assert_eq!(bytes, token);

        // A restart: a new replica with the same trust, fed the persisted bytes.
        let pinned = PasetoV4PublicVerifier::from_public_key(&pub_bytes(&r.issuer)).unwrap();
        let restarted = ReplicatedRevocations::new(IssuerTrust::pinned(ISS, pinned));
        assert_eq!(
            adopt(&restarted, &bytes).unwrap(),
            Adopted::Advanced { from: None, to: 42 }
        );
        assert!(jti(&restarted, "j1"));
        assert!(device(&restarted, "phone"));
        assert!(member(&restarted, "band", "b1", "carol"));
        // Tampered bytes do not import.
        let mut tampered = bytes.clone();
        tampered.pop();
        let fresh = ReplicatedRevocations::new(IssuerTrust::key_set(
            ISS,
            KeySetVerifier::from_issuer_key("iss-1", &pub_bytes(&r.issuer), ISS),
        ));
        assert!(adopt(&fresh, &tampered).is_err());
        assert_eq!(fresh.epoch(), None);
    }

    #[test]
    fn concurrent_adopts_and_reads_settle_on_the_highest_epoch() {
        let r = Arc::new(jwks_rig());
        // Cumulative, as an issuer's sets are: epoch e names j1..=je.
        let tokens: Vec<String> = (1..=32u64)
            .map(|e| {
                let revoked = (1..=e).map(|i| Revoked::jti(format!("j{i}"), None)).collect();
                sign_set(&r.issuer.secret, "iss-1", &set(e, revoked))
            })
            .collect();
        let handles: Vec<_> = tokens
            .into_iter()
            .rev()
            .map(|t| {
                let r = r.clone();
                std::thread::spawn(move || {
                    let _ = adopt(&r.replica, &t);
                    // Readers interleave with writers; the epoch never goes
                    // backwards, so what epoch e named stays named.
                    let e = r.replica.epoch().expect("something is held after an adopt");
                    assert!(jti(&r.replica, &format!("j{e}")));
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(r.replica.epoch(), Some(32));
        assert!(jti(&r.replica, "j32"));
        assert!(!jti(&r.replica, "j33"));
    }

    #[test]
    fn trait_is_dyn_compatible_and_shareable() {
        fn _reader(_: &dyn RevocationReader) {}
        fn _shared(r: Arc<ReplicatedRevocations>) -> impl RevocationReader {
            r
        }
    }
}
