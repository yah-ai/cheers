//! The **write** side of the revocation split, and the issuer's signed
//! revocation set (R732-F6).
//!
//! Edge-verifiable auth (R019) keeps revocation's two sides physically apart.
//! This crate holds the origin half:
//!
//! - [`RevocationWriter`] — the **cold path**, run at the origin on logout /
//!   device-revoke / membership removal. Records a [`Revoked`] entry and
//!   advances the store's epoch.
//! - [`RevocationPublisher`] — signs the store's current contents as a
//!   [`RevocationSet`] under the issuer key, membership entries tagged under
//!   their resource's revocation key ([`OwnershipStore::revocation_key`];
//!   R732-T10), for the publish route and for
//!   offline peers to replicate (`cheers_verify::ReplicatedRevocations`).
//! - The **hot-path** reader (`cheers_verify::RevocationReader`) lives in
//!   `cheers-verify` — the verify-only edge holds it without the power to revoke
//!   anyone else's sessions.
//!
//! The set is **eventually consistent** by design: a `revoke` here propagates to
//! edge readers asynchronously (KV replication / gossip). For access tokens the
//! access TTL bounds the lag (see [`SessionPolicy`](crate::session::SessionPolicy));
//! for standing credentials (membership snapshots, node bindings) revocation is
//! the *only* bound. Full contract on `cheers_verify::RevocationReader`.
//!
//! # The epoch
//!
//! A store is **one issuer's** revocation log: it holds a single persistent
//! epoch, and every write that changes the contents advances it by
//! [`next_epoch`]: `max(epoch + 1, now)`. Strictly monotonic either way; the
//! clock floor is there so a store restored from an older backup still issues
//! epochs above the ones replicas already hold — a plain counter would restart
//! below them, and every replica would refuse every set until it caught up.
//! Nothing orders sets by wall-clock time: replicas compare epochs only.
//!
//! # Revoking a session vs. a whole login
//!
//! # Identity and bound (R732-T7)
//!
//! A store holds **one row per identity** (`(kind, subject, resource_kind,
//! resource_id)`, see [`revoked_columns`]) carrying **one bound** — the jti's
//! `exp`, the device's `at_seq`, the membership's `at_epoch` (see
//! [`Revoked`]). Re-revoking an identity keeps the larger bound, and the epoch
//! advances only when a row was inserted or its bound rose. A jti with an
//! `exp` lapses once `exp <= now`: store gc drops it, and
//! [`RevocationPublisher::current`] omits it even before gc runs.
//!
//! # Revoking a session vs. a whole login
//!
//! [`RevocationWriter::revoke`] with [`Revoked::Jti`] kills **one** access token
//! immediately (edge-visible within the propagation window). The coarser flows
//! compose it with the refresh cold path:
//!
//! - **Logout / single device-revoke:** call
//!   [`RefreshStore::revoke_chain`](crate::store::RefreshStore::revoke_chain) so
//!   the chain can mint no *further* access tokens, and revoke the session's
//!   current `jti`. [`SessionAuthority::revoke_device`](crate::session::SessionAuthority::revoke_device)
//!   also records [`Revoked::Device`], which is what ends a standing node
//!   binding for that device.
//! - **Account-wide revoke:** revoke every chain via the
//!   [`UserStore`](crate::store::UserStore) device list; same TTL bound applies.
//!
//! [`SessionAuthority`](crate::session::SessionAuthority) is where these calls
//! are composed — it holds both the [`RevocationWriter`] and the
//! [`RefreshStore`](crate::store::RefreshStore).

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

use cheers_core::{DeviceId, Error, PrincipalId, RevocationKey, RevocationSet, Revoked, StoreError};
use cheers_verify::{revocation_entry, RevocationReader};

use crate::codec::PasetoV4SecretMinter;
use crate::ownership::OwnershipStore;

/// A store's contents at one epoch, read atomically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationSnapshot {
    pub epoch: u64,
    pub revoked: Vec<Revoked>,
}

/// The epoch a write advances to: `max(current + 1, now)`. See the module docs.
pub fn next_epoch(current: u64, now: i64) -> u64 {
    current.saturating_add(1).max(u64::try_from(now).unwrap_or(0))
}

/// One entry as a relational row, shared by the SQL stores (cheers-sqlx,
/// cheers-turso). The key is `(kind, subject, resource_kind, resource_id)` —
/// the entry's identity: `subject` is the jti, the device id, or the member's
/// principal in wire form (`user:alice`, `key:..`, migration 0015); the resource columns are `""` unless the entry is a membership.
/// The bound lives in `bound` (device `at_seq`, membership `at_epoch`; `NULL`
/// for a jti) or `expires_at` (a jti's `exp`; `NULL` = never lapses).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedColumns<'a> {
    pub kind: &'static str,
    pub subject: Cow<'a, str>,
    pub resource_kind: &'a str,
    pub resource_id: &'a str,
    pub bound: Option<i64>,
    pub expires_at: Option<i64>,
}

/// The row of `entry`. A `u64` bound past `i64::MAX` is stored as `i64::MAX`,
/// which still masks every sequence a store can hand out.
pub fn revoked_columns(entry: &Revoked) -> RevokedColumns<'_> {
    let clamp = |b: u64| i64::try_from(b).unwrap_or(i64::MAX);
    match entry {
        Revoked::Jti { jti, exp } => RevokedColumns {
            kind: "jti",
            subject: Cow::Borrowed(jti),
            resource_kind: "",
            resource_id: "",
            bound: None,
            expires_at: *exp,
        },
        Revoked::Device { device, at_seq } => RevokedColumns {
            kind: "device",
            subject: Cow::Borrowed(device.as_str()),
            resource_kind: "",
            resource_id: "",
            bound: Some(clamp(*at_seq)),
            expires_at: None,
        },
        Revoked::Membership { kind, id, principal, at_epoch } => RevokedColumns {
            kind: "membership",
            subject: Cow::Owned(principal.to_string()),
            resource_kind: kind,
            resource_id: id,
            bound: Some(clamp(*at_epoch)),
            expires_at: None,
        },
    }
}

/// The inverse of [`revoked_columns`].
pub fn revoked_from_columns(
    kind: &str,
    subject: String,
    resource_kind: String,
    resource_id: String,
    bound: Option<i64>,
    expires_at: Option<i64>,
) -> Result<Revoked, StoreError> {
    let bound = || -> Result<u64, StoreError> {
        let b = bound.ok_or_else(|| StoreError::Backend(format!("{kind} revocation {subject:?} has no bound")))?;
        u64::try_from(b).map_err(|_| StoreError::Backend(format!("negative revocation bound {b}")))
    };
    match kind {
        "jti" => Ok(Revoked::jti(subject, expires_at)),
        "device" => Ok(Revoked::device(DeviceId::new(subject.clone()), bound()?)),
        "membership" => {
            let principal = subject
                .parse::<PrincipalId>()
                .map_err(|e| StoreError::Backend(format!("membership revocation subject {subject:?}: {e}")))?;
            Ok(Revoked::membership(resource_kind, resource_id, principal, bound()?))
        }
        other => Err(StoreError::Backend(format!("unknown revocation kind {other:?}"))),
    }
}

/// An epoch read back from a signed 64-bit SQL column.
pub fn epoch_from_sql(epoch: i64) -> Result<u64, StoreError> {
    u64::try_from(epoch).map_err(|_| StoreError::Backend(format!("negative revocation epoch {epoch}")))
}

/// Origin-side revocation log. Held by
/// [`SessionAuthority`](crate::session::SessionAuthority) on the cold path and
/// by [`RevocationPublisher`].
#[async_trait]
pub trait RevocationWriter: Send + Sync {
    /// Add `entry` to the set, advancing the epoch ([`next_epoch`]) in the same
    /// atomic write. An identity already present keeps the larger bound
    /// ([`Revoked::cmp_bound`]); the epoch advances only when a row was
    /// inserted or its bound rose. **Idempotent** — re-revoking with an equal
    /// or lower bound is a no-op, not an error, and leaves the epoch alone. Propagation to edge
    /// `cheers_verify::RevocationReader`s is asynchronous (see the module
    /// contract).
    async fn revoke(&self, entry: &Revoked) -> Result<(), StoreError>;

    /// The current epoch and entries, read as one consistent view: the
    /// contents are exactly those the epoch was advanced to. Includes lapsed
    /// jtis that gc has not yet removed; [`RevocationPublisher::current`]
    /// filters those.
    async fn snapshot(&self) -> Result<RevocationSnapshot, StoreError>;
}

/// A [`RevocationSet`] signed under the issuer key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRevocationSet {
    pub epoch: u64,
    /// PASETO v4.public, [`RevocationSet::IMPLICIT_ASSERTION`](cheers_core::SignedArtifact).
    pub token: String,
}

/// Signs a store's current contents as its issuer's [`RevocationSet`].
///
/// `kid` must be published in the JWKS with the **issuer** role — replicas
/// refuse a set signed by any other role. `keys` is the ownership store whose
/// per-resource revocation keys tag membership entries — the same store
/// [`SnapshotIssuer`](crate::SnapshotIssuer) hands the keys out of.
pub struct RevocationPublisher<W> {
    store: W,
    keys: Arc<dyn OwnershipStore>,
    minter: PasetoV4SecretMinter,
    issuer: String,
    kid: String,
}

impl<W> std::fmt::Debug for RevocationPublisher<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevocationPublisher")
            .field("issuer", &self.issuer)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl<W: RevocationWriter> RevocationPublisher<W> {
    pub fn new(
        store: W,
        keys: Arc<dyn OwnershipStore>,
        minter: PasetoV4SecretMinter,
        issuer: impl Into<String>,
        kid: impl Into<String>,
    ) -> Self {
        Self {
            store,
            keys,
            minter,
            issuer: issuer.into(),
            kid: kid.into(),
        }
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn store(&self) -> &W {
        &self.store
    }

    /// The current set as of `now`, signed. Jtis already lapsed at `now`
    /// (`exp <= now`) are omitted: the credential is dead on its own signature,
    /// and carrying it would let the set grow without bound between gc runs.
    /// Re-signed on every call; a set's bytes are a function of its contents
    /// (keys never change), so two calls at one epoch and one set of live
    /// entries return equal tokens. Memberships are published as tags, never
    /// as `(kind, id, user)`.
    pub async fn current(&self, now: i64) -> Result<SignedRevocationSet, Error> {
        let mut snapshot = self.store.snapshot().await?;
        snapshot.revoked.retain(|entry| !entry.is_lapsed_at(now));
        let mut keys: BTreeMap<(String, String), RevocationKey> = BTreeMap::new();
        for entry in &snapshot.revoked {
            if let Revoked::Membership { kind, id, .. } = entry {
                if !keys.contains_key(&(kind.clone(), id.clone())) {
                    let key = self.keys.revocation_key(kind, id).await?;
                    keys.insert((kind.clone(), id.clone()), key);
                }
            }
        }
        let entries = snapshot
            .revoked
            .iter()
            .map(|entry| revocation_entry(entry, |kind, id| keys[&(kind.to_owned(), id.to_owned())].clone()))
            .collect();
        let set = RevocationSet::new(self.issuer.clone(), snapshot.epoch, entries);
        let token = self.minter.mint_artifact(&set, &self.kid)?;
        Ok(SignedRevocationSet {
            epoch: set.epoch,
            token,
        })
    }
}

/// In-process revocation log — tests, and single-process deployments that do
/// not need the set to survive a restart. Clones share one log, so an
/// authority-side writer and an edge-side reader see the same set.
#[derive(Debug, Clone, Default)]
pub struct MemoryRevocationStore(Arc<Mutex<MemoryLog>>);

/// An entry's identity as an owned map key ([`Revoked::identity`]).
type IdentityKey = (u8, String, String, String);

fn identity_key(entry: &Revoked) -> IdentityKey {
    let (v, a, b, c) = entry.identity();
    (v, a.to_owned(), b.to_owned(), c.into_owned())
}

#[derive(Debug, Default)]
struct MemoryLog {
    epoch: u64,
    /// identity -> the entry holding its greatest bound.
    entries: HashMap<IdentityKey, Revoked>,
}

impl MemoryRevocationStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// The held entry with `probe`'s identity, if any.
    fn get(&self, probe: &Revoked) -> Option<Revoked> {
        let log = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        log.entries.get(&identity_key(probe)).cloned()
    }

    /// Drop jtis lapsed at or before `now`, advancing the epoch when anything
    /// went. Returns the number removed. Same contract as the SQL stores' gc.
    pub fn gc(&self, now: i64) -> u64 {
        let mut log = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let before = log.entries.len();
        log.entries.retain(|_, entry| !entry.is_lapsed_at(now));
        let removed = (before - log.entries.len()) as u64;
        if removed > 0 {
            log.epoch = next_epoch(log.epoch, now_unix());
        }
        removed
    }
}

#[async_trait]
impl RevocationWriter for MemoryRevocationStore {
    async fn revoke(&self, entry: &Revoked) -> Result<(), StoreError> {
        let mut log = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let key = identity_key(entry);
        let raises = log
            .entries
            .get(&key)
            .is_none_or(|held| entry.cmp_bound(held) == std::cmp::Ordering::Greater);
        if raises {
            log.entries.insert(key, entry.clone());
            log.epoch = next_epoch(log.epoch, now_unix());
        }
        Ok(())
    }

    async fn snapshot(&self) -> Result<RevocationSnapshot, StoreError> {
        let log = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(RevocationSnapshot {
            epoch: log.epoch,
            revoked: log.entries.values().cloned().collect(),
        })
    }
}

#[async_trait]
impl RevocationReader for MemoryRevocationStore {
    async fn is_revoked(&self, jti: &str) -> Result<bool, StoreError> {
        Ok(self.get(&Revoked::jti(jti, None)).is_some())
    }

    async fn is_device_revoked(&self, device: &DeviceId, seq: u64) -> Result<bool, StoreError> {
        Ok(matches!(
            self.get(&Revoked::device(device.clone(), 0)),
            Some(Revoked::Device { at_seq, .. }) if seq < at_seq
        ))
    }

    /// Plaintext rows: `key` is not needed.
    async fn is_membership_revoked(
        &self,
        _key: &RevocationKey,
        kind: &str,
        id: &str,
        principal: &PrincipalId,
        snapshot_epoch: u64,
    ) -> Result<bool, StoreError> {
        Ok(matches!(
            self.get(&Revoked::membership(kind, id, principal.clone(), 0)),
            Some(Revoked::Membership { at_epoch, .. }) if snapshot_epoch < at_epoch
        ))
    }
}

pub(crate) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cheers_core::{KeyRole, RevocationEntry, SignedArtifact};
    use cheers_verify::{
        AdoptError, Adopted, IssuerTrust, JwkKey, JwksDoc, KeySet, KeySetVerifier, ReplicatedRevocations,
    };

    const ISS: &str = "https://cheers.test";

    #[test]
    fn next_epoch_is_strictly_monotonic_with_a_clock_floor() {
        assert_eq!(next_epoch(0, 1_000), 1_000);
        // Many writes in one second outrun the clock and keep counting.
        assert_eq!(next_epoch(1_000, 1_000), 1_001);
        assert_eq!(next_epoch(5_000, 1_000), 5_001);
        // A clock behind the epoch (skew, restore) never moves it backwards.
        assert_eq!(next_epoch(5_000, 10), 5_001);
        assert_eq!(next_epoch(5_000, -1), 5_001);
        assert_eq!(next_epoch(u64::MAX, 0), u64::MAX);
    }

    #[test]
    fn revoke_keeps_the_greatest_bound_and_only_raises_advance_the_epoch() {
        let store = MemoryRevocationStore::default();
        pollster::block_on(async {
            assert_eq!(store.snapshot().await.unwrap().epoch, 0);
            store.revoke(&Revoked::jti("tok-1", Some(100))).await.unwrap();
            let e1 = store.snapshot().await.unwrap().epoch;
            assert!(e1 > 0);
            // Equal or lower bound: a no-op that leaves the epoch alone.
            store.revoke(&Revoked::jti("tok-1", Some(100))).await.unwrap();
            store.revoke(&Revoked::jti("tok-1", Some(50))).await.unwrap();
            assert_eq!(store.snapshot().await.unwrap().epoch, e1);
            // A raise (and None, which never lapses, is the top) advances it.
            store.revoke(&Revoked::jti("tok-1", None)).await.unwrap();
            let e2 = store.snapshot().await.unwrap().epoch;
            assert!(e2 > e1);
            store.revoke(&Revoked::jti("tok-1", Some(i64::MAX))).await.unwrap();
            assert_eq!(store.snapshot().await.unwrap().epoch, e2);

            store.revoke(&Revoked::device("phone", 10)).await.unwrap();
            let e3 = store.snapshot().await.unwrap().epoch;
            store.revoke(&Revoked::device("phone", 9)).await.unwrap();
            assert_eq!(store.snapshot().await.unwrap().epoch, e3);
            store.revoke(&Revoked::device("phone", 20)).await.unwrap();
            assert!(store.snapshot().await.unwrap().epoch > e3);
            let phone = DeviceId::new("phone");
            assert!(store.is_device_revoked(&phone, 19).await.unwrap());
            assert!(!store.is_device_revoked(&phone, 20).await.unwrap());

            store.revoke(&Revoked::membership("namespace", "ns-1", PrincipalId::user("alice"), 7)).await.unwrap();
            let alice = PrincipalId::user("alice");
            let k = cheers_verify::test_revocation_key("namespace", "ns-1");
            assert!(store.is_membership_revoked(&k, "namespace", "ns-1", &alice, 6).await.unwrap());
            assert!(!store.is_membership_revoked(&k, "namespace", "ns-1", &alice, 7).await.unwrap());
            assert!(!store.is_membership_revoked(&k, "namespace", "ns-1", &PrincipalId::user("bob"), 0).await.unwrap());

            let snap = store.snapshot().await.unwrap();
            assert_eq!(snap.revoked.len(), 3);
            assert!(store.is_revoked("tok-1").await.unwrap());
        });
    }

    #[test]
    fn gc_drops_lapsed_jtis_only_and_advances_the_epoch_iff_it_removed_something() {
        let store = MemoryRevocationStore::default();
        pollster::block_on(async {
            store.revoke(&Revoked::jti("short", Some(50))).await.unwrap();
            store.revoke(&Revoked::jti("forever", None)).await.unwrap();
            store.revoke(&Revoked::device("phone", 1)).await.unwrap();
            let before = store.snapshot().await.unwrap().epoch;
            assert_eq!(store.gc(49), 0);
            assert_eq!(store.snapshot().await.unwrap().epoch, before);
            assert_eq!(store.gc(50), 1);
            let after = store.snapshot().await.unwrap();
            assert!(after.epoch > before);
            assert_eq!(after.revoked.len(), 2);
            assert!(!store.is_revoked("short").await.unwrap());
            assert!(store.is_revoked("forever").await.unwrap());
        });
    }

    #[test]
    fn the_published_set_omits_jtis_lapsed_at_mint_time() {
        let (publisher, keys) = publisher();
        pollster::block_on(async {
            publisher.store().revoke(&Revoked::jti("short", Some(50))).await.unwrap();
            publisher.store().revoke(&Revoked::jti("forever", None)).await.unwrap();
            let names = |token: String| {
                let keys = &keys;
                async move {
                    let set: RevocationSet = keys.verify_artifact(&token).await.unwrap();
                    set.revoked
                }
            };
            assert_eq!(
                names(publisher.current(49).await.unwrap().token).await,
                vec![RevocationEntry::Jti { jti: "forever".into(), exp: None }, RevocationEntry::Jti { jti: "short".into(), exp: Some(50) }]
            );
            assert_eq!(
                names(publisher.current(50).await.unwrap().token).await,
                vec![RevocationEntry::Jti { jti: "forever".into(), exp: None }]
            );
        });
    }

    fn publisher() -> (RevocationPublisher<MemoryRevocationStore>, KeySetVerifier) {
        let (minter, verifier) = PasetoV4SecretMinter::generate().unwrap();
        let public: [u8; 32] = verifier.public_key().as_bytes().try_into().unwrap();
        let keys = KeySetVerifier::from_issuer_key("iss-1", &public, ISS);
        let ownership: Arc<dyn OwnershipStore> = Arc::new(crate::MemoryOwnershipStore::new());
        (RevocationPublisher::new(MemoryRevocationStore::default(), ownership, minter, ISS, "iss-1"), keys)
    }

    #[test]
    fn a_published_membership_is_a_tag_a_key_holder_can_test() {
        let (minter, verifier) = PasetoV4SecretMinter::generate().unwrap();
        let public: [u8; 32] = verifier.public_key().as_bytes().try_into().unwrap();
        let keys = KeySetVerifier::from_issuer_key("iss-1", &public, ISS);
        let ownership = crate::MemoryOwnershipStore::new();
        let publisher = RevocationPublisher::new(
            MemoryRevocationStore::default(),
            Arc::new(ownership.clone()),
            minter,
            ISS,
            "iss-1",
        );
        let replica = ReplicatedRevocations::new(IssuerTrust::key_set(ISS, keys.clone()));
        pollster::block_on(async {
            publisher.store().revoke(&Revoked::membership("room", "r-secret", PrincipalId::user("alice-secret"), 9)).await.unwrap();
            let signed = publisher.current(0).await.unwrap();
            let set: RevocationSet = keys.verify_artifact(&signed.token).await.unwrap();
            let wire = serde_json::to_string(&set).unwrap();
            assert!(!wire.contains("r-secret") && !wire.contains("alice-secret"), "{wire}");
            replica.adopt(&signed.token).await.unwrap();
            let key = ownership.revocation_key("room", "r-secret").await.unwrap();
            // The key is created once and never changes.
            assert_eq!(ownership.revocation_key("room", "r-secret").await.unwrap(), key);
            let alice = PrincipalId::user("alice-secret");
            assert!(replica.is_membership_revoked(&key, "room", "r-secret", &alice, 8).await.unwrap());
            assert!(!replica.is_membership_revoked(&key, "room", "r-secret", &alice, 9).await.unwrap());
            let other = ownership.revocation_key("room", "r-other").await.unwrap();
            assert_ne!(other, key);
            assert!(!replica.is_membership_revoked(&other, "room", "r-secret", &alice, 8).await.unwrap());
        });
    }

    #[test]
    fn published_sets_verify_at_a_replica_in_epoch_order() {
        let (publisher, keys) = publisher();
        let replica = ReplicatedRevocations::new(IssuerTrust::key_set(ISS, keys));
        pollster::block_on(async {
            let empty = publisher.current(0).await.unwrap();
            assert_eq!(empty.epoch, 0);
            assert_eq!(replica.adopt(&empty.token).await.unwrap(), Adopted::Advanced { from: None, to: 0 });

            publisher.store().revoke(&Revoked::device("phone", 1)).await.unwrap();
            let first = publisher.current(0).await.unwrap();
            assert!(first.epoch > empty.epoch);
            // Re-signing at one epoch yields the same bytes.
            assert_eq!(publisher.current(0).await.unwrap(), first);
            replica.adopt(&first.token).await.unwrap();
            assert!(replica.is_device_revoked(&DeviceId::new("phone"), 0).await.unwrap());

            publisher.store().revoke(&Revoked::jti("j1", None)).await.unwrap();
            let second = publisher.current(0).await.unwrap();
            replica.adopt(&second.token).await.unwrap();
            assert!(replica.is_revoked("j1").await.unwrap());
            // Gossip replaying the older set is refused.
            assert!(matches!(replica.adopt(&first.token).await, Err(AdoptError::Stale { .. })));
        });
    }

    #[test]
    fn mint_artifact_is_domain_separated_from_access_tokens() {
        let (minter, verifier) = PasetoV4SecretMinter::generate().unwrap();
        let public: [u8; 32] = verifier.public_key().as_bytes().try_into().unwrap();
        let keys = KeySetVerifier::from_issuer_key("iss-1", &public, ISS);
        let set = RevocationSet::new(ISS, 1, vec![RevocationEntry::Jti { jti: "j1".into(), exp: None }]);
        let token = minter.mint_artifact(&set, "iss-1").unwrap();
        assert_eq!(pollster::block_on(keys.verify_artifact::<RevocationSet>(&token)).unwrap(), set);
        assert_eq!(verifier.verify_artifact::<RevocationSet>(&token).unwrap(), set);

        // The same key's access-token paths refuse the set…
        assert!(cheers_core::TokenVerifier::verify_at(&verifier, &token, 0).is_err());
        assert!(verifier.verify_mcp_at(&token, 0, "iss-1").is_err());
        assert!(pollster::block_on(keys.verify_mcp(&token, 0, ISS, None)).is_err());
        // …and its artifact path refuses an access token signed by that key.
        let mcp = cheers_core::McpClaims::new(ISS, "aud", cheers_core::PrincipalId::user("alice"), 1, 2, "j", vec![]);
        let access = minter.mint_mcp(&mcp, "iss-1").unwrap();
        assert!(verifier.verify_artifact::<RevocationSet>(&access).is_err());
        assert!(pollster::block_on(keys.verify_artifact::<RevocationSet>(&access)).is_err());
    }

    #[test]
    fn a_set_signed_by_a_non_issuer_role_key_is_refused() {
        let (minter, verifier) = PasetoV4SecretMinter::generate().unwrap();
        let public: [u8; 32] = verifier.public_key().as_bytes().try_into().unwrap();
        let doc = JwksDoc {
            keys: vec![JwkKey::ed25519("svc-1", &public, ISS, KeyRole::Assertion)],
        };
        let keys = KeySetVerifier::from_key_set(KeySet::from_doc(doc).unwrap());
        let token = minter.mint_artifact(&RevocationSet::new(ISS, 1, vec![]), "svc-1").unwrap();
        assert!(pollster::block_on(keys.verify_artifact::<RevocationSet>(&token)).is_err());
        assert!(!RevocationSet::IMPLICIT_ASSERTION.is_empty());
    }

    #[test]
    fn trait_is_dyn_compatible() {
        fn _writer(_: &dyn RevocationWriter) {}
    }
}
