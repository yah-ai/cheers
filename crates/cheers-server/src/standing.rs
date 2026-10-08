//! The issuer half of the **standing node binding** (R732-F5; noisetable W235
//! §0.1, §5).
//!
//! - [`BindingSequenceStore`] — the per-device sequence a binding is stamped
//!   with. Advanced by [`next_binding_seq`]: `max(prev + 1, now)`, the same
//!   clock floor as the revocation epoch, so an issuer restored from an older
//!   backup still mints above the sequences edges already hold.
//! - [`StandingBinder`] — signs [`StandingBinding`]s under the issuer key.
//!   [`SessionAuthority`](crate::session::SessionAuthority) holds one and mints
//!   a binding with every peer-key-bound `DeviceBinding::LanPair` session.
//!
//! The edge half is `cheers_verify::StandingVerifier`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;

use cheers_core::{DeviceId, Error, Lease, PeerKey, StandingBinding, StoreError, UserId};

use crate::codec::PasetoV4SecretMinter;
use crate::session::generate_jti;

/// The sequence a mint advances to: `max(prev + 1, now)`, or `max(1, now)` for
/// a device's first binding. Strictly monotonic per device whatever the clock
/// does; the floor keeps a restored-from-backup issuer above what edges hold.
pub fn next_binding_seq(prev: Option<u64>, now: i64) -> u64 {
    prev.unwrap_or(0).saturating_add(1).max(u64::try_from(now).unwrap_or(0))
}

/// Origin-side per-device binding sequence. Keyed by device alone: a device id
/// re-bound to another user still supersedes its previous binding, which is
/// what an edge must see when a node changes hands.
#[async_trait]
pub trait BindingSequenceStore: Send + Sync {
    /// Advance `device`'s sequence by [`next_binding_seq`] and return it, as
    /// one atomic step: two concurrent mints for one device never share a
    /// sequence.
    async fn next_binding_seq(&self, device: &DeviceId, now: i64) -> Result<u64, StoreError>;
}

#[async_trait]
impl<T: BindingSequenceStore + ?Sized> BindingSequenceStore for Arc<T> {
    async fn next_binding_seq(&self, device: &DeviceId, now: i64) -> Result<u64, StoreError> {
        (**self).next_binding_seq(device, now).await
    }
}

/// In-process sequences — tests and single-process deployments. Clones share
/// one map.
#[derive(Debug, Clone, Default)]
pub struct MemoryBindingSequenceStore(Arc<Mutex<HashMap<DeviceId, u64>>>);

impl MemoryBindingSequenceStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// The sequence `device` is at, without advancing it.
    pub fn current(&self, device: &DeviceId) -> Option<u64> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).get(device).copied()
    }
}

#[async_trait]
impl BindingSequenceStore for MemoryBindingSequenceStore {
    async fn next_binding_seq(&self, device: &DeviceId, now: i64) -> Result<u64, StoreError> {
        let mut seqs = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let next = next_binding_seq(seqs.get(device).copied(), now);
        seqs.insert(device.clone(), next);
        Ok(next)
    }
}

/// A [`StandingBinding`] and its signed token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedStandingBinding {
    pub binding: StandingBinding,
    /// PASETO v4.public under the issuer key, with
    /// [`StandingBinding::IMPLICIT_ASSERTION`](cheers_core::SignedArtifact).
    pub token: String,
}

/// Mints standing bindings under the issuer key.
///
/// `kid` must be published in the JWKS with the **issuer** role; edges refuse
/// any other. A kid that has signed bindings stays published until every one
/// of them is superseded or revoked — removing it invalidates them (see
/// `cheers_verify::standing`, "Key rotation rule").
pub struct StandingBinder {
    sequences: Arc<dyn BindingSequenceStore>,
    minter: PasetoV4SecretMinter,
    issuer: String,
    kid: String,
    refresh_after_seconds: i64,
}

impl std::fmt::Debug for StandingBinder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StandingBinder")
            .field("issuer", &self.issuer)
            .field("kid", &self.kid)
            .field("refresh_after_seconds", &self.refresh_after_seconds)
            .finish_non_exhaustive()
    }
}

impl StandingBinder {
    /// 7 days. Advisory: how long until a node that can reach the issuer
    /// fetches a successor. It bounds how long an online fleet keeps bindings
    /// signed by a kid that has stopped signing, never how long one is valid.
    pub const DEFAULT_REFRESH_AFTER_SECONDS: i64 = 7 * 24 * 60 * 60;

    pub fn new(
        sequences: impl BindingSequenceStore + 'static,
        minter: PasetoV4SecretMinter,
        issuer: impl Into<String>,
        kid: impl Into<String>,
    ) -> Self {
        Self {
            sequences: Arc::new(sequences),
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

    /// Consume `device`'s next sequence number as the bound of a
    /// [`Revoked::Device`](cheers_core::Revoked::Device) entry (R732-T7).
    /// Every binding minted before sits below it and every binding minted
    /// after (re-enrollment) above it — one atomic advance, no read-then-write
    /// race against a concurrent mint.
    pub async fn revocation_seq(&self, device: &DeviceId, now: i64) -> Result<u64, Error> {
        Ok(self.sequences.next_binding_seq(device, now).await?)
    }

    /// Bind `sub` to the node keyed `peer_key` as `device`: advance the
    /// device's sequence, then sign. A failed sign leaves only a skipped
    /// sequence number behind.
    pub async fn mint(&self, sub: UserId, device: DeviceId, peer_key: PeerKey, now: i64) -> Result<SignedStandingBinding, Error> {
        let seq = self.sequences.next_binding_seq(&device, now).await?;
        let binding = StandingBinding {
            issuer: self.issuer.clone(),
            sub,
            device,
            peer_key,
            seq,
            iat: now,
            jti: generate_jti(),
            lease: Lease::new(now, now.saturating_add(self.refresh_after_seconds), None)?,
        };
        let token = self.minter.mint_artifact(&binding, &self.kid)?;
        Ok(SignedStandingBinding { binding, token })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cheers_verify::{IssuerTrust, ReplicatedRevocations, StandingVerifier};

    #[test]
    fn next_seq_is_clock_floored_and_strictly_monotonic() {
        assert_eq!(next_binding_seq(None, 1_000), 1_000);
        assert_eq!(next_binding_seq(None, -5), 1);
        assert_eq!(next_binding_seq(Some(1_000), 1_000), 1_001);
        // The clock went backwards: still above what was issued.
        assert_eq!(next_binding_seq(Some(5_000), 1_000), 5_001);
        // Restored from a backup that remembers only 10: the floor lifts the
        // next sequence above anything minted before the clock read now.
        assert_eq!(next_binding_seq(Some(10), 9_000), 9_000);
        assert_eq!(next_binding_seq(Some(u64::MAX), 0), u64::MAX);
    }

    #[test]
    fn memory_store_advances_per_device() {
        pollster::block_on(async {
            let store = MemoryBindingSequenceStore::new();
            let (a, b) = (DeviceId::new("node:a"), DeviceId::new("node:b"));
            assert_eq!(store.next_binding_seq(&a, 100).await.unwrap(), 100);
            assert_eq!(store.next_binding_seq(&a, 100).await.unwrap(), 101);
            assert_eq!(store.next_binding_seq(&a, 50).await.unwrap(), 102);
            assert_eq!(store.next_binding_seq(&b, 50).await.unwrap(), 50);
            assert_eq!(store.current(&a), Some(102));
        });
    }

    #[test]
    fn minted_binding_verifies_at_the_edge_and_carries_the_sequence() {
        pollster::block_on(async {
            let (minter, verifier) = PasetoV4SecretMinter::generate().unwrap();
            let store = MemoryBindingSequenceStore::new();
            let binder = StandingBinder::new(store.clone(), minter, "https://c.test", "k1").with_refresh_after(60);
            let key = PeerKey::ed25519([3; 32]);
            let first = binder
                .mint(UserId::new("alice"), DeviceId::new("node:a"), key.clone(), 1_000)
                .await
                .unwrap();
            assert_eq!(first.binding.seq, 1_000);
            assert_eq!(first.binding.lease.refresh_after(), 1_060);
            assert!(!first.binding.jti.is_empty());

            let trust = IssuerTrust::pinned("https://c.test", verifier);
            let edge = StandingVerifier::new(trust.clone(), ReplicatedRevocations::new(trust));
            let ok = edge.verify_standing_at(&first.token, &key, 1_000).await.unwrap();
            assert_eq!(ok.binding, first.binding);

            let second = binder
                .mint(UserId::new("alice"), DeviceId::new("node:a"), key.clone(), 1_000)
                .await
                .unwrap();
            assert_eq!(second.binding.seq, 1_001);
            assert_ne!(second.binding.jti, first.binding.jti);
        });
    }
}
