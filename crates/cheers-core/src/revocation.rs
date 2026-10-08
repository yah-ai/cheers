//! The **revocation set** wire type (R732-F6; noisetable W235 §5.1, C6).
//!
//! Standing credentials — membership snapshots (C4) and node bindings (C5) —
//! carry no edge-enforced expiry: offline admission lasts until *revoked*
//! (W235 §0.1). A [`RevocationSet`] is therefore the only way one ends. cheers
//! signs the current set under its issuer key; offline peers replicate it by
//! gossip and keep the highest [`epoch`](RevocationSet::epoch) they have seen
//! (`cheers_verify::ReplicatedRevocations`).
//!
//! The accepted cost: a removed member keeps a fully offline LAN until a set
//! naming them reaches it.
//!
//! # Wire shape
//!
//! The PASETO payload is the JSON of [`RevocationSet`], signed with
//! [`RevocationSet::IMPLICIT_ASSERTION`](crate::SignedArtifact) and a
//! `{"kid": ...}` footer:
//!
//! ```json
//! {"issuer":"https://cheers.example","epoch":1791234567,"revoked":[
//!   {"jti":{"jti":"6f1c...","exp":1791235467}},
//!   {"device":{"device":"phone-1","at_seq":1791234000}},
//!   {"membership":{"tag":"q0Zp...","at_epoch":12}}]}
//! ```
//!
//! # Membership privacy (R732-T10)
//!
//! The set is public, so a membership entry never names `(kind, id, user)`.
//! The issuer stores plaintext [`Revoked`] rows; on publish each membership
//! becomes a [`RevocationEntry::Membership`] carrying a [`MembershipTag`]:
//! `HMAC-SHA256(key, ctx || len-prefixed kind, id, user)` under the
//! resource's [`RevocationKey`] (`cheers_verify::membership_tag`). The key is
//! random per `(kind, id)`, immutable once created, and reaches an edge only
//! inside a signed [`SetSnapshot`](crate::SetSnapshot) — for the snapshot's
//! own resource and every resource a member's `via` names. Anyone without the
//! snapshot cannot confirm a removal offline; anyone holding it (an insider)
//! can, which is accepted.
//!
//! # Identity and bound (R732-T7)
//!
//! Every entry is an **identity** (what it names: a jti, a device, a
//! `(kind, id, user)` membership) plus one **bound** that limits what it masks:
//!
//! - [`Revoked::Jti`] `exp` — the credential's own expiry. Once `exp <= now`
//!   the credential is dead on its signature, so the entry *lapses* and may be
//!   dropped (store gc, and the published set omits it). `None` never lapses —
//!   standing bindings and non-expiring user tokens.
//! - [`Revoked::Device`] `at_seq` — masks only standing bindings of the device
//!   with `seq < at_seq`. Re-enrolling the same machine mints a higher seq and
//!   is admitted again.
//! - [`Revoked::Membership`] `at_epoch` — the user's last direct tuple on
//!   `(kind, id)` was revoked at ownership version `at_epoch` (R732-F4). It
//!   masks, in any membership snapshot with `epoch < at_epoch`, the user's
//!   entries that derive from `(kind, id)` — and drops an entry only once
//!   every resource in its `via` is masked (`crate::snapshot`).
//!
//! An identity holds one bound: re-revoking keeps the larger (for a jti,
//! `None` counts as larger than any `exp`), and [`RevocationSet::new`] dedups
//! by identity the same way.

use std::borrow::Cow;
use std::cmp::Ordering;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::artifact::SignedArtifact;
use crate::claims::DeviceId;
use crate::principal::PrincipalId;

/// 32 raw bytes on the wire as a base64url-no-pad string.
fn ser_b64<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
}

fn de_b64<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
    let text = String::deserialize(d)?;
    let raw = URL_SAFE_NO_PAD.decode(text.as_bytes()).map_err(serde::de::Error::custom)?;
    raw.try_into()
        .map_err(|raw: Vec<u8>| serde::de::Error::custom(format!("expected 32 bytes, got {}", raw.len())))
}

/// A resource's secret membership-revocation key (module docs, "Membership
/// privacy"). Random, created once per `(kind, id)` and never changed: a
/// changed key would make every edge holding an older snapshot miss every new
/// entry — revocation failing open. Travels only inside signed snapshots.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RevocationKey(#[serde(serialize_with = "ser_b64", deserialize_with = "de_b64")] [u8; 32]);

impl RevocationKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for RevocationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RevocationKey(..)")
    }
}

/// The published name of a membership revocation: an HMAC of `(kind, id,
/// principal)` under the resource's [`RevocationKey`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MembershipTag(#[serde(serialize_with = "ser_b64", deserialize_with = "de_b64")] [u8; 32]);

impl MembershipTag {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// One entry of the issuer's revocation log, in plaintext: an identity plus
/// its bound (module docs). What stores hold. A [`RevocationSet`] publishes
/// it as a [`RevocationEntry`], with memberships tagged.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Revoked {
    /// One credential, by its `jti`. Lapses once `exp <= now`; `None` never
    /// lapses.
    Jti { jti: String, exp: Option<i64> },
    /// Standing bindings of this device with `seq < at_seq`.
    Device { device: DeviceId, at_seq: u64 },
    /// `principal`'s direct membership of resource `(kind, id)`, whatever
    /// relation it held, in snapshots with `epoch < at_epoch` — of `(kind, id)`
    /// itself and of every resource whose members derive from it by a subject
    /// set ([`SnapshotMember::via`](crate::SnapshotMember::via)). Any principal
    /// kind, a [`Key`](crate::PrincipalKind::Key) included.
    Membership {
        kind: String,
        id: String,
        principal: PrincipalId,
        at_epoch: u64,
    },
}

impl Revoked {
    pub fn jti(jti: impl Into<String>, exp: Option<i64>) -> Self {
        Self::Jti { jti: jti.into(), exp }
    }

    pub fn device(device: impl Into<DeviceId>, at_seq: u64) -> Self {
        Self::Device {
            device: device.into(),
            at_seq,
        }
    }

    pub fn membership(
        kind: impl Into<String>,
        id: impl Into<String>,
        principal: impl Into<PrincipalId>,
        at_epoch: u64,
    ) -> Self {
        Self::Membership {
            kind: kind.into(),
            id: id.into(),
            principal: principal.into(),
            at_epoch,
        }
    }

    /// What the entry names, without its bound: `(variant, a, b, c)`. Two
    /// entries with one identity are the same row in every store. A
    /// membership's `c` is the principal's wire form (`user:alice`, `key:..`).
    pub fn identity(&self) -> (u8, &str, &str, Cow<'_, str>) {
        match self {
            Self::Jti { jti, .. } => (0, jti, "", Cow::Borrowed("")),
            Self::Device { device, .. } => (1, device.as_str(), "", Cow::Borrowed("")),
            Self::Membership { kind, id, principal, .. } => (2, kind, id, Cow::Owned(principal.to_string())),
        }
    }

    /// Order of the bounds of two entries with one identity: the greater bound
    /// masks more. For a jti, `None` (never lapses) is greater than any `exp`.
    /// Entries with different identities compare `Equal`.
    pub fn cmp_bound(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Jti { exp: a, .. }, Self::Jti { exp: b, .. }) => match (a, b) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(a), Some(b)) => a.cmp(b),
            },
            (Self::Device { at_seq: a, .. }, Self::Device { at_seq: b, .. }) => a.cmp(b),
            (Self::Membership { at_epoch: a, .. }, Self::Membership { at_epoch: b, .. }) => a.cmp(b),
            _ => Ordering::Equal,
        }
    }

    /// `true` once a jti's `exp` is at or before `now`; never for the others.
    pub fn is_lapsed_at(&self, now: i64) -> bool {
        matches!(self, Self::Jti { exp: Some(exp), .. } if *exp <= now)
    }
}

/// One entry of a published [`RevocationSet`]: a [`Revoked`] with its
/// membership identity replaced by a [`MembershipTag`] (module docs).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationEntry {
    /// As [`Revoked::Jti`].
    Jti { jti: String, exp: Option<i64> },
    /// As [`Revoked::Device`].
    Device { device: DeviceId, at_seq: u64 },
    /// As [`Revoked::Membership`], named by its tag.
    Membership { tag: MembershipTag, at_epoch: u64 },
}

impl RevocationEntry {
    /// What the entry names, without its bound.
    pub fn identity(&self) -> (u8, &[u8]) {
        match self {
            Self::Jti { jti, .. } => (0, jti.as_bytes()),
            Self::Device { device, .. } => (1, device.as_str().as_bytes()),
            Self::Membership { tag, .. } => (2, tag.as_bytes()),
        }
    }

    /// As [`Revoked::cmp_bound`].
    pub fn cmp_bound(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Jti { exp: a, .. }, Self::Jti { exp: b, .. }) => match (a, b) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(a), Some(b)) => a.cmp(b),
            },
            (Self::Device { at_seq: a, .. }, Self::Device { at_seq: b, .. }) => a.cmp(b),
            (Self::Membership { at_epoch: a, .. }, Self::Membership { at_epoch: b, .. }) => a.cmp(b),
            _ => Ordering::Equal,
        }
    }
}

/// An issuer's revocations as of `epoch`.
///
/// `epoch` is strictly monotonic per issuer: every change the issuer records
/// produces a higher one, so a replica orders sets by epoch alone and never by
/// clock. Equal epochs carry equal contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationSet {
    pub issuer: String,
    pub epoch: u64,
    pub revoked: Vec<RevocationEntry>,
}

impl RevocationSet {
    /// A set in canonical form: `revoked` sorted and de-duplicated.
    ///
    /// Entries sharing an identity collapse to the one with the greatest bound
    /// ([`RevocationEntry::cmp_bound`]).
    pub fn new(issuer: impl Into<String>, epoch: u64, mut revoked: Vec<RevocationEntry>) -> Self {
        // Identity ascending, then bound descending, so the first of each
        // identity run is the one to keep.
        revoked.sort_by(|a, b| a.identity().cmp(&b.identity()).then_with(|| b.cmp_bound(a)));
        revoked.dedup_by(|later, kept| later.identity() == kept.identity());
        Self {
            issuer: issuer.into(),
            epoch,
            revoked,
        }
    }
}

impl SignedArtifact for RevocationSet {
    const IMPLICIT_ASSERTION: &'static [u8] = b"urn:cheers:artifact:revocation-set:v1";

    fn issuer(&self) -> &str {
        &self.issuer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jti(j: &str, exp: Option<i64>) -> RevocationEntry {
        RevocationEntry::Jti { jti: j.into(), exp }
    }

    fn device(d: &str, at_seq: u64) -> RevocationEntry {
        RevocationEntry::Device { device: DeviceId::new(d), at_seq }
    }

    fn membership(tag: u8, at_epoch: u64) -> RevocationEntry {
        RevocationEntry::Membership { tag: MembershipTag::from_bytes([tag; 32]), at_epoch }
    }

    #[test]
    fn wire_shape_is_externally_tagged_with_bounds() {
        let set = RevocationSet::new(
            "https://c.example",
            7,
            vec![
                membership(7, 12),
                device("phone", 900),
                jti("j1", Some(1_000)),
                jti("j0", None),
            ],
        );
        let v = serde_json::to_value(&set).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "issuer": "https://c.example",
                "epoch": 7,
                "revoked": [
                    {"jti": {"jti": "j0", "exp": null}},
                    {"jti": {"jti": "j1", "exp": 1_000}},
                    {"device": {"device": "phone", "at_seq": 900}},
                    {"membership": {"tag": URL_SAFE_NO_PAD.encode([7u8; 32]), "at_epoch": 12}},
                ],
            })
        );
        let back: RevocationSet = serde_json::from_value(v).unwrap();
        assert_eq!(back, set);
    }

    #[test]
    fn new_sorts_and_dedups_so_equal_contents_sign_equal_bytes() {
        let a = RevocationSet::new(
            "i",
            1,
            vec![jti("b", None), jti("a", None), jti("b", None)],
        );
        let b = RevocationSet::new("i", 1, vec![jti("a", None), jti("b", None)]);
        assert_eq!(serde_json::to_vec(&a).unwrap(), serde_json::to_vec(&b).unwrap());
    }

    #[test]
    fn new_dedups_by_identity_keeping_the_greatest_bound() {
        let set = RevocationSet::new(
            "i",
            1,
            vec![
                device("d", 5),
                jti("j", Some(10)),
                device("d", 9),
                jti("j", None),
                jti("k", Some(3)),
                jti("k", Some(7)),
                membership(1, 2),
                membership(1, 1),
            ],
        );
        assert_eq!(
            set.revoked,
            vec![
                jti("j", None),
                jti("k", Some(7)),
                device("d", 9),
                membership(1, 2),
            ]
        );
    }

    #[test]
    fn only_a_jti_with_an_exp_lapses() {
        assert!(Revoked::jti("j", Some(10)).is_lapsed_at(10));
        assert!(!Revoked::jti("j", Some(10)).is_lapsed_at(9));
        assert!(!Revoked::jti("j", None).is_lapsed_at(i64::MAX));
        assert!(!Revoked::device("d", 1).is_lapsed_at(i64::MAX));
    }

    #[test]
    fn a_tag_or_key_of_the_wrong_length_is_refused() {
        let short = serde_json::json!({"membership": {"tag": URL_SAFE_NO_PAD.encode([1u8; 31]), "at_epoch": 1}});
        assert!(serde_json::from_value::<RevocationEntry>(short).is_err());
        let key = RevocationKey::from_bytes([9; 32]);
        let back: RevocationKey = serde_json::from_value(serde_json::to_value(&key).unwrap()).unwrap();
        assert_eq!(back, key);
        assert_eq!(format!("{key:?}"), "RevocationKey(..)");
    }

    #[test]
    fn implicit_assertion_is_non_empty() {
        // The access-token paths verify with the empty assertion; a non-empty
        // one is what keeps a set from ever verifying there.
        assert!(!RevocationSet::IMPLICIT_ASSERTION.is_empty());
    }
}
