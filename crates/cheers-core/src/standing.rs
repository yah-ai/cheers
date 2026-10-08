//! The **standing node binding** wire type (R732-F5; noisetable W235 §0.1, §5,
//! C5).
//!
//! A LAN-paired node used to hold only a 15-minute access token, so an edge
//! that could not reach cheers refused it a quarter of an hour after its last
//! refresh. W235 §0.1 fixes the invariant: **offline admission lasts until
//! revoked**. A [`StandingBinding`] is the credential that carries it — an
//! issuer-signed attestation that `sub` owns the node whose public key is
//! `peer_key`, with **no `exp`**. It ends in exactly two ways:
//!
//! - **revocation** — its `jti`, or its `device`, appears in the issuer's
//!   [`RevocationSet`](crate::RevocationSet);
//! - **supersession** — the issuer minted a newer binding for the same
//!   `device`, i.e. one with a higher [`seq`](StandingBinding::seq).
//!
//! Access tokens keep their 15-minute TTL; this amends cheers D2 for standing
//! edge credentials only.
//!
//! # Ordering
//!
//! `seq` is a per-device sequence kept by the issuer and advanced by
//! `max(prev + 1, now_unix)` — the same clock-floored rule as the revocation
//! epoch, so an issuer restored from an older backup still mints above what
//! edges already hold. Edges order bindings for one device by `seq` alone,
//! never by `iat`: issuer clocks move.
//!
//! # Wire shape
//!
//! The PASETO v4.public payload is the JSON of [`StandingBinding`], signed with
//! [`StandingBinding::IMPLICIT_ASSERTION`](crate::SignedArtifact) and a
//! `{"kid": ...}` footer:
//!
//! ```json
//! {"issuer":"https://cheers.example","sub":"alice","device":"node:9f2c..",
//!  "peer_key":{"alg":"ed25519","key":"<base64url>"},"seq":1791234567,
//!  "iat":1791234567,"jti":"Xq3..","refresh_after":1791839367}
//! ```

use serde::{Deserialize, Serialize};

use crate::artifact::SignedArtifact;
use crate::claims::{DeviceId, PeerKey, UserId};
use crate::lease::Lease;

/// An issuer's attestation that `sub` owns the node keyed `peer_key`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingBinding {
    /// The issuer that signed it; must equal the signing key's owner.
    pub issuer: String,
    /// The user the node belongs to, spelled like [`Claims::sub`](crate::Claims::sub).
    pub sub: UserId,
    /// The device this binding speaks for. Supersession and
    /// [`Revoked::Device`](crate::Revoked::Device) are both keyed on it.
    pub device: DeviceId,
    /// The node's long-lived public key. A binding admits only a peer that
    /// proved this key in its transport handshake.
    pub peer_key: PeerKey,
    /// The issuer's per-device sequence; a higher one supersedes this binding.
    pub seq: u64,
    /// When it was minted (Unix seconds). Informational: nothing orders or
    /// expires bindings by it.
    pub iat: i64,
    /// This binding's id — what [`Revoked::Jti`](crate::Revoked::Jti) names to
    /// end it alone.
    pub jti: String,
    /// When the node should fetch a successor if it can reach the issuer
    /// ([`Lease`]). **Advisory**: a binding past it still verifies. On the
    /// wire it flattens to `refresh_after` (and `exp`, when set).
    #[serde(flatten)]
    pub lease: Lease,
}

impl StandingBinding {
    /// `true` if this binding names `presented` as its node key.
    pub fn is_bound_to(&self, presented: &PeerKey) -> bool {
        &self.peer_key == presented
    }
}

impl SignedArtifact for StandingBinding {
    const IMPLICIT_ASSERTION: &'static [u8] = b"urn:cheers:artifact:standing-binding:v1";

    fn issuer(&self) -> &str {
        &self.issuer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease::LeaseState;
    use crate::RevocationSet;

    fn binding() -> StandingBinding {
        StandingBinding {
            issuer: "https://c.example".into(),
            sub: UserId::new("alice"),
            device: DeviceId::new("node:1"),
            peer_key: PeerKey::ed25519([7; 32]),
            seq: 42,
            iat: 1_000,
            jti: "j1".into(),
            lease: Lease::new(1_000, 2_000, None).unwrap(),
        }
    }

    #[test]
    fn wire_shape_has_no_exp_and_round_trips() {
        let v = serde_json::to_value(binding()).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "issuer": "https://c.example",
                "sub": "alice",
                "device": "node:1",
                "peer_key": {"alg": "ed25519", "key": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"},
                "seq": 42,
                "iat": 1_000,
                "jti": "j1",
                "refresh_after": 2_000,
            })
        );
        let back: StandingBinding = serde_json::from_value(v).unwrap();
        assert_eq!(back, binding());
    }

    #[test]
    fn refresh_after_is_advisory_and_binding_compares_keys() {
        let b = binding();
        assert_eq!(b.lease.state_at(1_999), LeaseState::Current);
        assert_eq!(b.lease.state_at(2_000), LeaseState::Warning { exp: None });
        assert!(b.is_bound_to(&PeerKey::ed25519([7; 32])));
        assert!(!b.is_bound_to(&PeerKey::ed25519([8; 32])));
    }

    /// Bytes the pre-`Lease` struct (`refresh_after: i64` as its last field)
    /// serialized to; the flattened lease must reproduce them exactly.
    const GOLDEN: &str = r#"{"issuer":"https://c.example","sub":"alice","device":"node:1","peer_key":{"alg":"ed25519","key":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"},"seq":42,"iat":1000,"jti":"j1","refresh_after":2000}"#;

    #[test]
    fn flattened_lease_is_byte_identical_to_the_old_wire() {
        assert_eq!(serde_json::to_string(&binding()).unwrap(), GOLDEN);
        let back: StandingBinding = serde_json::from_str(GOLDEN).unwrap();
        assert_eq!(back, binding());
        assert_eq!(serde_json::to_string(&back).unwrap(), GOLDEN);
    }

    #[test]
    fn exp_rides_the_flattened_lease() {
        let mut b = binding();
        b.lease = Lease::new(1_000, 1_500, Some(2_000)).unwrap();
        let json = serde_json::to_string(&b).unwrap();
        assert!(json.ends_with(r#""jti":"j1","refresh_after":1500,"exp":2000}"#), "{json}");
        assert_eq!(serde_json::from_str::<StandingBinding>(&json).unwrap(), b);
    }

    #[test]
    fn implicit_assertion_is_its_own() {
        assert!(!StandingBinding::IMPLICIT_ASSERTION.is_empty());
        assert_ne!(StandingBinding::IMPLICIT_ASSERTION, RevocationSet::IMPLICIT_ASSERTION);
    }
}
