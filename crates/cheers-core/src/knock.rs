//! Knock artifacts (R734-F2; `knock.md`, "Artifacts"): [`Knock`], [`Offer`]
//! and [`Admit`].
//!
//! A `Knock` is the knock direction (an outsider's key asks for a relation),
//! an `Offer` is the invite direction (whoever redeems it may hold the
//! relation), and both end in an `Admit` (an approver's device key says the
//! requester holds the relation). Each binds its own implicit assertion, so
//! no two of them, and no other artifact or access token, verify as each
//! other.
//!
//! # Device-signed
//!
//! `Knock` and `Admit` are signed by a **device key**, never the issuer, and a
//! device-signed `Offer` is signed by its approver's key. They implement
//! [`DeviceSigned`]: the payload names the signing key as a
//! [`Key`](PrincipalKind::Key) principal, and
//! `cheers_verify::verify_device_artifact` verifies the PASETO under exactly
//! that key. It is the same [`SignedArtifact`] envelope (flat payload, kind
//! assertion), keyed by the embedded public key instead of a JWKS lookup.
//! For a device-signed artifact [`SignedArtifact::issuer`] is the signing
//! key's id.

use serde::{Deserialize, Serialize};

use crate::admission::{AdmissionPath, Confirmation};
use crate::artifact::SignedArtifact;
use crate::lease::{Lease, LeaseError};
use crate::principal::{PrincipalId, PrincipalKind};

/// A [`SignedArtifact`] signed by the device key it names, not by the issuer.
pub trait DeviceSigned: SignedArtifact {
    /// The signing key, always a [`PrincipalKind::Key`] principal.
    fn signer(&self) -> &PrincipalId;
}

/// Why a knock artifact was refused at construction or verification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KnockError {
    /// The signer (or requester) must be a `key:` principal.
    #[error("{0} is not a key principal")]
    NotAKey(PrincipalId),
    /// An `Admit` must carry an `exp` (C1, posted lease).
    #[error("an Admit lease must carry exp")]
    MissingExp,
    /// The lease breaks the midpoint invariant.
    #[error(transparent)]
    Lease(#[from] LeaseError),
}

fn require_key(p: &PrincipalId) -> Result<(), KnockError> {
    if p.kind == PrincipalKind::Key {
        Ok(())
    } else {
        Err(KnockError::NotAKey(p.clone()))
    }
}

/// Key K asks for `relation` on `(kind, id)`. Signed by K.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Knock {
    /// The requester's key, which signed this knock.
    pub requester: PrincipalId,
    pub kind: String,
    pub id: String,
    pub relation: String,
    /// Fresh per knock; feeds the `compare` code.
    pub nonce: String,
    /// What the approver's screen shows.
    pub label: String,
    /// A standing binding token naming the requester's user, if it has one
    /// (`users` mode admits only these).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standing: Option<String>,
    /// The `jti` of a prior [`Admit`] this knock renews (`knock.md`, "Renew").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renews: Option<String>,
    pub iat: i64,
}

impl Knock {
    /// Refuses a requester that is not a key principal.
    pub fn validate(&self) -> Result<(), KnockError> {
        require_key(&self.requester)
    }
}

impl SignedArtifact for Knock {
    const IMPLICIT_ASSERTION: &'static [u8] = b"urn:cheers:artifact:knock:v1";

    fn issuer(&self) -> &str {
        &self.requester.id
    }
}

impl DeviceSigned for Knock {
    fn signer(&self) -> &PrincipalId {
        &self.requester
    }
}

/// Whoever redeems this with a key may hold `relation` on `(kind, id)`, up to
/// `max_uses` times before `exp`.
///
/// `issuer` is the cheers issuer URL when the issuer signed it, or a
/// key id when an approver's device did (then [`signer`](Self::signer) is
/// `Some`). Redemption is the online routes' job (R734-F4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offer {
    pub issuer: String,
    /// The approver key that signed it; `None` when the issuer did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<PrincipalId>,
    pub kind: String,
    pub id: String,
    pub relation: String,
    pub max_uses: u32,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
}

impl SignedArtifact for Offer {
    const IMPLICIT_ASSERTION: &'static [u8] = b"urn:cheers:artifact:offer:v1";

    fn issuer(&self) -> &str {
        &self.issuer
    }
}

/// What an [`Admit`] answers: the hash of the [`Knock`] or [`Offer`] token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "type", content = "hash")]
pub enum AdmitSource {
    Knock(String),
    Offer(String),
}

/// The approver's key says `requester` holds `relation` on `(kind, id)`.
/// Signed by `approver`; offline only (an online admission writes a tuple).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Admit {
    /// The approver's device key, which signed this admit.
    pub approver: PrincipalId,
    /// The approver's standing binding token, proving which user the key
    /// belongs to. `None` when the key itself holds an issuer tuple.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver_binding: Option<String>,
    /// The cheers issuer the authority was checked under.
    pub authority: String,
    pub requester: PrincipalId,
    /// The requester's standing binding token (from its [`Knock`]), if it
    /// presented one; `users` mode admits only these.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester_binding: Option<String>,
    pub kind: String,
    pub id: String,
    pub relation: String,
    pub source: AdmitSource,
    pub confirmation: Confirmation,
    /// The snapshot epoch of `(kind, id)` the approver checked against.
    pub epoch: u64,
    /// What [`Revoked::Jti`](crate::Revoked::Jti) names to drop it.
    pub jti: String,
    pub iat: i64,
    /// Always with `exp` (C1). Flattens to `refresh_after` and `exp`.
    #[serde(flatten)]
    pub lease: Lease,
}

impl Admit {
    /// Everything a decoded or freshly built admit must satisfy: key
    /// principals on both sides, a lease with `exp`, and the midpoint
    /// invariant.
    pub fn validate(&self) -> Result<(), KnockError> {
        require_key(&self.approver)?;
        require_key(&self.requester)?;
        if self.lease.exp().is_none() {
            return Err(KnockError::MissingExp);
        }
        self.lease.validate(self.iat)?;
        Ok(())
    }

    /// The admission path whose posted-lease terms apply: `scan` when the
    /// approver confirmed by scanning, else the source's kind.
    pub fn path(&self) -> AdmissionPath {
        match (self.confirmation, &self.source) {
            (Confirmation::Scan, _) => AdmissionPath::Scan,
            (_, AdmitSource::Knock(_)) => AdmissionPath::Knock,
            (_, AdmitSource::Offer(_)) => AdmissionPath::Offer,
        }
    }
}

impl SignedArtifact for Admit {
    const IMPLICIT_ASSERTION: &'static [u8] = b"urn:cheers:artifact:admit:v1";

    fn issuer(&self) -> &str {
        &self.approver.id
    }
}

impl DeviceSigned for Admit {
    fn signer(&self) -> &PrincipalId {
        &self.approver
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admit(refresh_after: i64, exp: Option<i64>) -> Admit {
        Admit {
            approver: PrincipalId::from_public_key(&[1; 32]),
            approver_binding: None,
            authority: "https://c.example".into(),
            requester: PrincipalId::from_public_key(&[2; 32]),
            requester_binding: None,
            kind: "namespace".into(),
            id: "ed".into(),
            relation: "guest".into(),
            source: AdmitSource::Knock("h".into()),
            confirmation: Confirmation::Compare,
            epoch: 3,
            jti: "j".into(),
            iat: 1_000,
            lease: serde_json::from_value(serde_json::json!({"refresh_after": refresh_after, "exp": exp})).unwrap(),
        }
    }

    #[test]
    fn admit_requires_exp_and_the_midpoint() {
        assert!(admit(1_500, Some(2_000)).validate().is_ok());
        assert_eq!(admit(1_500, None).validate(), Err(KnockError::MissingExp));
        assert!(matches!(admit(1_501, Some(2_000)).validate(), Err(KnockError::Lease(_))));
        let mut a = admit(1_500, Some(2_000));
        a.approver = PrincipalId::user("alice");
        assert!(matches!(a.validate(), Err(KnockError::NotAKey(_))));
    }

    #[test]
    fn wire_flattens_the_lease_and_spells_levels_lowercase() {
        let v = serde_json::to_value(admit(1_500, Some(2_000))).unwrap();
        assert_eq!(v["refresh_after"], 1_500);
        assert_eq!(v["exp"], 2_000);
        assert_eq!(v["confirmation"], "compare");
        assert_eq!(v["source"], serde_json::json!({"type": "knock", "hash": "h"}));
        let mut a = admit(1_500, Some(2_000));
        assert_eq!(a.path(), AdmissionPath::Knock);
        a.confirmation = Confirmation::Scan;
        assert_eq!(a.path(), AdmissionPath::Scan);
    }

    #[test]
    fn each_kind_has_its_own_assertion() {
        let all = [Knock::IMPLICIT_ASSERTION, Offer::IMPLICIT_ASSERTION, Admit::IMPLICIT_ASSERTION];
        assert_eq!(all[0], b"urn:cheers:artifact:knock:v1");
        assert_eq!(all[1], b"urn:cheers:artifact:offer:v1");
        assert_eq!(all[2], b"urn:cheers:artifact:admit:v1");
        assert_ne!(Admit::IMPLICIT_ASSERTION, crate::StandingBinding::IMPLICIT_ASSERTION);
    }
}
