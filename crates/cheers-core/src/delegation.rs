//! [`UserDelegation`] — the user-signed authorization that lets cheers bind a
//! camp principal to a user at provision time.
//!
//! See `.yah/docs/working/mcp-auth-and-ownership.md` §Camp bootstrap. Yubaba
//! provisions a camp on behalf of a user `U`; cheers won't allocate the camp
//! principal until it sees a payload signed by `U` authorising the binding.
//! The signing flow itself is yah-side (W122 QR-pair / mobile-app); cheers's
//! job is to (a) carry a well-typed shape on the wire and (b) verify the
//! Ed25519 signature inside `cheers-server` against a pubkey trusted for `U`.
//!
//! This module only defines the **shape** + the **canonical signing payload**.
//! The verification primitive (Ed25519 over `signing_payload()`) lives in
//! `cheers-server` so `cheers-core` stays crypto-free.
//!
//! ## Wire format
//!
//! `user_signing_key` is the 32-byte Ed25519 public key the signature must
//! verify under; both it and the 64-byte `signature` ride on the wire as
//! base64url-no-pad strings (matches the JWKS / service-principal-key encoding
//! the doc uses elsewhere). `bound_to` MUST be a user principal — invariant is
//! checked by [`UserDelegation::new`] *and* the [`Deserialize`] impl up front
//! so a misconfigured (or hand-crafted wire) payload never reaches the
//! authority.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::principal::{PrincipalId, PrincipalKind};

/// Why a [`UserDelegation`] failed to validate before reaching the authority.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DelegationError {
    /// `bound_to` must name a user principal (`user:<id>`).
    #[error("bound_to must be a user principal; got {0}")]
    BoundToNotUser(PrincipalKind),
    /// `camp_id` was empty — the delegation is meaningless without a target.
    #[error("camp_id must be non-empty")]
    EmptyCampId,
    /// `expires_at <= issued_at`.
    #[error("expires_at must be strictly greater than issued_at")]
    ExpiresBeforeIssued,
}

/// A short-lived authorization signed by a user `U` that lets cheers bind a
/// camp principal to `U` at provision time.
///
/// The signed payload is the canonical byte serialization of every field
/// except `signature` itself (see [`signing_payload`](Self::signing_payload)).
/// Construct via [`UserDelegation::new`] — the constructor enforces the
/// invariants the authority would otherwise reject downstream. Deserialization
/// runs those same checks via [`RawUserDelegation`], so a wire payload can't
/// bypass them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct UserDelegation {
    /// The user authorising the delegation. MUST have
    /// [`kind = User`](PrincipalKind::User).
    pub bound_to: PrincipalId,
    /// Camp identifier (the bare half of the to-be-minted `camp:<id>`).
    /// Non-empty.
    pub camp_id: String,
    /// Unix-second timestamp the user signed at.
    pub issued_at: i64,
    /// Unix-second timestamp the delegation stops being acceptable.
    pub expires_at: i64,
    /// Ed25519 public key the signature must verify under (32 bytes).
    /// Wire form: base64url-no-pad string.
    #[serde(with = "ed25519_public_key_serde")]
    pub user_signing_key: [u8; 32],
    /// Ed25519 signature over [`signing_payload`](Self::signing_payload)
    /// (64 bytes). Wire form: base64url-no-pad string.
    #[serde(with = "ed25519_signature_serde")]
    pub signature: [u8; 64],
}

impl UserDelegation {
    /// Construct + validate. Rejects a non-user `bound_to`, an empty
    /// `camp_id`, or an `expires_at` not strictly after `issued_at`.
    pub fn new(
        bound_to: PrincipalId,
        camp_id: impl Into<String>,
        issued_at: i64,
        expires_at: i64,
        user_signing_key: [u8; 32],
        signature: [u8; 64],
    ) -> Result<Self, DelegationError> {
        if bound_to.kind != PrincipalKind::User {
            return Err(DelegationError::BoundToNotUser(bound_to.kind));
        }
        let camp_id = camp_id.into();
        if camp_id.is_empty() {
            return Err(DelegationError::EmptyCampId);
        }
        if expires_at <= issued_at {
            return Err(DelegationError::ExpiresBeforeIssued);
        }
        Ok(Self {
            bound_to,
            camp_id,
            issued_at,
            expires_at,
            user_signing_key,
            signature,
        })
    }

    /// `true` iff `expires_at <= now` — mirrors
    /// [`McpClaims::is_expired_at`](crate::McpClaims::is_expired_at).
    pub fn is_expired_at(&self, now: i64) -> bool {
        self.expires_at <= now
    }

    /// Canonical bytes the user signed.
    ///
    /// Stable across runs: a fixed-ordered struct of every field except the
    /// signature itself, serialized through `serde_json` (which preserves
    /// struct field order). Producers (the yah-side W122 signing flow) and
    /// verifiers (cheers-server) MUST agree on this format byte-for-byte;
    /// any change is a wire-contract change.
    pub fn signing_payload(&self) -> Vec<u8> {
        let unsigned = UnsignedPayload {
            bound_to: &self.bound_to,
            camp_id: &self.camp_id,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            user_signing_key: &self.user_signing_key,
        };
        serde_json::to_vec(&unsigned).expect("UnsignedPayload serializes infallibly")
    }
}

/// The wire shape [`UserDelegation`] deserializes *through* — a structural
/// mirror with the same fields + serde attrs, but no invariant checks. The
/// [`Deserialize`] impl below reconstructs through [`UserDelegation::new`] so a
/// hand-crafted payload can't bypass the constructor's guarantees (mirrors
/// [`Principal`](crate::Principal) / `RawPrincipal`).
#[derive(Deserialize)]
struct RawUserDelegation {
    bound_to: PrincipalId,
    camp_id: String,
    issued_at: i64,
    expires_at: i64,
    #[serde(with = "ed25519_public_key_serde")]
    user_signing_key: [u8; 32],
    #[serde(with = "ed25519_signature_serde")]
    signature: [u8; 64],
}

impl<'de> Deserialize<'de> for UserDelegation {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let raw = RawUserDelegation::deserialize(de)?;
        UserDelegation::new(
            raw.bound_to,
            raw.camp_id,
            raw.issued_at,
            raw.expires_at,
            raw.user_signing_key,
            raw.signature,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// The struct whose JSON encoding IS the canonical signing payload.
///
/// Field order here is load-bearing — `serde_json` emits keys in struct
/// declaration order, and that's what both producer and verifier hash over.
/// The signing key rides as base64url-no-pad for the same reason it does in
/// [`UserDelegation`]: cross-platform Ed25519 toolchains all share that
/// encoding.
#[derive(Serialize)]
struct UnsignedPayload<'a> {
    bound_to: &'a PrincipalId,
    camp_id: &'a str,
    issued_at: i64,
    expires_at: i64,
    #[serde(with = "ed25519_public_key_serde_ref")]
    user_signing_key: &'a [u8; 32],
}

mod ed25519_public_key_serde {
    use super::*;
    use serde::de::Error as DeError;

    pub fn serialize<S: serde::Serializer>(bytes: &[u8; 32], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(de: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(de)?;
        let raw = URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map_err(|e| D::Error::custom(format!("invalid base64url user_signing_key: {e}")))?;
        raw.try_into().map_err(|v: Vec<u8>| {
            D::Error::custom(format!("expected 32 user_signing_key bytes, got {}", v.len()))
        })
    }
}

mod ed25519_public_key_serde_ref {
    use super::*;

    pub fn serialize<S: serde::Serializer>(
        bytes: &&[u8; 32],
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&URL_SAFE_NO_PAD.encode(**bytes))
    }
}

mod ed25519_signature_serde {
    use super::*;
    use serde::de::Error as DeError;

    pub fn serialize<S: serde::Serializer>(bytes: &[u8; 64], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(de: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(de)?;
        let raw = URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map_err(|e| D::Error::custom(format!("invalid base64url signature: {e}")))?;
        raw.try_into().map_err(|v: Vec<u8>| {
            D::Error::custom(format!("expected 64 signature bytes, got {}", v.len()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(now: i64) -> UserDelegation {
        UserDelegation::new(
            PrincipalId::user("alice"),
            "camp-xyz",
            now,
            now + 600,
            [7u8; 32],
            [9u8; 64],
        )
        .unwrap()
    }

    #[test]
    fn new_rejects_non_user_bound_to() {
        let err = UserDelegation::new(
            PrincipalId::service("yubaba"),
            "c-1",
            1_000,
            1_600,
            [0u8; 32],
            [0u8; 64],
        )
        .unwrap_err();
        assert_eq!(err, DelegationError::BoundToNotUser(PrincipalKind::Service));

        let err = UserDelegation::new(
            PrincipalId::camp("c-1"),
            "c-1",
            1_000,
            1_600,
            [0u8; 32],
            [0u8; 64],
        )
        .unwrap_err();
        assert_eq!(err, DelegationError::BoundToNotUser(PrincipalKind::Camp));
    }

    #[test]
    fn new_rejects_empty_camp_id() {
        let err = UserDelegation::new(
            PrincipalId::user("alice"),
            "",
            1_000,
            1_600,
            [0u8; 32],
            [0u8; 64],
        )
        .unwrap_err();
        assert_eq!(err, DelegationError::EmptyCampId);
    }

    #[test]
    fn new_rejects_expires_at_or_before_issued_at() {
        let err = UserDelegation::new(
            PrincipalId::user("alice"),
            "c-1",
            1_000,
            1_000,
            [0u8; 32],
            [0u8; 64],
        )
        .unwrap_err();
        assert_eq!(err, DelegationError::ExpiresBeforeIssued);

        let err = UserDelegation::new(
            PrincipalId::user("alice"),
            "c-1",
            1_000,
            999,
            [0u8; 32],
            [0u8; 64],
        )
        .unwrap_err();
        assert_eq!(err, DelegationError::ExpiresBeforeIssued);
    }

    #[test]
    fn is_expired_at_uses_inclusive_boundary() {
        let d = sample(1_000);
        assert!(!d.is_expired_at(1_599));
        assert!(d.is_expired_at(1_600));
        assert!(d.is_expired_at(1_601));
    }

    #[test]
    fn serde_roundtrips_with_base64url_keys_and_sig() {
        let d = sample(1_000);
        let json = serde_json::to_string(&d).unwrap();
        // pubkey and signature ride as plain strings, not byte arrays.
        assert!(json.contains("\"user_signing_key\":\""));
        assert!(json.contains("\"signature\":\""));
        assert!(!json.contains("[7,7"), "must NOT be a byte array: {json}");
        let back: UserDelegation = serde_json::from_str(&json).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn deserialize_rejects_wrong_length_pubkey() {
        let json = r#"{
            "bound_to":"user:alice",
            "camp_id":"c-1",
            "issued_at":1,
            "expires_at":2,
            "user_signing_key":"AAAA",
            "signature":"AA"
        }"#;
        let err = serde_json::from_str::<UserDelegation>(json).unwrap_err();
        assert!(
            err.to_string().contains("32 user_signing_key bytes"),
            "got {err}"
        );
    }

    #[test]
    fn deserialize_rejects_non_user_bound_to() {
        // A wire delegation whose `bound_to` names a non-user principal must
        // fail to deserialize — the raw intermediate can't bypass `new()`.
        let json = serde_json::to_string(&sample(1_000))
            .unwrap()
            .replace("user:alice", "svc:yubaba");
        let err = serde_json::from_str::<UserDelegation>(&json).unwrap_err();
        assert!(
            err.to_string().contains("bound_to must be a user principal"),
            "got {err}"
        );
    }

    #[test]
    fn deserialize_rejects_expires_at_or_before_issued_at() {
        // sample(1_000) has issued_at:1000, expires_at:1600. Collapse expiry to
        // equal issued_at on the wire and the deserializer must reject it.
        let json = serde_json::to_string(&sample(1_000))
            .unwrap()
            .replace("\"expires_at\":1600", "\"expires_at\":1000");
        let err = serde_json::from_str::<UserDelegation>(&json).unwrap_err();
        assert!(
            err.to_string()
                .contains("expires_at must be strictly greater than issued_at"),
            "got {err}"
        );
    }

    #[test]
    fn signing_payload_is_stable_byte_order() {
        // Two delegations with identical content produce byte-identical
        // payloads — the property the producer side relies on.
        let a = sample(1_000);
        let b = sample(1_000);
        assert_eq!(a.signing_payload(), b.signing_payload());
    }

    #[test]
    fn signing_payload_excludes_signature() {
        // Mutating only the signature must not change the payload — the
        // verifier needs the payload to be a *function of the to-be-signed
        // fields only*, not a circular dependency on the signature itself.
        let a = sample(1_000);
        let mut b = a.clone();
        b.signature = [42u8; 64];
        assert_eq!(a.signing_payload(), b.signing_payload());
    }

    #[test]
    fn signing_payload_differs_when_any_signed_field_changes() {
        let base = sample(1_000);
        for mutate in &[
            |d: &mut UserDelegation| d.camp_id = "other".into(),
            |d: &mut UserDelegation| d.issued_at = 9_999,
            |d: &mut UserDelegation| d.expires_at = 9_999,
            |d: &mut UserDelegation| d.user_signing_key = [1u8; 32],
            |d: &mut UserDelegation| d.bound_to = PrincipalId::user("bob"),
        ] {
            let mut m = base.clone();
            mutate(&mut m);
            assert_ne!(
                base.signing_payload(),
                m.signing_payload(),
                "mutation must change the payload"
            );
        }
    }

    #[test]
    fn signing_payload_starts_with_bound_to_field() {
        // Pin the canonical-byte-order property: bound_to is the first field
        // in the struct, so the encoded payload starts with "{"bound_to":".
        // If someone reorders the fields, this test will fail loudly.
        let d = sample(1_000);
        let payload = d.signing_payload();
        let head = std::str::from_utf8(&payload[..18]).unwrap();
        assert_eq!(head, "{\"bound_to\":\"user:");
    }
}
