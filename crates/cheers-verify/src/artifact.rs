//! [`IssuerTrust`] — which issuer a verifier believes, and how it knows that
//! issuer's keys (R732-F6).
//!
//! Every [`SignedArtifact`] consumer (the revocation-set replica here; the
//! membership snapshot and standing node binding of R732-F4/F5) needs the same
//! answer: "was this signed by the issuer I trust?". The keys come either from
//! one pinned public key (the edge configured with the issuer's 32 bytes) or
//! from a JWKS key set, where only an **issuer**-role key may sign (§D5).

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use cheers_core::{CodecError, SignedArtifact};

use crate::jwks::{JwksDoc, JwksError, KeySet};
use crate::key_set::{KeySetVerifier, VerifyError};
use crate::public_verifier::PasetoV4PublicVerifier;

/// An [`IssuerTrust`] as a document an edge can persist (R732-F5).
///
/// Standing credentials never expire, so an edge that restarts offline must
/// verify the ones it holds against the keys it trusted when it accepted them —
/// not against a JWKS it cannot fetch. Write [`IssuerTrust::export`] next to
/// the persisted binding, ledger and revocation set, and rebuild with
/// [`IssuerTrust::from_doc`] at boot. The rebuilt trust is static: it never
/// fetches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustDoc {
    pub issuer: String,
    pub anchor: AnchorDoc,
}

/// The keys of a [`TrustDoc`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorDoc {
    /// One pinned Ed25519 public key, base64url without padding.
    Pinned(String),
    /// A JWKS key set, exactly as published (roles and owners included).
    KeySet(JwksDoc),
}

#[derive(Clone)]
enum Anchor {
    Pinned(Arc<PasetoV4PublicVerifier>),
    KeySet(KeySetVerifier),
}

/// One trusted issuer and the keys that may speak for it. Cheap to clone.
#[derive(Clone)]
pub struct IssuerTrust {
    issuer: String,
    anchor: Anchor,
}

impl std::fmt::Debug for IssuerTrust {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let anchor = match self.anchor {
            Anchor::Pinned(_) => "pinned",
            Anchor::KeySet(_) => "key-set",
        };
        f.debug_struct("IssuerTrust")
            .field("issuer", &self.issuer)
            .field("anchor", &anchor)
            .finish()
    }
}

impl IssuerTrust {
    /// Trust `issuer` as whatever `key` signs.
    pub fn pinned(issuer: impl Into<String>, key: PasetoV4PublicVerifier) -> Self {
        Self {
            issuer: issuer.into(),
            anchor: Anchor::Pinned(Arc::new(key)),
        }
    }

    /// Trust `issuer` through a JWKS key set: the signing key must be
    /// issuer-role and owned by `issuer`.
    pub fn key_set(issuer: impl Into<String>, keys: KeySetVerifier) -> Self {
        Self {
            issuer: issuer.into(),
            anchor: Anchor::KeySet(keys),
        }
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The keys this trust verifies with right now, as a persistable document.
    /// A JWKS-cache-backed trust exports the cache's current set.
    pub fn export(&self) -> TrustDoc {
        let anchor = match &self.anchor {
            Anchor::Pinned(key) => AnchorDoc::Pinned(URL_SAFE_NO_PAD.encode(key.public_key().as_bytes())),
            Anchor::KeySet(keys) => AnchorDoc::KeySet(keys.key_set().doc().clone()),
        };
        TrustDoc {
            issuer: self.issuer.clone(),
            anchor,
        }
    }

    /// Rebuild a trust from [`export`](Self::export)'s document. Static: it
    /// verifies with exactly the persisted keys and never fetches.
    pub fn from_doc(doc: TrustDoc) -> Result<Self, JwksError> {
        match doc.anchor {
            AnchorDoc::Pinned(b64) => {
                let bad = |reason: String| JwksError::BadKey {
                    kid: "<pinned>".into(),
                    reason,
                };
                let bytes = URL_SAFE_NO_PAD
                    .decode(&b64)
                    .map_err(|e| bad(format!("base64url decode: {e}")))?;
                let key: [u8; 32] = bytes
                    .try_into()
                    .map_err(|v: Vec<u8>| bad(format!("expected 32 bytes, got {}", v.len())))?;
                let verifier = PasetoV4PublicVerifier::from_public_key(&key).map_err(|e| bad(e.to_string()))?;
                Ok(Self::pinned(doc.issuer, verifier))
            }
            AnchorDoc::KeySet(jwks) => Ok(Self::key_set(
                doc.issuer,
                KeySetVerifier::from_key_set(KeySet::from_doc(jwks)?),
            )),
        }
    }

    /// Verify `token` as a `T` signed for this issuer.
    pub async fn verify<T: SignedArtifact>(&self, token: &str) -> Result<T, VerifyError> {
        let artifact: T = match &self.anchor {
            Anchor::Pinned(key) => key.verify_artifact(token).map_err(from_codec)?,
            Anchor::KeySet(keys) => keys.verify_artifact(token).await?,
        };
        if artifact.issuer() != self.issuer {
            return Err(VerifyError::BadIssuer {
                expected: self.issuer.clone(),
                got: artifact.issuer().to_owned(),
            });
        }
        Ok(artifact)
    }
}

fn from_codec(e: CodecError) -> VerifyError {
    match e {
        CodecError::SignatureMismatch => VerifyError::SignatureMismatch,
        CodecError::Serde(e) => VerifyError::BadClaims(e.to_string()),
        other => VerifyError::Malformed(other.to_string()),
    }
}
