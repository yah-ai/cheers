//! Signed artifacts — issuer-signed PASETO v4.public payloads that are **not**
//! access tokens (R732-F6; noisetable W235 §5.1).
//!
//! Access tokens ([`Claims`](crate::Claims), [`McpClaims`](crate::McpClaims)),
//! service ceilings and client assertions are all signed with the **empty**
//! PASETO implicit assertion and told apart by payload shape and key role.
//! That is not enough for an artifact an issuer key signs with no expiry: a
//! payload that happened to parse as both would verify on both paths.
//!
//! So every artifact kind binds its own non-empty implicit assertion into the
//! signature. An artifact therefore fails signature verification on every
//! access-token path (which verify with the empty assertion), an access token
//! fails on every artifact path, and two artifact kinds cannot be confused with
//! each other. Domain separation is cryptographic, not a parsing accident.
//!
//! The footer carries `{"kid": ...}` exactly as an access token's does, so a
//! JWKS verifier selects the key the same way. Only an **issuer**-role key may
//! sign an artifact (`cheers_verify::KeySetVerifier::verify_artifact`).

use serde::de::DeserializeOwned;
use serde::Serialize;

/// A payload cheers signs as a PASETO v4.public under its issuer key, outside
/// the access-token domain.
///
/// Spell the assertion `urn:cheers:artifact:<kind>:v<n>`; bump `<n>` when the
/// payload changes incompatibly so old and new never verify as each other.
pub trait SignedArtifact: Serialize + DeserializeOwned {
    /// The PASETO implicit assertion bound into this kind's signature.
    const IMPLICIT_ASSERTION: &'static [u8];

    /// The issuer the payload claims. Verifiers require it to equal the
    /// signing key's owner and the issuer they were configured to trust.
    fn issuer(&self) -> &str;
}
