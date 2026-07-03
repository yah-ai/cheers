//! Enrollment seam for the LAN-pair outcome (R593-F5, W268 §"The binding:
//! enrollment is an ownership row").
//!
//! On a successful pairing, the accepter (the already-authenticated device
//! vouching for the new one) is the party that knows the binding to record:
//! `principal U owns node:<NodeId>`, where `U` is the pairing account and
//! `<NodeId>` is the QUIC-connection-authenticated identity of the paired
//! device. [`EnrollmentSink`] is the seam
//! [`Accepter::pair`](crate::lan_pair::Accepter::pair) calls with that binding
//! once both sides have completed the mutually-authenticated handshake and the
//! [`ConfirmationStrategy`](crate::lan_pair::ConfirmationStrategy) has
//! accepted — see [`Accepter::with_enrollment_sink`](crate::lan_pair::Accepter::with_enrollment_sink).
//!
//! ## The production writer is deferred to R593-F9 (server-mediated)
//!
//! This module deliberately ships **only the seam** — the trait and its
//! wiring — plus a `#[cfg(test)]` recorder. It intentionally does **not** ship
//! a client-side [`EnrollmentSink`] impl that mints an `ownership:write`
//! token and `POST`s the row itself, because doing so safely is not possible
//! with cheers's current `POST /ownership` contract, and the accepter is an
//! **end-user device** (phone / Mac):
//!
//! - Writing an ownership row requires a service-principal secret carrying the
//!   `ownership:write` scope. Shipping that secret inside a distributed app
//!   binary means one extraction compromises the whole ledger.
//! - cheers-server does **not** check `POST /ownership`'s body `principal_id`
//!   against the token's `sub`, and `resource_kind` is a free-form `String`
//!   with no allow-list. So a leaked `ownership:write` secret can forge
//!   *arbitrary* rows (`camp:any owns service:any`, not merely
//!   `node`-enrollment for the pairing user) — a full ledger compromise, not
//!   a scoped one.
//!
//! The safe privileged-write design — a **server-mediated** flow that never
//! puts an `ownership:write` secret on the device (the device presents its
//! pairing proof and cheers writes the row itself, scoped to `node`-enrollment
//! for the authenticated pairing account) — is tracked as **R593-F9**, with
//! the token-binding consumer **R593-F6** gated on it. Whoever implements F9
//! provides the production [`EnrollmentSink`] and wires it via
//! [`Accepter::with_enrollment_sink`](crate::lan_pair::Accepter::with_enrollment_sink);
//! the seam here is the exact insertion point, and [`NODE_RESOURCE_KIND`] /
//! [`OWNS_RELATIONSHIP`] pin the row shape it must produce (verbatim with
//! yubaba's fleet-path `cheers_client::enroll_node`, R593-F4). The row must
//! also set `on_behalf_of = user:<U>` so cheers's cascade revoke
//! (`OwnershipStore::revoke_by_on_behalf_of`) sweeps the device row when the
//! account goes away.
//!
//! ## UserDelegation (W268 §binding ceremonies) — also deferred to F9
//!
//! W268 additionally calls out an *optional* `UserDelegation`
//! (`cheers_core::delegation::UserDelegation`) — a user-signed payload
//! authorizing the paired device to act on `U`'s behalf, verified by
//! `cheers_server::camp::CampAuthority::provision`. That signing ceremony
//! (W122's QR-pair / mobile-app flow) has no production minting path anywhere
//! in the repo today — `UserDelegation::new` requires a real Ed25519
//! signature from a `UserSigningKey` the user already registered, and cheers
//! has no HTTP route yet to register one for a real user. It belongs with the
//! same server-mediated ceremony as the ownership write (R593-F9): once the
//! device holds a signing key, mint the `UserDelegation` in
//! [`Accepter::pair`](crate::lan_pair::Accepter::pair) right after
//! [`EnrollmentSink::enroll`] succeeds (same call site, same `user_id`, plus
//! the accepter's local signing key) and submit it alongside the enrollment
//! row.

use async_trait::async_trait;

use crate::lan_pair::LanPairError;

/// Canonical `resource_kind` for node-enrollment ownership rows — verbatim
/// with yubaba's fleet-path `cheers_client::NODE_RESOURCE_KIND` (R593-F4).
/// Both enrollment ceremonies (fleet admission, LAN-pair) must land the same
/// literal so the `owns[].node` claim vocabulary can't fork; the R593-F9
/// writer that ships the production LAN-pair sink uses this.
pub const NODE_RESOURCE_KIND: &str = "node";

/// Relationship string for enrollment rows — verbatim with F4's fleet path.
pub const OWNS_RELATIONSHIP: &str = "owns";

/// Where a completed pairing outcome gets recorded.
///
/// Called once by [`Accepter::pair`](crate::lan_pair::Accepter::pair) per
/// successful pairing, with:
///
/// - `user_id`: the pairing account, taken from the confirmed
///   [`PairAccept::user_id`](crate::lan_pair::PairAccept::user_id) (a
///   `cheers_core::UserId`-shaped string). The row's `principal_id` /
///   `on_behalf_of` are both `user:<user_id>`.
/// - `node_id`: the mshr `NodeId` of the **paired device**, taken from the
///   QUIC connection itself (`Connection::remote_id`) — never a self-reported
///   copy off the wire (see [`Accepter::pair`](crate::lan_pair::Accepter::pair)'s
///   doc for why that matters). Hex-encode it with `NodeId::to_string()` for
///   the row's `resource_id` (matches F4 / yubaba's `/identity` encoding).
///
/// The production impl (R593-F9) is **server-mediated** and holds no
/// `ownership:write` secret on the device — see the module doc for why a
/// client-side minter is unsafe under cheers's current `POST /ownership`
/// contract. Implementations SHOULD be idempotent for repeated pairing of the
/// same device (cheers's `POST /ownership` already is — identical live row →
/// `200`, no duplicate, R593-F4 — so a server-mediated sink inherits it).
#[async_trait]
pub trait EnrollmentSink: Send + Sync {
    async fn enroll(&self, user_id: &str, node_id: mshr::NodeId) -> Result<(), LanPairError>;
}

/// Test-only [`EnrollmentSink`] implementations.
///
/// Lives behind `#[cfg(test)]` so it never ships: F5 delivers the seam, not a
/// production writer (that's R593-F9). [`RecordingSink`] captures every
/// `(user_id, node_id)` the accepter hands it so tests can assert the seam is
/// invoked with the QUIC-authenticated identity and the vouching account, and
/// that a re-pair reports the same binding.
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Mutex;

    use super::*;

    /// Records each [`EnrollmentSink::enroll`] call. Optionally forced to
    /// fail, to prove the accepter surfaces a sink error as
    /// [`LanPairError::Enrollment`].
    #[derive(Default)]
    pub(crate) struct RecordingSink {
        calls: Mutex<Vec<(String, mshr::NodeId)>>,
        fail: bool,
    }

    impl RecordingSink {
        pub(crate) fn new() -> Self {
            Self::default()
        }

        pub(crate) fn failing() -> Self {
            Self { calls: Mutex::new(Vec::new()), fail: true }
        }

        /// Snapshot of every `(user_id, node_id)` captured so far.
        pub(crate) fn calls(&self) -> Vec<(String, mshr::NodeId)> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl EnrollmentSink for RecordingSink {
        async fn enroll(&self, user_id: &str, node_id: mshr::NodeId) -> Result<(), LanPairError> {
            self.calls.lock().unwrap().push((user_id.to_string(), node_id));
            if self.fail {
                Err(LanPairError::Enrollment("test-forced enrollment failure".into()))
            } else {
                Ok(())
            }
        }
    }
}
