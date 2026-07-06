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
//! ## The production writer: `HttpEnrollmentSink` (R593-F9, server-mediated)
//!
//! F5 shipped only the seam — the trait, its wiring, and a `#[cfg(test)]`
//! recorder — deliberately *not* a client-side impl that mints an
//! `ownership:write` token and `POST`s the row itself, because doing so
//! safely was not possible with cheers's `POST /ownership` contract, and the
//! accepter is an **end-user device** (phone / Mac):
//!
//! - Writing an ownership row that way requires a service-principal secret
//!   carrying the `ownership:write` scope. Shipping that secret inside a
//!   distributed app binary means one extraction compromises the whole
//!   ledger.
//! - `POST /ownership` does not check its body `principal_id` against the
//!   token's `sub`, and `resource_kind` was a free-form `String` with no
//!   allow-list. A leaked `ownership:write` secret could forge *arbitrary*
//!   rows (`camp:any owns service:any`, not merely `node`-enrollment for the
//!   pairing user) — a full ledger compromise, not a scoped one.
//!
//! [`HttpEnrollmentSink`] is the R593-F9 fix: it never holds an
//! `ownership:write` secret at all. It POSTs to cheers-server's
//! **`/enrollment/node`** route (`cheers_axum::enrollment`, distinct from
//! `/ownership`) carrying the accepter's *own pre-existing user session
//! bearer* — the same session token the accepter already needed to be
//! "already-authed" in the first place (from its own passkey / OIDC /
//! magic-link login). That route:
//!
//! 1. Verifies the bearer as a **session** token ([`cheers_core::Claims`]),
//!    never an MCP token — a structurally different shape, so no
//!    `ownership:write` scope check even enters the picture.
//! 2. Derives `principal_id` from the verified session's `sub` — there is no
//!    body field for it, so there is nothing to mismatch against the token.
//! 3. Hardcodes `resource_kind`/`relationship` to [`NODE_RESOURCE_KIND`] /
//!    [`OWNS_RELATIONSHIP`] server-side — the only thing this sink sends in
//!    the body is the `node_id` hex string.
//!
//! So the only "secret" [`HttpEnrollmentSink`] carries is the user's own
//! short-TTL, revocable session token — not a static, distributed, ledger-wide
//! credential. `on_behalf_of` is set by the server to the same authenticated
//! user, so `OwnershipStore::revoke_by_on_behalf_of`'s cascade sweeps the row
//! when the account goes away.
//!
//! ## UserDelegation (W268 §binding ceremonies) — still deferred
//!
//! W268 additionally calls out an *optional* `UserDelegation`
//! (`cheers_core::delegation::UserDelegation`) — a user-signed payload
//! authorizing the paired device to act on `U`'s behalf, verified by
//! `cheers_server::camp::CampAuthority::provision`. That signing ceremony
//! (W122's QR-pair / mobile-app flow) still has no production minting path
//! anywhere in the repo — `UserDelegation::new` requires a real Ed25519
//! signature from a `UserSigningKey` the user already registered, and cheers
//! has no HTTP route yet to register one for a real user. This remains a
//! follow-up: once the device holds a signing key, mint the `UserDelegation`
//! in [`Accepter::pair`](crate::lan_pair::Accepter::pair) right after
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

/// Production [`EnrollmentSink`] (R593-F9): POSTs to cheers-server's
/// `POST /enrollment/node` route, authenticated with the accepter's own
/// pre-existing user **session** bearer — never a static, distributed
/// secret. See the module doc's "The production writer" section for the
/// full security rationale.
///
/// ## What this does NOT do
///
/// It does not mint any token, does not hold an `ownership:write` scope, and
/// does not send `principal_id` / `resource_kind` on the wire — the request
/// body carries only the hex `node_id`; the server derives the principal
/// from the verified bearer and hardcodes the resource shape. This sink is
/// deliberately "dumb": it is a thin, unprivileged HTTP forwarder for a
/// credential the caller already legitimately holds.
///
/// ## Where the bearer comes from
///
/// [`HttpEnrollmentSink::new`] takes the session bearer as a plain string,
/// already obtained through whatever login flow the host app uses (passkey /
/// OIDC / magic-link against `cheers-axum`'s `/auth/*` routes) — this crate
/// has no opinion on how the accepter app stores or refreshes its own
/// session; that is product-level plumbing, same as `Offerer::
/// with_credential_store`'s stance on credential persistence.
pub struct HttpEnrollmentSink {
    client: reqwest::Client,
    /// Full URL of the target route, e.g. `https://cheers.example/api/enrollment/node`.
    endpoint: String,
    /// The accepter's own, already-established user session bearer
    /// (`Authorization: Bearer <this>`) — NOT a service-principal secret.
    session_bearer: String,
}

impl HttpEnrollmentSink {
    /// Build a sink that POSTs to `endpoint` (the full `/enrollment/node` URL)
    /// using `session_bearer` as the caller's own session token.
    pub fn new(
        client: reqwest::Client,
        endpoint: impl Into<String>,
        session_bearer: impl Into<String>,
    ) -> Self {
        Self {
            client,
            endpoint: endpoint.into(),
            session_bearer: session_bearer.into(),
        }
    }
}

impl std::fmt::Debug for HttpEnrollmentSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the bearer.
        f.debug_struct("HttpEnrollmentSink")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

#[derive(serde::Serialize)]
struct EnrollNodeRequestBody<'a> {
    node_id: &'a str,
}

#[async_trait]
impl EnrollmentSink for HttpEnrollmentSink {
    /// `user_id` is accepted for signature parity with [`EnrollmentSink`] and
    /// for callers that want to log/assert it locally, but it is NOT sent on
    /// the wire and plays no role in authorization — the server derives the
    /// actual principal from the verified `session_bearer`'s own claimed
    /// subject, which is the whole point (a forged `user_id` here cannot
    /// attribute the row to anyone but whoever the bearer really belongs to).
    async fn enroll(&self, _user_id: &str, node_id: mshr::NodeId) -> Result<(), LanPairError> {
        let node_id_hex = node_id.to_string();
        let resp = self
            .client
            .post(&self.endpoint)
            .bearer_auth(&self.session_bearer)
            .json(&EnrollNodeRequestBody {
                node_id: &node_id_hex,
            })
            .send()
            .await
            .map_err(|e| LanPairError::Enrollment(format!("enrollment http request: {e}")))?;

        if resp.status().is_success() {
            return Ok(());
        }
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        Err(LanPairError::Enrollment(format!(
            "enrollment route returned {status}: {body}"
        )))
    }
}

/// Test-only [`EnrollmentSink`] implementations.
///
/// Lives behind `#[cfg(test)]` — a seam-level double, cheaper than driving
/// [`HttpEnrollmentSink`] through a real HTTP mock for tests that only care
/// about `Accepter::pair`'s own behavior (see `http_tests` below for the
/// HttpEnrollmentSink-specific coverage). [`RecordingSink`] captures every
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

/// [`HttpEnrollmentSink`]-specific coverage (R593-F9): drives it against a
/// `wiremock` server standing in for cheers-server's `/enrollment/node`
/// route, verifying the wire contract this sink promises — bearer-only auth,
/// `node_id`-only body, no `principal_id`/`resource_kind` ever sent — plus a
/// full real-QUIC round trip through `Accepter::pair`.
#[cfg(test)]
mod http_tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::lan_pair::confirm::AutoTrust;
    use crate::lan_pair::{Accepter, Offerer, ALPN};
    use mshr::{Endpoint, Keypair};

    const TEST_BEARER: &str = "test-session-bearer-abc123";

    fn test_accept() -> crate::lan_pair::PairAccept {
        crate::lan_pair::PairAccept {
            user_id: "test-user-001".to_string(),
            device_id: "test-device-rpi".to_string(),
            attrs: HashMap::new(),
            expires_at: i64::MAX,
        }
    }

    #[tokio::test]
    async fn enroll_posts_only_node_id_with_the_session_bearer_no_other_fields() {
        let server = MockServer::start().await;
        let real_node_id: mshr::NodeId = Keypair::generate().node_id();
        let node_id = real_node_id.to_string();

        Mock::given(method("POST"))
            .and(path("/enrollment/node"))
            .and(header("authorization", format!("Bearer {TEST_BEARER}").as_str()))
            .and(body_json(serde_json::json!({ "node_id": node_id })))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "own-1",
                "principal_id": "user:test-user-001",
                "resource_kind": "node",
                "resource_id": node_id,
                "relationship": "owns",
                "granted_by": "svc:cheers-enrollment",
                "on_behalf_of": "user:test-user-001",
                "granted_at": 1_000,
                "revoked_at": null,
            })))
            .expect(1)
            .mount(&server)
            .await;

        let sink = HttpEnrollmentSink::new(
            reqwest::Client::new(),
            format!("{}/enrollment/node", server.uri()),
            TEST_BEARER,
        );

        sink.enroll("test-user-001", real_node_id)
            .await
            .expect("enroll succeeds against the mock 201");

        // wiremock's .expect(1) + verify() below is the load-bearing
        // assertion: exactly one POST, matching method/path/header/body —
        // body_json fails the match (and thus the mock, and thus this
        // await) if the sink ever sends principal_id or resource_kind.
        server.verify().await;
    }

    #[tokio::test]
    async fn enroll_surfaces_non_success_status_as_enrollment_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/enrollment/node"))
            .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
            .mount(&server)
            .await;

        let sink = HttpEnrollmentSink::new(
            reqwest::Client::new(),
            format!("{}/enrollment/node", server.uri()),
            "an-expired-or-invalid-bearer",
        );
        let node_id = Keypair::generate().node_id();
        let err = sink
            .enroll("test-user-001", node_id)
            .await
            .expect_err("401 must surface as an error, not Ok");
        assert!(matches!(err, LanPairError::Enrollment(_)), "got {err:?}");
    }

    /// Full round trip: real mshr QUIC handshake through `Accepter::pair`,
    /// wired with `HttpEnrollmentSink` pointed at a wiremock server — proves
    /// the seam (F5) and the production writer (F9) compose end to end, the
    /// same property F5's now-removed HttpEnrollmentSink integration tests
    /// checked, but against the new safe wire contract.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn completed_pair_posts_the_authenticated_node_id_via_the_enrollment_route() {
        let server = MockServer::start().await;

        let offerer_ep = Endpoint::builder()
            .keypair(Keypair::generate())
            .alpns([ALPN])
            .bind()
            .await
            .expect("offerer bind");
        let accepter_ep = Endpoint::builder()
            .keypair(Keypair::generate())
            .alpns([ALPN])
            .bind()
            .await
            .expect("accepter bind");
        let addr = offerer_ep.endpoint_addr();
        let offerer_node_id_hex = offerer_ep.node_id().to_string();

        Mock::given(method("POST"))
            .and(path("/enrollment/node"))
            .and(header("authorization", format!("Bearer {TEST_BEARER}").as_str()))
            .and(body_json(
                serde_json::json!({ "node_id": offerer_node_id_hex }),
            ))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "own-1",
                "principal_id": "user:test-user-001",
                "resource_kind": "node",
                "resource_id": offerer_node_id_hex,
                "relationship": "owns",
                "granted_by": "svc:cheers-enrollment",
                "on_behalf_of": "user:test-user-001",
                "granted_at": 1_000,
                "revoked_at": null,
            })))
            .expect(1)
            .mount(&server)
            .await;

        let sink = Arc::new(HttpEnrollmentSink::new(
            reqwest::Client::new(),
            format!("{}/enrollment/node", server.uri()),
            TEST_BEARER,
        ));
        let accepter = Accepter::new(accepter_ep).with_enrollment_sink(sink);
        let offerer = Offerer::new(offerer_ep);
        let strategy = AutoTrust { accept: test_accept() };

        let (o, a) = tokio::join!(offerer.wait_for_pair(), accepter.pair(addr, &strategy));
        o.expect("offerer completes pair");
        a.expect("accepter completes pair and the HTTP enrollment POST succeeds");

        server.verify().await;
    }
}
