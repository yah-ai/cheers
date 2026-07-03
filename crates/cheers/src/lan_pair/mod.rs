//! LAN-pair: credential bootstrap for headless devices over mshr.
//!
//! The rpi case: an already-authed device (phone/Mac) vouches for a fresh
//! headless device over the local network, using mshr as transport.
//!
//! ## Protocol
//!
//! ```text
//! Offerer (rpi, new device)   <─QUIC/TLS─>   Accepter (phone, authed)
//!   listen on ALPN                               connect to offerer addr
//!   open bidi stream
//!   ── PairOffer ──────────────────────────────►
//!                              ◄─────────────── run ConfirmationStrategy
//!   ◄── AccepterMsg::{Accept|Reject} ──────────
//!   store Credential (on Accept)
//! ```
//!
//! [`Offerer`] broadcasts `PairOffer` and waits for [`PairAccept`].
//! [`Accepter`] connects to the offerer, receives the offer, runs the
//! [`ConfirmationStrategy`], and sends the accept or reject response.
//!
//! ## Enrollment (R593-F5, W268 §"The binding: enrollment is an ownership row")
//!
//! A successful pair is the end-user-device enrollment ceremony: it proves
//! `PairAccept::user_id` (an already-authenticated account) vouches for the
//! offerer's mshr `NodeId`. [`Accepter::pair`] optionally calls an
//! [`enroll::EnrollmentSink`] with that binding once both sides have
//! completed the QUIC-authenticated handshake and the [`ConfirmationStrategy`]
//! has accepted — see [`Accepter::with_enrollment_sink`]. [`Offerer::wait_for_pair`]
//! optionally parks the received [`PairAccept`] into a
//! `cheers_core::CredentialStore` on the same success path — see
//! [`Offerer::with_credential_store`]. Both are opt-in (`Option`, default
//! `None`) so existing callers (and every test in this module) are
//! unaffected.
//!
//! F5 ships the **seam only** for the ownership write: the production
//! [`enroll::EnrollmentSink`] impl (a server-mediated privileged write that
//! never puts an `ownership:write` secret on the device) is deferred to
//! **R593-F9** — see [`enroll`]'s module doc for the security rationale. The
//! credential-parking side wires a real `cheers-store`
//! `KeyringStore`/`EncryptedFileStore` today (no privileged secret involved).

pub mod accepter;
pub mod confirm;
pub mod enroll;
pub mod offerer;

pub use accepter::Accepter;
pub use confirm::{AutoTrust, ConfirmationStrategy, DisplayCode, SixDigitCode};
pub use enroll::{EnrollmentSink, NODE_RESOURCE_KIND, OWNS_RELATIONSHIP};
pub use offerer::Offerer;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// ALPN protocol identifier for the LAN-pair handshake.
pub const ALPN: &[u8] = b"cheers/lan-pair/v1";

/// Maximum JSON frame size accepted for any single protocol message (64 KiB).
const MAX_FRAME: usize = 65_536;

/// Wire message sent by the offerer (rpi) to the accepter (phone).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PairOffer {
    /// Raw bytes of the offerer's mshr `NodeId` (Ed25519 public key).
    pub node_id: [u8; 32],
    /// Capabilities the offerer declares. Accepter should verify
    /// `"cheers/lan-pair/v1"` is present before sending credentials.
    pub capabilities: Vec<String>,
    /// Short confirmation code shown on the offerer's console. Present when
    /// the caller configured a code (e.g. via [`Offerer::with_code`] or
    /// [`Offerer::with_random_code`]). Absent for [`AutoTrust`] flows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

/// Credential bundle sent by the accepter (phone) to the offerer (rpi) on
/// successful pairing. The offerer stores this as its local `Credential`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PairAccept {
    /// `cheers_core::UserId` of the user vouching for the new device.
    pub user_id: String,
    /// Stable device identifier to assign to the newly-paired device.
    pub device_id: String,
    /// Arbitrary metadata (e.g. display name, device class, region).
    #[serde(default)]
    pub attrs: HashMap<String, String>,
    /// Unix timestamp (seconds) after which this pairing credential expires.
    pub expires_at: i64,
}

/// Internal response sent by the accepter after running its
/// [`ConfirmationStrategy`]. Not exposed in the public API.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum AccepterMsg {
    Accept(PairAccept),
    Reject { reason: String },
}

/// Errors from the LAN-pair protocol.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LanPairError {
    #[error("transport: {0}")]
    Transport(String),
    #[error("codec: {0}")]
    Codec(String),
    /// Remote peer explicitly declined or the strategy returned `None`.
    #[error("pairing rejected")]
    Rejected,
    /// Endpoint closed before a pairing attempt arrived (or before the
    /// protocol completed).
    #[error("connection closed unexpectedly")]
    ConnectionClosed,
    /// The QUIC handshake and pairing protocol completed successfully, but
    /// recording the outcome durably failed: either the accepter's
    /// [`EnrollmentSink::enroll`] call (ownership-row write, R593-F5) or the
    /// offerer's `CredentialStore::put` call (credential parking) errored.
    /// The peer has already been told `Accept`/`Reject` by this point, so
    /// callers should treat this as "pairing succeeded, enrollment needs a
    /// retry" rather than re-running the handshake.
    #[error("enrollment: {0}")]
    Enrollment(String),
    /// The offerer's self-reported [`PairOffer::node_id`] does not match the
    /// mshr `NodeId` the QUIC connection was actually authenticated as
    /// (`Connection::remote_id`). Only the connection-verified id is ever
    /// used to write the enrollment row — this rejects the (spoofable)
    /// wire-JSON copy outright rather than trusting it.
    #[error("offered node_id does not match the authenticated QUIC peer")]
    NodeIdMismatch,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use mshr::{Endpoint, Keypair};

    use super::*;
    use crate::lan_pair::confirm::{AutoTrust, DisplayCode, SixDigitCode};

    fn test_accept() -> PairAccept {
        PairAccept {
            user_id: "test-user-001".to_string(),
            device_id: "test-device-rpi".to_string(),
            attrs: HashMap::new(),
            expires_at: i64::MAX,
        }
    }

    async fn make_pair() -> (Offerer, Accepter, mshr::EndpointAddr) {
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
        (Offerer::new(offerer_ep), Accepter::new(accepter_ep), addr)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn autotrust_round_trip() {
        let (offerer, accepter, addr) = make_pair().await;
        let strategy = AutoTrust { accept: test_accept() };

        let (o, a) = tokio::join!(
            offerer.wait_for_pair(),
            accepter.pair(addr, &strategy),
        );

        let received = o.expect("offerer got PairAccept");
        let sent = a.expect("accepter completed pair");
        assert_eq!(received.user_id, "test-user-001");
        assert_eq!(sent.user_id, "test-user-001");
        assert_eq!(received.device_id, sent.device_id);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sixdigitcode_correct_accepts() {
        let (offerer, accepter, addr) = make_pair().await;
        let offerer = offerer.with_code("424242");

        let strategy = SixDigitCode {
            accept: test_accept(),
            // Simulate user reading code from console and entering it.
            prompt: Box::new(|offer| offer.code.clone().unwrap_or_default()),
        };

        let (o, a) = tokio::join!(
            offerer.wait_for_pair(),
            accepter.pair(addr, &strategy),
        );

        assert_eq!(o.expect("offerer").user_id, "test-user-001");
        assert_eq!(a.expect("accepter").user_id, "test-user-001");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sixdigitcode_wrong_code_rejects() {
        let (offerer, accepter, addr) = make_pair().await;
        let offerer = offerer.with_code("424242");

        let strategy = SixDigitCode {
            accept: test_accept(),
            prompt: Box::new(|_| "000000".to_string()),
        };

        let (o, a) = tokio::join!(
            offerer.wait_for_pair(),
            accepter.pair(addr, &strategy),
        );

        assert!(matches!(o, Err(LanPairError::Rejected)));
        assert!(matches!(a, Err(LanPairError::Rejected)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn displaycode_confirm_accepts() {
        let (offerer, accepter, addr) = make_pair().await;
        let offerer = offerer.with_code("777888");

        let strategy = DisplayCode {
            accept: test_accept(),
            display: Box::new(|_offer, _code| true),
        };

        let (o, a) = tokio::join!(
            offerer.wait_for_pair(),
            accepter.pair(addr, &strategy),
        );

        assert_eq!(o.expect("offerer").user_id, "test-user-001");
        assert_eq!(a.expect("accepter").user_id, "test-user-001");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn displaycode_cancel_rejects() {
        let (offerer, accepter, addr) = make_pair().await;
        let offerer = offerer.with_code("777888");

        let strategy = DisplayCode {
            accept: test_accept(),
            display: Box::new(|_offer, _code| false),
        };

        let (o, a) = tokio::join!(
            offerer.wait_for_pair(),
            accepter.pair(addr, &strategy),
        );

        assert!(matches!(o, Err(LanPairError::Rejected)));
        assert!(matches!(a, Err(LanPairError::Rejected)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn random_code_is_six_digits() {
        let ep = Endpoint::builder()
            .keypair(Keypair::generate())
            .alpns([ALPN])
            .bind()
            .await
            .unwrap();
        let offerer = Offerer::new(ep).with_random_code().unwrap();
        let code = offerer.code().expect("code was set");
        assert_eq!(code.len(), 6, "code must be exactly 6 chars");
        assert!(code.chars().all(|c| c.is_ascii_digit()), "code must be all digits");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn offerer_parks_credential_when_store_attached() {
        use cheers_core::{CredentialStore, DeviceBinding, StoreError};
        use std::sync::Mutex;

        #[derive(Default)]
        struct RecordingStore(Mutex<Vec<(String, cheers_core::Credential)>>);

        #[async_trait::async_trait]
        impl CredentialStore for RecordingStore {
            async fn put(
                &self,
                key: &str,
                cred: &cheers_core::Credential,
            ) -> Result<(), StoreError> {
                self.0.lock().unwrap().push((key.to_string(), cred.clone()));
                Ok(())
            }
            async fn get(
                &self,
                _key: &str,
            ) -> Result<Option<cheers_core::Credential>, StoreError> {
                unimplemented!("not exercised by this test")
            }
            async fn delete(&self, _key: &str) -> Result<(), StoreError> {
                unimplemented!("not exercised by this test")
            }
        }

        let (offerer, accepter, addr) = make_pair().await;
        let store = std::sync::Arc::new(RecordingStore::default());
        let offerer = offerer.with_credential_store(store.clone());
        let strategy = AutoTrust { accept: test_accept() };

        let (o, a) = tokio::join!(offerer.wait_for_pair(), accepter.pair(addr, &strategy));
        o.expect("offerer completes pair and parks credential");
        a.expect("accepter completes pair");

        let recorded = store.0.lock().unwrap();
        assert_eq!(recorded.len(), 1, "exactly one credential parked");
        let (key, cred) = &recorded[0];
        assert_eq!(key, "test-device-rpi");
        assert_eq!(cred.user_id.as_str(), "test-user-001");
        assert_eq!(cred.device_id.as_str(), "test-device-rpi");
        assert_eq!(cred.binding, DeviceBinding::LanPair);
        let roundtrip: PairAccept =
            serde_json::from_slice(&cred.material).expect("material round-trips PairAccept");
        assert_eq!(roundtrip.user_id, "test-user-001");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn accepter_rejects_offer_whose_claimed_node_id_does_not_match_the_authenticated_peer() {
        // Drive the wire protocol manually on the "offerer" side (bypassing
        // Offerer::wait_for_pair, which always sends its own real node_id)
        // so we can send a PairOffer whose node_id lies about who is
        // connecting. Accepter::pair must reject this before ever running
        // the ConfirmationStrategy or calling an EnrollmentSink.
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
        let real_node_id = *offerer_ep.node_id().as_bytes();
        assert_ne!(real_node_id, [0xAAu8; 32], "sanity: fixture id differs from the real one");

        let malicious_offerer = tokio::spawn(async move {
            let incoming = offerer_ep.accept().await.expect("incoming connection");
            let conn = incoming.await.expect("handshake completes");
            let (mut send, mut recv) = conn.open_bi().await.expect("open bidi stream");
            let lying_offer = PairOffer {
                node_id: [0xAAu8; 32], // does NOT match offerer_ep's real id
                capabilities: vec!["cheers/lan-pair/v1".to_string()],
                code: None,
            };
            let bytes = serde_json::to_vec(&lying_offer).unwrap();
            send.write_all(&bytes).await.expect("send lying offer");
            send.finish().expect("finish send");
            // The accepter rejects before responding — expect the recv side
            // to observe the connection close with no bytes, not a hang.
            let _ = recv.read_to_end(MAX_FRAME).await;
        });

        let strategy = AutoTrust { accept: test_accept() };
        let result = Accepter::new(accepter_ep).pair(addr, &strategy).await;
        assert!(
            matches!(result, Err(LanPairError::NodeIdMismatch)),
            "expected NodeIdMismatch, got {result:?}"
        );

        malicious_offerer.await.expect("offerer task did not panic");
    }

    /// R593-F5 seam-level: a completed pair (real mshr QUIC handshake, real
    /// `Accepter::pair`) invokes the [`EnrollmentSink`] with the pairing
    /// account and the *authenticated* `NodeId` of the paired device; a
    /// re-pair reports the same binding again (server-side idempotency —
    /// "identical live row -> 200, no duplicate" — is R593-F4/F9's job; the
    /// seam's obligation is to faithfully re-report the same identity each
    /// time). The privileged write itself is deferred to R593-F9, so these
    /// exercise a `#[cfg(test)]` [`enroll::test_support::RecordingSink`], not
    /// a network client.
    mod enrollment {
        use std::sync::Arc;

        use super::*;
        use crate::lan_pair::enroll::test_support::RecordingSink;

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn completed_pair_invokes_sink_with_authenticated_node_id_and_pairing_user() {
            let (offerer, accepter, addr) = make_pair().await;
            let offerer_node_id = offerer.node_id();

            let sink = Arc::new(RecordingSink::new());
            let accepter = accepter.with_enrollment_sink(sink.clone());
            let strategy = AutoTrust { accept: test_accept() };

            let (o, a) = tokio::join!(offerer.wait_for_pair(), accepter.pair(addr, &strategy));
            o.expect("offerer completes pair");
            a.expect("accepter completes pair and invokes the enrollment sink");

            let calls = sink.calls();
            assert_eq!(calls.len(), 1, "sink invoked exactly once");
            let (user_id, node_id) = &calls[0];
            // The vouching account, sourced from PairAccept.user_id.
            assert_eq!(user_id, "test-user-001");
            // The QUIC-authenticated identity of the paired (offerer) device
            // — the row's resource_id would be its hex form. This is the
            // load-bearing property: LAN-pair must enroll the *same* NodeId,
            // in the *same* encoding, that F4's fleet admission would.
            assert_eq!(node_id, &offerer_node_id);
            assert_eq!(node_id.to_string(), offerer_node_id.to_string());
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn repairing_same_device_reports_the_same_binding_each_time() {
            let (offerer, accepter, addr) = make_pair().await;
            let offerer_node_id = offerer.node_id();

            let sink = Arc::new(RecordingSink::new());
            let accepter = accepter.with_enrollment_sink(sink.clone());
            let strategy = AutoTrust { accept: test_accept() };

            // Pair the same offerer/accepter endpoints twice — same physical
            // device, same account, mirroring a user re-running LAN-pair
            // against a device it already enrolled.
            let (o1, a1) =
                tokio::join!(offerer.wait_for_pair(), accepter.pair(addr.clone(), &strategy));
            o1.expect("first pair (offerer)");
            a1.expect("first pair (accepter)");

            let (o2, a2) = tokio::join!(offerer.wait_for_pair(), accepter.pair(addr, &strategy));
            o2.expect("second pair (offerer)");
            a2.expect("second pair (accepter)");

            let calls = sink.calls();
            assert_eq!(calls.len(), 2, "one sink invocation per pairing attempt");
            // Both invocations carry the identical (user, node) binding — so
            // the F9 writer downstream sees the same row twice and its
            // idempotent POST /ownership collapses them to one live row. The
            // seam does not (and must not) dedup locally; it just re-reports.
            assert_eq!(calls[0], calls[1]);
            assert_eq!(calls[0].0, "test-user-001");
            assert_eq!(calls[0].1, offerer_node_id);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn sink_error_surfaces_as_enrollment_error_on_the_accepter() {
            let (offerer, accepter, addr) = make_pair().await;

            let sink = Arc::new(RecordingSink::failing());
            let accepter = accepter.with_enrollment_sink(sink.clone());
            let strategy = AutoTrust { accept: test_accept() };

            let (o, a) = tokio::join!(offerer.wait_for_pair(), accepter.pair(addr, &strategy));
            // The offerer side already got its Accept before the sink ran, so
            // it completes; the accepter surfaces the sink failure.
            o.expect("offerer completes pair (Accept sent before enrollment ran)");
            let err = a.expect_err("accepter surfaces the sink failure");
            assert!(matches!(err, LanPairError::Enrollment(_)), "got {err:?}");
            // The sink was still invoked with the right binding before failing.
            assert_eq!(sink.calls().len(), 1);
        }
    }
}
