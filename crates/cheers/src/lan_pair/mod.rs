//! LAN-pair: credential bootstrap for headless devices over xlb-net.
//!
//! The rpi case: an already-authed device (phone/Mac) vouches for a fresh
//! headless device over the local network, using xlb-net as transport.
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

pub mod accepter;
pub mod confirm;
pub mod offerer;

pub use accepter::Accepter;
pub use confirm::{AutoTrust, ConfirmationStrategy, DisplayCode, SixDigitCode};
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
    /// Raw bytes of the offerer's xlb-net `NodeId` (Ed25519 public key).
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
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use xlb_net::{Endpoint, Keypair};

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

    async fn make_pair() -> (Offerer, Accepter, xlb_net::EndpointAddr) {
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
}
