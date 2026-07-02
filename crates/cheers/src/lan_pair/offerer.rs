//! LAN-pair offerer — the headless / new-device side.

use mshr::{Endpoint, EndpointAddr, NodeId};

use crate::lan_pair::{AccepterMsg, LanPairError, PairAccept, PairOffer, MAX_FRAME};

/// The offerer is the device that wants to receive credentials over LAN-pair.
/// Typically a headless device (rpi, embedded node) on first boot.
///
/// # Lifecycle
///
/// 1. Build an [`mshr::Endpoint`] with [`ALPN`] in its ALPN list.
/// 2. Optionally call [`with_code`] or [`with_random_code`] and show the
///    code on the device's console so the user can enter it on the phone.
/// 3. Call [`wait_for_pair`] to block until a phone connects and sends
///    credentials.
/// 4. Persist the returned [`PairAccept`] (e.g. via `EncryptedFileStore`).
///
/// [`with_code`]: Offerer::with_code
/// [`with_random_code`]: Offerer::with_random_code
/// [`wait_for_pair`]: Offerer::wait_for_pair
///
/// # @yah:assumes
/// Default UX is "six-digit code on rpi first-boot console output" (design
/// doc §"Open decisions" #4). The display-detection auto-switch alternative
/// has not been decided. Confirm with user before changing the default.
pub struct Offerer {
    endpoint: Endpoint,
    code: Option<String>,
}

impl Offerer {
    /// Create an offerer wrapping the given endpoint.
    ///
    /// The endpoint must have [`ALPN`] registered; iroh rejects connections
    /// on unregistered ALPNs at the TLS layer.
    pub fn new(endpoint: Endpoint) -> Self {
        Self { endpoint, code: None }
    }

    /// Attach a fixed confirmation code. The caller is responsible for
    /// displaying this code on the device's output (console, LED matrix,
    /// e-ink display, …) before calling [`wait_for_pair`].
    ///
    /// [`wait_for_pair`]: Offerer::wait_for_pair
    pub fn with_code(mut self, code: impl Into<String>) -> Self {
        self.code = Some(code.into());
        self
    }

    /// Generate a random 6-digit decimal code and attach it.
    ///
    /// Display [`code`] on the device's console before calling
    /// [`wait_for_pair`] so the user can enter it on the accepter.
    ///
    /// [`code`]: Offerer::code
    /// [`wait_for_pair`]: Offerer::wait_for_pair
    pub fn with_random_code(mut self) -> Result<Self, LanPairError> {
        let mut buf = [0u8; 3];
        getrandom::fill(&mut buf).map_err(|e| LanPairError::Transport(e.to_string()))?;
        let n = ((buf[0] as u32) << 16 | (buf[1] as u32) << 8 | buf[2] as u32) % 1_000_000;
        self.code = Some(format!("{n:06}"));
        Ok(self)
    }

    /// The confirmation code, if one was set.
    pub fn code(&self) -> Option<&str> {
        self.code.as_deref()
    }

    /// This endpoint's mshr node identifier (Ed25519 public key).
    pub fn node_id(&self) -> NodeId {
        self.endpoint.node_id()
    }

    /// Snapshot the current endpoint address (node ID + best-known direct
    /// addrs). Hand this to the accepter for out-of-band rendezvous when
    /// mDNS discovery is unavailable.
    pub fn endpoint_addr(&self) -> EndpointAddr {
        self.endpoint.endpoint_addr()
    }

    /// Block until one incoming pairing attempt completes and return the
    /// accepted credential bundle.
    ///
    /// Accepts the first connection on the endpoint (iroh enforces the
    /// [`ALPN`] at the TLS layer), opens a bidirectional QUIC stream, sends
    /// [`PairOffer`], and returns the [`PairAccept`] from the accepter.
    ///
    /// Returns [`LanPairError::Rejected`] if the accepter's strategy declined.
    pub async fn wait_for_pair(&self) -> Result<PairAccept, LanPairError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or(LanPairError::ConnectionClosed)?;

        let conn = incoming
            .await
            .map_err(|e| LanPairError::Transport(e.to_string()))?;

        let offer = PairOffer {
            node_id: *self.endpoint.node_id().as_bytes(),
            capabilities: vec!["cheers/lan-pair/v1".to_string()],
            code: self.code.clone(),
        };

        // Offerer opens the bidi stream; accepter calls accept_bi().
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| LanPairError::Transport(e.to_string()))?;

        let offer_bytes =
            serde_json::to_vec(&offer).map_err(|e| LanPairError::Codec(e.to_string()))?;
        send.write_all(&offer_bytes)
            .await
            .map_err(|e| LanPairError::Transport(e.to_string()))?;
        // Finishing the send half signals EOF to the accepter's recv.read_to_end().
        send.finish()
            .map_err(|e| LanPairError::Transport(e.to_string()))?;

        let resp_bytes = recv
            .read_to_end(MAX_FRAME)
            .await
            .map_err(|e| LanPairError::Transport(e.to_string()))?;

        let msg: AccepterMsg = serde_json::from_slice(&resp_bytes)
            .map_err(|e| LanPairError::Codec(e.to_string()))?;

        match msg {
            AccepterMsg::Accept(accept) => Ok(accept),
            AccepterMsg::Reject { .. } => Err(LanPairError::Rejected),
        }
    }
}
