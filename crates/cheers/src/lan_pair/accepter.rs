//! LAN-pair accepter — the already-authed device side (phone / Mac).

use xlb_net::{Endpoint, EndpointAddr, NodeId};

use crate::lan_pair::{
    AccepterMsg, ConfirmationStrategy, LanPairError, PairAccept, PairOffer, ALPN, MAX_FRAME,
};

/// The accepter is the device that already has user credentials and can vouch
/// for a new device over LAN-pair. Typically a phone or Mac on the same LAN.
///
/// # Lifecycle
///
/// 1. Build an [`xlb_net::Endpoint`] with [`ALPN`] in its ALPN list.
/// 2. Discover the offerer's [`EndpointAddr`] (via mDNS or out-of-band).
/// 3. Call [`pair`] with a [`ConfirmationStrategy`] that matches the desired
///    UX (auto-trust, six-digit code, display-code).
/// 4. On success, the offerer has stored the returned [`PairAccept`] and is
///    now paired as the user.
///
/// [`pair`]: Accepter::pair
pub struct Accepter {
    endpoint: Endpoint,
}

impl Accepter {
    /// Create an accepter wrapping the given endpoint.
    ///
    /// The endpoint must have [`ALPN`] registered; iroh uses it for the TLS
    /// ALPN extension and will reject connections on unregistered values.
    pub fn new(endpoint: Endpoint) -> Self {
        Self { endpoint }
    }

    /// This endpoint's xlb-net node identifier (Ed25519 public key).
    pub fn node_id(&self) -> NodeId {
        self.endpoint.node_id()
    }

    /// Connect to the offerer at `addr` and complete the LAN-pair protocol.
    ///
    /// Steps:
    /// 1. Dial the offerer on the LAN-pair ALPN.
    /// 2. Accept the bidirectional QUIC stream the offerer opens.
    /// 3. Read [`PairOffer`] (offerer's node ID, capabilities, optional code).
    /// 4. Run `strategy.confirm(&offer)`.
    /// 5. Send [`AccepterMsg::Accept`] or [`AccepterMsg::Reject`].
    ///
    /// Returns the [`PairAccept`] that was sent on success, or
    /// [`LanPairError::Rejected`] if the strategy returned `None`.
    pub async fn pair<S, A>(
        &self,
        addr: A,
        strategy: &S,
    ) -> Result<PairAccept, LanPairError>
    where
        S: ConfirmationStrategy,
        A: Into<EndpointAddr>,
    {
        let conn = self
            .endpoint
            .connect_alpn(addr, ALPN)
            .await
            .map_err(|e| LanPairError::Transport(e.to_string()))?;

        // Offerer opens the bidi stream; we accept it here.
        let (mut send, mut recv) = conn
            .accept_bi()
            .await
            .map_err(|e| LanPairError::Transport(e.to_string()))?;

        // Read PairOffer — ends when offerer calls send.finish().
        let offer_bytes = recv
            .read_to_end(MAX_FRAME)
            .await
            .map_err(|e| LanPairError::Transport(e.to_string()))?;

        let offer: PairOffer = serde_json::from_slice(&offer_bytes)
            .map_err(|e| LanPairError::Codec(e.to_string()))?;

        let decision = strategy.confirm(&offer).await?;

        let msg = match decision.as_ref() {
            Some(accept) => AccepterMsg::Accept(accept.clone()),
            None => AccepterMsg::Reject { reason: "declined".into() },
        };

        let resp_bytes =
            serde_json::to_vec(&msg).map_err(|e| LanPairError::Codec(e.to_string()))?;
        send.write_all(&resp_bytes)
            .await
            .map_err(|e| LanPairError::Transport(e.to_string()))?;
        send.finish()
            .map_err(|e| LanPairError::Transport(e.to_string()))?;

        // Wait for the offerer to close the connection (ensures it received
        // the full response before the connection is torn down).
        let _ = conn.closed().await;

        match decision {
            Some(accept) => Ok(accept),
            None => Err(LanPairError::Rejected),
        }
    }
}
