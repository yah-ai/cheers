//! LAN-pair accepter — the already-authed device side (phone / Mac).

use std::sync::Arc;

use mshr::{Endpoint, EndpointAddr, NodeId};

use crate::lan_pair::enroll::EnrollmentSink;
use crate::lan_pair::{
    AccepterMsg, ConfirmationStrategy, LanPairError, PairAccept, PairOffer, ALPN, MAX_FRAME,
};

/// The accepter is the device that already has user credentials and can vouch
/// for a new device over LAN-pair. Typically a phone or Mac on the same LAN.
///
/// # Lifecycle
///
/// 1. Build an [`mshr::Endpoint`] with [`ALPN`] in its ALPN list.
/// 2. Discover the offerer's [`EndpointAddr`] (via mDNS or out-of-band).
/// 3. Optionally call [`with_enrollment_sink`] so a confirmed pair writes
///    the `principal U owns node:<NodeId>` enrollment row (R593-F5).
/// 4. Call [`pair`] with a [`ConfirmationStrategy`] that matches the desired
///    UX (auto-trust, six-digit code, display-code).
/// 5. On success, the offerer has stored the returned [`PairAccept`] and is
///    now paired as the user.
///
/// [`pair`]: Accepter::pair
/// [`with_enrollment_sink`]: Accepter::with_enrollment_sink
pub struct Accepter {
    endpoint: Endpoint,
    enrollment_sink: Option<Arc<dyn EnrollmentSink>>,
}

impl Accepter {
    /// Create an accepter wrapping the given endpoint.
    ///
    /// The endpoint must have [`ALPN`] registered; iroh uses it for the TLS
    /// ALPN extension and will reject connections on unregistered values.
    pub fn new(endpoint: Endpoint) -> Self {
        Self { endpoint, enrollment_sink: None }
    }

    /// Attach an [`EnrollmentSink`] (R593-F5, W268 §"The binding: enrollment
    /// is an ownership row"). When set, a confirmed pair (see [`pair`])
    /// records `principal <PairAccept::user_id> owns node:<NodeId>` in
    /// cheers's ownership ledger before returning — the NodeId used is the
    /// QUIC-connection-authenticated peer id, not the offerer's
    /// self-reported [`PairOffer::node_id`] copy. Leaving this unset (the
    /// default) skips the write entirely — existing callers that only want
    /// the credential-bootstrap protocol are unaffected.
    ///
    /// [`pair`]: Accepter::pair
    pub fn with_enrollment_sink(mut self, sink: Arc<dyn EnrollmentSink>) -> Self {
        self.enrollment_sink = Some(sink);
        self
    }

    /// This endpoint's mshr node identifier (Ed25519 public key).
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

        // The NodeId that matters for enrollment is the one the QUIC/TLS
        // handshake actually authenticated (`Connection::remote_id`), never
        // the copy the offerer self-reports in `PairOffer.node_id` — that
        // field travels as ordinary JSON payload over an authenticated
        // channel, but nothing stops an offerer from putting a different
        // 32 bytes there. Reject a mismatch outright rather than silently
        // preferring one source (R593-F5 item 4).
        let authenticated_node_id = conn.remote_id();
        if offer.node_id != *authenticated_node_id.as_bytes() {
            return Err(LanPairError::NodeIdMismatch);
        }

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

        // Enrollment write (R593-F5): the pairing is now accepted — both
        // sides completed the QUIC-authenticated handshake and the
        // ConfirmationStrategy said yes. This is the seam W268 §"The
        // binding: enrollment is an ownership row" describes: record
        // `principal <accept.user_id> owns node:<authenticated_node_id>` so
        // the paired device shows up in `U`'s `owns[]` claim.
        //
        // Per W268 §binding ceremonies, an optional `UserDelegation` could
        // also be minted+attached right here (same call site, same
        // `accept.user_id`) so the device may act on U's behalf — not wired
        // in this ticket; see `crate::lan_pair::enroll`'s module doc for why
        // and exactly where it would attach.
        if let (Some(accept), Some(sink)) = (decision.as_ref(), self.enrollment_sink.as_ref()) {
            sink.enroll(&accept.user_id, authenticated_node_id).await?;
        }

        match decision {
            Some(accept) => Ok(accept),
            None => Err(LanPairError::Rejected),
        }
    }
}
