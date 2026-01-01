//! Accepter-side confirmation strategies for the LAN-pair protocol.

use async_trait::async_trait;

use crate::lan_pair::{LanPairError, PairAccept, PairOffer};

/// Accepter-side hook for deciding whether to accept a pairing request.
///
/// Implementations may block for user input (e.g. displaying a dialog,
/// reading from a TTY, waiting for a button press). If the callback is
/// blocking, run it inside `tokio::task::spawn_blocking` so the runtime
/// thread is not held.
#[async_trait]
pub trait ConfirmationStrategy: Send + Sync {
    /// Evaluate the incoming [`PairOffer`].
    ///
    /// Return `Some(accept)` to proceed with pairing, or `None` to reject.
    async fn confirm(&self, offer: &PairOffer) -> Result<Option<PairAccept>, LanPairError>;
}

/// Auto-trust: always accept without user interaction.
///
/// Appropriate for LAN-trusted environments where the user has opted in to
/// automatic pairing (e.g. an isolated IoT VLAN where all hosts are trusted).
///
/// # Security
/// No user verification is performed. Any device on the LAN that connects
/// to the accepter's endpoint will receive credentials. Only use when the
/// network boundary is the trust boundary.
pub struct AutoTrust {
    /// Credential bundle to send to the offerer on acceptance.
    pub accept: PairAccept,
}

#[async_trait]
impl ConfirmationStrategy for AutoTrust {
    async fn confirm(&self, _offer: &PairOffer) -> Result<Option<PairAccept>, LanPairError> {
        Ok(Some(self.accept.clone()))
    }
}

/// Six-digit code: the offerer displays a code on its console; the user
/// reads it and enters it on the accepter to confirm physical presence.
///
/// The code travels in [`PairOffer::code`] over the already-authenticated
/// QUIC channel. Security relies on:
/// 1. QUIC transport authentication (Ed25519 — only the real offerer sends).
/// 2. Physical presence — the user must see the code on the target device.
///
/// Configure the offerer with [`Offerer::with_code`] or
/// [`Offerer::with_random_code`] to generate and display the code.
pub struct SixDigitCode {
    /// Credential bundle to send to the offerer on a successful code match.
    pub accept: PairAccept,
    /// Callback that prompts the user for the code shown on the offerer's
    /// console. Receives the full [`PairOffer`] so the prompt can display
    /// the offerer's `node_id` (hex-encoded) as extra context. Returns the
    /// string the user entered; leading/trailing whitespace is stripped before
    /// comparison.
    pub prompt: Box<dyn Fn(&PairOffer) -> String + Send + Sync>,
}

#[async_trait]
impl ConfirmationStrategy for SixDigitCode {
    async fn confirm(&self, offer: &PairOffer) -> Result<Option<PairAccept>, LanPairError> {
        let expected = offer
            .code
            .as_deref()
            .ok_or_else(|| LanPairError::Codec("PairOffer missing code for SixDigitCode strategy".into()))?;
        let entered = (self.prompt)(offer);
        if entered.trim() == expected.trim() {
            Ok(Some(self.accept.clone()))
        } else {
            Ok(None)
        }
    }
}

/// Display-code: both devices show the same code; the user visually confirms
/// they match before the accepter sends credentials.
///
/// The code is sent in [`PairOffer::code`] (over the secure QUIC channel).
/// The accepter shows it alongside the offerer's identity, and the user
/// confirms the code matches what they see on the offerer's screen.
///
/// Configure the offerer with [`Offerer::with_code`] or
/// [`Offerer::with_random_code`].
pub struct DisplayCode {
    /// Credential bundle to send on a successful visual confirmation.
    pub accept: PairAccept,
    /// Callback that shows the code to the user. Receives the full
    /// [`PairOffer`] and the code string (same as `offer.code.as_deref()`
    /// for convenience). Returns `true` to accept, `false` to cancel.
    pub display: Box<dyn Fn(&PairOffer, &str) -> bool + Send + Sync>,
}

#[async_trait]
impl ConfirmationStrategy for DisplayCode {
    async fn confirm(&self, offer: &PairOffer) -> Result<Option<PairAccept>, LanPairError> {
        let code = offer.code.as_deref().unwrap_or("");
        if (self.display)(offer, code) {
            Ok(Some(self.accept.clone()))
        } else {
            Ok(None)
        }
    }
}
