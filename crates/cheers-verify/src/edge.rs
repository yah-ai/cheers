//! The [`EdgeVerifier`] facade — what a CF Worker holds.

use cheers_core::{Claims, Error, PeerKey, TokenVerifier};

use crate::revocation::RevocationReader;

/// Edge facade: verify a token, then check it hasn't been revoked.
///
/// Holds a [`TokenVerifier`] and a [`RevocationReader`] — and nothing else.
/// There is **no `TokenMinter` in this type**, so an edge built on it cannot
/// forge sessions even if compromised; that absence is the whole point of the
/// asymmetric codec split. Generic (not `dyn`) so the "no minter" property is a
/// fact about the type, not a runtime convention. Pair a
/// [`PasetoV4PublicVerifier`](crate::PasetoV4PublicVerifier) with a CF-KV-backed
/// `RevocationReader`.
pub struct EdgeVerifier<V, Rd> {
    verifier: V,
    revoked: Rd,
}

impl<V, Rd> EdgeVerifier<V, Rd>
where
    V: TokenVerifier + Send + Sync,
    Rd: RevocationReader,
{
    pub fn new(verifier: V, revoked: Rd) -> Self {
        Self { verifier, revoked }
    }

    /// Verify `token` against `now`, then reject it if its `jti` is revoked.
    ///
    /// Two stages, cheapest first: cryptographic verification (stateless, local
    /// to the edge) gates the revocation read, so a forged or expired token
    /// never reaches the revocation set. A token that verifies but whose `jti`
    /// is revoked returns [`Error::Revoked`].
    pub async fn verify_at(&self, token: &str, now: i64) -> Result<Claims, Error> {
        let claims = self.verifier.verify_at(token, now)?;
        if self.revoked.is_revoked(&claims.jti).await? {
            return Err(Error::Revoked);
        }
        Ok(claims)
    }

    /// [`verify_at`](Self::verify_at), plus: the token must be bound to
    /// `presented` — the long-lived public key the *connecting peer* already
    /// proved possession of in the transport handshake (R515).
    ///
    /// This is what turns a bearer token into a proof that **token holder ==
    /// connecting peer**. Without it a stolen token replays under the thief's
    /// own node key and they become the victim user; with it the stolen token
    /// names a key the thief cannot present, and this returns
    /// [`Error::PeerKeyMismatch`].
    ///
    /// Three stages, cheapest and most local first: signature (stateless),
    /// binding (a byte compare, still local), then the revocation read (the
    /// only I/O). An **unbound** token is rejected here too — it asserts
    /// nothing about any node key, so it cannot satisfy a binding check. A
    /// deployment that also admits unbound tokens must call
    /// [`verify_at`](Self::verify_at) and branch on
    /// [`Claims::peer_key`](cheers_core::Claims::peer_key) itself, so that
    /// choice is visible at the call site.
    ///
    /// The caller supplies `presented` from its own transport — cheers has no
    /// view of the connection and never infers the peer key from the token.
    pub async fn verify_bound_at(
        &self,
        token: &str,
        presented: &PeerKey,
        now: i64,
    ) -> Result<Claims, Error> {
        let claims = self.verifier.verify_at(token, now)?;
        if !claims.is_bound_to(presented) {
            return Err(Error::PeerKeyMismatch);
        }
        if self.revoked.is_revoked(&claims.jti).await? {
            return Err(Error::Revoked);
        }
        Ok(claims)
    }
}
