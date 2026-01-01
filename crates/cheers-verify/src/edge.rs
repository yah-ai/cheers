//! The [`EdgeVerifier`] facade — what a CF Worker holds.

use cheers_core::{Claims, Error, TokenVerifier};

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
}
