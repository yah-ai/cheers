//! Session JSON response shape returned by `callback` handlers.
//!
//! R018-T4 will refine this with /api/me/sessions list+revoke. For T2 we
//! return the minimal triple a client needs: access_token (the PASETO/HMAC
//! string), refresh_token (the opaque secret), and the user_id the IdP
//! resolved to.

use serde::{Deserialize, Serialize};

#[cfg(any(feature = "google", feature = "apple", feature = "passkey", feature = "email"))]
use cheers_server::NewSession;

/// JSON body returned by every successful login callback.
///
/// `token_type` is `Bearer` so a frontend can drop the header in verbatim:
/// `Authorization: Bearer <access_token>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SessionBody {
    pub access_token: String,
    pub token_type: &'static str,
    /// Absolute unix-seconds expiry, mirroring the `Claims.expires_at` in the
    /// signed access token. Clients can use this without re-verifying the
    /// PASETO to decide when to rotate.
    pub access_expires_at: i64,
    pub refresh_token: String,
    pub refresh_expires_at: i64,
    pub user_id: String,
    pub device_id: String,
    /// `jti` of the access token — useful so a frontend that wants to
    /// preemptively logout can hand it back without re-decoding the token.
    pub jti: String,
}

#[cfg(any(feature = "google", feature = "apple", feature = "passkey", feature = "email"))]
impl SessionBody {
    pub(crate) fn from_new_session(session: NewSession) -> Self {
        let NewSession {
            access_token,
            claims,
            refresh,
            ..
        } = session;
        Self {
            access_token,
            token_type: "Bearer",
            access_expires_at: claims.expires_at,
            refresh_token: refresh.token.into_inner(),
            refresh_expires_at: refresh.record.expires_at,
            user_id: claims.sub.into_inner(),
            device_id: claims.device.into_inner(),
            jti: claims.jti,
        }
    }
}
