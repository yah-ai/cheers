//! Passkey (WebAuthn) server-side ceremonies — P7.
//!
//! [`PasskeyRelyingParty`] wraps [`webauthn_rs::Webauthn`] and exposes the two
//! ceremonies a relying party runs: registration ([`register`]) and
//! authentication ([`authenticate`]). This is the **server** side only — the
//! per-platform client UI (browser WebAuthn JS, native `AuthenticationServices`
//! on Apple) lands in P9.
//!
//! ## Credential profile: non-discoverable by default
//!
//! cheers ships the **non-discoverable** (server-side) passkey profile:
//! [`start_registration`](PasskeyRelyingParty::start_registration) maps onto
//! `webauthn-rs`'s `start_passkey_registration`, which sets
//! `requireResidentKey = false`. The relying party always knows *which* user
//! is authenticating (it supplies the candidate credential list to the
//! authentication ceremony), so a discoverable/resident credential is not
//! required. This matches the design doc's "discoverable-credential flag,
//! default off." Discoverable (resident-key) registration — where the
//! authenticator stores the user handle and a username-less login becomes
//! possible — is a deliberate future extension; it would route through
//! `webauthn-rs`'s resident-key entry points rather than the `Passkey` profile.
//!
//! ## The ceremony state MUST be stored server-side
//!
//! Both ceremonies are two-step: `start_*` returns a challenge to send to the
//! client **and** an opaque state value ([`PasskeyRegistration`] /
//! `PasskeyAuthentication`) that the server must hold until the client
//! responds, then hand to `finish_*`. That state carries the challenge; losing
//! it to the client (or reusing it) reopens replay attacks. Treat it exactly
//! like the OIDC flow store: server-side, single-use, confidential. The
//! `webauthn-rs` `danger-allow-state-serialisation` feature (enabled here)
//! makes the state serde-encodable so it can live in a session store between
//! the two HTTP requests.
//!
//! ## User handles are `Uuid`, not [`UserId`](cheers_core::UserId)
//!
//! WebAuthn user handles are opaque ≤64-byte identifiers that must be stable
//! per user and must not be PII. `webauthn-rs` models them as [`Uuid`]. cheers
//! keeps its own [`UserId`](cheers_core::UserId) (an arbitrary string), so the
//! product is responsible for the `UserId` ↔ `Uuid` mapping (store the pair, or
//! derive a stable v5 UUID). The ceremony API takes the `Uuid` handle directly.
//!
//! ## Persisting the result
//!
//! [`finish_registration`](PasskeyRelyingParty::finish_registration) returns a
//! [`Passkey`] — the credential ID + public key + signature counter. Persist it
//! against the user's account (one user may hold many passkeys: phone, laptop,
//! security key). [`passkey_to_credential`] / [`passkey_from_credential`] bridge
//! a [`Passkey`] to and from a [`cheers_core::Credential`] (binding
//! [`DeviceBinding::Passkey`](cheers_core::DeviceBinding::Passkey)) so it drops
//! straight into a `CredentialStore` (P8) or a product's own table (P12).
//!
//! On the authentication side, [`apply_authentication_result`] folds a finished
//! ceremony's [`AuthenticationResult`] back into the answering passkey (counter
//! / backup-flag update) and tells the caller whether to re-persist it.
//!
//! ## License
//!
//! `webauthn-rs` and its dependencies are MPL-2.0 (allowed in `deny.toml`). Its
//! `webauthn-rs-core` → `webauthn-attestation-ca` chain pulls `openssl` for
//! COSE-key + X.509 attestation crypto; this is the only place in cheers that
//! reaches openssl, and only under the `passkey` feature (see `deny.toml`).

mod authenticate;
mod register;

pub use authenticate::{apply_authentication_result, PasskeyUpdate};
pub use register::{passkey_from_credential, passkey_to_credential};

use std::time::Duration;

use webauthn_rs::prelude::{Webauthn, WebauthnBuilder, WebauthnError};

// Re-export the WebAuthn protocol types a consumer needs to run the ceremonies,
// so products depending on `cheers` (feature `passkey`) don't also have to take
// a direct `webauthn-rs` dependency just to name them.
pub use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, CredentialID, Passkey, PasskeyAuthentication,
    PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse,
    Url, Uuid,
};

/// Errors surfaced by [`PasskeyRelyingParty`] and the credential bridge.
///
/// The two `webauthn-rs`-backed variants ([`Config`](PasskeyError::Config),
/// [`Ceremony`](PasskeyError::Ceremony)) keep the underlying [`WebauthnError`]
/// as their source so the full failure chain survives into logs/`tracing`;
/// callers that only need coarse handling can match the variant (a bad
/// configuration is a deploy-time bug; a ceremony failure is a client retry).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PasskeyError {
    /// The relying-party configuration is invalid — bad RP id/origin pairing,
    /// a non-https origin, etc. A deploy-time bug, not a per-request failure.
    #[error("invalid passkey relying-party configuration: {0}")]
    Config(#[source] WebauthnError),

    /// A registration or authentication ceremony failed verification — bad
    /// challenge, signature, origin mismatch, excluded credential, and so on.
    /// The client may retry from a fresh `start_*`.
    #[error("passkey ceremony failed: {0}")]
    Ceremony(#[source] WebauthnError),

    /// Serialising a [`Passkey`] into [`Credential::material`](cheers_core::Credential::material).
    #[error("serialising passkey credential: {0}")]
    Serialize(#[source] serde_json::Error),

    /// Deserialising a [`Passkey`] out of a stored credential blob.
    #[error("deserialising passkey credential: {0}")]
    Deserialize(#[source] serde_json::Error),

    /// A stored [`Credential`](cheers_core::Credential) was handed to
    /// [`passkey_from_credential`] but its binding is not
    /// [`DeviceBinding::Passkey`](cheers_core::DeviceBinding::Passkey).
    #[error("stored credential is not a passkey binding (found {found:?})")]
    WrongBinding {
        found: cheers_core::DeviceBinding,
    },
}

/// Server-side WebAuthn relying party — the entry point for passkey
/// registration and authentication.
///
/// Construct one per relying party (one per origin, typically one per binary)
/// and share it; it holds no per-ceremony state. Build via [`new`](Self::new)
/// for the common case or [`builder`](Self::builder) to tune `rp_name`,
/// subdomain handling, extra origins, or the challenge timeout.
pub struct PasskeyRelyingParty {
    webauthn: Webauthn,
    rp_id: String,
    rp_origin: Url,
    rp_name: Option<String>,
    extra_origins: Vec<Url>,
    allow_subdomains: bool,
}

impl PasskeyRelyingParty {
    /// Build a relying party for `rp_id` (the effective domain, e.g.
    /// `"example.com"`) anchored at `rp_origin` (the page origin, e.g.
    /// `https://auth.example.com`). The origin's host must be `rp_id` or a
    /// subdomain of it; see [`builder`](Self::builder) for subdomain/extra-origin
    /// control.
    ///
    /// Returns [`PasskeyError::Config`] if `webauthn-rs` rejects the pairing.
    pub fn new(rp_id: impl Into<String>, rp_origin: Url) -> Result<Self, PasskeyError> {
        Self::builder(rp_id, rp_origin).build()
    }

    /// Start configuring a relying party. Finish with
    /// [`build`](PasskeyRelyingPartyBuilder::build).
    pub fn builder(rp_id: impl Into<String>, rp_origin: Url) -> PasskeyRelyingPartyBuilder {
        PasskeyRelyingPartyBuilder {
            rp_id: rp_id.into(),
            rp_origin,
            rp_name: None,
            extra_origins: Vec::new(),
            allow_subdomains: false,
            timeout: None,
        }
    }

    /// The relying-party id (effective domain) this RP verifies against.
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    /// The primary page origin this RP was anchored at.
    pub fn rp_origin(&self) -> &Url {
        &self.rp_origin
    }

    /// The human-facing RP name shown by some authenticators, if set.
    pub fn rp_name(&self) -> Option<&str> {
        self.rp_name.as_deref()
    }

    /// Every origin this RP accepts ceremony responses from (primary first).
    pub fn allowed_origins(&self) -> &[Url] {
        self.webauthn.get_allowed_origins()
    }

    /// Borrow the wrapped [`Webauthn`] for advanced flows not yet surfaced by
    /// cheers (e.g. discoverable-credential authentication).
    pub fn webauthn(&self) -> &Webauthn {
        &self.webauthn
    }
}

impl std::fmt::Debug for PasskeyRelyingParty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyRelyingParty")
            .field("rp_id", &self.rp_id)
            .field("rp_origin", &self.rp_origin.as_str())
            .field("rp_name", &self.rp_name)
            .field("allow_subdomains", &self.allow_subdomains)
            .field("extra_origins", &self.extra_origins.len())
            .finish_non_exhaustive()
    }
}

/// Builder for [`PasskeyRelyingParty`]. See [`PasskeyRelyingParty::builder`].
#[derive(Debug, Clone)]
pub struct PasskeyRelyingPartyBuilder {
    rp_id: String,
    rp_origin: Url,
    rp_name: Option<String>,
    extra_origins: Vec<Url>,
    allow_subdomains: bool,
    timeout: Option<Duration>,
}

impl PasskeyRelyingPartyBuilder {
    /// Set the human-facing relying-party name some authenticators display.
    pub fn rp_name(mut self, rp_name: impl Into<String>) -> Self {
        self.rp_name = Some(rp_name.into());
        self
    }

    /// Allow ceremony origins on subdomains of `rp_id` (default `false`).
    pub fn allow_subdomains(mut self, allow: bool) -> Self {
        self.allow_subdomains = allow;
        self
    }

    /// Accept an additional page origin (e.g. a second front-end host). The
    /// primary `rp_origin` is always allowed; this appends others.
    pub fn append_allowed_origin(mut self, origin: Url) -> Self {
        self.extra_origins.push(origin);
        self
    }

    /// Override the challenge timeout sent to authenticators.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Finalise the relying party. Returns [`PasskeyError::Config`] if
    /// `webauthn-rs` rejects the configuration.
    pub fn build(self) -> Result<PasskeyRelyingParty, PasskeyError> {
        let mut builder = WebauthnBuilder::new(&self.rp_id, &self.rp_origin)
            .map_err(PasskeyError::Config)?
            .allow_subdomains(self.allow_subdomains);
        if let Some(rp_name) = self.rp_name.as_deref() {
            builder = builder.rp_name(rp_name);
        }
        for origin in &self.extra_origins {
            builder = builder.append_allowed_origin(origin);
        }
        if let Some(timeout) = self.timeout {
            builder = builder.timeout(timeout);
        }
        let webauthn = builder.build().map_err(PasskeyError::Config)?;
        Ok(PasskeyRelyingParty {
            webauthn,
            rp_id: self.rp_id,
            rp_origin: self.rp_origin,
            rp_name: self.rp_name,
            extra_origins: self.extra_origins,
            allow_subdomains: self.allow_subdomains,
        })
    }
}
