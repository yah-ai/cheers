//! Route-level errors. Each handler converts a typed `RouteError` into a
//! JSON response with a stable code so a frontend can switch on it without
//! string-matching messages.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use cheers_core::Scope;
use cheers_server::{
    AuditValidationError, CampAuthorityError, OwnershipValidationError, ServicePrincipalError,
};
use serde::Serialize;

/// What can go wrong inside a cheers-axum route handler.
///
/// Each variant maps to a stable JSON body + HTTP status — see
/// [`RouteError::status_and_code`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RouteError {
    /// No CSRF cookie on the callback request.
    #[error("missing csrf cookie")]
    MissingCsrfCookie,

    /// CSRF cookie present but its value doesn't match the `?state=` param.
    /// Either a CSRF attempt or a cross-tab race.
    #[error("csrf cookie / state mismatch")]
    CsrfStateMismatch,

    /// The OIDC flow keyed on `?state=` was never stashed (or already
    /// consumed). Most likely a replay of an old callback URL.
    #[error("unknown or already-consumed flow")]
    UnknownFlow,

    /// The OIDC flow stored at `begin()` exceeded its TTL before the
    /// callback arrived.
    #[error("flow expired")]
    FlowExpired,

    /// The IdP signaled an error in the callback (`error=access_denied`, …).
    #[error("provider error: {0}")]
    Provider(String),

    /// `id_token` verification failed (signature, audience, nonce, expiry).
    #[error("id_token verification failed: {0}")]
    IdToken(String),

    /// Network / HTTP failure talking to the IdP's token endpoint.
    #[error("upstream http: {0}")]
    Upstream(String),

    /// Backend store failure — UserStore, RefreshStore, or RevocationWriter
    /// returned an error.
    #[error("store: {0}")]
    Store(String),

    /// Catch-all for misconfiguration the handler can't continue past
    /// (missing token endpoint, wrong client_secret shape, …).
    #[error("config: {0}")]
    Config(String),

    /// Apple's form-post body was missing a required field.
    #[error("malformed callback body: {0}")]
    MalformedCallback(String),

    /// A passkey registration/authentication ceremony failed — bad challenge,
    /// signature, origin, or excluded credential. The client may retry from a
    /// fresh `start_*`.
    #[error("ceremony failed: {0}")]
    Ceremony(String),

    /// No stored passkey matched the asserted credential id — either the user
    /// has no registered passkeys or the assertion came from a credential they
    /// do not own. The login must be rejected.
    #[error("unknown credential")]
    UnknownCredential,

    /// Magic-link token replayed after consumption.
    #[error("token already used")]
    AlreadyUsed,

    /// Magic-link request received a malformed email address.
    #[error("invalid email")]
    InvalidEmail,

    /// Magic-link token decoded but its `purpose` claim was unexpected — a
    /// session token presented to a magic-link verify slot, or vice versa.
    #[error("wrong token purpose: {0}")]
    WrongPurpose(String),

    /// Magic-link token failed PASETO decryption / signature / expiry checks.
    #[error("magic-link token invalid: {0}")]
    MagicLinkToken(String),

    /// Mailer rejected the message (bad address shape, body encoding, …) —
    /// typically a deploy-time bug.
    #[error("mailer build: {0}")]
    MailerBuild(String),

    /// Mailer transport failed (SMTP error, network error, auth refused) —
    /// may be transient; retry policy is the caller's choice.
    #[error("mailer transport: {0}")]
    MailerTransport(String),

    /// `Authorization` header absent on a route that needs a bearer token.
    #[error("missing bearer token")]
    MissingBearer,

    /// `Authorization` header present but not in `Bearer <token>` form (wrong
    /// scheme, non-ASCII bytes, empty token).
    #[error("malformed bearer token")]
    MalformedBearer,

    /// Bearer token failed verification at the edge — bad signature, expired,
    /// or revoked. Collapsed into one variant on purpose: leaking which of the
    /// three a token tripped is a small but real oracle.
    #[error("unauthorized")]
    Unauthorized,

    /// `DELETE /me/sessions/{device_id}` targeted a device the user does not
    /// own. 404 so a probe can't enumerate other users' device ids.
    #[error("unknown device")]
    UnknownDevice,

    /// An MCP-call token authenticated but lacks a scope the handler requires
    /// (e.g. `ownership:write` on `POST /ownership`). 403 — the principal is
    /// known, the request is just not authorized.
    #[error("insufficient scope: required '{required}'")]
    InsufficientScope { required: Scope },

    /// `POST /ownership` body parsed as JSON but violated a NewOwnership
    /// invariant (e.g. `on_behalf_of` named a non-user principal). 400 —
    /// distinct from 401/403 so a caller can tell auth failure from a
    /// well-formed-but-invalid row.
    #[error("ownership_invalid: {0}")]
    OwnershipInvalid(#[from] OwnershipValidationError),

    /// `DELETE /ownership/{id}` targeted an id no [`OwnershipStore`] row
    /// matches. 404 — the absence is reported, not the cause.
    ///
    /// [`OwnershipStore`]: cheers_server::OwnershipStore
    #[error("unknown ownership")]
    UnknownOwnership,

    /// `POST /audit/ingest` body parsed as JSON but a record violated an
    /// [`AuditRecord`] invariant (e.g. empty `aud`, non-positive `at`). 400
    /// — distinct from 401/403 so kamaji can tell auth failure from a
    /// well-formed-but-invalid batch (do not retry as-is).
    ///
    /// [`AuditRecord`]: cheers_server::AuditRecord
    #[error("audit_invalid: {0}")]
    AuditInvalid(#[from] AuditValidationError),

    /// `POST /admin/service-principals` collided with an existing principal
    /// id. 409 — same shape as a database unique-key conflict.
    #[error("already exists: {0}")]
    AlreadyExists(String),

    /// `POST /admin/service-principals/{id}/rotate` (or similar) named a
    /// principal cheers doesn't know. 404.
    #[error("unknown principal: {0}")]
    UnknownPrincipal(String),

    /// An authenticated session bearer reached an admin endpoint, but the
    /// authenticated user is not on the product's operator list. 403 — the
    /// caller proved who they are, they're just not authorized for this
    /// surface. Distinct from [`InsufficientScope`](Self::InsufficientScope)
    /// (which is the MCP/scope equivalent) so admin endpoints can stay
    /// scope-free without conflating the two.
    #[error("not an operator")]
    NotOperator,

    /// `POST /admin/camps/bootstrap` rejected a user-signed delegation for
    /// reasons distinct from auth failure: the delegation's `bound_to` /
    /// `camp_id` did not match the provision request, it had already
    /// expired (`expires_at <= now`), or it failed an invariant. 400 —
    /// well-formed-but-invalid input, callable to fix without re-auth.
    #[error("invalid delegation: {0}")]
    InvalidDelegation(String),
}

impl RouteError {
    /// HTTP status + stable error code for this variant.
    pub fn status_and_code(&self) -> (StatusCode, &'static str) {
        match self {
            RouteError::MissingCsrfCookie => (StatusCode::BAD_REQUEST, "missing_csrf_cookie"),
            RouteError::CsrfStateMismatch => (StatusCode::BAD_REQUEST, "csrf_state_mismatch"),
            RouteError::UnknownFlow => (StatusCode::BAD_REQUEST, "unknown_flow"),
            RouteError::FlowExpired => (StatusCode::BAD_REQUEST, "flow_expired"),
            RouteError::Provider(_) => (StatusCode::BAD_REQUEST, "provider_error"),
            RouteError::IdToken(_) => (StatusCode::UNAUTHORIZED, "id_token_invalid"),
            RouteError::Upstream(_) => (StatusCode::BAD_GATEWAY, "upstream_error"),
            RouteError::Store(_) => (StatusCode::INTERNAL_SERVER_ERROR, "store_error"),
            RouteError::Config(_) => (StatusCode::INTERNAL_SERVER_ERROR, "config_error"),
            RouteError::MalformedCallback(_) => {
                (StatusCode::BAD_REQUEST, "malformed_callback")
            }
            RouteError::Ceremony(_) => (StatusCode::BAD_REQUEST, "ceremony_failed"),
            RouteError::UnknownCredential => (StatusCode::UNAUTHORIZED, "unknown_credential"),
            RouteError::AlreadyUsed => (StatusCode::BAD_REQUEST, "already_used"),
            RouteError::InvalidEmail => (StatusCode::BAD_REQUEST, "invalid_email"),
            RouteError::WrongPurpose(_) => (StatusCode::BAD_REQUEST, "wrong_purpose"),
            RouteError::MagicLinkToken(_) => (StatusCode::BAD_REQUEST, "magic_link_token"),
            RouteError::MailerBuild(_) => (StatusCode::INTERNAL_SERVER_ERROR, "mailer_build"),
            RouteError::MailerTransport(_) => (StatusCode::BAD_GATEWAY, "mailer_transport"),
            RouteError::MissingBearer => (StatusCode::UNAUTHORIZED, "missing_bearer"),
            RouteError::MalformedBearer => (StatusCode::UNAUTHORIZED, "malformed_bearer"),
            RouteError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            RouteError::UnknownDevice => (StatusCode::NOT_FOUND, "unknown_device"),
            RouteError::InsufficientScope { .. } => {
                (StatusCode::FORBIDDEN, "insufficient_scope")
            }
            RouteError::OwnershipInvalid(_) => (StatusCode::BAD_REQUEST, "ownership_invalid"),
            RouteError::UnknownOwnership => (StatusCode::NOT_FOUND, "unknown_ownership"),
            RouteError::AuditInvalid(_) => (StatusCode::BAD_REQUEST, "audit_invalid"),
            RouteError::AlreadyExists(_) => (StatusCode::CONFLICT, "already_exists"),
            RouteError::UnknownPrincipal(_) => (StatusCode::NOT_FOUND, "unknown_principal"),
            RouteError::NotOperator => (StatusCode::FORBIDDEN, "not_operator"),
            RouteError::InvalidDelegation(_) => (StatusCode::BAD_REQUEST, "invalid_delegation"),
        }
    }
}

#[derive(Serialize)]
struct RouteErrorBody<'a> {
    error: &'a str,
    message: String,
}

impl IntoResponse for RouteError {
    fn into_response(self) -> Response {
        let (status, code) = self.status_and_code();
        // The Display impl is already redaction-safe (Provider/IdToken/Upstream
        // text comes from upstreams we trust to not echo secrets). We DO NOT
        // include the source chain — that can leak internal hostnames.
        let body = RouteErrorBody {
            error: code,
            message: self.to_string(),
        };
        tracing::warn!(error = code, message = %self, "cheers-axum route error");
        (status, Json(body)).into_response()
    }
}

impl From<cheers_core::StoreError> for RouteError {
    fn from(value: cheers_core::StoreError) -> Self {
        RouteError::Store(value.to_string())
    }
}

impl From<cheers_core::Error> for RouteError {
    fn from(value: cheers_core::Error) -> Self {
        // cheers_core::Error covers codec / store / input — any of those
        // surfacing in a handler is an integration bug, not a user problem.
        RouteError::Store(value.to_string())
    }
}

impl From<CampAuthorityError> for RouteError {
    fn from(value: CampAuthorityError) -> Self {
        // Three client-distinguishable outcomes:
        // - AlreadyExists (the camp id is taken)            → 409
        // - InvalidDelegation/Mismatch/Expired              → 400
        // - UntrustedSigningKey/BadSignature                → 401
        // Everything else (WrongPrincipalKind, Principal, Store) is a
        // programmer / integration bug at this surface and collapses to 500
        // through `Store(...)` — same shape as ServicePrincipalError below.
        match value {
            CampAuthorityError::AlreadyExists(id) => RouteError::AlreadyExists(id.to_string()),
            CampAuthorityError::InvalidDelegation(e) => RouteError::InvalidDelegation(e.to_string()),
            CampAuthorityError::DelegationMismatch(msg) => {
                RouteError::InvalidDelegation(msg.to_owned())
            }
            CampAuthorityError::DelegationExpired => {
                RouteError::InvalidDelegation("delegation expired".into())
            }
            CampAuthorityError::UntrustedSigningKey(_)
            | CampAuthorityError::BadSignature => RouteError::Unauthorized,
            CampAuthorityError::Store(e) => RouteError::Store(e.to_string()),
            other => RouteError::Store(other.to_string()),
        }
    }
}

impl From<ServicePrincipalError> for RouteError {
    fn from(value: ServicePrincipalError) -> Self {
        // AlreadyExists / UnknownPrincipal are the only client-distinguishable
        // outcomes — everything else (wrong-kind, no-active-key, codec failure,
        // unexpected store error) is a programmer/integration bug at this
        // surface and collapses to 500.
        match value {
            ServicePrincipalError::AlreadyExists(id) => RouteError::AlreadyExists(id.to_string()),
            ServicePrincipalError::UnknownPrincipal(id) => {
                RouteError::UnknownPrincipal(id.to_string())
            }
            ServicePrincipalError::Store(e) => RouteError::Store(e.to_string()),
            other => RouteError::Store(other.to_string()),
        }
    }
}

#[cfg(any(feature = "google", feature = "apple"))]
impl From<cheers::providers::oidc_generic::OidcError> for RouteError {
    fn from(value: cheers::providers::oidc_generic::OidcError) -> Self {
        use cheers::providers::oidc_generic::OidcError;
        match value {
            OidcError::UnknownFlow => RouteError::UnknownFlow,
            OidcError::FlowExpired => RouteError::FlowExpired,
            OidcError::StateMismatch => RouteError::CsrfStateMismatch,
            OidcError::Http(msg) => RouteError::Upstream(msg),
            OidcError::IdToken(msg) => RouteError::IdToken(msg),
            OidcError::MissingIdToken => RouteError::IdToken("missing id_token".into()),
            OidcError::Discovery(msg) | OidcError::Config(msg) => RouteError::Config(msg),
            OidcError::Store(msg) => RouteError::Store(msg),
            // OidcError is #[non_exhaustive]; new variants land in this catchall
            // as Config until the bridge gets a dedicated mapping.
            other => RouteError::Config(other.to_string()),
        }
    }
}

#[cfg(feature = "passkey")]
impl From<cheers::passkey::PasskeyError> for RouteError {
    fn from(value: cheers::passkey::PasskeyError) -> Self {
        use cheers::passkey::PasskeyError;
        match value {
            PasskeyError::Config(e) => RouteError::Config(e.to_string()),
            PasskeyError::Ceremony(e) => RouteError::Ceremony(e.to_string()),
            // Serialize/Deserialize/WrongBinding surface only when stored
            // credentials disagree with the live code path — a store-side bug,
            // not a client-side one.
            PasskeyError::Serialize(e) => RouteError::Store(format!("passkey serialize: {e}")),
            PasskeyError::Deserialize(e) => {
                RouteError::Store(format!("passkey deserialize: {e}"))
            }
            PasskeyError::WrongBinding { found } => {
                RouteError::Store(format!("stored credential binding {found:?} is not passkey"))
            }
            other => RouteError::Config(other.to_string()),
        }
    }
}

#[cfg(feature = "email")]
impl From<cheers::email::magic_link::MagicLinkError> for RouteError {
    fn from(value: cheers::email::magic_link::MagicLinkError) -> Self {
        use cheers::email::magic_link::MagicLinkError;
        match value {
            MagicLinkError::Codec(e) => RouteError::MagicLinkToken(e.to_string()),
            MagicLinkError::WrongPurpose { got } => RouteError::WrongPurpose(got),
            MagicLinkError::AlreadyUsed => RouteError::AlreadyUsed,
            MagicLinkError::InvalidEmail => RouteError::InvalidEmail,
            MagicLinkError::Store(msg) => RouteError::Store(msg),
            other => RouteError::Config(other.to_string()),
        }
    }
}

#[cfg(feature = "email")]
impl From<cheers::email::MailerError> for RouteError {
    fn from(value: cheers::email::MailerError) -> Self {
        use cheers::email::MailerError;
        match value {
            MailerError::Build(msg) => RouteError::MailerBuild(msg),
            MailerError::Transport(msg) => RouteError::MailerTransport(msg),
            other => RouteError::MailerTransport(other.to_string()),
        }
    }
}

#[cfg(feature = "apple")]
impl From<cheers::providers::apple::AppleRedirectError> for RouteError {
    fn from(value: cheers::providers::apple::AppleRedirectError) -> Self {
        use cheers::providers::apple::AppleRedirectError;
        match value {
            AppleRedirectError::Oidc(e) => e.into(),
            AppleRedirectError::MissingFormField(f) => {
                RouteError::MalformedCallback(format!("missing field `{f}`"))
            }
            AppleRedirectError::Provider(msg) => RouteError::Provider(msg),
            AppleRedirectError::ClientSecret(e) => RouteError::Config(e.to_string()),
            // Same reason as the OidcError catchall: AppleRedirectError is
            // #[non_exhaustive], so we tolerate new variants surfacing as
            // Config until a dedicated mapping lands.
            other => RouteError::Config(other.to_string()),
        }
    }
}
