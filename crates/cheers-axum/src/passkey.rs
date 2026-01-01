//! Passkey routes — registration + authentication ceremonies.
//!
//! Each ceremony is a two-request flow: the client POSTs `start` with the
//! user identity, the server stashes the `PasskeyRegistration` /
//! `PasskeyAuthentication` state server-side keyed on a fresh `flow_id`, and
//! returns the WebAuthn challenge to send to the authenticator. The client
//! posts the authenticator's response back to `finish` with the same
//! `flow_id`. The server reclaims the state, verifies the response, and (on
//! success) mints a session.
//!
//! ## Why a flow store instead of a cookie
//!
//! The two cheers-axum OIDC modules bind state to a CSRF cookie because the
//! flow is *browser-driven*: the user is sent off-site to the IdP, returns
//! via a cross-site GET/POST, and the cookie is the only thing the browser
//! preserves. Passkey ceremonies never leave the relying party's origin —
//! WebAuthn's challenge is itself the CSRF binding (the authenticator signs
//! the origin into the assertion). A client-supplied `flow_id` in the body
//! is enough; we keep it explicit so a non-browser client (a native iOS app
//! posting JSON over `URLSession`) doesn't have to wrangle cookies.
//!
//! ## Persist the result, then mint a session
//!
//! `finish_registration` lands a fresh [`Passkey`] into
//! [`PasskeyCredentialStore`] via [`passkey_to_credential`], then establishes
//! a session through the [`SessionAuthority`] with
//! [`DeviceBinding::Passkey`]. The same shape on `finish_authentication`:
//! verify, fold any counter advance back into the stored credential via
//! [`apply_authentication_result`], then mint.
//!
//! ## Wiring
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use axum::Router;
//! # use cheers::passkey::{PasskeyRelyingParty, Url};
//! # use cheers_axum::passkey::{router, MemoryPasskeyFlowStore, PasskeyAuthState};
//! # use cheers_server::{PasskeyCredentialStore, SessionAuthority};
//! # async fn run<M, R, U, W, P>(
//! #     rp: Arc<PasskeyRelyingParty>,
//! #     authority: Arc<SessionAuthority<M, R, U, W>>,
//! #     credentials: Arc<P>,
//! # ) -> Result<(), Box<dyn std::error::Error>>
//! # where
//! #     M: cheers_core::TokenMinter + Send + Sync + 'static,
//! #     R: cheers_server::RefreshStore + 'static,
//! #     U: cheers_server::UserStore + 'static,
//! #     W: cheers_server::RevocationWriter + 'static,
//! #     P: PasskeyCredentialStore + 'static,
//! # {
//! let state = PasskeyAuthState {
//!     relying_party: rp,
//!     authority,
//!     credentials,
//!     flows: Arc::new(MemoryPasskeyFlowStore::new()),
//! };
//!
//! let app: Router = Router::new().nest("/auth", router(Arc::new(state)));
//! # Ok(()) }
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::routing::post;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use cheers::passkey::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PasskeyRelyingParty, PasskeyUpdate, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Uuid, apply_authentication_result, passkey_from_credential,
    passkey_to_credential,
};
use cheers_core::{DeviceBinding, DeviceId, TokenMinter, UserId};
use cheers_server::{
    PasskeyCredentialStore, RefreshStore, RevocationWriter, SessionAuthority, UserStore,
};

use crate::error::RouteError;
use crate::session::SessionBody;

/// Server-side stash for a passkey registration ceremony in flight.
///
/// The `user_id` and `device_id` are chosen at `start_registration` time so
/// `finish_registration` can persist the resulting [`Passkey`] without
/// trusting the client to supply them again.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct StashedRegistration {
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub state: PasskeyRegistration,
}

/// Server-side stash for a passkey authentication ceremony in flight.
///
/// The `user_id` is pinned at `start_authentication` so `finish_authentication`
/// always re-lists credentials for the same user the challenge was scoped to.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct StashedAuthentication {
    pub user_id: UserId,
    pub state: PasskeyAuthentication,
}

/// Persistence for in-flight passkey ceremony state.
///
/// Implementations MUST treat each entry as single-use (a successful
/// `take_*` removes it) so a replayed `finish` cannot re-verify a stale
/// assertion. The state itself carries the WebAuthn challenge; losing the
/// state to the client or reusing it reopens replay attacks — the same
/// contract `OidcFlowStore` carries for OIDC.
#[async_trait]
pub trait PasskeyFlowStore: Send + Sync {
    async fn put_registration(
        &self,
        flow_id: &str,
        value: StashedRegistration,
    ) -> Result<(), String>;
    async fn take_registration(
        &self,
        flow_id: &str,
    ) -> Result<Option<StashedRegistration>, String>;
    async fn put_authentication(
        &self,
        flow_id: &str,
        value: StashedAuthentication,
    ) -> Result<(), String>;
    async fn take_authentication(
        &self,
        flow_id: &str,
    ) -> Result<Option<StashedAuthentication>, String>;
}

/// In-process [`PasskeyFlowStore`] for tests, dev, and single-replica
/// deployments. Production multi-replica deployments want a shared backend
/// (Redis, Postgres, …).
#[derive(Default, Debug)]
pub struct MemoryPasskeyFlowStore {
    reg: Mutex<HashMap<String, StashedRegistration>>,
    auth: Mutex<HashMap<String, StashedAuthentication>>,
}

impl MemoryPasskeyFlowStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl PasskeyFlowStore for MemoryPasskeyFlowStore {
    async fn put_registration(
        &self,
        flow_id: &str,
        value: StashedRegistration,
    ) -> Result<(), String> {
        self.reg.lock().unwrap().insert(flow_id.to_owned(), value);
        Ok(())
    }
    async fn take_registration(
        &self,
        flow_id: &str,
    ) -> Result<Option<StashedRegistration>, String> {
        Ok(self.reg.lock().unwrap().remove(flow_id))
    }
    async fn put_authentication(
        &self,
        flow_id: &str,
        value: StashedAuthentication,
    ) -> Result<(), String> {
        self.auth.lock().unwrap().insert(flow_id.to_owned(), value);
        Ok(())
    }
    async fn take_authentication(
        &self,
        flow_id: &str,
    ) -> Result<Option<StashedAuthentication>, String> {
        Ok(self.auth.lock().unwrap().remove(flow_id))
    }
}

/// State bundle held by the passkey handlers.
pub struct PasskeyAuthState<M, R, U, W, P, F> {
    pub relying_party: Arc<PasskeyRelyingParty>,
    pub authority: Arc<SessionAuthority<M, R, U, W>>,
    pub credentials: Arc<P>,
    pub flows: Arc<F>,
}

impl<M, R, U, W, P, F> std::fmt::Debug for PasskeyAuthState<M, R, U, W, P, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyAuthState")
            .field("rp_id", &self.relying_party.rp_id())
            .finish_non_exhaustive()
    }
}

/// Build a router mounting the four passkey routes. The product mounts it
/// under whatever base path it chose (`/auth`, `/api/auth`, …).
pub fn router<M, R, U, W, P, F>(state: Arc<PasskeyAuthState<M, R, U, W, P, F>>) -> Router
where
    M: TokenMinter + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    U: UserStore + Send + Sync + 'static,
    W: RevocationWriter + Send + Sync + 'static,
    P: PasskeyCredentialStore + Send + Sync + 'static,
    F: PasskeyFlowStore + Send + Sync + 'static,
{
    Router::new()
        .route(
            "/passkey/register/start",
            post(register_start::<M, R, U, W, P, F>),
        )
        .route(
            "/passkey/register/finish",
            post(register_finish::<M, R, U, W, P, F>),
        )
        .route(
            "/passkey/authenticate/start",
            post(authenticate_start::<M, R, U, W, P, F>),
        )
        .route(
            "/passkey/authenticate/finish",
            post(authenticate_finish::<M, R, U, W, P, F>),
        )
        .with_state(state)
}

/// Request body for `POST /passkey/register/start`.
///
/// `user_id` + `device_id` pin the ceremony — `finish_registration` writes
/// the resulting passkey into the credential store at that key. Products
/// that want a server-chosen `device_id` (the common case for "add a new
/// authenticator to this account") should supply one here; the value is
/// opaque to the WebAuthn flow.
#[derive(Debug, Clone, Deserialize)]
pub struct RegisterStartRequest {
    pub user_id: String,
    pub device_id: String,
    /// Friendly account label (typically an email). Surfaced in some
    /// authenticator UIs; must not be treated as a key.
    pub user_name: String,
    /// Display name shown to the user during the ceremony.
    pub user_display_name: String,
}

#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct RegisterStartResponse {
    pub flow_id: String,
    pub challenge: CreationChallengeResponse,
}

pub async fn register_start<M, R, U, W, P, F>(
    State(state): State<Arc<PasskeyAuthState<M, R, U, W, P, F>>>,
    Json(req): Json<RegisterStartRequest>,
) -> Result<Json<RegisterStartResponse>, RouteError>
where
    M: TokenMinter + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    U: UserStore + Send + Sync + 'static,
    W: RevocationWriter + Send + Sync + 'static,
    P: PasskeyCredentialStore + Send + Sync + 'static,
    F: PasskeyFlowStore + Send + Sync + 'static,
{
    let user_id = UserId::new(req.user_id);
    let device_id = DeviceId::new(req.device_id);

    // Exclude already-registered passkeys so an authenticator can't enroll a
    // duplicate against the same account (a different authenticator can still
    // enroll a separate credential — that's the multi-credential model).
    let existing = state.credentials.list_for_user(&user_id).await?;
    let exclude: Vec<Passkey> = existing
        .iter()
        .map(passkey_from_credential)
        .collect::<Result<_, _>>()?;

    let user_handle = uuid_from_user_id(&user_id);
    let (challenge, registration) = state.relying_party.start_registration(
        user_handle,
        &req.user_name,
        &req.user_display_name,
        &exclude,
    )?;

    let flow_id = random_flow_id();
    let stashed = StashedRegistration {
        user_id,
        device_id,
        state: registration,
    };
    state
        .flows
        .put_registration(&flow_id, stashed)
        .await
        .map_err(RouteError::Store)?;

    Ok(Json(RegisterStartResponse { flow_id, challenge }))
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegisterFinishRequest {
    pub flow_id: String,
    pub credential: RegisterPublicKeyCredential,
}

pub async fn register_finish<M, R, U, W, P, F>(
    State(state): State<Arc<PasskeyAuthState<M, R, U, W, P, F>>>,
    Json(req): Json<RegisterFinishRequest>,
) -> Result<Json<SessionBody>, RouteError>
where
    M: TokenMinter + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    U: UserStore + Send + Sync + 'static,
    W: RevocationWriter + Send + Sync + 'static,
    P: PasskeyCredentialStore + Send + Sync + 'static,
    F: PasskeyFlowStore + Send + Sync + 'static,
{
    let stashed = state
        .flows
        .take_registration(&req.flow_id)
        .await
        .map_err(RouteError::Store)?
        .ok_or(RouteError::UnknownFlow)?;

    let passkey = state
        .relying_party
        .finish_registration(&req.credential, &stashed.state)?;
    let credential =
        passkey_to_credential(stashed.user_id.clone(), stashed.device_id.clone(), &passkey)?;
    state.credentials.put(&credential).await?;

    let now = now_unix();
    let session = state
        .authority
        .establish(
            stashed.user_id,
            stashed.device_id,
            DeviceBinding::Passkey,
            now,
        )
        .await?;
    Ok(Json(SessionBody::from_new_session(session)))
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthenticateStartRequest {
    pub user_id: String,
}

#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct AuthenticateStartResponse {
    pub flow_id: String,
    pub challenge: RequestChallengeResponse,
}

pub async fn authenticate_start<M, R, U, W, P, F>(
    State(state): State<Arc<PasskeyAuthState<M, R, U, W, P, F>>>,
    Json(req): Json<AuthenticateStartRequest>,
) -> Result<Json<AuthenticateStartResponse>, RouteError>
where
    M: TokenMinter + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    U: UserStore + Send + Sync + 'static,
    W: RevocationWriter + Send + Sync + 'static,
    P: PasskeyCredentialStore + Send + Sync + 'static,
    F: PasskeyFlowStore + Send + Sync + 'static,
{
    let user_id = UserId::new(req.user_id);
    let credentials = state.credentials.list_for_user(&user_id).await?;
    if credentials.is_empty() {
        // start_authentication with no candidates would still produce a
        // challenge, but no authenticator can answer it — fail loud here.
        return Err(RouteError::UnknownCredential);
    }
    let passkeys: Vec<Passkey> = credentials
        .iter()
        .map(passkey_from_credential)
        .collect::<Result<_, _>>()?;

    let (challenge, authentication) = state.relying_party.start_authentication(&passkeys)?;

    let flow_id = random_flow_id();
    let stashed = StashedAuthentication {
        user_id,
        state: authentication,
    };
    state
        .flows
        .put_authentication(&flow_id, stashed)
        .await
        .map_err(RouteError::Store)?;
    Ok(Json(AuthenticateStartResponse { flow_id, challenge }))
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthenticateFinishRequest {
    pub flow_id: String,
    pub credential: PublicKeyCredential,
}

pub async fn authenticate_finish<M, R, U, W, P, F>(
    State(state): State<Arc<PasskeyAuthState<M, R, U, W, P, F>>>,
    Json(req): Json<AuthenticateFinishRequest>,
) -> Result<Json<SessionBody>, RouteError>
where
    M: TokenMinter + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    U: UserStore + Send + Sync + 'static,
    W: RevocationWriter + Send + Sync + 'static,
    P: PasskeyCredentialStore + Send + Sync + 'static,
    F: PasskeyFlowStore + Send + Sync + 'static,
{
    let stashed = state
        .flows
        .take_authentication(&req.flow_id)
        .await
        .map_err(RouteError::Store)?
        .ok_or(RouteError::UnknownFlow)?;

    let result = state
        .relying_party
        .finish_authentication(&req.credential, &stashed.state)?;

    // Re-list the user's credentials to find which device answered + persist
    // any counter advance the assertion produced.
    let credentials = state.credentials.list_for_user(&stashed.user_id).await?;
    let paired: Vec<(DeviceId, Passkey)> = credentials
        .iter()
        .map(|c| Ok::<_, RouteError>((c.device_id.clone(), passkey_from_credential(c)?)))
        .collect::<Result<_, _>>()?;
    let device_id = paired
        .iter()
        .find(|(_, p)| p.cred_id() == result.cred_id())
        .map(|(d, _)| d.clone())
        .ok_or(RouteError::UnknownCredential)?;

    let mut passkeys: Vec<Passkey> = paired.iter().map(|(_, p)| p.clone()).collect();
    match apply_authentication_result(&mut passkeys, &result) {
        PasskeyUpdate::Updated(updated) => {
            let cred =
                passkey_to_credential(stashed.user_id.clone(), device_id.clone(), updated)?;
            state.credentials.update(&cred).await?;
        }
        PasskeyUpdate::Unchanged(_) => {}
        PasskeyUpdate::UnknownCredential => return Err(RouteError::UnknownCredential),
        // PasskeyUpdate is #[non_exhaustive]; any future variant gets a
        // ceremony-failed mapping until a dedicated handler lands.
        other => return Err(RouteError::Ceremony(format!("{other:?}"))),
    }

    let now = now_unix();
    let session = state
        .authority
        .establish(stashed.user_id, device_id, DeviceBinding::Passkey, now)
        .await?;
    Ok(Json(SessionBody::from_new_session(session)))
}

/// WebAuthn user handles are opaque ≤64-byte UUIDs that must be stable per
/// user and must not be PII. We derive one by hashing the cheers `UserId`
/// into a v5 UUID so the same user always reaches the same handle without
/// the product having to maintain a `UserId ↔ Uuid` table.
///
/// `webauthn-rs` re-exports `Uuid` but its transitive `uuid` dep doesn't
/// enable the `v5` feature; we take a direct `uuid` dep (gated on the
/// `passkey` feature) for the constructor and convert via `into()` — the
/// concrete type is the same `uuid::Uuid`.
fn uuid_from_user_id(user_id: &UserId) -> Uuid {
    let derived = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, user_id.as_str().as_bytes());
    // `webauthn_rs::prelude::Uuid` IS `uuid::Uuid` — explicit conversion in
    // case a future webauthn-rs ever wraps it in a newtype.
    Uuid::from_bytes(*derived.as_bytes())
}

/// 128-bit random flow id, base64url-no-pad. Used as the in-flight ceremony
/// key — uniqueness only, not a secret (the secret is the challenge inside
/// the stashed state).
fn random_flow_id() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("OS CSPRNG must be available");
    URL_SAFE_NO_PAD.encode(bytes)
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_from_user_id_is_stable_per_user() {
        let a = uuid_from_user_id(&UserId::new("u-1"));
        let b = uuid_from_user_id(&UserId::new("u-1"));
        assert_eq!(a, b);
        let c = uuid_from_user_id(&UserId::new("u-2"));
        assert_ne!(a, c);
    }

    #[test]
    fn random_flow_id_is_unique() {
        let a = random_flow_id();
        let b = random_flow_id();
        assert_ne!(a, b);
        assert_eq!(a.len(), 22);
    }
}
