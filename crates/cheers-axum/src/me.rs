//! `/me/sessions` routes — list and revoke the live sessions on the
//! authenticated user's account.
//!
//! These two endpoints close the loop on the bearer/PASETO response shape the
//! provider modules return: `SessionBody::access_token` is the bearer token a
//! client hands back here as `Authorization: Bearer <paseto>`. The
//! [`EdgeVerifier`] in [`MeAuthState`] checks the signature *and* the
//! revocation set — the same verifier shape a CF Worker would hold — so the
//! origin and the edge agree on what "still valid" means.
//!
//! ## What you list, and where the binding comes from
//!
//! The refresh-token row in [`RefreshStore`] does **not** carry a
//! `DeviceBinding` (the cheers refresh chain is about *which session*, not
//! *how it authenticated*). To surface
//! `[{device_id, binding, issued_at, expires_at, is_current}]` per the ticket
//! spec, the row lives in product code: the product implements
//! [`SessionDirectory`] over its own table. Both halves of that table are
//! product-owned — [`SessionRecorder`] is how the rows get written, and it is
//! the reason this is implementable at all. The binding is known in exactly
//! three places (magic-link verify, passkey register, passkey authenticate),
//! all of them inside this crate, so a product that merely *mounts* those
//! routers is never on the stack when a session is established; the recorder
//! is the seam that hands it out. Both traits stay in `cheers-axum` rather
//! than `cheers-server` so the cheers-server trait surface remains minimal —
//! no new `SessionStore` trait, per the R018 design call, and the refresh
//! chain goes on saying nothing about how a session authenticated.
//!
//! A service that wants no session list wires [`NoSessionRecorder`] and skips
//! [`router`].
//!
//! ## Revoke semantics
//!
//! `DELETE /me/sessions/{device_id}` calls
//! [`SessionAuthority::revoke_device`](cheers_server::SessionAuthority::revoke_device),
//! which the `UserStore` impl is expected to extend to "also revoke refresh
//! chains for that device" (cheers-sqlx's `PgUserStore` does). That blocks
//! *new* sessions immediately. If the targeted device is the *current*
//! device, the route additionally revokes the current access token's `jti`
//! via [`SessionAuthority::revoke_session`] so the edge stops accepting it
//! within the propagation window. For non-current devices the in-flight
//! access token expires naturally inside the (minutes-scale) access TTL —
//! that bound is documented on [`SessionPolicy`](cheers_server::SessionPolicy).
//!
//! ## Wiring
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use axum::Router;
//! # use cheers_axum::me::{router, MeAuthState, SessionDirectory};
//! # use cheers_server::{EdgeVerifier, SessionAuthority};
//! # async fn run<V, Rd, M, R, U, W, D>(
//! #     edge: Arc<EdgeVerifier<V, Rd>>,
//! #     authority: Arc<SessionAuthority<M, R, U, W>>,
//! #     directory: Arc<D>,
//! # ) -> Result<(), Box<dyn std::error::Error>>
//! # where
//! #     V: cheers_core::TokenVerifier + Send + Sync + 'static,
//! #     Rd: cheers_server::RevocationReader + 'static,
//! #     M: cheers_core::TokenMinter + Send + Sync + 'static,
//! #     R: cheers_server::RefreshStore + 'static,
//! #     U: cheers_server::UserStore + 'static,
//! #     W: cheers_server::RevocationWriter + 'static,
//! #     D: SessionDirectory + 'static,
//! # {
//! let state = MeAuthState { edge, authority, directory };
//! let app: Router = Router::new().nest("/api", router(Arc::new(state)));
//! # Ok(()) }
//! ```
//!
//! @yah:relay(R516, "SessionRecorder seam in cheers-axum so a product can populate SessionDirectory")
//! @yah:at(2026-09-09T06:03:22Z)
//! @yah:status(open)
//! @yah:assignee(agent:claude)
//! @yah:parent(Q003)
//! @yah:gotcha("The three establish call sites are all INSIDE cheers-axum, so no product code is ever on the stack when a binding is known: crates/cheers-axum/src/magic_link.rs:189 (DeviceBinding::EmailMagicLink, device id freshly minted there by generate_device_id), crates/cheers-axum/src/passkey.rs:341 (register, Passkey) and passkey.rs:461 (authenticate, Passkey). This is the whole gap — not a missing store impl, a missing observation point. The only SessionDirectory impl in the tree today is the test one at crates/cheers-axum/tests/common/mod.rs.")
//! @yah:next("ALTERNATIVE CONSIDERED AND NOT RECOMMENDED — put binding on RefreshTokenRecord plus a binding column on refresh_tokens. It is the more faithful data model but it contradicts the guide-by-omission call stated twice in crates/cheers-server/src/session.rs (rotate and establish_bound both argue the chain is about which session, not how this token authenticated), and its blast radius is cheers-server, cheers/src/store/memory.rs, cheers-sqlx, cheers-redis, cheers-turso, the shared crates/cheers-test-support/src/store_scenarios.rs suite, plus a migration that must land byte-identically in crates/cheers-turso/migrations/sqlite/ and crates/cheers-sqlx/migrations/{sqlite,pg}/ — enforced by migrations_match_cheers_sqlx at crates/cheers-turso/tests/turso.rs:211. The recorder shape touches one crate and no migrations.")
//! @yah:next("FIRST CONSUMER, and why this is filed from outside: noisetable's account service (noisetable camp R131-F7) merges both provider routers at web/services/account/src/auth.rs:258-259 and wants GET /me/sessions for an account-UI device list. It consumes the cheers family as plain crates.io deps at 0.8.32 (web/services/account/Cargo.toml:47-52, no [patch.crates-io] since the R131-T11 graduation), so this landing needs a published release before noisetable can move. Note establish_bound needs no seam: noisetable's node-enrollment route calls it from product code (web/services/account/src/node_token.rs), so the product already holds the binding there.")
//! @yah:verify("cargo test -p cheers-axum — the /me tests at crates/cheers-axum/tests/me_basic.rs must go on passing against a real recorder-backed directory rather than only the hand-rolled one in tests/common/mod.rs")
//! @yah:next("The shape is settled in R516-F1: a SessionRecorder trait in cheers-axum plus a required recorder field on the two provider states. This relay holds the why and the rejected alternative; the work unit is the child.")
//! @yah:gotcha("WHY THIS EXISTS (verified 2026-09-08 against the working tree). SessionDirectory at crates/cheers-axum/src/me.rs was unimplementable by a product that only mounts the provider routers. SessionListEntry requires a binding, but SessionAuthority::establish_inner in crates/cheers-server/src/session.rs hands the binding to mint_access and then writes the root refresh row without it; RefreshTokenRecord in crates/cheers-server/src/store.rs has no binding field, deliberately — 'guide by omission, the refresh chain is about which session, not how it authenticated', per rotate's doc comment. UserStore::list_devices returns bare device ids with no binding either. Hence a recorder rather than a store change.")
//!
//! @yah:ticket(R516-F1, "Add SessionRecorder trait + required state field, call it from the three establish sites")
//! @yah:status(review)
//! @yah:at(2026-09-09T06:21:45Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R516)
//! @yah:next("Declare `#[async_trait] pub trait SessionRecorder: Send + Sync { async fn record_established(&self, user_id: &UserId, device_id: &DeviceId, binding: &DeviceBinding, issued_at: i64, expires_at: i64) -> Result<(), StoreError>; }` in crates/cheers-axum/src/me.rs beside SessionDirectory (me.rs:141) and re-export it from crates/cheers-axum/src/lib.rs where SessionDirectory is already re-exported. Same crate for the same reason me.rs:21-24 gives — the cheers-server trait surface stays minimal, no new SessionStore, per the R018 design call.")
//! @yah:next("Add the recorder as a REQUIRED field (not Option) on MagicLinkAuthState (crates/cheers-axum/src/magic_link.rs:82) and PasskeyAuthState (crates/cheers-axum/src/passkey.rs:188), and call it after establish() returns Ok at magic_link.rs:189, passkey.rs:341 and passkey.rs:461. Ship a no-op impl for services that do not list sessions. Both structs are plain pub-field bundles, so a required field is a compile error at every construction site rather than a silent None — and a missed recorder means a device the user can neither see nor revoke. Breaking for yubaba/passway/cloud-admin, but mechanical: one field, one NoRecorder.")
//! @yah:next("Decide and document the failure policy for record_established. Recommend propagating the error so the sign-in request fails: a session that was minted but not recorded is one the user can neither see on /me/sessions nor revoke from it, which is worse than a failed sign-in the client can retry. The alternative (log and continue) trades a silent security hole for availability and should be an explicit product choice, not the default. Whichever wins, say so in the trait's doc comment — this is the kind of call me.rs already documents rather than leaves to the reader.")
//! @yah:verify("cargo test -p cheers-axum — extend crates/cheers-axum/tests/me_basic.rs so the SessionDirectory under test is fed by a SessionRecorder wired into the magic-link and passkey routers, rather than the hand-populated one in tests/common/mod.rs. That end-to-end path (sign in, then list) is the thing this ticket exists to make possible, so it is the test that proves it.")
//! @yah:handoff("LANDED. `SessionRecorder` + `NoSessionRecorder` in crates/cheers-axum/src/me.rs, re-exported from lib.rs beside SessionDirectory. Required `recorder: Arc<dyn SessionRecorder>` field on MagicLinkAuthState and PasskeyAuthState — `Arc<dyn …>` rather than a seventh generic, matching AdminAuthState's `Arc<dyn OperatorPolicy>` precedent in admin.rs. Called at all three establish sites (magic_link.rs verify, passkey.rs register/finish, passkey.rs authenticate/finish) via the trait's provided `record_new_session(&NewSession)`, which reads the refresh chain's issued_at/expires_at so no caller can pick the access token's minutes-long TTL by mistake. Errors propagate through `From<StoreError> for RouteError`, so a failed record fails the sign-in — documented on the trait with the reasoning and the opt-out.")
//! @yah:handoff("TESTS. crates/cheers-axum/tests/common/mod.rs: MemSessionDirectory now impls SessionRecorder over the same map, which is the product shape — one table, written at establish, read at list. me_basic.rs: seed_session switched to record_new_session (the fixture stopped duplicating the timestamp mapping), plus a new end-to-end magic_link_sign_in_then_list_sessions_round_trip that mounts the magic-link router and the /me router over one authority and one directory, signs in for real, and asserts GET /me/sessions returns that device with binding kind email_magic_link and is_current true — nothing seeded by hand. magic_link_basic.rs asserts one row per sign-in with the refresh-chain lifetime (not the access TTL); passkey_basic.rs asserts register records the device and re-authenticating on it upserts rather than adding a second row. cheers-test-identity mounts NoSessionRecorder — it has no /me surface.")
//! @yah:verify("cargo test --workspace --all-features: cheers-axum 69 unit + 54 integration + 12 doctests green, cheers-server 161 green, whole workspace green except cheers-redis's 5 tests, which fail on SocketNotFoundError(\"/var/run/docker.sock\") — testcontainers with no docker on this host, pre-existing and untouched by this change (no store crate was modified). cargo clippy -p cheers-axum -p cheers-test-identity --all-features --all-targets: no new warnings (the 12 'very complex type' ones are the pre-existing 6-generic handlers; the borrowed-expression one is camps.rs:238). cargo doc: 53 pre-existing warnings crate-wide, none in me.rs / magic_link.rs / passkey.rs. cargo fmt deliberately not run — lib.rs:298 records that the crate is already fmt-dirty tree-wide.")
//! @yah:gotcha("BREAKING for anyone constructing MagicLinkAuthState or PasskeyAuthState — that is the design (a forgotten recorder would be a device the user can neither see nor revoke, so the compiler asks). The only construction sites in the yah monorepo were inside this repo: the two module doctests, the two integration-test rigs, and cheers-test-identity. Grepped /Users/leif/ss/yah for both type names and found nothing else — yubaba, passway and cloud-admin do not construct them, contrary to the guess recorded on the parent relay. Outside the monorepo, noisetable's account service does (web/services/account/src/auth.rs), and it needs a published release to pick this up.")

use std::sync::Arc;

use async_trait::async_trait;
use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::routing::{delete, get};
use serde::{Deserialize, Serialize};

use cheers_core::{
    Claims, DeviceBinding, DeviceId, Error, StoreError, TokenMinter, TokenVerifier, UserId,
};
use cheers_server::{
    EdgeVerifier, NewSession, RefreshStore, RevocationReader, RevocationWriter, SessionAuthority,
    UserStore,
};

use crate::error::RouteError;

/// Per-device active-session row a [`SessionDirectory`] returns.
///
/// One row per `(user, device)` pair — the directory is responsible for
/// collapsing rotation chains so a device with many historical refresh
/// tokens still shows up once. `binding` is the authentication that minted
/// the session; the directory stores it (the cheers refresh row doesn't).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SessionDescriptor {
    pub device_id: DeviceId,
    pub binding: DeviceBinding,
    /// Unix-seconds when this session was first established (the root
    /// refresh token's `issued_at`, NOT the latest rotation).
    pub issued_at: i64,
    /// Unix-seconds expiry of the active refresh row — when this device
    /// will be forced to re-authenticate.
    pub expires_at: i64,
}

impl SessionDescriptor {
    pub fn new(
        device_id: DeviceId,
        binding: DeviceBinding,
        issued_at: i64,
        expires_at: i64,
    ) -> Self {
        Self {
            device_id,
            binding,
            issued_at,
            expires_at,
        }
    }
}

/// Per-row JSON shape returned by `GET /me/sessions`.
///
/// `is_current` is derived from the bearer token used on the request: the
/// row whose `device_id` matches the verified [`Claims::device`] flips to
/// `true`. Exactly zero or one row is current; clients can switch on it to
/// label "this device" in a sessions UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct SessionListEntry {
    pub device_id: String,
    pub binding: DeviceBinding,
    pub issued_at: i64,
    pub expires_at: i64,
    pub is_current: bool,
}

/// Product-side enumeration of a user's active sessions.
///
/// One row per `(user, device)` — the impl is responsible for filtering out
/// revoked + expired entries and for sourcing `binding` (which the cheers
/// refresh-token row doesn't carry; see the module docs). Order is
/// unspecified.
#[async_trait]
pub trait SessionDirectory: Send + Sync {
    async fn list_sessions(
        &self,
        user_id: &UserId,
        now: i64,
    ) -> Result<Vec<SessionDescriptor>, StoreError>;
}

/// Product-side observation of a session at the moment it is established.
///
/// The counterpart to [`SessionDirectory`]: the directory reads a device list
/// back, and this is where the rows come from. cheers calls it from the
/// provider ceremonies (magic-link verify, passkey register/authenticate) —
/// the only points at which a [`DeviceBinding`] is known, and points the
/// product has no call site inside, since it mounts those routers rather than
/// writing them. Without it a product literally cannot implement
/// `SessionDirectory`: the refresh row carries no binding
/// ([`RefreshTokenRecord`](cheers_server::RefreshTokenRecord)), and
/// [`UserStore::list_devices`] hands back bare
/// [`DeviceId`]s.
///
/// `issued_at` / `expires_at` are the refresh chain's, not the access token's
/// — they are the lifetime `SessionDescriptor` reports, and the access TTL is
/// minutes.
///
/// **Called on every establish, including a re-authentication on a device the
/// user already has.** Impls should upsert on `(user_id, device_id)` rather
/// than insert, and are free to overwrite `binding` — the latest ceremony is
/// the honest answer to "how is this device signed in".
///
/// **An error fails the sign-in.** That is deliberate: a session that minted
/// but did not record is one the user can neither see on `GET /me/sessions`
/// nor revoke from it, which is a worse outcome than a failed sign-in the
/// client can retry. A product that would rather trade that away can swallow
/// the error inside its own impl and return `Ok(())` — but it makes that call
/// explicitly, in its own code.
///
/// Services that surface no session list wire [`NoSessionRecorder`].
#[async_trait]
pub trait SessionRecorder: Send + Sync {
    async fn record_established(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
        binding: &DeviceBinding,
        issued_at: i64,
        expires_at: i64,
    ) -> Result<(), StoreError>;

    /// Record a [`NewSession`] straight off
    /// [`SessionAuthority::establish`](cheers_server::SessionAuthority::establish).
    ///
    /// Provided, not implemented by products: it exists so the caller cannot
    /// pick the wrong timestamps. The lifetime recorded is the refresh
    /// chain's (minted alongside the access token, and what
    /// [`SessionDescriptor`] reports), never the access token's minutes-long
    /// TTL. The provider ceremonies in this crate call this; a product that
    /// runs its own ceremony over `establish` / `establish_bound` should call
    /// it too.
    async fn record_new_session(&self, session: &NewSession) -> Result<(), StoreError> {
        self.record_established(
            &session.refresh.record.user_id,
            &session.refresh.record.device_id,
            &session.claims.binding,
            session.refresh.record.issued_at,
            session.refresh.record.expires_at,
        )
        .await
    }
}

/// A [`SessionRecorder`] that records nothing, for services with no
/// `/me/sessions` surface.
///
/// The recorder field on the provider states is deliberately required rather
/// than `Option`, so a product that wants a session list cannot forget to
/// wire one — the compiler asks. This is the explicit way to answer "I don't
/// want one", and pairing it with [`me::router`](router) is a contradiction:
/// the directory will stay empty.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSessionRecorder;

#[async_trait]
impl SessionRecorder for NoSessionRecorder {
    async fn record_established(
        &self,
        _user_id: &UserId,
        _device_id: &DeviceId,
        _binding: &DeviceBinding,
        _issued_at: i64,
        _expires_at: i64,
    ) -> Result<(), StoreError> {
        Ok(())
    }
}

/// State bundle held by the `/me/sessions` handlers.
///
/// `edge` is the same [`EdgeVerifier`] a CF Worker would hold; an integrated
/// origin can construct one from the symmetric codec it already mints with
/// (any [`cheers_core::Codec`] is both a [`TokenMinter`] and a
/// [`TokenVerifier`]), or from the asymmetric pair
/// (`PasetoV4SecretMinter::verifier()` ⇒ a `PasetoV4PublicVerifier`).
pub struct MeAuthState<V, Rd, M, R, U, W, D> {
    pub edge: Arc<EdgeVerifier<V, Rd>>,
    pub authority: Arc<SessionAuthority<M, R, U, W>>,
    pub directory: Arc<D>,
}

impl<V, Rd, M, R, U, W, D> std::fmt::Debug for MeAuthState<V, Rd, M, R, U, W, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeAuthState").finish_non_exhaustive()
    }
}

/// Build a router mounting `GET /me/sessions` + `DELETE /me/sessions/{device_id}`.
/// The product nests it under whatever base path it chose (`/api`, …).
pub fn router<V, Rd, M, R, U, W, D>(state: Arc<MeAuthState<V, Rd, M, R, U, W, D>>) -> Router
where
    V: TokenVerifier + Send + Sync + 'static,
    Rd: RevocationReader + Send + Sync + 'static,
    M: TokenMinter + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    U: UserStore + Send + Sync + 'static,
    W: RevocationWriter + Send + Sync + 'static,
    D: SessionDirectory + Send + Sync + 'static,
{
    Router::new()
        .route("/me/sessions", get(list::<V, Rd, M, R, U, W, D>))
        .route(
            "/me/sessions/{device_id}",
            delete(revoke::<V, Rd, M, R, U, W, D>),
        )
        .with_state(state)
}

/// `GET /me/sessions` — list the authenticated user's active sessions.
pub async fn list<V, Rd, M, R, U, W, D>(
    State(state): State<Arc<MeAuthState<V, Rd, M, R, U, W, D>>>,
    headers: HeaderMap,
) -> Result<Json<Vec<SessionListEntry>>, RouteError>
where
    V: TokenVerifier + Send + Sync,
    Rd: RevocationReader,
    D: SessionDirectory,
{
    let now = now_unix();
    let claims = authenticate(&headers, &state.edge, now).await?;
    let descriptors = state.directory.list_sessions(&claims.sub, now).await?;
    let current = claims.device.clone();
    let entries = descriptors
        .into_iter()
        .map(|d| {
            let is_current = d.device_id == current;
            SessionListEntry {
                device_id: d.device_id.into_inner(),
                binding: d.binding,
                issued_at: d.issued_at,
                expires_at: d.expires_at,
                is_current,
            }
        })
        .collect();
    Ok(Json(entries))
}

/// `DELETE /me/sessions/{device_id}` — revoke a device for the authenticated
/// user. Returns `204 No Content` on success. If the targeted device is the
/// current one, the in-flight access token's `jti` is also revoked so the
/// edge stops accepting it immediately.
pub async fn revoke<V, Rd, M, R, U, W, D>(
    State(state): State<Arc<MeAuthState<V, Rd, M, R, U, W, D>>>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
) -> Result<StatusCode, RouteError>
where
    V: TokenVerifier + Send + Sync,
    Rd: RevocationReader,
    M: TokenMinter + Send + Sync,
    R: RefreshStore,
    U: UserStore,
    W: RevocationWriter,
{
    let now = now_unix();
    let claims = authenticate(&headers, &state.edge, now).await?;
    let target = DeviceId::new(device_id);
    state
        .authority
        .revoke_device(&claims.sub, &target)
        .await
        .map_err(map_authority_error)?;
    if target == claims.device {
        state
            .authority
            .revoke_session(&claims.jti)
            .await
            .map_err(map_authority_error)?;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Extract the raw token from `Authorization: Bearer <token>`. Returns
/// [`RouteError::MissingBearer`] / [`RouteError::MalformedBearer`] for the
/// two distinct failure modes so a client can tell "didn't send a header"
/// from "sent a header in the wrong shape".
pub fn bearer_from_headers(headers: &HeaderMap) -> Result<&str, RouteError> {
    let raw = headers
        .get(header::AUTHORIZATION)
        .ok_or(RouteError::MissingBearer)?
        .to_str()
        .map_err(|_| RouteError::MalformedBearer)?;
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
        .ok_or(RouteError::MalformedBearer)?;
    if token.is_empty() {
        return Err(RouteError::MalformedBearer);
    }
    Ok(token)
}

/// Pull the bearer header and run the [`EdgeVerifier`] over the token at
/// `now`. Maps verification failures to [`RouteError::Unauthorized`].
pub async fn authenticate<V, Rd>(
    headers: &HeaderMap,
    edge: &EdgeVerifier<V, Rd>,
    now: i64,
) -> Result<Claims, RouteError>
where
    V: TokenVerifier + Send + Sync,
    Rd: RevocationReader,
{
    let token = bearer_from_headers(headers)?;
    edge.verify_at(token, now).await.map_err(map_verify_error)
}

fn map_verify_error(err: Error) -> RouteError {
    match err {
        // A token that failed the codec layer (bad signature, expired,
        // malformed) is the same outcome from the caller's POV: 401.
        Error::Codec(_) => RouteError::Unauthorized,
        Error::Revoked => RouteError::Unauthorized,
        Error::Store(e) => RouteError::Store(e.to_string()),
        // Refresh / InvalidInput don't surface from EdgeVerifier::verify_at
        // in practice — keep them mapped to the existing buckets rather than
        // letting them silently turn into 401.
        Error::Refresh(e) => RouteError::Store(e.to_string()),
        Error::InvalidInput(msg) => RouteError::Config(msg),
        // cheers_core::Error is #[non_exhaustive] — any future variant gets
        // a generic 500 bridge until a dedicated mapping lands.
        other => RouteError::Store(other.to_string()),
    }
}

fn map_authority_error(err: Error) -> RouteError {
    match err {
        Error::Store(StoreError::NotFound) => RouteError::UnknownDevice,
        other => RouteError::from(other),
    }
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
    fn bearer_from_headers_accepts_canonical_form() {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            "Bearer abc123".parse().unwrap(),
        );
        assert_eq!(bearer_from_headers(&h).unwrap(), "abc123");
    }

    #[test]
    fn bearer_from_headers_accepts_lowercase_scheme() {
        // RFC 7235 says the scheme is case-insensitive; some clients lowercase.
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            "bearer abc123".parse().unwrap(),
        );
        assert_eq!(bearer_from_headers(&h).unwrap(), "abc123");
    }

    #[test]
    fn bearer_from_headers_distinguishes_missing_from_malformed() {
        let empty = HeaderMap::new();
        assert!(matches!(
            bearer_from_headers(&empty).unwrap_err(),
            RouteError::MissingBearer,
        ));

        let mut wrong_scheme = HeaderMap::new();
        wrong_scheme.insert(header::AUTHORIZATION, "Basic abc123".parse().unwrap());
        assert!(matches!(
            bearer_from_headers(&wrong_scheme).unwrap_err(),
            RouteError::MalformedBearer,
        ));

        let mut empty_token = HeaderMap::new();
        empty_token.insert(header::AUTHORIZATION, "Bearer ".parse().unwrap());
        assert!(matches!(
            bearer_from_headers(&empty_token).unwrap_err(),
            RouteError::MalformedBearer,
        ));
    }
}
