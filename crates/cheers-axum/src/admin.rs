//! `POST /admin/service-principals` + `POST /admin/service-principals/{id}/rotate`
//! — the operator-only path that mints service-principal Ed25519 keypairs.
//!
//! Lives separately from [`mcp`](crate::mcp) because the bearer is **different
//! in kind**: admin endpoints take a *session* bearer (verified through
//! [`EdgeVerifier::verify_at`] into a [`Claims`]), not an MCP token. The
//! distinction matters because the principal model is different: a session
//! identifies a *user* (an operator passkey-authenticated their browser), so
//! the gate is "is this user on the operator list" — not "does this token
//! carry the right scope".
//!
//! ## What gets returned, exactly once
//!
//! The successful provision/rotate response carries a base64url-no-pad copy of
//! the 64-byte Ed25519 secret. Cheers retains only the public half (in the
//! [`ServicePrincipalStore`]); the secret is unrecoverable after this
//! response. Operators are expected to write it to the consumer's config dir
//! (mode 0600) before navigating away. Rotation issues a fresh secret and
//! retires the old key into the JWKS overlap window
//! ([`OverlapPolicy`](cheers_server::OverlapPolicy)).
//!
//! ## OperatorPolicy
//!
//! `OperatorPolicy` is a tiny `Send + Sync` trait so the product can wire
//! whatever check it likes: a hardcoded `HashSet<UserId>`, a query against
//! its own roles table, an LDAP lookup. Kept in `cheers-axum` (not
//! `cheers-server`) because the check is *HTTP-route-shaped* — handlers
//! consult it directly with the verified `claims.sub` and convert a `false`
//! into [`RouteError::NotOperator`] (403).
//!
//! ## Wiring
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use std::collections::HashSet;
//! # use axum::Router;
//! # use cheers_axum::admin::{router, AdminAuthState, OperatorPolicy};
//! # use cheers_core::{TokenVerifier, UserId};
//! # use cheers_server::{EdgeVerifier, RevocationReader, ServicePrincipalAuthority,
//! #     ServicePrincipalStore};
//! struct AllowList { ids: HashSet<UserId> }
//! impl OperatorPolicy for AllowList {
//!     fn is_operator(&self, user: &UserId) -> bool { self.ids.contains(user) }
//! }
//! # async fn run<V, Rd, S>(
//! #     edge: Arc<EdgeVerifier<V, Rd>>,
//! #     authority: Arc<ServicePrincipalAuthority<S>>,
//! #     allow: Arc<AllowList>,
//! # ) -> Result<(), Box<dyn std::error::Error>>
//! # where
//! #     V: TokenVerifier + Send + Sync + 'static,
//! #     Rd: RevocationReader + 'static,
//! #     S: ServicePrincipalStore + 'static,
//! # {
//! let state = Arc::new(AdminAuthState { edge, authority, operators: allow });
//! let app: Router = Router::new().nest("/api", router(state));
//! # Ok(()) }
//! ```

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use cheers_core::{Principal, PrincipalId, TokenVerifier, UserId};
use cheers_server::{
    EdgeVerifier, NewServicePrincipal, ProvisionedKey, RevocationReader,
    ServicePrincipalAuthority, ServicePrincipalStore, SigningKey,
};

use crate::error::RouteError;
use crate::me::authenticate;

/// Operator gate consulted by every admin handler after session
/// authentication. Returns `true` iff `user` is allowed to call operator
/// endpoints. The product supplies the impl (a hardcoded set, a roles
/// table, whatever fits).
pub trait OperatorPolicy: Send + Sync {
    fn is_operator(&self, user: &UserId) -> bool;
}

/// State bundle held by the admin handlers.
///
/// Generic over the same `V`/`Rd` shape [`MeAuthState`](crate::me::MeAuthState)
/// is generic over (so the same `EdgeVerifier` configuration works for both),
/// plus `S` for the [`ServicePrincipalStore`] impl backing the authority.
/// `operators` is `dyn` so the product can change the policy impl without
/// re-genericifying every call site.
pub struct AdminAuthState<V, Rd, S> {
    pub edge: Arc<EdgeVerifier<V, Rd>>,
    pub authority: Arc<ServicePrincipalAuthority<S>>,
    pub operators: Arc<dyn OperatorPolicy>,
}

impl<V, Rd, S> std::fmt::Debug for AdminAuthState<V, Rd, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminAuthState").finish_non_exhaustive()
    }
}

/// Body for `POST /admin/service-principals`.
///
/// `desired_id` becomes the bare half of `svc:<desired_id>`. A collision on
/// that id surfaces as [`RouteError::AlreadyExists`] (409) — operators retry
/// with a different name rather than rotate (rotate is for an *existing*
/// principal).
#[derive(Debug, Clone, Deserialize)]
pub struct CreateServicePrincipalBody {
    pub desired_id: String,
}

/// One-shot provision/rotate response. `secret_key_b64` is the 64-byte
/// PASETO V4 `seed || public` layout, base64url-no-pad encoded — write it
/// to the consumer's config dir before this response leaves the operator's
/// hands. Cheers retains nothing of the secret half.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionResponse {
    pub principal: Principal,
    pub signing_key: SigningKey,
    pub secret_key_b64: String,
}

impl ProvisionResponse {
    fn from_provisioned(p: ProvisionedKey) -> Self {
        Self {
            principal: p.principal,
            signing_key: p.signing_key,
            secret_key_b64: URL_SAFE_NO_PAD.encode(p.secret_key),
        }
    }
}

/// Mount `POST /admin/service-principals` + `POST /admin/service-principals/{id}/rotate`.
/// The product nests this under whatever base path it chose (e.g. `/api`).
pub fn router<V, Rd, S>(state: Arc<AdminAuthState<V, Rd, S>>) -> Router
where
    V: TokenVerifier + Send + Sync + 'static,
    Rd: RevocationReader + Send + Sync + 'static,
    S: ServicePrincipalStore + 'static,
{
    Router::new()
        .route(
            "/admin/service-principals",
            post(create_service_principal::<V, Rd, S>),
        )
        .route(
            "/admin/service-principals/{id}/rotate",
            post(rotate_service_principal::<V, Rd, S>),
        )
        .with_state(state)
}

/// `POST /admin/service-principals` — allocate a fresh service principal and
/// return its Ed25519 keypair (secret returned **once**).
pub async fn create_service_principal<V, Rd, S>(
    State(state): State<Arc<AdminAuthState<V, Rd, S>>>,
    headers: HeaderMap,
    Json(body): Json<CreateServicePrincipalBody>,
) -> Result<(StatusCode, Json<ProvisionResponse>), RouteError>
where
    V: TokenVerifier + Send + Sync,
    Rd: RevocationReader,
    S: ServicePrincipalStore,
{
    let now = now_unix();
    let claims = authenticate(&headers, &state.edge, now).await?;
    if !state.operators.is_operator(&claims.sub) {
        return Err(RouteError::NotOperator);
    }
    let provisioned = state
        .authority
        .provision(NewServicePrincipal::new(body.desired_id), now)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(ProvisionResponse::from_provisioned(provisioned)),
    ))
}

/// `POST /admin/service-principals/{id}/rotate` — register a fresh keypair
/// for an existing service principal, retire the previously-active key into
/// the JWKS overlap window, and return the new secret **once**.
pub async fn rotate_service_principal<V, Rd, S>(
    State(state): State<Arc<AdminAuthState<V, Rd, S>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ProvisionResponse>, RouteError>
where
    V: TokenVerifier + Send + Sync,
    Rd: RevocationReader,
    S: ServicePrincipalStore,
{
    let now = now_unix();
    let claims = authenticate(&headers, &state.edge, now).await?;
    if !state.operators.is_operator(&claims.sub) {
        return Err(RouteError::NotOperator);
    }
    let target = PrincipalId::service(id);
    let provisioned = state.authority.rotate(&target, now).await?;
    Ok(Json(ProvisionResponse::from_provisioned(provisioned)))
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

    use std::collections::HashSet;

    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode, header};
    use cheers_core::{Claims, DeviceBinding, DeviceId, PrincipalId, TokenMinter, UserId};
    use cheers_server::{
        EdgeVerifier, MemoryServicePrincipalStore, PasetoV4SecretMinter, RevocationReader,
        ServicePrincipalAuthority, SigningKeyStatus,
    };
    use tower::ServiceExt;

    /// In-memory `RevocationReader` — every jti reads as unrevoked. Tests
    /// for revocation interaction live in `me::tests`; here we only care that
    /// the session bearer verifies.
    #[derive(Default, Clone, Debug)]
    struct NoopRevoked;

    #[async_trait::async_trait]
    impl RevocationReader for NoopRevoked {
        async fn is_revoked(&self, _jti: &str) -> Result<bool, cheers_core::StoreError> {
            Ok(false)
        }
    }

    /// Static allow-list `OperatorPolicy` for tests. A real product wires
    /// whatever shape it likes — the trait is the contract.
    #[derive(Default, Clone, Debug)]
    struct AllowList(HashSet<UserId>);

    impl AllowList {
        fn with(ids: &[&str]) -> Self {
            Self(ids.iter().map(|s| UserId::new(*s)).collect())
        }
    }

    impl OperatorPolicy for AllowList {
        fn is_operator(&self, user: &UserId) -> bool {
            self.0.contains(user)
        }
    }

    fn now() -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .expect("clock past epoch")
    }

    /// Build the admin router with an empty in-memory principal store and a
    /// configurable operator allow-list. Returns the router plus the bits
    /// tests need to mint session bearers and observe authority state.
    fn rig(
        operators: &[&str],
    ) -> (
        Router,
        PasetoV4SecretMinter,
        Arc<ServicePrincipalAuthority<MemoryServicePrincipalStore>>,
    ) {
        let (minter, verifier) = PasetoV4SecretMinter::generate().expect("paseto v4 keypair");
        let edge = Arc::new(EdgeVerifier::new(verifier, NoopRevoked));
        let authority = Arc::new(ServicePrincipalAuthority::new(
            MemoryServicePrincipalStore::new(),
        ));
        let state = Arc::new(AdminAuthState {
            edge,
            authority: authority.clone(),
            operators: Arc::new(AllowList::with(operators)),
        });
        let app = Router::new().nest("/api", router(state));
        (app, minter, authority)
    }

    /// Mint a session token (the `Claims` shape — NOT McpClaims). The admin
    /// endpoints intentionally take session bearers; this matches what an
    /// operator-passkey-authenticated browser would carry.
    fn mint_session_for(minter: &PasetoV4SecretMinter, user: &str, now: i64) -> String {
        let claims = Claims::new(
            UserId::new(user),
            DeviceId::new("admin-laptop"),
            DeviceBinding::Passkey,
            now,
            now + 600,
        );
        minter.mint(&claims).expect("session mint")
    }

    fn bearer(token: &str) -> (header::HeaderName, String) {
        (header::AUTHORIZATION, format!("Bearer {token}"))
    }

    async fn body_json<T: for<'de> serde::Deserialize<'de>>(body: Body) -> T {
        let bytes = to_bytes(body, 16 * 1024).await.expect("body bytes");
        serde_json::from_slice(&bytes).expect("json decode")
    }

    // ---- create_service_principal -----------------------------------------

    #[tokio::test]
    async fn create_service_principal_returns_secret_exactly_once() {
        let (app, minter, authority) = rig(&["alice"]);
        let token = mint_session_for(&minter, "alice", now());
        let (k, v) = bearer(&token);
        let req = Request::builder()
            .method("POST")
            .uri("/api/admin/service-principals")
            .header(k, v)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"desired_id":"yubaba-1"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body: ProvisionResponse = body_json(resp.into_body()).await;
        assert_eq!(body.principal.id, PrincipalId::service("yubaba-1"));
        assert_eq!(body.signing_key.status, SigningKeyStatus::Active);
        // 64-byte secret base64url-no-pad (88 chars without padding).
        let raw = URL_SAFE_NO_PAD
            .decode(body.secret_key_b64.as_bytes())
            .expect("secret decodes");
        assert_eq!(raw.len(), 64);
        // Cheers retained the pubkey; the published JWKS set sees it.
        let live = authority.published_signing_keys(now()).await.unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].kid, body.signing_key.kid);
    }

    #[tokio::test]
    async fn create_service_principal_rejects_non_operator_with_403() {
        let (app, minter, authority) = rig(&["alice"]); // bob is NOT an operator
        let token = mint_session_for(&minter, "bob", now());
        let (k, v) = bearer(&token);
        let req = Request::builder()
            .method("POST")
            .uri("/api/admin/service-principals")
            .header(k, v)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"desired_id":"yubaba-2"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        // Critically: no principal was allocated — the authority store is
        // unchanged. (We assert via the empty published JWKS, which is the
        // observable surface; the store has no read-by-id from outside.)
        let live = authority.published_signing_keys(now()).await.unwrap();
        assert!(live.is_empty(), "non-operator must not provision: {live:?}");
    }

    #[tokio::test]
    async fn create_service_principal_rejects_missing_bearer_with_401() {
        let (app, _minter, _) = rig(&["alice"]);
        let req = Request::builder()
            .method("POST")
            .uri("/api/admin/service-principals")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"desired_id":"yubaba-3"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn create_service_principal_rejects_duplicate_id_with_409() {
        let (app, minter, _) = rig(&["alice"]);
        let token = mint_session_for(&minter, "alice", now());
        let make_req = || {
            let (k, v) = bearer(&token);
            Request::builder()
                .method("POST")
                .uri("/api/admin/service-principals")
                .header(k, v)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"desired_id":"yubaba-dup"}"#))
                .unwrap()
        };
        let resp = app.clone().oneshot(make_req()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let resp = app.oneshot(make_req()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    // ---- rotate_service_principal -----------------------------------------

    #[tokio::test]
    async fn rotate_service_principal_retires_old_and_issues_fresh() {
        let (app, minter, authority) = rig(&["alice"]);
        let token = mint_session_for(&minter, "alice", now());

        // Provision first.
        let (k, v) = bearer(&token);
        let req = Request::builder()
            .method("POST")
            .uri("/api/admin/service-principals")
            .header(k, v)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"desired_id":"yubaba-r"}"#))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let first: ProvisionResponse = body_json(resp.into_body()).await;

        // Then rotate.
        let (k, v) = bearer(&token);
        let req = Request::builder()
            .method("POST")
            .uri("/api/admin/service-principals/yubaba-r/rotate")
            .header(k, v)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let second: ProvisionResponse = body_json(resp.into_body()).await;

        // Fresh kid, fresh pubkey, different secret.
        assert_ne!(second.signing_key.kid, first.signing_key.kid);
        assert_ne!(
            second.signing_key.public_key,
            first.signing_key.public_key
        );
        assert_ne!(second.secret_key_b64, first.secret_key_b64);

        // Both kids live in the published JWKS during the overlap window.
        let live = authority.published_signing_keys(now()).await.unwrap();
        let mut kids: Vec<_> = live.iter().map(|k| k.kid.clone()).collect();
        kids.sort();
        let mut expected = vec![first.signing_key.kid, second.signing_key.kid];
        expected.sort();
        assert_eq!(kids, expected);
    }

    #[tokio::test]
    async fn rotate_service_principal_unknown_id_returns_404() {
        let (app, minter, _) = rig(&["alice"]);
        let token = mint_session_for(&minter, "alice", now());
        let (k, v) = bearer(&token);
        let req = Request::builder()
            .method("POST")
            .uri("/api/admin/service-principals/ghost/rotate")
            .header(k, v)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn rotate_service_principal_rejects_non_operator_with_403() {
        let (app, minter, _) = rig(&["alice"]);
        // bob isn't on the list — should be 403 before the rotation runs.
        let token = mint_session_for(&minter, "bob", now());
        let (k, v) = bearer(&token);
        let req = Request::builder()
            .method("POST")
            .uri("/api/admin/service-principals/yubaba-x/rotate")
            .header(k, v)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // ---- response shape ---------------------------------------------------

    #[tokio::test]
    async fn provision_response_serializes_secret_as_base64url_no_pad() {
        // Exercise the secret-encoding path via a real provision (SigningKey
        // and ProvisionedKey are #[non_exhaustive] — they can only be
        // constructed from inside cheers-server, which is what the authority
        // does).
        let authority = ServicePrincipalAuthority::new(MemoryServicePrincipalStore::new());
        let provisioned = authority
            .provision(NewServicePrincipal::new("yubaba-enc"), 1_000)
            .await
            .unwrap();
        let response = ProvisionResponse::from_provisioned(provisioned);
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"secret_key_b64\""));
        // 64 raw bytes → 86-char base64url without padding (88 with padding).
        assert_eq!(response.secret_key_b64.len(), 86);
        assert!(!response.secret_key_b64.contains('='), "{response:?}");
        // The encoded form round-trips back to exactly 64 bytes.
        let raw = URL_SAFE_NO_PAD
            .decode(response.secret_key_b64.as_bytes())
            .unwrap();
        assert_eq!(raw.len(), 64);
    }

    // ---- trait dyn-compat -------------------------------------------------

    #[test]
    fn operator_policy_is_dyn_compatible() {
        fn _f(_: &dyn OperatorPolicy) {}
    }
}
