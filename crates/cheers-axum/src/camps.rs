//! `POST /admin/camps/bootstrap` — the warden-callable path that provisions a
//! camp principal on behalf of a user.
//!
//! Lives separately from [`admin`](crate::admin) because the bearer is
//! **different in kind**: this endpoint takes an MCP token (warden's service
//! principal, scope = [`Scope::CampAdmin`]), not a session bearer (operator
//! passkey). The admin / service-principal endpoints elevate a *human*
//! operator; this endpoint elevates a *service* (warden) calling on behalf of
//! a human U whose signed delegation rides in the request body.
//!
//! ## Wire shape
//!
//! `bound_to` is the human U the camp will be bound to (kind=user). `desired_id`
//! becomes the bare half of the to-be-minted `camp:<desired_id>`.
//! `delegation` is the
//! [`UserDelegation`](cheers_core::UserDelegation) payload signed by U via the
//! yah-side W122 flow.
//!
//! ```ignore
//! POST /admin/camps/bootstrap
//! Authorization: Bearer <v4.public.*>   # warden, scope=camp:admin
//! Content-Type: application/json
//! {
//!   "bound_to": "user:alice",
//!   "desired_id": "camp-xyz",
//!   "delegation": {
//!     "bound_to": "user:alice",
//!     "camp_id": "camp-xyz",
//!     "issued_at": 1717000000,
//!     "expires_at": 1717000600,
//!     "user_signing_key": "<base64url-32>",
//!     "signature": "<base64url-64>"
//!   }
//! }
//! ```
//!
//! Response (201 Created):
//!
//! ```ignore
//! { "principal": {...}, "credential": { "token": "<opaque>", "expires_at": ... } }
//! ```
//!
//! `credential.token` is the long-lived secret warden persists alongside the
//! camp's runtime state. The doc retains it cheers-side (unlike the
//! service-principal Ed25519 secret which leaves cheers exactly once) because
//! the camp must present this exact string back to mint MCP tokens via flow
//! #2.
//!
//! ## Wiring
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use axum::Router;
//! # use cheers_axum::camps::{router, CampAdminState};
//! # use cheers_axum::mcp::McpAuthState;
//! # use cheers_server::{CampAuthority, CampPrincipalStore, PasetoV4SecretMinter,
//! #     UserSigningKeyStore};
//! # async fn run<S: CampPrincipalStore + 'static, K: UserSigningKeyStore + 'static>(
//! #     authority: Arc<CampAuthority<S, K>>,
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//! let (_minter, verifier) = PasetoV4SecretMinter::generate()?;
//! let mcp = Arc::new(McpAuthState::new(verifier));
//! let state = Arc::new(CampAdminState { mcp, authority });
//! let app: Router = Router::new().nest("/api", router(state));
//! # Ok(()) }
//! ```

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use serde::{Deserialize, Serialize};

use cheers_core::{Principal, PrincipalId, Scope, UserDelegation};
use cheers_server::{
    CampAuthority, CampBootstrapCredential, CampPrincipalStore, NewCampPrincipal,
    UserSigningKeyStore,
};

use crate::error::RouteError;
use crate::mcp::{McpAuthState, McpClaimsExt, authenticate_mcp};

/// State bundle held by the camp-admin handler.
///
/// Holds the verify-only [`McpAuthState`] (no minter — this endpoint cannot
/// mint a session) and an `Arc` over a product-supplied [`CampAuthority`].
/// Mounting this router cannot mint MCP tokens; it can only allocate camp
/// principals + issue long-lived bootstrap credentials.
pub struct CampAdminState<S, K> {
    pub mcp: Arc<McpAuthState>,
    pub authority: Arc<CampAuthority<S, K>>,
}

impl<S, K> std::fmt::Debug for CampAdminState<S, K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CampAdminState").finish_non_exhaustive()
    }
}

/// JSON body for `POST /admin/camps/bootstrap`.
///
/// `bound_to` and `delegation.bound_to` MUST agree (the authority would
/// otherwise reject [`CampAuthorityError::DelegationMismatch`]); ditto
/// `desired_id` vs `delegation.camp_id`. The duplication is on purpose: it
/// lets a caller see the binding at the top of the JSON without re-parsing
/// the delegation.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateCampBootstrapBody {
    pub bound_to: PrincipalId,
    pub desired_id: String,
    pub delegation: UserDelegation,
}

/// `201 Created` response shape.
///
/// Both halves are returned in full: the persisted [`Principal`] (so the
/// caller sees the assigned `created_at`, etc.) and the
/// [`CampBootstrapCredential`] including the opaque `token`. Warden is
/// expected to persist `credential.token` alongside the camp's runtime
/// state before navigating away from the response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampBootstrapResponse {
    pub principal: Principal,
    pub credential: CampBootstrapCredential,
}

impl CampBootstrapResponse {
    fn from_provisioned(p: cheers_server::ProvisionedCamp) -> Self {
        Self {
            principal: p.principal,
            credential: p.credential,
        }
    }
}

/// Mount `POST /admin/camps/bootstrap`. The product nests this under whatever
/// base path it chose (e.g. `/api`).
pub fn router<S, K>(state: Arc<CampAdminState<S, K>>) -> Router
where
    S: CampPrincipalStore + 'static,
    K: UserSigningKeyStore + 'static,
{
    Router::new()
        .route("/admin/camps/bootstrap", post(bootstrap_camp::<S, K>))
        .with_state(state)
}

/// `POST /admin/camps/bootstrap` — allocate a fresh camp principal bound to
/// the user named in the delegation, retain the delegation as the audit
/// record, and return the long-lived bootstrap credential.
pub async fn bootstrap_camp<S, K>(
    State(state): State<Arc<CampAdminState<S, K>>>,
    headers: HeaderMap,
    Json(body): Json<CreateCampBootstrapBody>,
) -> Result<(StatusCode, Json<CampBootstrapResponse>), RouteError>
where
    S: CampPrincipalStore,
    K: UserSigningKeyStore,
{
    let now = now_unix();
    let claims = authenticate_mcp(&headers, &state.mcp.verifier, now)?;
    claims.require_scope(Scope::CampAdmin)?;
    let provisioned = state
        .authority
        .provision(
            NewCampPrincipal::new(body.bound_to, body.desired_id),
            body.delegation,
            now,
        )
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(CampBootstrapResponse::from_provisioned(provisioned)),
    ))
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

    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode, header};
    use cheers_core::{
        Actor, AuthStrength, McpClaims, PrincipalId, PrincipalKind, PrincipalStatus,
        UserDelegation,
    };
    use cheers_server::{
        CampAuthority, MemoryCampPrincipalStore, MemoryUserSigningKeyStore,
        PasetoV4SecretMinter, UserSigningKey, UserSigningKeyStatus,
    };
    use ed25519_compact::{KeyPair, Seed};
    use tower::ServiceExt;

    fn now() -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .expect("clock past epoch")
    }

    fn keypair_from_seed(seed: u8) -> KeyPair {
        KeyPair::from_seed(Seed::from_slice(&[seed; 32]).unwrap())
    }

    fn signed_delegation(
        kp: &KeyPair,
        bound_to: PrincipalId,
        camp_id: &str,
        issued_at: i64,
        expires_at: i64,
    ) -> UserDelegation {
        let unsigned = UserDelegation::new(
            bound_to,
            camp_id,
            issued_at,
            expires_at,
            *kp.pk,
            [0u8; 64],
        )
        .unwrap();
        let sig = kp.sk.sign(&unsigned.signing_payload(), None);
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(sig.as_ref());
        UserDelegation::new(
            unsigned.bound_to,
            unsigned.camp_id,
            unsigned.issued_at,
            unsigned.expires_at,
            unsigned.user_signing_key,
            bytes,
        )
        .unwrap()
    }

    fn trust_key(store: &MemoryUserSigningKeyStore, user: &PrincipalId, pubkey: [u8; 32]) {
        store.insert(UserSigningKey::new(
            "trusted",
            user.clone(),
            pubkey,
            UserSigningKeyStatus::Active,
            0,
        ));
    }

    /// Build the camp router with a fresh in-memory authority. Returns the
    /// router, the MCP minter (so tests can mint warden-bearer tokens), the
    /// authority Arc (for state inspection), and the user-signing-key store
    /// (so tests can register the user's trusted pubkey).
    #[allow(clippy::type_complexity)]
    fn rig() -> (
        Router,
        PasetoV4SecretMinter,
        Arc<CampAuthority<MemoryCampPrincipalStore, MemoryUserSigningKeyStore>>,
        MemoryUserSigningKeyStore,
        MemoryCampPrincipalStore,
    ) {
        let (minter, verifier) = PasetoV4SecretMinter::generate().expect("paseto v4 keypair");
        let mcp = Arc::new(McpAuthState::new(verifier));
        let camp_store = MemoryCampPrincipalStore::new();
        let key_store = MemoryUserSigningKeyStore::new();
        let authority = Arc::new(CampAuthority::new(camp_store.clone(), key_store.clone()));
        let state = Arc::new(CampAdminState {
            mcp,
            authority: authority.clone(),
        });
        let app = Router::new().nest("/api", router(state));
        (app, minter, authority, key_store, camp_store)
    }

    /// Mint an MCP bearer for warden's service principal.
    fn mint_warden_mcp(
        minter: &PasetoV4SecretMinter,
        scopes: Vec<Scope>,
        now_s: i64,
    ) -> String {
        let claims = McpClaims::new(
            "https://cheers.example",
            "https://cheers.example/api",
            PrincipalId::service("warden-1"),
            now_s,
            now_s + 600,
            "jti-warden",
            scopes,
        )
        .with_act(Actor::new(PrincipalId::service("warden-1")))
        .with_auth_strength(AuthStrength::Bootstrap);
        minter.mint_mcp(&claims).expect("mcp mint")
    }

    fn bearer(token: &str) -> (header::HeaderName, String) {
        (header::AUTHORIZATION, format!("Bearer {token}"))
    }

    async fn body_json<T: for<'de> serde::Deserialize<'de>>(body: Body) -> T {
        let bytes = to_bytes(body, 16 * 1024).await.expect("body bytes");
        serde_json::from_slice(&bytes).expect("json decode")
    }

    fn json_body(body: &CreateCampBootstrapBody) -> Body {
        Body::from(serde_json::to_string(body).expect("body json"))
    }

    impl Serialize for CreateCampBootstrapBody {
        // Test-only — exists so json_body() can encode a request payload.
        // Public deserialize lives on the type already; deriving Serialize
        // on the public surface would also work but isn't needed beyond
        // tests.
        fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
            use serde::ser::SerializeStruct;
            let mut s = ser.serialize_struct("CreateCampBootstrapBody", 3)?;
            s.serialize_field("bound_to", &self.bound_to)?;
            s.serialize_field("desired_id", &self.desired_id)?;
            s.serialize_field("delegation", &self.delegation)?;
            s.end()
        }
    }

    // ---- happy path -------------------------------------------------------

    #[tokio::test]
    async fn bootstrap_camp_happy_path_returns_201_with_camp_principal_and_credential() {
        let (app, minter, authority, keys, _store) = rig();
        let user = PrincipalId::user("alice");
        let kp = keypair_from_seed(1);
        trust_key(&keys, &user, *kp.pk);
        let now_s = now();
        let delegation = signed_delegation(
            &kp,
            user.clone(),
            "camp-xyz",
            now_s,
            now_s + 600,
        );
        let token = mint_warden_mcp(&minter, vec![Scope::CampAdmin], now_s);

        let body = CreateCampBootstrapBody {
            bound_to: user.clone(),
            desired_id: "camp-xyz".into(),
            delegation,
        };
        let (k, v) = bearer(&token);
        let req = Request::builder()
            .method("POST")
            .uri("/api/admin/camps/bootstrap")
            .header(k, v)
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let payload: CampBootstrapResponse = body_json(resp.into_body()).await;

        // Camp principal bound_to user, status Active.
        assert_eq!(payload.principal.id, PrincipalId::camp("camp-xyz"));
        assert_eq!(payload.principal.bound_to.as_ref(), Some(&user));
        assert_eq!(payload.principal.status, PrincipalStatus::Active);

        // Credential carries a non-empty token + matching camp_id.
        assert_eq!(payload.credential.camp_id, PrincipalId::camp("camp-xyz"));
        assert!(!payload.credential.token.is_empty());
        assert!(!payload.credential.revoked);

        // Authority can mint via path #2 for the freshly-provisioned camp —
        // proves the principal record is in shape.
        let camp_id = payload.principal.id.clone();
        let stored = authority
            .store()
            .get_principal(&camp_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored, payload.principal);
    }

    #[tokio::test]
    async fn bootstrap_credential_round_trips_into_mint_bootstrap_path() {
        // The verify line on R020-F10: "mint via path #2 with the returned
        // credential succeeds". The /token endpoint that exchanges the
        // credential -> MCP token is a separate ticket — here we hit the
        // authority APIs directly to prove the wiring is intact.
        use cheers_server::{
            McpAuthority, MemoryBundleStore, MemoryGrantStore, ScopeOrBundle,
        };
        use std::sync::Mutex;

        // Minimal in-line ownership store — the same shape mcp_authority's
        // tests use. (Tests can't import the test-only MemOwnershipStore.)
        use async_trait::async_trait;
        use cheers_core::StoreError;
        use cheers_server::{NewOwnership, OwnershipRow, OwnershipStore};
        #[derive(Default)]
        struct InlineOwn(Mutex<Vec<OwnershipRow>>);
        #[async_trait]
        impl OwnershipStore for InlineOwn {
            async fn insert(
                &self,
                o: &NewOwnership,
                now: i64,
            ) -> Result<OwnershipRow, StoreError> {
                let row = OwnershipRow::new(
                    "r".into(),
                    o.principal_id.clone(),
                    o.resource_kind.clone(),
                    o.resource_id.clone(),
                    o.relationship.clone(),
                    o.granted_by.clone(),
                    o.on_behalf_of.clone(),
                    now,
                    None,
                );
                self.0.lock().unwrap().push(row.clone());
                Ok(row)
            }
            async fn get(&self, _id: &str) -> Result<Option<OwnershipRow>, StoreError> {
                Ok(None)
            }
            async fn revoke_by_id(&self, _id: &str, _now: i64) -> Result<(), StoreError> {
                Ok(())
            }
            async fn revoke_by_on_behalf_of(
                &self,
                _u: &PrincipalId,
                _n: i64,
            ) -> Result<u64, StoreError> {
                Ok(0)
            }
            async fn list_for_principal(
                &self,
                _p: &PrincipalId,
            ) -> Result<Vec<OwnershipRow>, StoreError> {
                Ok(vec![])
            }
        }

        let (app, _verifier_minter, camp_authority, keys, _store) = rig();
        let user = PrincipalId::user("alice");
        let kp = keypair_from_seed(50);
        trust_key(&keys, &user, *kp.pk);
        let now_s = now();
        let d = signed_delegation(&kp, user.clone(), "camp-y", now_s, now_s + 600);

        // Provision directly through the authority (sidestepping the HTTP
        // layer — the route already has its own happy-path test above) so
        // we can pass the camp into mint_bootstrap.
        let prov = camp_authority
            .provision(
                NewCampPrincipal::new(user.clone(), "camp-y"),
                d,
                now_s,
            )
            .await
            .unwrap();

        // Stand up an McpAuthority over the same minter + ownership/grants
        // shape mint_bootstrap needs, and grant the freshly-provisioned camp
        // a scope for `aud`.
        let (mcp_minter, mcp_verifier) = PasetoV4SecretMinter::generate().unwrap();
        let grants = MemoryGrantStore::new();
        let ownership = InlineOwn::default();
        let bundles = MemoryBundleStore::with_defaults();
        let aud = "https://constable.camp.example";
        grants.put(
            prov.principal.id.clone(),
            aud,
            vec![ScopeOrBundle::Scope(Scope::CloudRead)],
        );
        let authority = McpAuthority::new(
            mcp_minter,
            bundles,
            grants,
            ownership,
            "https://cheers.example",
        );

        // Mint a path-#2 token off the camp principal — the same code the
        // future /token endpoint will execute when it receives the
        // credential. (Looking up credential -> camp -> mint is what
        // CampPrincipalStore::get_credential is for.)
        let cred = camp_authority
            .store()
            .get_credential(&prov.credential.token)
            .await
            .unwrap()
            .expect("credential persisted");
        let minted = authority
            .mint_bootstrap(cred.camp_id, aud, now_s)
            .await
            .unwrap();
        assert!(minted.token.starts_with("v4.public."));
        assert_eq!(minted.claims.sub, prov.principal.id);
        assert_eq!(minted.claims.camp_id.as_deref(), Some("camp-y"));
        // Edge verifies it.
        let back = mcp_verifier
            .verify_mcp_at(&minted.token, now_s + 60)
            .unwrap();
        assert_eq!(back, minted.claims);
        // Camp principal still Active end-to-end.
        assert_eq!(prov.principal.status, PrincipalStatus::Active);
        // Route's happy path is unchanged.
        drop(app);
    }

    // ---- auth / authorization rejections ---------------------------------

    #[tokio::test]
    async fn bootstrap_camp_rejects_missing_bearer_with_401() {
        let (app, _minter, _, keys, _) = rig();
        let user = PrincipalId::user("alice");
        let kp = keypair_from_seed(2);
        trust_key(&keys, &user, *kp.pk);
        let now_s = now();
        let d = signed_delegation(&kp, user.clone(), "c", now_s, now_s + 600);
        let body = CreateCampBootstrapBody {
            bound_to: user,
            desired_id: "c".into(),
            delegation: d,
        };
        let req = Request::builder()
            .method("POST")
            .uri("/api/admin/camps/bootstrap")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bootstrap_camp_rejects_session_bearer_as_unauthorized() {
        // A session-shape PASETO is rejected by the MCP verifier (different
        // additional-claim key) — surfaces as 401.
        use cheers_core::{Claims, DeviceBinding, DeviceId, TokenMinter, UserId};

        let (app, minter, _, keys, _) = rig();
        let user = PrincipalId::user("alice");
        let kp = keypair_from_seed(3);
        trust_key(&keys, &user, *kp.pk);
        let now_s = now();
        let d = signed_delegation(&kp, user.clone(), "c", now_s, now_s + 600);

        let session = Claims::new(
            UserId::new("warden-operator"),
            DeviceId::new("dev"),
            DeviceBinding::Passkey,
            now_s,
            now_s + 600,
        );
        let token = minter.mint(&session).unwrap();
        let body = CreateCampBootstrapBody {
            bound_to: user,
            desired_id: "c".into(),
            delegation: d,
        };
        let (k, v) = bearer(&token);
        let req = Request::builder()
            .method("POST")
            .uri("/api/admin/camps/bootstrap")
            .header(k, v)
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bootstrap_camp_rejects_missing_camp_admin_scope_with_403() {
        let (app, minter, _, keys, store) = rig();
        let user = PrincipalId::user("alice");
        let kp = keypair_from_seed(4);
        trust_key(&keys, &user, *kp.pk);
        let now_s = now();
        let d = signed_delegation(&kp, user.clone(), "c", now_s, now_s + 600);
        // MCP bearer with WRONG scope (CloudRead, not CampAdmin).
        let token = mint_warden_mcp(&minter, vec![Scope::CloudRead], now_s);
        let body = CreateCampBootstrapBody {
            bound_to: user,
            desired_id: "c".into(),
            delegation: d,
        };
        let (k, v) = bearer(&token);
        let req = Request::builder()
            .method("POST")
            .uri("/api/admin/camps/bootstrap")
            .header(k, v)
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // No camp principal allocated — the side-effect gate held.
        let p = store
            .get_principal(&PrincipalId::camp("c"))
            .await
            .unwrap();
        assert!(p.is_none(), "scope failure must not allocate: {p:?}");
    }

    // ---- delegation failure modes -----------------------------------------

    #[tokio::test]
    async fn bootstrap_camp_rejects_expired_delegation_with_400() {
        let (app, minter, _, keys, _) = rig();
        let user = PrincipalId::user("alice");
        let kp = keypair_from_seed(5);
        trust_key(&keys, &user, *kp.pk);
        let now_s = now();
        // Delegation already expired (expires_at <= now).
        let d = signed_delegation(&kp, user.clone(), "c", now_s - 200, now_s - 100);
        let token = mint_warden_mcp(&minter, vec![Scope::CampAdmin], now_s);
        let body = CreateCampBootstrapBody {
            bound_to: user,
            desired_id: "c".into(),
            delegation: d,
        };
        let (k, v) = bearer(&token);
        let req = Request::builder()
            .method("POST")
            .uri("/api/admin/camps/bootstrap")
            .header(k, v)
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn bootstrap_camp_rejects_untrusted_signing_key_with_401() {
        let (app, minter, _, _keys, _) = rig();
        let user = PrincipalId::user("alice");
        let kp = keypair_from_seed(6);
        // Deliberately NOT registered.
        let now_s = now();
        let d = signed_delegation(&kp, user.clone(), "c", now_s, now_s + 600);
        let token = mint_warden_mcp(&minter, vec![Scope::CampAdmin], now_s);
        let body = CreateCampBootstrapBody {
            bound_to: user,
            desired_id: "c".into(),
            delegation: d,
        };
        let (k, v) = bearer(&token);
        let req = Request::builder()
            .method("POST")
            .uri("/api/admin/camps/bootstrap")
            .header(k, v)
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bootstrap_camp_rejects_bad_signature_with_401() {
        let (app, minter, _, keys, _) = rig();
        let user = PrincipalId::user("alice");
        let kp = keypair_from_seed(7);
        trust_key(&keys, &user, *kp.pk);
        let now_s = now();
        let mut d = signed_delegation(&kp, user.clone(), "c", now_s, now_s + 600);
        // Mutate the signature so the trusted-key check passes but verify fails.
        d.signature[0] ^= 0x01;
        let token = mint_warden_mcp(&minter, vec![Scope::CampAdmin], now_s);
        let body = CreateCampBootstrapBody {
            bound_to: user,
            desired_id: "c".into(),
            delegation: d,
        };
        let (k, v) = bearer(&token);
        let req = Request::builder()
            .method("POST")
            .uri("/api/admin/camps/bootstrap")
            .header(k, v)
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bootstrap_camp_rejects_delegation_bound_to_mismatch_with_400() {
        let (app, minter, _, keys, _) = rig();
        let user_a = PrincipalId::user("alice");
        let user_b = PrincipalId::user("bob");
        let kp_b = keypair_from_seed(8);
        // Trust kp_b for BOTH users — so the rejection is the
        // bound_to mismatch, not the trust-binding check firing first.
        trust_key(&keys, &user_a, *kp_b.pk);
        trust_key(&keys, &user_b, *kp_b.pk);
        let now_s = now();
        // Delegation says bob authorised camp `c`.
        let d = signed_delegation(&kp_b, user_b.clone(), "c", now_s, now_s + 600);
        // Request asks for alice instead.
        let token = mint_warden_mcp(&minter, vec![Scope::CampAdmin], now_s);
        let body = CreateCampBootstrapBody {
            bound_to: user_a,
            desired_id: "c".into(),
            delegation: d,
        };
        let (k, v) = bearer(&token);
        let req = Request::builder()
            .method("POST")
            .uri("/api/admin/camps/bootstrap")
            .header(k, v)
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn bootstrap_camp_rejects_duplicate_camp_id_with_409() {
        let (app, minter, _, keys, _) = rig();
        let user = PrincipalId::user("alice");
        let kp = keypair_from_seed(9);
        trust_key(&keys, &user, *kp.pk);
        let now_s = now();

        // Two delegations with the same camp_id but distinct expiry — so
        // each one is independently valid; the duplicate is the camp id
        // itself.
        let d1 = signed_delegation(&kp, user.clone(), "dup", now_s, now_s + 600);
        let d2 = signed_delegation(&kp, user.clone(), "dup", now_s + 10, now_s + 700);

        let token = mint_warden_mcp(&minter, vec![Scope::CampAdmin], now_s);
        let make_req = |d: UserDelegation, t: &str| {
            let body = CreateCampBootstrapBody {
                bound_to: user.clone(),
                desired_id: "dup".into(),
                delegation: d,
            };
            let (k, v) = bearer(t);
            Request::builder()
                .method("POST")
                .uri("/api/admin/camps/bootstrap")
                .header(k, v)
                .header(header::CONTENT_TYPE, "application/json")
                .body(json_body(&body))
                .unwrap()
        };
        let resp = app.clone().oneshot(make_req(d1, &token)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let resp = app.oneshot(make_req(d2, &token)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    // ---- request-shape rejections (axum body parsing) --------------------

    #[tokio::test]
    async fn bootstrap_camp_rejects_unprefixed_bound_to_at_parse_time() {
        // PrincipalId rejects unprefixed strings — axum's body parser
        // surfaces that as 400 with a JSON-decode error.
        let (app, minter, _, _, _) = rig();
        let now_s = now();
        let token = mint_warden_mcp(&minter, vec![Scope::CampAdmin], now_s);
        let raw_body = format!(
            r#"{{
                "bound_to":"alice",
                "desired_id":"c",
                "delegation": {{
                    "bound_to":"user:alice",
                    "camp_id":"c",
                    "issued_at":{0},
                    "expires_at":{1},
                    "user_signing_key":"{2}",
                    "signature":"{2}{2}"
                }}
            }}"#,
            now_s,
            now_s + 600,
            // 32 'A' base64url decoded = 24 bytes (length mismatch, but
            // bound_to parsing fails first).
            "A".repeat(32),
        );
        let (k, v) = bearer(&token);
        let req = Request::builder()
            .method("POST")
            .uri("/api/admin/camps/bootstrap")
            .header(k, v)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(raw_body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // axum returns 422 Unprocessable Entity for JSON body errors when
        // the Json extractor is the failure point; assert it's a 4xx not a
        // 2xx — the exact code is axum's call.
        assert!(
            resp.status().is_client_error(),
            "expected 4xx, got {}",
            resp.status()
        );
    }

    // ---- response shape ---------------------------------------------------

    #[tokio::test]
    async fn bootstrap_response_serializes_principal_and_credential() {
        let (app, minter, _, keys, _) = rig();
        let user = PrincipalId::user("alice");
        let kp = keypair_from_seed(10);
        trust_key(&keys, &user, *kp.pk);
        let now_s = now();
        let d = signed_delegation(&kp, user.clone(), "c-encoded", now_s, now_s + 600);
        let token = mint_warden_mcp(&minter, vec![Scope::CampAdmin], now_s);
        let body = CreateCampBootstrapBody {
            bound_to: user.clone(),
            desired_id: "c-encoded".into(),
            delegation: d,
        };
        let (k, v) = bearer(&token);
        let req = Request::builder()
            .method("POST")
            .uri("/api/admin/camps/bootstrap")
            .header(k, v)
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let bytes = to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
        let json = std::str::from_utf8(&bytes).unwrap();
        assert!(json.contains("\"id\":\"camp:c-encoded\""), "{json}");
        assert!(json.contains("\"bound_to\":\"user:alice\""), "{json}");
        assert!(json.contains("\"token\":\""), "{json}");

        // Round-trip the response shape.
        let payload: CampBootstrapResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payload.principal.kind(), PrincipalKind::Camp);
        assert!(!payload.credential.token.is_empty());
    }
}
