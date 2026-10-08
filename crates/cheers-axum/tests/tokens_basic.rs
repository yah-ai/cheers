//! Integration tests for the `/me/tokens` routes (R728-F1, R728-F2).
//!
//! The rig is the real thing on both sides of the boundary: a session is
//! established through a real [`SessionAuthority`] and presented as a real
//! bearer, and the PAT that comes back is a real `v4.public` token which the
//! test verifies with `PasetoV4PublicVerifier::verify_mcp_at` — the same call
//! a resource server makes. Nothing is hand-constructed.
//!
//! What is pinned here, beyond the happy path:
//!
//! 1. The secret is returned exactly once — `GET /me/tokens` carries metadata
//!    only, and nothing in the store can reproduce it.
//! 2. Attenuation: a requested scope the caller does not hold is a 400 that
//!    NAMES it, not a silently narrower token.
//! 3. Revoke kills both halves — the revocation set (what the edge reads) and
//!    the metadata row (what the user sees).
//! 4. A revoked PAT is byte-for-byte indistinguishable from a garbage one at
//!    the door, and so is a PAT presented where a session belongs.
//! 5. R728-F2 — the PAT door. A caller holding only a PAT can list, revoke and
//!    rotate; `POST /me/tokens` still refuses one. A rotation's scopes come
//!    from the presented token and never from the grant table, a PAT rolls
//!    only itself, and a dead token cannot be rolled back to life.
//! 6. R728-F2 — the uniform 401 now spans BOTH verifiers: seven different
//!    reasons to refuse, one byte-identical body.

use std::sync::Arc;
use cheers_core::yah_scopes;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use cheers_core::{AuthStrength, DeviceBinding, DeviceId, Scope, UserId};
use cheers_server::{
    McpAuthority, MemoryAuditStore, MemoryBundleStore, SchemaGrantStore, MemoryUserTokenStore,
    PasetoV4PublicVerifier, PasetoV4SecretMinter, RevocationReader, SessionAuthority,
    SessionPolicy, UserTokenStore,
};
use tower::ServiceExt;

use cheers_axum::me::SessionRecorder;
use cheers_axum::tokens::{router as tokens_router, ApiTokenTrust, MeTokensState};

use crate::common::{
    body_to_string, MemOwnershipStore, MemRefreshStore, MemRevocations, MemSessionDirectory,
    MemUserStore, test_edge, test_minter,
};

/// `kid` the rig's mint authority stamps; `verify_mcp_at` must be handed the
/// same value.
const RIG_KID: &str = "tokens-basic-test-kid";
const RIG_ISS: &str = "https://cheers.test";
const AUD: &str = "https://kamaji.test";
/// The audiences yah's namespaces are bound to in this rig. Anything else
/// (`https://not-granted.test`) is an audience no derived grant reaches.
const BOUND_AUDS: [&str; 2] = [AUD, "https://somewhere-else.test"];

type TestAuthority =
    SessionAuthority<cheers_server::HmacBlobCodec, MemRefreshStore, MemUserStore, MemRevocations>;
type TestMcpAuthority = McpAuthority<
    MemoryBundleStore,
    SchemaGrantStore<Arc<MemOwnershipStore>>,
    Arc<MemOwnershipStore>,
>;

/// Grants are ownership tuples: `kind/grant#<scope>` unlocks that scope.
const GRANT_KIND: &str = "grant";
const GRANT_SCHEMA: cheers_core::ResourceSchema = cheers_core::ResourceSchema {
    kind: GRANT_KIND,
    relations: &[],
    kind_relations: &[
        cheers_core::RelationDef {
            name: "cloud:read",
            membership: true,
            implies: &[],
            scopes: &[yah_scopes::CLOUD_READ],
            grants: &[],
        },
        cheers_core::RelationDef {
            name: "cloud:deploy",
            membership: true,
            implies: &[],
            scopes: &[yah_scopes::CLOUD_DEPLOY],
            grants: &[],
        },
        cheers_core::RelationDef {
            name: "cloud:destroy",
            membership: true,
            implies: &[],
            scopes: &[yah_scopes::CLOUD_DESTROY],
            grants: &[],
        },
    ],
};

fn schema_grants(ownership: &Arc<MemOwnershipStore>) -> SchemaGrantStore<Arc<MemOwnershipStore>> {
    let scopes = Arc::new(yah_scopes::registry_at(BOUND_AUDS).unwrap());
    let schema = cheers_core::SchemaRegistry::build(&[GRANT_SCHEMA], &scopes).expect("schema");
    SchemaGrantStore::new(ownership.clone(), Arc::new(schema), scopes)
}

fn seed_scopes(ownership: &MemOwnershipStore, principal: cheers_core::PrincipalId, scopes: &[Scope]) {
    for scope in scopes {
        let n = cheers_server::NewOwnership::new(
            principal.clone(),
            cheers_core::KIND_RESOURCE,
            GRANT_KIND,
            scope.as_wire(),
            cheers_core::PrincipalId::service("seed"),
            None,
        )
        .unwrap();
        pollster::block_on(cheers_server::OwnershipStore::insert(ownership, &n, 1)).unwrap();
    }
}

struct Rig {
    app: Router,
    /// The mint key's raw secret, kept so a test can build a SECOND authority
    /// that signs identically but claims a different `iss` — the only way to
    /// exercise the issuer half of the trust policy without the signature
    /// failing first.
    mint_secret: [u8; 64],
    session_authority: Arc<TestAuthority>,
    directory: Arc<MemSessionDirectory>,
    mcp: Arc<TestMcpAuthority>,
    ownership: Arc<MemOwnershipStore>,
    tokens: MemoryUserTokenStore,
    revocations: MemRevocations,
    audit: Arc<MemoryAuditStore>,
    verifier: PasetoV4PublicVerifier,
}

fn rig() -> Rig {
    let revocations = MemRevocations::default();
    let session_authority = Arc::new(
        SessionAuthority::new(
            test_minter(),
            MemRefreshStore::default(),
            MemUserStore::default(),
            revocations.clone(),
        )
        .with_policy(SessionPolicy::default().with_access_ttl(60)),
    );
    let directory = Arc::new(MemSessionDirectory::default());

    let (minter, verifier) = PasetoV4SecretMinter::generate().expect("generate mint keypair");
    // The PAT door verifies with the same published key the mint authority
    // signs with — a second copy of the same public half, not a second key.
    let pat_verifier = minter.verifier().expect("derive pat verifier");
    let mint_secret: [u8; 64] = minter
        .secret_key_bytes()
        .try_into()
        .expect("v4 secret key is 64 bytes");
    let ownership = Arc::new(MemOwnershipStore::default());
    let mcp = Arc::new(McpAuthority::new(
        minter,
        MemoryBundleStore::with_defaults(),
        schema_grants(&ownership),
        ownership.clone(),
        Arc::new(yah_scopes::registry_at(BOUND_AUDS).unwrap()),
        RIG_ISS,
        RIG_KID,
    ));

    let tokens = MemoryUserTokenStore::new();
    let audit = Arc::new(MemoryAuditStore::default());

    let state = Arc::new(MeTokensState {
        edge: Arc::new(test_edge(revocations.clone())),
        mcp: mcp.clone(),
        tokens: Arc::new(tokens.clone()) as Arc<dyn UserTokenStore>,
        revocations: Arc::new(revocations.clone()),
        audit: audit.clone() as Arc<dyn cheers_server::AuditStore>,
        pat: ApiTokenTrust::new(pat_verifier, RIG_KID, RIG_ISS),
    });
    let app = Router::new().nest("/api", tokens_router(state));

    Rig {
        app,
        mint_secret,
        session_authority,
        directory,
        mcp,
        ownership,
        tokens,
        revocations,
        audit,
        verifier,
    }
}

fn now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .expect("clock past epoch")
}

/// Establish a real session and hand back its access token.
async fn sign_in(rig: &Rig, user: &UserId) -> (String, cheers_core::Claims) {
    let session = rig
        .session_authority
        .establish(
            user.clone(),
            DeviceId::new("laptop"),
            DeviceBinding::EmailMagicLink,
            now(),
        )
        .await
        .expect("establish session");
    rig.directory
        .record_new_session(&session)
        .await
        .expect("record session");
    (session.access_token, session.claims)
}

fn grant(rig: &Rig, user: &UserId, scopes: &[Scope]) {
    grant_for(rig, user, AUD, scopes);
}

/// `aud` is documentation only: yah scopes are valid at every audience, so a
/// derived grant is held wherever the registry allows it.
fn grant_for(rig: &Rig, user: &UserId, _aud: &str, scopes: &[Scope]) {
    seed_scopes(&rig.ownership, cheers_core::PrincipalId::user(user.as_str()), scopes);
}

fn post(bearer: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/me/tokens")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn get(bearer: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri("/api/me/tokens")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .body(Body::empty())
        .unwrap()
}

fn del(bearer: &str, id: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(format!("/api/me/tokens/{id}"))
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .body(Body::empty())
        .unwrap()
}

fn rotate(bearer: &str, id: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/api/me/tokens/{id}/rotate"))
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// A rotate with no body at all — the shape `curl -X POST .../rotate` sends.
/// Credential maintenance must not require a request body to say "same again".
fn rotate_bare(bearer: &str, id: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/api/me/tokens/{id}/rotate"))
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .body(Body::empty())
        .unwrap()
}

async fn json_of(resp: axum::response::Response) -> serde_json::Value {
    let body = body_to_string(resp.into_body()).await;
    serde_json::from_str(&body).unwrap_or_else(|e| panic!("not json: {body} ({e})"))
}

// ---------------------------------------------------------------------------
// Mint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mint_returns_a_real_mcp_token_carrying_api_token_strength() {
    let rig = rig();
    let user = UserId::new("alice");
    grant(&rig, &user, &[yah_scopes::CLOUD_READ, yah_scopes::CLOUD_DEPLOY]);
    let (bearer, _) = sign_in(&rig, &user).await;

    let resp = rig
        .app
        .clone()
        .oneshot(post(&bearer, serde_json::json!({"name": "ci", "aud": AUD})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = json_of(resp).await;

    let secret = body["token"].as_str().expect("token in mint response");
    let id = body["id"].as_str().expect("id in mint response").to_owned();
    assert_eq!(body["name"], "ci");
    assert_eq!(body["aud"], AUD);

    // It is a real token on the existing stack: same signing key, same
    // envelope, verifiable by the ordinary MCP verifier with no new path.
    let claims = rig
        .verifier
        .verify_mcp_at(secret, now() + 10, RIG_KID)
        .expect("minted PAT verifies at the edge");
    assert_eq!(claims.jti, id, "the response id IS the token's jti");
    assert_eq!(claims.sub, cheers_core::PrincipalId::user("alice"));
    assert_eq!(claims.auth_strength, Some(AuthStrength::ApiToken));
    assert_eq!(claims.aud, AUD);

    // Default TTL: 90 days, deliberately not session-shaped (the rig's
    // session access TTL is 60 seconds).
    let ttl = claims.exp - claims.iat;
    assert_eq!(ttl, 90 * 24 * 60 * 60);

    // Metadata row landed, and it holds no secret to leak.
    let row = rig.tokens.get(&id).await.unwrap().expect("metadata row");
    assert_eq!(row.user_id, user);
    assert_eq!(row.name, "ci");
    assert!(!row.revoked);
    assert_eq!(row.last_used_at, None);

    // Mint is audited.
    assert_eq!(rig.audit.snapshot().len(), 1);
}

/// The secret is returned once and is unreproducible: no store holds it and
/// no hash of it, because verification is by signature.
#[tokio::test]
async fn the_secret_is_returned_exactly_once_and_never_appears_in_the_list() {
    let rig = rig();
    let user = UserId::new("alice");
    grant(&rig, &user, &[yah_scopes::CLOUD_READ]);
    let (bearer, _) = sign_in(&rig, &user).await;

    let created = json_of(
        rig.app
            .clone()
            .oneshot(post(&bearer, serde_json::json!({"name": "ci", "aud": AUD})))
            .await
            .unwrap(),
    )
    .await;
    let secret = created["token"].as_str().unwrap().to_owned();

    let resp = rig.app.clone().oneshot(get(&bearer)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let raw = body_to_string(resp.into_body()).await;

    assert!(
        !raw.contains(&secret),
        "the mint secret must never come back from the list: {raw}"
    );
    let rows: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 1);
    assert_eq!(rows[0]["name"], "ci");
    assert_eq!(rows[0]["id"], created["id"]);
    assert!(rows[0].get("token").is_none());
    assert_eq!(rows[0]["last_used_at"], serde_json::Value::Null);
}

#[tokio::test]
async fn requested_scopes_are_intersected_and_omitting_them_takes_everything_held() {
    let rig = rig();
    let user = UserId::new("alice");
    grant(
        &rig,
        &user,
        &[yah_scopes::CLOUD_READ, yah_scopes::CLOUD_DEPLOY, yah_scopes::CLOUD_DESTROY],
    );
    let (bearer, _) = sign_in(&rig, &user).await;

    // Narrow: exactly what was asked for, a strict subset of the grant.
    let narrow = json_of(
        rig.app
            .clone()
            .oneshot(post(
                &bearer,
                serde_json::json!({"name": "ro", "aud": AUD, "scopes": ["cloud:read"]}),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(narrow["scopes"], serde_json::json!(["cloud:read"]));

    // Omitted: everything currently held for this aud.
    let wide = json_of(
        rig.app
            .clone()
            .oneshot(post(&bearer, serde_json::json!({"name": "all", "aud": AUD})))
            .await
            .unwrap(),
    )
    .await;
    let got: Vec<&str> = wide["scopes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(got.len(), 3);
    for want in ["cloud:read", "cloud:deploy", "cloud:destroy"] {
        assert!(got.contains(&want), "missing {want} in {got:?}");
    }
}

/// A scope the caller does not hold is a 400 that names it. Silently dropping
/// it would hand back a token quietly weaker than the one requested, which
/// fails days later somewhere else as an unexplained 403.
#[tokio::test]
async fn an_unheld_scope_is_a_400_naming_it_not_a_silently_narrower_token() {
    let rig = rig();
    let user = UserId::new("alice");
    grant(&rig, &user, &[yah_scopes::CLOUD_READ]);
    let (bearer, _) = sign_in(&rig, &user).await;

    let resp = rig
        .app
        .clone()
        .oneshot(post(
            &bearer,
            serde_json::json!({
                "name": "greedy",
                "aud": AUD,
                "scopes": ["cloud:read", "cloud:destroy", "camp:admin"]
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = json_of(resp).await;
    assert_eq!(body["error"], "unentitled_scopes");
    let msg = body["message"].as_str().unwrap();
    assert!(msg.contains("cloud:destroy"), "{msg}");
    assert!(msg.contains("camp:admin"), "{msg}");

    // Nothing was minted or recorded.
    assert!(rig.tokens.is_empty());
    assert_eq!(rig.audit.snapshot().len(), 0);
}

#[tokio::test]
async fn an_aud_with_no_grant_at_all_is_403_and_a_bad_ttl_or_name_is_400() {
    let rig = rig();
    let user = UserId::new("alice");
    grant(&rig, &user, &[yah_scopes::CLOUD_READ]);
    let (bearer, _) = sign_in(&rig, &user).await;

    // The tuple derives cloud:read, but `cloud` is bound only to BOUND_AUDS:
    // the audience lock is the registry binding.
    let resp = rig
        .app
        .clone()
        .oneshot(post(
            &bearer,
            serde_json::json!({"name": "x", "aud": "https://not-granted.test"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_of(resp).await["error"], "aud_not_entitled");

    // Over the 365-day ceiling: rejected, never clamped.
    let resp = rig
        .app
        .clone()
        .oneshot(post(
            &bearer,
            serde_json::json!({
                "name": "forever",
                "aud": AUD,
                "expires_in_secs": 366 * 24 * 60 * 60i64
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_of(resp).await["error"], "invalid_token_request");

    // Empty name: a token list nobody can read is not a token list.
    let resp = rig
        .app
        .clone()
        .oneshot(post(
            &bearer,
            serde_json::json!({"name": "   ", "aud": AUD}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_of(resp).await["error"], "invalid_token_request");

    // A wildcard scope dies at the request boundary (composition rule (1)).
    let resp = rig
        .app
        .clone()
        .oneshot(post(
            &bearer,
            serde_json::json!({"name": "star", "aud": AUD, "scopes": ["cloud:*"]}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    assert!(rig.tokens.is_empty());
}

#[tokio::test]
async fn an_honoured_expires_in_secs_lands_on_the_signed_claim() {
    let rig = rig();
    let user = UserId::new("alice");
    grant(&rig, &user, &[yah_scopes::CLOUD_READ]);
    let (bearer, _) = sign_in(&rig, &user).await;

    let body = json_of(
        rig.app
            .clone()
            .oneshot(post(
                &bearer,
                serde_json::json!({"name": "week", "aud": AUD, "expires_in_secs": 604_800}),
            ))
            .await
            .unwrap(),
    )
    .await;
    let claims = rig
        .verifier
        .verify_mcp_at(body["token"].as_str().unwrap(), now() + 10, RIG_KID)
        .unwrap();
    assert_eq!(claims.exp - claims.iat, 604_800);
    assert_eq!(body["expires_at"], claims.exp);
}

// ---------------------------------------------------------------------------
// List + revoke
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_shows_only_the_callers_own_live_tokens() {
    let rig = rig();
    let alice = UserId::new("alice");
    let bob = UserId::new("bob");
    grant(&rig, &alice, &[yah_scopes::CLOUD_READ]);
    grant(&rig, &bob, &[yah_scopes::CLOUD_READ]);
    let (a_bearer, _) = sign_in(&rig, &alice).await;
    let (b_bearer, _) = sign_in(&rig, &bob).await;

    for (bearer, name) in [(&a_bearer, "a1"), (&a_bearer, "a2"), (&b_bearer, "b1")] {
        let resp = rig
            .app
            .clone()
            .oneshot(post(bearer, serde_json::json!({"name": name, "aud": AUD})))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    let rows = json_of(rig.app.clone().oneshot(get(&a_bearer)).await.unwrap()).await;
    let names: Vec<&str> = rows
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), 2);
    assert!(names.contains(&"a1") && names.contains(&"a2"));

    let rows = json_of(rig.app.clone().oneshot(get(&b_bearer)).await.unwrap()).await;
    assert_eq!(rows.as_array().unwrap().len(), 1);
    assert_eq!(rows[0]["name"], "b1");
}

#[tokio::test]
async fn revoke_kills_both_halves_and_the_token_drops_out_of_the_list() {
    let rig = rig();
    let user = UserId::new("alice");
    grant(&rig, &user, &[yah_scopes::CLOUD_READ]);
    let (bearer, _) = sign_in(&rig, &user).await;

    let created = json_of(
        rig.app
            .clone()
            .oneshot(post(&bearer, serde_json::json!({"name": "ci", "aud": AUD})))
            .await
            .unwrap(),
    )
    .await;
    let id = created["id"].as_str().unwrap().to_owned();
    assert!(!rig.revocations.is_revoked(&id).await.unwrap());

    let resp = rig.app.clone().oneshot(del(&bearer, &id)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Half one: the revocation set the edge actually reads.
    assert!(rig.revocations.is_revoked(&id).await.unwrap());
    // Half two: the metadata row, so GET tells the truth.
    assert!(rig.tokens.get(&id).await.unwrap().unwrap().revoked);
    let rows = json_of(rig.app.clone().oneshot(get(&bearer)).await.unwrap()).await;
    assert!(rows.as_array().unwrap().is_empty());

    // Revocation is not deletion: the row survives, so a second revoke of
    // your own token is still 204, not a 404 about someone else's id.
    let resp = rig.app.clone().oneshot(del(&bearer, &id)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Mint + two revokes audited.
    assert_eq!(rig.audit.snapshot().len(), 3);
}

/// Unknown id and another user's id are the same answer, for the same reason
/// `DELETE /me/sessions` gives: a probe must not be able to enumerate token
/// ids it does not own.
#[tokio::test]
async fn revoking_a_foreign_or_unknown_token_is_an_identical_404() {
    let rig = rig();
    let alice = UserId::new("alice");
    let bob = UserId::new("bob");
    grant(&rig, &bob, &[yah_scopes::CLOUD_READ]);
    let (a_bearer, _) = sign_in(&rig, &alice).await;
    let (b_bearer, _) = sign_in(&rig, &bob).await;

    let bobs = json_of(
        rig.app
            .clone()
            .oneshot(post(&b_bearer, serde_json::json!({"name": "b", "aud": AUD})))
            .await
            .unwrap(),
    )
    .await;
    let bob_id = bobs["id"].as_str().unwrap().to_owned();

    let foreign = rig
        .app
        .clone()
        .oneshot(del(&a_bearer, &bob_id))
        .await
        .unwrap();
    let unknown = rig
        .app
        .clone()
        .oneshot(del(&a_bearer, "no-such-token-id"))
        .await
        .unwrap();

    assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        body_to_string(foreign.into_body()).await,
        body_to_string(unknown.into_body()).await,
        "'not yours' and 'does not exist' must be indistinguishable"
    );

    // Bob's token is untouched.
    assert!(!rig.revocations.is_revoked(&bob_id).await.unwrap());
    assert!(!rig.tokens.get(&bob_id).await.unwrap().unwrap().revoked);
}

// ---------------------------------------------------------------------------
// The door
// ---------------------------------------------------------------------------

/// Every way of failing the door produces the SAME status and the SAME body
/// bytes. Anything else is an oracle: "revoked" vs "forged" tells an attacker
/// their stolen token was real.
#[tokio::test]
async fn every_authentication_failure_is_byte_identical() {
    let rig = rig();
    let user = UserId::new("alice");
    grant(&rig, &user, &[yah_scopes::CLOUD_READ]);
    let (bearer, claims) = sign_in(&rig, &user).await;

    // A real PAT of this user, which we then kill — the "revoked PAT" arm.
    let created = json_of(
        rig.app
            .clone()
            .oneshot(post(&bearer, serde_json::json!({"name": "ci", "aud": AUD})))
            .await
            .unwrap(),
    )
    .await;
    let revoked_pat = created["token"].as_str().unwrap().to_owned();
    cheers_server::RevocationWriter::revoke(
        &rig.revocations,
        &cheers_core::Revoked::jti(created["id"].as_str().unwrap(), None),
    )
    .await
    .unwrap();

    // Already past its `exp` when minted — same key, same kid, same issuer.
    let expired_pat = rig
        .mcp
        .mint_api_token(
            cheers_core::PrincipalId::user(user.as_str()),
            AUD,
            &[],
            Some(1),
            now() - 10_000,
        )
        .await
        .expect("mint an already-expired PAT")
        .token;

    // Valid in every respect except that a key this surface does not trust
    // signed it.
    let foreign_key_pat = foreign_authority(None, None)
        .mint_api_token(
            cheers_core::PrincipalId::user(user.as_str()),
            AUD,
            &[],
            None,
            now(),
        )
        .await
        .expect("mint with a foreign key")
        .token;

    // The subtlest arm: OUR key, OUR kid, a valid signature — and an issuer
    // this surface does not trust. Only the trust policy can catch it.
    let foreign_iss_pat = foreign_authority(Some(&rig.mint_secret), Some("https://evil.test"))
        .mint_api_token(
            cheers_core::PrincipalId::user(user.as_str()),
            AUD,
            &[],
            None,
            now(),
        )
        .await
        .expect("mint with a foreign iss")
        .token;

    // A perfectly valid MCP token whose subject is not a user at all.
    grant_camp(&rig, "c1", &[yah_scopes::CLOUD_READ]);
    let camp_token = rig
        .mcp
        .mint_bootstrap(cheers_core::PrincipalId::camp("c1"), AUD, now())
        .await
        .expect("mint a camp token")
        .token;

    // Revoke the caller's session so the same bytes that worked a moment ago
    // now fail — the "revoked session" arm.
    rig.session_authority
        .revoke_session(&claims.jti, claims.expires_at)
        .await
        .unwrap();

    let arms = [
        ("revoked session", bearer.as_str()),
        ("garbage", "garbage"),
        ("revoked PAT", revoked_pat.as_str()),
        ("expired PAT", expired_pat.as_str()),
        ("foreign-key PAT", foreign_key_pat.as_str()),
        ("foreign-iss PAT", foreign_iss_pat.as_str()),
        ("camp token", camp_token.as_str()),
    ];

    let mut seen = Vec::new();
    for (label, token) in arms {
        let resp = rig.app.clone().oneshot(get(token)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "arm: {label}");
        seen.push((label, body_to_string(resp.into_body()).await));
    }
    for (label, body) in &seen {
        assert_eq!(
            body, &seen[0].1,
            "arm '{label}' is distinguishable from '{}' — a door that tells you WHY it refused is an oracle",
            seen[0].0
        );
    }
    assert_eq!(seen[0].1, r#"{"error":"unauthorized","message":"unauthorized"}"#);
}

/// A second mint authority, for the arms that need a token this surface must
/// refuse. `secret: None` ⇒ a fresh key (wrong signature); `iss: None` ⇒ the
/// rig's own issuer. Everything else — the `kid`, the claim shape — matches
/// the rig exactly, so each arm isolates ONE reason to refuse.
fn foreign_authority(secret: Option<&[u8; 64]>, iss: Option<&str>) -> TestMcpAuthority {
    let minter = match secret {
        Some(bytes) => PasetoV4SecretMinter::from_secret_key(bytes).expect("rebuild minter"),
        None => PasetoV4SecretMinter::generate().expect("generate").0,
    };
    let ownership = Arc::new(MemOwnershipStore::default());
    seed_scopes(&ownership, cheers_core::PrincipalId::user("alice"), &[yah_scopes::CLOUD_READ]);
    McpAuthority::new(
        minter,
        MemoryBundleStore::with_defaults(),
        schema_grants(&ownership),
        ownership,
        Arc::new(yah_scopes::registry_at(BOUND_AUDS).unwrap()),
        iss.unwrap_or(RIG_ISS),
        RIG_KID,
    )
}

fn grant_camp(rig: &Rig, camp: &str, scopes: &[Scope]) {
    seed_scopes(&rig.ownership, cheers_core::PrincipalId::camp(camp), scopes);
}

/// A PAT cannot mint a PAT, and it is structural rather than a check: the two
/// PASETO claim shapes are distinct, so a PAT presented to `POST /me/tokens`
/// never reaches an `auth_strength` branch that could be forgotten.
#[tokio::test]
async fn a_pat_cannot_mint_a_pat() {
    let rig = rig();
    let user = UserId::new("alice");
    grant(&rig, &user, &[yah_scopes::CLOUD_READ]);
    let (bearer, _) = sign_in(&rig, &user).await;

    let pat = json_of(
        rig.app
            .clone()
            .oneshot(post(&bearer, serde_json::json!({"name": "ci", "aud": AUD})))
            .await
            .unwrap(),
    )
    .await["token"]
        .as_str()
        .unwrap()
        .to_owned();

    // The PAT is genuinely valid as an MCP token — this is not a "broken
    // token" test.
    assert!(rig.verifier.verify_mcp_at(&pat, now() + 10, RIG_KID).is_ok());

    let resp = rig
        .app
        .clone()
        .oneshot(post(&pat, serde_json::json!({"name": "child", "aud": AUD})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(rig.tokens.len(), 1, "no second token was minted");
}

/// A PAT outlives the grant that authorized it — an already-signed token does
/// not shrink when the grant table changes. That is exactly why revocation
/// and the TTL ceiling exist, and it is worth pinning so nobody "fixes" it by
/// re-reading grants on the verify path.
#[tokio::test]
async fn a_minted_pat_is_frozen_and_does_not_track_later_grant_edits() {
    let rig = rig();
    let user = UserId::new("alice");
    grant(&rig, &user, &[yah_scopes::CLOUD_READ, yah_scopes::CLOUD_DEPLOY]);
    let (bearer, _) = sign_in(&rig, &user).await;

    let created = json_of(
        rig.app
            .clone()
            .oneshot(post(&bearer, serde_json::json!({"name": "ci", "aud": AUD})))
            .await
            .unwrap(),
    )
    .await;
    let secret = created["token"].as_str().unwrap().to_owned();

    // Grant shrinks to nothing.
    pollster::block_on(cheers_server::OwnershipStore::revoke_by_principal(
        &*rig.ownership,
        &cheers_core::PrincipalId::user("alice"),
        2,
    ))
    .unwrap();

    // A fresh mint now fails...
    let resp = rig
        .app
        .clone()
        .oneshot(post(&bearer, serde_json::json!({"name": "later", "aud": AUD})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // ...but the already-signed token still verifies with its old scopes.
    let claims = rig
        .verifier
        .verify_mcp_at(&secret, now() + 10, RIG_KID)
        .expect("a signed token does not un-sign itself");
    assert_eq!(claims.scope.len(), 2);

    // Which is what revocation is for.
    let id = created["id"].as_str().unwrap();
    let resp = rig.app.clone().oneshot(del(&bearer, id)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(rig.revocations.is_revoked(id).await.unwrap());

    let _ = &rig.mcp;
}

// ---------------------------------------------------------------------------
// R728-F2 — the PAT door: list, revoke and rotate with only a PAT in hand
// ---------------------------------------------------------------------------

/// The operator's requirement, end to end: a credential that holds nothing but
/// itself can see itself and end itself, with no browser anywhere.
#[tokio::test]
async fn a_pat_can_list_and_revoke_with_no_session_at_all() {
    let rig = rig();
    let user = UserId::new("alice");
    grant(&rig, &user, &[yah_scopes::CLOUD_READ]);
    let (bearer, _) = sign_in(&rig, &user).await;

    let created = json_of(
        rig.app
            .clone()
            .oneshot(post(&bearer, serde_json::json!({"name": "ci", "aud": AUD})))
            .await
            .unwrap(),
    )
    .await;
    let pat = created["token"].as_str().unwrap().to_owned();
    let id = created["id"].as_str().unwrap().to_owned();

    // LIST, on the PAT alone.
    let resp = rig.app.clone().oneshot(get(&pat)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let rows = json_of(resp).await;
    assert_eq!(rows.as_array().unwrap().len(), 1);
    assert_eq!(rows[0]["id"], id.as_str());
    assert!(rows[0].get("token").is_none(), "still metadata only");

    // REVOKE, on the PAT alone — the token killing itself.
    let resp = rig.app.clone().oneshot(del(&pat, &id)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(rig.revocations.is_revoked(&id).await.unwrap());

    // And it is now as anonymous as noise: the same bytes that worked one
    // request ago are the uniform 401.
    let resp = rig.app.clone().oneshot(get(&pat)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// The permissive `aud` call, pinned. A PAT minted for kamaji manages
/// credentials at cheers, because nothing these verbs do is an action at an
/// audience. If someone later adds an `expected_aud` to `ApiTokenTrust`, this
/// is the test that will tell them they broke every rig token's ability to
/// roll itself.
#[tokio::test]
async fn a_pat_minted_for_another_audience_still_manages_credentials() {
    let rig = rig();
    let user = UserId::new("alice");
    const OTHER_AUD: &str = "https://somewhere-else.test";
    grant_for(&rig, &user, OTHER_AUD, &[yah_scopes::CLOUD_READ]);
    let (bearer, _) = sign_in(&rig, &user).await;

    let created = json_of(
        rig.app
            .clone()
            .oneshot(post(
                &bearer,
                serde_json::json!({"name": "rig", "aud": OTHER_AUD}),
            ))
            .await
            .unwrap(),
    )
    .await;
    let pat = created["token"].as_str().unwrap().to_owned();

    let resp = rig.app.clone().oneshot(get(&pat)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "aud is deliberately not gated");

    let resp = rig
        .app
        .clone()
        .oneshot(rotate_bare(&pat, created["id"].as_str().unwrap()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(json_of(resp).await["aud"], OTHER_AUD, "audience carries over");
}

/// Rolling itself: a new secret, the old one dead, no ceremony, no body.
#[tokio::test]
async fn rotate_replaces_the_token_and_kills_the_one_it_replaces() {
    let rig = rig();
    let user = UserId::new("alice");
    grant(&rig, &user, &[yah_scopes::CLOUD_READ, yah_scopes::CLOUD_DEPLOY]);
    let (bearer, _) = sign_in(&rig, &user).await;

    let created = json_of(
        rig.app
            .clone()
            .oneshot(post(&bearer, serde_json::json!({"name": "ci", "aud": AUD})))
            .await
            .unwrap(),
    )
    .await;
    let old_pat = created["token"].as_str().unwrap().to_owned();
    let old_id = created["id"].as_str().unwrap().to_owned();

    let resp = rig
        .app
        .clone()
        .oneshot(rotate_bare(&old_pat, &old_id))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let rolled = json_of(resp).await;
    let new_pat = rolled["token"].as_str().unwrap().to_owned();
    let new_id = rolled["id"].as_str().unwrap().to_owned();

    assert_ne!(new_id, old_id, "a rotation is a new jti, not a re-issue");
    assert_ne!(new_pat, old_pat);
    assert_eq!(rolled["name"], "ci", "the name carries over");
    assert_eq!(rolled["aud"], AUD);
    // Derived grants come back in scope order.
    assert_eq!(rolled["scopes"], serde_json::json!(["cloud:deploy", "cloud:read"]));

    // The replacement is a real token on the same stack.
    let claims = rig
        .verifier
        .verify_mcp_at(&new_pat, now() + 10, RIG_KID)
        .expect("the replacement verifies like any other PAT");
    assert_eq!(claims.jti, new_id);
    assert_eq!(claims.auth_strength, Some(AuthStrength::ApiToken));
    assert_eq!(claims.sub, cheers_core::PrincipalId::user("alice"));

    // The old one is dead in both halves.
    assert!(rig.revocations.is_revoked(&old_id).await.unwrap());
    assert!(rig.tokens.get(&old_id).await.unwrap().unwrap().revoked);
    let resp = rig.app.clone().oneshot(get(&old_pat)).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "the replaced bytes must stop working immediately"
    );

    // The new one works, and the list shows exactly one live token.
    let rows = json_of(rig.app.clone().oneshot(get(&new_pat)).await.unwrap()).await;
    assert_eq!(rows.as_array().unwrap().len(), 1);
    assert_eq!(rows[0]["id"], new_id.as_str());

    // Both ids are findable in the journal: mint, rotate-new, rotate-old.
    let audit = rig.audit.snapshot();
    assert_eq!(audit.len(), 3);
    assert!(audit.iter().any(|r| r.record.request_id == old_id));
    assert!(audit.iter().any(|r| r.record.request_id == new_id));
}

/// The invariant this endpoint most easily breaks: a rotation must mint from
/// the PRESENTED token's scopes, never from the grant table. If it re-read
/// grants, the widened grant below would silently come back inside a token
/// that was frozen narrow — which is exactly what
/// `a_minted_pat_is_frozen_and_does_not_track_later_grant_edits` forbids.
#[tokio::test]
async fn rotate_scopes_come_from_the_presented_token_not_from_current_grants() {
    let rig = rig();
    let user = UserId::new("alice");
    grant(&rig, &user, &[yah_scopes::CLOUD_READ]);
    let (bearer, _) = sign_in(&rig, &user).await;

    let created = json_of(
        rig.app
            .clone()
            .oneshot(post(
                &bearer,
                serde_json::json!({"name": "ro", "aud": AUD, "scopes": ["cloud:read"]}),
            ))
            .await
            .unwrap(),
    )
    .await;
    let pat = created["token"].as_str().unwrap().to_owned();
    let id = created["id"].as_str().unwrap().to_owned();

    // The user is granted MORE after the token was minted.
    grant(
        &rig,
        &user,
        &[yah_scopes::CLOUD_READ, yah_scopes::CLOUD_DEPLOY, yah_scopes::CLOUD_DESTROY],
    );

    // Asking for the newly-granted scope is refused BY NAME — the ceiling is
    // the token, not the table.
    let resp = rig
        .app
        .clone()
        .oneshot(rotate(&pat, &id, serde_json::json!({"scopes": ["cloud:destroy"]})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let err = json_of(resp).await;
    assert_eq!(err["error"], "unentitled_scopes");
    assert!(
        err["message"].as_str().unwrap().contains("cloud:destroy"),
        "the refusal must name the scope: {err}"
    );

    // And a plain rotation carries the frozen scope set over unchanged.
    let rolled = json_of(
        rig.app
            .clone()
            .oneshot(rotate_bare(&pat, &id))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        rolled["scopes"],
        serde_json::json!(["cloud:read"]),
        "a rotation must not widen a frozen token up to current grants"
    );
    let claims = rig
        .verifier
        .verify_mcp_at(rolled["token"].as_str().unwrap(), now() + 10, RIG_KID)
        .unwrap();
    assert_eq!(claims.scope, vec![yah_scopes::CLOUD_READ]);
}

/// Narrowing on the way through is allowed — that is how a credential sheds
/// authority it no longer needs without a browser.
#[tokio::test]
async fn rotate_can_narrow_and_rename() {
    let rig = rig();
    let user = UserId::new("alice");
    grant(&rig, &user, &[yah_scopes::CLOUD_READ, yah_scopes::CLOUD_DEPLOY]);
    let (bearer, _) = sign_in(&rig, &user).await;

    let created = json_of(
        rig.app
            .clone()
            .oneshot(post(&bearer, serde_json::json!({"name": "wide", "aud": AUD})))
            .await
            .unwrap(),
    )
    .await;
    let pat = created["token"].as_str().unwrap().to_owned();
    let id = created["id"].as_str().unwrap().to_owned();

    let rolled = json_of(
        rig.app
            .clone()
            .oneshot(rotate(
                &pat,
                &id,
                serde_json::json!({"name": "narrow", "scopes": ["cloud:read"]}),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(rolled["name"], "narrow");
    assert_eq!(rolled["scopes"], serde_json::json!(["cloud:read"]));

    // A blank rename is a 400, same as on create.
    let second = rolled["id"].as_str().unwrap().to_owned();
    let resp = rig
        .app
        .clone()
        .oneshot(rotate(
            rolled["token"].as_str().unwrap(),
            &second,
            serde_json::json!({"name": "  "}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_of(resp).await["error"], "invalid_token_request");
}

/// A PAT rolls ITSELF and nothing else. Rolling a sibling would be lateral
/// movement: a narrow credential minting a replacement for authority it does
/// not hold. The refusal is the same `unknown_token` an id that does not exist
/// gets, so a stolen token cannot probe which ids are real.
#[tokio::test]
async fn a_pat_cannot_rotate_a_token_that_is_not_its_own() {
    let rig = rig();
    let user = UserId::new("alice");
    grant(&rig, &user, &[yah_scopes::CLOUD_READ, yah_scopes::CLOUD_DEPLOY]);
    let (bearer, _) = sign_in(&rig, &user).await;

    let first = json_of(
        rig.app
            .clone()
            .oneshot(post(
                &bearer,
                serde_json::json!({"name": "a", "aud": AUD, "scopes": ["cloud:read"]}),
            ))
            .await
            .unwrap(),
    )
    .await;
    let second = json_of(
        rig.app
            .clone()
            .oneshot(post(
                &bearer,
                serde_json::json!({"name": "b", "aud": AUD, "scopes": ["cloud:deploy"]}),
            ))
            .await
            .unwrap(),
    )
    .await;

    let a_pat = first["token"].as_str().unwrap().to_owned();
    let b_id = second["id"].as_str().unwrap().to_owned();

    let resp = rig
        .app
        .clone()
        .oneshot(rotate_bare(&a_pat, &b_id))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let sibling_body = body_to_string(resp.into_body()).await;

    let resp = rig
        .app
        .clone()
        .oneshot(rotate_bare(&a_pat, "no-such-jti"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let unknown_body = body_to_string(resp.into_body()).await;

    assert_eq!(
        sibling_body, unknown_body,
        "a sibling's id must be indistinguishable from a nonexistent one"
    );
    assert_eq!(rig.tokens.len(), 2, "no replacement was minted");
    assert!(!rig.revocations.is_revoked(&b_id).await.unwrap());
}

/// A session bearer is the full interactive authority, so it may roll any of
/// the user's tokens — but only ever up to what that token already held, since
/// the row is the authority being rolled.
#[tokio::test]
async fn a_session_may_rotate_any_of_the_users_tokens_bounded_by_that_token() {
    let rig = rig();
    let user = UserId::new("alice");
    grant(&rig, &user, &[yah_scopes::CLOUD_READ, yah_scopes::CLOUD_DEPLOY]);
    let (bearer, _) = sign_in(&rig, &user).await;

    let created = json_of(
        rig.app
            .clone()
            .oneshot(post(
                &bearer,
                serde_json::json!({"name": "ro", "aud": AUD, "scopes": ["cloud:read"]}),
            ))
            .await
            .unwrap(),
    )
    .await;
    let id = created["id"].as_str().unwrap().to_owned();

    // The session holds cloud:deploy via its grants, but the TOKEN does not,
    // so a rotation cannot smuggle it in.
    let resp = rig
        .app
        .clone()
        .oneshot(rotate(&bearer, &id, serde_json::json!({"scopes": ["cloud:deploy"]})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_of(resp).await["error"], "unentitled_scopes");

    let rolled = json_of(
        rig.app
            .clone()
            .oneshot(rotate_bare(&bearer, &id))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(rolled["scopes"], serde_json::json!(["cloud:read"]));
    assert!(rig.revocations.is_revoked(&id).await.unwrap());
}

/// Rotation refreshes the clock, and the same policy ceiling a first mint is
/// held to bounds it — so a chain of rotations cannot extend authority
/// indefinitely.
#[tokio::test]
async fn rotate_gets_a_fresh_ttl_and_is_still_bounded_by_the_policy_ceiling() {
    let rig = rig();
    let user = UserId::new("alice");
    grant(&rig, &user, &[yah_scopes::CLOUD_READ]);
    let (bearer, _) = sign_in(&rig, &user).await;

    let created = json_of(
        rig.app
            .clone()
            .oneshot(post(
                &bearer,
                serde_json::json!({"name": "ci", "aud": AUD, "expires_in_secs": 3600}),
            ))
            .await
            .unwrap(),
    )
    .await;
    let pat = created["token"].as_str().unwrap().to_owned();
    let id = created["id"].as_str().unwrap().to_owned();

    // Above the ceiling: rejected, not clamped.
    let over = cheers_server::McpPolicy::MAX_API_TOKEN_TTL_SECONDS + 1;
    let resp = rig
        .app
        .clone()
        .oneshot(rotate(&pat, &id, serde_json::json!({"expires_in_secs": over})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_of(resp).await["error"], "invalid_token_request");

    // The default: a full fresh lifetime, longer than the hour the replaced
    // token had left.
    let rolled = json_of(
        rig.app
            .clone()
            .oneshot(rotate_bare(&pat, &id))
            .await
            .unwrap(),
    )
    .await;
    let claims = rig
        .verifier
        .verify_mcp_at(rolled["token"].as_str().unwrap(), now() + 10, RIG_KID)
        .unwrap();
    assert_eq!(claims.exp - claims.iat, 90 * 24 * 60 * 60);
    assert!(claims.exp > created["expires_at"].as_i64().unwrap());
}

/// A dead token cannot be rolled back to life. Revoking is how a user ends a
/// credential; if rotate accepted a revoked `jti` it would hand the authority
/// straight back, and a stolen token would survive its own revocation.
#[tokio::test]
async fn rotating_a_revoked_token_is_refused_rather_than_resurrected() {
    let rig = rig();
    let user = UserId::new("alice");
    grant(&rig, &user, &[yah_scopes::CLOUD_READ]);
    let (bearer, _) = sign_in(&rig, &user).await;

    let created = json_of(
        rig.app
            .clone()
            .oneshot(post(&bearer, serde_json::json!({"name": "ci", "aud": AUD})))
            .await
            .unwrap(),
    )
    .await;
    let id = created["id"].as_str().unwrap().to_owned();

    let resp = rig.app.clone().oneshot(del(&bearer, &id)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // The session is still perfectly valid — it is the TARGET that is dead.
    let resp = rig
        .app
        .clone()
        .oneshot(rotate_bare(&bearer, &id))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(json_of(resp).await["error"], "unknown_token");
    assert_eq!(rig.tokens.len(), 1, "nothing was minted");

    // And the PAT itself, presenting its own revoked bytes, gets the uniform
    // 401 at the door — it never even reaches the target check.
    let resp = rig
        .app
        .clone()
        .oneshot(rotate_bare(created["token"].as_str().unwrap(), &id))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// Rotating another user's token is the same `unknown_token` as an id that
/// does not exist — `DELETE`'s non-enumeration property, held on the new door.
#[tokio::test]
async fn rotating_a_foreign_users_token_is_an_identical_404() {
    let rig = rig();
    let alice = UserId::new("alice");
    let bob = UserId::new("bob");
    grant(&rig, &alice, &[yah_scopes::CLOUD_READ]);
    grant(&rig, &bob, &[yah_scopes::CLOUD_READ]);
    let (alice_bearer, _) = sign_in(&rig, &alice).await;
    let (bob_bearer, _) = sign_in(&rig, &bob).await;

    let bobs = json_of(
        rig.app
            .clone()
            .oneshot(post(&bob_bearer, serde_json::json!({"name": "bob", "aud": AUD})))
            .await
            .unwrap(),
    )
    .await;
    let bob_id = bobs["id"].as_str().unwrap().to_owned();

    let resp = rig
        .app
        .clone()
        .oneshot(rotate_bare(&alice_bearer, &bob_id))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let foreign = body_to_string(resp.into_body()).await;

    let resp = rig
        .app
        .clone()
        .oneshot(rotate_bare(&alice_bearer, "no-such-jti"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(foreign, body_to_string(resp.into_body()).await);
    assert!(!rig.revocations.is_revoked(&bob_id).await.unwrap());
}
