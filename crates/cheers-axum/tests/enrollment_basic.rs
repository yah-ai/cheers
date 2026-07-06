//! Integration tests for `POST /enrollment/node` (R593-F9).
//!
//! Round-trips via `tower::Service::call` (no TCP listener), mirroring
//! `ownership_basic.rs`'s shape but authenticating with a **session** bearer
//! ([`cheers_core::Claims`], minted through [`SessionAuthority::establish`])
//! rather than an MCP token — the load-bearing difference this route exists
//! to make possible: an end-user device authenticates with the session it
//! already holds from its own login, never a service-principal secret.

mod common;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use cheers_core::{DeviceBinding, DeviceId, PrincipalId, UserId};
use cheers_server::{OwnershipStore, SessionAuthority};
use tower::ServiceExt;

use cheers_axum::enrollment::{
    ENROLLMENT_GRANTED_BY, EnrollmentState, NODE_RESOURCE_KIND, OWNS_RELATIONSHIP,
    router as enrollment_router,
};

use crate::common::{
    MemOwnershipStore, MemRefreshStore, MemRevocations, MemUserStore, body_to_string, test_edge,
    test_minter,
};

fn now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .expect("clock past epoch")
}

type TestAuthority =
    SessionAuthority<cheers_server::HmacBlobCodec, MemRefreshStore, MemUserStore, MemRevocations>;

/// Build the full /enrollment router plus the session authority (to mint
/// fixture bearer tokens) and the ownership store (to observe rows).
fn rig() -> (Router, TestAuthority, Arc<MemOwnershipStore>) {
    let revocations = MemRevocations::default();
    let authority = SessionAuthority::new(
        test_minter(),
        MemRefreshStore::default(),
        MemUserStore::default(),
        revocations.clone(),
    );
    let edge = Arc::new(test_edge(revocations));
    let store = Arc::new(MemOwnershipStore::default());
    let state = Arc::new(EnrollmentState {
        edge,
        store: store.clone(),
    });
    let app = Router::new().nest("/api", enrollment_router(state));
    (app, authority, store)
}

fn auth(token: &str) -> String {
    format!("Bearer {token}")
}

fn post_enroll(token: &str, node_id_hex: &str) -> Request<Body> {
    let body = serde_json::json!({ "node_id": node_id_hex });
    Request::builder()
        .method("POST")
        .uri("/api/enrollment/node")
        .header(header::AUTHORIZATION, auth(token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn authenticated_session_enrolls_a_node_row_scoped_to_its_own_sub() {
    let (app, authority, store) = rig();
    let now = now();
    let session = authority
        .establish(
            UserId::new("alice"),
            DeviceId::new("phone-1"),
            DeviceBinding::Passkey,
            now,
        )
        .await
        .expect("establish session");

    let resp = app
        .clone()
        .oneshot(post_enroll(&session.access_token, "aa11bb22"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let returned: serde_json::Value =
        serde_json::from_str(&body_to_string(resp.into_body()).await).unwrap();

    // The row is scoped entirely from the verified session — none of these
    // fields could be forged via the request body, which only ever carries
    // node_id.
    assert_eq!(
        returned.get("principal_id").and_then(|v| v.as_str()),
        Some("user:alice")
    );
    assert_eq!(
        returned.get("resource_kind").and_then(|v| v.as_str()),
        Some(NODE_RESOURCE_KIND)
    );
    assert_eq!(
        returned.get("relationship").and_then(|v| v.as_str()),
        Some(OWNS_RELATIONSHIP)
    );
    assert_eq!(
        returned.get("resource_id").and_then(|v| v.as_str()),
        Some("aa11bb22")
    );
    assert_eq!(
        returned.get("granted_by").and_then(|v| v.as_str()),
        Some(format!("svc:{ENROLLMENT_GRANTED_BY}").as_str()),
    );
    assert_eq!(
        returned.get("on_behalf_of").and_then(|v| v.as_str()),
        Some("user:alice")
    );

    // The store really has it, discoverable via list_for_principal like any
    // other ownership row.
    let rows = store
        .list_for_principal(&PrincipalId::user("alice"))
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].resource_id, "aa11bb22");
}

#[tokio::test]
async fn missing_bearer_is_401_before_any_store_call() {
    let (app, _authority, store) = rig();
    let body = serde_json::json!({ "node_id": "aa11bb22" });
    let req = Request::builder()
        .method("POST")
        .uri("/api/enrollment/node")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(store.insert_call_count(), 0);
}

#[tokio::test]
async fn an_mcp_token_is_rejected_not_a_session_bearer() {
    // The whole point of this route is that it verifies the SESSION shape
    // (Claims via the HmacBlobCodec test edge), not an MCP token — even one
    // that (hypothetically) carried ownership:write. A v4.public MCP-shaped
    // PASETO from an entirely different minter/encoding must not
    // authenticate here; this is the same "shapes can't be confused"
    // property cheers_axum::mcp pins from the other direction.
    let (app, _authority, store) = rig();
    let now = now();
    use cheers_core::{AuthStrength, McpClaims, Scope};
    use cheers_server::PasetoV4SecretMinter;
    let (mcp_minter, _verifier) = PasetoV4SecretMinter::generate().unwrap();
    let claims = McpClaims::new(
        "https://cheers.example",
        "https://cheers.example",
        PrincipalId::service("yubaba"),
        now,
        now + 60,
        "jti-mcp",
        vec![Scope::OwnershipWrite],
    )
    .with_auth_strength(AuthStrength::Bootstrap);
    let token = mcp_minter.mint_mcp(&claims, "some-kid").unwrap();

    let resp = app
        .oneshot(post_enroll(&token, "aa11bb22"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(store.insert_call_count(), 0);
}

#[tokio::test]
async fn repairing_the_same_device_is_idempotent_one_live_row() {
    let (app, authority, store) = rig();
    let now = now();
    let session = authority
        .establish(
            UserId::new("bob"),
            DeviceId::new("mac-1"),
            DeviceBinding::Passkey,
            now,
        )
        .await
        .expect("establish session");

    let resp = app
        .clone()
        .oneshot(post_enroll(&session.access_token, "cc33dd44"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let first: serde_json::Value =
        serde_json::from_str(&body_to_string(resp.into_body()).await).unwrap();

    let resp = app
        .clone()
        .oneshot(post_enroll(&session.access_token, "cc33dd44"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "re-pair converges, not a fresh insert");
    let second: serde_json::Value =
        serde_json::from_str(&body_to_string(resp.into_body()).await).unwrap();
    assert_eq!(first["id"], second["id"]);
    assert_eq!(store.insert_call_count(), 1);

    let rows = store
        .list_for_principal(&PrincipalId::user("bob"))
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "no duplicate row stacked: {rows:?}");
}

#[tokio::test]
async fn repairing_under_a_different_user_evicts_the_previous_owners_row_q6() {
    // W268 Q6 eviction parity: a device re-paired under a DIFFERENT user
    // (the device changed hands) must NOT leave two simultaneously-live
    // rows — the stale row would keep satisfying R593-F6's token binding
    // for the original owner. Last completed ceremony wins: bob's
    // enrollment revokes alice's live row for the same node.
    let (app, authority, store) = rig();
    let now = now();
    let alice = authority
        .establish(UserId::new("alice"), DeviceId::new("d1"), DeviceBinding::Passkey, now)
        .await
        .unwrap();
    let bob = authority
        .establish(UserId::new("bob"), DeviceId::new("d2"), DeviceBinding::Passkey, now)
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(post_enroll(&alice.access_token, "shared-node-id"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = app
        .clone()
        .oneshot(post_enroll(&bob.access_token, "shared-node-id"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "new owner, fresh row");

    // Alice's live view no longer contains the node; bob's does.
    let alice_rows = store.list_for_principal(&PrincipalId::user("alice")).await.unwrap();
    let bob_rows = store.list_for_principal(&PrincipalId::user("bob")).await.unwrap();
    assert_eq!(
        alice_rows.len(),
        0,
        "previous owner's row must be revoked on ownership change: {alice_rows:?}"
    );
    assert_eq!(bob_rows.len(), 1);

    // Exactly one live row over the resource itself.
    let live = store
        .list_for_resource(NODE_RESOURCE_KIND, "shared-node-id")
        .await
        .unwrap();
    assert_eq!(live.len(), 1, "one live owner per node: {live:?}");
    assert_eq!(live[0].principal_id, PrincipalId::user("bob"));
}

#[tokio::test]
async fn deenroll_revokes_only_the_callers_own_row() {
    let (app, authority, store) = rig();
    let now = now();
    let alice = authority
        .establish(UserId::new("alice"), DeviceId::new("d1"), DeviceBinding::Passkey, now)
        .await
        .unwrap();
    let bob = authority
        .establish(UserId::new("bob"), DeviceId::new("d2"), DeviceBinding::Passkey, now)
        .await
        .unwrap();

    // Alice enrolls node A; bob enrolls node B.
    for (tok, node) in [(&alice.access_token, "node-a"), (&bob.access_token, "node-b")] {
        let resp = app.clone().oneshot(post_enroll(tok, node)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    let del = |tok: &str, node: &str| {
        Request::builder()
            .method("DELETE")
            .uri(format!("/api/enrollment/node/{node}"))
            .header(header::AUTHORIZATION, auth(tok))
            .body(Body::empty())
            .unwrap()
    };

    // Bob cannot de-enroll alice's node — 404 (no existence oracle).
    let resp = app.clone().oneshot(del(&bob.access_token, "node-a")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        store.list_for_principal(&PrincipalId::user("alice")).await.unwrap().len(),
        1,
        "alice's row untouched by bob's DELETE"
    );

    // Alice de-enrolls her own node — 204, row revoked.
    let resp = app.clone().oneshot(del(&alice.access_token, "node-a")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        store.list_for_principal(&PrincipalId::user("alice")).await.unwrap().len(),
        0
    );

    // Re-deleting is a 404 — no live row remains to revoke.
    let resp = app.clone().oneshot(del(&alice.access_token, "node-a")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Bob's own enrollment is unaffected throughout.
    assert_eq!(
        store.list_for_principal(&PrincipalId::user("bob")).await.unwrap().len(),
        1
    );
}
