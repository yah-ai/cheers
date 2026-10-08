//! `GET /ownership?principal_id=P&resource_kind=K` (R732-F8): the rows held
//! directly by `P` on resources of kind `K`, gated by grant rights on the
//! kind-level row `kind/K`.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use cheers_core::{
    Claims, DeviceBinding, DeviceId, KIND_RESOURCE, PrincipalId, RelationDef, ResourceSchema,
    SchemaRegistry, TokenMinter, UserId, yah_scopes,
};
use cheers_server::{PasetoV4SecretMinter, SeedTuple, seed_ownership};
use tower::ServiceExt;

use cheers_axum::mcp::McpAuthState;
use cheers_axum::ownership::{OwnershipState, router as ownership_router};

use crate::common::{MemOwnershipStore, MemRevocations, body_to_string, test_edge, test_minter};

const ISS: &str = "https://cheers.example";

const DOC: ResourceSchema = ResourceSchema {
    kind: "doc",
    relations: &[
        RelationDef { name: "reader", membership: true, implies: &[], scopes: &[], grants: &[] },
        RelationDef { name: "admin", membership: true, implies: &["reader"], scopes: &[], grants: &["reader"] },
    ],
    kind_relations: &[RelationDef { name: "admin", membership: true, implies: &[], scopes: &[], grants: &["admin"] }],
};

const BOARD: ResourceSchema = ResourceSchema {
    kind: "board",
    relations: &[
        RelationDef { name: "member", membership: true, implies: &[], scopes: &[], grants: &[] },
        RelationDef { name: "admin", membership: true, implies: &["member"], scopes: &[], grants: &["member"] },
    ],
    kind_relations: &[RelationDef { name: "admin", membership: true, implies: &[], scopes: &[], grants: &["admin"] }],
};

fn now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

fn tuple(who: &str, kind: &str, id: &str, rel: &str) -> SeedTuple {
    SeedTuple {
        principal_id: PrincipalId::user(who),
        resource_kind: kind.into(),
        resource_id: id.into(),
        relationship: rel.into(),
    }
}

/// root administers kind `doc`; boardroot administers kind `board`; alice
/// administers doc/d1 only; bob holds rows on two docs and one board.
async fn rig() -> Router {
    let (_minter, verifier) = PasetoV4SecretMinter::generate().unwrap();
    let store = Arc::new(MemOwnershipStore::default());
    let scopes = yah_scopes::registry_at([ISS]).unwrap();
    let schema = Arc::new(SchemaRegistry::build(&[DOC, BOARD], &scopes).unwrap());
    let state = Arc::new(OwnershipState {
        edge: Arc::new(test_edge(MemRevocations::default())),
        mcp: Arc::new(McpAuthState::new(verifier, "kind-list-kid", ISS, ISS)),
        schema,
        store: store.clone(),
        revocations: Arc::new(MemRevocations::default()),
    });
    seed_ownership(
        store.as_ref(),
        &[
            tuple("root", KIND_RESOURCE, "doc", "admin"),
            tuple("boardroot", KIND_RESOURCE, "board", "admin"),
            tuple("alice", "doc", "d1", "admin"),
            tuple("bob", "doc", "d1", "reader"),
            tuple("bob", "doc", "d2", "reader"),
            tuple("bob", "board", "b1", "member"),
        ],
        &PrincipalId::service("cheers-test"),
        now(),
    )
    .await
    .unwrap();
    Router::new().nest("/api", ownership_router(state))
}

fn session(user: &str) -> String {
    let claims = Claims::new(
        UserId::new(user),
        DeviceId::new("laptop"),
        DeviceBinding::EmailMagicLink,
        now(),
        now() + 60,
    )
    .with_jti(format!("sess-{user}"));
    test_minter().mint(&claims).unwrap()
}

async fn get(app: &Router, user: &str, query: &str) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/ownership?{query}"))
        .header(header::AUTHORIZATION, format!("Bearer {}", session(user)))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = body_to_string(resp.into_body()).await;
    (status, serde_json::from_str(&body).unwrap_or(serde_json::Value::Null))
}

#[tokio::test]
async fn a_kind_admin_lists_a_principals_rows_of_that_kind_only() {
    let app = rig().await;
    let (status, rows) = get(&app, "root", "principal_id=user:bob&resource_kind=doc").await;
    assert_eq!(status, StatusCode::OK);
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 2);
    for r in rows {
        assert_eq!(r["principal_id"], "user:bob");
        assert_eq!(r["resource_kind"], "doc");
    }
}

#[tokio::test]
async fn a_resource_admin_without_the_kind_row_is_403() {
    let app = rig().await;
    let (status, body) = get(&app, "alice", "principal_id=user:bob&resource_kind=doc").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "grant_forbidden");
    let (status, _) = get(&app, "bob", "principal_id=user:bob&resource_kind=doc").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "even for one's own rows, the kind form needs the kind row");
}

#[tokio::test]
async fn an_admin_of_another_kind_is_403() {
    let app = rig().await;
    let (status, _) = get(&app, "boardroot", "principal_id=user:bob&resource_kind=doc").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, rows) = get(&app, "boardroot", "principal_id=user:bob&resource_kind=board").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(rows.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn malformed_combinations_are_400() {
    let app = rig().await;
    for q in [
        "principal_id=user:bob&resource_id=d1",
        "resource_kind=doc",
        "resource_id=d1",
        "principal_id=user:bob&resource_kind=doc&resource_id=d1",
        "principal_id=user:bob&resource_kind=doc&subject_kind=doc",
        "principal_id=user:bob&resource_kind=doc&subject_kind=doc&subject_id=d1&subject_relation=admin",
        "resource_kind=doc&subject_kind=doc&subject_id=d1&subject_relation=admin",
        "",
    ] {
        let (status, body) = get(&app, "root", q).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "query {q:?}");
        assert_eq!(body["error"], "invalid_ownership_query", "query {q:?}");
    }
}

#[tokio::test]
async fn bare_principal_id_stays_caller_own_only() {
    let app = rig().await;
    let (status, _) = get(&app, "root", "principal_id=user:bob").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a kind admin gets no bare cross-principal list");
    let (status, rows) = get(&app, "bob", "principal_id=user:bob").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(rows.as_array().unwrap().len(), 3);
}
