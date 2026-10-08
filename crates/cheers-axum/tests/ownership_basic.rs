//! Integration tests for the `/ownership` grant door (R731-F8, D4) — round
//! trips via `tower::Service::call` (no TCP listener).
//!
//! Authority is a relationship: the caller's live rows, resolved through the
//! test schema below, decide what it may grant, revoke and list. Either a
//! session bearer or an MCP bearer authenticates.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use cheers_core::{
    Actor, AuthStrength, Claims, DeviceBinding, DeviceId, McpClaims, PrincipalId, RelationDef,
    ResourceSchema, SchemaRegistry, Subject, TokenMinter, UserId, yah_scopes,
};
use cheers_core::Revoked;
use cheers_server::{
    NewOwnership, OwnershipStore, PasetoV4SecretMinter, RevocationWriter, SeedTuple, seed_ownership,
};
use tower::ServiceExt;

use cheers_axum::mcp::McpAuthState;
use cheers_axum::ownership::{OwnershipState, router as ownership_router};

use crate::common::{MemOwnershipStore, MemRevocations, body_to_string, test_edge, test_minter};

const TEST_KID: &str = "ownership-basic-test-kid";
const ISS: &str = "https://cheers.example";

/// `doc`: `admin` may grant `triager` and `reader`; `triager` and `reader`
/// grant nothing. A kind-level `admin` may grant `admin` on any doc.
const DOC: ResourceSchema = ResourceSchema {
    kind: "doc",
    relations: &[
        RelationDef { name: "reader", membership: true, implies: &[], scopes: &[], grants: &[] },
        RelationDef { name: "triager", membership: true, implies: &["reader"], scopes: &[], grants: &[] },
        RelationDef { name: "admin", membership: true, implies: &["triager"], scopes: &[], grants: &["triager", "reader"] },
    ],
    kind_relations: &[RelationDef { name: "admin", membership: true, implies: &[], scopes: &[], grants: &["admin"] }],
};

struct Rig {
    app: Router,
    minter: PasetoV4SecretMinter,
    store: Arc<MemOwnershipStore>,
    revocations: MemRevocations,
}

fn now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .expect("clock past epoch")
}

fn svc() -> PrincipalId {
    PrincipalId::service("cheers-test")
}

fn seed(principal: PrincipalId, id: &str, relationship: &str) -> SeedTuple {
    SeedTuple {
        principal_id: principal,
        resource_kind: "doc".into(),
        resource_id: id.into(),
        relationship: relationship.into(),
    }
}

/// alice holds `admin` on doc/d1; bob holds `reader` on doc/d1.
async fn rig() -> Rig {
    let (minter, verifier) = PasetoV4SecretMinter::generate().expect("paseto v4 keypair");
    let store = Arc::new(MemOwnershipStore::default());
    let revocations = MemRevocations::default();
    let scopes = yah_scopes::registry_at([ISS]).unwrap();
    let schema = Arc::new(SchemaRegistry::build(&[DOC], &scopes).expect("schema"));
    let state = Arc::new(OwnershipState {
        edge: Arc::new(test_edge(revocations.clone())),
        mcp: Arc::new(McpAuthState::new(verifier, TEST_KID, ISS, ISS)),
        schema,
        store: store.clone(),
        revocations: Arc::new(revocations.clone()),
    });
    seed_ownership(
        store.as_ref(),
        &[seed(PrincipalId::user("alice"), "d1", "admin"), seed(PrincipalId::user("bob"), "d1", "reader")],
        &svc(),
        now(),
    )
    .await
    .expect("seed");
    let app = Router::new().nest("/api", ownership_router(state));
    Rig { app, minter, store, revocations }
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
    test_minter().mint(&claims).expect("mint session")
}

fn mcp(rig: &Rig, sub: PrincipalId, act: Option<PrincipalId>, jti: &str) -> String {
    let mut claims = McpClaims::new(ISS, ISS, sub, now(), now() + 60, jti, vec![])
        .with_auth_strength(AuthStrength::UserFresh);
    if let Some(a) = act {
        claims = claims.with_act(Actor::new(a));
    }
    rig.minter.mint_mcp(&claims, TEST_KID).expect("mint mcp")
}

fn post(bearer: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/ownership")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn grant_body(principal: &str, id: &str, relationship: &str) -> serde_json::Value {
    serde_json::json!({
        "principal_id": principal,
        "resource_kind": "doc",
        "resource_id": id,
        "relationship": relationship,
    })
}

fn del(bearer: &str, id: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(format!("/api/ownership/{id}"))
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .body(Body::empty())
        .unwrap()
}

fn get(bearer: &str, id: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(format!("/api/ownership?resource_kind=doc&resource_id={id}"))
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .body(Body::empty())
        .unwrap()
}

async fn json_of(resp: axum::response::Response) -> serde_json::Value {
    serde_json::from_str(&body_to_string(resp.into_body()).await).expect("json body")
}

#[tokio::test]
async fn an_admin_with_a_session_bearer_grants_triager() {
    let rig = rig().await;
    let resp = rig
        .app
        .clone()
        .oneshot(post(&session("alice"), grant_body("user:carol", "d1", "triager")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let row = json_of(resp).await;
    assert_eq!(row["granted_by"], "user:alice");
    assert!(row["on_behalf_of"].is_null());

    // Idempotent: the same grant again returns the live row.
    let again = rig
        .app
        .clone()
        .oneshot(post(&session("alice"), grant_body("user:carol", "d1", "triager")))
        .await
        .unwrap();
    assert_eq!(again.status(), StatusCode::OK);
    assert_eq!(json_of(again).await["id"], row["id"]);
}

#[tokio::test]
async fn an_admin_with_an_mcp_bearer_grants_triager() {
    let rig = rig().await;
    let token = mcp(&rig, PrincipalId::user("alice"), None, "jti-mcp");
    let resp = rig
        .app
        .clone()
        .oneshot(post(&token, grant_body("user:carol", "d1", "triager")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(json_of(resp).await["granted_by"], "user:alice");
}

#[tokio::test]
async fn an_admin_cannot_grant_a_relation_outside_its_grants() {
    let rig = rig().await;
    let resp = rig
        .app
        .clone()
        .oneshot(post(&session("alice"), grant_body("user:carol", "d1", "admin")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // Nor on a resource it holds nothing on.
    let resp = rig
        .app
        .clone()
        .oneshot(post(&session("alice"), grant_body("user:carol", "d2", "reader")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_reader_is_refused_with_403_and_nothing_is_written() {
    let rig = rig().await;
    let before = rig.store.list_for_resource("doc", "d1").await.unwrap().len();
    let resp = rig
        .app
        .clone()
        .oneshot(post(&session("bob"), grant_body("user:carol", "d1", "reader")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_of(resp).await["error"], "grant_forbidden");
    assert_eq!(rig.store.list_for_resource("doc", "d1").await.unwrap().len(), before);
}

#[tokio::test]
async fn on_behalf_of_in_the_body_is_rejected() {
    let rig = rig().await;
    let mut body = grant_body("user:carol", "d1", "triager");
    body["on_behalf_of"] = "user:mallory".into();
    let resp = rig.app.clone().oneshot(post(&session("alice"), body)).await.unwrap();
    assert!(resp.status().is_client_error(), "got {}", resp.status());
    assert!(rig.store.list_for_principal(&PrincipalId::user("carol")).await.unwrap().is_empty());
}

#[tokio::test]
async fn on_behalf_of_comes_from_a_verified_act_claim() {
    let rig = rig().await;
    let agent = PrincipalId::service("agent-claude");
    let token = mcp(&rig, PrincipalId::user("alice"), Some(agent), "jti-act");
    let resp = rig
        .app
        .clone()
        .oneshot(post(&token, grant_body("user:carol", "d1", "reader")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let row = json_of(resp).await;
    assert_eq!(row["granted_by"], "svc:agent-claude");
    assert_eq!(row["on_behalf_of"], "user:alice");
}

#[tokio::test]
async fn a_revoked_mcp_bearer_is_401() {
    let rig = rig().await;
    let token = mcp(&rig, PrincipalId::user("alice"), None, "jti-dead");
    cheers_server::RevocationWriter::revoke(&rig.revocations, &cheers_core::Revoked::jti("jti-dead", None))
        .await
        .unwrap();
    let resp = rig
        .app
        .clone()
        .oneshot(post(&token, grant_body("user:carol", "d1", "reader")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn revoke_needs_grant_rights_on_the_target_row() {
    let rig = rig().await;
    let created = rig
        .app
        .clone()
        .oneshot(post(&session("alice"), grant_body("user:carol", "d1", "triager")))
        .await
        .unwrap();
    let id = json_of(created).await["id"].as_str().unwrap().to_owned();

    // bob (reader) has no grant rights: refused, row stays live.
    let resp = rig.app.clone().oneshot(del(&session("bob"), &id)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(rig.store.get(&id).await.unwrap().unwrap().revoked_at.is_none());

    // Unknown id is a 404.
    let resp = rig.app.clone().oneshot(del(&session("alice"), "nope")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // alice (admin, grants triager) may revoke it — though she didn't need
    // to be its writer.
    let resp = rig.app.clone().oneshot(del(&session("alice"), &id)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(rig.store.get(&id).await.unwrap().unwrap().revoked_at.is_some());
}

#[tokio::test]
async fn a_holder_may_revoke_its_own_tuple_but_not_anothers() {
    let rig = rig().await;
    // bob holds reader (no grant rights); alice grants carol reader.
    let bobs = rig.store.list_for_principal(&PrincipalId::user("bob")).await.unwrap();
    let bobs_id = bobs[0].id.clone();
    let created = rig
        .app
        .clone()
        .oneshot(post(&session("alice"), grant_body("user:carol", "d1", "reader")))
        .await
        .unwrap();
    let carols_id = json_of(created).await["id"].as_str().unwrap().to_owned();

    // bob may not revoke carol's tuple.
    let resp = rig.app.clone().oneshot(del(&session("bob"), &carols_id)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(rig.store.get(&carols_id).await.unwrap().unwrap().revoked_at.is_none());

    // bob may revoke his own.
    let resp = rig.app.clone().oneshot(del(&session("bob"), &bobs_id)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(rig.store.get(&bobs_id).await.unwrap().unwrap().revoked_at.is_some());
}

#[tokio::test]
async fn list_needs_some_grant_right_on_the_resource() {
    let rig = rig().await;
    let resp = rig.app.clone().oneshot(get(&session("alice"), "d1")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json_of(resp).await.as_array().unwrap().len(), 2);

    let resp = rig.app.clone().oneshot(get(&session("bob"), "d1")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_kind_level_admin_may_grant_admin_on_any_doc() {
    let rig = rig().await;
    seed_ownership(
        rig.store.as_ref(),
        &[SeedTuple {
            principal_id: PrincipalId::user("root"),
            resource_kind: cheers_core::KIND_RESOURCE.into(),
            resource_id: "doc".into(),
            relationship: "admin".into(),
        }],
        &svc(),
        now(),
    )
    .await
    .unwrap();
    let resp = rig
        .app
        .clone()
        .oneshot(post(&session("root"), grant_body("user:dana", "d9", "admin")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn seed_is_idempotent() {
    let rig = rig().await;
    let seeds = [seed(PrincipalId::user("alice"), "d1", "admin"), seed(PrincipalId::user("eve"), "d3", "admin")];
    let first = seed_ownership(rig.store.as_ref(), &seeds, &svc(), now()).await.unwrap();
    assert_eq!(first, 1, "alice's row was already seeded by the rig");
    let second = seed_ownership(rig.store.as_ref(), &seeds, &svc(), now()).await.unwrap();
    assert_eq!(second, 0);
    let rows = rig.store.list_for_principal(&PrincipalId::user("eve")).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].granted_by, svc());
}

fn get_query(bearer: &str, query: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(format!("/api/ownership?{query}"))
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .body(Body::empty())
        .unwrap()
}

/// `doc/d1#reader ← doc/d1#triager`: every triager of d1 reads d1.
fn set_grant_body() -> serde_json::Value {
    serde_json::json!({
        "subject_kind": "doc",
        "subject_id": "d1",
        "subject_relation": "triager",
        "resource_kind": "doc",
        "resource_id": "d1",
        "relationship": "reader",
    })
}

#[tokio::test]
async fn a_caller_lists_rows_held_by_its_own_subject() {
    let rig = rig().await;
    let resp = rig
        .app
        .clone()
        .oneshot(get_query(&session("alice"), "principal_id=user:alice"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let rows = json_of(resp).await;
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["principal_id"], "user:alice");
    assert_eq!(rows[0]["relationship"], "admin");
}

#[tokio::test]
async fn another_principals_subject_is_refused_even_to_a_resource_admin() {
    let rig = rig().await;
    // alice administers doc/d1, where bob reads — still not bob's row list.
    let resp = rig
        .app
        .clone()
        .oneshot(get_query(&session("alice"), "principal_id=user:bob"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_of(resp).await["error"], "grant_forbidden");
}

#[tokio::test]
async fn a_set_subject_is_granted_and_listed_by_a_caller_with_rights_on_its_resource() {
    let rig = rig().await;
    let resp = rig.app.clone().oneshot(post(&session("alice"), set_grant_body())).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created = json_of(resp).await;
    assert_eq!(created["subject_kind"], "doc");
    assert_eq!(created["subject_relation"], "triager");
    assert!(created.get("principal_id").is_none());
    // Idempotent like a principal grant.
    let resp = rig.app.clone().oneshot(post(&session("alice"), set_grant_body())).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json_of(resp).await["id"], created["id"]);

    let q = "subject_kind=doc&subject_id=d1&subject_relation=triager";
    let resp = rig.app.clone().oneshot(get_query(&session("alice"), q)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let rows = json_of(resp).await;
    assert_eq!(rows.as_array().unwrap().len(), 1);
    assert_eq!(rows[0]["id"], created["id"]);
    // Another relation's set on the same resource is a different subject.
    let other = "subject_kind=doc&subject_id=d1&subject_relation=admin";
    let resp = rig.app.clone().oneshot(get_query(&session("alice"), other)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(json_of(resp).await.as_array().unwrap().is_empty());

    // bob reads d1 but may grant nothing on it.
    let resp = rig.app.clone().oneshot(get_query(&session("bob"), q)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_body_naming_both_subject_forms_is_400() {
    let rig = rig().await;
    let mut body = set_grant_body();
    body["principal_id"] = "user:carol".into();
    let resp = rig.app.clone().oneshot(post(&session("alice"), body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_of(resp).await["error"], "ownership_invalid");
    assert_eq!(rig.store.insert_call_count(), 2, "only the rig's two seeds were written");
}

#[tokio::test]
async fn mixed_or_partial_list_forms_are_400() {
    let rig = rig().await;
    for q in [
        "resource_kind=doc&resource_id=d1&principal_id=user:alice",
        "resource_kind=doc&resource_id=d1&subject_kind=doc&subject_id=d1&subject_relation=triager",
        "resource_kind=doc",
        "subject_kind=doc&subject_id=d1",
        "",
    ] {
        let resp = rig.app.clone().oneshot(get_query(&session("alice"), q)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "query {q:?}");
        assert_eq!(json_of(resp).await["error"], "invalid_ownership_query", "query {q:?}");
    }
}

/// `doc/d2#admin ← team/t#member`, and dave is a member of team/t: the door
/// honours the set-derived admin right (R732-F2) for grant, list and revoke,
/// and withdraws it with the membership.
#[tokio::test]
async fn a_set_derived_right_is_honoured_at_the_door() {
    let rig = rig().await;
    let write = |subject: Subject, kind: &str, id: &str, rel: &str| {
        NewOwnership::new(subject, kind, id, rel, svc(), None).expect("valid tuple")
    };
    rig.store
        .insert(&write(Subject::set("team", "t", "member"), "doc", "d2", "admin"), now())
        .await
        .unwrap();
    let membership = rig
        .store
        .insert(&write(PrincipalId::user("dave").into(), "team", "t", "member"), now())
        .await
        .unwrap();

    let resp = rig
        .app
        .clone()
        .oneshot(post(&session("dave"), grant_body("user:carol", "d2", "triager")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let granted = json_of(resp).await["id"].as_str().unwrap().to_owned();
    let resp = rig.app.clone().oneshot(get(&session("dave"), "d2")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json_of(resp).await.as_array().unwrap().len(), 2, "the set row and carol's");
    let resp = rig.app.clone().oneshot(del(&session("dave"), &granted)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = rig
        .app
        .clone()
        .oneshot(post(&session("dave"), grant_body("user:frank", "d2", "reader")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let granted = json_of(resp).await["id"].as_str().unwrap().to_owned();
    // Outside the set, nothing.
    let resp = rig
        .app
        .clone()
        .oneshot(post(&session("erin"), grant_body("user:carol", "d2", "reader")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // The set confers on d2 only.
    let resp = rig
        .app
        .clone()
        .oneshot(post(&session("dave"), grant_body("user:carol", "d1", "reader")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Leaving the team ends the right at the door.
    rig.store.revoke_by_id(&membership.row.id, now()).await.unwrap();
    let resp = rig.app.clone().oneshot(del(&session("dave"), &granted)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let resp = rig
        .app
        .clone()
        .oneshot(post(&session("dave"), grant_body("user:carol", "d2", "reader")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// R732-F4: the door records `Revoked::Membership` only when a user's last
/// live direct tuple on the resource goes, at the ownership version that
/// removal produced — so offline edges drop the user from older snapshots.
#[tokio::test]
async fn delete_records_a_membership_entry_only_for_the_last_direct_tuple() {
    let rig = rig().await;
    // bob already reads d1; alice also makes him triager.
    let resp = rig
        .app
        .clone()
        .oneshot(post(&session("alice"), grant_body("user:bob", "d1", "triager")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let triager = json_of(resp).await["id"].as_str().unwrap().to_owned();
    let reader = rig
        .store
        .list_for_resource("doc", "d1")
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.relationship == "reader")
        .unwrap()
        .id;

    // A demotion: bob still holds reader, so nothing is recorded.
    let resp = rig.app.clone().oneshot(del(&session("alice"), &triager)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(rig.revocations.snapshot().await.unwrap().revoked.is_empty());

    // His last direct tuple on d1 (left by himself, C3): recorded.
    let resp = rig.app.clone().oneshot(del(&session("bob"), &reader)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let version = rig.store.current_version().await.unwrap();
    assert_eq!(
        rig.revocations.snapshot().await.unwrap().revoked,
        vec![Revoked::membership("doc", "d1", cheers_core::PrincipalId::user("bob"), version)]
    );
}

#[tokio::test]
async fn missing_bearer_is_401() {
    let rig = rig().await;
    let req = Request::builder()
        .method("GET")
        .uri("/api/ownership?resource_kind=doc&resource_id=d1")
        .body(Body::empty())
        .unwrap();
    let resp = rig.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
