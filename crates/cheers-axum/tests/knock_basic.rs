//! R734-F4: the knock routes end to end over in-memory stores.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use cheers_core::{
    AdmissionMode, AdmissionPolicy, Admit, AdmitSource, Claims, Confirmation, DeviceBinding, DeviceId, Knock, Lease,
    PrincipalId, RelationDef, ResourceSchema, SchemaRegistry, ScopeRegistry, SignedArtifact, TokenMinter, UserId,
};
use cheers_server::{
    IssuerTrust, KnockAuthority, KnockConfig, MemoryKnockStore, MemoryOwnershipStore, NewOwnership, OwnershipStore,
    PasetoV4SecretMinter, ReplicatedRevocations, StandingVerifier,
};
use pasetors::keys::{AsymmetricKeyPair, Generate};
use pasetors::version4::{PublicToken, V4};
use serde::Serialize;
use tower::ServiceExt;

use cheers_axum::knock::{AdmitUploadOutcome, AdmittedBody, KnockQueued, KnockState, OfferCreated, RateLimiter, router};

use crate::common::{MemRevocations, body_to_string, test_edge, test_minter};

fn now_seconds() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

const ISS: &str = "https://cheers.example";
const DAY: i64 = 24 * 60 * 60;

const NAMESPACE: ResourceSchema = ResourceSchema {
    kind: "namespace",
    relations: &[
        RelationDef { name: "owner", membership: true, implies: &["admin"], scopes: &[], grants: &[] },
        RelationDef { name: "admin", membership: true, implies: &["guest"], scopes: &[], grants: &[] },
        RelationDef { name: "guest", membership: true, implies: &[], scopes: &[], grants: &[] },
    ],
    kind_relations: &[],
};

struct Rig {
    app: Router,
    store: MemoryOwnershipStore,
}

fn key_of(k: &AsymmetricKeyPair<V4>) -> PrincipalId {
    PrincipalId::from_public_key(k.public.as_bytes().try_into().unwrap())
}

fn sign<T: SignedArtifact + Serialize>(k: &AsymmetricKeyPair<V4>, payload: &T) -> String {
    let body = serde_json::to_vec(payload).unwrap();
    PublicToken::sign(&k.secret, &body, Some(br#"{"kid":"device"}"#), Some(T::IMPLICIT_ASSERTION)).unwrap()
}

fn knock(k: &AsymmetricKeyPair<V4>, label: &str) -> String {
    sign(
        k,
        &Knock {
            requester: key_of(k),
            kind: "namespace".into(),
            id: "ed".into(),
            relation: "guest".into(),
            nonce: "n".into(),
            label: label.into(),
            standing: None,
            renews: None,
            iat: now_seconds(),
        },
    )
}

async fn rig(config: KnockConfig) -> Rig {
    let (minter, verifier) = PasetoV4SecretMinter::generate().unwrap();
    let trust = IssuerTrust::pinned(ISS, verifier);
    let replica = Arc::new(ReplicatedRevocations::new(trust.clone()));
    let store = MemoryOwnershipStore::new();
    let schema = Arc::new(SchemaRegistry::build(&[NAMESPACE], &ScopeRegistry::builder().build().unwrap()).unwrap());
    let authority = KnockAuthority::new(
        schema,
        Arc::new(store.clone()),
        Arc::new(MemoryKnockStore::new()),
        Arc::new(MemRevocations::default()),
        StandingVerifier::new(trust, replica),
        minter,
        ISS,
        "k1",
    )
    .unwrap()
    .with_config(config);
    let seed = PrincipalId::service("seed");
    store
        .insert(&NewOwnership::new(PrincipalId::user("alice"), "namespace", "ed", "owner", seed, None).unwrap(), 10)
        .await
        .unwrap();
    let policy = AdmissionPolicy::new(AdmissionMode::Knock, "guest").with_admitters(["admin"]);
    store.set_admission_policy("namespace", "ed", Some(&policy), 10).await.unwrap();
    let state = Arc::new(KnockState {
        edge: Arc::new(test_edge(MemRevocations::default())),
        authority: Arc::new(authority),
        limiter: Arc::new(RateLimiter::new()),
    });
    Rig { app: Router::new().nest("/api", router(state)), store }
}

fn session(user: &str) -> String {
    let claims = Claims::new(UserId::new(user), DeviceId::new("laptop"), DeviceBinding::EmailMagicLink, now_seconds(), now_seconds() + 60)
        .with_jti(format!("sess-{user}"));
    test_minter().mint(&claims).unwrap()
}

fn request(method: &str, uri: &str, bearer: Option<&str>, body: Option<serde_json::Value>) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri).header(header::CONTENT_TYPE, "application/json");
    if let Some(t) = bearer {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let mut req = b.body(body.map(|v| Body::from(v.to_string())).unwrap_or_else(Body::empty)).unwrap();
    req.extensions_mut().insert(ConnectInfo(SocketAddr::from(([10, 0, 0, 1], 4000))));
    req
}

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, String) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    (status, body_to_string(resp.into_body()).await)
}

#[tokio::test]
async fn knock_then_admit_writes_the_tuple_and_a_second_knock_replaces_the_first() {
    let r = rig(KnockConfig::default()).await;
    let guest = AsymmetricKeyPair::<V4>::generate().unwrap();
    let (s, b) = call(&r.app, request("POST", "/api/knock", None, Some(serde_json::json!({"knock": knock(&guest, "one")})))).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{b}");
    let first: KnockQueued = serde_json::from_str(&b).unwrap();
    assert!(!first.replaced);
    let (_, b) = call(&r.app, request("POST", "/api/knock", None, Some(serde_json::json!({"knock": knock(&guest, "two")})))).await;
    let second: KnockQueued = serde_json::from_str(&b).unwrap();
    assert!(second.replaced);

    let list = "/api/knock?resource_kind=namespace&resource_id=ed";
    assert_eq!(call(&r.app, request("GET", list, None, None)).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(call(&r.app, request("GET", list, Some(&session("bob")), None)).await.0, StatusCode::FORBIDDEN);
    let (s, b) = call(&r.app, request("GET", list, Some(&session("alice")), None)).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let pending: Vec<serde_json::Value> = serde_json::from_str(&b).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0]["label"], "two");

    let uri = format!("/api/knock/{}/admit", second.id);
    assert_eq!(
        call(&r.app, request("POST", &uri, Some(&session("bob")), Some(serde_json::json!({})))).await.0,
        StatusCode::FORBIDDEN
    );
    let (s, b) = call(&r.app, request("POST", &uri, Some(&session("alice")), Some(serde_json::json!({"lease_seconds": DAY})))).await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let admitted: AdmittedBody = serde_json::from_str(&b).unwrap();
    assert_eq!(admitted.ownership.granted_by, PrincipalId::user("alice"));
    assert_eq!(admitted.ownership.subject.principal(), Some(&key_of(&guest)));
    assert_eq!(admitted.ownership.lease.and_then(|l| l.lease.exp()), Some(admitted.ownership.lease.unwrap().iat + DAY));
    assert_eq!(call(&r.app, request("POST", &uri, Some(&session("alice")), Some(serde_json::json!({})))).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn post_knock_is_rate_limited_per_source_and_capped_per_resource() {
    let r = rig(KnockConfig { knocks_per_source_per_minute: 2, pending_cap: 1, ..KnockConfig::default() }).await;
    let a = AsymmetricKeyPair::<V4>::generate().unwrap();
    let b = AsymmetricKeyPair::<V4>::generate().unwrap();
    let post = |k: &AsymmetricKeyPair<V4>| request("POST", "/api/knock", None, Some(serde_json::json!({"knock": knock(k, "x")})));
    assert_eq!(call(&r.app, post(&a)).await.0, StatusCode::ACCEPTED);
    let (s, body) = call(&r.app, post(&b)).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert!(body.contains("pending_full"), "{body}");
    let (s, body) = call(&r.app, post(&a)).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert!(body.contains("rate_limited"), "{body}");
    // A forged knock is refused before it is queued.
    let mut forged = knock(&a, "x");
    forged.pop();
    let r2 = rig(KnockConfig::default()).await;
    assert_eq!(
        call(&r2.app, request("POST", "/api/knock", None, Some(serde_json::json!({"knock": forged})))).await.0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn an_uploaded_admit_and_an_offer_reconcile_through_the_routes() {
    let r = rig(KnockConfig::default()).await;
    // A device key that holds the admitter relation itself approves offline.
    let approver = AsymmetricKeyPair::<V4>::generate().unwrap();
    let seed = PrincipalId::service("seed");
    r.store
        .insert(&NewOwnership::new(key_of(&approver), "namespace", "ed", "admin", seed, None).unwrap(), 10)
        .await
        .unwrap();
    let guest = AsymmetricKeyPair::<V4>::generate().unwrap();
    let now = now_seconds();
    let admit = sign(
        &approver,
        &Admit {
            approver: key_of(&approver),
            approver_binding: None,
            authority: ISS.into(),
            requester: key_of(&guest),
            requester_binding: None,
            kind: "namespace".into(),
            id: "ed".into(),
            relation: "guest".into(),
            source: AdmitSource::Knock("h".into()),
            confirmation: Confirmation::Accept,
            epoch: 1,
            jti: "admit-route-1".into(),
            iat: now,
            lease: Lease::new(now, now + DAY, Some(now + 7 * DAY)).unwrap(),
        },
    );
    let body = serde_json::json!({"admit": admit});
    let (s, b) = call(&r.app, request("POST", "/api/admit", None, Some(body.clone()))).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let AdmitUploadOutcome::Accepted { jti, ownership } = serde_json::from_str(&b).unwrap() else { panic!("{b}") };
    assert_eq!(jti, "admit-route-1");
    assert_eq!(ownership.granted_by, key_of(&approver));
    assert_eq!(ownership.lease.and_then(|l| l.lease.exp()), Some(now + 7 * DAY));
    let (s, again) = call(&r.app, request("POST", "/api/admit", None, Some(body))).await;
    assert_eq!((s, again), (StatusCode::OK, b), "idempotent per jti");

    let (s, b) = call(
        &r.app,
        request(
            "POST",
            "/api/offer",
            Some(&session("alice")),
            Some(serde_json::json!({"resource_kind": "namespace", "resource_id": "ed", "relation": "guest", "max_uses": 1})),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let offer: OfferCreated = serde_json::from_str(&b).unwrap();
    let other = AsymmetricKeyPair::<V4>::generate().unwrap();
    let redeem = |k: &AsymmetricKeyPair<V4>| {
        request("POST", "/api/offer/redeem", None, Some(serde_json::json!({"offer": offer.token, "knock": knock(k, "y")})))
    };
    let (s, b) = call(&r.app, redeem(&other)).await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let redeemed: AdmittedBody = serde_json::from_str(&b).unwrap();
    assert_eq!(redeemed.ownership.granted_by, PrincipalId::user("alice"));
    let third = AsymmetricKeyPair::<V4>::generate().unwrap();
    assert_eq!(call(&r.app, redeem(&third)).await.0, StatusCode::GONE);
}
