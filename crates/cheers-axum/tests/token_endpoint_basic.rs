//! R731-F5 — `POST /token` end to end: a service's PASETO client assertion,
//! an RFC 8693 user+camp exchange, replay, an unsupported grant, and the
//! discovery document advertising exactly what the route serves.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use cheers_core::{
    ClientAssertion, DeviceBinding, DeviceId, MemoryUsedJtiStore, PrincipalId, Scope,
    UserDelegation, UserId, yah_scopes,
};
use cheers_server::{
    CampAuthority, CampPrincipalStore, McpAuthority, MemoryBundleStore,
    MemoryCampPrincipalStore, MemoryServicePrincipalStore, MemoryUserSigningKeyStore,
    NewCampPrincipal, NewServicePrincipal, PasetoV4PublicVerifier, PasetoV4SecretMinter,
    ProvisionedKey, SchemaGrantStore, ServicePrincipalAuthority, SessionAuthority, SessionPolicy,
    UserSigningKey, UserSigningKeyStatus,
};
use ed25519_compact::{KeyPair, Seed};
use pasetors::keys::AsymmetricSecretKey;
use pasetors::version4::{PublicToken as PasetoPublic, V4};
use tower::ServiceExt;

use cheers_axum::discovery::{self, DiscoveryState, OpenIdConfiguration};
use cheers_axum::token_endpoint::{self, TokenEndpointState, TokenResponse};

use crate::common::{
    MemOwnershipStore, MemRefreshStore, MemRevocations, MemUserStore, body_to_string, test_edge,
    test_minter,
};

const ISS: &str = "https://cheers.test";
const KID: &str = "token-endpoint-test-kid";
const AUD: &str = "https://kamaji.test";
const TOKEN_URL: &str = "https://cheers.test/token";

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
    ],
};

struct Rig {
    app: Router,
    ownership: Arc<MemOwnershipStore>,
    verifier: PasetoV4PublicVerifier,
    sessions: SessionAuthority<cheers_server::HmacBlobCodec, MemRefreshStore, MemUserStore, MemRevocations>,
    camps: CampAuthority<MemoryCampPrincipalStore, MemoryUserSigningKeyStore>,
    user_keys: MemoryUserSigningKeyStore,
    svc_key: ProvisionedKey,
}

fn now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

async fn rig() -> Rig {
    let scopes = Arc::new(yah_scopes::registry_at([AUD]).unwrap());
    let ownership = Arc::new(MemOwnershipStore::default());
    let schema = cheers_core::SchemaRegistry::build(&[GRANT_SCHEMA], &scopes).unwrap();
    let grants = SchemaGrantStore::new(ownership.clone(), Arc::new(schema), scopes.clone());

    let svc_store = MemoryServicePrincipalStore::new();
    let svc_key = ServicePrincipalAuthority::new(svc_store.clone())
        .provision(NewServicePrincipal::new("yubaba"), now())
        .await
        .unwrap();

    let (minter, verifier) = PasetoV4SecretMinter::generate().unwrap();
    let mcp = Arc::new(
        McpAuthority::new(
            minter,
            MemoryBundleStore::with_defaults(),
            grants,
            ownership.clone(),
            scopes.clone(),
            ISS,
            KID,
        )
        .with_service_assertions(Arc::new(svc_store), Arc::new(MemoryUsedJtiStore::new())),
    );

    let revocations = MemRevocations::default();
    let sessions = SessionAuthority::new(
        test_minter(),
        MemRefreshStore::default(),
        MemUserStore::default(),
        revocations.clone(),
    )
    .with_policy(SessionPolicy::default().with_access_ttl(600));

    let camp_store = MemoryCampPrincipalStore::new();
    let user_keys = MemoryUserSigningKeyStore::new();
    let camps = CampAuthority::new(camp_store.clone(), user_keys.clone());

    let state = Arc::new(TokenEndpointState {
        mcp,
        edge: Arc::new(test_edge(revocations)),
        camps: Arc::new(camp_store) as Arc<dyn CampPrincipalStore>,
    });
    let app = Router::new()
        .merge(token_endpoint::router(state))
        .merge(discovery::router(Arc::new(DiscoveryState::new(ISS, scopes))));
    Rig { app, ownership, verifier, sessions, camps, user_keys, svc_key }
}

fn seed(rig: &Rig, principal: PrincipalId, scope: Scope) {
    let n = cheers_server::NewOwnership::new(
        principal,
        cheers_core::KIND_RESOURCE,
        GRANT_KIND,
        scope.as_wire(),
        PrincipalId::service("seed"),
        None,
    )
    .unwrap();
    pollster::block_on(cheers_server::OwnershipStore::insert(rig.ownership.as_ref(), &n, 1)).unwrap();
}

fn sign_assertion(key: &ProvisionedKey, jti: &str) -> String {
    let t = now();
    let claims = ClientAssertion::new(PrincipalId::service("yubaba"), TOKEN_URL, jti, t, t + 60);
    let sk = AsymmetricSecretKey::<V4>::from(&key.secret_key[..]).unwrap();
    let footer = serde_json::to_vec(&serde_json::json!({ "kid": key.signing_key.kid })).unwrap();
    PasetoPublic::sign(&sk, &serde_json::to_vec(&claims).unwrap(), Some(&footer), None).unwrap()
}

async fn post_form(app: &Router, pairs: &[(&str, &str)]) -> (StatusCode, serde_json::Value) {
    let body = serde_urlencoded::to_string(pairs).unwrap();
    let req = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    assert_eq!(
        resp.headers().get(header::CACHE_CONTROL).map(|v| v.to_str().unwrap()),
        Some("no-store"),
    );
    let text = body_to_string(resp.into_body()).await;
    (status, serde_json::from_str(&text).unwrap_or_else(|_| panic!("json body: {text}")))
}

fn assertion_form<'a>(assertion: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("grant_type", "client_credentials"),
        ("client_assertion_type", token_endpoint::PASETO_ASSERTION_TYPE),
        ("client_assertion", assertion),
        ("audience", AUD),
    ]
}

/// A provisioned camp bound to `user`, returning its bootstrap credential.
async fn provision_camp(rig: &Rig, user: &PrincipalId, camp_id: &str) -> String {
    let kp = KeyPair::from_seed(Seed::from_slice(&[7u8; 32]).unwrap());
    rig.user_keys.insert(UserSigningKey::new(
        "trusted",
        user.clone(),
        *kp.pk,
        UserSigningKeyStatus::Active,
        0,
    ));
    let t = now();
    let unsigned =
        UserDelegation::new(user.clone(), camp_id, t, t + 600, *kp.pk, [0u8; 64]).unwrap();
    let sig = kp.sk.sign(unsigned.signing_payload(), None);
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(sig.as_ref());
    let delegation =
        UserDelegation::new(user.clone(), camp_id, t, t + 600, *kp.pk, bytes).unwrap();
    rig.camps
        .provision(NewCampPrincipal::new(user.clone(), camp_id), delegation, t)
        .await
        .unwrap()
        .credential
        .token
}

#[tokio::test]
async fn client_assertion_mints_a_token_scoped_by_the_relationship() {
    let rig = rig().await;
    seed(&rig, PrincipalId::service("yubaba"), yah_scopes::CLOUD_READ);
    let assertion = sign_assertion(&rig.svc_key, "jti-ok");
    let (status, body) = post_form(&rig.app, &assertion_form(&assertion)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let resp: TokenResponse = serde_json::from_value(body).unwrap();
    assert_eq!(resp.token_type, "Bearer");
    assert_eq!(resp.scope, "cloud:read");
    assert!(resp.expires_in > 0 && resp.expires_in <= 3600);
    assert_eq!(resp.issued_token_type, None);
    let claims = rig.verifier.verify_mcp_at(&resp.access_token, now(), KID).unwrap();
    assert_eq!(claims.sub, PrincipalId::service("yubaba"));
    assert_eq!(claims.aud, AUD);
    assert_eq!(claims.scope, vec![yah_scopes::CLOUD_READ]);
}

#[tokio::test]
async fn replayed_assertion_is_invalid_grant() {
    let rig = rig().await;
    seed(&rig, PrincipalId::service("yubaba"), yah_scopes::CLOUD_READ);
    let assertion = sign_assertion(&rig.svc_key, "jti-once");
    let (status, _) = post_form(&rig.app, &assertion_form(&assertion)).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = post_form(&rig.app, &assertion_form(&assertion)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn bad_assertion_is_invalid_client_401() {
    let rig = rig().await;
    let (status, body) = post_form(&rig.app, &assertion_form("v4.public.garbage")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_client");
}

#[tokio::test]
async fn unknown_grant_type_is_unsupported_grant_type() {
    let rig = rig().await;
    let (status, body) = post_form(&rig.app, &[("grant_type", "password")]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "unsupported_grant_type");
    let (status, body) = post_form(&rig.app, &[("audience", AUD)]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn token_exchange_mints_a_user_token_in_camp_context() {
    let rig = rig().await;
    let user = PrincipalId::user("alice");
    let camp_token = provision_camp(&rig, &user, "camp-a").await;
    seed(&rig, user.clone(), yah_scopes::CLOUD_READ);
    seed(&rig, user.clone(), yah_scopes::CLOUD_DEPLOY);
    seed(&rig, PrincipalId::camp("camp-a"), yah_scopes::CLOUD_READ);
    let session = rig
        .sessions
        .establish(UserId::new("alice"), DeviceId::new("laptop"), DeviceBinding::EmailMagicLink, now())
        .await
        .unwrap();

    let form = |scope: &'static str| {
        vec![
            ("grant_type", token_endpoint::TOKEN_EXCHANGE_GRANT),
            ("subject_token", session.access_token.as_str()),
            ("subject_token_type", token_endpoint::ACCESS_TOKEN_TYPE),
            ("actor_token", camp_token.as_str()),
            ("actor_token_type", token_endpoint::CAMP_BOOTSTRAP_TOKEN_TYPE),
            ("audience", AUD),
            ("scope", scope),
        ]
    };
    let (status, body) = post_form(&rig.app, &form("cloud:read")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let resp: TokenResponse = serde_json::from_value(body).unwrap();
    assert_eq!(resp.issued_token_type.as_deref(), Some(token_endpoint::ACCESS_TOKEN_TYPE));
    assert_eq!(resp.scope, "cloud:read");
    let claims = rig.verifier.verify_mcp_at(&resp.access_token, now(), KID).unwrap();
    assert_eq!(claims.sub, user);
    assert_eq!(claims.camp_id.as_deref(), Some("camp-a"));
    assert_eq!(
        claims.act.as_ref().map(|a| &a.sub),
        Some(&PrincipalId::camp("camp-a")),
        "the camp must ride as act so ownership writes attribute granted_by to it",
    );

    // The camp does not hold cloud:deploy: the whole exchange is refused.
    let (status, body) = post_form(&rig.app, &form("cloud:read cloud:deploy")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_scope");

    // A credential cheers never issued.
    let mut bad = form("cloud:read");
    bad[3].1 = "not-a-credential";
    let (status, body) = post_form(&rig.app, &bad).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");

    // Swapped roles: the camp credential as subject, the session as actor,
    // each typed as what it really is. Refused on the type check.
    let mut swapped = form("cloud:read");
    swapped[1] = ("subject_token", camp_token.as_str());
    swapped[2] = ("subject_token_type", token_endpoint::CAMP_BOOTSTRAP_TOKEN_TYPE);
    swapped[3] = ("actor_token", session.access_token.as_str());
    swapped[4] = ("actor_token_type", token_endpoint::ACCESS_TOKEN_TYPE);
    let (status, body) = post_form(&rig.app, &swapped).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");

    // Swapped tokens under the correct type labels: neither verifies.
    let mut mislabeled = form("cloud:read");
    mislabeled[1].1 = camp_token.as_str();
    mislabeled[3].1 = session.access_token.as_str();
    let (status, body) = post_form(&rig.app, &mislabeled).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn discovery_advertises_exactly_the_grants_the_route_serves() {
    let rig = rig().await;
    let req = Request::builder()
        .uri(discovery::OPENID_CONFIGURATION_PATH)
        .body(Body::empty())
        .unwrap();
    let resp = rig.app.clone().oneshot(req).await.unwrap();
    let cfg: OpenIdConfiguration =
        serde_json::from_str(&body_to_string(resp.into_body()).await).unwrap();
    assert_eq!(cfg.token_endpoint, TOKEN_URL);
    assert_eq!(
        cfg.grant_types_supported,
        vec![
            "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            "client_credentials".to_string(),
        ],
    );
    assert_eq!(
        cfg.token_endpoint_auth_methods_supported,
        vec!["urn:cheers:client-assertion-type:paseto-v4-public".to_string()],
    );
    // Every advertised grant is dispatched — none answers unsupported_grant_type.
    for grant in &cfg.grant_types_supported {
        let (_, body) = post_form(&rig.app, &[("grant_type", grant.as_str())]).await;
        assert_ne!(body["error"], "unsupported_grant_type", "{grant}");
    }
}
