//! Native Google ID-token exchange through the axum router.
//!
//! Drives `GET /auth/google/id-token/nonce` -> mint a token carrying that
//! nonce -> `POST /auth/google/id-token`, and asserts the session body, the
//! persisted user row, the replay refusal, and that a `sub` arriving both ways
//! (browser callback *and* Credential Manager) collapses onto one user.

#![cfg(feature = "google")]

use crate::common;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use chrono::{Duration, Utc};
use openidconnect::core::{
    CoreIdToken, CoreIdTokenClaims, CoreIdTokenFields, CoreJwsSigningAlgorithm,
    CoreProviderMetadata, CoreTokenResponse, CoreTokenType,
};
use openidconnect::{
    AccessToken, Audience, ClientId, ClientSecret, EmptyAdditionalClaims, EmptyExtraTokenFields,
    EndUserEmail, EndUserName, IssuerUrl, LocalizedClaim, Nonce, RedirectUrl, StandardClaims,
    SubjectIdentifier,
};
use serde_json::Value;
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

use cheers::providers::google::GoogleProvider;
use cheers::providers::oidc_generic::{MemoryOidcFlowStore, OidcFlowStore};
use cheers_axum::cookie::CsrfCookieConfig;
use cheers_axum::google::{router, GoogleAuthState};
use cheers_core::UserId;
use cheers_server::UserStore;

use common::{
    body_to_string, build_http_client, mount_discovery_and_jwks, now_seconds, signing_key,
    test_authority, TestAuthority,
};

/// The **server** (web) OAuth client id — the audience Google stamps into a
/// Credential Manager token when the app passes it as `serverClientId`.
const CLIENT_ID: &str = "test-client.apps.googleusercontent.com";
const REDIRECT_URI: &str = "https://app.example/auth/callback/google";

fn build_id_token(
    issuer: &str,
    nonce: Option<&Nonce>,
    audience: &str,
    lifetime: Duration,
    sub: &str,
) -> CoreIdToken {
    let now = Utc::now();
    let mut std_claims = StandardClaims::new(SubjectIdentifier::new(sub.to_owned()))
        .set_email(Some(EndUserEmail::new("alice@example.com".to_owned())))
        .set_email_verified(Some(true));
    let mut lc: LocalizedClaim<EndUserName> = LocalizedClaim::default();
    lc.insert(None, EndUserName::new("Alice Anderson".to_owned()));
    std_claims = std_claims.set_name(Some(lc));

    let claims = CoreIdTokenClaims::new(
        IssuerUrl::new(issuer.to_owned()).unwrap(),
        vec![Audience::new(audience.to_owned())],
        now + lifetime,
        now,
        std_claims,
        EmptyAdditionalClaims {},
    )
    .set_nonce(nonce.cloned());

    CoreIdToken::new(
        claims,
        &signing_key(),
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        None,
        None,
    )
    .expect("ID token signs")
}

/// The happy-path token: this server's audience, a live lifetime, and the
/// nonce the server just handed out.
fn good_token(issuer: &str, nonce: &Nonce, sub: &str) -> String {
    build_id_token(
        issuer,
        Some(nonce),
        CLIENT_ID,
        Duration::seconds(600),
        sub,
    )
    .to_string()
}

async fn build_router(
    server: &wiremock::MockServer,
    http: &openidconnect::reqwest::Client,
) -> (
    Router,
    Arc<GoogleProvider<MemoryOidcFlowStore>>,
    Arc<TestAuthority>,
) {
    let issuer = IssuerUrl::new(server.uri()).unwrap();
    let metadata = CoreProviderMetadata::discover_async(issuer, http)
        .await
        .expect("wiremock discovery succeeds");
    let provider = Arc::new(GoogleProvider::from_provider_metadata(
        metadata,
        ClientId::new(CLIENT_ID.into()),
        Some(ClientSecret::new("test-secret".into())),
        RedirectUrl::new(REDIRECT_URI.into()).unwrap(),
        MemoryOidcFlowStore::new(),
    ));
    let authority = Arc::new(test_authority());
    let state = GoogleAuthState {
        provider: provider.clone(),
        authority: authority.clone(),
        http: http.clone(),
        cookie: CsrfCookieConfig::new("cheers_csrf_google").with_secure(false),
    };
    let app = Router::new().nest("/auth", router(Arc::new(state)));
    (app, provider, authority)
}

/// `GET /auth/google/id-token/nonce`, returning the minted secret.
async fn take_nonce(app: &Router) -> String {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/google/id-token/nonce")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = serde_json::from_str(&body_to_string(resp.into_body()).await).unwrap();
    assert!(body["expires_in_seconds"].as_i64().unwrap() > 0);
    body["nonce"]
        .as_str()
        .expect("nonce in body")
        .to_owned()
}

async fn post_id_token(app: &Router, id_token: &str, nonce: &str) -> axum::response::Response {
    let payload = serde_json::json!({ "id_token": id_token, "nonce": nonce });
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/google/id-token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn id_token_exchange_creates_user_and_mints_session() {
    let http = build_http_client();
    let server = wiremock::MockServer::start().await;
    let base = server.uri();
    mount_discovery_and_jwks(&server, &base).await;
    let (app, _provider, authority) = build_router(&server, &http).await;

    let nonce = take_nonce(&app).await;
    let raw = good_token(&base, &Nonce::new(nonce.clone()), "google-sub-cm-1");

    let resp = post_id_token(&app, &raw, &nonce).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: Value = serde_json::from_str(&body_to_string(resp.into_body()).await).unwrap();
    assert_eq!(body["token_type"], "Bearer");
    assert!(body["access_token"].as_str().unwrap().len() > 32);
    assert!(body["refresh_token"].as_str().unwrap().len() > 32);
    assert!(!body["device_id"].as_str().unwrap().is_empty());
    assert!(body["access_expires_at"].as_i64().unwrap() > now_seconds());

    let stored = authority
        .users()
        .get(&UserId::new(body["user_id"].as_str().unwrap()))
        .await
        .expect("get by id")
        .expect("user persisted under the id the exchange returned");
    assert_eq!(stored.email.as_deref(), Some("alice@example.com"));
    assert_eq!(stored.name.as_deref(), Some("Alice Anderson"));
    assert_eq!(authority.users().user_count(), 1);
}

/// The nonce is consumed by the first exchange, so posting the identical
/// (still-unexpired, still-correctly-signed) token again is refused. This is
/// the whole point of minting it server-side: Google's `exp` is an hour wide.
#[tokio::test]
async fn replaying_the_same_id_token_is_refused() {
    let http = build_http_client();
    let server = wiremock::MockServer::start().await;
    let base = server.uri();
    mount_discovery_and_jwks(&server, &base).await;
    let (app, _provider, authority) = build_router(&server, &http).await;

    let nonce = take_nonce(&app).await;
    let raw = good_token(&base, &Nonce::new(nonce.clone()), "google-sub-cm-2");

    assert_eq!(post_id_token(&app, &raw, &nonce).await.status(), StatusCode::OK);

    let resp = post_id_token(&app, &raw, &nonce).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_str(&body_to_string(resp.into_body()).await).unwrap();
    assert_eq!(body["error"], "unknown_flow");
    // The replay minted nothing.
    assert_eq!(authority.users().user_count(), 1);
}

/// A token whose `nonce` the client picked — or that carries none at all —
/// is not evidence of a live exchange.
#[tokio::test]
async fn id_token_with_a_foreign_nonce_is_refused() {
    let http = build_http_client();
    let server = wiremock::MockServer::start().await;
    let base = server.uri();
    mount_discovery_and_jwks(&server, &base).await;
    let (app, _provider, authority) = build_router(&server, &http).await;

    let nonce = take_nonce(&app).await;
    let foreign = good_token(
        &base,
        &Nonce::new("client-picked-this".to_owned()),
        "google-sub-cm-3",
    );

    let resp = post_id_token(&app, &foreign, &nonce).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: Value = serde_json::from_str(&body_to_string(resp.into_body()).await).unwrap();
    assert_eq!(body["error"], "id_token_invalid");

    // Same again with no nonce claim at all.
    let nonce = take_nonce(&app).await;
    let nonceless = build_id_token(
        &base,
        None,
        CLIENT_ID,
        Duration::seconds(600),
        "google-sub-cm-3",
    )
    .to_string();
    let resp = post_id_token(&app, &nonceless, &nonce).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    assert_eq!(authority.users().user_count(), 0);
}

/// `aud` is the check that separates "a token for this server" from "a token
/// some other app on the device got". A token minted for a different client id
/// is refused even with a perfect nonce and signature.
#[tokio::test]
async fn id_token_for_another_audience_is_refused() {
    let http = build_http_client();
    let server = wiremock::MockServer::start().await;
    let base = server.uri();
    mount_discovery_and_jwks(&server, &base).await;
    let (app, _provider, authority) = build_router(&server, &http).await;

    let nonce = take_nonce(&app).await;
    let raw = build_id_token(
        &base,
        Some(&Nonce::new(nonce.clone())),
        "someone-elses-app.apps.googleusercontent.com",
        Duration::seconds(600),
        "google-sub-cm-4",
    )
    .to_string();

    let resp = post_id_token(&app, &raw, &nonce).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(authority.users().user_count(), 0);
}

/// An unparseable body fails as a malformed request, not as a 500 — and an
/// empty `id_token` never reaches the verifier.
#[tokio::test]
async fn empty_fields_are_rejected_as_malformed() {
    let http = build_http_client();
    let server = wiremock::MockServer::start().await;
    let base = server.uri();
    mount_discovery_and_jwks(&server, &base).await;
    let (app, _provider, _authority) = build_router(&server, &http).await;

    let nonce = take_nonce(&app).await;
    let resp = post_id_token(&app, "", &nonce).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let resp = post_id_token(&app, "not-a-jwt", "").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// The same human, both doors: a browser redirect callback and a Credential
/// Manager exchange carrying the same Google `sub` must resolve to one user
/// row, not two. Both routes go through the same
/// `(ProviderKey::OidcGoogle, sub)` lookup — this test is what keeps them
/// there.
#[tokio::test]
async fn browser_callback_and_native_exchange_share_one_user() {
    let http = build_http_client();
    let server = wiremock::MockServer::start().await;
    let base = server.uri();
    mount_discovery_and_jwks(&server, &base).await;
    let (app, provider, authority) = build_router(&server, &http).await;

    // 1. Browser leg: /login -> stashed flow -> /token -> /callback.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/login/google")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let location = resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let state_param = openidconnect::url::Url::parse(&location)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        .expect("state param");

    let stashed = provider
        .flows()
        .take(&state_param)
        .await
        .expect("store ok")
        .expect("flow stashed");
    let redirect_nonce = stashed.nonce().clone();
    provider
        .flows()
        .put(&state_param, stashed)
        .await
        .expect("re-put");

    let redirect_token = build_id_token(
        &base,
        Some(&redirect_nonce),
        CLIENT_ID,
        Duration::seconds(600),
        "google-sub-shared",
    );
    let token_response = CoreTokenResponse::new(
        AccessToken::new("test-access-token".to_owned()),
        CoreTokenType::Bearer,
        CoreIdTokenFields::new(Some(redirect_token), EmptyExtraTokenFields {}),
    );
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&token_response))
        .mount(&server)
        .await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/callback/google?code=auth-code-xyz&state={state_param}"
                ))
                .header(header::COOKIE, format!("cheers_csrf_google={state_param}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let browser_body: Value =
        serde_json::from_str(&body_to_string(resp.into_body()).await).unwrap();

    // 2. Native leg: same `sub`, fresh nonce, no browser involved.
    let nonce = take_nonce(&app).await;
    let raw = good_token(&base, &Nonce::new(nonce.clone()), "google-sub-shared");
    let resp = post_id_token(&app, &raw, &nonce).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let native_body: Value = serde_json::from_str(&body_to_string(resp.into_body()).await).unwrap();

    assert_eq!(browser_body["user_id"], native_body["user_id"]);
    // Two sign-ins, two device rows, one human.
    assert_ne!(browser_body["device_id"], native_body["device_id"]);
    assert_eq!(authority.users().user_count(), 1);
}
