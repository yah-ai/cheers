//! Full Google OIDC round-trip through the axum router.
//! Drives /login -> stash nonce -> wiremock token endpoint -> /callback
//! -> assert SessionBody fields + UserStore got the row.

#![cfg(feature = "google")]

mod common;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode, header};
use chrono::{Duration, Utc};
use openidconnect::core::{
    CoreIdToken, CoreIdTokenClaims, CoreIdTokenFields, CoreJwsSigningAlgorithm,
    CoreProviderMetadata, CoreTokenResponse, CoreTokenType,
};
use openidconnect::{
    AccessToken, Audience, ClientId, ClientSecret, EmptyAdditionalClaims,
    EmptyExtraTokenFields, EndUserEmail, EndUserName, IssuerUrl, LocalizedClaim, Nonce,
    RedirectUrl, StandardClaims, SubjectIdentifier,
};
use serde_json::Value;
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

use cheers::providers::google::GoogleProvider;
use cheers::providers::oidc_generic::{MemoryOidcFlowStore, OidcFlowStore};
use cheers_axum::cookie::CsrfCookieConfig;
use cheers_axum::google::{router, GoogleAuthState};

use common::{
    body_to_string, build_http_client, mount_discovery_and_jwks, signing_key, now_seconds,
    test_authority, TestAuthority,
};

const CLIENT_ID: &str = "test-client.apps.googleusercontent.com";
const REDIRECT_URI: &str = "https://app.example/auth/callback/google";

fn build_id_token(issuer: &str, nonce: &Nonce, email: &str, name: &str, sub: &str) -> CoreIdToken {
    let now = Utc::now();
    let mut std_claims = StandardClaims::new(SubjectIdentifier::new(sub.to_owned()))
        .set_email(Some(EndUserEmail::new(email.to_owned())))
        .set_email_verified(Some(true));
    let mut lc: LocalizedClaim<EndUserName> = LocalizedClaim::default();
    lc.insert(None, EndUserName::new(name.to_owned()));
    std_claims = std_claims.set_name(Some(lc));

    let claims = CoreIdTokenClaims::new(
        IssuerUrl::new(issuer.to_owned()).unwrap(),
        vec![Audience::new(CLIENT_ID.to_owned())],
        now + Duration::seconds(600),
        now,
        std_claims,
        EmptyAdditionalClaims {},
    )
    .set_nonce(Some(nonce.clone()));

    CoreIdToken::new(
        claims,
        &signing_key(),
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        None,
        None,
    )
    .expect("ID token signs")
}

async fn mount_token_endpoint(server: &wiremock::MockServer, id_token: CoreIdToken) {
    let resp = CoreTokenResponse::new(
        AccessToken::new("test-access-token".to_owned()),
        CoreTokenType::Bearer,
        CoreIdTokenFields::new(Some(id_token), EmptyExtraTokenFields {}),
    );
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&resp))
        .mount(server)
        .await;
}

async fn peek_stashed_nonce(
    provider: &GoogleProvider<MemoryOidcFlowStore>,
    csrf_state_secret: &str,
) -> Nonce {
    let st = provider
        .flows()
        .take(csrf_state_secret)
        .await
        .expect("store ok")
        .expect("flow stashed");
    let nonce = st.nonce().clone();
    provider
        .flows()
        .put(csrf_state_secret, st)
        .await
        .expect("re-put");
    nonce
}

async fn build_router(
    server: &wiremock::MockServer,
    http: &openidconnect::reqwest::Client,
) -> (Router, Arc<GoogleProvider<MemoryOidcFlowStore>>, Arc<TestAuthority>) {
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

fn extract_cookie_value(set_cookie: &HeaderValue, name: &str) -> Option<String> {
    let s = set_cookie.to_str().ok()?;
    let first = s.split(';').next()?;
    let (k, v) = first.split_once('=')?;
    if k.trim() == name {
        Some(v.trim().to_owned())
    } else {
        None
    }
}

#[tokio::test]
async fn full_round_trip_creates_user_and_mints_session() {
    let http = build_http_client();
    let server = wiremock::MockServer::start().await;
    let base = server.uri();
    mount_discovery_and_jwks(&server, &base).await;
    let (app, provider, authority) = build_router(&server, &http).await;

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
    let csrf = extract_cookie_value(
        resp.headers().get(header::SET_COOKIE).unwrap(),
        "cheers_csrf_google",
    )
    .expect("csrf cookie value");

    let parsed = openidconnect::url::Url::parse(&location).unwrap();
    let state_param = parsed
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        .expect("state param");
    assert_eq!(state_param, csrf);

    let nonce = peek_stashed_nonce(&provider, &state_param).await;
    let id_token = build_id_token(
        &base,
        &nonce,
        "alice@example.com",
        "Alice Anderson",
        "google-sub-001",
    );
    mount_token_endpoint(&server, id_token).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/auth/callback/google?code=auth-code-xyz&state={state_param}"))
                .header(
                    header::COOKIE,
                    format!("cheers_csrf_google={state_param}"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let clear = resp
        .headers()
        .get(header::SET_COOKIE)
        .expect("clear Set-Cookie")
        .to_str()
        .unwrap();
    assert!(clear.contains("cheers_csrf_google="));
    assert!(clear.contains("Max-Age=0"));

    let body: Value = serde_json::from_str(&body_to_string(resp.into_body()).await).unwrap();
    assert_eq!(body["token_type"], "Bearer");
    assert!(body["access_token"].as_str().unwrap().len() > 32);
    assert!(body["refresh_token"].as_str().unwrap().len() > 32);
    assert_eq!(body["user_id"].as_str().unwrap(), "u-1");
    assert!(!body["device_id"].as_str().unwrap().is_empty());
    assert!(!body["jti"].as_str().unwrap().is_empty());
    assert!(body["access_expires_at"].as_i64().unwrap() > now_seconds());
    assert!(body["refresh_expires_at"].as_i64().unwrap() > now_seconds());

    let stored = authority
        .users()
        .lookup_email("alice@example.com")
        .expect("user persisted");
    assert_eq!(stored.name.as_deref(), Some("Alice Anderson"));
    assert_eq!(authority.users().user_count(), 1);
}
