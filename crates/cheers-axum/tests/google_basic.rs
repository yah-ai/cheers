//! Smoke tests for Google routes — login redirect + the three CSRF/error
//! rejection paths. No id_token round-trip here; the wiremock'd token
//! endpoint round-trip lives in `google_round_trip.rs`.

#![cfg(feature = "google")]

mod common;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use openidconnect::core::CoreProviderMetadata;
use openidconnect::{ClientId, ClientSecret, IssuerUrl, RedirectUrl};
use serde_json::Value;
use tower::ServiceExt;

use cheers::providers::google::GoogleProvider;
use cheers::providers::oidc_generic::MemoryOidcFlowStore;
use cheers_axum::cookie::CsrfCookieConfig;
use cheers_axum::google::{router, GoogleAuthState};

use common::{
    body_to_string, build_http_client, mount_discovery_and_jwks, test_authority,
};

const CLIENT_ID: &str = "test-client.apps.googleusercontent.com";
const REDIRECT_URI: &str = "https://app.example/auth/callback/google";

async fn build_app(
    server: &wiremock::MockServer,
    http: &openidconnect::reqwest::Client,
) -> Router {
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
        provider,
        authority,
        http: http.clone(),
        cookie: CsrfCookieConfig::new("cheers_csrf_google").with_secure(false),
    };
    Router::new().nest("/auth", router(Arc::new(state)))
}

#[tokio::test]
async fn login_redirects_to_idp_and_sets_csrf_cookie() {
    let http = build_http_client();
    let server = wiremock::MockServer::start().await;
    mount_discovery_and_jwks(&server, &server.uri()).await;
    let app = build_app(&server, &http).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/auth/login/google")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FOUND);
    let location = resp
        .headers()
        .get(header::LOCATION)
        .expect("Location header")
        .to_str()
        .unwrap();
    assert!(location.starts_with(&server.uri()), "Location -> {location}");
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header")
        .to_str()
        .unwrap();
    assert!(set_cookie.starts_with("cheers_csrf_google="));
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Lax"));
}

#[tokio::test]
async fn callback_without_cookie_is_400_missing_csrf() {
    let http = build_http_client();
    let server = wiremock::MockServer::start().await;
    mount_discovery_and_jwks(&server, &server.uri()).await;
    let app = build_app(&server, &http).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/auth/callback/google?code=C&state=S")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_str(&body_to_string(resp.into_body()).await).unwrap();
    assert_eq!(body["error"], "missing_csrf_cookie");
}

#[tokio::test]
async fn callback_with_mismatched_cookie_is_400_state_mismatch() {
    let http = build_http_client();
    let server = wiremock::MockServer::start().await;
    mount_discovery_and_jwks(&server, &server.uri()).await;
    let app = build_app(&server, &http).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/auth/callback/google?code=C&state=WRONG")
                .header(header::COOKIE, "cheers_csrf_google=DIFFERENT")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_str(&body_to_string(resp.into_body()).await).unwrap();
    assert_eq!(body["error"], "csrf_state_mismatch");
}

#[tokio::test]
async fn callback_with_provider_error_param_is_400() {
    let http = build_http_client();
    let server = wiremock::MockServer::start().await;
    mount_discovery_and_jwks(&server, &server.uri()).await;
    let app = build_app(&server, &http).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/auth/callback/google?error=access_denied")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_str(&body_to_string(resp.into_body()).await).unwrap();
    assert_eq!(body["error"], "provider_error");
}
