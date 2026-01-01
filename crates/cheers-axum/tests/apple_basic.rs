//! Smoke tests for Apple Sign-In routes — login redirect (form-post mode),
//! CSRF rejection, and provider-error short-circuit. Full /token round-trip
//! lives in `apple_round_trip.rs`.

#![cfg(feature = "apple")]

mod common;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use openidconnect::{ClientId, RedirectUrl};
use serde_json::Value;
use tower::ServiceExt;

use cheers::providers::apple::{
    apple_provider_metadata, AppleClientSecret, AppleRedirectProvider,
};
use cheers::providers::oidc_generic::MemoryOidcFlowStore;
use cheers_axum::apple::{router, AppleAuthState};
use cheers_axum::cookie::CsrfCookieConfig;

use common::{body_to_string, build_http_client, test_authority};

const CLIENT_ID: &str = "com.example.signin";
const REDIRECT_URI: &str = "https://app.example/auth/callback/apple";

/// Apple needs a P-256 `.p8` key. Use a deterministic test scalar — same
/// trick the upstream cheers Apple tests use. No live Apple talk-to here, so
/// no signature verification matters.
fn deterministic_p8_pem() -> String {
    use p256::pkcs8::{EncodePrivateKey, LineEnding};
    let mut bytes = [0u8; 32];
    bytes[31] = 0x42;
    let sk = p256::SecretKey::from_slice(&bytes).expect("valid P-256 scalar");
    sk.to_pkcs8_pem(LineEnding::LF)
        .expect("P-256 PKCS#8 PEM")
        .to_string()
}

fn apple_secret() -> Arc<AppleClientSecret> {
    Arc::new(
        AppleClientSecret::from_p8_pem(
            "TEAM123ABC",
            "KEYID45678",
            CLIENT_ID,
            deterministic_p8_pem().as_bytes(),
        )
        .expect("p8 pem parses"),
    )
}

async fn build_app(http: &openidconnect::reqwest::Client) -> Router {
    let provider = Arc::new(AppleRedirectProvider::from_provider_metadata(
        apple_provider_metadata(),
        ClientId::new(CLIENT_ID.into()),
        RedirectUrl::new(REDIRECT_URI.into()).unwrap(),
        apple_secret(),
        MemoryOidcFlowStore::new(),
    ));
    let authority = Arc::new(test_authority());
    let state = AppleAuthState {
        provider,
        authority,
        http: http.clone(),
        cookie: CsrfCookieConfig::for_apple("cheers_csrf_apple").with_secure(false),
    };
    Router::new().nest("/auth", router(Arc::new(state)))
}

#[tokio::test]
async fn login_redirects_to_apple_with_samesite_none_cookie() {
    let http = build_http_client();
    let app = build_app(&http).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/auth/login/apple")
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
    assert!(location.starts_with("https://appleid.apple.com/auth/authorize"));
    assert!(location.contains("response_mode=form_post"));
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header")
        .to_str()
        .unwrap();
    assert!(set_cookie.starts_with("cheers_csrf_apple="));
    assert!(set_cookie.contains("HttpOnly"));
    // Apple needs SameSite=None because the callback POST is cross-site.
    assert!(set_cookie.contains("SameSite=None"));
}

#[tokio::test]
async fn callback_without_cookie_is_400_missing_csrf() {
    let http = build_http_client();
    let app = build_app(&http).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/auth/callback/apple")
                .method("POST")
                .header(
                    header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(Body::from("code=C&state=S"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_str(&body_to_string(resp.into_body()).await).unwrap();
    assert_eq!(body["error"], "missing_csrf_cookie");
}

#[tokio::test]
async fn callback_with_apple_error_body_is_400_provider() {
    let http = build_http_client();
    let app = build_app(&http).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/auth/callback/apple")
                .method("POST")
                .header(
                    header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(Body::from("error=user_cancelled_authorize"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_str(&body_to_string(resp.into_body()).await).unwrap();
    assert_eq!(body["error"], "provider_error");
}
