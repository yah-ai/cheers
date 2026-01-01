//! `GET /.well-known/openid-configuration` — OIDC discovery document.
//!
//! Standard OIDC-discovery shape per the
//! [`mcp-auth-and-ownership.md`](../../../.yah/docs/working/mcp-auth-and-ownership.md)
//! §Discovery section. The doc pins these fields:
//!
//! - `issuer` — the product-supplied cheers issuer URL.
//! - `jwks_uri` — `<issuer>/.well-known/jwks.json` (the [`jwks`](crate::jwks)
//!   route).
//! - `token_endpoint` — `<issuer>/token` (the multi-grant token endpoint
//!   landing in a peer ticket).
//! - `scopes_supported` — derived directly from
//!   [`cheers_core::Scope::ALL`](cheers_core::Scope::ALL); the enum is the
//!   single source of truth, so the discovery doc cannot drift from what the
//!   mint path accepts. A regression test pinned at the cheers-core level
//!   forces `ALL` to stay exhaustive as the vocabulary grows.
//! - `grant_types_supported` — RFC 8693 token-exchange plus cheers's
//!   `passkey` grant.
//! - `subject_types_supported` — the three principal kinds the doc enumerates
//!   (`user`, `service`, `camp`). Note this re-uses the OIDC field name to
//!   carry cheers's principal-kind vocabulary, not OIDC's pseudonymity
//!   variants (`public` / `pairwise`) — consistent with the spec doc.
//!
//! ## yah constable coordination
//!
//! yah's constable serves its own
//! `${constable}/.well-known/oauth-protected-resource` that points back at
//! cheers's issuer — that's the discovery hop MCP clients follow to reach
//! cheers. The constable does not rewrite this document; it just references
//! cheers's `issuer` field.
//!
//! ## Wiring
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use axum::Router;
//! # use cheers_axum::discovery::{router, DiscoveryState};
//! let state = Arc::new(DiscoveryState::new("https://cheers.example"));
//! let app: Router = Router::new().merge(router(state));
//! ```

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::routing::get;
use serde::{Deserialize, Serialize};

use cheers_core::Scope;

/// Path the route is mounted at — `<issuer>/.well-known/openid-configuration`.
pub const OPENID_CONFIGURATION_PATH: &str = "/.well-known/openid-configuration";

/// Sub-path of `jwks_uri` relative to the issuer — kept verbatim with the
/// path the [`jwks`](crate::jwks) module mounts.
pub const JWKS_PATH: &str = "/.well-known/jwks.json";

/// Sub-path of `token_endpoint` relative to the issuer.
pub const TOKEN_ENDPOINT_PATH: &str = "/token";

/// `subject_types_supported` values per the doc. Cheers's three principal
/// kinds, not OIDC's pseudonymity variants — see the module docs.
pub const SUBJECT_TYPES_SUPPORTED: &[&str] = &["user", "service", "camp"];

/// `grant_types_supported` values per the doc. RFC 8693 token-exchange plus
/// the `passkey` grant.
pub const GRANT_TYPES_SUPPORTED: &[&str] = &[
    "urn:ietf:params:oauth:grant-type:token-exchange",
    "passkey",
];

/// State held by the discovery handler.
///
/// Only the issuer URL is needed — all other fields are derived statically
/// or from the typed [`Scope`] enum.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DiscoveryState {
    /// The cheers issuer URL (no trailing slash). Used as `issuer` and as the
    /// prefix for `jwks_uri` and `token_endpoint`.
    pub issuer: String,
}

impl DiscoveryState {
    pub fn new(issuer: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
        }
    }
}

/// The OIDC discovery document body. Fields match the doc's §Discovery
/// example verbatim. `#[non_exhaustive]` so additional fields can land
/// without a breaking API change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct OpenIdConfiguration {
    pub issuer: String,
    pub jwks_uri: String,
    pub token_endpoint: String,
    pub scopes_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
}

/// Mount `GET /.well-known/openid-configuration`.
pub fn router(state: Arc<DiscoveryState>) -> Router {
    Router::new()
        .route(OPENID_CONFIGURATION_PATH, get(openid_configuration))
        .with_state(state)
}

async fn openid_configuration(
    State(state): State<Arc<DiscoveryState>>,
) -> Json<OpenIdConfiguration> {
    Json(build_configuration(&state.issuer))
}

fn build_configuration(issuer: &str) -> OpenIdConfiguration {
    OpenIdConfiguration {
        issuer: issuer.to_string(),
        jwks_uri: format!("{issuer}{JWKS_PATH}"),
        token_endpoint: format!("{issuer}{TOKEN_ENDPOINT_PATH}"),
        scopes_supported: Scope::ALL.iter().map(|s| s.as_wire().to_string()).collect(),
        grant_types_supported: GRANT_TYPES_SUPPORTED
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        subject_types_supported: SUBJECT_TYPES_SUPPORTED
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt;

    async fn body_json<T: for<'de> serde::Deserialize<'de>>(body: Body) -> T {
        let bytes = to_bytes(body, 64 * 1024).await.expect("body bytes");
        serde_json::from_slice(&bytes).expect("json decode")
    }

    fn app() -> Router {
        let state = Arc::new(DiscoveryState::new("https://cheers.example"));
        Router::new().merge(router(state))
    }

    async fn fetch_configuration() -> OpenIdConfiguration {
        let req = Request::builder()
            .method("GET")
            .uri(OPENID_CONFIGURATION_PATH)
            .body(Body::empty())
            .unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .expect("content-type")
            .clone();
        assert!(
            ct.to_str().unwrap().starts_with("application/json"),
            "content-type must be JSON, got {ct:?}",
        );
        body_json(resp.into_body()).await
    }

    #[tokio::test]
    async fn discovery_doc_matches_known_good_fixture() {
        let cfg = fetch_configuration().await;
        let expected_scopes: Vec<String> =
            Scope::ALL.iter().map(|s| s.as_wire().to_string()).collect();
        let expected = OpenIdConfiguration {
            issuer: "https://cheers.example".into(),
            jwks_uri: "https://cheers.example/.well-known/jwks.json".into(),
            token_endpoint: "https://cheers.example/token".into(),
            scopes_supported: expected_scopes,
            grant_types_supported: vec![
                "urn:ietf:params:oauth:grant-type:token-exchange".into(),
                "passkey".into(),
            ],
            subject_types_supported: vec!["user".into(), "service".into(), "camp".into()],
        };
        assert_eq!(cfg, expected);
    }

    #[tokio::test]
    async fn scopes_supported_equals_the_full_scope_enum() {
        // Pairs with the cheers-core `scope_all_is_exhaustive` test:
        // there, `Scope::ALL` is pinned to every variant; here, the
        // discovery doc is pinned to `Scope::ALL`. Together they make
        // adding a `Scope` variant without surfacing it in discovery a
        // test failure (or a compile error at the cheers-core side).
        let cfg = fetch_configuration().await;
        let from_enum: Vec<String> =
            Scope::ALL.iter().map(|s| s.as_wire().to_string()).collect();
        assert_eq!(
            cfg.scopes_supported, from_enum,
            "scopes_supported must reflect Scope::ALL exactly (order and contents)",
        );
        for s in Scope::ALL {
            assert!(
                cfg.scopes_supported.contains(&s.as_wire().to_string()),
                "{s} missing from scopes_supported",
            );
        }
    }

    #[tokio::test]
    async fn grant_and_subject_types_include_the_required_values() {
        let cfg = fetch_configuration().await;
        assert!(
            cfg.grant_types_supported
                .contains(&"urn:ietf:params:oauth:grant-type:token-exchange".to_string()),
            "token-exchange grant must be advertised",
        );
        assert!(
            cfg.grant_types_supported.contains(&"passkey".to_string()),
            "passkey grant must be advertised",
        );
        assert_eq!(
            cfg.subject_types_supported,
            vec!["user".to_string(), "service".to_string(), "camp".to_string()],
        );
    }

    #[tokio::test]
    async fn issuer_prefixes_jwks_and_token_endpoints() {
        let cfg = fetch_configuration().await;
        assert!(cfg.jwks_uri.starts_with(&cfg.issuer));
        assert!(cfg.token_endpoint.starts_with(&cfg.issuer));
        assert!(cfg.jwks_uri.ends_with(JWKS_PATH));
        assert!(cfg.token_endpoint.ends_with(TOKEN_ENDPOINT_PATH));
    }
}
