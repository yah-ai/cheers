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
//! - `scopes_supported` — read from the deployment's
//!   [`ScopeRegistry`](cheers_core::ScopeRegistry) in [`DiscoveryState`], in
//!   declaration order. The registry is the same one the mint path validates
//!   against, so the discovery doc cannot drift from what cheers will sign.
//! - `grant_types_supported` — RFC 8693 token-exchange plus cheers's
//!   `passkey` grant.
//! - `subject_types_supported` — the three principal kinds the doc enumerates
//!   (`user`, `service`, `camp`). Note this re-uses the OIDC field name to
//!   carry cheers's principal-kind vocabulary, not OIDC's pseudonymity
//!   variants (`public` / `pairwise`) — consistent with the spec doc.
//!
//! ## yah kamaji coordination
//!
//! yah's kamaji serves its own
//! `${kamaji}/.well-known/oauth-protected-resource` that points back at
//! cheers's issuer — that's the discovery hop MCP clients follow to reach
//! cheers. The kamaji does not rewrite this document; it just references
//! cheers's `issuer` field.
//!
//! ## Wiring
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use axum::Router;
//! # use cheers_axum::discovery::{router, DiscoveryState};
//! let scopes = Arc::new(cheers_core::yah_scopes::registry_at(["https://kamaji.example"]).unwrap());
//! let state = Arc::new(DiscoveryState::new("https://cheers.example", scopes));
//! let app: Router = Router::new().merge(router(state));
//! ```
//!
//! @yah:ticket(R731-F5, "POST /token — one token endpoint for client assertion and RFC 8693 exchange (D6)")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:at(2026-10-06T23:43:00Z)
//! @yah:phase(P2)
//! @yah:parent(R731)
//! @yah:next("Doc D6. The exchange mint side exists (mint_token_exchange, user + camp); the route does not. Discovery already advertises token_endpoint=/token and the token-exchange grant type (discovery.rs:60,69), so until this lands it advertises a dead endpoint.")
//! @yah:next("Takes audience + scope; grant_type selects assertion or exchange. Replaces per-feature mint doors in consumers (noisetable issues, diagnostics, assist).")
//! @yah:next("yubaba (oss/yubaba cheers_client.rs:204 self-signs an ownership:write token) moves onto this endpoint; coordinate in the yah camp.")
//! @yah:depends_on(R731-F4)
//! @yah:tier(Warrior)
//! @yah:next("F5 DECIDED (leader, 2026-10-06). POST /token, form-encoded (application/x-www-form-urlencoded), one route in cheers-axum dispatching on grant_type. (a) `urn:ietf:params:oauth:grant-type:token-exchange` (RFC 8693): subject_token, subject_token_type, audience, scope (space-separated), routed to mint_token_exchange; the response carries issued_token_type. (b) `client_credentials` with client_assertion_type = `urn:cheers:client-assertion-type:paseto-v4-public` plus client_assertion, routed to mint_service. The assertion is PASETO, not a JWT, so do NOT advertise RFC 7523's jwt-bearer URN. Success is RFC 6749 §5.1 JSON {access_token, token_type: \"Bearer\", expires_in, scope}. Errors are RFC 6749 §5.2 JSON {error: invalid_request | invalid_client | invalid_grant | invalid_scope | unsupported_grant_type}, with 400, or 401 for invalid_client. Discovery: token_endpoint stays /token; grant_types_supported lists both; add token_endpoint_auth_methods_supported naming the cheers assertion type. A test pins that discovery advertises only grants the route serves. yubaba (oss/yubaba cheers_client.rs) is NOT edited here: append the exact client flow to yah R426 so the yah-side relay moves it.")
//! @yah:handoff("NEW crates/cheers-axum/src/token_endpoint.rs (pub mod in lib.rs): TokenEndpointState<B,G,O,V,Rd>{mcp: Arc<McpAuthority>, edge: Arc<EdgeVerifier> (verifies the user session), camps: Arc<dyn CampPrincipalStore> (resolves the camp credential)} + router(state) mounting POST /token. Form-encoded; every field is Option so missing params are a 5.2 invalid_request, not an axum rejection. Dispatches on grant_type.")
//! @yah:handoff("RFC 8693 mapping (route doc comment has the table): subject_token = camp bootstrap credential, subject_token_type=urn:cheers:token-type:camp-bootstrap (unknown, expired, revoked or non-Active camp -> invalid_grant); actor_token = user session access token, actor_token_type=urn:ietf:params:oauth:token-type:access_token (EdgeVerifier failure -> invalid_grant); audience -> aud; scope (space-separated, required non-empty) -> requested_scope; act=None because no wire param carries an agent. issued_token_type=urn:ietf:params:oauth:token-type:access_token. This follows mint_token_exchange's own doc: camp is the subject, user is the actor, sub of the result is the user.")
//! @yah:handoff("client_credentials: client_assertion_type must be urn:cheers:client-assertion-type:paseto-v4-public (otherwise invalid_client), client_assertion -> mint_service, audience required, scope optional (empty = everything the relationship grants).")
//! @yah:handoff("map_mint_error (pub): Assertion{Malformed,UnknownKid,RetiredKey,PrincipalMismatch,BadAudience,Expired,LifetimeTooLong} -> invalid_client 401; AssertionReplayed -> invalid_grant; AudNotEntitled/InvalidScope/UnentitledScopes/NoGrantedScopes -> invalid_scope; TtlOutOfRange -> invalid_request; Store/JtiStore -> 503 temporarily_unavailable; everything else -> 500 server_error with a generic description (logged). Unregistered or unparsable scope -> invalid_scope. Success = 6749 5.1 JSON + issued_token_type on exchange; every response carries Cache-Control: no-store.")
//! @yah:handoff("Discovery: GRANT_TYPES_SUPPORTED is now owned by token_endpoint and re-exported by discovery (so they cannot drift) = [token-exchange, client_credentials]. passkey is REMOVED because the route serves no passkey grant. New field token_endpoint_auth_methods_supported=[urn:cheers:client-assertion-type:paseto-v4-public]. Inline discovery tests updated.")
//! @yah:handoff("Tests: tests/token_endpoint_basic.rs (mod added to tests/main.rs) has 6 cases: assertion flow with scope from a seeded relationship, verified at the edge; replay -> invalid_grant; garbage assertion -> 401 invalid_client; unknown grant_type -> unsupported_grant_type, missing grant_type -> invalid_request; full exchange (camp provisioned via CampAuthority with a signed delegation, real session) plus scope outside the camp's grants -> invalid_scope and an unknown credential -> invalid_grant; discovery advertises exactly the 2 grants + auth method and each advertised grant dispatches. pasetors 0.7 added as a cheers-axum dev-dep.")
//! @yah:handoff("yubaba was not edited. The client flow is appended to yah R426 as a gotcha. F8 files were not touched; lib.rs got one line and tests/main.rs got one line.")
//! @yah:verify("cargo test --workspace --no-fail-fast (oss/cheers): 702 passed / 0 failed / 4 ignored, against the 696/0/4 baseline measured before the first edit. My +6 are the token_endpoint_basic tests.")
//! @yah:verify("cargo test -p cheers-axum --test main token_endpoint_basic: 6/6 pass with no new warnings.")
//! @yah:handoff("CORRECTION (leader follow-up): the first RFC 8693 mapping had subject and actor inverted. Corrected mapping: subject_token = the user session (urn:ietf:params:oauth:token-type:access_token, verified by EdgeVerifier) is the party the token is ABOUT; actor_token = the camp bootstrap credential (urn:cheers:token-type:camp-bootstrap, resolved via CampPrincipalStore) is the party ACTING for the user. The route passes actor = Some(Actor::new(camp)) to mint_token_exchange, so the issued token carries sub=user, camp_id=camp and act={sub: camp:<id>} (RFC 8693 §4.1), which F8's ownership attribution reads as act->granted_by and sub->on_behalf_of. No more specific actor is reachable from the wire, so the camp is always the actor. The exchange test now asserts sub, act.sub and camp_id. Two rejection cases were added: swapped roles with honest type labels -> invalid_request, and swapped tokens under the correct labels -> invalid_grant. Workspace: 702/0/4, unchanged from the prior end state (the new assertions sit inside the existing test).")
//! @yah:verify("Leader final re-verify 2026-10-06 (quiet tree, no skew): cheers workspace 702 pass / 0 fail / 4 ignored, including token_endpoint_basic. The RFC 8693 mapping was corrected in-ticket after leader review: subject_token = user session, actor_token = camp bootstrap credential, and the issued token has sub = user, act = {sub: camp}. That matches the act -> granted_by / sub -> on_behalf_of attribution in R731-F8's ownership door.")

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::routing::get;
use serde::{Deserialize, Serialize};

use cheers_core::ScopeRegistry;

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

/// `grant_types_supported`: exactly the grants `POST /token` serves (R731-F5)
/// — RFC 8693 token-exchange and `client_credentials`. Re-exported from the
/// route so discovery cannot advertise a grant the endpoint does not take.
pub use crate::token_endpoint::{GRANT_TYPES_SUPPORTED, TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED};

/// State held by the discovery handler.
///
/// The issuer URL plus the deployment's [`ScopeRegistry`]; every other field
/// is static.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DiscoveryState {
    /// The cheers issuer URL (no trailing slash). Used as `issuer` and as the
    /// prefix for `jwks_uri` and `token_endpoint`.
    pub issuer: String,
    /// The deployment's scope vocabulary; `scopes_supported` lists it.
    pub scopes: Arc<ScopeRegistry>,
}

impl DiscoveryState {
    pub fn new(issuer: impl Into<String>, scopes: Arc<ScopeRegistry>) -> Self {
        Self {
            issuer: issuer.into(),
            scopes,
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
    pub token_endpoint_auth_methods_supported: Vec<String>,
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
    Json(build_configuration(&state.issuer, &state.scopes))
}

fn build_configuration(issuer: &str, scopes: &ScopeRegistry) -> OpenIdConfiguration {
    OpenIdConfiguration {
        issuer: issuer.to_string(),
        jwks_uri: format!("{issuer}{JWKS_PATH}"),
        token_endpoint: format!("{issuer}{TOKEN_ENDPOINT_PATH}"),
        scopes_supported: scopes.iter().map(|d| d.scope.as_wire().to_string()).collect(),
        grant_types_supported: GRANT_TYPES_SUPPORTED
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        token_endpoint_auth_methods_supported: TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED
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
    use cheers_core::yah_scopes;

    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt;

    async fn body_json<T: for<'de> serde::Deserialize<'de>>(body: Body) -> T {
        let bytes = to_bytes(body, 64 * 1024).await.expect("body bytes");
        serde_json::from_slice(&bytes).expect("json decode")
    }

    fn app() -> Router {
        app_with(Arc::new(yah_scopes::registry_at(["https://cheers.example"]).unwrap()))
    }

    fn app_with(scopes: Arc<ScopeRegistry>) -> Router {
        let state = Arc::new(DiscoveryState::new("https://cheers.example", scopes));
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
            yah_scopes::DEFS.iter().map(|d| d.scope.as_wire().to_string()).collect();
        let expected = OpenIdConfiguration {
            issuer: "https://cheers.example".into(),
            jwks_uri: "https://cheers.example/.well-known/jwks.json".into(),
            token_endpoint: "https://cheers.example/token".into(),
            scopes_supported: expected_scopes,
            grant_types_supported: vec![
                "urn:ietf:params:oauth:grant-type:token-exchange".into(),
                "client_credentials".into(),
            ],
            token_endpoint_auth_methods_supported: vec![
                "urn:cheers:client-assertion-type:paseto-v4-public".into(),
            ],
            subject_types_supported: vec!["user".into(), "service".into(), "camp".into()],
        };
        assert_eq!(cfg, expected);
    }

    #[tokio::test]
    async fn scopes_supported_equals_the_registry() {
        // A registry wider than yah's set: discovery must list exactly what
        // the deployment registered, in declaration order.
        mod extra {
            cheers_core::scopes! {
                TRIAGE = "issues:triage" {
                    description: "triage",
                    audiences: ["https://issues.example"],
                };
            }
        }
        let scopes = Arc::new(
            yah_scopes::NAMESPACES
                .iter()
                .fold(yah_scopes::builder().with(extra::DEFS), |b, ns| {
                    b.bind_audiences(ns, ["https://cheers.example".to_owned()])
                })
                .build()
                .unwrap(),
        );
        let req = Request::builder()
            .method("GET")
            .uri(OPENID_CONFIGURATION_PATH)
            .body(Body::empty())
            .unwrap();
        let resp = app_with(scopes.clone()).oneshot(req).await.unwrap();
        let cfg: OpenIdConfiguration = body_json(resp.into_body()).await;
        let from_registry: Vec<String> =
            scopes.iter().map(|d| d.scope.as_wire().to_string()).collect();
        assert_eq!(
            cfg.scopes_supported, from_registry,
            "scopes_supported must reflect the registry exactly (order and contents)",
        );
        assert_eq!(cfg.scopes_supported.len(), 19);
        assert_eq!(cfg.scopes_supported.last().map(String::as_str), Some("issues:triage"));
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
            cfg.grant_types_supported.contains(&"client_credentials".to_string()),
            "client_credentials grant must be advertised",
        );
        assert!(
            !cfg.grant_types_supported.contains(&"passkey".to_string()),
            "POST /token serves no passkey grant, so discovery must not advertise one",
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
