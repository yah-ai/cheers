//! `POST /token` — cheers's one OAuth token endpoint (R731 doc §D6).
//!
//! Form-encoded (`application/x-www-form-urlencoded`), dispatching on
//! `grant_type`. Exactly two grants are served, and
//! [`GRANT_TYPES_SUPPORTED`] — which discovery advertises verbatim — lists
//! exactly those two:
//!
//! ## (a) RFC 8693 token exchange — user + camp
//!
//! `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, routed to
//! [`McpAuthority::mint_token_exchange`]. The RFC 8693 parameters map onto
//! that call's existing inputs as follows:
//!
//! | RFC 8693 param | value | becomes |
//! |---|---|---|
//! | `subject_token` | the human's cheers session access token — the party the issued token is ABOUT (RFC 8693 §1.1) | `user` — verified by the [`EdgeVerifier`] (signature, expiry, revocation); failure → `invalid_grant` |
//! | `subject_token_type` | `urn:ietf:params:oauth:token-type:access_token` ([`ACCESS_TOKEN_TYPE`]) — the session token honestly is an access token | — |
//! | `actor_token` | the camp's opaque bootstrap credential ([`CampBootstrapCredential::token`]) — the party ACTING for the user | `camp`, AND `actor = Actor(camp)` — looked up in the [`CampPrincipalStore`]; unknown / expired / revoked → `invalid_grant` |
//! | `actor_token_type` | `urn:cheers:token-type:camp-bootstrap` ([`CAMP_BOOTSTRAP_TOKEN_TYPE`]) — cheers-specific: the credential is an opaque cheers secret, not any IETF token type | — |
//! | `audience` | target resource URI | `aud` |
//! | `scope` | space-separated `namespace:verb` | `requested_scope` (must be non-empty; each must be registered) |
//!
//! The issued token is an MCP access token, so `issued_token_type` is
//! `urn:ietf:params:oauth:token-type:access_token`. It carries `sub = user`,
//! `camp_id = <camp>` and `act = {sub: camp:<id>}` (RFC 8693 §4.1). `act` is
//! load-bearing: the ownership door attributes `act` → `granted_by` and
//! `sub` → `on_behalf_of`, so without it a camp's write would be recorded as
//! the user's own. The wire carries no more specific actor (e.g. an agent
//! variant) yet, so the camp is always the actor here.
//!
//! ## (b) `client_credentials` — service principal assertion
//!
//! `grant_type=client_credentials` with
//! `client_assertion_type=urn:cheers:client-assertion-type:paseto-v4-public`
//! ([`PASETO_ASSERTION_TYPE`]) and `client_assertion=<v4.public.*>`, routed
//! to [`McpAuthority::mint_service`]. The assertion is PASETO (iss = sub =
//! `svc:<id>`, aud = `<issuer>/token`, `jti`, `exp - iat <= 300s`, footer
//! `kid`), not a JWT, so RFC 7523's jwt-bearer URN is deliberately NOT used.
//! `audience` names the resource; `scope` optionally narrows (empty = every
//! scope the service's relationships grant at that audience).
//!
//! ## Responses
//!
//! Success is RFC 6749 §5.1 JSON `{access_token, token_type: "Bearer",
//! expires_in, scope, issued_token_type?}` with `Cache-Control: no-store`.
//! Errors are RFC 6749 §5.2 JSON `{error, error_description}`: 400, or 401
//! for `invalid_client`. Server-side faults surface as 500 `server_error` /
//! 503 `temporarily_unavailable`. See [`map_mint_error`] for the per-variant
//! table.

use std::str::FromStr;
use std::sync::Arc;

use axum::extract::rejection::FormRejection;
use axum::extract::{Form, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use cheers_core::{Actor, PrincipalId, PrincipalStatus, Scope, TokenVerifier};
use cheers_server::{
    BundleStore, CampPrincipalStore, EdgeVerifier, GrantStore, McpAuthority, McpMintError,
    MintedMcpToken, OwnershipStore, RevocationReader,
};

use crate::discovery::TOKEN_ENDPOINT_PATH;

/// RFC 8693 token-exchange grant.
pub const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// RFC 6749 §4.4 client-credentials grant (authenticated by a cheers assertion).
pub const CLIENT_CREDENTIALS_GRANT: &str = "client_credentials";
/// The grants this route serves — and therefore the grants discovery
/// advertises. One list, so the two cannot drift.
pub const GRANT_TYPES_SUPPORTED: &[&str] = &[TOKEN_EXCHANGE_GRANT, CLIENT_CREDENTIALS_GRANT];

/// `client_assertion_type` for a service principal's PASETO v4.public
/// assertion. Also the sole `token_endpoint_auth_methods_supported` entry.
pub const PASETO_ASSERTION_TYPE: &str = "urn:cheers:client-assertion-type:paseto-v4-public";
/// The auth methods the endpoint accepts.
pub const TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED: &[&str] = &[PASETO_ASSERTION_TYPE];

/// `actor_token_type` for a camp bootstrap credential (cheers-specific).
pub const CAMP_BOOTSTRAP_TOKEN_TYPE: &str = "urn:cheers:token-type:camp-bootstrap";
/// RFC 8693 §3 access-token type: the user's session token on the way in,
/// the minted MCP token on the way out.
pub const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// State for `POST /token`.
pub struct TokenEndpointState<B, G, O, V, Rd> {
    /// Mints both grants. Must be assembled
    /// [`with_service_assertions`](McpAuthority::with_service_assertions)
    /// for `client_credentials` to work (else 500 `server_error`).
    pub mcp: Arc<McpAuthority<B, G, O>>,
    /// Verifies the exchange's `subject_token` (the user's session).
    pub edge: Arc<EdgeVerifier<V, Rd>>,
    /// Resolves the exchange's `actor_token` (the camp credential).
    pub camps: Arc<dyn CampPrincipalStore>,
}

impl<B, G, O, V, Rd> std::fmt::Debug for TokenEndpointState<B, G, O, V, Rd> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenEndpointState").finish_non_exhaustive()
    }
}

/// Mount `POST /token` at the issuer root (the path discovery advertises).
pub fn router<B, G, O, V, Rd>(state: Arc<TokenEndpointState<B, G, O, V, Rd>>) -> Router
where
    B: BundleStore + Send + Sync + 'static,
    G: GrantStore + Send + Sync + 'static,
    O: OwnershipStore + Send + Sync + 'static,
    V: TokenVerifier + Send + Sync + 'static,
    Rd: RevocationReader + Send + Sync + 'static,
{
    Router::new()
        .route(TOKEN_ENDPOINT_PATH, post(token::<B, G, O, V, Rd>))
        .with_state(state)
}

/// The form body. Every field optional so a missing one is a §5.2
/// `invalid_request`, not an axum rejection.
#[derive(Debug, Default, Deserialize)]
pub struct TokenRequest {
    pub grant_type: Option<String>,
    pub audience: Option<String>,
    pub scope: Option<String>,
    pub subject_token: Option<String>,
    pub subject_token_type: Option<String>,
    pub actor_token: Option<String>,
    pub actor_token_type: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
}

/// RFC 6749 §5.1 success body (+ RFC 8693 `issued_token_type`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_token_type: Option<String>,
}

/// RFC 6749 §5.2 error codes this endpoint emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthErrorCode {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    InvalidScope,
    UnsupportedGrantType,
    ServerError,
    TemporarilyUnavailable,
}

impl OAuthErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::InvalidScope => "invalid_scope",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
        }
    }

    fn status(self) -> StatusCode {
        match self {
            Self::InvalidClient => StatusCode::UNAUTHORIZED,
            Self::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::TemporarilyUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::BAD_REQUEST,
        }
    }
}

/// A §5.2 error response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthError {
    pub code: OAuthErrorCode,
    pub description: String,
}

impl OAuthError {
    fn new(code: OAuthErrorCode, description: impl Into<String>) -> Self {
        Self { code, description: description.into() }
    }
}

#[derive(Serialize)]
struct OAuthErrorBody<'a> {
    error: &'a str,
    error_description: &'a str,
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let body = OAuthErrorBody {
            error: self.code.as_str(),
            error_description: &self.description,
        };
        (self.code.status(), no_store(), Json(body)).into_response()
    }
}

fn no_store() -> [(header::HeaderName, &'static str); 2] {
    [(header::CACHE_CONTROL, "no-store"), (header::PRAGMA, "no-cache")]
}

/// Map a mint failure onto §5.2.
///
/// - assertion authentication failures (malformed, unknown / retired kid,
///   principal mismatch, wrong `aud`, expired, too long) → `invalid_client` 401;
/// - a replayed assertion `jti` → `invalid_grant` (the client authenticated
///   once already; this presentation is the grant being reused);
/// - no entitlement at `aud` / scope outside the grants → `invalid_scope`;
/// - `TtlOutOfRange` → `invalid_request` (not reachable from this route);
/// - wrong principal kind, unconfigured assertions, misconfigured grants or
///   bundles, codec → 500 `server_error`; store / jti-store → 503.
pub fn map_mint_error(e: McpMintError) -> OAuthError {
    use OAuthErrorCode::*;
    let code = match &e {
        McpMintError::AssertionMalformed(_)
        | McpMintError::AssertionUnknownKid(_)
        | McpMintError::AssertionRetiredKey(_)
        | McpMintError::AssertionPrincipalMismatch { .. }
        | McpMintError::AssertionBadAudience { .. }
        | McpMintError::AssertionExpired { .. }
        | McpMintError::AssertionLifetimeTooLong { .. } => InvalidClient,
        McpMintError::AssertionReplayed(_) => InvalidGrant,
        McpMintError::AudNotEntitled { .. }
        | McpMintError::InvalidScope { .. }
        | McpMintError::UnentitledScopes { .. }
        | McpMintError::NoGrantedScopes { .. } => InvalidScope,
        McpMintError::TtlOutOfRange { .. } => InvalidRequest,
        McpMintError::Store(_) | McpMintError::JtiStore(_) => TemporarilyUnavailable,
        _ => ServerError,
    };
    let description = match code {
        // Don't echo internals for server-side faults.
        ServerError | TemporarilyUnavailable => {
            tracing::error!(error = %e, "POST /token mint failure");
            "token mint failed".to_owned()
        }
        _ => e.to_string(),
    };
    OAuthError::new(code, description)
}

/// `POST /token`.
pub async fn token<B, G, O, V, Rd>(
    State(state): State<Arc<TokenEndpointState<B, G, O, V, Rd>>>,
    form: Result<Form<TokenRequest>, FormRejection>,
) -> Result<Response, OAuthError>
where
    B: BundleStore,
    G: GrantStore,
    O: OwnershipStore,
    V: TokenVerifier + Send + Sync,
    Rd: RevocationReader,
{
    let Form(req) = form.map_err(|e| {
        OAuthError::new(OAuthErrorCode::InvalidRequest, format!("malformed form body: {e}"))
    })?;
    let now = now_unix();
    let grant_type = required(&req.grant_type, "grant_type")?;
    match grant_type {
        TOKEN_EXCHANGE_GRANT => exchange(&state, &req, now).await,
        CLIENT_CREDENTIALS_GRANT => client_credentials(&state, &req, now).await,
        other => Err(OAuthError::new(
            OAuthErrorCode::UnsupportedGrantType,
            format!("grant_type '{other}' is not supported"),
        )),
    }
}

async fn exchange<B, G, O, V, Rd>(
    state: &TokenEndpointState<B, G, O, V, Rd>,
    req: &TokenRequest,
    now: i64,
) -> Result<Response, OAuthError>
where
    B: BundleStore,
    G: GrantStore,
    O: OwnershipStore,
    V: TokenVerifier + Send + Sync,
    Rd: RevocationReader,
{
    use OAuthErrorCode::*;
    let subject_token = required(&req.subject_token, "subject_token")?;
    let subject_type = required(&req.subject_token_type, "subject_token_type")?;
    if subject_type != ACCESS_TOKEN_TYPE {
        return Err(OAuthError::new(
            InvalidRequest,
            format!("subject_token_type must be '{ACCESS_TOKEN_TYPE}'"),
        ));
    }
    let actor_token = required(&req.actor_token, "actor_token")?;
    let actor_type = required(&req.actor_token_type, "actor_token_type")?;
    if actor_type != CAMP_BOOTSTRAP_TOKEN_TYPE {
        return Err(OAuthError::new(
            InvalidRequest,
            format!("actor_token_type must be '{CAMP_BOOTSTRAP_TOKEN_TYPE}'"),
        ));
    }
    let audience = required(&req.audience, "audience")?;
    let scopes = parse_scopes(state.mcp.scopes(), req.scope.as_deref())?;
    if scopes.is_empty() {
        return Err(OAuthError::new(InvalidRequest, "scope is required for token exchange"));
    }

    let camp = resolve_camp(state.camps.as_ref(), actor_token, now).await?;
    let session = state
        .edge
        .verify_at(subject_token, now)
        .await
        .map_err(|_| OAuthError::new(InvalidGrant, "subject_token is invalid, expired or revoked"))?;
    let user = PrincipalId::user(session.sub.as_str());

    let minted = state
        .mcp
        .mint_token_exchange(user, camp.clone(), Some(Actor::new(camp)), audience, scopes, now)
        .await
        .map_err(map_mint_error)?;
    Ok(success(minted, now, Some(ACCESS_TOKEN_TYPE)))
}

async fn client_credentials<B, G, O, V, Rd>(
    state: &TokenEndpointState<B, G, O, V, Rd>,
    req: &TokenRequest,
    now: i64,
) -> Result<Response, OAuthError>
where
    B: BundleStore,
    G: GrantStore,
    O: OwnershipStore,
{
    let assertion_type = required(&req.client_assertion_type, "client_assertion_type")?;
    if assertion_type != PASETO_ASSERTION_TYPE {
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidClient,
            format!("client_assertion_type must be '{PASETO_ASSERTION_TYPE}'"),
        ));
    }
    let assertion = required(&req.client_assertion, "client_assertion")?;
    let audience = required(&req.audience, "audience")?;
    let scopes = parse_scopes(state.mcp.scopes(), req.scope.as_deref())?;
    let minted = state
        .mcp
        .mint_service(assertion, audience, &scopes, now)
        .await
        .map_err(map_mint_error)?;
    Ok(success(minted, now, None))
}

/// The camp a bootstrap credential authenticates — or `invalid_grant`.
async fn resolve_camp(
    camps: &dyn CampPrincipalStore,
    token: &str,
    now: i64,
) -> Result<PrincipalId, OAuthError> {
    let invalid = || OAuthError::new(OAuthErrorCode::InvalidGrant, "actor_token is invalid, expired or revoked");
    let unavailable = |e: cheers_core::StoreError| {
        tracing::error!(error = %e, "POST /token camp credential lookup failed");
        OAuthError::new(OAuthErrorCode::TemporarilyUnavailable, "credential store unavailable")
    };
    let cred = camps.get_credential(token).await.map_err(unavailable)?.ok_or_else(invalid)?;
    if cred.revoked || cred.expires_at <= now {
        return Err(invalid());
    }
    match camps.get_principal(&cred.camp_id).await.map_err(unavailable)? {
        Some(p) if p.status == PrincipalStatus::Active => Ok(cred.camp_id),
        _ => Err(invalid()),
    }
}

fn success(minted: MintedMcpToken, now: i64, issued_token_type: Option<&str>) -> Response {
    let body = TokenResponse {
        access_token: minted.token,
        token_type: "Bearer".to_owned(),
        expires_in: (minted.claims.exp - now).max(0),
        scope: minted.claims.scope.iter().map(|s| s.as_wire()).collect::<Vec<_>>().join(" "),
        issued_token_type: issued_token_type.map(str::to_owned),
    };
    (StatusCode::OK, no_store(), Json(body)).into_response()
}

fn required<'a>(field: &'a Option<String>, name: &str) -> Result<&'a str, OAuthError> {
    match field.as_deref() {
        Some(v) if !v.is_empty() => Ok(v),
        _ => Err(OAuthError::new(OAuthErrorCode::InvalidRequest, format!("missing '{name}'"))),
    }
}

/// Space-separated scopes; each must parse and be registered, else
/// `invalid_scope`.
fn parse_scopes(
    registry: &cheers_core::ScopeRegistry,
    raw: Option<&str>,
) -> Result<Vec<Scope>, OAuthError> {
    raw.unwrap_or_default()
        .split_ascii_whitespace()
        .map(|s| {
            let scope = Scope::from_str(s)
                .map_err(|e| OAuthError::new(OAuthErrorCode::InvalidScope, e.to_string()))?;
            if !registry.contains(&scope) {
                return Err(OAuthError::new(
                    OAuthErrorCode::InvalidScope,
                    format!("unknown scope '{scope}'"),
                ));
            }
            Ok(scope)
        })
        .collect()
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}
