//! Vend a service's own Turso database over Hrana-over-HTTP to callers holding
//! a cheers camp-token (W358 §vend, R960-F10).
//!
//! The minimum Hrana surface the workbench's libsql HTTP client speaks:
//! `GET /v2|/v3` (version probe), `POST /v2|/v3/pipeline` carrying `execute`,
//! `batch`, `describe`, `get_autocommit` and `close`, and `POST /v3/cursor`,
//! which is how libsql's `Connection::query` reads rows. Bodies are JSON
//! whatever their `Content-Type`, since libsql sends none. No websocket, no
//! batons: every request is stateless, which is all a read-only vend needs.
//! `tests/libsql_client.rs` holds this to the real client.
//!
//! Invariants:
//! - **One writer (W195).** The listener takes the service's already-open
//!   [`turso::Database`] and connects to *it*; nothing here opens the file.
//!   A `sql:read` token is served on a `PRAGMA query_only` connection, so a
//!   read-scoped statement cannot write even if the gate below were wrong.
//! - **Mesh-bound.** [`VendListener::bind`] refuses an unspecified address;
//!   [`VendListener::bind_mesh_from_env`] binds `YAH_MESH_IP` + `PORT_SQL`, the
//!   env kamaji's native backend injects.
//! - **Every request is gated** on a PASETO v4.public camp-token verified with
//!   `cheers-verify`: signature, `kid`, `aud = <workload>/<db>`, expiry, and a
//!   `sql:read` scope. Every refusal of that check — no token, expired, wrong
//!   aud, bad signature, unknown kid, missing scope — answers the same status
//!   and body, padded to the same minimum latency ([`VendConfig::reject_floor`]).
//! - **Read-write rides `sql:write`** (R960-F16, W358 open decision 1): the
//!   camp mints that scope only for an operator-confirmed action on a
//!   `write = confirm|allow` connection, after its audit row is written. Such a
//!   token is served on a second, writable connection; every other request
//!   stays on the `query_only` one. Any other `sql:*` scope is answered 403
//!   after it has verified.
//!
//! @yah:ticket(R960-T1, "cheers seams for noisetable R804-F2: TursoConn::database(), kid_for, VendConfig::from_public_key")
//! @yah:status(review)
//! @yah:at(2026-10-08T08:05:01Z)
//! @yah:assignee(agent:bundle-anthropic-miravel)
//! @yah:parent(R960)
//! @yah:handoff("cheers-turso: TursoConn::database(&self)->&turso::Database (field _db renamed db, lock comment kept). cheers-verify: pub fn kid_for(&[u8;32])->String in public_verifier.rs, re-exported at crate root; CLI cloud_cheers.rs now `pub use cheers_verify::kid_for` and its copy is deleted; cheers-verify moved from yah CLI dev-deps to deps. cheers-vend: VendConfig::from_public_key(&[u8;32], impl Into<String>)->Result<VendConfig, cheers_core::CodecError>.")
//! @yah:handoff("Tests: cheers-turso lib 25 (new database_handle_connects_to_the_same_engine), cheers-vend tests/vend.rs 6 (new config_from_public_key_admits_a_token_with_the_derived_kid), cheers-verify lib 80 (new kid_for_is_stable_distinct_and_22_chars), yah CLI cloud_cheers 9 pass; cargo check -p yah --tests green. No version bump, no publish.")
//! @yah:verify("cd ~/ss/yah/oss/cheers && cargo test -p cheers-turso -p cheers-vend -p cheers-verify")
//! @yah:verify("cd ~/ss/yah && cargo check -p yah --tests && cargo test -p yah --lib cloud_cheers")
//! @yah:handoff("ADDED BY noisetable R804-F2 (Glimmerstone session:7596d334, 2026-10-08), three DEFECTS IN R960-F10 found by dogfooding `yah sql` (libsql 0.9.30, the same client as data-source/src/libsql_adapter.rs:71) at the real noisetable-account binary. Before this, libsql could not READ a vend at all. (1) Bodies are parsed from Bytes whatever the Content-Type: libsql sends none, and axum's Json extractor answered 415 (lib.rs `pipeline`). (2) `describe` in the pipeline: libsql's prepare sends it (libsql hrana/mod.rs:134) and got 'request type not supported' (hrana.rs `describe`; params is always [] because turso's Statement has no parameter introspection, and is_readonly is true because the connection is query_only). (3) POST /v3/cursor, NDJSON `{baton,base_url}` then step_begin/row/step_end or step_error: libsql's `query` reads rows only through it (hrana.rs `run_cursor`). batch and cursor share one `run_steps`, so they cannot disagree about which steps run. The module header's surface list was false and is rewritten.")
//! @yah:verify("cd ~/ss/yah/oss/cheers && cargo test -p cheers-vend: 7 (tests/vend.rs, new a_pipeline_without_a_content_type_is_served) + 3 (NEW tests/libsql_client.rs: the real libsql remote client, dev-dep libsql 0.9 remote+tls, same features as data-source) = 10 passed / 0 failed; cargo clippy -p cheers-vend --all-targets clean. Negative control: the same client against the pre-fix listener failed 415, then 'request type not supported'. End to end: the real noisetable-account binary with vend on (the camp's real vend verify key, YAH_MESH_IP=127.0.0.1, PORT_SQL) and a token from `yah cloud cheers token --key vend` -> `yah sql query` returned the account schema; no-token / wrong-aud / operator-key / garbage all got identical 401s; sql:write got 403; a write got the query_only engine error.")

mod hrana;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use cheers_verify::{kid_for, PasetoV4PublicVerifier};
use tokio::sync::Mutex;

// `sql:read` is the scope a vend token must carry; `sql:write` additionally
// selects the writable connection. One definition, in `cheers_core::yah_scopes`.
pub use cheers_core::yah_scopes::{SQL_READ, SQL_WRITE};
/// Env var naming the mesh address kamaji assigns the workload.
pub const MESH_IP_ENV: &str = "YAH_MESH_IP";
/// Env var kamaji publishes for the mesh port named `sql`.
pub const SQL_PORT_ENV: &str = "PORT_SQL";

/// Body of every authentication refusal. One constant so the cases cannot
/// drift apart.
const UNAUTHORIZED_BODY: &str = "unauthorized";
const RW_REFUSED_BODY: &str = "unsupported sql scope";

#[derive(Debug, thiserror::Error)]
pub enum VendError {
    #[error("refusing to bind unspecified address {0}: a vend listener binds the mesh address only")]
    UnspecifiedBind(IpAddr),
    #[error("{0} is not set")]
    MissingEnv(&'static str),
    #[error("{name}={value:?} does not parse")]
    BadEnv { name: &'static str, value: String },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("turso: {0}")]
    Turso(#[from] turso::Error),
}

/// What the gate checks a token against.
pub struct VendConfig {
    /// Verify half of the vend-DB signing key (R960-F9 owns the key itself).
    pub verifier: PasetoV4PublicVerifier,
    /// The `kid` the token's footer must name.
    pub kid: String,
    /// `<workload>/<db>`.
    pub audience: String,
    /// Minimum time an authentication refusal takes, so the cheap no-token
    /// path and the crypto path look the same from outside.
    pub reject_floor: Duration,
}

impl VendConfig {
    pub fn new(verifier: PasetoV4PublicVerifier, kid: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            verifier,
            kid: kid.into(),
            audience: audience.into(),
            reject_floor: Duration::from_millis(50),
        }
    }

    /// Configure from the 32-byte verify key alone: builds the verifier and
    /// derives `kid` with [`cheers_verify::kid_for`], the same function the
    /// minting side uses. Nothing is hand-copied, so a key rotation cannot leave
    /// a stale kid behind.
    pub fn from_public_key(
        public: &[u8; 32],
        audience: impl Into<String>,
    ) -> Result<Self, cheers_core::CodecError> {
        let verifier = PasetoV4PublicVerifier::from_public_key(public)?;
        Ok(Self::new(verifier, kid_for(public), audience))
    }
}

/// The router and its state. Build one per vended database.
pub struct VendService {
    inner: Arc<Inner>,
}

struct Inner {
    cfg: VendConfig,
    /// `PRAGMA query_only`: every `sql:read`-only token.
    read: Mutex<turso::Connection>,
    /// Writable: only a token that also carries `sql:write`.
    write: Mutex<turso::Connection>,
}

/// Which connection the gate admitted a request onto (a request extension).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Access {
    Read,
    Write,
}

impl Inner {
    fn conn(&self, access: Access) -> &Mutex<turso::Connection> {
        match access {
            Access::Read => &self.read,
            Access::Write => &self.write,
        }
    }
}

impl VendService {
    /// Connect to the service's own `db` (never re-open the file): one
    /// connection pinned read-only, one writable for `sql:write` tokens.
    pub async fn new(db: &turso::Database, cfg: VendConfig) -> Result<Self, VendError> {
        let read = db.connect()?;
        read.execute_batch("PRAGMA query_only = 1").await?;
        let write = db.connect()?;
        Ok(Self { inner: Arc::new(Inner { cfg, read: Mutex::new(read), write: Mutex::new(write) }) })
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route("/v2", get(version))
            .route("/v3", get(version))
            .route("/v2/pipeline", post(pipeline))
            .route("/v3/pipeline", post(pipeline))
            .route("/v3/cursor", post(cursor))
            .layer(middleware::from_fn_with_state(self.inner.clone(), gate))
            .with_state(self.inner.clone())
    }
}

/// A bound, serving listener.
pub struct VendListener {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl VendListener {
    /// Bind `ip:port` and serve. Refuses `0.0.0.0` / `::`.
    pub async fn bind(ip: IpAddr, port: u16, service: VendService) -> Result<Self, VendError> {
        if ip.is_unspecified() {
            return Err(VendError::UnspecifiedBind(ip));
        }
        let listener = tokio::net::TcpListener::bind((ip, port)).await?;
        let addr = listener.local_addr()?;
        let app = service.router();
        let task = tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                tracing::error!(error = %e, "vend listener stopped");
            }
        });
        Ok(Self { addr, task })
    }

    /// Bind `YAH_MESH_IP`:`PORT_SQL` — the address and port kamaji assigned.
    pub async fn bind_mesh_from_env(service: VendService) -> Result<Self, VendError> {
        let ip = env_parse::<IpAddr>(MESH_IP_ENV)?;
        let port = env_parse::<u16>(SQL_PORT_ENV)?;
        Self::bind(ip, port, service).await
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Hrana base URL — what goes in `StatefulServiceContract.vend_endpoint`.
    pub fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn abort(&self) {
        self.task.abort();
    }
}

impl Drop for VendListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn env_parse<T: std::str::FromStr>(name: &'static str) -> Result<T, VendError> {
    let value = std::env::var(name).map_err(|_| VendError::MissingEnv(name))?;
    value.parse().map_err(|_| VendError::BadEnv { name, value })
}

enum Verdict {
    Admit(Access),
    Unauthorized,
    UnsupportedScope,
}

fn judge(cfg: &VendConfig, authorization: Option<&str>, now: i64) -> Verdict {
    let Some(token) = authorization.and_then(|h| h.strip_prefix("Bearer ")) else {
        return Verdict::Unauthorized;
    };
    let Ok(claims) = cfg.verifier.verify_mcp_at(token.trim(), now, &cfg.kid) else {
        return Verdict::Unauthorized;
    };
    if claims.aud != cfg.audience {
        return Verdict::Unauthorized;
    }
    let wires: Vec<&str> = claims.scope.iter().map(|s| s.as_wire()).collect();
    let (read_scope, write_scope) = (SQL_READ, SQL_WRITE);
    let (read, write) = (read_scope.as_wire(), write_scope.as_wire());
    if wires.iter().any(|w| w.starts_with("sql:") && *w != read && *w != write) {
        return Verdict::UnsupportedScope;
    }
    if !wires.contains(&read) {
        return Verdict::Unauthorized;
    }
    Verdict::Admit(if wires.contains(&write) { Access::Write } else { Access::Read })
}

async fn gate(State(inner): State<Arc<Inner>>, mut req: Request, next: Next) -> Response {
    let started = tokio::time::Instant::now();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let authorization = req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok());
    match judge(&inner.cfg, authorization, now) {
        Verdict::Admit(access) => {
            req.extensions_mut().insert(access);
            next.run(req).await
        }
        Verdict::Unauthorized => {
            tokio::time::sleep_until(started + inner.cfg.reject_floor).await;
            (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Bearer")],
                UNAUTHORIZED_BODY,
            )
                .into_response()
        }
        Verdict::UnsupportedScope => (StatusCode::FORBIDDEN, RW_REFUSED_BODY).into_response(),
    }
}

async fn version() -> &'static str {
    "Hello, this is cheers-vend"
}

/// The body is parsed as JSON whatever its `Content-Type` says. libsql's Hrana
/// client posts the pipeline with none, and sqld serves it, so axum's `Json`
/// extractor (415 without `application/json`) refused the very client the
/// workbench runs. Found by noisetable R804-F2 driving `yah sql` at a live
/// listener; the reqwest-based tests here all set the header.
async fn pipeline(
    State(inner): State<Arc<Inner>>,
    Extension(access): Extension<Access>,
    body: axum::body::Bytes,
) -> Response {
    let req: hrana::PipelineRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("malformed pipeline request: {e}"))
                .into_response()
        }
    };
    let conn = inner.conn(access).lock().await;
    Json(hrana::run_pipeline(&conn, req).await).into_response()
}

/// `POST /v3/cursor`: how libsql's `Connection::query` reads rows. Same
/// content-type tolerance as [`pipeline`]; the body is newline-delimited JSON.
async fn cursor(
    State(inner): State<Arc<Inner>>,
    Extension(access): Extension<Access>,
    body: axum::body::Bytes,
) -> Response {
    let req: hrana::CursorRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("malformed cursor request: {e}"))
                .into_response()
        }
    };
    let conn = inner.conn(access).lock().await;
    let lines = hrana::run_cursor(&conn, req).await;
    ([(header::CONTENT_TYPE, "application/x-ndjson")], lines).into_response()
}
