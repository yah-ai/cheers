//! @yah:ticket(R513-T8, "Promote cheers magic_link_sqlite example to a supported --test-identity surface (Gap #3)")
//! @yah:at(2026-06-20T00:00:00Z)
//! @yah:status(review)
//! @yah:parent(R513)
//! @arch:see(.yah/docs/working/W207-dashboard-e2e-in-qed.md)
//!
//! # cheers-test-identity — the supported cheers test-identity surface
//!
//! A deterministic, SQLite/libsql-backed magic-link auth server for E2E and
//! registration harnesses. This is the **promotion** of cheers-axum's old
//! `magic_link_sqlite` *example* into a supported surface (R513-T8, W207
//! Gap #3): a reusable [`build_router`] the harness — or an in-process test —
//! mounts, plus the `cheers-test-identity` binary that serves it.
//!
//! It deliberately lives in its own crate rather than inside `cheers-axum`,
//! whose charter is to stay product-agnostic ("no `DATABASE_URL`, no
//! cheers-sqlx coupling"). The test-identity surface is the opposite — it picks
//! SQLite, a deterministic codec key, and an in-process [`CapturingMailer`] so a
//! harness can complete the magic-link loop without SMTP. Keeping it separate
//! keeps that product-ish wiring out of the core HTTP crate.
//!
//! ## Why "test-identity" and not a `--test-identity` flag on a server binary
//!
//! cheers ships no production server binary today (the crates are libraries a
//! product mounts). There is nothing to hang a `--test-identity` *mode flag*
//! on. A dedicated binary is also strictly safer: a separate `publish = false`
//! crate carrying the dev-only `/dev/last-magic-link` endpoint can never be
//! accidentally linked into a production image the way a feature-flagged code
//! path in the shipping crate could.
//!
//! ## Surface
//!
//! [`build_router`] mounts:
//!
//! - `POST /auth/magic-link/request {"email": ...}` → `{ok:true}`; the mail is
//!   captured in-process (never sent).
//! - `GET  /auth/magic-link/verify?token=...` → `SessionBody` (access + refresh
//!   + `user_id`); finds-or-creates the user (registration).
//! - `GET  /dev/last-magic-link` → `{ "url": ... }`, the captured click-through
//!   URL. **Dev-only by construction** — this is why the surface is a
//!   `publish = false` crate, not a shippable service.
//! - `GET  /health` → `{ok:true}` once migrations have run.
//!
//! The `DATABASE_URL` convention matches the yah-camp appliance contract
//! (R274-F5/F6): an absolute path to an embedded libsql/SQLite file, vended via
//! `.yah/jit/<svc>/appliances.json` and injected into the workload env.

use std::sync::Arc;

use axum::routing::get;
use axum::{Json, Router};
use cheers::email::magic_link::{
    MagicLinkCodec, MagicLinkProvider, MagicLinkUrlBuilder, MemoryUsedJtiStore,
};
use cheers::email::{CapturingMailer, MagicLinkEmail};
use cheers_axum::magic_link::{router as magic_link_router, MagicLinkAuthState};
use cheers_server::{PasetoV4SecretMinter, SessionAuthority};
use cheers_sqlx::{SqliteRefreshStore, SqliteRevocationStore, SqliteUserStore, SQLITE_MIGRATIONS};
use sqlx::sqlite::SqlitePoolOptions;

/// Default magic-link codec key — a deterministic stand-in for a real secret
/// store, fine for a test-identity harness (and *only* a harness). Overridden
/// by `MAGIC_LINK_KEY_HEX`.
const DEFAULT_KEY: [u8; 32] = [7u8; 32];

/// Default magic-link token time-to-live, in seconds (15 minutes).
const DEFAULT_TOKEN_TTL_SECS: i64 = 900;

/// Default listen port when `PORT` is unset.
pub const DEFAULT_PORT: u16 = 8745;

/// Everything the test-identity server needs to stand up. Build it from the
/// environment with [`TestIdentityConfig::from_env`] (the binary path) or by
/// hand (the in-process test path).
#[derive(Debug, Clone)]
pub struct TestIdentityConfig {
    /// A sqlx-ready SQLite URL (e.g. `sqlite:///abs/path/db.sqlite?mode=rwc`).
    /// Use [`normalize_sqlite_url`] to turn a bare camp-vended path into one.
    pub db_url: String,
    /// Port the binary listens on. Ignored by [`build_router`] (which returns a
    /// transport-agnostic [`Router`]); used by the binary's bind + the default
    /// `base_url`.
    pub port: u16,
    /// Base URL baked into the magic-link verify URLs the mailer captures —
    /// what a client would click. Defaults to `http://127.0.0.1:<port>`.
    pub base_url: String,
    /// Magic-link codec key. [`DEFAULT_KEY`] unless `MAGIC_LINK_KEY_HEX` is set.
    pub magic_link_key: [u8; 32],
    /// Magic-link token TTL in seconds.
    pub token_ttl_secs: i64,
}

impl TestIdentityConfig {
    /// Build a config from the environment, matching the appliance contract:
    /// `DATABASE_URL` (required, a bare path or sqlite URL), `PORT` (default
    /// [`DEFAULT_PORT`]), `BASE_URL` (default `http://127.0.0.1:<port>`),
    /// `MAGIC_LINK_KEY_HEX` (default [`DEFAULT_KEY`]).
    pub fn from_env() -> Result<Self, TestIdentityError> {
        let db_path = std::env::var("DATABASE_URL").map_err(|_| {
            TestIdentityError::Config("DATABASE_URL must point at the test sqlite file".into())
        })?;
        let port = std::env::var("PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(DEFAULT_PORT);
        let base_url =
            std::env::var("BASE_URL").unwrap_or_else(|_| format!("http://127.0.0.1:{port}"));
        let magic_link_key = match std::env::var("MAGIC_LINK_KEY_HEX") {
            Ok(hex) => parse_key_hex(&hex)?,
            Err(_) => DEFAULT_KEY,
        };
        Ok(Self {
            db_url: normalize_sqlite_url(&db_path),
            port,
            base_url,
            magic_link_key,
            token_ttl_secs: DEFAULT_TOKEN_TTL_SECS,
        })
    }
}

/// Errors standing up the test-identity server.
#[derive(Debug, thiserror::Error)]
pub enum TestIdentityError {
    #[error("test-identity config: {0}")]
    Config(String),
    #[error("test-identity database: {0}")]
    Database(#[from] sqlx::Error),
    #[error("test-identity migrations: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// A cheers-side setup step (key minter, codec) failed.
    #[error("test-identity setup: {0}")]
    Setup(String),
}

/// Turn a camp-vended bare filesystem path into a sqlx SQLite URL. A value that
/// already looks like a sqlite URL is returned unchanged.
pub fn normalize_sqlite_url(db_path: &str) -> String {
    if db_path.starts_with("sqlite:") {
        db_path.to_string()
    } else {
        format!("sqlite://{db_path}?mode=rwc")
    }
}

/// Parse a 32-byte (64 hex char) key for `MAGIC_LINK_KEY_HEX`.
pub fn parse_key_hex(s: &str) -> Result<[u8; 32], TestIdentityError> {
    if s.len() != 64 {
        return Err(TestIdentityError::Config(
            "MAGIC_LINK_KEY_HEX must be 32 bytes hex (64 chars)".into(),
        ));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|e| TestIdentityError::Config(format!("MAGIC_LINK_KEY_HEX: {e}")))?;
    }
    Ok(out)
}

/// Build the test-identity [`Router`]: open the SQLite pool, run migrations,
/// wire a [`SessionAuthority`] over the sqlite stores plus a deterministic
/// magic-link provider and an in-process [`CapturingMailer`], and mount the
/// `/auth` + `/dev/last-magic-link` + `/health` routes.
///
/// Returns a transport-agnostic router so callers (the binary; an in-process
/// `tower` test) decide how to serve it.
pub async fn build_router(config: &TestIdentityConfig) -> Result<Router, TestIdentityError> {
    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .connect(&config.db_url)
        .await?;
    SQLITE_MIGRATIONS.run(&pool).await?;

    let (minter, _verifier) = PasetoV4SecretMinter::generate()
        .map_err(|e| TestIdentityError::Setup(format!("paseto minter: {e}")))?;
    let authority = Arc::new(SessionAuthority::new(
        minter,
        SqliteRefreshStore::new(pool.clone()),
        SqliteUserStore::new(pool.clone()),
        SqliteRevocationStore::new(pool.clone()),
    ));

    let codec = MagicLinkCodec::new(&config.magic_link_key, config.token_ttl_secs)
        .map_err(|e| TestIdentityError::Setup(format!("magic-link codec: {e}")))?;
    let provider = Arc::new(MagicLinkProvider::new(
        codec,
        MagicLinkUrlBuilder::new(format!("{}/auth/magic-link/verify", config.base_url)),
        MemoryUsedJtiStore::new(),
    ));
    let mailer = Arc::new(CapturingMailer::new());
    let template = MagicLinkEmail::new("yah dev", "yah dev <noreply@yah.invalid>");

    let state = Arc::new(MagicLinkAuthState {
        provider,
        mailer: Arc::clone(&mailer),
        authority,
        template,
    });

    let app = Router::new()
        .nest("/auth", magic_link_router(state))
        .route(
            "/dev/last-magic-link",
            get(move || {
                let mailer = Arc::clone(&mailer);
                async move {
                    match mailer.last() {
                        Some(mail) => Json(serde_json::json!({ "url": extract_url(&mail.text) })),
                        None => Json(serde_json::json!({ "url": null })),
                    }
                }
            }),
        )
        .route("/health", get(|| async { Json(serde_json::json!({ "ok": true })) }));

    Ok(app)
}

/// Pull the first `http(s)://…` URL out of a captured mail body (the
/// click-through link a harness follows in lieu of a real inbox).
pub fn extract_url(text: &str) -> Option<String> {
    let start = text.find("http://").or_else(|| text.find("https://"))?;
    let rest = &text[start..];
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn temp_config() -> (TestIdentityConfig, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("test-identity.sqlite");
        let cfg = TestIdentityConfig {
            db_url: normalize_sqlite_url(&db.to_string_lossy()),
            port: 0,
            base_url: "http://127.0.0.1:8745".into(),
            magic_link_key: DEFAULT_KEY,
            token_ttl_secs: DEFAULT_TOKEN_TTL_SECS,
        };
        (cfg, dir)
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn parse_key_hex_roundtrips_and_rejects_bad_length() {
        let hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let key = parse_key_hex(hex).unwrap();
        assert_eq!(key[0], 0x00);
        assert_eq!(key[31], 0xff);
        assert!(parse_key_hex("abcd").is_err());
        assert!(parse_key_hex(&"z".repeat(64)).is_err());
    }

    #[test]
    fn normalize_sqlite_url_wraps_bare_path_and_passes_url_through() {
        assert_eq!(
            normalize_sqlite_url("/abs/db.sqlite"),
            "sqlite:///abs/db.sqlite?mode=rwc"
        );
        assert_eq!(
            normalize_sqlite_url("sqlite::memory:"),
            "sqlite::memory:"
        );
    }

    #[tokio::test]
    async fn health_is_ok_after_build() {
        let (cfg, _dir) = temp_config();
        let app = build_router(&cfg).await.unwrap();
        let resp = app
            .oneshot(Request::get("/health").body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await, serde_json::json!({ "ok": true }));
    }

    /// Full registration round-trip in-process: request → capture link → verify
    /// → a SessionBody with an access token + user_id, finds-or-creates the user.
    #[tokio::test]
    async fn magic_link_registration_round_trips() {
        let (cfg, _dir) = temp_config();

        // `Router` is `Clone` and the `CapturingMailer` is shared through an
        // `Arc`, so every `app.clone()` drives the same in-process mailer — the
        // request and the captured-link read see the same state.
        let app = build_router(&cfg).await.unwrap();

        // 1. request a magic link → captured by the in-process mailer.
        let resp = app
            .clone()
            .oneshot(
                Request::post("/auth/magic-link/request")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(r#"{"email":"cecil@yah.dev"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "request acks");

        // 2. read the captured click-through URL.
        let resp = app
            .clone()
            .oneshot(
                Request::get("/dev/last-magic-link")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let captured = body_json(resp).await;
        let url = captured["url"].as_str().expect("captured a magic-link url");
        let token = url
            .split_once("token=")
            .map(|(_, t)| t.to_string())
            .expect("url carries a token query param");

        // 3. verify the token → SessionBody (registration: finds-or-creates).
        let resp = app
            .oneshot(
                Request::get(format!("/auth/magic-link/verify?token={token}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "verify mints a session");
        let session = body_json(resp).await;
        assert!(
            session["access_token"].as_str().is_some_and(|t| !t.is_empty()),
            "session carries an access token: {session}"
        );
        assert!(
            session["user_id"].as_str().is_some_and(|u| !u.is_empty()),
            "session carries a user_id: {session}"
        );
    }
}
