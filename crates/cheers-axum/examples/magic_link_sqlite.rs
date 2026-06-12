//! Headless magic-link auth server backed by a real SQLite/libsql file —
//! the W207 "cheers test-mode contract" shape (Gap #3), runnable under a
//! supervisor for E2E registration tests.
//!
//! ```text
//! DATABASE_URL=/path/db.sqlite PORT=8745 cargo run -p cheers-axum \
//!     --example magic_link_sqlite --features email
//! ```
//!
//! Surface:
//! - `POST /auth/magic-link/request {"email": ...}` → `{ok:true}`; the mail
//!   is captured in-process (CapturingMailer), never sent.
//! - `GET  /auth/magic-link/verify?token=...` → SessionBody (access +
//!   refresh + user_id); finds-or-creates the user (registration).
//! - `GET  /dev/last-magic-link` → the captured click-through URL.
//!   **Dev-only by construction** — this binary is an example, not a
//!   shippable service; the endpoint exists so harnesses can complete the
//!   loop without SMTP.
//! - `GET  /health` → `{ok:true}` once migrations have run.
//!
//! The DATABASE_URL convention matches the yah-camp appliance contract
//! (R274-F5/F6): an absolute path to an embedded libsql/SQLite file, vended
//! via `.yah/jit/<svc>/appliances.json` and injected into the workload env.

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db_path = std::env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL must point at the vended sqlite file")?;
    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8745);
    let base_url =
        std::env::var("BASE_URL").unwrap_or_else(|_| format!("http://127.0.0.1:{port}"));

    // The camp vends a bare filesystem path; sqlx wants a sqlite URL.
    let db_url = if db_path.starts_with("sqlite:") {
        db_path.clone()
    } else {
        format!("sqlite://{db_path}?mode=rwc")
    };
    let pool = SqlitePoolOptions::new().max_connections(4).connect(&db_url).await?;
    SQLITE_MIGRATIONS.run(&pool).await?;

    let (minter, _verifier) = PasetoV4SecretMinter::generate()?;
    let authority = Arc::new(SessionAuthority::new(
        minter,
        SqliteRefreshStore::new(pool.clone()),
        SqliteUserStore::new(pool.clone()),
        SqliteRevocationStore::new(pool.clone()),
    ));

    // Deterministic dev codec key — fine for an example/test harness; a real
    // deployment derives this from its secret store.
    let mut key = [7u8; 32];
    if let Ok(hex_key) = std::env::var("MAGIC_LINK_KEY_HEX") {
        let bytes = hex_decode(&hex_key)?;
        key.copy_from_slice(&bytes);
    }
    let provider = Arc::new(MagicLinkProvider::new(
        MagicLinkCodec::new(&key, 900)?,
        MagicLinkUrlBuilder::new(format!("{base_url}/auth/magic-link/verify")),
        MemoryUsedJtiStore::new(),
    ));
    let mailer = Arc::new(CapturingMailer::new());
    let template = MagicLinkEmail::new("yah dev", "yah dev <noreply@yah.invalid>");

    let state = Arc::new(MagicLinkAuthState { provider, mailer: Arc::clone(&mailer), authority, template });

    let app: Router = Router::new()
        .nest("/auth", magic_link_router(state))
        .route(
            "/dev/last-magic-link",
            get({
                let mailer = Arc::clone(&mailer);
                move || {
                    let mailer = Arc::clone(&mailer);
                    async move {
                        let Some(mail) = mailer.last() else {
                            return Json(serde_json::json!({ "url": null }));
                        };
                        Json(serde_json::json!({ "url": extract_url(&mail.text) }))
                    }
                }
            }),
        )
        .route("/health", get(|| async { Json(serde_json::json!({ "ok": true })) }));

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("magic_link_sqlite listening on http://127.0.0.1:{port} (db: {db_path})");
    axum::serve(listener, app).await?;
    Ok(())
}

fn extract_url(text: &str) -> Option<String> {
    let start = text.find("http://").or_else(|| text.find("https://"))?;
    let rest = &text[start..];
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() != 64 {
        return Err("MAGIC_LINK_KEY_HEX must be 32 bytes hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}
