//! `cheers-test-identity` — the supported test-identity auth server.
//!
//! Boots a deterministic, SQLite-backed magic-link cheers server for E2E /
//! registration harnesses. Configured entirely from the environment so it drops
//! into the yah-camp appliance contract (the camp vends `DATABASE_URL` and the
//! supervisor — constable `Backend::Native` — fork+execs this binary):
//!
//! ```text
//! DATABASE_URL=/abs/db.sqlite PORT=8745 cheers-test-identity
//! # optional: BASE_URL=http://127.0.0.1:8745  MAGIC_LINK_KEY_HEX=<64 hex>
//! ```
//!
//! Dev/test only — see the crate docs for why this is a `publish = false`
//! surface rather than a production service. The router itself is
//! [`cheers_test_identity::build_router`], so in-process harnesses skip the
//! binary entirely.

use cheers_test_identity::{build_router, TestIdentityConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = TestIdentityConfig::from_env()?;
    let router = build_router(&config).await?;

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", config.port)).await?;
    eprintln!(
        "cheers-test-identity listening on http://127.0.0.1:{} (db: {})",
        config.port, config.db_url
    );
    axum::serve(listener, router).await?;
    Ok(())
}
