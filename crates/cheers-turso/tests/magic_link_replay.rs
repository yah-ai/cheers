//! R727-B1 acceptance test — a consumed magic link must not be replayable
//! after a process restart.
//!
//! Drives the real `cheers::email::magic_link::MagicLinkProvider` (request +
//! consume, unmodified) against a [`TursoUsedJtiStore`] backed by an on-disk
//! file, dropping the store and opening a fresh one against the same file
//! between the first consume and the replay. That is the honest in-process
//! stand-in for "a different process opened the same database" — the engine
//! takes a process-wide exclusive lock (see `cheers_turso::conn`), so an
//! actual second process could not open the file at all; `tests/turso.rs`'s
//! own persistence test uses the identical drop-and-reopen technique.
//!
//! The negative control below runs the identical scenario against
//! `MemoryUsedJtiStore` — the pre-R727-B1 sole impl — and asserts the replay
//! *succeeds*, proving this harness would have caught the defect before the
//! fix landed.

use std::sync::Arc;

use cheers::email::magic_link::{
    MagicLinkCodec, MagicLinkError, MagicLinkProvider, MagicLinkUrlBuilder, MemoryUsedJtiStore,
};
use cheers_turso::{migrate, TursoConn, TursoUsedJtiStore};

const KEY: [u8; 32] = [9u8; 32];
const TTL_SECONDS: i64 = 3600;
const BASE_URL: &str = "https://app.example/auth/verify";

/// The fix: replaying a magic link after the store handle is dropped and
/// reopened against the same on-disk database is refused, not honored.
#[tokio::test]
async fn magic_link_replay_is_refused_after_reopening_turso_store() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("used_jti.db");
    let now = 1_700_000_000;

    let token = {
        let conn = Arc::new(TursoConn::open(&path).await.unwrap());
        migrate::run(&conn).await.unwrap();
        let provider = MagicLinkProvider::new(
            MagicLinkCodec::new(&KEY, TTL_SECONDS).unwrap(),
            MagicLinkUrlBuilder::new(BASE_URL),
            TursoUsedJtiStore::new(conn.clone()),
        );
        let req = provider.request("alice@example.com", now).await.unwrap();
        provider
            .consume(&req.token, now + 1)
            .await
            .expect("first consume must succeed");
        req.token
        // `conn` (and with it the store) drops here, releasing the engine's
        // exclusive lock — the shape a process restart takes on disk.
    };

    let conn = Arc::new(TursoConn::open(&path).await.unwrap());
    let provider = MagicLinkProvider::new(
        MagicLinkCodec::new(&KEY, TTL_SECONDS).unwrap(),
        MagicLinkUrlBuilder::new(BASE_URL),
        TursoUsedJtiStore::new(conn),
    );
    let err = provider
        .consume(&token, now + 2)
        .await
        .expect_err("a replay after reopening the store must be refused");
    assert!(
        matches!(err, MagicLinkError::AlreadyUsed),
        "replay must map to the existing AlreadyUsed variant (client code \
         `already_used`, cheers-axum/src/error.rs:218), not a new one; got {err:?}"
    );
}

/// Negative control, proving the harness above is not vacuously green.
///
/// `MemoryUsedJtiStore` forgets every jti it ever marked used the moment its
/// handle is dropped, so the identical restart-shaped scenario against it
/// must let the replay through — this is exactly the production defect
/// R727-B1 fixes for the persistent stores. If this assertion starts
/// failing, `MemoryUsedJtiStore`'s contract changed, not the bug.
#[tokio::test]
async fn magic_link_replay_succeeds_across_restart_with_memory_store() {
    let now = 1_700_000_000;

    let token = {
        let provider = MagicLinkProvider::new(
            MagicLinkCodec::new(&KEY, TTL_SECONDS).unwrap(),
            MagicLinkUrlBuilder::new(BASE_URL),
            MemoryUsedJtiStore::new(),
        );
        let req = provider.request("alice@example.com", now).await.unwrap();
        provider.consume(&req.token, now + 1).await.unwrap();
        req.token
        // `provider` (and its MemoryUsedJtiStore) drops here, forgetting the
        // burned jti — exactly what a process restart does in production.
    };

    let provider = MagicLinkProvider::new(
        MagicLinkCodec::new(&KEY, TTL_SECONDS).unwrap(),
        MagicLinkUrlBuilder::new(BASE_URL),
        MemoryUsedJtiStore::new(),
    );
    let claims = provider
        .consume(&token, now + 2)
        .await
        .expect("MemoryUsedJtiStore has no memory of the prior process, so the replay succeeds");
    assert_eq!(claims.email, "alice@example.com");
}
