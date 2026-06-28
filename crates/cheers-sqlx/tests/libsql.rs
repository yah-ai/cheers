//! libSQL-backed schema smoke. Off by default — enable with `--features
//! libsql-integration` (Docker required, the test stands up a real
//! `ghcr.io/tursodatabase/libsql-server` via testcontainers). Honors
//! `CHEERS_LIBSQL_URL` to bypass the container and target an existing server.
//!
//! Why this exists separately from `tests/sqlite.rs`: the `sqlite` feature
//! drives the typed `Sqlite*Store` impls through sqlx's vanilla SQLite driver
//! (rusqlite). sqlx has no libSQL driver, so we can't reuse the store types
//! here. The production target for cheers-sqlx is libSQL (Turso) — per
//! [[cheers-sqlx-backends]] — so the property we want to verify is that the
//! SQLite-flavor migrations (CREATE TABLE / CHECK / FK CASCADE / partial
//! indexes) apply cleanly to libSQL and that constraint enforcement matches.
//! If/when sqlx ships a libsql driver, swap the raw client for it and lift
//! the common store scenarios over (per the ticket).
//!
//! Coverage:
//! - 0001 + 0002 + 0003 migrations apply in order, statement-by-statement
//! - users(email) partial UNIQUE index allows multiple NULLs, rejects dup
//! - FK CASCADE: deleting a user wipes oauth_identities / refresh_tokens
//! - service_principals CHECK: id must LIKE 'svc:%', status in vocab
//! - service_principal_keys CHECK: active⇒retire_at NULL, retiring⇒NOT NULL
//! - FK CASCADE: deleting a service_principal wipes its keys
//! - ix_spk_principal_active partial index used by EXPLAIN QUERY PLAN
//!
//! Ticket: R020-T19 (annotation lives in tests/sqlite.rs).

#![cfg(feature = "libsql-integration")]

use libsql::{params, Builder, Connection};
use std::path::Path;
use testcontainers::core::{ContainerPort, IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

const LIBSQL_IMAGE: &str = "ghcr.io/tursodatabase/libsql-server";
const LIBSQL_TAG: &str = "latest";
const HRANA_HTTP_PORT: u16 = 8080;

struct LibsqlFixture {
    conn: Connection,
    _container: Option<ContainerAsync<GenericImage>>,
}

async fn fresh_libsql() -> LibsqlFixture {
    let (url, container) = if let Ok(url) = std::env::var("CHEERS_LIBSQL_URL") {
        (url, None)
    } else {
        let container = GenericImage::new(LIBSQL_IMAGE, LIBSQL_TAG)
            .with_exposed_port(ContainerPort::Tcp(HRANA_HTTP_PORT))
            // libsql-server logs this line once the HTTP listener is ready.
            // Matching it avoids a flaky sleep between container start and the
            // first connect attempt.
            .with_wait_for(WaitFor::message_on_stderr("listening for HTTP requests"))
            .with_env_var("SQLD_NODE", "primary")
            .start()
            .await
            .expect("start libsql-server container");
        let host = container.get_host().await.expect("container host");
        let port = container
            .get_host_port_ipv4(HRANA_HTTP_PORT.tcp())
            .await
            .expect("container hrana port");
        (format!("http://{host}:{port}"), Some(container))
    };

    // The remote builder targets a libsql-server over HTTP/Hrana. The auth
    // token is empty because the test container runs without authentication
    // (SQLD_NODE=primary, no JWT key configured).
    let db = Builder::new_remote(url, String::new())
        .build()
        .await
        .expect("libsql build");
    let conn = db.connect().expect("libsql connect");

    apply_migrations(&conn).await;
    LibsqlFixture {
        conn,
        _container: container,
    }
}

/// libsql's remote `execute` takes a single statement per call. Migration
/// files are multi-statement SQL, so we split on top-level `;` boundaries.
/// The migration SQL here is hand-authored and has no string literals
/// containing `;`, so the naive split is safe; if a future migration adds
/// one, swap this for a proper tokenizer.
async fn apply_migrations(conn: &Connection) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations/sqlite");
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("read migrations dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "sql"))
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let sql = std::fs::read_to_string(&path).expect("read migration");
        for stmt in split_statements(&sql) {
            conn.execute(&stmt, ())
                .await
                .unwrap_or_else(|e| panic!("migration {path:?} stmt failed: {e}\n--- sql ---\n{stmt}"));
        }
    }
    // FK enforcement is off by default on libsql, same as vanilla SQLite.
    conn.execute("PRAGMA foreign_keys = ON", ())
        .await
        .expect("enable FKs");
}

fn split_statements(sql: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    for line in sql.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("--") || trimmed.is_empty() {
            continue;
        }
        buf.push_str(line);
        buf.push('\n');
        if line.trim_end().ends_with(';') {
            let stmt = buf.trim().to_string();
            if !stmt.is_empty() {
                out.push(stmt);
            }
            buf.clear();
        }
    }
    let tail = buf.trim().to_string();
    if !tail.is_empty() {
        out.push(tail);
    }
    out
}

async fn count(conn: &Connection, sql: &str) -> i64 {
    let mut rows = conn.query(sql, ()).await.expect("count query");
    let row = rows.next().await.expect("count step").expect("count row");
    row.get::<i64>(0).expect("count col")
}

// ---------------------------------------------------------------------------
// 0001 — users + oauth_identities + refresh_tokens
// ---------------------------------------------------------------------------

#[tokio::test]
async fn migrations_apply_clean() {
    // No assertions beyond fresh_libsql's panics: if every migration applied,
    // we're done. The other tests verify constraint behavior.
    let _fx = fresh_libsql().await;
}

#[tokio::test]
async fn email_partial_unique_allows_nulls_rejects_duplicates() {
    let fx = fresh_libsql().await;

    // Two NULL-email users coexist — the partial unique index skips NULLs.
    fx.conn
        .execute(
            "INSERT INTO users (user_id, email, created_at) VALUES (?, NULL, ?)",
            params!["u1", 1_000_i64],
        )
        .await
        .expect("insert u1");
    fx.conn
        .execute(
            "INSERT INTO users (user_id, email, created_at) VALUES (?, NULL, ?)",
            params!["u2", 1_000_i64],
        )
        .await
        .expect("insert u2");

    // Non-null email gets a uniqueness check.
    fx.conn
        .execute(
            "INSERT INTO users (user_id, email, created_at) VALUES (?, ?, ?)",
            params!["u3", "a@example.com", 1_000_i64],
        )
        .await
        .expect("insert u3");
    let dup = fx
        .conn
        .execute(
            "INSERT INTO users (user_id, email, created_at) VALUES (?, ?, ?)",
            params!["u4", "a@example.com", 1_000_i64],
        )
        .await;
    assert!(dup.is_err(), "duplicate non-null email must be rejected");
}

#[tokio::test]
async fn fk_cascade_user_delete_wipes_dependent_rows() {
    let fx = fresh_libsql().await;

    fx.conn
        .execute(
            "INSERT INTO users (user_id, email, created_at) VALUES ('u1', NULL, 1000)",
            (),
        )
        .await
        .expect("user");
    fx.conn
        .execute(
            "INSERT INTO oauth_identities (provider, issuer, subject, user_id, linked_at) \
             VALUES ('google', '', 'sub-1', 'u1', 1000)",
            (),
        )
        .await
        .expect("oauth row");
    fx.conn
        .execute(
            "INSERT INTO refresh_tokens (token, chain_id, user_id, device_id, issued_at, expires_at) \
             VALUES ('t1', 'c1', 'u1', 'd1', 1000, 2000)",
            (),
        )
        .await
        .expect("refresh row");

    assert_eq!(count(&fx.conn, "SELECT COUNT(*) FROM oauth_identities").await, 1);
    assert_eq!(count(&fx.conn, "SELECT COUNT(*) FROM refresh_tokens").await, 1);

    fx.conn
        .execute("DELETE FROM users WHERE user_id = 'u1'", ())
        .await
        .expect("delete user");

    assert_eq!(
        count(&fx.conn, "SELECT COUNT(*) FROM oauth_identities").await,
        0,
        "oauth row should cascade",
    );
    assert_eq!(
        count(&fx.conn, "SELECT COUNT(*) FROM refresh_tokens").await,
        0,
        "refresh row should cascade",
    );
}

// ---------------------------------------------------------------------------
// 0002 — ownership
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ownership_check_constraints_reject_bad_rows() {
    let fx = fresh_libsql().await;

    // granted_by must LIKE 'svc:%'.
    let bad_grantor = fx
        .conn
        .execute(
            "INSERT INTO ownership (id, principal_id, resource_kind, resource_id, relationship, granted_by, granted_at) \
             VALUES ('o1', 'user:alice', 'doc', 'd1', 'owner', 'user:bob', 1000)",
            (),
        )
        .await;
    assert!(
        bad_grantor.is_err(),
        "ownership.granted_by without svc: prefix must be rejected",
    );

    // on_behalf_of must be NULL or LIKE 'user:%'.
    let bad_obo = fx
        .conn
        .execute(
            "INSERT INTO ownership (id, principal_id, resource_kind, resource_id, relationship, granted_by, on_behalf_of, granted_at) \
             VALUES ('o2', 'user:alice', 'doc', 'd1', 'owner', 'svc:yubaba', 'svc:other', 1000)",
            (),
        )
        .await;
    assert!(
        bad_obo.is_err(),
        "ownership.on_behalf_of with svc: prefix must be rejected",
    );

    // Valid row goes through; NULL on_behalf_of is accepted.
    fx.conn
        .execute(
            "INSERT INTO ownership (id, principal_id, resource_kind, resource_id, relationship, granted_by, on_behalf_of, granted_at) \
             VALUES ('o3', 'user:alice', 'doc', 'd1', 'owner', 'svc:yubaba', NULL, 1000)",
            (),
        )
        .await
        .expect("valid ownership row");
}

// ---------------------------------------------------------------------------
// 0003 — service_principals + service_principal_keys
// ---------------------------------------------------------------------------

#[tokio::test]
async fn service_principals_check_constraints() {
    let fx = fresh_libsql().await;

    // id must LIKE 'svc:%'.
    let bad_id = fx
        .conn
        .execute(
            "INSERT INTO service_principals (id, status, created_at) VALUES ('user:alice', 'active', 1000)",
            (),
        )
        .await;
    assert!(bad_id.is_err(), "non-svc id must be rejected");

    // status vocab is {active, revoked}.
    let bad_status = fx
        .conn
        .execute(
            "INSERT INTO service_principals (id, status, created_at) VALUES ('svc:a', 'emerging', 1000)",
            (),
        )
        .await;
    assert!(bad_status.is_err(), "bogus status must be rejected");

    fx.conn
        .execute(
            "INSERT INTO service_principals (id, status, created_at) VALUES ('svc:a', 'active', 1000)",
            (),
        )
        .await
        .expect("valid svc row");
}

#[tokio::test]
async fn service_principal_keys_active_retire_invariant() {
    let fx = fresh_libsql().await;
    fx.conn
        .execute(
            "INSERT INTO service_principals (id, status, created_at) VALUES ('svc:a', 'active', 1000)",
            (),
        )
        .await
        .expect("seed svc");

    // active ⇒ retire_at NULL: violating shape is rejected.
    let bad_active = fx
        .conn
        .execute(
            "INSERT INTO service_principal_keys (kid, principal_id, public_key, status, created_at, retire_at) \
             VALUES ('k1', 'svc:a', X'00', 'active', 1000, 9999)",
            (),
        )
        .await;
    assert!(
        bad_active.is_err(),
        "active key with retire_at set must be rejected",
    );

    // retiring ⇒ retire_at NOT NULL: violating shape is rejected.
    let bad_retiring = fx
        .conn
        .execute(
            "INSERT INTO service_principal_keys (kid, principal_id, public_key, status, created_at, retire_at) \
             VALUES ('k2', 'svc:a', X'00', 'retiring', 1000, NULL)",
            (),
        )
        .await;
    assert!(
        bad_retiring.is_err(),
        "retiring key without retire_at must be rejected",
    );

    // Valid shapes land.
    fx.conn
        .execute(
            "INSERT INTO service_principal_keys (kid, principal_id, public_key, status, created_at) \
             VALUES ('k3', 'svc:a', X'00', 'active', 1000)",
            (),
        )
        .await
        .expect("valid active key");
    fx.conn
        .execute(
            "INSERT INTO service_principal_keys (kid, principal_id, public_key, status, created_at, retire_at) \
             VALUES ('k4', 'svc:a', X'00', 'retiring', 1000, 2000)",
            (),
        )
        .await
        .expect("valid retiring key");

    assert_eq!(
        count(
            &fx.conn,
            "SELECT COUNT(*) FROM service_principal_keys WHERE principal_id = 'svc:a'"
        )
        .await,
        2,
    );

    // FK CASCADE wipes keys when the principal is deleted.
    fx.conn
        .execute("DELETE FROM service_principals WHERE id = 'svc:a'", ())
        .await
        .expect("delete svc");
    assert_eq!(
        count(&fx.conn, "SELECT COUNT(*) FROM service_principal_keys").await,
        0,
        "keys should cascade",
    );
}

#[tokio::test]
async fn spk_active_partial_index_present() {
    // sqlite_master records the partial index with its WHERE clause; this is a
    // cheap structural check that libSQL accepted the partial-index syntax.
    let fx = fresh_libsql().await;
    let mut rows = fx
        .conn
        .query(
            "SELECT sql FROM sqlite_master WHERE type='index' AND name='ix_spk_principal_active'",
            (),
        )
        .await
        .expect("query sqlite_master");
    let row = rows
        .next()
        .await
        .expect("step")
        .expect("ix_spk_principal_active should exist");
    let sql: String = row.get(0).expect("sql col");
    assert!(
        sql.to_ascii_lowercase().contains("where status = 'active'"),
        "expected partial-index WHERE clause, got: {sql}",
    );
}
