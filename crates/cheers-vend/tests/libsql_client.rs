//! The vend listener driven by the client the workbench actually runs: libsql's
//! remote (Hrana-over-HTTP) connection, the same crate and features as yah
//! data-source's libsql adapter.
//!
//! The reqwest tests in `vend.rs` set `Content-Type` and speak only the
//! pipeline, so they passed while libsql could not read at all. Its `query`
//! prepares with `describe` and reads rows through `POST /v3/cursor`, and it
//! sends no `Content-Type`. This file is what keeps those three honest.

use std::net::{IpAddr, Ipv4Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use cheers_core::{McpClaims, PrincipalId, PrincipalKind, Scope};
use cheers_server::PasetoV4SecretMinter;
use cheers_vend::{VendConfig, VendListener, VendService};

const AUD: &str = "svc/main";

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

struct Fixture {
    _dir: tempfile::TempDir,
    _db: turso::Database,
    listener: VendListener,
    token: String,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("svc.turso");
    let db = turso::Builder::new_local(path.to_str().unwrap()).build().await.unwrap();
    let own = db.connect().unwrap();
    own.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)", ()).await.unwrap();
    own.execute("INSERT INTO t (id, name) VALUES (1, 'alpha'), (2, 'beta')", ()).await.unwrap();

    let (minter, _) = PasetoV4SecretMinter::generate().unwrap();
    let mut public = [0u8; 32];
    public.copy_from_slice(&minter.secret_key_bytes()[32..]);
    let cfg = VendConfig::from_public_key(&public, AUD).unwrap();
    let kid = cfg.kid.clone();
    let service = VendService::new(&db, cfg).await.unwrap();
    let listener = VendListener::bind(IpAddr::V4(Ipv4Addr::LOCALHOST), 0, service).await.unwrap();

    let sub = PrincipalId { kind: PrincipalKind::User, id: "operator".into() };
    let claims = McpClaims::new("yah-camp", AUD, sub, now() - 10, now() + 300, "jti-libsql", vec![Scope::from_static("sql:read")]);
    let token = minter.mint_mcp(&claims, &kid).unwrap();
    Fixture { _dir: dir, _db: db, listener, token }
}

async fn connect(f: &Fixture) -> libsql::Connection {
    libsql::Builder::new_remote(f.listener.endpoint(), f.token.clone())
        .build()
        .await
        .unwrap()
        .connect()
        .unwrap()
}

#[tokio::test]
async fn libsql_query_reads_rows_through_describe_and_the_cursor() {
    let f = fixture().await;
    let conn = connect(&f).await;
    let mut rows = conn
        .query("SELECT id, name FROM t WHERE id >= ?1 ORDER BY id", libsql::params![1])
        .await
        .unwrap();
    assert_eq!(rows.column_name(1), Some("name"));
    let mut got = Vec::new();
    while let Some(row) = rows.next().await.unwrap() {
        got.push((row.get::<i64>(0).unwrap(), row.get::<String>(1).unwrap()));
    }
    assert_eq!(got, vec![(1, "alpha".to_string()), (2, "beta".to_string())]);
}

#[tokio::test]
async fn libsql_sees_a_write_refused_and_a_bad_statement_as_errors_not_hangs() {
    let f = fixture().await;
    let conn = connect(&f).await;
    let write = conn.execute("INSERT INTO t (id, name) VALUES (3, 'gamma')", ()).await;
    assert!(write.is_err(), "a vended connection is query_only: {write:?}");
    let bad = conn.query("SELECT nope FROM missing", ()).await;
    assert!(bad.is_err(), "a statement that cannot prepare is an error: {:?}", bad.err());
}

#[tokio::test]
async fn libsql_with_the_wrong_token_is_refused() {
    let mut f = fixture().await;
    f.token = "v4.public.not-a-token".into();
    let conn = connect(&f).await;
    assert!(conn.query("SELECT 1", ()).await.is_err());
}
