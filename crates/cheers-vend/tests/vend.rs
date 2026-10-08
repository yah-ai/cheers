//! In-process vend listener over a temp Turso file (R960-F10 acceptance).

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cheers_core::{McpClaims, PrincipalId, PrincipalKind, Scope};
use cheers_server::PasetoV4SecretMinter;
use cheers_vend::{VendConfig, VendError, VendListener, VendService};
use serde_json::{json, Value};

const KID: &str = "vend-test-kid";
const AUD: &str = "noisetable-account/account";

struct Fixture {
    _dir: tempfile::TempDir,
    db: turso::Database,
    minter: PasetoV4SecretMinter,
    listener: VendListener,
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("svc.turso");
    let db = turso::Builder::new_local(path.to_str().unwrap()).build().await.unwrap();
    let own = db.connect().unwrap();
    own.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)", ()).await.unwrap();
    own.execute("INSERT INTO t (id, name) VALUES (1, 'alpha'), (2, 'beta')", ()).await.unwrap();

    let (minter, verifier) = PasetoV4SecretMinter::generate().unwrap();
    let mut cfg = VendConfig::new(verifier, KID, AUD);
    cfg.reject_floor = Duration::from_millis(40);
    let service = VendService::new(&db, cfg).await.unwrap();
    let listener = VendListener::bind(IpAddr::V4(Ipv4Addr::LOCALHOST), 0, service).await.unwrap();
    Fixture { _dir: dir, db, minter, listener }
}

fn mint(f: &Fixture, aud: &str, scopes: Vec<Scope>, exp: i64) -> String {
    let sub = PrincipalId { kind: PrincipalKind::User, id: "operator".into() };
    let claims = McpClaims::new("yah-camp", aud, sub, now() - 10, exp, "jti-1", scopes);
    f.minter.mint_mcp(&claims, KID).unwrap()
}

fn select_body() -> Value {
    json!({"baton": null, "requests": [
        {"type": "execute", "stmt": {"sql": "SELECT id, name FROM t WHERE id >= ? ORDER BY id", "args": [{"type": "integer", "value": "1"}]}},
        {"type": "close"}
    ]})
}

async fn post(f: &Fixture, token: Option<&str>, body: &Value) -> (u16, String, Duration) {
    let client = reqwest::Client::new();
    let mut req = client.post(format!("{}/v2/pipeline", f.listener.endpoint())).json(body);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let started = std::time::Instant::now();
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap();
    (status, text, started.elapsed())
}

#[tokio::test]
async fn valid_read_token_answers_select() {
    let f = fixture().await;
    let token = mint(&f, AUD, vec![Scope::from_static("sql:read")], now() + 300);
    let (status, text, _) = post(&f, Some(&token), &select_body()).await;
    assert_eq!(status, 200, "{text}");
    let v: Value = serde_json::from_str(&text).unwrap();
    let result = &v["results"][0]["response"]["result"];
    assert_eq!(v["results"][0]["type"], "ok");
    assert_eq!(result["cols"][1]["name"], "name");
    assert_eq!(result["rows"][0][0], json!({"type": "integer", "value": "1"}));
    assert_eq!(result["rows"][1][1], json!({"type": "text", "value": "beta"}));
    assert_eq!(v["results"][1]["response"]["type"], "close");
}

/// libsql's Hrana client sends the pipeline with no `Content-Type`. The
/// listener must serve it exactly as it serves a JSON-typed body.
#[tokio::test]
async fn a_pipeline_without_a_content_type_is_served() {
    let f = fixture().await;
    let token = mint(&f, AUD, vec![Scope::from_static("sql:read")], now() + 300);
    let resp = reqwest::Client::new()
        .post(format!("{}/v2/pipeline", f.listener.endpoint()))
        .bearer_auth(&token)
        .body(serde_json::to_vec(&select_body()).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.headers().get("content-type"), Some(&"application/json".parse().unwrap()));
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap();
    assert_eq!(status, 200, "{text}");
    let v: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["results"][0]["response"]["result"]["rows"][1][1], json!({"type": "text", "value": "beta"}));

    let resp = reqwest::Client::new()
        .post(format!("{}/v2/pipeline", f.listener.endpoint()))
        .bearer_auth(&token)
        .body("not json")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
}

#[tokio::test]
async fn no_token_expired_and_wrong_aud_fail_identically() {
    let f = fixture().await;
    let expired = mint(&f, AUD, vec![Scope::from_static("sql:read")], now() - 5);
    let wrong_aud = mint(&f, "other-workload/db", vec![Scope::from_static("sql:read")], now() + 300);

    let a = post(&f, None, &select_body()).await;
    let b = post(&f, Some(&expired), &select_body()).await;
    let c = post(&f, Some(&wrong_aud), &select_body()).await;
    for (status, body, elapsed) in [&a, &b, &c] {
        assert_eq!(*status, 401);
        assert_eq!(body, &a.1);
        assert!(*elapsed >= Duration::from_millis(40), "refusal under the floor: {elapsed:?}");
    }
}

/// R960-F16: a `sql:write` token (minted by the camp only for a confirmed
/// action) is served on the writable connection; an unknown `sql:*` scope is
/// still 403.
#[tokio::test]
async fn write_token_writes_and_unknown_sql_scope_is_refused() {
    let f = fixture().await;
    let token = mint(
        &f,
        AUD,
        vec![Scope::from_static("sql:read"), Scope::from_static("sql:write")],
        now() + 300,
    );
    let body = json!({"requests": [{"type": "execute", "stmt": {"sql": "INSERT INTO t (id, name) VALUES (3, 'gamma')"}}]});
    let (status, text, _) = post(&f, Some(&token), &body).await;
    assert_eq!(status, 200, "{text}");
    let v: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["results"][0]["type"], "ok", "{text}");

    // Write scope alone (no sql:read) is not a valid vend token.
    let write_only = mint(&f, AUD, vec![Scope::from_static("sql:write")], now() + 300);
    assert_eq!(post(&f, Some(&write_only), &select_body()).await.0, 401);

    let admin = mint(
        &f,
        AUD,
        vec![Scope::from_static("sql:read"), Scope::from_static("sql:admin")],
        now() + 300,
    );
    assert_eq!(post(&f, Some(&admin), &select_body()).await.0, 403);
}

#[tokio::test]
async fn vended_connection_cannot_write_but_owner_can() {
    let f = fixture().await;
    let token = mint(&f, AUD, vec![Scope::from_static("sql:read")], now() + 300);
    let body = json!({"requests": [{"type": "execute", "stmt": {"sql": "INSERT INTO t (id, name) VALUES (3, 'gamma')"}}]});
    let (status, text, _) = post(&f, Some(&token), &body).await;
    assert_eq!(status, 200);
    let v: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["results"][0]["type"], "error", "{text}");
    // The service's own connection is unaffected by the vend connection's pragma.
    f.db.connect().unwrap().execute("INSERT INTO t (id, name) VALUES (4, 'delta')", ()).await.unwrap();
}

#[tokio::test]
async fn unspecified_bind_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let db = turso::Builder::new_local(dir.path().join("x.turso").to_str().unwrap()).build().await.unwrap();
    let (_m, verifier) = PasetoV4SecretMinter::generate().unwrap();
    let service = VendService::new(&db, VendConfig::new(verifier, KID, AUD)).await.unwrap();
    let err = VendListener::bind(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0, service).await.err().unwrap();
    assert!(matches!(err, VendError::UnspecifiedBind(_)));
}

#[tokio::test]
async fn config_from_public_key_admits_a_token_with_the_derived_kid() {
    let (minter, _) = PasetoV4SecretMinter::generate().unwrap();
    let mut public = [0u8; 32];
    public.copy_from_slice(&minter.secret_key_bytes()[32..]);
    let kid = cheers_verify::kid_for(&public);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("svc.turso");
    let db = turso::Builder::new_local(path.to_str().unwrap()).build().await.unwrap();
    let own = db.connect().unwrap();
    own.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)", ()).await.unwrap();
    own.execute("INSERT INTO t (id, name) VALUES (1, 'alpha'), (2, 'beta')", ()).await.unwrap();

    let mut cfg = VendConfig::from_public_key(&public, AUD).unwrap();
    assert_eq!(cfg.kid, kid);
    cfg.reject_floor = Duration::from_millis(40);
    let service = VendService::new(&db, cfg).await.unwrap();
    let listener = VendListener::bind(IpAddr::V4(Ipv4Addr::LOCALHOST), 0, service).await.unwrap();
    let f = Fixture { _dir: dir, db, minter, listener };

    let sub = PrincipalId { kind: PrincipalKind::User, id: "operator".into() };
    let claims = McpClaims::new("yah-camp", AUD, sub, now() - 10, now() + 300, "jti-2", vec![Scope::from_static("sql:read")]);
    let token = f.minter.mint_mcp(&claims, &kid).unwrap();
    let (status, body, _) = post(&f, Some(&token), &select_body()).await;
    assert_eq!(status, 200, "{body}");
}
