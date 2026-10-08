//! The Hrana subset: pipeline request types, the v3 cursor, and their
//! execution over one `turso::Connection`. Responses are built as JSON values in
//! the shapes the libsql HTTP client parses (`StreamResult`, `StmtResult`,
//! `BatchResult`, `DescribeResult`, cursor entries).
//!
//! `describe` and the cursor are not optional extras. libsql's
//! `Connection::query` prepares with a `describe` and then reads rows through
//! `POST /v3/cursor`. Without both, a libsql client could write (and be
//! refused) but never read. noisetable R804-F2 found this by driving `yah sql`
//! at a live listener.

use base64::Engine as _;
use serde::Deserialize;
use serde_json::{json, Value as Json};

#[derive(Deserialize)]
pub struct PipelineRequest {
    /// Accepted and ignored: every pipeline is stateless, so the response
    /// baton is always `null` and the client starts a fresh stream next time.
    #[serde(default)]
    #[allow(dead_code)]
    pub baton: Option<String>,
    pub requests: Vec<StreamRequest>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamRequest {
    Close,
    Execute { stmt: Stmt },
    Batch { batch: Batch },
    GetAutocommit,
    Describe {
        sql: Option<String>,
    },
    #[serde(other)]
    Unsupported,
}

/// `POST /v3/cursor`: one batch, answered as newline-delimited JSON.
#[derive(Deserialize)]
pub struct CursorRequest {
    /// Accepted and ignored, as on the pipeline: the response baton is `null`.
    #[serde(default)]
    #[allow(dead_code)]
    pub baton: Option<String>,
    pub batch: Batch,
}

#[derive(Deserialize)]
pub struct Stmt {
    pub sql: Option<String>,
    #[serde(default)]
    pub args: Vec<HValue>,
    #[serde(default)]
    pub named_args: Vec<NamedArg>,
    #[serde(default)]
    pub want_rows: Option<bool>,
}

#[derive(Deserialize)]
pub struct NamedArg {
    pub name: String,
    pub value: HValue,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HValue {
    Null,
    Integer { value: String },
    Float { value: f64 },
    Text { value: String },
    Blob { base64: String },
}

#[derive(Deserialize)]
pub struct Batch {
    pub steps: Vec<BatchStep>,
}

#[derive(Deserialize)]
pub struct BatchStep {
    #[serde(default)]
    pub condition: Option<Cond>,
    pub stmt: Stmt,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Cond {
    Ok { step: usize },
    Error { step: usize },
    Not { cond: Box<Cond> },
    And { conds: Vec<Cond> },
    Or { conds: Vec<Cond> },
    IsAutocommit,
}

pub async fn run_pipeline(conn: &turso::Connection, req: PipelineRequest) -> Json {
    let mut results = Vec::with_capacity(req.requests.len());
    for r in req.requests {
        let out = match r {
            StreamRequest::Close => Ok(json!({"type": "close"})),
            StreamRequest::Execute { stmt } => execute(conn, stmt)
                .await
                .map(|result| json!({"type": "execute", "result": result})),
            StreamRequest::Batch { batch } => Ok(json!({"type": "batch", "result": run_batch(conn, batch).await})),
            StreamRequest::GetAutocommit => Ok(json!({
                "type": "get_autocommit",
                "is_autocommit": conn.is_autocommit().unwrap_or(true),
            })),
            StreamRequest::Describe { sql } => describe(conn, sql)
                .await
                .map(|result| json!({"type": "describe", "result": result})),
            StreamRequest::Unsupported => Err("request type not supported by this server".to_string()),
        };
        results.push(match out {
            Ok(response) => json!({"type": "ok", "response": response}),
            Err(message) => json!({"type": "error", "error": error(message)}),
        });
    }
    json!({"baton": null, "base_url": null, "results": results})
}

fn error(message: String) -> Json {
    json!({"message": message, "code": "SQLITE_ERROR"})
}

async fn run_batch(conn: &turso::Connection, batch: Batch) -> Json {
    let mut step_results: Vec<Json> = Vec::with_capacity(batch.steps.len());
    let mut step_errors: Vec<Json> = Vec::with_capacity(batch.steps.len());
    for step in run_steps(conn, batch).await {
        match step {
            None => {
                step_results.push(Json::Null);
                step_errors.push(Json::Null);
            }
            Some(Ok(out)) => {
                step_results.push(out.into_stmt_result());
                step_errors.push(Json::Null);
            }
            Some(Err(m)) => {
                step_results.push(Json::Null);
                step_errors.push(error(m));
            }
        }
    }
    json!({"step_results": step_results, "step_errors": step_errors})
}

/// The `/v3/cursor` response body: a `{baton, base_url}` header line, then per
/// executed step `step_begin`, its `row`s and `step_end`, or one `step_error`.
/// A skipped step emits nothing. Buffered rather than streamed, like the
/// pipeline: the whole batch has run before the first line goes out.
pub async fn run_cursor(conn: &turso::Connection, req: CursorRequest) -> String {
    let mut lines = vec![json!({"baton": null, "base_url": null})];
    for (step, outcome) in run_steps(conn, req.batch).await.into_iter().enumerate() {
        match outcome {
            None => {}
            Some(Ok(out)) => {
                lines.push(json!({"type": "step_begin", "step": step, "cols": out.cols}));
                lines.extend(out.rows.into_iter().map(|row| json!({"type": "row", "row": row})));
                lines.push(json!({"type": "step_end", "affected_row_count": 0, "last_inserted_rowid": null}));
            }
            Some(Err(m)) => lines.push(json!({"type": "step_error", "step": step, "error": error(m)})),
        }
    }
    let mut body = String::new();
    for line in lines {
        body.push_str(&line.to_string());
        body.push('\n');
    }
    body
}

/// Run a batch's steps in order, honouring each step's condition against the
/// earlier steps' outcomes. `None` is a skipped step. Shared by `batch` and the
/// cursor so the two cannot disagree about which steps run.
async fn run_steps(conn: &turso::Connection, batch: Batch) -> Vec<Option<Result<StmtOutcome, String>>> {
    let mut results: Vec<Option<Result<StmtOutcome, String>>> = Vec::with_capacity(batch.steps.len());
    let mut outcomes: Vec<Option<bool>> = Vec::with_capacity(batch.steps.len());
    for step in batch.steps {
        let run = match &step.condition {
            None => true,
            Some(c) => eval(c, &outcomes, conn),
        };
        if !run {
            results.push(None);
            outcomes.push(None);
            continue;
        }
        let out = run_stmt(conn, step.stmt).await;
        outcomes.push(Some(out.is_ok()));
        results.push(Some(out));
    }
    results
}

/// `outcomes[i]`: `Some(true)` ok, `Some(false)` error, `None` skipped.
fn eval(c: &Cond, outcomes: &[Option<bool>], conn: &turso::Connection) -> bool {
    match c {
        Cond::Ok { step } => outcomes.get(*step).copied().flatten() == Some(true),
        Cond::Error { step } => outcomes.get(*step).copied().flatten() == Some(false),
        Cond::Not { cond } => !eval(cond, outcomes, conn),
        Cond::And { conds } => conds.iter().all(|c| eval(c, outcomes, conn)),
        Cond::Or { conds } => conds.iter().any(|c| eval(c, outcomes, conn)),
        Cond::IsAutocommit => conn.is_autocommit().unwrap_or(true),
    }
}

fn to_turso(v: HValue) -> Result<turso::Value, String> {
    Ok(match v {
        HValue::Null => turso::Value::Null,
        HValue::Integer { value } => {
            turso::Value::Integer(value.parse().map_err(|_| format!("bad integer {value:?}"))?)
        }
        HValue::Float { value } => turso::Value::Real(value),
        HValue::Text { value } => turso::Value::Text(value),
        HValue::Blob { base64 } => turso::Value::Blob(
            base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(base64.trim_end_matches('='))
                .map_err(|e| format!("bad blob: {e}"))?,
        ),
    })
}

fn from_turso(v: turso::Value) -> Json {
    match v {
        turso::Value::Null => json!({"type": "null"}),
        turso::Value::Integer(i) => json!({"type": "integer", "value": i.to_string()}),
        turso::Value::Real(f) => json!({"type": "float", "value": f}),
        turso::Value::Text(s) => json!({"type": "text", "value": s}),
        turso::Value::Blob(b) => {
            json!({"type": "blob", "base64": base64::engine::general_purpose::STANDARD.encode(b)})
        }
    }
}

/// One statement's columns and rows, before it is shaped for the pipeline
/// (`StmtResult`) or the cursor (entries).
struct StmtOutcome {
    cols: Vec<Json>,
    rows: Vec<Json>,
    rows_read: u64,
}

impl StmtOutcome {
    fn into_stmt_result(self) -> Json {
        json!({
            "cols": self.cols,
            "rows": self.rows,
            "affected_row_count": 0,
            "last_insert_rowid": null,
            "rows_read": self.rows_read,
            "rows_written": 0,
        })
    }
}

async fn execute(conn: &turso::Connection, stmt: Stmt) -> Result<Json, String> {
    run_stmt(conn, stmt).await.map(StmtOutcome::into_stmt_result)
}

fn cols_of(prepared: &turso::Statement) -> Vec<Json> {
    prepared
        .columns()
        .iter()
        .map(|c| json!({"name": c.name(), "decltype": c.decl_type()}))
        .collect()
}

/// `describe`: the statement's columns, from preparing it on this connection.
///
/// `params` is always empty: turso's `Statement` exposes no parameter
/// introspection, and the libsql client reads only `cols`. `is_readonly` is
/// `true` because this connection is pinned `PRAGMA query_only`, so no
/// statement can write here. A writing one fails at execution, not at describe.
async fn describe(conn: &turso::Connection, sql: Option<String>) -> Result<Json, String> {
    let sql = sql.ok_or("describe needs sql (sql_id is not supported)")?;
    let prepared = conn.prepare(&sql).await.map_err(|e| e.to_string())?;
    let is_explain = sql.trim_start().get(..7).is_some_and(|w| w.eq_ignore_ascii_case("explain"));
    Ok(json!({
        "params": [],
        "cols": cols_of(&prepared),
        "is_explain": is_explain,
        "is_readonly": true,
    }))
}

async fn run_stmt(conn: &turso::Connection, stmt: Stmt) -> Result<StmtOutcome, String> {
    let sql = stmt.sql.ok_or("stmt.sql is required (sql_id is not supported)")?;
    if !stmt.args.is_empty() && !stmt.named_args.is_empty() {
        return Err("positional and named args cannot be mixed".into());
    }
    let mut prepared = conn.prepare(&sql).await.map_err(|e| e.to_string())?;
    let cols = cols_of(&prepared);
    let mut rows = if stmt.named_args.is_empty() {
        let args = stmt.args.into_iter().map(to_turso).collect::<Result<Vec<_>, _>>()?;
        prepared.query(args).await
    } else {
        let args = stmt
            .named_args
            .into_iter()
            .map(|a| to_turso(a.value).map(|v| (a.name, v)))
            .collect::<Result<Vec<_>, _>>()?;
        prepared.query(args).await
    }
    .map_err(|e| e.to_string())?;
    let want_rows = stmt.want_rows.unwrap_or(true);
    let mut out_rows = Vec::new();
    let mut rows_read = 0u64;
    while let Some(row) = rows.next().await.map_err(|e| e.to_string())? {
        rows_read += 1;
        if want_rows {
            let mut cells = Vec::with_capacity(row.column_count());
            for i in 0..row.column_count() {
                cells.push(from_turso(row.get_value(i).map_err(|e| e.to_string())?));
            }
            out_rows.push(Json::Array(cells));
        }
    }
    Ok(StmtOutcome { cols, rows: out_rows, rows_read })
}
