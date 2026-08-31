//! Centralized audit table — the [`AuditStore`] trait.
//!
//! Cheers's audit table is the durable, queryable copy of every MCP-mediated
//! action kamaji observes on its host. Kamaji retains a local JSONL as
//! the source of truth and forwards batches here via `POST /audit/ingest`;
//! cheers's responsibility ends at "accepted and durable on cheers's side"
//! (see `.yah/docs/working/mcp-auth-and-ownership.md` §Audit ingest).
//!
//! Append-only. There is no in-place edit or delete — the only writes are
//! [`AuditStore::insert_batch`]. The read side is
//! [`AuditStore::query_by_on_behalf_of`] (R020-F14): cursor-paged, filtered
//! by the human the action is attributable to.
//!
//! ## What "on behalf of" means here
//!
//! The wire record has no `on_behalf_of` column — it is *derived* from `sub`.
//! Per RFC 8693 (and [`Actor`]'s own contract) `sub` is the primary subject
//! and `act` is the agent acting on that subject's behalf, so a row is
//! attributable to user `U` exactly when `record.sub == user:U`, whether or
//! not an agent carried the call out. That is the projection W159 §Audit
//! journal describes as
//! `SELECT * FROM audit WHERE method LIKE … AND on_behalf_of = $1`.
//!
//! Camp-subject rows are deliberately NOT rolled up to the user the camp is
//! `bound_to`: `.yah/docs/working/mcp-auth-and-ownership.md` §Principal kinds
//! requires "camp X took this action" and "user U took this action" to stay
//! unambiguously distinguishable in the audit trail. A camp rollup, if W127
//! ever wants one, is a separate query — not a widening of this one.
//!
//! Record shape per W159 §Audit journal: `{ at, sub, act, camp_id, aud,
//! method, scope, result, request_id }`. The wire and storage shapes match
//! one-to-one — cheers doesn't repackage what kamaji sends, it just
//! durably appends. The only field cheers contributes is the row `id` and
//! the `ingested_at` server timestamp.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cheers_core::{Actor, PrincipalId, PrincipalKind, Scope, StoreError};

/// Why an [`AuditRecord`] failed validation before reaching the store.
///
/// The HTTP layer surfaces these as `400 audit_invalid`. They are the
/// "forbidden shape" the F13 verify item calls out — a malformed batch is
/// rejected wholesale so kamaji's bounded-backoff retry sees a clean
/// 4xx, not a partial commit.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuditValidationError {
    #[error("audit record: `at` must be > 0; got {0}")]
    NonPositiveAt(i64),
    #[error("audit record: `aud` must not be empty")]
    EmptyAud,
    #[error("audit record: `method` must not be empty")]
    EmptyMethod,
    #[error("audit record: `result` must not be empty")]
    EmptyResult,
    #[error("audit record: `request_id` must not be empty")]
    EmptyRequestId,
}

/// One audit record — verbatim with W159 §Audit journal.
///
/// Required fields: `at`, `sub`, `aud`, `method`, `result`, `request_id`.
/// `scope` MAY be empty (e.g. a call rejected before scope-matching). `act`
/// and `camp_id` are set when an agent acted on the subject's behalf and/or
/// the call was scoped to a camp; both `None` for a direct user-principal
/// action with no camp context.
///
/// Mirrors the conditional-claim shape of [`McpClaims`](cheers_core::McpClaims)
/// so a verified token's metadata can flow into the record without lossy
/// repackaging.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AuditRecord {
    /// Unix-seconds timestamp the action happened (kamaji's local clock).
    pub at: i64,
    /// Acting principal — the `sub` claim from the verified token.
    pub sub: PrincipalId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<Actor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub camp_id: Option<String>,
    /// Target resource URI (the verified token's `aud`).
    pub aud: String,
    /// Free-form method identifier (`POST /cloud/deploy`, `mcp.tools/call`, …)
    /// — kamaji supplies a stable string per call shape.
    pub method: String,
    /// Scope list the call presented. Stored as a typed `Vec<Scope>` so a
    /// future wildcard or unknown-scope ingest is rejected at parse time
    /// (per composition rule 1 — no wildcards on the wire).
    #[serde(default)]
    pub scope: Vec<Scope>,
    /// Outcome string kamaji produced (`allow` | `deny` | `error` is the
    /// usual taxonomy, but cheers does not constrain it — see audit-reader
    /// docs in F14 for the canonical vocabulary). Cheers is durable storage,
    /// not the source of result semantics.
    pub result: String,
    /// Correlator into kamaji's local JSONL — same id appears in both
    /// places so an operator can match a cheers row to kamaji's source.
    pub request_id: String,
}

impl AuditRecord {
    /// Construct + validate. Returns the same error variants the wire layer
    /// surfaces as `400 audit_invalid`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        at: i64,
        sub: PrincipalId,
        act: Option<Actor>,
        camp_id: Option<String>,
        aud: impl Into<String>,
        method: impl Into<String>,
        scope: Vec<Scope>,
        result: impl Into<String>,
        request_id: impl Into<String>,
    ) -> Result<Self, AuditValidationError> {
        let rec = Self {
            at,
            sub,
            act,
            camp_id,
            aud: aud.into(),
            method: method.into(),
            scope,
            result: result.into(),
            request_id: request_id.into(),
        };
        rec.validate()?;
        Ok(rec)
    }

    /// Re-check the wire-shape invariants. Called from [`Self::new`]; the
    /// HTTP layer calls it again on records that arrived via `Deserialize`
    /// so a deserialized record can't side-step the constructor.
    pub fn validate(&self) -> Result<(), AuditValidationError> {
        if self.at <= 0 {
            return Err(AuditValidationError::NonPositiveAt(self.at));
        }
        if self.aud.is_empty() {
            return Err(AuditValidationError::EmptyAud);
        }
        if self.method.is_empty() {
            return Err(AuditValidationError::EmptyMethod);
        }
        if self.result.is_empty() {
            return Err(AuditValidationError::EmptyResult);
        }
        if self.request_id.is_empty() {
            return Err(AuditValidationError::EmptyRequestId);
        }
        Ok(())
    }
}

/// One row in the audit table — an [`AuditRecord`] plus the bits cheers
/// contributes (`id` and `ingested_at`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AuditRow {
    pub id: String,
    pub record: AuditRecord,
    /// Unix-seconds timestamp cheers received and durably appended the row.
    /// Distinct from `record.at` (kamaji's clock) — having both lets an
    /// operator see ingest latency without joining clocks at query time.
    pub ingested_at: i64,
}

impl AuditRow {
    pub fn new(id: String, record: AuditRecord, ingested_at: i64) -> Self {
        Self {
            id,
            record,
            ingested_at,
        }
    }
}

/// Default page size when the caller doesn't ask for one.
pub const DEFAULT_AUDIT_PAGE_LIMIT: usize = 100;

/// Hard ceiling on a page — a caller asking for more gets this. The audit
/// table is large and append-only; an unbounded page is a denial-of-service
/// shape, not a feature.
pub const MAX_AUDIT_PAGE_LIMIT: usize = 500;

/// Keyset position in the audit result order.
///
/// The order is `(at DESC, id DESC)` — `at` alone is kamaji's clock and is
/// not unique, so the row `id` breaks ties and makes the order total. That
/// totality is what lets this be a *keyset* cursor rather than an offset:
/// rows appended while a client pages never shift the rows behind it, so no
/// row is skipped or repeated.
///
/// Opaque on the wire — see [`to_wire`](Self::to_wire) /
/// [`from_wire`](Self::from_wire). Clients must treat the string as a token
/// to echo back, never as a parseable position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditCursor {
    pub at: i64,
    pub id: String,
}

impl AuditCursor {
    pub fn new(at: i64, id: impl Into<String>) -> Self {
        Self { at, id: id.into() }
    }

    /// Position of this row in the result order.
    pub fn from_row(row: &AuditRow) -> Self {
        Self::new(row.record.at, row.id.clone())
    }

    /// Encode for the wire — base64url-no-pad over `"<at>:<id>"`. The
    /// encoding is deliberately opaque, not signed: the cursor names a
    /// public position in a result set the caller is already authorized to
    /// read, so forging one grants nothing the caller couldn't ask for
    /// directly with `since=`. Authorization is re-checked per request and
    /// never carried in the cursor.
    pub fn to_wire(&self) -> String {
        URL_SAFE_NO_PAD.encode(format!("{}:{}", self.at, self.id))
    }

    /// Inverse of [`to_wire`](Self::to_wire).
    pub fn from_wire(s: &str) -> Result<Self, AuditCursorError> {
        let raw = URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map_err(|_| AuditCursorError::Malformed)?;
        let text = String::from_utf8(raw).map_err(|_| AuditCursorError::Malformed)?;
        let (at, id) = text.split_once(':').ok_or(AuditCursorError::Malformed)?;
        let at: i64 = at.parse().map_err(|_| AuditCursorError::Malformed)?;
        if id.is_empty() {
            return Err(AuditCursorError::Malformed);
        }
        Ok(Self::new(at, id))
    }

    /// `true` if `row` sorts strictly after this cursor under
    /// `(at DESC, id DESC)` — i.e. the row belongs on a later page.
    fn precedes(&self, row: &AuditRow) -> bool {
        (row.record.at, row.id.as_str()) < (self.at, self.id.as_str())
    }
}

/// A cursor string that didn't decode. One variant on purpose — the wire
/// form is opaque, so distinguishing "bad base64" from "bad payload" tells a
/// client nothing actionable beyond "you didn't echo back what we gave you".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuditCursorError {
    #[error("malformed audit cursor")]
    Malformed,
}

/// Why an [`AuditQuery`] could not be constructed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuditQueryError {
    /// `on_behalf_of` names a non-user principal. The `on_behalf_of` lane is
    /// user-only by the same invariant the ownership table enforces in SQL
    /// (`CHECK (on_behalf_of IS NULL OR on_behalf_of LIKE 'user:%')`), and
    /// widening it would collapse the camp-vs-user audit distinction the
    /// design doc requires.
    #[error("on_behalf_of must be a user principal; got {0}")]
    OnBehalfOfNotUser(PrincipalKind),
}

/// One page request against the audit table.
///
/// Build with [`new`](Self::new) (which enforces the user-principal
/// invariant) and narrow with the `with_*` combinators. Every filter is
/// conjunctive.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuditQuery {
    /// The human the rows must be attributable to — matched against
    /// `record.sub`. Always a [`PrincipalKind::User`].
    pub on_behalf_of: PrincipalId,
    /// Inclusive lower bound on `record.at` (kamaji's clock), when set.
    pub since: Option<i64>,
    /// Literal prefix `record.method` must start with, when set. Not a glob
    /// and not a regex — W127's "who deployed what" needs `cloud.deploy`,
    /// nothing richer.
    pub method_prefix: Option<String>,
    /// Resume position from a previous page's `next_cursor`.
    pub cursor: Option<AuditCursor>,
    /// Page size, already clamped to `1..=MAX_AUDIT_PAGE_LIMIT`.
    pub limit: usize,
}

impl AuditQuery {
    /// New query for `on_behalf_of`, at the default page size.
    ///
    /// Rejects a non-user principal — see
    /// [`AuditQueryError::OnBehalfOfNotUser`].
    pub fn new(on_behalf_of: PrincipalId) -> Result<Self, AuditQueryError> {
        if on_behalf_of.kind != PrincipalKind::User {
            return Err(AuditQueryError::OnBehalfOfNotUser(on_behalf_of.kind));
        }
        Ok(Self {
            on_behalf_of,
            since: None,
            method_prefix: None,
            cursor: None,
            limit: DEFAULT_AUDIT_PAGE_LIMIT,
        })
    }

    pub fn with_since(mut self, since: i64) -> Self {
        self.since = Some(since);
        self
    }

    pub fn with_method_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.method_prefix = Some(prefix.into());
        self
    }

    pub fn with_cursor(mut self, cursor: AuditCursor) -> Self {
        self.cursor = Some(cursor);
        self
    }

    /// Set the page size, clamped to `1..=MAX_AUDIT_PAGE_LIMIT`. Clamps
    /// rather than erroring: an over-large `?limit=` is a client that wants
    /// "as much as you'll give me", and failing the whole request over it
    /// buys nothing.
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = limit.clamp(1, MAX_AUDIT_PAGE_LIMIT);
        self
    }

    /// `true` if `row` satisfies every filter except the cursor position.
    /// Shared by the in-memory impl and available to any impl that can't
    /// push the whole predicate into its backend.
    pub fn matches(&self, row: &AuditRow) -> bool {
        if row.record.sub != self.on_behalf_of {
            return false;
        }
        if let Some(since) = self.since {
            if row.record.at < since {
                return false;
            }
        }
        if let Some(prefix) = &self.method_prefix {
            if !row.record.method.starts_with(prefix.as_str()) {
                return false;
            }
        }
        true
    }
}

/// One page of audit rows, newest first.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuditPage {
    /// Rows in `(at DESC, id DESC)` order.
    pub rows: Vec<AuditRow>,
    /// Position to pass as the next request's cursor. `None` means this was
    /// the last page — impls set it only when a further row is known to
    /// exist (by over-fetching one), so a client never has to make a final
    /// empty round-trip to discover the end.
    pub next_cursor: Option<AuditCursor>,
}

impl AuditPage {
    /// Build a page from `limit + 1` candidate rows already in result order:
    /// truncates to `limit` and derives `next_cursor` iff the extra row was
    /// present.
    pub fn from_overfetch(mut rows: Vec<AuditRow>, limit: usize) -> Self {
        let next_cursor = if rows.len() > limit {
            rows.truncate(limit);
            rows.last().map(AuditCursor::from_row)
        } else {
            None
        };
        Self { rows, next_cursor }
    }
}

/// Append-only persistence for audit records.
///
/// Only one mutation method — [`insert_batch`](Self::insert_batch). A batch
/// is rejected wholesale if any record fails [`AuditRecord::validate`]; no
/// partial commits, so kamaji's retry-with-backoff sees a clean 4xx.
///
/// The read side is [`query_by_on_behalf_of`](Self::query_by_on_behalf_of).
#[async_trait]
pub trait AuditStore: Send + Sync {
    /// Insert a batch of records atomically. The impl assigns each row a
    /// fresh opaque id and stamps `ingested_at`. Returns the resulting
    /// [`AuditRow`]s in the same order as the input.
    ///
    /// Validation is the caller's responsibility — pass already-validated
    /// [`AuditRecord`]s (the HTTP layer runs [`AuditRecord::validate`] over
    /// the batch before calling here). The trait does not re-validate; it
    /// just durably appends.
    async fn insert_batch(
        &self,
        records: &[AuditRecord],
        ingested_at: i64,
    ) -> Result<Vec<AuditRow>, StoreError>;

    /// One page of rows attributable to `query.on_behalf_of`, newest first
    /// (`at DESC, id DESC`), honouring the `since` / `method_prefix` filters
    /// and resuming from `query.cursor`.
    ///
    /// Impls must over-fetch one row beyond `query.limit` and hand the result
    /// to [`AuditPage::from_overfetch`], so `next_cursor` is `Some` only when
    /// a further row genuinely exists.
    async fn query_by_on_behalf_of(&self, query: &AuditQuery)
    -> Result<AuditPage, StoreError>;
}

/// In-memory [`AuditStore`] for tests and single-node bootstrapping. Cheap
/// to `clone` — shares one backing queue. Records keep insertion order.
#[derive(Default, Clone)]
pub struct MemoryAuditStore {
    inner: Arc<Mutex<MemoryAuditInner>>,
}

#[derive(Default)]
struct MemoryAuditInner {
    next_seq: u64,
    rows: VecDeque<AuditRow>,
}

impl MemoryAuditStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of every row inserted so far, in insertion order. Test-only
    /// accessor — `AuditStore` proper exposes reads through F14's surface.
    pub fn snapshot(&self) -> Vec<AuditRow> {
        self.inner
            .lock()
            .expect("audit store mutex poisoned")
            .rows
            .iter()
            .cloned()
            .collect()
    }
}

impl std::fmt::Debug for MemoryAuditStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryAuditStore").finish_non_exhaustive()
    }
}

#[async_trait]
impl AuditStore for MemoryAuditStore {
    async fn insert_batch(
        &self,
        records: &[AuditRecord],
        ingested_at: i64,
    ) -> Result<Vec<AuditRow>, StoreError> {
        let mut g = self.inner.lock().expect("audit store mutex poisoned");
        let mut out = Vec::with_capacity(records.len());
        for rec in records {
            g.next_seq += 1;
            let id = format!("audit-{:016x}", g.next_seq);
            let row = AuditRow::new(id, rec.clone(), ingested_at);
            g.rows.push_back(row.clone());
            out.push(row);
        }
        Ok(out)
    }

    async fn query_by_on_behalf_of(
        &self,
        query: &AuditQuery,
    ) -> Result<AuditPage, StoreError> {
        let g = self.inner.lock().expect("audit store mutex poisoned");
        let mut hits: Vec<AuditRow> = g
            .rows
            .iter()
            .filter(|row| query.matches(row))
            .filter(|row| {
                query
                    .cursor
                    .as_ref()
                    .map(|c| c.precedes(row))
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        // (at DESC, id DESC) — the same total order the SQL impls index on.
        hits.sort_by(|a, b| {
            b.record
                .at
                .cmp(&a.record.at)
                .then_with(|| b.id.cmp(&a.id))
        });
        hits.truncate(query.limit + 1);
        Ok(AuditPage::from_overfetch(hits, query.limit))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cheers_core::PrincipalId;
    use pollster::block_on;

    fn rec(method: &str, request_id: &str) -> AuditRecord {
        AuditRecord::new(
            1_700_000_000,
            PrincipalId::user("alice"),
            None,
            Some("camp-a".into()),
            "https://kamaji.example",
            method,
            vec![Scope::CloudDeploy],
            "allow",
            request_id,
        )
        .unwrap()
    }

    #[test]
    fn new_accepts_well_formed_record() {
        let r = rec("POST /cloud/deploy", "req-1");
        assert_eq!(r.sub, PrincipalId::user("alice"));
        assert_eq!(r.method, "POST /cloud/deploy");
        assert_eq!(r.result, "allow");
        assert_eq!(r.scope, vec![Scope::CloudDeploy]);
    }

    #[test]
    fn validate_rejects_each_empty_field() {
        // at <= 0
        let mut r = rec("m", "rid");
        r.at = 0;
        assert_eq!(r.validate(), Err(AuditValidationError::NonPositiveAt(0)));
        r.at = -1;
        assert_eq!(r.validate(), Err(AuditValidationError::NonPositiveAt(-1)));

        // empty aud
        let mut r = rec("m", "rid");
        r.aud = String::new();
        assert_eq!(r.validate(), Err(AuditValidationError::EmptyAud));

        // empty method
        let mut r = rec("m", "rid");
        r.method = String::new();
        assert_eq!(r.validate(), Err(AuditValidationError::EmptyMethod));

        // empty result
        let mut r = rec("m", "rid");
        r.result = String::new();
        assert_eq!(r.validate(), Err(AuditValidationError::EmptyResult));

        // empty request_id
        let mut r = rec("m", "rid");
        r.request_id = String::new();
        assert_eq!(r.validate(), Err(AuditValidationError::EmptyRequestId));
    }

    #[test]
    fn validate_allows_empty_scope_list() {
        // A call rejected before scope-matching legitimately has no scope.
        let mut r = rec("m", "rid");
        r.scope.clear();
        r.validate().expect("empty scope is allowed");
    }

    #[test]
    fn memory_store_insert_batch_preserves_order_and_stamps_metadata() {
        let store = MemoryAuditStore::new();
        let batch = vec![
            rec("m1", "rid-1"),
            rec("m2", "rid-2"),
            rec("m3", "rid-3"),
        ];
        let rows = block_on(store.insert_batch(&batch, 5_000)).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].record.method, "m1");
        assert_eq!(rows[1].record.method, "m2");
        assert_eq!(rows[2].record.method, "m3");
        for row in &rows {
            assert_eq!(row.ingested_at, 5_000);
            assert!(!row.id.is_empty());
        }
        // Ids are unique.
        let ids: std::collections::HashSet<_> = rows.iter().map(|r| &r.id).collect();
        assert_eq!(ids.len(), 3);

        // Snapshot reflects insertion order across batches.
        let more = vec![rec("m4", "rid-4")];
        block_on(store.insert_batch(&more, 6_000)).unwrap();
        let snap = store.snapshot();
        assert_eq!(snap.len(), 4);
        assert_eq!(snap[3].record.method, "m4");
        assert_eq!(snap[3].ingested_at, 6_000);
    }

    #[test]
    fn memory_store_empty_batch_is_a_noop() {
        let store = MemoryAuditStore::new();
        let rows = block_on(store.insert_batch(&[], 1_000)).unwrap();
        assert!(rows.is_empty());
        assert!(store.snapshot().is_empty());
    }

    #[test]
    fn audit_record_round_trips_through_serde() {
        let r = rec("POST /x", "rid");
        let json = serde_json::to_string(&r).unwrap();
        let back: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn audit_record_serde_omits_optional_none_fields() {
        let r = rec("m", "rid");
        let json = serde_json::to_string(&r).unwrap();
        // act is None for this fixture; camp_id is Some — only act should be omitted.
        assert!(!json.contains("\"act\""), "act:None must be skipped: {json}");
        assert!(json.contains("\"camp_id\""), "camp_id:Some(_) must serialize: {json}");
    }

    #[test]
    fn trait_is_dyn_compatible() {
        fn _u(_: &dyn AuditStore) {}
    }

    // -----------------------------------------------------------------
    // R020-F14 — the read side
    // -----------------------------------------------------------------

    fn rec_for(sub: PrincipalId, at: i64, method: &str, request_id: &str) -> AuditRecord {
        AuditRecord::new(
            at,
            sub,
            None,
            None,
            "https://kamaji.example",
            method,
            vec![Scope::CloudDeploy],
            "allow",
            request_id,
        )
        .unwrap()
    }

    fn alice() -> PrincipalId {
        PrincipalId::user("alice")
    }

    fn bob() -> PrincipalId {
        PrincipalId::user("bob")
    }

    #[test]
    fn query_rejects_non_user_on_behalf_of() {
        use cheers_core::PrincipalKind;
        assert_eq!(
            AuditQuery::new(PrincipalId::service("kamaji")),
            Err(AuditQueryError::OnBehalfOfNotUser(PrincipalKind::Service)),
        );
        assert_eq!(
            AuditQuery::new(PrincipalId::camp("camp-a")),
            Err(AuditQueryError::OnBehalfOfNotUser(PrincipalKind::Camp)),
        );
        AuditQuery::new(alice()).expect("a user principal is accepted");
    }

    #[test]
    fn query_limit_is_clamped_to_the_ceiling_and_never_zero() {
        let q = AuditQuery::new(alice()).unwrap();
        assert_eq!(q.limit, DEFAULT_AUDIT_PAGE_LIMIT);
        assert_eq!(q.clone().with_limit(0).limit, 1);
        assert_eq!(
            q.clone().with_limit(usize::MAX).limit,
            MAX_AUDIT_PAGE_LIMIT
        );
        assert_eq!(q.with_limit(7).limit, 7);
    }

    #[test]
    fn cursor_round_trips_through_the_opaque_wire_form() {
        let c = AuditCursor::new(1_700_000_000, "audit-000000000000002a");
        let wire = c.to_wire();
        // Opaque: the raw position must not be readable straight off the wire.
        assert!(!wire.contains(':'), "cursor must not leak its shape: {wire}");
        assert!(!wire.contains("1700000000"), "cursor must be encoded: {wire}");
        assert_eq!(AuditCursor::from_wire(&wire).unwrap(), c);
    }

    #[test]
    fn cursor_rejects_malformed_wire_forms() {
        for bad in [
            "!!!not-base64!!!",
            &URL_SAFE_NO_PAD.encode("no-separator"),
            &URL_SAFE_NO_PAD.encode("notanumber:id"),
            &URL_SAFE_NO_PAD.encode("123:"),
        ] {
            assert_eq!(
                AuditCursor::from_wire(bad),
                Err(AuditCursorError::Malformed),
                "expected rejection for {bad:?}",
            );
        }
    }

    #[test]
    fn query_filters_to_the_named_user_only() {
        let store = MemoryAuditStore::new();
        block_on(store.insert_batch(
            &[
                rec_for(alice(), 100, "cloud.deploy", "a1"),
                rec_for(bob(), 101, "cloud.deploy", "b1"),
                rec_for(PrincipalId::service("kamaji"), 102, "cloud.deploy", "s1"),
                // A camp-subject row is NOT rolled up to the user the camp is
                // bound to — camp and user trails stay distinguishable.
                rec_for(PrincipalId::camp("camp-a"), 103, "cloud.deploy", "c1"),
            ],
            1,
        ))
        .unwrap();

        let page = block_on(
            store.query_by_on_behalf_of(&AuditQuery::new(alice()).unwrap()),
        )
        .unwrap();
        assert_eq!(page.rows.len(), 1);
        assert_eq!(page.rows[0].record.request_id, "a1");
        assert_eq!(page.next_cursor, None);
    }

    #[test]
    fn query_returns_newest_first_and_honours_since_and_method_prefix() {
        let store = MemoryAuditStore::new();
        block_on(store.insert_batch(
            &[
                rec_for(alice(), 100, "cloud.deploy.start", "old-deploy"),
                rec_for(alice(), 200, "board.write", "new-other"),
                rec_for(alice(), 300, "cloud.deploy.finish", "new-deploy"),
            ],
            1,
        ))
        .unwrap();

        let all = block_on(
            store.query_by_on_behalf_of(&AuditQuery::new(alice()).unwrap()),
        )
        .unwrap();
        let order: Vec<&str> = all
            .rows
            .iter()
            .map(|r| r.record.request_id.as_str())
            .collect();
        assert_eq!(order, ["new-deploy", "new-other", "old-deploy"]);

        // since is an INCLUSIVE lower bound on record.at.
        let since = block_on(store.query_by_on_behalf_of(
            &AuditQuery::new(alice()).unwrap().with_since(200),
        ))
        .unwrap();
        let ids: Vec<&str> = since
            .rows
            .iter()
            .map(|r| r.record.request_id.as_str())
            .collect();
        assert_eq!(ids, ["new-deploy", "new-other"]);

        // W127's actual query: "who deployed what".
        let deploys = block_on(store.query_by_on_behalf_of(
            &AuditQuery::new(alice())
                .unwrap()
                .with_method_prefix("cloud.deploy"),
        ))
        .unwrap();
        let ids: Vec<&str> = deploys
            .rows
            .iter()
            .map(|r| r.record.request_id.as_str())
            .collect();
        assert_eq!(ids, ["new-deploy", "old-deploy"]);
    }

    #[test]
    fn cursor_paging_walks_every_row_exactly_once() {
        let store = MemoryAuditStore::new();
        // Deliberately all at the SAME `at`: the tie-break by row id is what
        // makes the order total, and a page boundary landing inside a tie is
        // exactly where an `at`-only cursor would skip or repeat rows.
        let batch: Vec<AuditRecord> = (0..10)
            .map(|i| rec_for(alice(), 500, "cloud.deploy", &format!("rid-{i}")))
            .collect();
        block_on(store.insert_batch(&batch, 1)).unwrap();

        let mut seen = Vec::new();
        let mut cursor = None;
        let mut pages = 0;
        loop {
            let mut q = AuditQuery::new(alice()).unwrap().with_limit(3);
            if let Some(c) = cursor {
                q = q.with_cursor(c);
            }
            let page = block_on(store.query_by_on_behalf_of(&q)).unwrap();
            pages += 1;
            assert!(pages <= 5, "paging failed to terminate");
            seen.extend(page.rows.iter().map(|r| r.record.request_id.clone()));
            match page.next_cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
        // 10 rows at limit 3 → 4 pages, and the last page (1 row) reports no
        // next_cursor rather than costing a fifth, empty round-trip.
        assert_eq!(pages, 4);
        assert_eq!(seen.len(), 10, "every row returned exactly once: {seen:?}");
        let unique: std::collections::HashSet<_> = seen.iter().collect();
        assert_eq!(unique.len(), 10, "no row repeated across pages");
    }

    #[test]
    fn rows_appended_during_paging_do_not_shift_the_rows_behind_the_cursor() {
        // The append-only property keyset pagination buys us: an offset-based
        // pager would re-show a row here.
        let store = MemoryAuditStore::new();
        block_on(store.insert_batch(
            &[
                rec_for(alice(), 100, "m", "oldest"),
                rec_for(alice(), 200, "m", "middle"),
                rec_for(alice(), 300, "m", "newest"),
            ],
            1,
        ))
        .unwrap();

        let first = block_on(store.query_by_on_behalf_of(
            &AuditQuery::new(alice()).unwrap().with_limit(1),
        ))
        .unwrap();
        assert_eq!(first.rows[0].record.request_id, "newest");
        let cursor = first.next_cursor.expect("more rows remain");

        // Kamaji forwards a fresh, newer batch mid-page.
        block_on(store.insert_batch(&[rec_for(alice(), 400, "m", "arrived-later")], 2))
            .unwrap();

        let second = block_on(store.query_by_on_behalf_of(
            &AuditQuery::new(alice())
                .unwrap()
                .with_limit(1)
                .with_cursor(cursor),
        ))
        .unwrap();
        assert_eq!(
            second.rows[0].record.request_id, "middle",
            "the newly-appended row must not push 'middle' off this page",
        );
    }

    #[test]
    fn query_on_an_empty_store_is_an_empty_terminal_page() {
        let store = MemoryAuditStore::new();
        let page = block_on(
            store.query_by_on_behalf_of(&AuditQuery::new(alice()).unwrap()),
        )
        .unwrap();
        assert!(page.rows.is_empty());
        assert_eq!(page.next_cursor, None);
    }
}
