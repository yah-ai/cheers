//! Centralized audit table — the [`AuditStore`] trait.
//!
//! Cheers's audit table is the durable, queryable copy of every MCP-mediated
//! action constable observes on its host. Constable retains a local JSONL as
//! the source of truth and forwards batches here via `POST /audit/ingest`;
//! cheers's responsibility ends at "accepted and durable on cheers's side"
//! (see `.yah/docs/working/mcp-auth-and-ownership.md` §Audit ingest).
//!
//! Append-only. There is no in-place edit or delete — the only writes are
//! [`AuditStore::insert_batch`]. Reads (paged by `on_behalf_of`) land in F14
//! atop this same trait.
//!
//! Record shape per W159 §Audit journal: `{ at, sub, act, camp_id, aud,
//! method, scope, result, request_id }`. The wire and storage shapes match
//! one-to-one — cheers doesn't repackage what constable sends, it just
//! durably appends. The only field cheers contributes is the row `id` and
//! the `ingested_at` server timestamp.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use cheers_core::{Actor, PrincipalId, Scope, StoreError};

/// Why an [`AuditRecord`] failed validation before reaching the store.
///
/// The HTTP layer surfaces these as `400 audit_invalid`. They are the
/// "forbidden shape" the F13 verify item calls out — a malformed batch is
/// rejected wholesale so constable's bounded-backoff retry sees a clean
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
    /// Unix-seconds timestamp the action happened (constable's local clock).
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
    /// — constable supplies a stable string per call shape.
    pub method: String,
    /// Scope list the call presented. Stored as a typed `Vec<Scope>` so a
    /// future wildcard or unknown-scope ingest is rejected at parse time
    /// (per composition rule 1 — no wildcards on the wire).
    #[serde(default)]
    pub scope: Vec<Scope>,
    /// Outcome string constable produced (`allow` | `deny` | `error` is the
    /// usual taxonomy, but cheers does not constrain it — see audit-reader
    /// docs in F14 for the canonical vocabulary). Cheers is durable storage,
    /// not the source of result semantics.
    pub result: String,
    /// Correlator into constable's local JSONL — same id appears in both
    /// places so an operator can match a cheers row to constable's source.
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
    /// Distinct from `record.at` (constable's clock) — having both lets an
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

/// Append-only persistence for audit records.
///
/// Only one mutation method — [`insert_batch`](Self::insert_batch). A batch
/// is rejected wholesale if any record fails [`AuditRecord::validate`]; no
/// partial commits, so constable's retry-with-backoff sees a clean 4xx.
///
/// Read APIs (paged by `on_behalf_of` + filters) land alongside F14.
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
            "https://constable.example",
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
}
