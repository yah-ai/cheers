//! [`RevocationWriter`] + [`RevocationReader`] over the in-process engine.
//!
//! One struct implements both halves, because in the cell-hosted model they
//! are the same process: the account cell writes the kill-list and answers
//! `is_revoked` for it. There is no edge/origin split to arrange here — the
//! engine's exclusive file lock means a separate edge process could not open
//! this database even if you wanted it to. An edge that needs its own copy
//! takes one over the capability surface (or runs `cheers-redis`), it does not
//! open the file.
//!
//! Schema (migration 0010, R732-F6): entries keyed on `(kind, subject,
//! resource_kind, resource_id)` — see [`revoked_columns`] — plus the one-row
//! `revocation_epoch`. Every write that changes the entries advances the epoch
//! in the same transaction; [`RevocationWriter::snapshot`] reads both in one
//! statement.

use std::sync::Arc;

use async_trait::async_trait;
use cheers_core::{DeviceId, PrincipalId, Revoked, StoreError};
use cheers_server::{
    epoch_from_sql, revoked_columns, revoked_from_columns, RevocationSnapshot, RevocationWriter,
};
use cheers_verify::RevocationReader;
use turso::Value;

use crate::conn::{ReadOnlyConn, TursoConn, Unit};
use crate::util::{col, now};

const HELD_SQL: &str = "SELECT bound, expires_at FROM revocations
     WHERE kind = ? AND subject = ? AND resource_kind = ? AND resource_id = ?";

const ADVANCE_EPOCH_SQL: &str = "UPDATE revocation_epoch SET epoch = MAX(epoch + 1, ?)";

/// The upsert keeps the larger bound; see cheers-sqlx's `RAISES_SQL` for why
/// one `WHERE` covers every kind.
const UPSERT_SQL: &str = "INSERT INTO revocations (kind, subject, resource_kind, resource_id, bound, expires_at, revoked_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (kind, subject, resource_kind, resource_id)
     DO UPDATE SET bound = excluded.bound, expires_at = excluded.expires_at, revoked_at = excluded.revoked_at
     WHERE excluded.bound > revocations.bound
        OR (revocations.expires_at IS NOT NULL
            AND (excluded.expires_at IS NULL OR excluded.expires_at > revocations.expires_at))";

fn key_params(entry: &Revoked) -> Vec<Value> {
    let c = revoked_columns(entry);
    vec![c.kind.into(), c.subject.into_owned().into(), c.resource_kind.into(), c.resource_id.into()]
}

fn opt(v: Option<i64>) -> Value {
    v.map_or(Value::Null, Value::from)
}

/// The held `(bound, expires_at)` of `probe`'s identity.
async fn held(conn: &impl HeldQuery, probe: &Revoked) -> Result<Option<(Option<i64>, Option<i64>)>, StoreError> {
    let Some(row) = conn.held_row(key_params(probe)).await? else {
        return Ok(None);
    };
    Ok(Some((col::<Option<i64>>(&row, 0, "bound")?, col::<Option<i64>>(&row, 1, "expires_at")?)))
}

/// `true` if a held device / membership bound masks `at` (`at < bound`).
fn masks(held: Option<(Option<i64>, Option<i64>)>, at: u64) -> bool {
    held.and_then(|(bound, _)| bound)
        .is_some_and(|bound| u64::try_from(bound).is_ok_and(|bound| at < bound))
}

/// The one read both halves make, over either connection kind.
#[async_trait]
trait HeldQuery: Sync {
    async fn held_row(&self, params: Vec<Value>) -> Result<Option<turso::Row>, StoreError>;
}

#[async_trait]
impl HeldQuery for TursoConn {
    async fn held_row(&self, params: Vec<Value>) -> Result<Option<turso::Row>, StoreError> {
        self.query_one(HELD_SQL, params).await
    }
}

#[async_trait]
impl HeldQuery for ReadOnlyConn {
    async fn held_row(&self, params: Vec<Value>) -> Result<Option<turso::Row>, StoreError> {
        self.query_one(HELD_SQL, params).await
    }
}

/// The revocation set, both halves.
pub struct TursoRevocationStore {
    conn: Arc<TursoConn>,
}

impl TursoRevocationStore {
    pub fn new(conn: Arc<TursoConn>) -> Self {
        Self { conn }
    }

    pub fn conn(&self) -> &Arc<TursoConn> {
        &self.conn
    }

    /// Hand out a reader that structurally cannot write the kill-list.
    ///
    /// This is the read-capability path: a component that only needs to answer
    /// "is this jti dead?" gets a [`TursoRevocationReader`], which holds a
    /// [`ReadOnlyConn`] and implements [`RevocationReader`] and nothing else.
    pub fn reader(&self) -> TursoRevocationReader {
        TursoRevocationReader {
            conn: ReadOnlyConn::new(self.conn.clone()),
        }
    }

    /// Garbage-collect entries whose `expires_at` is at or before `now`,
    /// advancing the epoch when anything went.
    ///
    /// Call periodically to keep the table bounded. Rows with a NULL
    /// `expires_at` are never collected — that is the "revoked forever"
    /// spelling, and sweeping it would resurrect a dead token.
    pub async fn gc(&self, now: i64) -> Result<u64, StoreError> {
        // `transaction` cannot branch on a statement's row count, so count
        // first and skip the write (and the epoch) when nothing is due.
        let due = self
            .conn
            .query(
                "SELECT 1 FROM revocations WHERE expires_at IS NOT NULL AND expires_at <= ?",
                vec![now.into()],
            )
            .await?
            .len() as u64;
        if due > 0 {
            self.conn
                .transaction(vec![
                    Unit::stmt(
                        "DELETE FROM revocations WHERE expires_at IS NOT NULL AND expires_at <= ?",
                        vec![now.into()],
                    ),
                    Unit::stmt(ADVANCE_EPOCH_SQL, vec![crate::util::now().into()]),
                ])
                .await?;
        }
        Ok(due)
    }
}

impl std::fmt::Debug for TursoRevocationStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TursoRevocationStore").finish_non_exhaustive()
    }
}

#[async_trait]
impl RevocationWriter for TursoRevocationStore {
    async fn revoke(&self, entry: &Revoked) -> Result<(), StoreError> {
        // `transaction` cannot branch on a statement's row count, so read the
        // held bound first and skip the write (and the epoch) unless this
        // inserts the identity or raises its bound. Two racing raises may both
        // advance the epoch — two epochs with equal contents, which replicas
        // handle like any other; the upsert itself still keeps the max.
        if let Some((bound, expires_at)) = held(self.conn.as_ref(), entry).await? {
            let c = revoked_columns(entry);
            let raises = match (c.bound, bound) {
                (Some(new), Some(old)) => new > old,
                (Some(_), None) => true,
                (None, _) => expires_at.is_some() && c.expires_at.is_none_or(|new| expires_at.is_some_and(|old| new > old)),
            };
            if !raises {
                return Ok(());
            }
        }
        let c = revoked_columns(entry);
        let params = vec![
            c.kind.into(),
            c.subject.into_owned().into(),
            c.resource_kind.into(),
            c.resource_id.into(),
            opt(c.bound),
            opt(c.expires_at),
            now().into(),
        ];
        self.conn
            .transaction(vec![
                Unit::stmt(UPSERT_SQL, params),
                Unit::stmt(ADVANCE_EPOCH_SQL, vec![now().into()]),
            ])
            .await
    }

    async fn snapshot(&self) -> Result<RevocationSnapshot, StoreError> {
        // One statement: the epoch and the entries come from the same read.
        // The epoch row always exists, so an empty set is one row of NULLs.
        let rows = self
            .conn
            .query(
                "SELECT e.epoch, r.kind, r.subject, r.resource_kind, r.resource_id, r.bound, r.expires_at
                 FROM revocation_epoch e LEFT JOIN revocations r ON 1 = 1",
                vec![],
            )
            .await?;
        let mut epoch = None;
        let mut revoked = Vec::with_capacity(rows.len());
        for row in &rows {
            epoch = Some(col::<i64>(row, 0, "epoch")?);
            let Some(kind) = col::<Option<String>>(row, 1, "kind")? else {
                continue;
            };
            revoked.push(revoked_from_columns(
                &kind,
                col::<Option<String>>(row, 2, "subject")?.unwrap_or_default(),
                col::<Option<String>>(row, 3, "resource_kind")?.unwrap_or_default(),
                col::<Option<String>>(row, 4, "resource_id")?.unwrap_or_default(),
                col::<Option<i64>>(row, 5, "bound")?,
                col::<Option<i64>>(row, 6, "expires_at")?,
            )?);
        }
        let epoch = epoch.ok_or_else(|| StoreError::Backend("revocation_epoch row missing".into()))?;
        Ok(RevocationSnapshot {
            epoch: epoch_from_sql(epoch)?,
            revoked,
        })
    }
}

#[async_trait]
impl RevocationReader for TursoRevocationStore {
    async fn is_revoked(&self, jti: &str) -> Result<bool, StoreError> {
        Ok(held(self.conn.as_ref(), &Revoked::jti(jti, None)).await?.is_some())
    }

    async fn is_device_revoked(&self, device: &DeviceId, seq: u64) -> Result<bool, StoreError> {
        Ok(masks(held(self.conn.as_ref(), &Revoked::device(device.clone(), 0)).await?, seq))
    }

    async fn is_membership_revoked(
        &self,
        _key: &cheers_core::RevocationKey,
        kind: &str,
        id: &str,
        principal: &PrincipalId,
        snapshot_epoch: u64,
    ) -> Result<bool, StoreError> {
        let probe = Revoked::membership(kind, id, principal.clone(), 0);
        Ok(masks(held(self.conn.as_ref(), &probe).await?, snapshot_epoch))
    }
}

/// The read-only half of the revocation set.
///
/// Constructed via [`TursoRevocationStore::reader`]. It implements
/// [`RevocationReader`] only, and its handle refuses non-read statements — so
/// a component holding one cannot revoke, un-revoke, or garbage-collect,
/// whatever it does with it.
#[derive(Debug, Clone)]
pub struct TursoRevocationReader {
    conn: ReadOnlyConn,
}

#[async_trait]
impl RevocationReader for TursoRevocationReader {
    async fn is_revoked(&self, jti: &str) -> Result<bool, StoreError> {
        Ok(held(&self.conn, &Revoked::jti(jti, None)).await?.is_some())
    }

    async fn is_device_revoked(&self, device: &DeviceId, seq: u64) -> Result<bool, StoreError> {
        Ok(masks(held(&self.conn, &Revoked::device(device.clone(), 0)).await?, seq))
    }

    async fn is_membership_revoked(
        &self,
        _key: &cheers_core::RevocationKey,
        kind: &str,
        id: &str,
        principal: &PrincipalId,
        snapshot_epoch: u64,
    ) -> Result<bool, StoreError> {
        let probe = Revoked::membership(kind, id, principal.clone(), 0);
        Ok(masks(held(&self.conn, &probe).await?, snapshot_epoch))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrate::MIGRATIONS;

    async fn migrated_until(below: i64) -> Arc<TursoConn> {
        let conn = Arc::new(TursoConn::open_in_memory().await.unwrap());
        for m in MIGRATIONS.iter().filter(|m| m.version < below) {
            conn.execute_batch(m.sql).await.unwrap();
        }
        conn
    }

    async fn migrate_from(conn: &TursoConn, from: i64) {
        for m in MIGRATIONS.iter().filter(|m| m.version >= from) {
            conn.execute_batch(m.sql).await.unwrap();
        }
    }

    /// 0010 rebuilds `revocations`; a jti revoked under the old schema must
    /// come through it still revoked, at epoch 0, and the epoch must then
    /// advance on the first write.
    #[tokio::test]
    async fn migration_0010_keeps_legacy_jtis_and_starts_the_epoch() {
        let conn = migrated_until(10).await;
        conn.execute(
            "INSERT INTO revocations (jti, revoked_at) VALUES ('legacy-jti', 10)",
            vec![],
        )
        .await
        .unwrap();
        migrate_from(&conn, 10).await;

        let store = TursoRevocationStore::new(conn);
        assert!(store.is_revoked("legacy-jti").await.unwrap());
        assert!(store.reader().is_revoked("legacy-jti").await.unwrap());
        let snap = store.snapshot().await.unwrap();
        assert_eq!(snap.epoch, 0);
        assert_eq!(snap.revoked, vec![Revoked::jti("legacy-jti", None)]);

        store.revoke(&Revoked::device("phone", 5)).await.unwrap();
        assert!(store.snapshot().await.unwrap().epoch > 0);
        assert!(store.reader().is_device_revoked(&DeviceId::new("phone"), 4).await.unwrap());
    }

    /// 0012 gives legacy device / membership rows (which meant "masks
    /// everything") bound = i64::MAX, and leaves legacy jtis non-lapsing.
    #[tokio::test]
    async fn migration_0012_makes_legacy_rows_fail_closed() {
        let conn = migrated_until(12).await;
        conn.execute_batch(
            "INSERT INTO revocations (kind, subject, revoked_at) VALUES ('jti', 'old-jti', 1);
             INSERT INTO revocations (kind, subject, revoked_at) VALUES ('device', 'phone', 1);
             INSERT INTO revocations (kind, subject, resource_kind, resource_id, revoked_at)
                 VALUES ('membership', 'alice', 'namespace', 'ns-1', 1);",
        )
        .await
        .unwrap();
        migrate_from(&conn, 12).await;

        let store = TursoRevocationStore::new(conn);
        let reader = store.reader();
        assert!(reader.is_revoked("old-jti").await.unwrap());
        assert!(reader.is_device_revoked(&DeviceId::new("phone"), i64::MAX as u64 - 1).await.unwrap());
        assert!(reader
            .is_membership_revoked(&cheers_verify::test_revocation_key("namespace", "ns-1"), "namespace", "ns-1", &PrincipalId::user("alice"), 1 << 62)
            .await
            .unwrap());
        assert_eq!(store.gc(i64::MAX).await.unwrap(), 0, "a legacy jti never lapses");
        let max = i64::MAX as u64;
        let mut snap = store.snapshot().await.unwrap().revoked;
        snap.sort_by(|a, b| a.identity().cmp(&b.identity()));
        assert_eq!(
            snap,
            vec![
                Revoked::jti("old-jti", None),
                Revoked::device("phone", max),
                Revoked::membership("namespace", "ns-1", PrincipalId::user("alice"), max),
            ]
        );
    }

    /// 0015 rewrites a legacy membership subject (a bare user id) into the
    /// principal wire form, and leaves jti / device subjects alone.
    #[tokio::test]
    async fn migration_0015_prefixes_legacy_membership_subjects() {
        let conn = migrated_until(15).await;
        conn.execute_batch(
            "INSERT INTO revocations (kind, subject, revoked_at, bound) VALUES ('device', 'phone', 1, 3);
             INSERT INTO revocations (kind, subject, resource_kind, resource_id, revoked_at, bound)
                 VALUES ('membership', 'alice', 'namespace', 'ns-1', 1, 7);",
        )
        .await
        .unwrap();
        migrate_from(&conn, 15).await;

        let store = TursoRevocationStore::new(conn);
        let mut snap = store.snapshot().await.unwrap().revoked;
        snap.sort_by(|a, b| a.identity().cmp(&b.identity()));
        assert_eq!(
            snap,
            vec![Revoked::device("phone", 3), Revoked::membership("namespace", "ns-1", PrincipalId::user("alice"), 7)]
        );
        let k = cheers_verify::test_revocation_key("namespace", "ns-1");
        assert!(store.reader().is_membership_revoked(&k, "namespace", "ns-1", &PrincipalId::user("alice"), 6).await.unwrap());
    }

    #[tokio::test]
    async fn gc_advances_the_epoch_only_when_it_removes_something() {
        let conn = migrated_until(i64::MAX).await;
        let store = TursoRevocationStore::new(conn);
        store.revoke(&Revoked::jti("short", Some(50))).await.unwrap();
        store.revoke(&Revoked::jti("forever", None)).await.unwrap();
        store.revoke(&Revoked::device("phone", 1)).await.unwrap();
        let before = store.snapshot().await.unwrap().epoch;
        assert_eq!(store.gc(10).await.unwrap(), 0);
        assert_eq!(store.snapshot().await.unwrap().epoch, before);
        assert_eq!(store.gc(100).await.unwrap(), 1);
        let after = store.snapshot().await.unwrap();
        assert!(after.epoch > before);
        assert_eq!(after.revoked.len(), 2);
        assert!(!store.is_revoked("short").await.unwrap());
        assert!(store.is_revoked("forever").await.unwrap());
    }
}
