//! [`KnockStore`] over turso (migration 0017; R734-F4). The bounded writes
//! (the pending cap, an offer's `max_uses`) are conditional statements inside
//! one `BEGIN IMMEDIATE` transaction, so they are atomic.

use std::sync::Arc;

use async_trait::async_trait;
use cheers_core::{PrincipalId, StoreError, UserId};
use cheers_server::knock::{Admission, KnockStore, PendingKnock, Queued, Redeemed, StoredOffer};

use crate::conn::{TursoConn, Unit};
use crate::util::{col, opt_text};

const KNOCK_COLUMNS: &str =
    "id, resource_kind, resource_id, requester, relation, label, requester_user, renews, token, created_at, expires_at";
const OFFER_COLUMNS: &str = "jti, resource_kind, resource_id, relation, created_by, max_uses, created_at, exp";
const OTHERS_UNDER_CAP: &str =
    "(SELECT COUNT(*) FROM pending_knocks WHERE resource_kind = ? AND resource_id = ? AND requester <> ?) < ?";

/// [`KnockStore`] over a turso connection.
#[derive(Debug, Clone)]
pub struct TursoKnockStore {
    conn: Arc<TursoConn>,
}

impl TursoKnockStore {
    pub fn new(conn: Arc<TursoConn>) -> Self {
        Self { conn }
    }
}

fn pid(s: String, column: &str) -> Result<PrincipalId, StoreError> {
    s.parse().map_err(|e| StoreError::Backend(format!("invalid {column} principal in knock row: {e}")))
}

fn count(rows: Option<&Vec<turso::Row>>) -> Result<i64, StoreError> {
    let row = rows.and_then(|r| r.first()).ok_or_else(|| StoreError::Backend("COUNT returned no row".into()))?;
    col::<i64>(row, 0, "count")
}

fn knock_from(row: &turso::Row) -> Result<PendingKnock, StoreError> {
    Ok(PendingKnock {
        id: col(row, 0, "id")?,
        resource_kind: col(row, 1, "resource_kind")?,
        resource_id: col(row, 2, "resource_id")?,
        requester: pid(col(row, 3, "requester")?, "requester")?,
        relation: col(row, 4, "relation")?,
        label: col(row, 5, "label")?,
        requester_user: col::<Option<String>>(row, 6, "requester_user")?.map(UserId::new),
        renews: col(row, 7, "renews")?,
        token: col(row, 8, "token")?,
        created_at: col(row, 9, "created_at")?,
        expires_at: col(row, 10, "expires_at")?,
    })
}

fn offer_from(row: &turso::Row) -> Result<StoredOffer, StoreError> {
    let max_uses: i64 = col(row, 5, "max_uses")?;
    Ok(StoredOffer {
        jti: col(row, 0, "jti")?,
        resource_kind: col(row, 1, "resource_kind")?,
        resource_id: col(row, 2, "resource_id")?,
        relation: col(row, 3, "relation")?,
        created_by: pid(col(row, 4, "created_by")?, "created_by")?,
        max_uses: u32::try_from(max_uses).map_err(|_| StoreError::Backend(format!("bad max_uses {max_uses}")))?,
        created_at: col(row, 6, "created_at")?,
        exp: col(row, 7, "exp")?,
    })
}

#[async_trait]
impl KnockStore for TursoKnockStore {
    async fn queue_knock(&self, k: &PendingKnock, cap: usize, now: i64) -> Result<Queued, StoreError> {
        let requester = k.requester.to_string();
        let cap = i64::try_from(cap).unwrap_or(i64::MAX);
        let under = || -> Vec<turso::Value> {
            vec![k.resource_kind.as_str().into(), k.resource_id.as_str().into(), requester.as_str().into(), cap.into()]
        };
        let mut drop_params: Vec<turso::Value> =
            vec![k.resource_kind.as_str().into(), k.resource_id.as_str().into(), requester.as_str().into()];
        drop_params.extend(under());
        let mut queue_params: Vec<turso::Value> = vec![
            k.id.as_str().into(),
            k.resource_kind.as_str().into(),
            k.resource_id.as_str().into(),
            requester.as_str().into(),
            k.relation.as_str().into(),
            k.label.as_str().into(),
            opt_text(k.requester_user.as_ref().map(|u| u.as_str())),
            opt_text(k.renews.as_deref()),
            k.token.as_str().into(),
            k.created_at.into(),
            k.expires_at.into(),
        ];
        queue_params.extend(under());
        let read = self
            .conn
            .transaction_rows(vec![
                Unit::stmt(
                    "DELETE FROM pending_knocks WHERE resource_kind = ? AND resource_id = ? AND expires_at <= ?",
                    vec![k.resource_kind.as_str().into(), k.resource_id.as_str().into(), now.into()],
                ),
                Unit::query(
                    "SELECT COUNT(*) FROM pending_knocks WHERE resource_kind = ? AND resource_id = ? AND requester = ?",
                    vec![k.resource_kind.as_str().into(), k.resource_id.as_str().into(), requester.as_str().into()],
                ),
                Unit::stmt(
                    format!(
                        "DELETE FROM pending_knocks WHERE resource_kind = ? AND resource_id = ? AND requester = ? AND {OTHERS_UNDER_CAP}"
                    ),
                    drop_params,
                ),
                Unit::stmt(
                    format!(
                        "INSERT INTO pending_knocks ({KNOCK_COLUMNS}) SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE {OTHERS_UNDER_CAP}"
                    ),
                    queue_params,
                ),
                Unit::query("SELECT COUNT(*) FROM pending_knocks WHERE id = ?", vec![k.id.as_str().into()]),
            ])
            .await?;
        Ok(match (count(read.get(1))?, count(read.first())?) {
            (0, _) => Queued::Full,
            (_, 0) => Queued::Queued,
            _ => Queued::Replaced,
        })
    }

    async fn pending_knocks(&self, kind: &str, id: &str, now: i64) -> Result<Vec<PendingKnock>, StoreError> {
        let rows = self
            .conn
            .query(
                &format!(
                    "SELECT {KNOCK_COLUMNS} FROM pending_knocks \
                     WHERE resource_kind = ? AND resource_id = ? AND expires_at > ? ORDER BY created_at, id"
                ),
                vec![kind.into(), id.into(), now.into()],
            )
            .await?;
        rows.iter().map(knock_from).collect()
    }

    async fn pending_knock(&self, id: &str, now: i64) -> Result<Option<PendingKnock>, StoreError> {
        let row = self
            .conn
            .query_one(
                &format!("SELECT {KNOCK_COLUMNS} FROM pending_knocks WHERE id = ? AND expires_at > ?"),
                vec![id.into(), now.into()],
            )
            .await?;
        row.as_ref().map(knock_from).transpose()
    }

    async fn drop_knock(&self, id: &str) -> Result<(), StoreError> {
        self.conn.execute("DELETE FROM pending_knocks WHERE id = ?", vec![id.into()]).await?;
        Ok(())
    }

    async fn put_offer(&self, o: &StoredOffer) -> Result<(), StoreError> {
        self.conn
            .execute(
                &format!("INSERT INTO offers ({OFFER_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"),
                vec![
                    o.jti.as_str().into(),
                    o.resource_kind.as_str().into(),
                    o.resource_id.as_str().into(),
                    o.relation.as_str().into(),
                    o.created_by.to_string().into(),
                    i64::from(o.max_uses).into(),
                    o.created_at.into(),
                    o.exp.into(),
                ],
            )
            .await?;
        Ok(())
    }

    async fn redeem_offer(&self, jti: &str, redeemer: &PrincipalId, now: i64) -> Result<Redeemed, StoreError> {
        let who = redeemer.to_string();
        let by = || vec![jti.into(), who.as_str().into()];
        let read = self
            .conn
            .transaction_rows(vec![
                Unit::query(format!("SELECT {OFFER_COLUMNS} FROM offers WHERE jti = ?"), vec![jti.into()]),
                Unit::query("SELECT COUNT(*) FROM offer_redemptions WHERE offer_jti = ? AND redeemer = ?", by()),
                Unit::stmt(
                    "INSERT INTO offer_redemptions (offer_jti, redeemer, redeemed_at) SELECT ?, ?, ? \
                     WHERE EXISTS (SELECT 1 FROM offers WHERE jti = ? AND exp > ?) \
                     AND (SELECT COUNT(*) FROM offer_redemptions WHERE offer_jti = ?) < (SELECT max_uses FROM offers WHERE jti = ?) \
                     ON CONFLICT (offer_jti, redeemer) DO NOTHING",
                    vec![jti.into(), who.as_str().into(), now.into(), jti.into(), now.into(), jti.into(), jti.into()],
                ),
                Unit::query("SELECT COUNT(*) FROM offer_redemptions WHERE offer_jti = ? AND redeemer = ?", by()),
            ])
            .await?;
        let Some(row) = read.first().and_then(|r| r.first()) else {
            return Ok(Redeemed::Unknown);
        };
        let offer = offer_from(row)?;
        Ok(match (count(read.get(1))?, count(read.get(2))?) {
            (1.., _) => Redeemed::Again(offer),
            (_, 1..) => Redeemed::Fresh(offer),
            _ if offer.exp <= now => Redeemed::Expired,
            _ => Redeemed::Exhausted,
        })
    }

    async fn admission(&self, jti: &str) -> Result<Option<Admission>, StoreError> {
        let Some(row) = self
            .conn
            .query_one("SELECT ownership_id, refusal FROM admissions WHERE jti = ?", vec![jti.into()])
            .await?
        else {
            return Ok(None);
        };
        match (col::<Option<String>>(&row, 0, "ownership_id")?, col::<Option<String>>(&row, 1, "refusal")?) {
            (Some(ownership_id), None) => Ok(Some(Admission::Accepted { ownership_id })),
            (None, Some(refusal)) => Ok(Some(Admission::Refused { refusal })),
            _ => Err(StoreError::Backend("admission row with both or neither outcome".into())),
        }
    }

    async fn record_admission(&self, jti: &str, outcome: &Admission, now: i64) -> Result<Admission, StoreError> {
        let (ownership_id, refusal) = match outcome {
            Admission::Accepted { ownership_id } => (Some(ownership_id.as_str()), None),
            Admission::Refused { refusal } => (None, Some(refusal.as_str())),
        };
        self.conn
            .execute(
                "INSERT INTO admissions (jti, ownership_id, refusal, recorded_at) VALUES (?, ?, ?, ?) ON CONFLICT (jti) DO NOTHING",
                vec![jti.into(), opt_text(ownership_id), opt_text(refusal), now.into()],
            )
            .await?;
        self.admission(jti).await?.ok_or_else(|| StoreError::Backend(format!("admission {jti} vanished")))
    }
}
