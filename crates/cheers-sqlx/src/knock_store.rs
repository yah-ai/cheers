//! [`KnockStore`] over sqlx (migration 0017; R734-F4).
//!
//! One SQL text serves both backends: it is written with positional `?` and
//! numbered for Postgres by [`numbered`]. The bounded writes (the pending cap,
//! an offer's `max_uses`) are conditional statements inside one transaction,
//! and each holds exactly under concurrent writers on both backends: SQLite
//! serializes them on its writer lock, and on Postgres the transaction first
//! takes a lock that every competing writer must also take — the offer row
//! (`FOR UPDATE`) for a redemption, and a transaction-scoped advisory lock on
//! the resource for a knock, including one that replaces its own pending knock.
//! Racing writers therefore count after one another, never past the bound.

use async_trait::async_trait;
use cheers_core::{PrincipalId, StoreError, UserId};
use cheers_server::knock::{Admission, KnockStore, PendingKnock, Queued, Redeemed, StoredOffer};

use crate::error::map_sqlx_error;

#[cfg(feature = "pg")]
pub use pg::PgKnockStore;
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteKnockStore;

const LAPSE: &str = "DELETE FROM pending_knocks WHERE resource_kind = ? AND resource_id = ? AND expires_at <= ?";
const HAD: &str = "SELECT COUNT(*) FROM pending_knocks WHERE resource_kind = ? AND resource_id = ? AND requester = ?";
const DROP_OWN: &str = "DELETE FROM pending_knocks WHERE resource_kind = ? AND resource_id = ? AND requester = ? \
     AND (SELECT COUNT(*) FROM pending_knocks WHERE resource_kind = ? AND resource_id = ? AND requester <> ?) < ?";
const QUEUE: &str = "INSERT INTO pending_knocks \
     (id, resource_kind, resource_id, requester, relation, label, requester_user, renews, token, created_at, expires_at) \
     SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? \
     WHERE (SELECT COUNT(*) FROM pending_knocks WHERE resource_kind = ? AND resource_id = ? AND requester <> ?) < ?";
const QUEUED: &str = "SELECT COUNT(*) FROM pending_knocks WHERE id = ?";
const KNOCK_COLUMNS: &str =
    "id, resource_kind, resource_id, requester, relation, label, requester_user, renews, token, created_at, expires_at";
const OFFER_COLUMNS: &str = "jti, resource_kind, resource_id, relation, created_by, max_uses, created_at, exp";
const PUT_OFFER: &str = "INSERT INTO offers (jti, resource_kind, resource_id, relation, created_by, max_uses, created_at, exp) \
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
const REDEEMED_BY: &str = "SELECT COUNT(*) FROM offer_redemptions WHERE offer_jti = ? AND redeemer = ?";
const REDEEM: &str = "INSERT INTO offer_redemptions (offer_jti, redeemer, redeemed_at) SELECT ?, ?, ? \
     WHERE EXISTS (SELECT 1 FROM offers WHERE jti = ? AND exp > ?) \
     AND (SELECT COUNT(*) FROM offer_redemptions WHERE offer_jti = ?) < (SELECT max_uses FROM offers WHERE jti = ?) \
     ON CONFLICT (offer_jti, redeemer) DO NOTHING";
/// Postgres only: serialize a redemption against every other on the same offer.
#[cfg_attr(not(feature = "pg"), allow(dead_code))]
const PG_LOCK_OFFER: &str = "SELECT 1 FROM offers WHERE jti = $1 FOR UPDATE";
/// Postgres only: serialize a knock against every other on the same resource
/// (there is no per-resource row to lock).
#[cfg_attr(not(feature = "pg"), allow(dead_code))]
const PG_LOCK_RESOURCE: &str = "SELECT pg_advisory_xact_lock(hashtextextended($1 || ':' || $2, 0))";
const ADMISSION: &str = "SELECT ownership_id, refusal FROM admissions WHERE jti = ?";
const RECORD: &str = "INSERT INTO admissions (jti, ownership_id, refusal, recorded_at) VALUES (?, ?, ?, ?) \
     ON CONFLICT (jti) DO NOTHING";

/// `?` → `$1, $2, …` for Postgres.
#[cfg_attr(not(feature = "pg"), allow(dead_code))]
fn numbered(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len() + 16);
    let mut n = 0;
    for c in sql.chars() {
        if c == '?' {
            n += 1;
            out.push_str(&format!("${n}"));
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg_attr(not(feature = "sqlite"), allow(dead_code))]
fn verbatim(sql: &str) -> String {
    sql.to_owned()
}

fn pid(s: String, column: &str) -> Result<PrincipalId, StoreError> {
    s.parse().map_err(|e| StoreError::Backend(format!("invalid {column} principal in knock row: {e}")))
}

fn cap_i64(cap: usize) -> i64 {
    i64::try_from(cap).unwrap_or(i64::MAX)
}

fn admission_from(ownership_id: Option<String>, refusal: Option<String>) -> Result<Admission, StoreError> {
    match (ownership_id, refusal) {
        (Some(ownership_id), None) => Ok(Admission::Accepted { ownership_id }),
        (None, Some(refusal)) => Ok(Admission::Refused { refusal }),
        _ => Err(StoreError::Backend("admission row with both or neither outcome".into())),
    }
}

fn admission_columns(a: &Admission) -> (Option<&str>, Option<&str>) {
    match a {
        Admission::Accepted { ownership_id } => (Some(ownership_id), None),
        Admission::Refused { refusal } => (None, Some(refusal)),
    }
}

macro_rules! knock_store {
    ($store:ident, $pool:ty, $row:ty, $sql:expr, $lock_resource:expr, $lock_offer:expr) => {
        /// [`KnockStore`] over this backend.
        #[derive(Debug, Clone)]
        pub struct $store {
            pool: $pool,
        }

        impl $store {
            pub fn new(pool: $pool) -> Self {
                Self { pool }
            }
        }

        fn knock_from(row: $row) -> Result<PendingKnock, StoreError> {
            Ok(PendingKnock {
                id: row.get("id"),
                resource_kind: row.get("resource_kind"),
                resource_id: row.get("resource_id"),
                requester: pid(row.get("requester"), "requester")?,
                relation: row.get("relation"),
                label: row.get("label"),
                requester_user: row.get::<Option<String>, _>("requester_user").map(UserId::new),
                renews: row.get("renews"),
                token: row.get("token"),
                created_at: row.get("created_at"),
                expires_at: row.get("expires_at"),
            })
        }

        fn offer_from(row: $row) -> Result<StoredOffer, StoreError> {
            let max_uses: i64 = row.get("max_uses");
            Ok(StoredOffer {
                jti: row.get("jti"),
                resource_kind: row.get("resource_kind"),
                resource_id: row.get("resource_id"),
                relation: row.get("relation"),
                created_by: pid(row.get("created_by"), "created_by")?,
                max_uses: u32::try_from(max_uses).map_err(|_| StoreError::Backend(format!("bad max_uses {max_uses}")))?,
                created_at: row.get("created_at"),
                exp: row.get("exp"),
            })
        }

        #[async_trait]
        impl KnockStore for $store {
            async fn queue_knock(&self, k: &PendingKnock, cap: usize, now: i64) -> Result<Queued, StoreError> {
                let requester = k.requester.to_string();
                let user = k.requester_user.as_ref().map(|u| u.as_str().to_owned());
                let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
                if let Some(lock) = $lock_resource {
                    sqlx::query(lock)
                        .bind(&k.resource_kind)
                        .bind(&k.resource_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(map_sqlx_error)?;
                }
                sqlx::query(&$sql(LAPSE))
                    .bind(&k.resource_kind)
                    .bind(&k.resource_id)
                    .bind(now)
                    .execute(&mut *tx)
                    .await
                    .map_err(map_sqlx_error)?;
                let had: i64 = sqlx::query_scalar(&$sql(HAD))
                    .bind(&k.resource_kind)
                    .bind(&k.resource_id)
                    .bind(&requester)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(map_sqlx_error)?;
                sqlx::query(&$sql(DROP_OWN))
                    .bind(&k.resource_kind)
                    .bind(&k.resource_id)
                    .bind(&requester)
                    .bind(&k.resource_kind)
                    .bind(&k.resource_id)
                    .bind(&requester)
                    .bind(cap_i64(cap))
                    .execute(&mut *tx)
                    .await
                    .map_err(map_sqlx_error)?;
                sqlx::query(&$sql(QUEUE))
                    .bind(&k.id)
                    .bind(&k.resource_kind)
                    .bind(&k.resource_id)
                    .bind(&requester)
                    .bind(&k.relation)
                    .bind(&k.label)
                    .bind(user.as_deref())
                    .bind(k.renews.as_deref())
                    .bind(&k.token)
                    .bind(k.created_at)
                    .bind(k.expires_at)
                    .bind(&k.resource_kind)
                    .bind(&k.resource_id)
                    .bind(&requester)
                    .bind(cap_i64(cap))
                    .execute(&mut *tx)
                    .await
                    .map_err(map_sqlx_error)?;
                let queued: i64 = sqlx::query_scalar(&$sql(QUEUED))
                    .bind(&k.id)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(map_sqlx_error)?;
                tx.commit().await.map_err(map_sqlx_error)?;
                Ok(match (queued, had) {
                    (0, _) => Queued::Full,
                    (_, 0) => Queued::Queued,
                    _ => Queued::Replaced,
                })
            }

            async fn pending_knocks(&self, kind: &str, id: &str, now: i64) -> Result<Vec<PendingKnock>, StoreError> {
                let sql = format!(
                    "SELECT {KNOCK_COLUMNS} FROM pending_knocks \
                     WHERE resource_kind = ? AND resource_id = ? AND expires_at > ? ORDER BY created_at, id"
                );
                let rows = sqlx::query(&$sql(&sql))
                    .bind(kind)
                    .bind(id)
                    .bind(now)
                    .fetch_all(&self.pool)
                    .await
                    .map_err(map_sqlx_error)?;
                rows.into_iter().map(knock_from).collect()
            }

            async fn pending_knock(&self, id: &str, now: i64) -> Result<Option<PendingKnock>, StoreError> {
                let sql = format!("SELECT {KNOCK_COLUMNS} FROM pending_knocks WHERE id = ? AND expires_at > ?");
                let row = sqlx::query(&$sql(&sql))
                    .bind(id)
                    .bind(now)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(map_sqlx_error)?;
                row.map(knock_from).transpose()
            }

            async fn drop_knock(&self, id: &str) -> Result<(), StoreError> {
                sqlx::query(&$sql("DELETE FROM pending_knocks WHERE id = ?"))
                    .bind(id)
                    .execute(&self.pool)
                    .await
                    .map_err(map_sqlx_error)?;
                Ok(())
            }

            async fn put_offer(&self, o: &StoredOffer) -> Result<(), StoreError> {
                sqlx::query(&$sql(PUT_OFFER))
                    .bind(&o.jti)
                    .bind(&o.resource_kind)
                    .bind(&o.resource_id)
                    .bind(&o.relation)
                    .bind(o.created_by.to_string())
                    .bind(i64::from(o.max_uses))
                    .bind(o.created_at)
                    .bind(o.exp)
                    .execute(&self.pool)
                    .await
                    .map_err(map_sqlx_error)?;
                Ok(())
            }

            async fn redeem_offer(&self, jti: &str, redeemer: &PrincipalId, now: i64) -> Result<Redeemed, StoreError> {
                let who = redeemer.to_string();
                let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
                if let Some(lock) = $lock_offer {
                    sqlx::query(lock).bind(jti).execute(&mut *tx).await.map_err(map_sqlx_error)?;
                }
                let sql = format!("SELECT {OFFER_COLUMNS} FROM offers WHERE jti = ?");
                let Some(row) = sqlx::query(&$sql(&sql)).bind(jti).fetch_optional(&mut *tx).await.map_err(map_sqlx_error)? else {
                    return Ok(Redeemed::Unknown);
                };
                let offer = offer_from(row)?;
                let before: i64 = sqlx::query_scalar(&$sql(REDEEMED_BY))
                    .bind(jti)
                    .bind(&who)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(map_sqlx_error)?;
                if before > 0 {
                    return Ok(Redeemed::Again(offer));
                }
                let took = sqlx::query(&$sql(REDEEM))
                    .bind(jti)
                    .bind(&who)
                    .bind(now)
                    .bind(jti)
                    .bind(now)
                    .bind(jti)
                    .bind(jti)
                    .execute(&mut *tx)
                    .await
                    .map_err(map_sqlx_error)?
                    .rows_affected();
                tx.commit().await.map_err(map_sqlx_error)?;
                Ok(match took {
                    0 if offer.exp <= now => Redeemed::Expired,
                    0 => Redeemed::Exhausted,
                    _ => Redeemed::Fresh(offer),
                })
            }

            async fn admission(&self, jti: &str) -> Result<Option<Admission>, StoreError> {
                let row = sqlx::query(&$sql(ADMISSION)).bind(jti).fetch_optional(&self.pool).await.map_err(map_sqlx_error)?;
                row.map(|r| admission_from(r.get("ownership_id"), r.get("refusal"))).transpose()
            }

            async fn record_admission(&self, jti: &str, outcome: &Admission, now: i64) -> Result<Admission, StoreError> {
                let (ownership_id, refusal) = admission_columns(outcome);
                sqlx::query(&$sql(RECORD))
                    .bind(jti)
                    .bind(ownership_id)
                    .bind(refusal)
                    .bind(now)
                    .execute(&self.pool)
                    .await
                    .map_err(map_sqlx_error)?;
                self.admission(jti)
                    .await?
                    .ok_or_else(|| StoreError::Backend(format!("admission {jti} vanished")))
            }
        }
    };
}

#[cfg(feature = "pg")]
mod pg {
    use super::*;
    use sqlx::Row;

    knock_store!(PgKnockStore, sqlx::PgPool, sqlx::postgres::PgRow, numbered, Some(PG_LOCK_RESOURCE), Some(PG_LOCK_OFFER));
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use sqlx::Row;

    knock_store!(SqliteKnockStore, sqlx::SqlitePool, sqlx::sqlite::SqliteRow, verbatim, None::<&str>, None::<&str>);
}
