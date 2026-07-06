//! Embedded-ownership persistence — the [`OwnershipStore`] trait.
//!
//! The table this trait backs is the *source of truth* cheers reads at mint
//! time to fill the [`owns`](cheers_core::Owns) claim on an MCP token. See
//! `.yah/docs/working/mcp-auth-and-ownership.md` §Ownership table for the
//! schema and the W159 trust-layer reasoning behind it.
//!
//! Generic shape — `principal × resource × kind` — so cheers does not grow a
//! per-kind table for every resource type yah adds. The two unconditional
//! invariants are encoded both here (parse-time, via
//! [`OwnershipValidationError`]) and at the SQL CHECK level in the backing
//! schema:
//!
//! - **`granted_by` is always a service principal** (`svc:<id>`). Humans never
//!   appear in `granted_by`; cheers writes the writing service principal's
//!   own `sub` into this column on every POST /ownership.
//! - **`on_behalf_of` (when set) is always a user principal** (`user:<id>`).
//!   Service principals never appear here; for self-grants the field is
//!   `None`.
//!
//! Writes/deletes do not hard-delete — a soft `revoked_at` timestamp marks a
//! row inactive. The cascade revoke for "user U went away" sweeps every row
//! with `on_behalf_of = U` in one update, matching the staleness budget yah
//! accepts on access tokens (the short access-TTL is the bound on
//! propagation).
//!
//! The trait says nothing about authorisation — composition rule (4) (the
//! `ownership:write` scope being grantable to services only) is enforced at
//! the grant API by [`cheers_core::validate_grant`], and at the HTTP layer
//! by checking the bearer token's `scope` list. The store impl just enforces
//! the row invariants.

use async_trait::async_trait;
use cheers_core::{PrincipalId, PrincipalKind, StoreError};
use serde::{Deserialize, Serialize};

/// Why a [`NewOwnership`] failed to validate before reaching the store.
///
/// The SQL CHECK constraints are the same invariants enforced at the DB
/// level — this enum is the Rust-side guard so a misconfigured insert never
/// makes a round-trip to the database to be rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OwnershipValidationError {
    /// `granted_by` must be a service principal — humans never appear in
    /// this column.
    #[error("granted_by must be a service principal; got {0}")]
    GrantedByNotService(PrincipalKind),
    /// `on_behalf_of`, when set, must be a user principal — services never
    /// appear here.
    #[error("on_behalf_of must be a user principal when set; got {0}")]
    OnBehalfOfNotUser(PrincipalKind),
}

/// Input for [`OwnershipStore::insert`]. Constructed via
/// [`NewOwnership::new`] which enforces the `granted_by` / `on_behalf_of`
/// invariants up front.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct NewOwnership {
    pub principal_id: PrincipalId,
    pub resource_kind: String,
    pub resource_id: String,
    pub relationship: String,
    pub granted_by: PrincipalId,
    pub on_behalf_of: Option<PrincipalId>,
}

impl NewOwnership {
    /// Construct + validate. The kind invariants on `granted_by` /
    /// `on_behalf_of` are checked here so an impl never has to.
    pub fn new(
        principal_id: PrincipalId,
        resource_kind: impl Into<String>,
        resource_id: impl Into<String>,
        relationship: impl Into<String>,
        granted_by: PrincipalId,
        on_behalf_of: Option<PrincipalId>,
    ) -> Result<Self, OwnershipValidationError> {
        if granted_by.kind != PrincipalKind::Service {
            return Err(OwnershipValidationError::GrantedByNotService(
                granted_by.kind,
            ));
        }
        if let Some(ref obo) = on_behalf_of {
            if obo.kind != PrincipalKind::User {
                return Err(OwnershipValidationError::OnBehalfOfNotUser(obo.kind));
            }
        }
        Ok(Self {
            principal_id,
            resource_kind: resource_kind.into(),
            resource_id: resource_id.into(),
            relationship: relationship.into(),
            granted_by,
            on_behalf_of,
        })
    }
}

/// One row in the ownership table.
///
/// `id` is an opaque 128-bit identifier (UUIDv4 in the cheers-sqlx impls,
/// matching the existing `mint_user_id` shape — the doc spec calls for "ULID"
/// but the concrete crypto-random 128-bit shape is what's load-bearing, not
/// the encoding).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct OwnershipRow {
    pub id: String,
    pub principal_id: PrincipalId,
    pub resource_kind: String,
    pub resource_id: String,
    pub relationship: String,
    pub granted_by: PrincipalId,
    pub on_behalf_of: Option<PrincipalId>,
    pub granted_at: i64,
    /// `None` while the row is live; the unix-second timestamp the soft delete
    /// landed on once revoked. Rows with `Some(_)` are excluded from
    /// [`list_for_principal`](OwnershipStore::list_for_principal).
    pub revoked_at: Option<i64>,
}

impl OwnershipRow {
    /// Build a row from its constituent fields. Use from `OwnershipStore`
    /// impls that need to assemble a row from a SQL query result.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        principal_id: PrincipalId,
        resource_kind: String,
        resource_id: String,
        relationship: String,
        granted_by: PrincipalId,
        on_behalf_of: Option<PrincipalId>,
        granted_at: i64,
        revoked_at: Option<i64>,
    ) -> Self {
        Self {
            id,
            principal_id,
            resource_kind,
            resource_id,
            relationship,
            granted_by,
            on_behalf_of,
            granted_at,
            revoked_at,
        }
    }

    /// `true` iff the row has been soft-revoked.
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }
}

/// Persistence for the ownership table — the embedded-ownership source of
/// truth cheers reads at mint time.
///
/// All time arguments are unix seconds, signed — same as
/// [`Claims::issued_at`](cheers_core::Claims) and the refresh-token rows.
#[async_trait]
pub trait OwnershipStore: Send + Sync {
    /// Insert a fresh row. The impl mints `id` and sets `granted_at = now`;
    /// the returned [`OwnershipRow`] carries both. `revoked_at` is `None`.
    async fn insert(
        &self,
        ownership: &NewOwnership,
        now: i64,
    ) -> Result<OwnershipRow, StoreError>;

    /// Look up a row by id. `None` if no such row exists (live or revoked).
    async fn get(&self, id: &str) -> Result<Option<OwnershipRow>, StoreError>;

    /// Soft-delete by id — sets `revoked_at = now` if the row is live; no-op
    /// when already revoked. Returns [`StoreError::NotFound`] when the id is
    /// unknown.
    async fn revoke_by_id(&self, id: &str, now: i64) -> Result<(), StoreError>;

    /// Cascading revoke — sweep `revoked_at = now` across every live row whose
    /// `on_behalf_of` matches the supplied user principal. Returns the count
    /// of rows newly revoked.
    ///
    /// Soundness rests on the column invariant: `on_behalf_of` is always a
    /// user principal (`user:<id>`) or `None`. A non-user principal here
    /// matches nothing and returns `0` — the impl does NOT need to check
    /// `user.kind` itself; the SQL `WHERE on_behalf_of = $1` is precise.
    async fn revoke_by_on_behalf_of(
        &self,
        user: &PrincipalId,
        now: i64,
    ) -> Result<u64, StoreError>;

    /// Live (non-revoked) rows held by `principal`, in unspecified order.
    async fn list_for_principal(
        &self,
        principal: &PrincipalId,
    ) -> Result<Vec<OwnershipRow>, StoreError>;

    /// Live (non-revoked) rows over one resource — every principal currently
    /// holding a relationship on `(resource_kind, resource_id)`, in
    /// unspecified order.
    ///
    /// Exists for eviction-parity sweeps (R593-F9, W268 Q6): when a device
    /// (`resource_kind = "node"`) is re-enrolled under a *different* owner —
    /// the device changed hands — the enrollment writer must find and revoke
    /// the previous owner's still-live row, which `list_for_principal` cannot
    /// see (it is keyed on the *old* principal, which the new ceremony does
    /// not know).
    async fn list_for_resource(
        &self,
        resource_kind: &str,
        resource_id: &str,
    ) -> Result<Vec<OwnershipRow>, StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(id: &str) -> PrincipalId {
        PrincipalId::user(id)
    }
    fn svc(id: &str) -> PrincipalId {
        PrincipalId::service(id)
    }
    fn camp(id: &str) -> PrincipalId {
        PrincipalId::camp(id)
    }

    #[test]
    fn new_ownership_accepts_service_granted_by_and_user_on_behalf_of() {
        let n = NewOwnership::new(
            camp("c-1"),
            "service",
            "svc-abc",
            "owns",
            svc("yubaba"),
            Some(user("alice")),
        )
        .unwrap();
        assert_eq!(n.granted_by, svc("yubaba"));
        assert_eq!(n.on_behalf_of, Some(user("alice")));

        // Self-grant: on_behalf_of=None is valid.
        NewOwnership::new(camp("c-2"), "service", "s-1", "owns", svc("yubaba"), None).unwrap();
    }

    #[test]
    fn new_ownership_rejects_user_granted_by() {
        let err = NewOwnership::new(
            camp("c-1"),
            "service",
            "svc-abc",
            "owns",
            user("alice"),
            Some(user("alice")),
        )
        .unwrap_err();
        assert_eq!(
            err,
            OwnershipValidationError::GrantedByNotService(PrincipalKind::User)
        );

        // Camp principal also rejected — only Service is OK.
        let err = NewOwnership::new(
            camp("c-1"),
            "service",
            "svc-abc",
            "owns",
            camp("c-1"),
            None,
        )
        .unwrap_err();
        assert_eq!(
            err,
            OwnershipValidationError::GrantedByNotService(PrincipalKind::Camp)
        );
    }

    #[test]
    fn new_ownership_rejects_non_user_on_behalf_of() {
        let err = NewOwnership::new(
            camp("c-1"),
            "service",
            "svc-abc",
            "owns",
            svc("yubaba"),
            Some(svc("yubaba")),
        )
        .unwrap_err();
        assert_eq!(
            err,
            OwnershipValidationError::OnBehalfOfNotUser(PrincipalKind::Service)
        );

        let err = NewOwnership::new(
            camp("c-1"),
            "service",
            "svc-abc",
            "owns",
            svc("yubaba"),
            Some(camp("c-9")),
        )
        .unwrap_err();
        assert_eq!(
            err,
            OwnershipValidationError::OnBehalfOfNotUser(PrincipalKind::Camp)
        );
    }

    #[test]
    fn ownership_row_is_revoked_tracks_revoked_at() {
        let mut row = OwnershipRow::new(
            "id-1".into(),
            camp("c-1"),
            "service".into(),
            "svc-a".into(),
            "owns".into(),
            svc("yubaba"),
            Some(user("alice")),
            100,
            None,
        );
        assert!(!row.is_revoked());
        row.revoked_at = Some(150);
        assert!(row.is_revoked());
    }
}
