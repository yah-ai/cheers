//! Embedded-ownership persistence — the [`OwnershipStore`] trait.
//!
//! The table this trait backs is the *source of truth* cheers reads at mint
//! time to fill the [`owns`](cheers_core::Owns) claim on an MCP token. See
//! `.yah/docs/working/mcp-auth-and-ownership.md` §Ownership table for the
//! schema and the W159 trust-layer reasoning behind it.
//!
//! Generic shape — `subject × resource × kind` — so cheers does not grow a
//! per-kind table for every resource type yah adds. The subject is a
//! [`Subject`]: one principal (`principal_id`), or a subject set
//! (`subject_kind / subject_id / subject_relation`, "every holder of
//! `subject_relation` on that resource", noisetable W235 §2.1). Exactly one
//! form is populated — a SQL CHECK and [`Subject`]'s own constructors both
//! hold that line. The set-aware checks walk sets through
//! [`OwnershipTuples`] (R732-F2). The two unconditional invariants are encoded
//! both here (parse-time, via [`OwnershipValidationError`]) and at the SQL
//! CHECK level in the backing schema:
//!
//! - **`granted_by` is the writer's verified `sub`, of any kind** (D4,
//!   operator 2026-10-06). The right to grant is a relationship checked at
//!   the write door, not a property of the caller's principal kind.
//! - **`on_behalf_of` (when set) is always a user principal** (`user:<id>`).
//!   It is attribution only: it never drives a row's lifecycle.
//!
//! Writes/deletes do not hard-delete — a soft `revoked_at` timestamp marks a
//! row inactive. **Lifecycle follows the holder:** the cascade for "principal
//! P went away" sweeps every row with `principal_id = P`
//! ([`OwnershipStore::revoke_by_principal`]). Deleting a granter or an
//! `on_behalf_of` user never revokes rows they granted. (No current writer
//! needs a row to die with anyone but its holder, so there is no `bound_to`
//! column; add one explicitly if that changes.)
//!
//! **Ownership version (R732-F4).** The store carries one store-wide counter,
//! [`OwnershipStore::current_version`]. Every write that changes a row —
//! [`insert`](OwnershipStore::insert), a [`revoke_by_id`](OwnershipStore::revoke_by_id)
//! that revokes, a [`revoke_by_principal`](OwnershipStore::revoke_by_principal)
//! that sweeps anything — advances it to [`next_ownership_version`]
//! (`max(v + 1, now)`) **in the same transaction**, so two reads of an equal
//! version saw equal rows. It is the epoch of a membership snapshot
//! (`crate::snapshot`). Store-wide, not per resource, because subject sets make
//! one resource's flattened membership depend on other resources' rows. The
//! clock floor is the revocation epoch's and the binding sequence's: a store
//! restored from an older backup still advances above what edges hold.
//!
//! The trait says nothing about authorisation — composition rule (4) (the
//! `ownership:write` scope being grantable to services only) is enforced at
//! the grant API by [`cheers_core::validate_grant`], and at the HTTP layer
//! by checking the bearer token's `scope` list. The store impl just enforces
//! the row invariants.
//!
//! @yah:ticket(R731-F7, "Ownership rows: granted_by of any kind, on_behalf_of attribution only, revoke by holder (D4 storage)")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:at(2026-10-06T22:53:07Z)
//! @yah:phase(P3)
//! @yah:parent(R731)
//! @yah:next("Doc D4; operator decided 2026-10-06. Drop CHECK (granted_by LIKE svc:%) and OwnershipValidationError::GrantedByNotService.")
//! @yah:next("Revocation follows the holder (principal_id), never the granter: revoke_by_on_behalf_of today would revoke every grant an operator made when their account is deleted. Audit its callers; a row that must die with someone other than its holder gets an explicit nullable bound_to column.")
//! @yah:next("Migrations in all three schemas: cheers-sqlx migrations/sqlite and migrations/pg, cheers-turso migrations/sqlite. SQLite cannot drop a CHECK, so it is a table rebuild.")
//! @yah:verify("cheers-test-support store_scenarios cover user-granted rows and the holder cascade on every backend.")
//! @yah:tier(Warrior)
//! @yah:handoff("Dropped OwnershipValidationError::GrantedByNotService and the granted_by kind check in NewOwnership::new (cheers-server/src/ownership.rs); module + trait docs rewritten for D4 (any-kind granter, on_behalf_of attribution only, lifecycle follows holder).")
//! @yah:handoff("OwnershipStore::revoke_by_on_behalf_of REPLACED by revoke_by_principal(principal, now): UPDATE ... WHERE principal_id = ? AND revoked_at IS NULL. Impls: cheers-sqlx ownership_store.rs (pg + sqlite), cheers-turso ownership_store.rs; mocks in cheers-axum/src/camps.rs, cheers-server/src/mcp_authority.rs, cheers-axum/tests/common/mod.rs.")
//! @yah:handoff("bound_to NOT added. Audit: revoke_by_on_behalf_of had zero production callers (only trait impls, mocks and one scenario). The only in-tree ownership writer, enrollment (cheers-axum/src/enrollment.rs, fed by cheers/src/lan_pair/enroll.rs), writes rows HELD by the user, so the holder cascade covers them. camps.rs writes no ownership rows; camp principals die with their user via CampAuthority::revoke_user_cascade on the camp store. Doc comments in enrollment.rs and lan_pair/enroll.rs updated to name the holder cascade.")
//! @yah:handoff("Migration 0008_ownership_any_granter.sql in cheers-sqlx/migrations/sqlite, cheers-turso/migrations/sqlite (byte-identical, registered as version 8 in cheers-turso/src/migrate.rs) and cheers-sqlx/migrations/pg. SQLite: table rebuild without the granted_by CHECK (on_behalf_of CHECK kept, ix_ownership_principal recreated). PG: DROP CONSTRAINT ownership_granted_by_check (Postgres auto-name for 0002's unnamed column CHECK; inferred, not run against a live pg). Both drop ix_ownership_on_behalf_of, which only served the retired cascade.")
//! @yah:handoff("New scenario cheers-test-support store_scenarios::ownership_store_revoke_follows_holder (user-granted row inserts+lists; deleting the operator sweeps only their held row, rows they granted survive; holder cascade sweeps only that holder), wired in cheers-sqlx tests/sqlite.rs + tests/pg.rs and cheers-turso tests/turso.rs. Lifecycle scenario now cascades by holder; GrantedByNotService assertion removed.")
//! @yah:handoff("Extra: cheers-axum/tests/ownership_basic.rs post_with_user_sub_is_rejected_by_defense_in_depth asserted the deleted rule; renamed to post_with_user_sub_records_user_as_granted_by (201, granted_by user:). cheers-sqlx tests/libsql.rs now expects a user grantor to be ACCEPTED. cheers-turso/src/error.rs test string swapped to the surviving CHECK.")
//! @yah:handoff("Left for R731-F8 (router, out of my fence): cheers-axum/src/ownership.rs module doc lines 8-15 still say granted_by is a service; no code change was needed there.")
//! @yah:verify("Baseline before edits: cargo test -p cheers-server -p cheers-sqlx -p cheers-turso -p cheers-test-support -p cheers-axum = 390 passed, 0 failed, plus a cheers-axum doctest compile error (unresolved cheers_core::KeyRole from R731-B1's in-flight jwk work), so that run exited 1.")
//! @yah:verify("After, with --no-fail-fast: 407 passed, 0 failed, 3 ignored (doctests), exit 0. ownership_store_revoke_follows_holder ran OK on sqlx-sqlite and turso. The doctest error had cleared by then (R731-B1's fix landed in between).")
//! @yah:verify("NOT run: pg.rs (feature pg-integration) and libsql.rs (container-gated); the pg migration's constraint name is unverified against a live Postgres.")
//! @yah:verify("Leader re-verify 2026-10-06: cargo test --workspace (oss/cheers) 640 pass / 0 fail / 3 ignored. cargo test -p cheers-sqlx --features pg-integration,libsql-integration --test pg --test libsql: pg 17/17, libsql 7/7, so the Postgres 0008 DROP CONSTRAINT ownership_granted_by_check applies cleanly and the guessed constraint name is confirmed.")
//! @yah:gotcha("The container-gated suites DO run on this machine. Docker is OrbStack, and its socket is not /var/run/docker.sock, so testcontainers fails with SocketNotFoundError unless you prefix DOCKER_HOST=unix:///Users/leif/.orbstack/run/docker.sock TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/Users/leif/.orbstack/run/docker.sock. \"Container-gated, didn't run\" is not a valid skip here.")
//!
//! @yah:ticket(R732-T9, "OwnershipStore::list_for_kind(kind): enumerate every grant row of one resource_kind (needed by noisetable R803-T1 ledger migration)")
//! @yah:status(review)
//! @yah:at(2026-10-07T07:15:43Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R732)
//! @yah:handoff("Landed `async fn list_for_kind(&self, resource_kind: &str) -> Result<Vec<OwnershipRow>, StoreError>` on OwnershipStore (cheers-server/src/ownership.rs:339) with the Arc delegate, turso + sqlx pg/sqlite backends (WHERE resource_kind = ? AND revoked_at IS NULL), and mocks in grants.rs, mcp_authority.rs, camps.rs, axum tests/common. Shared scenario store_scenarios.rs::ownership_store_list_for_kind covers live rows of the kind, other kinds excluded, revoked excluded, empty kind -> empty; wired into turso.rs, sqlite.rs, pg.rs.")
//! @yah:verify("cargo test --workspace (oss/cheers, default features): 793 pass / 0 fail; list_for_kind passes on turso and sqlite.")
//! @yah:gotcha("noisetable requires cheers-server = \"0.8.32\"; this working copy is 0.8.43-pre.1, which a ^0.8.32 requirement does not match (prerelease), so a plain [patch.crates-io] to oss/cheers would be unused unless the burst also bumps the requirement. Not verified end-to-end.")

use async_trait::async_trait;
use cheers_core::{
    AdmissionPolicy, Lease, PrincipalId, PrincipalKind, RevocationKey, StoreError, Subject, SubjectFormError, TupleSource,
};
use serde::{Deserialize, Serialize};

/// Why a [`NewOwnership`] failed to validate before reaching the store.
///
/// The SQL CHECK constraints are the same invariants enforced at the DB
/// level — this enum is the Rust-side guard so a misconfigured insert never
/// makes a round-trip to the database to be rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OwnershipValidationError {
    /// `on_behalf_of`, when set, must be a user principal — services never
    /// appear here.
    #[error("on_behalf_of must be a user principal when set; got {0}")]
    OnBehalfOfNotUser(PrincipalKind),
    /// A subject given as loose fields (a request body) with both forms or
    /// neither.
    #[error(transparent)]
    SubjectForm(#[from] SubjectFormError),
}

/// Input for [`OwnershipStore::insert`]. Constructed via
/// [`NewOwnership::new`] which enforces the `on_behalf_of` invariant up
/// front.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct NewOwnership {
    /// Who holds the tuple. Serialized flat: `principal_id`, or the three
    /// `subject_*` keys.
    #[serde(flatten)]
    pub subject: Subject,
    pub resource_kind: String,
    pub resource_id: String,
    pub relationship: String,
    pub granted_by: PrincipalId,
    pub on_behalf_of: Option<PrincipalId>,
    /// A guest's posted lease (R734-F4); `None` for a standing tuple.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<TupleLease>,
}

/// The lease a tuple keeps from the `Admit` that wrote it (R734-F4,
/// `knock.md` "Posted lease"). Past `lease.exp` the tuple confers nothing:
/// [`OwnershipTuples`] drops it, so the server stops counting it as held and
/// the snapshot mint stops listing it. `iat` is the `Admit`'s, kept so the
/// lease re-validates on read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TupleLease {
    pub iat: i64,
    #[serde(flatten)]
    pub lease: Lease,
}

impl TupleLease {
    /// From stored columns; a lease that breaks its invariant is a
    /// data-integrity error.
    pub fn from_columns(iat: Option<i64>, refresh_after: Option<i64>, exp: Option<i64>) -> Result<Option<Self>, StoreError> {
        match (iat, refresh_after) {
            (Some(iat), Some(refresh_after)) => Lease::new(iat, refresh_after, exp)
                .map(|lease| Some(Self { iat, lease }))
                .map_err(|e| StoreError::Backend(format!("invalid ownership lease: {e}"))),
            (None, None) if exp.is_none() => Ok(None),
            _ => Err(StoreError::Backend("partial ownership lease columns".into())),
        }
    }

    /// `true` once the lease has lapsed at `now`.
    pub fn lapsed_at(&self, now: i64) -> bool {
        self.lease.exp().is_some_and(|exp| exp <= now)
    }
}

impl NewOwnership {
    /// Construct + validate. The kind invariant on `on_behalf_of` is checked
    /// here so an impl never has to; `granted_by` may be any kind.
    pub fn new(
        subject: impl Into<Subject>,
        resource_kind: impl Into<String>,
        resource_id: impl Into<String>,
        relationship: impl Into<String>,
        granted_by: PrincipalId,
        on_behalf_of: Option<PrincipalId>,
    ) -> Result<Self, OwnershipValidationError> {
        if let Some(ref obo) = on_behalf_of {
            if obo.kind != PrincipalKind::User {
                return Err(OwnershipValidationError::OnBehalfOfNotUser(obo.kind));
            }
        }
        Ok(Self {
            subject: subject.into(),
            resource_kind: resource_kind.into(),
            resource_id: resource_id.into(),
            relationship: relationship.into(),
            granted_by,
            on_behalf_of,
            lease: None,
        })
    }

    /// Attach a guest's lease.
    pub fn with_lease(mut self, lease: Option<TupleLease>) -> Self {
        self.lease = lease;
        self
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
    /// Who holds the tuple. Serialized flat, as in [`NewOwnership`]: a
    /// principal row keeps its `principal_id` key on the wire.
    #[serde(flatten)]
    pub subject: Subject,
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
    /// The tuple's lease, if it was admitted for a while (R734-F4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<TupleLease>,
}

impl OwnershipRow {
    /// Build a row from its constituent fields. Use from `OwnershipStore`
    /// impls that need to assemble a row from a SQL query result.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        subject: Subject,
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
            subject,
            resource_kind,
            resource_id,
            relationship,
            granted_by,
            on_behalf_of,
            granted_at,
            revoked_at,
            lease: None,
        }
    }

    /// Attach the stored lease.
    pub fn with_lease(mut self, lease: Option<TupleLease>) -> Self {
        self.lease = lease;
        self
    }

    /// `true` while the row confers its relation at `now`: not revoked and
    /// not past its lease.
    pub fn is_live_at(&self, now: i64) -> bool {
        !self.is_revoked() && !self.lease.is_some_and(|l| l.lapsed_at(now))
    }

    /// `true` iff the row has been soft-revoked.
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }
}

impl cheers_core::RelationTuple for OwnershipRow {
    fn subject(&self) -> &Subject {
        &self.subject
    }
    fn resource_kind(&self) -> &str {
        &self.resource_kind
    }
    fn resource_id(&self) -> &str {
        &self.resource_id
    }
    fn relation(&self) -> &str {
        &self.relationship
    }
    fn is_live(&self) -> bool {
        !self.is_revoked()
    }
}

/// One bootstrap tuple for [`seed_ownership`]: the first grant-holder of a
/// resource, which the grant door (D4) cannot create because nobody yet
/// holds a relation on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedTuple {
    pub principal_id: PrincipalId,
    pub resource_kind: String,
    pub resource_id: String,
    pub relationship: String,
}

/// D4 bootstrap: write each seed tuple unless an identical live row already
/// exists, attributed to `granted_by` (the deployment's own `svc:` identity).
/// Idempotent — a deployment calls it at every startup. Returns how many rows
/// were inserted.
///
/// This is the ONE path into the table that skips the `may_grant` check, so
/// it must never be reachable from an HTTP route; it takes the store, not a
/// request.
pub async fn seed_ownership<O: OwnershipStore + ?Sized>(
    store: &O,
    seeds: &[SeedTuple],
    granted_by: &PrincipalId,
    now: i64,
) -> Result<usize, StoreError> {
    let mut inserted = 0;
    for s in seeds {
        let live = store.list_for_principal(&s.principal_id).await?;
        if live.iter().any(|r| {
            !r.is_revoked()
                && r.resource_kind == s.resource_kind
                && r.resource_id == s.resource_id
                && r.relationship == s.relationship
        }) {
            continue;
        }
        let new = NewOwnership {
            subject: s.principal_id.clone().into(),
            resource_kind: s.resource_kind.clone(),
            resource_id: s.resource_id.clone(),
            relationship: s.relationship.clone(),
            granted_by: granted_by.clone(),
            on_behalf_of: None,
            lease: None,
        };
        store.insert(&new, now).await?;
        inserted += 1;
    }
    Ok(inserted)
}

/// The ownership version a write advances to: `max(prev + 1, now)`.
/// Strictly monotonic whatever the clock does; the floor keeps a store
/// restored from an older backup above the versions edges already hold. The
/// same rule as `next_epoch` and [`next_binding_seq`](crate::next_binding_seq).
pub fn next_ownership_version(prev: u64, now: i64) -> u64 {
    prev.saturating_add(1).max(u64::try_from(now).unwrap_or(0))
}

/// What [`OwnershipStore::insert`] wrote: the row, and the ownership version
/// the write advanced the store to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inserted {
    pub row: OwnershipRow,
    pub version: u64,
}

/// Persistence for the ownership table — the embedded-ownership source of
/// truth cheers reads at mint time.
///
/// All time arguments are unix seconds, signed — same as
/// [`Claims::issued_at`](cheers_core::Claims) and the refresh-token rows.
/// Every write that changes a row advances the store-wide ownership version
/// in its own transaction (module docs); `now` is its clock floor.
#[async_trait]
pub trait OwnershipStore: Send + Sync {
    /// Insert a fresh row and advance the ownership version, atomically. The
    /// impl mints `id` and sets `granted_at = now`; the returned row carries
    /// both, `revoked_at` is `None`, and [`Inserted::version`] is the version
    /// this insert produced.
    async fn insert(&self, ownership: &NewOwnership, now: i64) -> Result<Inserted, StoreError>;

    /// Look up a row by id. `None` if no such row exists (live or revoked).
    async fn get(&self, id: &str) -> Result<Option<OwnershipRow>, StoreError>;

    /// Soft-delete by id — sets `revoked_at = now` if the row is live and
    /// advances the ownership version in the same transaction. Returns the
    /// version after the call: the one this revoke produced, or, when the row
    /// was already revoked (a no-op that changes nothing and advances
    /// nothing), the current one. Returns [`StoreError::NotFound`] when the id
    /// is unknown.
    async fn revoke_by_id(&self, id: &str, now: i64) -> Result<u64, StoreError>;

    /// Cascading revoke — sweep `revoked_at = now` across every live row
    /// *held* by `principal` (`principal_id = principal`), advancing the
    /// ownership version in the same transaction when it sweeps any. Returns
    /// the version after the call: the one the sweep produced, or, when
    /// nothing was live, the current one. Rows the principal merely granted
    /// (`granted_by`) or was attributed on (`on_behalf_of`) are untouched, by
    /// design (D4). A deletion cascade goes through
    /// [`revoke_principal_ownership`](crate::revoke_principal_ownership), which
    /// also tells offline edges.
    async fn revoke_by_principal(
        &self,
        principal: &PrincipalId,
        now: i64,
    ) -> Result<u64, StoreError>;

    /// Every row held by `principal` directly — subject
    /// [`Subject::Principal`] — **live or revoked**, in unspecified order.
    /// What a principal held after its rows are gone, for
    /// [`revoke_principal_ownership`](crate::revoke_principal_ownership).
    /// Unbounded and unindexed for revoked rows: a cascade read, not a request
    /// path.
    async fn list_history_for_principal(
        &self,
        principal: &PrincipalId,
    ) -> Result<Vec<OwnershipRow>, StoreError>;

    /// The store-wide ownership version: `0` for a fresh store, then whatever
    /// the last row-changing write advanced it to. Equal versions read equal
    /// rows (module docs).
    async fn current_version(&self) -> Result<u64, StoreError>;

    /// Live (non-revoked) rows held by `principal` directly — subject
    /// [`Subject::Principal`]. Rows reaching it through a subject set are not
    /// included. Unspecified order.
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

    /// Live (non-revoked) rows whose subject is a set on `(kind, id)` — the
    /// tuples conferring their relation on holders of some relation on that
    /// resource (`<resource>#<rel> ← kind/id#<subject_relation>`), whatever
    /// `subject_relation` is. Unspecified order. Backed by a partial index on
    /// `(subject_kind, subject_id)`.
    async fn list_for_subject_set(
        &self,
        kind: &str,
        id: &str,
    ) -> Result<Vec<OwnershipRow>, StoreError>;

    /// Live (non-revoked) rows over every resource of `resource_kind`,
    /// whatever the subject form, in unspecified order. Unbounded, like its
    /// siblings: meant for one-shot ledger migrations (noisetable R803-T1
    /// re-keys every `publish-scope` row to `namespace`), not request paths.
    async fn list_for_kind(&self, resource_kind: &str) -> Result<Vec<OwnershipRow>, StoreError>;

    /// The membership-revocation key of `(resource_kind, resource_id)`,
    /// created on first use (R732-T10; `cheers_core::revocation`, "Membership
    /// privacy"). **Immutable**: once a key exists every call returns it, so
    /// an edge holding an old snapshot keeps matching new entries — a changed
    /// key would fail revocation open, silently. Get-or-create is insert-or-
    /// ignore of a fresh [`new_revocation_key`] followed by a reread, so two
    /// concurrent creators converge on the one row that won. Kept beside the
    /// ownership rows so a restore cannot separate the two. Secret: it goes
    /// out only inside signed snapshots, never on an unauthenticated route.
    async fn revocation_key(&self, resource_kind: &str, resource_id: &str) -> Result<RevocationKey, StoreError>;

    /// The admission policy row of `(resource_kind, resource_id)` (R734-F3,
    /// migration 0016). `None` when the resource has none, which reads as
    /// closed for offline admits.
    async fn admission_policy(
        &self,
        resource_kind: &str,
        resource_id: &str,
    ) -> Result<Option<AdmissionPolicy>, StoreError>;

    /// Set (`Some`) or delete (`None`) the admission policy row, advancing the
    /// ownership version in the same transaction, so the next snapshot carries
    /// the change at a higher epoch. Always advances, even when the value is
    /// unchanged. Returns the version it produced.
    async fn set_admission_policy(
        &self,
        resource_kind: &str,
        resource_id: &str,
        policy: Option<&AdmissionPolicy>,
        now: i64,
    ) -> Result<u64, StoreError>;
}

/// An [`AdmissionPolicy`] as its stored column: the JSON wire form.
pub fn encode_admission_policy(policy: &AdmissionPolicy) -> String {
    serde_json::to_string(policy).expect("AdmissionPolicy serializes")
}

/// Read a stored policy column back. A malformed row is a data-integrity
/// error, never a silent `None` (that would read as closed, or worse, mask a
/// tightening).
pub fn decode_admission_policy(kind: &str, id: &str, column: &str) -> Result<AdmissionPolicy, StoreError> {
    serde_json::from_str(column)
        .map_err(|e| StoreError::Backend(format!("invalid admission policy for {kind}/{id}: {e}")))
}

/// A fresh random [`RevocationKey`] for a store's get-or-create.
pub fn new_revocation_key() -> RevocationKey {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS CSPRNG must be available");
    RevocationKey::from_bytes(bytes)
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
    fn new_ownership_accepts_granted_by_of_any_kind() {
        for granter in [user("alice"), camp("c-1"), svc("yubaba")] {
            let n = NewOwnership::new(
                camp("c-1"),
                "service",
                "svc-abc",
                "owns",
                granter.clone(),
                Some(user("alice")),
            )
            .unwrap();
            assert_eq!(n.granted_by, granter);
        }
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
            camp("c-1").into(),
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

    #[test]
    fn ownership_row_wire_keeps_principal_id_and_flattens_sets() {
        let principal = OwnershipRow::new(
            "id-1".into(),
            user("alice").into(),
            "doc".into(),
            "d1".into(),
            "reader".into(),
            svc("cheers"),
            None,
            100,
            None,
        );
        let v = serde_json::to_value(&principal).unwrap();
        assert_eq!(v["principal_id"], "user:alice");
        assert!(v.get("subject_kind").is_none());
        assert_eq!(serde_json::from_value::<OwnershipRow>(v).unwrap(), principal);

        let set = NewOwnership::new(
            Subject::set("namespace", "n1", "member"),
            "doc",
            "d1",
            "reader",
            user("alice"),
            None,
        )
        .unwrap();
        let v = serde_json::to_value(&set).unwrap();
        assert!(v.get("principal_id").is_none());
        assert_eq!(v["subject_kind"], "namespace");
        assert_eq!(v["subject_id"], "n1");
        assert_eq!(v["subject_relation"], "member");
        assert_eq!(serde_json::from_value::<NewOwnership>(v).unwrap(), set);
    }
}

/// Shared handle: lets [`SchemaGrantStore`](crate::SchemaGrantStore) and the
/// mint authority read one ownership table.
#[async_trait]
impl<T: OwnershipStore + ?Sized> OwnershipStore for std::sync::Arc<T> {
    async fn insert(&self, o: &NewOwnership, now: i64) -> Result<Inserted, StoreError> {
        (**self).insert(o, now).await
    }
    async fn get(&self, id: &str) -> Result<Option<OwnershipRow>, StoreError> {
        (**self).get(id).await
    }
    async fn revoke_by_id(&self, id: &str, now: i64) -> Result<u64, StoreError> {
        (**self).revoke_by_id(id, now).await
    }
    async fn revoke_by_principal(&self, p: &PrincipalId, now: i64) -> Result<u64, StoreError> {
        (**self).revoke_by_principal(p, now).await
    }
    async fn list_history_for_principal(&self, p: &PrincipalId) -> Result<Vec<OwnershipRow>, StoreError> {
        (**self).list_history_for_principal(p).await
    }
    async fn current_version(&self) -> Result<u64, StoreError> {
        (**self).current_version().await
    }
    async fn list_for_principal(&self, p: &PrincipalId) -> Result<Vec<OwnershipRow>, StoreError> {
        (**self).list_for_principal(p).await
    }
    async fn list_for_resource(
        &self,
        kind: &str,
        id: &str,
    ) -> Result<Vec<OwnershipRow>, StoreError> {
        (**self).list_for_resource(kind, id).await
    }
    async fn list_for_subject_set(
        &self,
        kind: &str,
        id: &str,
    ) -> Result<Vec<OwnershipRow>, StoreError> {
        (**self).list_for_subject_set(kind, id).await
    }
    async fn list_for_kind(&self, kind: &str) -> Result<Vec<OwnershipRow>, StoreError> {
        (**self).list_for_kind(kind).await
    }
    async fn revocation_key(&self, kind: &str, id: &str) -> Result<RevocationKey, StoreError> {
        (**self).revocation_key(kind, id).await
    }
    async fn admission_policy(&self, kind: &str, id: &str) -> Result<Option<AdmissionPolicy>, StoreError> {
        (**self).admission_policy(kind, id).await
    }
    async fn set_admission_policy(
        &self,
        kind: &str,
        id: &str,
        policy: Option<&AdmissionPolicy>,
        now: i64,
    ) -> Result<u64, StoreError> {
        (**self).set_admission_policy(kind, id, policy, now).await
    }
}

/// In-process ownership table — tests and single-process deployments. Clones
/// share one table. Each write takes one lock, so the row change and the
/// version advance are atomic as the trait requires.
#[derive(Debug, Clone, Default)]
pub struct MemoryOwnershipStore(std::sync::Arc<std::sync::Mutex<MemoryOwnership>>);

#[derive(Debug, Default)]
struct MemoryOwnership {
    rows: Vec<OwnershipRow>,
    version: u64,
    revocation_keys: std::collections::HashMap<(String, String), RevocationKey>,
    policies: std::collections::HashMap<(String, String), AdmissionPolicy>,
}

impl MemoryOwnershipStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MemoryOwnership> {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn live(&self, keep: impl Fn(&OwnershipRow) -> bool) -> Vec<OwnershipRow> {
        self.lock().rows.iter().filter(|r| !r.is_revoked() && keep(r)).cloned().collect()
    }
}

#[async_trait]
impl OwnershipStore for MemoryOwnershipStore {
    async fn insert(&self, o: &NewOwnership, now: i64) -> Result<Inserted, StoreError> {
        let mut t = self.lock();
        let row = OwnershipRow::new(
            format!("own-{}", t.rows.len() + 1),
            o.subject.clone(),
            o.resource_kind.clone(),
            o.resource_id.clone(),
            o.relationship.clone(),
            o.granted_by.clone(),
            o.on_behalf_of.clone(),
            now,
            None,
        )
        .with_lease(o.lease);
        t.rows.push(row.clone());
        t.version = next_ownership_version(t.version, now);
        Ok(Inserted { row, version: t.version })
    }
    async fn get(&self, id: &str) -> Result<Option<OwnershipRow>, StoreError> {
        Ok(self.lock().rows.iter().find(|r| r.id == id).cloned())
    }
    async fn revoke_by_id(&self, id: &str, now: i64) -> Result<u64, StoreError> {
        let mut t = self.lock();
        let row = t.rows.iter_mut().find(|r| r.id == id).ok_or(StoreError::NotFound)?;
        if row.revoked_at.is_none() {
            row.revoked_at = Some(now);
            t.version = next_ownership_version(t.version, now);
        }
        Ok(t.version)
    }
    async fn revoke_by_principal(&self, p: &PrincipalId, now: i64) -> Result<u64, StoreError> {
        let mut t = self.lock();
        let mut swept = false;
        for row in t.rows.iter_mut().filter(|r| r.revoked_at.is_none() && r.subject.principal() == Some(p)) {
            row.revoked_at = Some(now);
            swept = true;
        }
        if swept {
            t.version = next_ownership_version(t.version, now);
        }
        Ok(t.version)
    }
    async fn list_history_for_principal(&self, p: &PrincipalId) -> Result<Vec<OwnershipRow>, StoreError> {
        Ok(self.lock().rows.iter().filter(|r| r.subject.principal() == Some(p)).cloned().collect())
    }
    async fn current_version(&self) -> Result<u64, StoreError> {
        Ok(self.lock().version)
    }
    async fn list_for_principal(&self, p: &PrincipalId) -> Result<Vec<OwnershipRow>, StoreError> {
        Ok(self.live(|r| r.subject.principal() == Some(p)))
    }
    async fn list_for_resource(&self, kind: &str, id: &str) -> Result<Vec<OwnershipRow>, StoreError> {
        Ok(self.live(|r| r.resource_kind == kind && r.resource_id == id))
    }
    async fn list_for_subject_set(&self, kind: &str, id: &str) -> Result<Vec<OwnershipRow>, StoreError> {
        Ok(self.live(|r| r.subject.as_set().is_some_and(|(k, i, _)| k == kind && i == id)))
    }
    async fn list_for_kind(&self, kind: &str) -> Result<Vec<OwnershipRow>, StoreError> {
        Ok(self.live(|r| r.resource_kind == kind))
    }
    async fn revocation_key(&self, kind: &str, id: &str) -> Result<RevocationKey, StoreError> {
        let fresh = new_revocation_key();
        let mut t = self.lock();
        Ok(t.revocation_keys.entry((kind.to_owned(), id.to_owned())).or_insert(fresh).clone())
    }
    async fn admission_policy(&self, kind: &str, id: &str) -> Result<Option<AdmissionPolicy>, StoreError> {
        Ok(self.lock().policies.get(&(kind.to_owned(), id.to_owned())).cloned())
    }
    async fn set_admission_policy(
        &self,
        kind: &str,
        id: &str,
        policy: Option<&AdmissionPolicy>,
        now: i64,
    ) -> Result<u64, StoreError> {
        let mut t = self.lock();
        let key = (kind.to_owned(), id.to_owned());
        match policy {
            Some(p) => t.policies.insert(key, p.clone()),
            None => t.policies.remove(&key),
        };
        t.version = next_ownership_version(t.version, now);
        Ok(t.version)
    }
}

/// An [`OwnershipStore`] read as the schema's [`TupleSource`] at instant
/// `now`, for the set-aware checks: `schema.may_grant(&OwnershipTuples::at(&*store, now), …)`,
/// [`holds`](cheers_core::SchemaRegistry::holds),
/// [`held_by`](cheers_core::SchemaRegistry::held_by),
/// [`members`](cheers_core::SchemaRegistry::members). Rows whose lease has
/// lapsed at `now` are dropped (R734-F4). A newtype because the orphan rule
/// forbids a blanket impl of cheers-core's trait for every store.
pub struct OwnershipTuples<'a, O: ?Sized> {
    store: &'a O,
    now: i64,
}

impl<'a, O: ?Sized> OwnershipTuples<'a, O> {
    pub fn at(store: &'a O, now: i64) -> Self {
        Self { store, now }
    }

    fn live(&self, rows: Vec<OwnershipRow>) -> Vec<OwnershipRow> {
        rows.into_iter().filter(|r| r.is_live_at(self.now)).collect()
    }
}

#[async_trait]
impl<'a, O: OwnershipStore + ?Sized> TupleSource for OwnershipTuples<'a, O> {
    type Tuple = OwnershipRow;
    async fn list_for_principal(&self, p: &PrincipalId) -> Result<Vec<OwnershipRow>, StoreError> {
        Ok(self.live(self.store.list_for_principal(p).await?))
    }
    async fn list_for_resource(
        &self,
        kind: &str,
        id: &str,
    ) -> Result<Vec<OwnershipRow>, StoreError> {
        Ok(self.live(self.store.list_for_resource(kind, id).await?))
    }
    async fn list_for_subject_set(
        &self,
        kind: &str,
        id: &str,
    ) -> Result<Vec<OwnershipRow>, StoreError> {
        Ok(self.live(self.store.list_for_subject_set(kind, id).await?))
    }
}
