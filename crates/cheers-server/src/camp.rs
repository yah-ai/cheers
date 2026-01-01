//! Camp-principal bootstrap — provision a camp on behalf of a user U.
//!
//! See `.yah/docs/working/mcp-auth-and-ownership.md` §Camp bootstrap. This
//! module is the origin-side implementation of the doc's mint flow #2
//! provisioning step:
//!
//! 1. Warden (authenticated as its service principal) calls
//!    `POST /admin/camps/bootstrap` with a [`NewCampPrincipal`] + a
//!    [`UserDelegation`] (a payload signed by user U via the yah-side W122
//!    flow). The HTTP layer lives in `cheers-axum`.
//! 2. [`CampAuthority::provision`] verifies the delegation's Ed25519
//!    signature against a key trusted for U (per [`UserSigningKeyStore`]),
//!    allocates a [`Principal`] of [`kind = Camp`](PrincipalKind::Camp) with
//!    `bound_to = Some(user:U)`, persists the delegation as the auditable
//!    "U authorised camp C" record, and issues a [`CampBootstrapCredential`]
//!    that the camp later exchanges for a short-TTL access token via
//!    [`McpAuthority::mint_bootstrap`](crate::mcp_authority::McpAuthority::mint_bootstrap).
//! 3. Cascading revocation: [`CampAuthority::revoke_user_cascade`] flips
//!    every camp principal `bound_to: U` to [`Revoked`](PrincipalStatus::Revoked)
//!    in one sweep. Revoking U revokes every camp bound to U; revoking the
//!    camp alone does NOT touch U.
//!
//! The crate-direction invariant from R019 still holds: this module is
//! origin-only (it verifies a signed delegation and persists a credential).
//! `cheers-verify` consumers (constable, CF Worker) never depend on this
//! crate — they verify the MCP-call tokens minted via path #2, not the
//! bootstrap credential itself.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use cheers_core::{
    DelegationError, Principal, PrincipalError, PrincipalId, PrincipalKind, PrincipalStatus,
    StoreError, UserDelegation,
};

// ----------------------------------------------------------------------------
// User signing keys — trusted Ed25519 pubkeys for delegation verification.
// ----------------------------------------------------------------------------

/// Lifecycle state of a user's signing key — mirrors
/// [`SigningKeyStatus`](crate::service_principal::SigningKeyStatus) on the
/// service-principal side. Only `Active` keys are accepted for delegation
/// verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum UserSigningKeyStatus {
    Active,
    Revoked,
}

/// One Ed25519 pubkey trusted for delegations signed by a user.
///
/// `public_key` is the raw 32-byte Ed25519 key — wire encoding matches
/// [`UserDelegation::user_signing_key`](cheers_core::UserDelegation): base64url
/// no-pad.
///
/// The (cheers-side) **enrollment flow** that registers these keys is W122 on
/// the yah side — out of scope for R020-F10. This struct + the trait below
/// are the surface that flow eventually wires into; the in-memory impl + the
/// trait shape land here so the camp-bootstrap path can be tested today.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct UserSigningKey {
    pub kid: String,
    /// The user this key signs for. `kind` MUST be [`PrincipalKind::User`].
    pub user: PrincipalId,
    #[serde(with = "ed25519_public_key_serde")]
    pub public_key: [u8; 32],
    pub status: UserSigningKeyStatus,
    pub created_at: i64,
}

impl UserSigningKey {
    /// Build a key record. Cross-crate construction needs a constructor
    /// because the struct is `#[non_exhaustive]` (matches the pattern
    /// `OwnershipRow::new` / `RefreshTokenRecord::new` use).
    pub fn new(
        kid: impl Into<String>,
        user: PrincipalId,
        public_key: [u8; 32],
        status: UserSigningKeyStatus,
        created_at: i64,
    ) -> Self {
        Self {
            kid: kid.into(),
            user,
            public_key,
            status,
            created_at,
        }
    }
}

mod ed25519_public_key_serde {
    use super::*;
    use serde::de::Error as DeError;

    pub fn serialize<S: serde::Serializer>(bytes: &[u8; 32], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(de: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(de)?;
        let raw = URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map_err(|e| D::Error::custom(format!("invalid base64url public_key: {e}")))?;
        raw.try_into().map_err(|v: Vec<u8>| {
            D::Error::custom(format!("expected 32 public_key bytes, got {}", v.len()))
        })
    }
}

/// Persistence for [`UserSigningKey`] records.
///
/// The single hot-path query is "what Ed25519 keys are trusted for user
/// `<U>`?" — the authority loads them at provision time and verifies the
/// supplied delegation against each `Active` key until one matches.
#[async_trait]
pub trait UserSigningKeyStore: Send + Sync {
    /// Every `Active` key trusted for `user`. Order is unspecified.
    async fn list_active_for_user(
        &self,
        user: &PrincipalId,
    ) -> Result<Vec<UserSigningKey>, StoreError>;
}

/// In-memory [`UserSigningKeyStore`] for tests and single-node bootstrapping.
/// Cheap to `clone` — shares one backing map.
#[derive(Default, Clone, Debug)]
pub struct MemoryUserSigningKeyStore {
    inner: Arc<Mutex<Vec<UserSigningKey>>>,
}

impl MemoryUserSigningKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Test/bootstrapping helper — push a key into the trusted set.
    pub fn insert(&self, key: UserSigningKey) {
        self.inner
            .lock()
            .expect("user-signing-key store mutex poisoned")
            .push(key);
    }
}

#[async_trait]
impl UserSigningKeyStore for MemoryUserSigningKeyStore {
    async fn list_active_for_user(
        &self,
        user: &PrincipalId,
    ) -> Result<Vec<UserSigningKey>, StoreError> {
        let g = self.inner.lock().expect("user-signing-key store mutex poisoned");
        Ok(g.iter()
            .filter(|k| &k.user == user && matches!(k.status, UserSigningKeyStatus::Active))
            .cloned()
            .collect())
    }
}

// ----------------------------------------------------------------------------
// Camp principal persistence.
// ----------------------------------------------------------------------------

/// One row in the camp-bootstrap-credential table.
///
/// The opaque `token` is a 32-byte CSPRNG secret encoded base64url-no-pad —
/// the camp presents this string to the future `/token` endpoint to mint
/// short-TTL access tokens. Stored verbatim (cheers retains the secret
/// because the camp must present it back; this is in contrast to the
/// service-principal Ed25519 secret which leaves cheers exactly once).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CampBootstrapCredential {
    pub token: String,
    /// The camp principal this credential authenticates for. `kind` is
    /// always [`PrincipalKind::Camp`]; the authority refuses to construct
    /// otherwise.
    pub camp_id: PrincipalId,
    pub created_at: i64,
    pub expires_at: i64,
    /// Set once the camp principal was revoked (cascade or direct).
    pub revoked: bool,
}

/// Provision input — what callers hand to [`CampAuthority::provision`].
///
/// `desired_id` becomes the bare half of `camp:<desired_id>`. The authority
/// refuses if a camp with that id already exists.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NewCampPrincipal {
    pub bound_to: PrincipalId,
    pub desired_id: String,
}

impl NewCampPrincipal {
    pub fn new(bound_to: PrincipalId, desired_id: impl Into<String>) -> Self {
        Self {
            bound_to,
            desired_id: desired_id.into(),
        }
    }
}

/// The output of a successful [`CampAuthority::provision`] call — the camp
/// principal record and the long-lived bootstrap credential the caller hands
/// to warden.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProvisionedCamp {
    pub principal: Principal,
    pub credential: CampBootstrapCredential,
}

/// Persistence for the camp-principal surface — principal records,
/// bootstrap credentials, and the retained delegation audit trail.
///
/// The trait is the **principal/credential/delegation** triple as one store
/// (one transactional surface): every provision inserts exactly one
/// principal row, one credential row, and one delegation row. Cascade
/// revocation is the only non-insert operation — a single sweep over the
/// principal table.
///
/// Time arguments are unix-seconds, signed — same shape as
/// [`OwnershipStore`](crate::OwnershipStore).
#[async_trait]
pub trait CampPrincipalStore: Send + Sync {
    /// Insert a fresh camp principal record. Returns [`StoreError::Conflict`]
    /// if the id already exists; the authority surfaces that as
    /// [`CampAuthorityError::AlreadyExists`].
    async fn insert_principal(&self, principal: &Principal) -> Result<(), StoreError>;

    /// Look up the camp principal record. `None` if no such principal
    /// exists.
    async fn get_principal(
        &self,
        id: &PrincipalId,
    ) -> Result<Option<Principal>, StoreError>;

    /// Insert a freshly-issued bootstrap credential. Returns
    /// [`StoreError::Conflict`] if `token` is already taken (the authority
    /// generates from a 256-bit CSPRNG, so collisions are
    /// cryptographically negligible).
    async fn insert_credential(&self, cred: &CampBootstrapCredential) -> Result<(), StoreError>;

    /// Look up a bootstrap credential by its opaque token. `None` if no
    /// such credential exists.
    async fn get_credential(
        &self,
        token: &str,
    ) -> Result<Option<CampBootstrapCredential>, StoreError>;

    /// Persist the user-signed delegation as the auditable "user U
    /// authorised camp C" record. The store is append-only for delegations:
    /// once written, the row is never modified (revocation rides on the
    /// principal, not the delegation).
    async fn insert_delegation(&self, delegation: &UserDelegation)
        -> Result<(), StoreError>;

    /// Cascade revoke — flip every camp principal whose `bound_to` matches
    /// `user` to [`Revoked`](PrincipalStatus::Revoked), and mark every
    /// associated bootstrap credential as `revoked = true`. Returns the
    /// count of camp principals newly revoked.
    ///
    /// Soundness rests on the column invariant: `bound_to` on a camp
    /// principal is always a user principal. A non-user input matches
    /// nothing.
    async fn revoke_camps_bound_to(
        &self,
        user: &PrincipalId,
        now: i64,
    ) -> Result<u64, StoreError>;
}

// ----------------------------------------------------------------------------
// MemoryCampPrincipalStore — test-only impl.
// ----------------------------------------------------------------------------

#[derive(Default, Clone, Debug)]
pub struct MemoryCampPrincipalStore {
    inner: Arc<Mutex<MemoryCampInner>>,
}

#[derive(Default, Debug)]
struct MemoryCampInner {
    principals: HashMap<PrincipalId, Principal>,
    credentials: HashMap<String, CampBootstrapCredential>,
    delegations: Vec<UserDelegation>,
}

impl MemoryCampPrincipalStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Test affordance — return every retained delegation in insertion order.
    /// The persistent impl exposes this through an audit-read endpoint
    /// (R020-F14); the memory impl just hands them back.
    pub fn delegations(&self) -> Vec<UserDelegation> {
        self.inner
            .lock()
            .expect("camp-principal store mutex poisoned")
            .delegations
            .clone()
    }
}

#[async_trait]
impl CampPrincipalStore for MemoryCampPrincipalStore {
    async fn insert_principal(&self, principal: &Principal) -> Result<(), StoreError> {
        let mut g = self.inner.lock().expect("camp-principal store mutex poisoned");
        if g.principals.contains_key(&principal.id) {
            return Err(StoreError::Conflict);
        }
        g.principals.insert(principal.id.clone(), principal.clone());
        Ok(())
    }

    async fn get_principal(
        &self,
        id: &PrincipalId,
    ) -> Result<Option<Principal>, StoreError> {
        let g = self.inner.lock().expect("camp-principal store mutex poisoned");
        Ok(g.principals.get(id).cloned())
    }

    async fn insert_credential(&self, cred: &CampBootstrapCredential) -> Result<(), StoreError> {
        let mut g = self.inner.lock().expect("camp-principal store mutex poisoned");
        if g.credentials.contains_key(&cred.token) {
            return Err(StoreError::Conflict);
        }
        g.credentials.insert(cred.token.clone(), cred.clone());
        Ok(())
    }

    async fn get_credential(
        &self,
        token: &str,
    ) -> Result<Option<CampBootstrapCredential>, StoreError> {
        let g = self.inner.lock().expect("camp-principal store mutex poisoned");
        Ok(g.credentials.get(token).cloned())
    }

    async fn insert_delegation(
        &self,
        delegation: &UserDelegation,
    ) -> Result<(), StoreError> {
        let mut g = self.inner.lock().expect("camp-principal store mutex poisoned");
        g.delegations.push(delegation.clone());
        Ok(())
    }

    async fn revoke_camps_bound_to(
        &self,
        user: &PrincipalId,
        _now: i64,
    ) -> Result<u64, StoreError> {
        let mut g = self.inner.lock().expect("camp-principal store mutex poisoned");
        let mut camp_ids: Vec<PrincipalId> = Vec::new();
        let mut newly_revoked = 0u64;
        for p in g.principals.values_mut() {
            if p.bound_to.as_ref() == Some(user) && p.status == PrincipalStatus::Active {
                p.status = PrincipalStatus::Revoked;
                camp_ids.push(p.id.clone());
                newly_revoked += 1;
            }
        }
        for cred in g.credentials.values_mut() {
            if camp_ids.contains(&cred.camp_id) {
                cred.revoked = true;
            }
        }
        Ok(newly_revoked)
    }
}

// ----------------------------------------------------------------------------
// CampAuthority — origin facade for provisioning + cascade revocation.
// ----------------------------------------------------------------------------

/// TTL defaults for a bootstrap credential.
///
/// Long-lived per `.yah/docs/working/mcp-auth-and-ownership.md` §TTLs — the
/// camp uses this credential to mint short-TTL access tokens for months/years,
/// and rotation (when added) registers a fresh credential alongside the old
/// one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CampBootstrapPolicy {
    pub credential_ttl_seconds: i64,
}

impl CampBootstrapPolicy {
    /// 1 year (365 days). The doc only commits to "long-lived"; one year is
    /// a defensible split between operator-rotation cadence and "rare enough
    /// to not be a hot path".
    pub const DEFAULT_CREDENTIAL_TTL_SECONDS: i64 = 365 * 24 * 60 * 60;

    pub fn new(credential_ttl_seconds: i64) -> Self {
        Self {
            credential_ttl_seconds,
        }
    }

    pub fn with_credential_ttl(mut self, seconds: i64) -> Self {
        self.credential_ttl_seconds = seconds;
        self
    }
}

impl Default for CampBootstrapPolicy {
    fn default() -> Self {
        Self {
            credential_ttl_seconds: Self::DEFAULT_CREDENTIAL_TTL_SECONDS,
        }
    }
}

/// Typed failure modes for [`CampAuthority`] operations.
///
/// HTTP layer maps these to status codes (camps route in `cheers-axum`):
/// `AlreadyExists` → 409, `InvalidDelegation` → 400, `UntrustedSigningKey` →
/// 401, `DelegationMismatch` / `DelegationExpired` → 400,
/// `BadSignature` → 401, `WrongPrincipalKind` → 500, `Store` → 500.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CampAuthorityError {
    /// A camp principal with the requested `desired_id` already exists.
    #[error("camp principal '{0}' already exists")]
    AlreadyExists(PrincipalId),
    /// `bound_to` (in [`NewCampPrincipal`]) is not a user principal — a
    /// programmer error, since the HTTP layer's parser would have caught it.
    #[error("camp-authority requires bound_to: kind=user; got {0}")]
    WrongPrincipalKind(PrincipalKind),
    /// The presented [`UserDelegation`] violates its own invariants
    /// (non-user `bound_to`, empty `camp_id`, …). Surfaces only when the
    /// caller pre-built a `UserDelegation` value through a path that
    /// bypassed [`UserDelegation::new`] — over the wire,
    /// [`UserDelegation`] deserialization runs the same check.
    #[error(transparent)]
    InvalidDelegation(#[from] DelegationError),
    /// The delegation's `bound_to` doesn't match the [`NewCampPrincipal::bound_to`],
    /// or its `camp_id` doesn't match `desired_id`. The delegation says "U
    /// authorises camp C"; if the provision request doesn't, the binding is
    /// not what was signed.
    #[error("delegation mismatch: {0}")]
    DelegationMismatch(&'static str),
    /// `delegation.expires_at <= now`.
    #[error("delegation expired (expires_at <= now)")]
    DelegationExpired,
    /// The delegation's `user_signing_key` is not in the trusted set for
    /// `bound_to` (no [`UserSigningKey`] row, or the matching row is
    /// `Revoked`).
    #[error("untrusted user signing key for {0}")]
    UntrustedSigningKey(PrincipalId),
    /// Ed25519 signature failed to verify under the supplied
    /// `user_signing_key`.
    #[error("bad delegation signature")]
    BadSignature,
    /// Programmer error reaching the authority with a non-camp principal id
    /// for cascade revoke / similar — bubbles
    /// [`PrincipalError`](cheers_core::PrincipalError).
    #[error(transparent)]
    Principal(#[from] PrincipalError),
    /// Underlying store failure.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Origin-side facade for camp-principal provisioning + cascade revocation.
///
/// Generic over the [`CampPrincipalStore`] and [`UserSigningKeyStore`] impls
/// (not `dyn`) so the assembled deployment surfaces in the type. Holds a
/// [`CampBootstrapPolicy`] so the credential TTL is set at construction.
pub struct CampAuthority<S, K> {
    store: S,
    signing_keys: K,
    policy: CampBootstrapPolicy,
}

impl<S, K> std::fmt::Debug for CampAuthority<S, K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CampAuthority")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl<S, K> CampAuthority<S, K>
where
    S: CampPrincipalStore,
    K: UserSigningKeyStore,
{
    pub fn new(store: S, signing_keys: K) -> Self {
        Self {
            store,
            signing_keys,
            policy: CampBootstrapPolicy::default(),
        }
    }

    pub fn with_policy(mut self, policy: CampBootstrapPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn policy(&self) -> &CampBootstrapPolicy {
        &self.policy
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn signing_keys(&self) -> &K {
        &self.signing_keys
    }

    /// Provision a camp principal on behalf of a user.
    ///
    /// Steps in order — any failure aborts before the next side-effect:
    ///
    /// 1. Validate `input.bound_to.kind == User`.
    /// 2. Validate the delegation matches the provision request
    ///    (`bound_to`, `camp_id`).
    /// 3. Reject an expired delegation (`expires_at <= now`).
    /// 4. Look up the trusted Ed25519 keys for `bound_to`. Reject if
    ///    `delegation.user_signing_key` is not in that set.
    /// 5. Verify the Ed25519 signature over [`UserDelegation::signing_payload`].
    /// 6. Build the [`Principal`] (kind=Camp, bound_to=Some(user)) via
    ///    [`Principal::try_new`].
    /// 7. Insert the principal, retain the delegation as audit, generate a
    ///    fresh CSPRNG bootstrap credential, persist + return it.
    pub async fn provision(
        &self,
        input: NewCampPrincipal,
        delegation: UserDelegation,
        now: i64,
    ) -> Result<ProvisionedCamp, CampAuthorityError> {
        if input.bound_to.kind != PrincipalKind::User {
            return Err(CampAuthorityError::WrongPrincipalKind(input.bound_to.kind));
        }
        if delegation.bound_to != input.bound_to {
            return Err(CampAuthorityError::DelegationMismatch(
                "delegation.bound_to does not match provision.bound_to",
            ));
        }
        if delegation.camp_id != input.desired_id {
            return Err(CampAuthorityError::DelegationMismatch(
                "delegation.camp_id does not match provision.desired_id",
            ));
        }
        if delegation.is_expired_at(now) {
            return Err(CampAuthorityError::DelegationExpired);
        }

        let trusted = self
            .signing_keys
            .list_active_for_user(&delegation.bound_to)
            .await?;
        if !trusted
            .iter()
            .any(|k| k.public_key == delegation.user_signing_key)
        {
            return Err(CampAuthorityError::UntrustedSigningKey(
                delegation.bound_to.clone(),
            ));
        }

        verify_delegation_signature(&delegation)?;

        let camp_id = PrincipalId::camp(input.desired_id.clone());
        let principal = Principal::try_new(
            camp_id.clone(),
            Some(input.bound_to.clone()),
            PrincipalStatus::Active,
            now,
        )?;
        match self.store.insert_principal(&principal).await {
            Ok(()) => {}
            Err(StoreError::Conflict) => {
                return Err(CampAuthorityError::AlreadyExists(camp_id));
            }
            Err(other) => return Err(other.into()),
        }
        self.store.insert_delegation(&delegation).await?;

        let credential = CampBootstrapCredential {
            token: mint_credential_token(),
            camp_id: camp_id.clone(),
            created_at: now,
            expires_at: now + self.policy.credential_ttl_seconds,
            revoked: false,
        };
        self.store.insert_credential(&credential).await?;

        Ok(ProvisionedCamp {
            principal,
            credential,
        })
    }

    /// Cascade revoke — flip every camp principal `bound_to = user` to
    /// `Revoked` and mark their bootstrap credentials revoked. Idempotent:
    /// calling repeatedly returns 0 after the first sweep.
    ///
    /// Returns [`CampAuthorityError::WrongPrincipalKind`] if `user.kind` is
    /// not `User` — protects against accidentally cascading a service /
    /// camp principal (which the store query would silently no-op on).
    pub async fn revoke_user_cascade(
        &self,
        user: &PrincipalId,
        now: i64,
    ) -> Result<u64, CampAuthorityError> {
        if user.kind != PrincipalKind::User {
            return Err(CampAuthorityError::WrongPrincipalKind(user.kind));
        }
        Ok(self.store.revoke_camps_bound_to(user, now).await?)
    }
}

/// Verify the Ed25519 signature carried in `delegation`.
///
/// The delegation embeds the pubkey the signature should verify under; the
/// CALLER (the authority) is responsible for proving that pubkey is trusted
/// for `delegation.bound_to` before invoking this — this function is the
/// pure crypto step.
fn verify_delegation_signature(
    delegation: &UserDelegation,
) -> Result<(), CampAuthorityError> {
    use ed25519_compact::{PublicKey, Signature};

    let pk = PublicKey::from_slice(&delegation.user_signing_key)
        .map_err(|_| CampAuthorityError::BadSignature)?;
    let sig = Signature::from_slice(&delegation.signature)
        .map_err(|_| CampAuthorityError::BadSignature)?;
    let payload = delegation.signing_payload();
    pk.verify(&payload, &sig)
        .map_err(|_| CampAuthorityError::BadSignature)
}

/// 256-bit base64url-no-pad CSPRNG secret. Matches the entropy of the
/// refresh-token primitive in `refresh.rs`.
fn mint_credential_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS CSPRNG must be available");
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_compact::{KeyPair, Seed};
    use pollster::block_on;

    fn keypair_from_seed(seed: u8) -> KeyPair {
        KeyPair::from_seed(Seed::from_slice(&[seed; 32]).unwrap())
    }

    fn signed_delegation(
        kp: &KeyPair,
        bound_to: PrincipalId,
        camp_id: &str,
        issued_at: i64,
        expires_at: i64,
    ) -> UserDelegation {
        // Build with a placeholder signature, then re-sign over the canonical
        // payload — same flow a real signer (W122 client) would follow.
        let unsigned = UserDelegation::new(
            bound_to,
            camp_id,
            issued_at,
            expires_at,
            *kp.pk,
            [0u8; 64],
        )
        .unwrap();
        let payload = unsigned.signing_payload();
        let sig = kp.sk.sign(&payload, None);
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(sig.as_ref());
        UserDelegation::new(
            unsigned.bound_to,
            unsigned.camp_id,
            unsigned.issued_at,
            unsigned.expires_at,
            unsigned.user_signing_key,
            bytes,
        )
        .unwrap()
    }

    fn trust_key(store: &MemoryUserSigningKeyStore, user: &PrincipalId, pubkey: [u8; 32]) {
        store.insert(UserSigningKey {
            kid: "test-key".into(),
            user: user.clone(),
            public_key: pubkey,
            status: UserSigningKeyStatus::Active,
            created_at: 0,
        });
    }

    fn rig() -> (
        CampAuthority<MemoryCampPrincipalStore, MemoryUserSigningKeyStore>,
        MemoryCampPrincipalStore,
        MemoryUserSigningKeyStore,
    ) {
        let store = MemoryCampPrincipalStore::new();
        let keys = MemoryUserSigningKeyStore::new();
        let authority = CampAuthority::new(store.clone(), keys.clone());
        (authority, store, keys)
    }

    // ---- policy -----------------------------------------------------------

    #[test]
    fn policy_default_is_one_year() {
        let p = CampBootstrapPolicy::default();
        assert_eq!(p.credential_ttl_seconds, 365 * 24 * 60 * 60);
        let p = CampBootstrapPolicy::new(60).with_credential_ttl(120);
        assert_eq!(p.credential_ttl_seconds, 120);
    }

    // ---- provision: happy path --------------------------------------------

    #[test]
    fn provision_happy_path_allocates_camp_and_credential() {
        let (authority, store, keys) = rig();
        let user = PrincipalId::user("alice");
        let kp = keypair_from_seed(1);
        trust_key(&keys, &user, *kp.pk);

        let delegation =
            signed_delegation(&kp, user.clone(), "camp-xyz", 1_000, 1_600);

        block_on(async {
            let prov = authority
                .provision(
                    NewCampPrincipal::new(user.clone(), "camp-xyz"),
                    delegation.clone(),
                    1_100,
                )
                .await
                .unwrap();

            // Camp principal carries the right shape.
            assert_eq!(prov.principal.id, PrincipalId::camp("camp-xyz"));
            assert_eq!(prov.principal.bound_to.as_ref(), Some(&user));
            assert_eq!(prov.principal.status, PrincipalStatus::Active);
            assert_eq!(prov.principal.created_at, 1_100);

            // Bootstrap credential carries a non-empty token + correct expiry.
            assert_eq!(prov.credential.camp_id, PrincipalId::camp("camp-xyz"));
            assert!(!prov.credential.token.is_empty());
            assert_eq!(prov.credential.created_at, 1_100);
            assert_eq!(
                prov.credential.expires_at,
                1_100 + CampBootstrapPolicy::DEFAULT_CREDENTIAL_TTL_SECONDS
            );
            assert!(!prov.credential.revoked);

            // Store side-effects.
            let stored_principal = store
                .get_principal(&PrincipalId::camp("camp-xyz"))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(stored_principal, prov.principal);

            let stored_cred = store
                .get_credential(&prov.credential.token)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(stored_cred, prov.credential);

            // Delegation retained for audit.
            assert_eq!(store.delegations(), vec![delegation]);
        });
    }

    #[test]
    fn provision_secret_token_decodes_to_32_bytes() {
        let (authority, _store, keys) = rig();
        let user = PrincipalId::user("alice");
        let kp = keypair_from_seed(2);
        trust_key(&keys, &user, *kp.pk);
        let delegation =
            signed_delegation(&kp, user.clone(), "camp-a", 1_000, 1_600);

        block_on(async {
            let prov = authority
                .provision(
                    NewCampPrincipal::new(user, "camp-a"),
                    delegation,
                    1_100,
                )
                .await
                .unwrap();
            let raw = URL_SAFE_NO_PAD
                .decode(prov.credential.token.as_bytes())
                .unwrap();
            assert_eq!(raw.len(), 32, "credential token is a 256-bit secret");
        });
    }

    #[test]
    fn provision_two_camps_for_same_user_succeed_with_distinct_ids() {
        let (authority, _, keys) = rig();
        let user = PrincipalId::user("alice");
        let kp = keypair_from_seed(3);
        trust_key(&keys, &user, *kp.pk);

        block_on(async {
            for camp in ["camp-one", "camp-two"] {
                let d = signed_delegation(&kp, user.clone(), camp, 1_000, 1_600);
                authority
                    .provision(
                        NewCampPrincipal::new(user.clone(), camp),
                        d,
                        1_100,
                    )
                    .await
                    .unwrap();
            }
        });
    }

    // ---- provision: rejection paths ---------------------------------------

    #[test]
    fn provision_rejects_non_user_bound_to_at_authority_boundary() {
        // Wrong-kind bound_to is a programmer error — the HTTP layer would
        // catch it earlier, but the authority is the last line of defense.
        let (authority, _, _) = rig();
        let kp = keypair_from_seed(4);
        // Build a delegation that bypasses UserDelegation::new (we go through
        // it but the authority sees a mismatched NewCampPrincipal.bound_to —
        // the test below covers that). Here the authority itself runs the
        // kind check first.
        let user = PrincipalId::user("alice");
        let d = signed_delegation(&kp, user.clone(), "c", 1_000, 1_600);

        block_on(async {
            let err = authority
                .provision(
                    NewCampPrincipal::new(PrincipalId::service("svc"), "c"),
                    d,
                    1_100,
                )
                .await
                .unwrap_err();
            match err {
                CampAuthorityError::WrongPrincipalKind(k) => {
                    assert_eq!(k, PrincipalKind::Service);
                }
                other => panic!("expected WrongPrincipalKind, got {other:?}"),
            }
        });
    }

    #[test]
    fn provision_rejects_delegation_bound_to_mismatch() {
        let (authority, _, keys) = rig();
        let user_a = PrincipalId::user("alice");
        let user_b = PrincipalId::user("bob");
        let kp = keypair_from_seed(5);
        // Trust kp for BOTH users — so the rejection is the bound_to mismatch
        // alone, not a missing trust binding.
        trust_key(&keys, &user_a, *kp.pk);
        trust_key(&keys, &user_b, *kp.pk);
        // Delegation says bob authorises camp-x.
        let d = signed_delegation(&kp, user_b.clone(), "camp-x", 1_000, 1_600);

        block_on(async {
            // Provision request says alice authorises camp-x.
            let err = authority
                .provision(
                    NewCampPrincipal::new(user_a.clone(), "camp-x"),
                    d,
                    1_100,
                )
                .await
                .unwrap_err();
            assert!(
                matches!(err, CampAuthorityError::DelegationMismatch(msg) if msg.contains("bound_to")),
                "got {err:?}"
            );
        });
    }

    #[test]
    fn provision_rejects_delegation_camp_id_mismatch() {
        let (authority, _, keys) = rig();
        let user = PrincipalId::user("alice");
        let kp = keypair_from_seed(6);
        trust_key(&keys, &user, *kp.pk);
        // Delegation says alice authorises camp-x …
        let d = signed_delegation(&kp, user.clone(), "camp-x", 1_000, 1_600);

        block_on(async {
            // … but the provision request asks for camp-y.
            let err = authority
                .provision(
                    NewCampPrincipal::new(user, "camp-y"),
                    d,
                    1_100,
                )
                .await
                .unwrap_err();
            assert!(
                matches!(err, CampAuthorityError::DelegationMismatch(msg) if msg.contains("camp_id")),
                "got {err:?}"
            );
        });
    }

    #[test]
    fn provision_rejects_expired_delegation() {
        let (authority, _, keys) = rig();
        let user = PrincipalId::user("alice");
        let kp = keypair_from_seed(7);
        trust_key(&keys, &user, *kp.pk);
        let d = signed_delegation(&kp, user.clone(), "c", 1_000, 1_600);

        block_on(async {
            let err = authority
                .provision(NewCampPrincipal::new(user, "c"), d, 1_600)
                .await
                .unwrap_err();
            assert!(matches!(err, CampAuthorityError::DelegationExpired), "got {err:?}");
        });
    }

    #[test]
    fn provision_rejects_untrusted_signing_key() {
        let (authority, _, _keys) = rig();
        let user = PrincipalId::user("alice");
        let kp = keypair_from_seed(8);
        // Deliberately do NOT register kp.pk as trusted for alice.
        let d = signed_delegation(&kp, user.clone(), "c", 1_000, 1_600);

        block_on(async {
            let err = authority
                .provision(NewCampPrincipal::new(user.clone(), "c"), d, 1_100)
                .await
                .unwrap_err();
            match err {
                CampAuthorityError::UntrustedSigningKey(u) => assert_eq!(u, user),
                other => panic!("expected UntrustedSigningKey, got {other:?}"),
            }
        });
    }

    #[test]
    fn provision_rejects_revoked_signing_key() {
        // A trust-key row exists but with status=Revoked — must NOT verify.
        let (authority, _, keys) = rig();
        let user = PrincipalId::user("alice");
        let kp = keypair_from_seed(9);
        keys.insert(UserSigningKey {
            kid: "stale".into(),
            user: user.clone(),
            public_key: *kp.pk,
            status: UserSigningKeyStatus::Revoked,
            created_at: 0,
        });
        let d = signed_delegation(&kp, user.clone(), "c", 1_000, 1_600);

        block_on(async {
            let err = authority
                .provision(NewCampPrincipal::new(user, "c"), d, 1_100)
                .await
                .unwrap_err();
            assert!(matches!(err, CampAuthorityError::UntrustedSigningKey(_)), "got {err:?}");
        });
    }

    #[test]
    fn provision_rejects_bad_signature() {
        let (authority, _, keys) = rig();
        let user = PrincipalId::user("alice");
        let kp = keypair_from_seed(10);
        trust_key(&keys, &user, *kp.pk);

        // Build a properly-signed delegation, then mutate the signed bytes —
        // pubkey trust check still passes, signature verify must fail.
        let mut d = signed_delegation(&kp, user.clone(), "c", 1_000, 1_600);
        d.signature[0] ^= 0x01;

        block_on(async {
            let err = authority
                .provision(NewCampPrincipal::new(user, "c"), d, 1_100)
                .await
                .unwrap_err();
            assert!(matches!(err, CampAuthorityError::BadSignature), "got {err:?}");
        });
    }

    #[test]
    fn provision_rejects_signature_from_other_keypair_in_trusted_set() {
        // The supplied pubkey IS trusted, but the signature was made by a
        // DIFFERENT key. Subtle attack: smuggle a trusted pubkey alongside a
        // forged signature. verify_delegation_signature catches it because
        // the signature doesn't validate under the embedded pubkey.
        let (authority, _, keys) = rig();
        let user = PrincipalId::user("alice");
        let kp_trusted = keypair_from_seed(11);
        let kp_other = keypair_from_seed(12);
        trust_key(&keys, &user, *kp_trusted.pk);

        // Sign with kp_other, claim the pubkey is kp_trusted's.
        let payload_d = UserDelegation::new(
            user.clone(),
            "c",
            1_000,
            1_600,
            *kp_trusted.pk,
            [0u8; 64],
        )
        .unwrap();
        let sig = kp_other.sk.sign(&payload_d.signing_payload(), None);
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(sig.as_ref());
        let forged = UserDelegation::new(
            payload_d.bound_to,
            payload_d.camp_id,
            payload_d.issued_at,
            payload_d.expires_at,
            payload_d.user_signing_key,
            sig_bytes,
        )
        .unwrap();

        block_on(async {
            let err = authority
                .provision(NewCampPrincipal::new(user, "c"), forged, 1_100)
                .await
                .unwrap_err();
            assert!(matches!(err, CampAuthorityError::BadSignature), "got {err:?}");
        });
    }

    #[test]
    fn provision_rejects_duplicate_camp_id() {
        let (authority, _, keys) = rig();
        let user = PrincipalId::user("alice");
        let kp = keypair_from_seed(13);
        trust_key(&keys, &user, *kp.pk);

        block_on(async {
            let d = signed_delegation(&kp, user.clone(), "dup", 1_000, 1_600);
            authority
                .provision(
                    NewCampPrincipal::new(user.clone(), "dup"),
                    d.clone(),
                    1_100,
                )
                .await
                .unwrap();
            let err = authority
                .provision(NewCampPrincipal::new(user, "dup"), d, 1_100)
                .await
                .unwrap_err();
            match err {
                CampAuthorityError::AlreadyExists(id) => {
                    assert_eq!(id, PrincipalId::camp("dup"));
                }
                other => panic!("expected AlreadyExists, got {other:?}"),
            }
        });
    }

    // ---- cascade revoke ---------------------------------------------------

    #[test]
    fn revoke_user_cascade_flips_only_camps_bound_to_that_user() {
        let (authority, store, keys) = rig();
        let alice = PrincipalId::user("alice");
        let bob = PrincipalId::user("bob");
        let kp_a = keypair_from_seed(20);
        let kp_b = keypair_from_seed(21);
        trust_key(&keys, &alice, *kp_a.pk);
        trust_key(&keys, &bob, *kp_b.pk);

        block_on(async {
            // Two camps for alice, one for bob.
            for camp in ["a-1", "a-2"] {
                let d = signed_delegation(&kp_a, alice.clone(), camp, 1_000, 1_600);
                authority
                    .provision(NewCampPrincipal::new(alice.clone(), camp), d, 1_100)
                    .await
                    .unwrap();
            }
            let d = signed_delegation(&kp_b, bob.clone(), "b-1", 1_000, 1_600);
            let b1 = authority
                .provision(NewCampPrincipal::new(bob.clone(), "b-1"), d, 1_100)
                .await
                .unwrap();

            // Revoke alice — both alice camps flip, bob's stays Active.
            let count = authority.revoke_user_cascade(&alice, 2_000).await.unwrap();
            assert_eq!(count, 2);

            for camp in ["a-1", "a-2"] {
                let p = store
                    .get_principal(&PrincipalId::camp(camp))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(p.status, PrincipalStatus::Revoked);
            }
            let bob_camp = store
                .get_principal(&PrincipalId::camp("b-1"))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(bob_camp.status, PrincipalStatus::Active);

            // bob's credential is unchanged.
            let bob_cred = store
                .get_credential(&b1.credential.token)
                .await
                .unwrap()
                .unwrap();
            assert!(!bob_cred.revoked);
        });
    }

    #[test]
    fn revoke_user_cascade_is_idempotent() {
        let (authority, _, keys) = rig();
        let user = PrincipalId::user("alice");
        let kp = keypair_from_seed(30);
        trust_key(&keys, &user, *kp.pk);

        block_on(async {
            let d = signed_delegation(&kp, user.clone(), "c", 1_000, 1_600);
            authority
                .provision(NewCampPrincipal::new(user.clone(), "c"), d, 1_100)
                .await
                .unwrap();

            let first = authority.revoke_user_cascade(&user, 2_000).await.unwrap();
            let second = authority.revoke_user_cascade(&user, 2_001).await.unwrap();
            assert_eq!(first, 1);
            assert_eq!(second, 0, "second sweep is a no-op");
        });
    }

    #[test]
    fn revoke_user_cascade_revokes_associated_credentials() {
        let (authority, store, keys) = rig();
        let user = PrincipalId::user("alice");
        let kp = keypair_from_seed(31);
        trust_key(&keys, &user, *kp.pk);

        block_on(async {
            let d = signed_delegation(&kp, user.clone(), "c", 1_000, 1_600);
            let prov = authority
                .provision(NewCampPrincipal::new(user.clone(), "c"), d, 1_100)
                .await
                .unwrap();
            assert!(!prov.credential.revoked);

            authority.revoke_user_cascade(&user, 2_000).await.unwrap();

            let cred = store
                .get_credential(&prov.credential.token)
                .await
                .unwrap()
                .unwrap();
            assert!(cred.revoked, "cascade must mark the credential revoked too");
        });
    }

    #[test]
    fn revoke_user_cascade_rejects_non_user_kind() {
        let (authority, _, _) = rig();
        block_on(async {
            let err = authority
                .revoke_user_cascade(&PrincipalId::service("warden"), 1_000)
                .await
                .unwrap_err();
            match err {
                CampAuthorityError::WrongPrincipalKind(k) => {
                    assert_eq!(k, PrincipalKind::Service);
                }
                other => panic!("expected WrongPrincipalKind, got {other:?}"),
            }
        });
    }

    // ---- trait dyn-compat -------------------------------------------------

    #[test]
    fn traits_are_dyn_compatible() {
        fn _s(_: &dyn CampPrincipalStore) {}
        fn _k(_: &dyn UserSigningKeyStore) {}
    }

    // ---- serde ------------------------------------------------------------

    #[test]
    fn user_signing_key_roundtrips_through_json_with_base64_pubkey() {
        let key = UserSigningKey {
            kid: "kid-1".into(),
            user: PrincipalId::user("alice"),
            public_key: [3u8; 32],
            status: UserSigningKeyStatus::Active,
            created_at: 100,
        };
        let json = serde_json::to_string(&key).unwrap();
        assert!(json.contains("\"public_key\":\""));
        assert!(!json.contains("[3,3,3"), "must NOT be a byte array: {json}");
        let back: UserSigningKey = serde_json::from_str(&json).unwrap();
        assert_eq!(back, key);
    }

    #[test]
    fn camp_bootstrap_credential_roundtrips_json() {
        let cred = CampBootstrapCredential {
            token: "tok-1".into(),
            camp_id: PrincipalId::camp("c-1"),
            created_at: 100,
            expires_at: 200,
            revoked: false,
        };
        let json = serde_json::to_string(&cred).unwrap();
        let back: CampBootstrapCredential = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cred);
    }
}
