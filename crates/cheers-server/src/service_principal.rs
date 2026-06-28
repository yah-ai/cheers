//! Service-principal lifecycle — provisioning, rotation, key publication.
//!
//! See `.yah/docs/working/mcp-auth-and-ownership.md` §Service principal
//! bootstrap for the install-time contract this implements:
//!
//! 1. An operator-authenticated `POST /admin/service-principals` call
//!    (HTTP layer is a peer ticket) provides a `desired_id` and the operator's
//!    intended grants. Cheers allocates the [`Principal`] record, generates a
//!    fresh Ed25519 keypair, persists the public half (kid'd, status=active),
//!    and returns the **secret half exactly once** in the `ProvisionedKey`.
//! 2. The consumer (yubaba) stores the secret in its config dir (mode 0600)
//!    and mints its own short-lived MCP tokens from that keypair. Cheers
//!    verifies those tokens via the JWKS endpoint (R020-F11) that publishes
//!    the principal's public key alongside cheers's own signing keys.
//! 3. Rotation registers a fresh keypair without invalidating in-flight
//!    tokens: the previously-active key flips to `Retiring` with
//!    `retire_at = now + overlap_seconds` (default 24 h, per
//!    [`OverlapPolicy`]). The JWKS keeps publishing the retiring key until
//!    `retire_at`, then [`prune_retired_keys`](ServicePrincipalAuthority::prune_retired_keys)
//!    drops it.
//!
//! The crate-direction invariant from R019 still holds: this module is
//! origin-only (it generates secret keys). The verify-side (kamaji, CF
//! Worker) never depends on `cheers-server` and never sees a
//! [`PasetoV4SecretMinter`] — it links `cheers-verify` and consumes the public
//! halves via JWKS.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use cheers_core::{
    CodecError, Principal, PrincipalError, PrincipalId, PrincipalKind, PrincipalStatus, StoreError,
};

use crate::codec::PasetoV4SecretMinter;

/// Lifecycle state of a signing key inside cheers's published JWKS.
///
/// `Active` keys are the ones cheers verifies tokens against without
/// caveat. `Retiring` keys are still served in the JWKS (because in-flight
/// tokens signed under them must still verify) but no consumer should mint
/// new tokens with them — once `retire_at` has passed,
/// [`prune_retired_keys`](ServicePrincipalAuthority::prune_retired_keys)
/// drops them from the table and the next JWKS publication no longer
/// includes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum SigningKeyStatus {
    Active,
    Retiring,
}

/// One Ed25519 keypair (public half + lifecycle metadata) belonging to a
/// service principal.
///
/// `public_key` is the raw 32-byte Ed25519 public key (PASETO V4's
/// `AsymmetricPublicKey<V4>::as_bytes()` shape). It is the only key half cheers
/// retains: the secret half is returned exactly once at provision/rotate time
/// in [`ProvisionedKey::secret_key`] and never again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SigningKey {
    /// Stable opaque identifier — the JWKS rotation handle. Unique across
    /// the JWKS (not just within one principal); kamaji matches against
    /// `kid` and falls back to a rate-limited refresh on unknown values.
    pub kid: String,
    /// Service principal this key signs for. `kind` is always
    /// [`PrincipalKind::Service`] — provision/rotate refuse other kinds at
    /// the authority layer.
    pub principal_id: PrincipalId,
    /// Raw Ed25519 public key — 32 bytes. Serialized to the JWKS as
    /// base64url; in this struct kept as the byte array so a JWKS publisher
    /// (R020-F11) doesn't have to re-decode.
    #[serde(with = "public_key_serde")]
    pub public_key: [u8; 32],
    pub status: SigningKeyStatus,
    pub created_at: i64,
    /// `None` while the key is `Active`. Set to the unix-second drop time
    /// when the key transitions to `Retiring` —
    /// [`prune_retired_keys`](ServicePrincipalAuthority::prune_retired_keys)
    /// removes rows whose `retire_at <= now`.
    pub retire_at: Option<i64>,
}

impl SigningKey {
    /// Build a [`SigningKey`] from its persisted parts.
    ///
    /// Provided so external [`ServicePrincipalStore`] impls (cheers-sqlx,
    /// cheers-redis, …) can reconstruct rows without depending on the
    /// `#[non_exhaustive]` struct expression — that compiles only from
    /// inside this crate.
    pub fn new(
        kid: impl Into<String>,
        principal_id: PrincipalId,
        public_key: [u8; 32],
        status: SigningKeyStatus,
        created_at: i64,
        retire_at: Option<i64>,
    ) -> Self {
        Self {
            kid: kid.into(),
            principal_id,
            public_key,
            status,
            created_at,
            retire_at,
        }
    }
}

/// Custom serde: the raw 32-byte Ed25519 public key rides on the wire as a
/// base64url-no-pad string. Keeps the JSON shape readable and matches the
/// JWKS key encoding R020-F11 will publish.
mod public_key_serde {
    use super::*;
    use serde::de::Error as DeError;

    pub fn serialize<S: serde::Serializer>(bytes: &[u8; 32], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(de: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(de)?;
        let decoded = URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map_err(|e| D::Error::custom(format!("invalid base64url public_key: {e}")))?;
        decoded
            .try_into()
            .map_err(|v: Vec<u8>| D::Error::custom(format!("expected 32 public_key bytes, got {}", v.len())))
    }
}

/// Provision input — what the operator hands to
/// [`ServicePrincipalAuthority::provision`].
///
/// `desired_id` becomes the bare id half of `svc:<desired_id>`. The
/// authority refuses if a principal with that id already exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct NewServicePrincipal {
    pub desired_id: String,
}

impl NewServicePrincipal {
    pub fn new(desired_id: impl Into<String>) -> Self {
        Self {
            desired_id: desired_id.into(),
        }
    }
}

/// The output of a provision or rotate call — the **only** time cheers
/// hands out a secret half.
///
/// `secret_key` is the 64-byte PASETO V4 `seed || public` layout. The caller
/// (yubaba install flow) writes it to its config dir (mode 0600). Cheers
/// retains nothing of it: the matching pubkey lives in [`SigningKey`] and a
/// lost secret is unrecoverable — the recovery path is to rotate and accept
/// a new keypair.
#[derive(Clone)]
#[non_exhaustive]
pub struct ProvisionedKey {
    pub principal: Principal,
    pub signing_key: SigningKey,
    pub secret_key: [u8; 64],
}

impl std::fmt::Debug for ProvisionedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the secret bytes.
        f.debug_struct("ProvisionedKey")
            .field("principal", &self.principal)
            .field("signing_key", &self.signing_key)
            .field("secret_key", &"***OMITTED***")
            .finish()
    }
}

/// Rotation policy — how long a retiring key keeps verifying in-flight
/// tokens before [`prune_retired_keys`](ServicePrincipalAuthority::prune_retired_keys)
/// drops it.
///
/// Default 24 h matches the doc's `service_overlap_window` knob. Longer
/// overlaps tolerate slower JWKS-cache propagation at the cost of a wider
/// window in which a leaked old secret could still mint accepted tokens —
/// pick to taste.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct OverlapPolicy {
    pub overlap_seconds: i64,
}

impl OverlapPolicy {
    /// 24 hours.
    pub const DEFAULT_OVERLAP_SECONDS: i64 = 24 * 60 * 60;

    pub fn new(overlap_seconds: i64) -> Self {
        Self { overlap_seconds }
    }

    pub fn with_overlap_seconds(mut self, seconds: i64) -> Self {
        self.overlap_seconds = seconds;
        self
    }
}

impl Default for OverlapPolicy {
    fn default() -> Self {
        Self {
            overlap_seconds: Self::DEFAULT_OVERLAP_SECONDS,
        }
    }
}

/// Typed failure modes for [`ServicePrincipalAuthority`] operations.
///
/// HTTP layer (peer ticket) maps these to status codes: `AlreadyExists` →
/// 409, `UnknownPrincipal` → 404, `WrongPrincipalKind` → 500 (programmer
/// error reaching the authority with a non-service id), `NoActiveKey` →
/// 500 (data integrity — every provisioned principal MUST have at least
/// one active key), `Codec` → 500, `Principal`/`Store` → bubble.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ServicePrincipalError {
    /// A principal with the requested `desired_id` already exists.
    #[error("service principal '{0}' already exists")]
    AlreadyExists(PrincipalId),
    /// `rotate` (or a JWKS lookup) named a principal cheers doesn't know.
    #[error("unknown service principal '{0}'")]
    UnknownPrincipal(PrincipalId),
    /// The id handed to provision/rotate wasn't a service kind. Bubbles up
    /// the underlying [`PrincipalError`].
    #[error(transparent)]
    Principal(#[from] PrincipalError),
    /// `kind` on the principal id was something other than `Service`.
    #[error("service-principal authority requires kind=service; got {0}")]
    WrongPrincipalKind(PrincipalKind),
    /// `rotate` ran against a principal with no `Active` key. Indicates a
    /// data-integrity break (every provision must seed one) — not a normal
    /// user-input failure.
    #[error("service principal '{0}' has no active signing key")]
    NoActiveKey(PrincipalId),
    /// Keypair generation failed inside the codec layer.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// Underlying store failure.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Persistence for service-principal records and their signing keys.
///
/// The store is `principal × signing_keys` normalised — one row per
/// principal in the principals table, many rows per principal in the
/// signing-keys table. The two are coupled at the authority layer rather
/// than via FK at the store layer: the trait lets a backend pick the
/// representation (one table joined, two tables, key-value collection) so
/// long as the visible semantics hold.
///
/// Time arguments are unix-seconds, signed — same shape as
/// [`OwnershipStore`](crate::OwnershipStore).
#[async_trait]
pub trait ServicePrincipalStore: Send + Sync {
    /// Insert a fresh principal record. Returns [`StoreError::Conflict`] if
    /// the id already exists; the authority surfaces that as
    /// [`ServicePrincipalError::AlreadyExists`].
    async fn insert_principal(&self, principal: &Principal) -> Result<(), StoreError>;

    /// Look up the principal record. `None` if no such principal exists.
    async fn get_principal(
        &self,
        id: &PrincipalId,
    ) -> Result<Option<Principal>, StoreError>;

    /// Insert a freshly-generated signing key. Returns
    /// [`StoreError::Conflict`] if the kid is already taken (kids are
    /// globally unique across the JWKS).
    async fn insert_signing_key(&self, key: &SigningKey) -> Result<(), StoreError>;

    /// All signing keys (active + retiring) owned by `principal`. Order is
    /// unspecified — the authority filters and orders as it needs.
    async fn list_signing_keys(
        &self,
        principal: &PrincipalId,
    ) -> Result<Vec<SigningKey>, StoreError>;

    /// All signing keys in the table (across every principal), regardless
    /// of status. The JWKS publication path filters these by
    /// `Active OR (Retiring AND retire_at > now)`.
    async fn list_all_signing_keys(&self) -> Result<Vec<SigningKey>, StoreError>;

    /// Flip the key identified by `kid` to `Retiring` with the supplied
    /// `retire_at`. Returns [`StoreError::NotFound`] when the kid is
    /// unknown; idempotent if the key is already retiring (overwrites the
    /// existing `retire_at`).
    async fn retire_signing_key(
        &self,
        kid: &str,
        retire_at: i64,
    ) -> Result<(), StoreError>;

    /// Permanently drop every signing key whose status is `Retiring` and
    /// whose `retire_at <= now`. Returns the count dropped.
    ///
    /// Idempotent — calling repeatedly with the same `now` returns 0 after
    /// the first sweep. Active keys are never touched, irrespective of
    /// their `created_at`.
    async fn prune_retired_keys(&self, now: i64) -> Result<u64, StoreError>;
}

/// Origin-side facade: provision new service principals + rotate existing
/// ones + publish the live JWKS material.
///
/// Generic over the [`ServicePrincipalStore`] impl (not `dyn`) so the
/// assembled deployment surfaces in the type. Holds an [`OverlapPolicy`] so
/// the rotation window is set at construction; deployments wanting a
/// non-default value call [`with_policy`](Self::with_policy).
///
/// The authority deliberately doesn't hold a [`PasetoV4SecretMinter`] — it
/// generates a *fresh* minter inside provision/rotate, hands the secret
/// back through [`ProvisionedKey::secret_key`] once, and drops it on the
/// floor. Cheers retains nothing of the secret half.
pub struct ServicePrincipalAuthority<S> {
    store: S,
    policy: OverlapPolicy,
}

impl<S> std::fmt::Debug for ServicePrincipalAuthority<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServicePrincipalAuthority")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl<S> ServicePrincipalAuthority<S>
where
    S: ServicePrincipalStore,
{
    pub fn new(store: S) -> Self {
        Self {
            store,
            policy: OverlapPolicy::default(),
        }
    }

    pub fn with_policy(mut self, policy: OverlapPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn policy(&self) -> &OverlapPolicy {
        &self.policy
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    /// Allocate a fresh service principal: generate the Ed25519 keypair,
    /// persist the public half + principal record, and return the secret
    /// half **exactly once** in the [`ProvisionedKey`].
    ///
    /// Validates `input.desired_id` via [`Principal::try_new`]
    /// (`kind=Service`, `bound_to=None`, status=Active). A collision on the
    /// id surfaces as [`ServicePrincipalError::AlreadyExists`].
    pub async fn provision(
        &self,
        input: NewServicePrincipal,
        now: i64,
    ) -> Result<ProvisionedKey, ServicePrincipalError> {
        let id = PrincipalId::service(input.desired_id);
        // Principal::try_new enforces kind=Service => bound_to=None and the
        // status invariant; if a future caller calls `provision` with a
        // pre-built PrincipalId, the same check applies.
        let principal = Principal::try_new(id.clone(), None, PrincipalStatus::Active, now)?;
        match self.store.insert_principal(&principal).await {
            Ok(()) => {}
            Err(StoreError::Conflict) => return Err(ServicePrincipalError::AlreadyExists(id)),
            Err(other) => return Err(other.into()),
        }
        let (signing_key, secret_key) = self.mint_signing_key(&id, now).await?;
        Ok(ProvisionedKey {
            principal,
            signing_key,
            secret_key,
        })
    }

    /// Register a fresh keypair for an existing principal, retire the
    /// currently-active key with `retire_at = now + policy.overlap_seconds`,
    /// and hand the new secret back once.
    ///
    /// Returns [`ServicePrincipalError::UnknownPrincipal`] if `id` doesn't
    /// resolve; [`ServicePrincipalError::WrongPrincipalKind`] if `id.kind`
    /// is something other than `Service`. The previous key remains in the
    /// JWKS (status=Retiring) until pruned — in-flight tokens still verify.
    pub async fn rotate(
        &self,
        id: &PrincipalId,
        now: i64,
    ) -> Result<ProvisionedKey, ServicePrincipalError> {
        if id.kind != PrincipalKind::Service {
            return Err(ServicePrincipalError::WrongPrincipalKind(id.kind));
        }
        let principal = self
            .store
            .get_principal(id)
            .await?
            .ok_or_else(|| ServicePrincipalError::UnknownPrincipal(id.clone()))?;

        let retire_at = now + self.policy.overlap_seconds;
        let existing = self.store.list_signing_keys(id).await?;
        let active = existing
            .iter()
            .find(|k| matches!(k.status, SigningKeyStatus::Active))
            .ok_or_else(|| ServicePrincipalError::NoActiveKey(id.clone()))?;
        self.store
            .retire_signing_key(&active.kid, retire_at)
            .await?;

        let (signing_key, secret_key) = self.mint_signing_key(id, now).await?;
        Ok(ProvisionedKey {
            principal,
            signing_key,
            secret_key,
        })
    }

    /// Drop signing keys whose `Retiring` window has elapsed (`retire_at
    /// <= now`). Returns the count dropped. Call from a periodic sweep
    /// before re-publishing the JWKS.
    pub async fn prune_retired_keys(
        &self,
        now: i64,
    ) -> Result<u64, ServicePrincipalError> {
        Ok(self.store.prune_retired_keys(now).await?)
    }

    /// The set of signing keys to publish in the JWKS *right now*: every
    /// `Active` key, plus every `Retiring` key whose `retire_at > now`.
    /// Retiring-and-due keys are filtered out without removing them — call
    /// [`prune_retired_keys`](Self::prune_retired_keys) to actually drop
    /// the rows.
    pub async fn published_signing_keys(
        &self,
        now: i64,
    ) -> Result<Vec<SigningKey>, ServicePrincipalError> {
        let all = self.store.list_all_signing_keys().await?;
        Ok(all
            .into_iter()
            .filter(|k| match k.status {
                SigningKeyStatus::Active => true,
                SigningKeyStatus::Retiring => k.retire_at.map(|t| t > now).unwrap_or(false),
            })
            .collect())
    }

    /// Generate a fresh Ed25519 keypair, persist its public half, and
    /// return both the persisted record and the secret bytes.
    async fn mint_signing_key(
        &self,
        principal_id: &PrincipalId,
        now: i64,
    ) -> Result<(SigningKey, [u8; 64]), ServicePrincipalError> {
        let (minter, verifier) = PasetoV4SecretMinter::generate()?;
        let public_bytes = verifier
            .public_key()
            .as_bytes()
            .try_into()
            .expect("v4.public key is 32 bytes");
        // pasetors stores the v4 secret as a 64-byte seed||pubkey layout.
        let secret_slice = minter.secret_key_bytes();
        let mut secret_key = [0u8; 64];
        secret_key.copy_from_slice(secret_slice);

        let signing_key = SigningKey {
            kid: mint_kid(),
            principal_id: principal_id.clone(),
            public_key: public_bytes,
            status: SigningKeyStatus::Active,
            created_at: now,
            retire_at: None,
        };
        self.store.insert_signing_key(&signing_key).await?;
        Ok((signing_key, secret_key))
    }
}

/// 128-bit opaque kid encoded base64url-no-pad. Matches the entropy /
/// shape of `generate_jti` in `session.rs`.
fn mint_kid() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("OS CSPRNG must be available");
    URL_SAFE_NO_PAD.encode(bytes)
}

// ----------------------------------------------------------------------------
// MemoryServicePrincipalStore — test-only impl
// ----------------------------------------------------------------------------

/// In-memory [`ServicePrincipalStore`] for tests and single-node
/// bootstrapping before the persistent impl lands (peer ticket against
/// `cheers-sqlx`). Cheap to `clone` — shares one backing map.
#[derive(Default, Clone, Debug)]
pub struct MemoryServicePrincipalStore {
    inner: Arc<Mutex<MemoryServicePrincipalInner>>,
}

#[derive(Default, Debug)]
struct MemoryServicePrincipalInner {
    principals: HashMap<PrincipalId, Principal>,
    keys: Vec<SigningKey>,
}

impl MemoryServicePrincipalStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ServicePrincipalStore for MemoryServicePrincipalStore {
    async fn insert_principal(&self, principal: &Principal) -> Result<(), StoreError> {
        let mut g = self.inner.lock().expect("service-principal store mutex poisoned");
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
        let g = self.inner.lock().expect("service-principal store mutex poisoned");
        Ok(g.principals.get(id).cloned())
    }

    async fn insert_signing_key(&self, key: &SigningKey) -> Result<(), StoreError> {
        let mut g = self.inner.lock().expect("service-principal store mutex poisoned");
        if g.keys.iter().any(|k| k.kid == key.kid) {
            return Err(StoreError::Conflict);
        }
        g.keys.push(key.clone());
        Ok(())
    }

    async fn list_signing_keys(
        &self,
        principal: &PrincipalId,
    ) -> Result<Vec<SigningKey>, StoreError> {
        let g = self.inner.lock().expect("service-principal store mutex poisoned");
        Ok(g.keys
            .iter()
            .filter(|k| &k.principal_id == principal)
            .cloned()
            .collect())
    }

    async fn list_all_signing_keys(&self) -> Result<Vec<SigningKey>, StoreError> {
        let g = self.inner.lock().expect("service-principal store mutex poisoned");
        Ok(g.keys.clone())
    }

    async fn retire_signing_key(
        &self,
        kid: &str,
        retire_at: i64,
    ) -> Result<(), StoreError> {
        let mut g = self.inner.lock().expect("service-principal store mutex poisoned");
        let key = g
            .keys
            .iter_mut()
            .find(|k| k.kid == kid)
            .ok_or(StoreError::NotFound)?;
        key.status = SigningKeyStatus::Retiring;
        key.retire_at = Some(retire_at);
        Ok(())
    }

    async fn prune_retired_keys(&self, now: i64) -> Result<u64, StoreError> {
        let mut g = self.inner.lock().expect("service-principal store mutex poisoned");
        let before = g.keys.len();
        g.keys.retain(|k| match k.status {
            SigningKeyStatus::Active => true,
            SigningKeyStatus::Retiring => k.retire_at.map(|t| t > now).unwrap_or(true),
        });
        Ok((before - g.keys.len()) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cheers_verify::PasetoV4PublicVerifier;
    use pollster::block_on;

    fn rig() -> ServicePrincipalAuthority<MemoryServicePrincipalStore> {
        ServicePrincipalAuthority::new(MemoryServicePrincipalStore::new())
    }

    // ---- OverlapPolicy -----------------------------------------------------

    #[test]
    fn overlap_policy_default_is_24_hours() {
        let p = OverlapPolicy::default();
        assert_eq!(p.overlap_seconds, 24 * 60 * 60);
        let custom = OverlapPolicy::new(3_600).with_overlap_seconds(7_200);
        assert_eq!(custom.overlap_seconds, 7_200);
    }

    // ---- provision ---------------------------------------------------------

    #[test]
    fn provision_allocates_principal_and_returns_secret_once() {
        let authority = rig();
        block_on(async {
            let provisioned = authority
                .provision(NewServicePrincipal::new("yubaba-1"), 1_000)
                .await
                .unwrap();

            // Principal record carries the right shape.
            assert_eq!(
                provisioned.principal.id,
                PrincipalId::service("yubaba-1")
            );
            assert_eq!(provisioned.principal.bound_to, None);
            assert_eq!(provisioned.principal.status, PrincipalStatus::Active);
            assert_eq!(provisioned.principal.created_at, 1_000);

            // Signing key is fresh + active, with a non-empty kid.
            assert_eq!(provisioned.signing_key.principal_id, PrincipalId::service("yubaba-1"));
            assert_eq!(provisioned.signing_key.status, SigningKeyStatus::Active);
            assert!(provisioned.signing_key.retire_at.is_none());
            assert_eq!(provisioned.signing_key.created_at, 1_000);
            assert!(!provisioned.signing_key.kid.is_empty());

            // Secret half is exactly 64 bytes and the embedded public half
            // (last 32) matches the persisted record.
            assert_eq!(
                &provisioned.secret_key[32..],
                &provisioned.signing_key.public_key,
                "PASETO V4 secret layout is seed||pubkey",
            );
        });
    }

    #[test]
    fn provision_persisted_pubkey_verifies_tokens_minted_by_returned_secret() {
        // Round-trip: cheers persists only the pubkey; the returned secret
        // half is what a service principal would carry off-cheers. Tokens
        // it mints must verify under the pubkey cheers retained.
        use cheers_core::{
            Actor, AuthStrength, McpClaims, Owns, PrincipalId, Scope,
        };

        let authority = rig();
        block_on(async {
            let provisioned = authority
                .provision(NewServicePrincipal::new("yubaba-2"), 1_000)
                .await
                .unwrap();

            // Reconstruct the minter off-cheers, like yubaba would.
            let off_cheers_minter =
                PasetoV4SecretMinter::from_secret_key(&provisioned.secret_key).unwrap();

            // Reconstruct the verifier from the public bytes cheers retained
            // (the JWKS publication path).
            let verifier =
                PasetoV4PublicVerifier::from_public_key(&provisioned.signing_key.public_key)
                    .unwrap();

            let mut owns = Owns::default();
            owns.service = vec!["svc-prod".into()];
            let claims = McpClaims::new(
                "https://cheers.example",
                "https://kamaji.example",
                PrincipalId::service("yubaba-2"),
                1_000,
                1_600,
                "jti-rt",
                vec![Scope::OwnershipWrite],
            )
            .with_act(Actor::new(PrincipalId::service("yubaba-2")))
            .with_owns(owns)
            .with_auth_strength(AuthStrength::Bootstrap);

            let token = off_cheers_minter.mint_mcp(&claims).unwrap();
            let back = verifier.verify_mcp_at(&token, 1_100).unwrap();
            assert_eq!(back, claims);
        });
    }

    #[test]
    fn provision_rejects_duplicate_id() {
        let authority = rig();
        block_on(async {
            authority
                .provision(NewServicePrincipal::new("dup"), 1_000)
                .await
                .unwrap();
            let err = authority
                .provision(NewServicePrincipal::new("dup"), 1_001)
                .await
                .unwrap_err();
            match err {
                ServicePrincipalError::AlreadyExists(id) => {
                    assert_eq!(id, PrincipalId::service("dup"));
                }
                other => panic!("expected AlreadyExists, got {other:?}"),
            }
        });
    }

    // ---- rotate ------------------------------------------------------------

    #[test]
    fn rotate_retires_old_key_and_returns_fresh_secret() {
        let authority = rig();
        block_on(async {
            let first = authority
                .provision(NewServicePrincipal::new("yubaba-r"), 1_000)
                .await
                .unwrap();
            let id = first.principal.id.clone();

            let second = authority.rotate(&id, 5_000).await.unwrap();

            // Fresh kid; fresh pubkey.
            assert_ne!(second.signing_key.kid, first.signing_key.kid);
            assert_ne!(second.signing_key.public_key, first.signing_key.public_key);
            assert_eq!(second.signing_key.status, SigningKeyStatus::Active);
            assert!(second.signing_key.retire_at.is_none());

            // Old key now Retiring with retire_at = now + 24h.
            let stored = authority
                .store
                .list_signing_keys(&id)
                .await
                .unwrap();
            assert_eq!(stored.len(), 2);
            let old = stored.iter().find(|k| k.kid == first.signing_key.kid).unwrap();
            assert_eq!(old.status, SigningKeyStatus::Retiring);
            assert_eq!(
                old.retire_at,
                Some(5_000 + OverlapPolicy::DEFAULT_OVERLAP_SECONDS)
            );
        });
    }

    #[test]
    fn rotate_respects_custom_overlap_window() {
        let authority = rig().with_policy(OverlapPolicy::new(60 * 60)); // 1h
        block_on(async {
            let first = authority
                .provision(NewServicePrincipal::new("yubaba-c"), 1_000)
                .await
                .unwrap();
            authority.rotate(&first.principal.id, 2_000).await.unwrap();
            let keys = authority
                .store
                .list_signing_keys(&first.principal.id)
                .await
                .unwrap();
            let old = keys.iter().find(|k| k.kid == first.signing_key.kid).unwrap();
            assert_eq!(old.retire_at, Some(2_000 + 3_600));
        });
    }

    #[test]
    fn rotate_rejects_unknown_principal() {
        let authority = rig();
        block_on(async {
            let err = authority
                .rotate(&PrincipalId::service("ghost"), 1_000)
                .await
                .unwrap_err();
            match err {
                ServicePrincipalError::UnknownPrincipal(id) => {
                    assert_eq!(id, PrincipalId::service("ghost"));
                }
                other => panic!("expected UnknownPrincipal, got {other:?}"),
            }
        });
    }

    #[test]
    fn rotate_rejects_non_service_principal_kind() {
        let authority = rig();
        block_on(async {
            // A user principal handed to rotate is a programmer error.
            let err = authority
                .rotate(&PrincipalId::user("alice"), 1_000)
                .await
                .unwrap_err();
            match err {
                ServicePrincipalError::WrongPrincipalKind(k) => {
                    assert_eq!(k, PrincipalKind::User);
                }
                other => panic!("expected WrongPrincipalKind, got {other:?}"),
            }
        });
    }

    // ---- published_signing_keys + prune_retired_keys -----------------------

    #[test]
    fn published_signing_keys_includes_active_and_retiring_within_window() {
        let authority = rig().with_policy(OverlapPolicy::new(100));
        block_on(async {
            let first = authority
                .provision(NewServicePrincipal::new("yubaba-p"), 1_000)
                .await
                .unwrap();
            // Rotate at t=2000; old key retire_at=2100, new key active.
            authority.rotate(&first.principal.id, 2_000).await.unwrap();

            // At t=2050, both keys are in the JWKS.
            let live = authority.published_signing_keys(2_050).await.unwrap();
            assert_eq!(live.len(), 2, "got {live:#?}");

            // At t=2099 (just before the window closes), still both.
            let live = authority.published_signing_keys(2_099).await.unwrap();
            assert_eq!(live.len(), 2);

            // At t=2100 (retire_at), the retiring key drops out of the
            // published set even though it's still in the store.
            let live = authority.published_signing_keys(2_100).await.unwrap();
            assert_eq!(live.len(), 1);
            assert_eq!(live[0].status, SigningKeyStatus::Active);
        });
    }

    #[test]
    fn prune_retired_keys_removes_expired_only() {
        let authority = rig().with_policy(OverlapPolicy::new(100));
        block_on(async {
            let first = authority
                .provision(NewServicePrincipal::new("yubaba-x"), 1_000)
                .await
                .unwrap();
            authority.rotate(&first.principal.id, 2_000).await.unwrap();

            // Before the window closes, prune is a no-op.
            let dropped = authority.prune_retired_keys(2_099).await.unwrap();
            assert_eq!(dropped, 0);
            assert_eq!(
                authority
                    .store
                    .list_signing_keys(&first.principal.id)
                    .await
                    .unwrap()
                    .len(),
                2
            );

            // After retire_at, prune drops exactly the retiring key.
            let dropped = authority.prune_retired_keys(2_100).await.unwrap();
            assert_eq!(dropped, 1);
            let remaining = authority
                .store
                .list_signing_keys(&first.principal.id)
                .await
                .unwrap();
            assert_eq!(remaining.len(), 1);
            assert_eq!(remaining[0].status, SigningKeyStatus::Active);

            // Idempotent.
            let dropped = authority.prune_retired_keys(2_200).await.unwrap();
            assert_eq!(dropped, 0);
        });
    }

    #[test]
    fn published_signing_keys_omits_keys_with_no_retire_at_in_retiring_state() {
        // Belt-and-braces: a Retiring key without retire_at (only possible
        // via a misbehaving direct store write — the authority always sets
        // it) is treated as not published. Keeps the wire shape from leaking
        // a zombie key.
        let store = MemoryServicePrincipalStore::new();
        let key = SigningKey {
            kid: "k".into(),
            principal_id: PrincipalId::service("zombie"),
            public_key: [0u8; 32],
            status: SigningKeyStatus::Retiring,
            created_at: 100,
            retire_at: None,
        };
        block_on(async {
            store.insert_signing_key(&key).await.unwrap();
            let authority = ServicePrincipalAuthority::new(store);
            let live = authority.published_signing_keys(1_000).await.unwrap();
            assert!(live.is_empty());
        });
    }

    // ---- serde -------------------------------------------------------------

    #[test]
    fn signing_key_roundtrips_through_json_with_base64_pubkey() {
        let key = SigningKey {
            kid: "kid-abc".into(),
            principal_id: PrincipalId::service("yubaba"),
            public_key: [1u8; 32],
            status: SigningKeyStatus::Active,
            created_at: 100,
            retire_at: None,
        };
        let json = serde_json::to_string(&key).unwrap();
        // pubkey is a single base64url string, not a 32-element array.
        assert!(json.contains("\"public_key\":\""), "got {json}");
        assert!(!json.contains("[1,1,1"), "must NOT be an array: {json}");
        let back: SigningKey = serde_json::from_str(&json).unwrap();
        assert_eq!(back, key);
    }

    #[test]
    fn signing_key_deserialize_rejects_wrong_length_pubkey() {
        // 4 base64url chars cleanly decode to 3 bytes — well short of 32, so
        // the length guard fires (not the base64 parser).
        let json = r#"{
            "kid": "k",
            "principal_id": "svc:x",
            "public_key": "AAAA",
            "status": "active",
            "created_at": 0,
            "retire_at": null
        }"#;
        let err = serde_json::from_str::<SigningKey>(json).unwrap_err();
        assert!(
            err.to_string().contains("32 public_key bytes"),
            "got {err}"
        );
    }

    // ---- trait shape -------------------------------------------------------

    #[test]
    fn service_principal_store_is_dyn_compatible() {
        fn _f(_: &dyn ServicePrincipalStore) {}
    }
}
