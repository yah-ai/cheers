//! Origin-side persistence contracts — [`UserStore`] and [`RefreshStore`].
//!
//! These are the *origin* store traits: identity/provider linkage and
//! refresh-token rotation state. They moved out of `cheers-core` (R019-F6) so a
//! verify-only or device-only consumer never names them. The device store,
//! [`CredentialStore`](cheers_core::CredentialStore), stays in `cheers-core`; the
//! shared [`StoreError`](cheers_core::StoreError) does too.
//!
//! All traits are `async` via [`async_trait`] so they remain dyn-compatible.
//! Concrete impls (Postgres, Warden-backed, in-memory) live in product code.
//!
//! @yah:ticket(R020-F4, "Ownership table schema + writers (POST/DELETE /ownership) + cascading revoke")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-04T01:35:23Z)
//! @yah:status(review)
//! @yah:phase(P1)
//! @yah:parent(R020)
//! @yah:gotcha("CHECK (granted_by LIKE 'svc:%') and CHECK (on_behalf_of IS NULL OR on_behalf_of LIKE 'user:%') are invariants. A row violating either is a bug — humans never appear in granted_by, services never in on_behalf_of.")
//! @yah:assumes("ownership_version (yah/W159 Layer 3 freshness backstop) is intentionally deferred in v1 — add the column/endpoint when the staleness budget needs tightening.")
//! @arch:see(.yah/docs/working/mcp-auth-and-ownership.md)
//! @yah:depends_on(R020-F2)
//! @yah:next("Sign off the store layer + cascade primitive (this ticket).")
//! @yah:next("On sign-off: R020-T1 (McpClaims mint/verify helpers) unblocks → R020-T2 (Bearer middleware) unblocks → R020-T3 (HTTP routes) unblocks. After T3 lands the F4 title's HTTP claim is fully realized in the codebase.")
//! @yah:next("Separately: wire the cascade revoke caller into SessionAuthority's user-revocation hook — file as a peer task when that surface grows MCP awareness.")
//! @yah:handoff("STORE LAYER COMPLETE & TESTED. Landed: (a) cheers-server/src/ownership.rs — OwnershipStore trait (insert/get/revoke_by_id/revoke_by_on_behalf_of/list_for_principal) + NewOwnership::new() enforcing the granted_by=Service + on_behalf_of=User|None invariants up front + OwnershipRow + OwnershipValidationError. (b) cheers-sqlx migrations/{pg,sqlite}/0002_ownership.sql with the schema verbatim from §Ownership table — CHECKs + ix_ownership_principal + ix_ownership_on_behalf_of (both partial WHERE revoked_at IS NULL). (c) PgOwnershipStore + SqliteOwnershipStore. (d) common::ownership_store_lifecycle + check_constraints_reject_bad_rows scenarios.")
//! @yah:handoff("Cascade revoke landed at the STORE level (revoke_by_on_behalf_of — single UPDATE … WHERE on_behalf_of=$1 AND revoked_at IS NULL, returns row count). revoke_by_id is idempotent (re-revoke doesn't overwrite revoked_at; unknown id => NotFound). Row id is UUIDv4 hex (load-bearing property is 'crypto-random 128-bit', not the ULID encoding the doc names).")
//! @yah:handoff("SCOPE NOTE — HTTP routes (POST/DELETE /ownership) split out. The 'writers' in the F4 title are satisfied at the OwnershipStore trait layer (the layer that actually enforces the row invariants); the HTTP wrappers need cheers-axum infrastructure that didn't exist (Bearer/McpClaims middleware, McpClaims mint/verify helpers — TokenMinter/Verifier are hard-coded to Claims). Split to peer tasks R020-T1 (McpClaims mint/verify helpers in cheers-server) → R020-T2 (Bearer/McpClaims middleware in cheers-axum) → R020-T3 (POST/DELETE /ownership routes). Cleaner than expanding F4 inline; also resolves the F6→F4 circular dep noted in the prior handoff.")
//! @yah:handoff("DEFERRED: caller of revoke_by_on_behalf_of in the user-revocation hook (SessionAuthority::revoke_device or peer). The cascade primitive itself is tested; composing it into user-revocation is a follow-up under the same store-side scope (peer task — file when SessionAuthority grows MCP awareness).")
//! @yah:handoff("Verified GREEN: cargo test -p cheers-core (51), -p cheers-server (39 incl. 4 new ownership tests), -p cheers-verify (35+9+2+4), -p cheers-sqlx --features sqlite (7 incl. 2 new ownership integration tests). pg-integration --tests compiles (full pg run needs Docker).")
//! @yah:verify("cargo test -p cheers-server && cargo test -p cheers-sqlx --features sqlite")
//! @yah:verify("ownership_store_lifecycle scenario: insert → revoke_by_id → list_for_principal excludes the revoked row; re-revoke is idempotent (revoked_at unchanged).")
//! @yah:verify("check_constraints_reject_bad_rows: a row with granted_by NOT LIKE 'svc:%' or on_behalf_of NOT LIKE 'user:%' fails the SQL CHECK (both pg + sqlite).")
//! @yah:verify("Cascade revoke: revoke_by_on_behalf_of(user, now) sweeps every live row with that on_behalf_of in one UPDATE, returns the row count, and a follow-up revoke returns 0.")
//!
//! @yah:ticket(R020-F13, "Audit ingest endpoint + centralized audit table (POST /audit/ingest)")
//! @yah:at(2026-06-04T01:36:39Z)
//! @yah:status(open)
//! @yah:phase(P4)
//! @yah:parent(R020)
//! @yah:next("Land audit table: { at, sub, act, camp_id, aud, method, scope, result, request_id }. Append-only; no in-place edits.")
//! @yah:next("POST /audit/ingest accepts a batch of records; requires Bearer with scope=audit:write (kind=service only).")
//! @yah:next("Failed forwards bubble back as 4xx/5xx. Cheers's responsibility ends at 'accepted and durable on cheers's side' — constable retains the JSONL durable copy with bounded backoff.")
//! @yah:verify("Batch POST 100 records, observe all present in the audit table, observe a 4xx for a record with a forbidden shape and a backed-off retry succeed.")
//! @yah:verify("User-principal token requesting audit:write at grant time is rejected (negative test).")
//! @yah:gotcha("audit:write is kind=service only. Same enforcement as ownership:write — reject at grant write time.")
//! @arch:see(.yah/docs/working/mcp-auth-and-ownership.md)
//! @yah:depends_on(R020-F3)
//! @yah:depends_on(R020-F4)

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use cheers_core::{Credential, DeviceId, StoreError, User, UserId};

/// The external identity-provider namespace a `subject` string lives in.
///
/// Two users with the same Google `sub` must collide; the same email address
/// presented to Apple vs. Google must *not* collide. `ProviderKey` is the
/// namespace tag that disambiguates.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "provider", rename_all = "snake_case")]
pub enum ProviderKey {
    /// Google OIDC — `subject` is the `sub` claim from Google's ID token.
    OidcGoogle,
    /// Apple Sign In — `subject` is the `sub` claim from Apple's ID token.
    OidcApple,
    /// Any other OIDC issuer; `subject` is that issuer's `sub` claim.
    OidcGeneric { issuer: String },
    /// Email-based identity (magic-link or password). `subject` is the email.
    Email,
    /// LAN-pair identity. `subject` is the device's xlb-net node-id.
    LanPair,
}

/// Fields required to mint a fresh `User`.
///
/// `UserStore::create` returns the resulting `User` with a freshly minted
/// `UserId`; the caller has no say in the id shape.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct NewUser {
    pub email: Option<String>,
    pub name: Option<String>,
}

impl NewUser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
}

/// User identity + provider-link persistence.
///
/// One `User` may be reachable through multiple `(ProviderKey, subject)`
/// pairs — that's what `link_provider` is for. `list_devices` and
/// `revoke_device` are the session-management surface: products surface them
/// to end-users on an /account/sessions page (P12).
#[async_trait]
pub trait UserStore: Send + Sync {
    /// Look up the user reachable via `(provider, subject)`. `None` if no
    /// such link exists.
    async fn find_by_provider(
        &self,
        provider: &ProviderKey,
        subject: &str,
    ) -> Result<Option<User>, StoreError>;

    /// Create a fresh user (no provider linked yet). Returns the user with
    /// its newly minted `UserId`.
    async fn create(&self, new_user: NewUser) -> Result<User, StoreError>;

    /// Link `(provider, subject)` to an existing user. Returns
    /// `StoreError::Conflict` if the link already exists for a *different*
    /// user; idempotent if it matches.
    async fn link_provider(
        &self,
        user_id: &UserId,
        provider: &ProviderKey,
        subject: &str,
    ) -> Result<(), StoreError>;

    /// Enumerate every device this user has signed in from (and not revoked).
    async fn list_devices(&self, user_id: &UserId) -> Result<Vec<DeviceId>, StoreError>;

    /// Revoke a device. The two halves of "revoked" are first-class (R019-F4):
    /// block *new* sessions by revoking the device's refresh chains
    /// ([`RefreshStore::revoke_chain`]), and kill an *in-flight* access token by
    /// its `jti` via [`RevocationWriter::revoke`](crate::revocation::RevocationWriter::revoke);
    /// the edge enforces the latter through
    /// [`RevocationReader`](cheers_verify::RevocationReader). This method records
    /// the device-level intent; composing those calls is
    /// [`SessionAuthority`](crate::session::SessionAuthority)'s job.
    async fn revoke_device(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
    ) -> Result<(), StoreError>;
}

/// One row in a refresh-token rotation chain.
///
/// This struct is the persistence contract the rotation impls
/// ([`RefreshRotator`](crate::refresh::RefreshRotator)) write against. The
/// struct is `#[non_exhaustive]` (so adding fields stays SemVer-clean for
/// downstream consumers), which blocks external struct-literal construction —
/// use [`RefreshTokenRecord::new`] from a [`RefreshStore`] impl that needs to
/// build one (e.g. in a `get` query handler).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RefreshTokenRecord {
    /// Opaque secret presented by the client (typically 32 random bytes,
    /// base64url-encoded).
    pub token: String,
    /// Stable identifier shared across every token in this rotation chain.
    pub chain_id: String,
    /// Token this one rotated from (`None` for the chain root).
    pub parent: Option<String>,
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub issued_at: i64,
    pub expires_at: i64,
    /// `true` once this token has minted a successor. Re-presenting a
    /// consumed token MUST revoke the whole chain (replay).
    pub consumed: bool,
    /// `true` once the chain has been revoked — by replay detection,
    /// explicit logout, or device revocation.
    pub revoked: bool,
}

impl RefreshTokenRecord {
    /// Construct a record from its constituent fields. Use this from external
    /// [`RefreshStore`] impls (the struct is `#[non_exhaustive]`, so direct
    /// struct-literal construction is crate-local only). New fields land here
    /// behind the `#[non_exhaustive]` shield so existing callers stay green.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        token: String,
        chain_id: String,
        parent: Option<String>,
        user_id: UserId,
        device_id: DeviceId,
        issued_at: i64,
        expires_at: i64,
        consumed: bool,
        revoked: bool,
    ) -> Self {
        Self {
            token,
            chain_id,
            parent,
            user_id,
            device_id,
            issued_at,
            expires_at,
            consumed,
            revoked,
        }
    }
}

/// Persistence for refresh-token rotation chains.
#[async_trait]
pub trait RefreshStore: Send + Sync {
    async fn put(&self, record: &RefreshTokenRecord) -> Result<(), StoreError>;
    async fn get(&self, token: &str) -> Result<Option<RefreshTokenRecord>, StoreError>;
    /// Mark `token` as consumed. Returns `NotFound` if unknown.
    async fn mark_consumed(&self, token: &str) -> Result<(), StoreError>;
    /// Revoke every record in `chain_id`. Idempotent.
    async fn revoke_chain(&self, chain_id: &str) -> Result<(), StoreError>;
}

/// Origin-side multi-passkey-per-user persistence for the WebAuthn relying-party
/// flow (P7 / R014).
///
/// Each row stores one passkey [`Credential`] (binding
/// [`DeviceBinding::Passkey`](cheers_core::DeviceBinding::Passkey), `material`
/// the `serde_json`-encoded `webauthn-rs` `Passkey`). The trait sits on
/// `cheers-core`'s [`Credential`] rather than `webauthn-rs::Passkey` so this
/// crate stays free of webauthn-rs in its public API — products bridge with
/// `cheers::passkey::passkey_to_credential` /
/// `cheers::passkey::passkey_from_credential`.
///
/// A user holds zero-or-more passkey credentials (phone, laptop, security key);
/// `(user_id, device_id)` is the unique key. Non-discoverable WebAuthn flow:
/// products call [`list_for_user`](Self::list_for_user) to assemble the
/// `allow_credentials` set before `start_authentication`, and
/// [`update`](Self::update) after a successful ceremony if the signature
/// counter advanced (see `cheers::passkey::apply_authentication_result`).
///
/// Long-lived credential material, indexed by user — belongs in the relational
/// SQL store (see `cheers-sqlx`), never in redis.
#[async_trait]
pub trait PasskeyCredentialStore: Send + Sync {
    /// Insert a fresh passkey credential. The credential's
    /// [`user_id`](Credential::user_id) and [`device_id`](Credential::device_id)
    /// fields are the unique key; [`StoreError::Conflict`] if the pair is
    /// already taken.
    async fn put(&self, cred: &Credential) -> Result<(), StoreError>;

    /// Every passkey credential owned by `user_id`. Order is unspecified.
    async fn list_for_user(&self, user_id: &UserId) -> Result<Vec<Credential>, StoreError>;

    /// Remove the passkey credential at `(user_id, device_id)`.
    /// [`StoreError::NotFound`] if no such row exists.
    async fn delete(&self, user_id: &UserId, device_id: &DeviceId) -> Result<(), StoreError>;

    /// Rewrite the stored material for the credential's
    /// `(user_id, device_id)` pair. Use after
    /// `apply_authentication_result` to persist an advanced counter / updated
    /// backup flags. [`StoreError::NotFound`] if the pair was never `put`.
    async fn update(&self, cred: &Credential) -> Result<(), StoreError>;
}

#[cfg(test)]
mod tests {
    //! Trait-shape smoke tests via tiny in-memory impls. The "real" memory
    //! impls live in the `cheers` crate (R015-T3).

    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemUserStore {
        inner: Mutex<MemUserInner>,
    }

    #[derive(Default)]
    struct MemUserInner {
        next_id: u64,
        users: HashMap<UserId, User>,
        links: HashMap<(ProviderKey, String), UserId>,
        devices: HashMap<UserId, Vec<DeviceId>>,
    }

    #[async_trait]
    impl UserStore for MemUserStore {
        async fn find_by_provider(
            &self,
            provider: &ProviderKey,
            subject: &str,
        ) -> Result<Option<User>, StoreError> {
            let g = self.inner.lock().unwrap();
            Ok(g.links
                .get(&(provider.clone(), subject.to_owned()))
                .and_then(|id| g.users.get(id).cloned()))
        }

        async fn create(&self, new_user: NewUser) -> Result<User, StoreError> {
            let mut g = self.inner.lock().unwrap();
            g.next_id += 1;
            let id = UserId::new(format!("u-{}", g.next_id));
            let mut u = User::new(id.clone());
            u.email = new_user.email;
            u.name = new_user.name;
            g.users.insert(id, u.clone());
            Ok(u)
        }

        async fn link_provider(
            &self,
            user_id: &UserId,
            provider: &ProviderKey,
            subject: &str,
        ) -> Result<(), StoreError> {
            let mut g = self.inner.lock().unwrap();
            let key = (provider.clone(), subject.to_owned());
            match g.links.get(&key) {
                Some(existing) if existing == user_id => Ok(()),
                Some(_) => Err(StoreError::Conflict),
                None => {
                    g.links.insert(key, user_id.clone());
                    Ok(())
                }
            }
        }

        async fn list_devices(&self, user_id: &UserId) -> Result<Vec<DeviceId>, StoreError> {
            let g = self.inner.lock().unwrap();
            Ok(g.devices.get(user_id).cloned().unwrap_or_default())
        }

        async fn revoke_device(
            &self,
            user_id: &UserId,
            device_id: &DeviceId,
        ) -> Result<(), StoreError> {
            let mut g = self.inner.lock().unwrap();
            let v = g.devices.entry(user_id.clone()).or_default();
            let before = v.len();
            v.retain(|d| d != device_id);
            if v.len() == before {
                return Err(StoreError::NotFound);
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct MemRefreshStore(Mutex<HashMap<String, RefreshTokenRecord>>);

    #[async_trait]
    impl RefreshStore for MemRefreshStore {
        async fn put(&self, record: &RefreshTokenRecord) -> Result<(), StoreError> {
            self.0
                .lock()
                .unwrap()
                .insert(record.token.clone(), record.clone());
            Ok(())
        }
        async fn get(&self, token: &str) -> Result<Option<RefreshTokenRecord>, StoreError> {
            Ok(self.0.lock().unwrap().get(token).cloned())
        }
        async fn mark_consumed(&self, token: &str) -> Result<(), StoreError> {
            let mut g = self.0.lock().unwrap();
            g.get_mut(token).ok_or(StoreError::NotFound)?.consumed = true;
            Ok(())
        }
        async fn revoke_chain(&self, chain_id: &str) -> Result<(), StoreError> {
            let mut g = self.0.lock().unwrap();
            for r in g.values_mut() {
                if r.chain_id == chain_id {
                    r.revoked = true;
                }
            }
            Ok(())
        }
    }

    #[test]
    fn user_store_create_link_find() {
        let s = MemUserStore::default();
        pollster::block_on(async {
            let u = s.create(NewUser::new().with_email("a@b")).await.unwrap();
            assert_eq!(u.email.as_deref(), Some("a@b"));
            s.link_provider(&u.id, &ProviderKey::OidcGoogle, "google-sub-1")
                .await
                .unwrap();
            // Idempotent re-link on same user.
            s.link_provider(&u.id, &ProviderKey::OidcGoogle, "google-sub-1")
                .await
                .unwrap();
            // Conflict with a different user.
            let u2 = s.create(NewUser::new()).await.unwrap();
            assert!(matches!(
                s.link_provider(&u2.id, &ProviderKey::OidcGoogle, "google-sub-1")
                    .await,
                Err(StoreError::Conflict)
            ));
            // Lookup succeeds.
            let found = s
                .find_by_provider(&ProviderKey::OidcGoogle, "google-sub-1")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(found.id, u.id);
        });
    }

    #[test]
    fn refresh_store_consume_and_revoke_chain() {
        let s = MemRefreshStore::default();
        pollster::block_on(async {
            let r = RefreshTokenRecord {
                token: "tok-1".into(),
                chain_id: "chain-A".into(),
                parent: None,
                user_id: UserId::new("u1"),
                device_id: DeviceId::new("d1"),
                issued_at: 100,
                expires_at: 1_000,
                consumed: false,
                revoked: false,
            };
            s.put(&r).await.unwrap();
            s.mark_consumed("tok-1").await.unwrap();
            assert!(s.get("tok-1").await.unwrap().unwrap().consumed);
            s.revoke_chain("chain-A").await.unwrap();
            assert!(s.get("tok-1").await.unwrap().unwrap().revoked);
        });
    }

    #[derive(Default)]
    struct MemPasskeyCredentialStore(Mutex<HashMap<(UserId, DeviceId), Credential>>);

    #[async_trait]
    impl PasskeyCredentialStore for MemPasskeyCredentialStore {
        async fn put(&self, cred: &Credential) -> Result<(), StoreError> {
            let mut g = self.0.lock().unwrap();
            let key = (cred.user_id.clone(), cred.device_id.clone());
            if g.contains_key(&key) {
                return Err(StoreError::Conflict);
            }
            g.insert(key, cred.clone());
            Ok(())
        }

        async fn list_for_user(&self, user_id: &UserId) -> Result<Vec<Credential>, StoreError> {
            let g = self.0.lock().unwrap();
            Ok(g.iter()
                .filter(|((u, _), _)| u == user_id)
                .map(|(_, c)| c.clone())
                .collect())
        }

        async fn delete(
            &self,
            user_id: &UserId,
            device_id: &DeviceId,
        ) -> Result<(), StoreError> {
            let mut g = self.0.lock().unwrap();
            g.remove(&(user_id.clone(), device_id.clone()))
                .ok_or(StoreError::NotFound)
                .map(|_| ())
        }

        async fn update(&self, cred: &Credential) -> Result<(), StoreError> {
            let mut g = self.0.lock().unwrap();
            let key = (cred.user_id.clone(), cred.device_id.clone());
            if !g.contains_key(&key) {
                return Err(StoreError::NotFound);
            }
            g.insert(key, cred.clone());
            Ok(())
        }
    }

    fn passkey_cred(user: &str, device: &str, material: &[u8]) -> Credential {
        Credential::new(
            UserId::new(user),
            DeviceId::new(device),
            cheers_core::DeviceBinding::Passkey,
            material.to_vec(),
        )
    }

    #[test]
    fn passkey_store_put_list_update_delete() {
        let s = MemPasskeyCredentialStore::default();
        pollster::block_on(async {
            // Empty list for a fresh user.
            assert!(s
                .list_for_user(&UserId::new("u1"))
                .await
                .unwrap()
                .is_empty());

            // Put a credential, list it.
            let phone = passkey_cred("u1", "phone", b"v1");
            s.put(&phone).await.unwrap();
            let list = s.list_for_user(&UserId::new("u1")).await.unwrap();
            assert_eq!(list, vec![phone.clone()]);

            // Put a second credential for the same user.
            let laptop = passkey_cred("u1", "laptop", b"v1-laptop");
            s.put(&laptop).await.unwrap();
            let mut list = s.list_for_user(&UserId::new("u1")).await.unwrap();
            list.sort_by(|a, b| a.device_id.as_str().cmp(b.device_id.as_str()));
            assert_eq!(list, vec![laptop.clone(), phone.clone()]);

            // Re-putting the same (user, device) conflicts.
            assert!(matches!(
                s.put(&phone).await,
                Err(StoreError::Conflict)
            ));

            // Update rewrites the material (counter advance).
            let phone_v2 = passkey_cred("u1", "phone", b"v2");
            s.update(&phone_v2).await.unwrap();
            let mut list = s.list_for_user(&UserId::new("u1")).await.unwrap();
            list.sort_by(|a, b| a.device_id.as_str().cmp(b.device_id.as_str()));
            assert_eq!(list[1].material, b"v2");

            // Update on a missing (user, device) is NotFound.
            let ghost = passkey_cred("u1", "ghost", b"x");
            assert!(matches!(
                s.update(&ghost).await,
                Err(StoreError::NotFound)
            ));

            // Delete works once.
            s.delete(&UserId::new("u1"), &DeviceId::new("phone"))
                .await
                .unwrap();
            assert!(matches!(
                s.delete(&UserId::new("u1"), &DeviceId::new("phone"))
                    .await,
                Err(StoreError::NotFound)
            ));

            // Second user's credentials are unaffected.
            let other = passkey_cred("u2", "phone", b"u2-v1");
            s.put(&other).await.unwrap();
            assert_eq!(
                s.list_for_user(&UserId::new("u1")).await.unwrap(),
                vec![laptop]
            );
            assert_eq!(
                s.list_for_user(&UserId::new("u2")).await.unwrap(),
                vec![other]
            );
        });
    }

    #[test]
    fn traits_are_dyn_compatible() {
        fn _u(_: &dyn UserStore) {}
        fn _r(_: &dyn RefreshStore) {}
        fn _p(_: &dyn PasskeyCredentialStore) {}
    }
}
