//! The [`McpAuthority`] origin facade for minting MCP-call tokens.
//!
//! Composes the moving parts the doc lays out in `.yah/docs/working/
//! mcp-auth-and-ownership.md` §Mint flows:
//!
//! - [`PasetoV4SecretMinter::mint_mcp`](crate::codec::PasetoV4SecretMinter::mint_mcp)
//!   — the signing primitive (R020-T15, v4.public over Ed25519).
//! - [`GrantStore`](crate::grants::GrantStore) — per-(principal, aud) grant
//!   entries; empty result = no entitlement = mint rejected (composition rule
//!   (5)).
//! - [`BundleStore`](crate::bundles::BundleStore) +
//!   [`expand_scopes`](crate::bundles::expand_scopes) — bundle expansion at
//!   mint time (R020-F5, rule (2)).
//! - [`validate_grant`] — composition rule (4) defence in depth: a bundle
//!   that smuggles a service-only scope into a user grant is caught here
//!   before signing.
//! - [`OwnershipStore`](crate::ownership::OwnershipStore) — the `owns` claim
//!   source of truth, read at mint time and baked into the token (R020-F4 /
//!   W159 §Layer 2).
//!
//! Mirrors the [`SessionAuthority`](crate::session::SessionAuthority) shape:
//! generic over the capability set so the assembled deployment is visible in
//! the type, and the absence of a verifier here keeps mint power confined to
//! this crate (the edge holds
//! [`PasetoV4PublicVerifier`](cheers_verify::PasetoV4PublicVerifier), never a
//! minter).

use cheers_core::{
    validate_grant, Actor, AuthStrength, CodecError, Error, GrantError, McpClaims, Owns,
    PrincipalId, PrincipalKind, Scope, StoreError,
};

use crate::bundles::{expand_scopes, BundleExpansionError, BundleStore};
use crate::codec::PasetoV4SecretMinter;
use crate::grants::GrantStore;
use crate::ownership::{OwnershipRow, OwnershipStore};
use crate::session::generate_jti;

/// TTL defaults for an MCP-call token.
///
/// Short by design — per `.yah/docs/working/mcp-auth-and-ownership.md` §TTLs,
/// the 5–15 minute access window is also the propagation bound for
/// revocations and ownership-table edits when no `ownership_version`
/// freshness backstop is in play.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct McpPolicy {
    /// Per-call access-token lifetime in seconds.
    pub access_ttl_seconds: i64,
}

impl McpPolicy {
    /// 10 minutes — middle of the doc's 5–15 min range.
    pub const DEFAULT_ACCESS_TTL_SECONDS: i64 = 10 * 60;

    pub fn new(access_ttl_seconds: i64) -> Self {
        Self { access_ttl_seconds }
    }

    pub fn with_access_ttl(mut self, seconds: i64) -> Self {
        self.access_ttl_seconds = seconds;
        self
    }
}

impl Default for McpPolicy {
    fn default() -> Self {
        Self {
            access_ttl_seconds: Self::DEFAULT_ACCESS_TTL_SECONDS,
        }
    }
}

/// A freshly-minted MCP-call token plus the [`McpClaims`] it carries.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct MintedMcpToken {
    /// The signed `v4.public.*` token string.
    pub token: String,
    /// The claims embedded in `token`, including the freshly minted `jti`.
    pub claims: McpClaims,
}

/// Why a mint attempt failed before (or after) the signing step.
///
/// Typed so the HTTP layer (R020-T17 routes) can map specific failures to the
/// right status code: `AudNotEntitled` → 403, `GrantMisconfigured` → 500
/// (server-side data bug), `Store` → 503, `Codec` → 500.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum McpMintError {
    /// Composition rule (5) — the principal holds no grant for the requested
    /// `aud`. Per-call rejection, returned before any signing happens.
    #[error("no entitlement: principal '{principal}' has no grant for aud '{aud}'")]
    AudNotEntitled { principal: String, aud: String },
    /// RFC 8693 — a requested scope on a token-exchange is not in the
    /// intersection of both principals' grants for this `aud`. Per the doc
    /// (`§Mint flows` → token exchange), the whole exchange is rejected —
    /// `invalid_scope`, not a partial token. Maps to HTTP 400 `invalid_scope`.
    #[error("requested scope '{scope}' is not granted by both principals for aud '{aud}'")]
    InvalidScope { scope: Scope, aud: String },
    /// The caller passed the wrong principal kind for this mint path — e.g.
    /// `mint_user_fresh` invoked with `svc:` or `camp:` in the `sub` slot.
    /// A programmer-error, not a user-input rejection: surface 500, not 403.
    #[error("mint path expects {expected} principal; got {got}")]
    WrongPrincipalKind {
        expected: PrincipalKind,
        got: PrincipalKind,
    },
    /// Composition rule (4) defence in depth — bundle expansion produced a
    /// service-only scope for a non-service principal. Indicates a
    /// misconfigured bundle or a grant that should have been rejected at the
    /// grant API; surface as 500.
    #[error(transparent)]
    GrantMisconfigured(#[from] GrantError),
    /// Bundle expansion failed (unknown bundle / store error inside
    /// expansion).
    #[error(transparent)]
    BundleExpansion(#[from] BundleExpansionError),
    /// Underlying store failure (grants / ownership).
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Signing failure inside the codec layer.
    #[error(transparent)]
    Codec(#[from] CodecError),
}

impl From<McpMintError> for Error {
    fn from(e: McpMintError) -> Self {
        match e {
            McpMintError::Store(s) => Error::Store(s),
            McpMintError::Codec(c) => Error::Codec(c),
            McpMintError::BundleExpansion(BundleExpansionError::Store(s)) => Error::Store(s),
            // Structured rejections (AudNotEntitled, WrongPrincipalKind,
            // GrantMisconfigured, BundleExpansion::Unknown) carry a message
            // that's safe to surface; route them through InvalidInput so a
            // caller that doesn't pattern-match on McpMintError still gets a
            // sensible umbrella error.
            other => Error::InvalidInput(other.to_string()),
        }
    }
}

/// Origin facade: everything that can *mint* an MCP-call token.
///
/// Holds the four origin-tier capabilities for the MCP boundary — a
/// [`PasetoV4SecretMinter`], a [`BundleStore`], a [`GrantStore`], and an
/// [`OwnershipStore`] — plus the cheers issuer URL and an [`McpPolicy`].
/// Generic (not `dyn`) so the assembled capability set is visible in the
/// type. The matching edge-side verifier is
/// [`PasetoV4PublicVerifier`](cheers_verify::PasetoV4PublicVerifier) +
/// `verify_mcp_at`; the verify-only consumer (constable) never depends on
/// this crate.
pub struct McpAuthority<B, G, O> {
    minter: PasetoV4SecretMinter,
    bundles: B,
    grants: G,
    ownership: O,
    iss: String,
    policy: McpPolicy,
}

impl<B, G, O> McpAuthority<B, G, O>
where
    B: BundleStore,
    G: GrantStore,
    O: OwnershipStore,
{
    /// Assemble an authority with the [default policy](McpPolicy::default).
    pub fn new(
        minter: PasetoV4SecretMinter,
        bundles: B,
        grants: G,
        ownership: O,
        iss: impl Into<String>,
    ) -> Self {
        Self {
            minter,
            bundles,
            grants,
            ownership,
            iss: iss.into(),
            policy: McpPolicy::default(),
        }
    }

    /// Override the TTL policy.
    pub fn with_policy(mut self, policy: McpPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn policy(&self) -> &McpPolicy {
        &self.policy
    }

    pub fn issuer(&self) -> &str {
        &self.iss
    }

    /// **Mint path 1** — user-initiated, passkey-fresh (R020-F6).
    ///
    /// Returns a token bearing
    /// `{sub: user:<U>, act?, camp_id?, scope: [...], owns: {...}, auth_strength: "user-fresh"}`.
    /// Required inputs:
    ///
    /// - `user`: the authenticated user's principal (kind MUST be
    ///   [`PrincipalKind::User`]).
    /// - `actor`: the optional `act` claim (RFC 8693) — the agent acting on
    ///   the user's behalf. The agent is never the primary `sub`.
    /// - `camp_id`: when set, both populates the `camp_id` claim and is the
    ///   key used to look up the `owns` claim (rows held by
    ///   `camp:<camp_id>`).
    /// - `aud`: the target resource URI for this call. Per composition rule
    ///   (5) the principal MUST hold at least one grant entry for `aud` — an
    ///   empty grant list returns [`McpMintError::AudNotEntitled`] before
    ///   any signing happens.
    /// - `now`: unix seconds. `iat = now`, `exp = now + policy.access_ttl`.
    ///
    /// The pipeline: grants → [`expand_scopes`] → [`validate_grant`] per
    /// scope (rule (4) defence) → ownership lookup → sign with `mint_mcp`.
    pub async fn mint_user_fresh(
        &self,
        user: PrincipalId,
        actor: Option<Actor>,
        camp_id: Option<String>,
        aud: impl Into<String>,
        now: i64,
    ) -> Result<MintedMcpToken, McpMintError> {
        if user.kind != PrincipalKind::User {
            return Err(McpMintError::WrongPrincipalKind {
                expected: PrincipalKind::User,
                got: user.kind,
            });
        }
        let aud = aud.into();

        let entries = self.grants.list_for(&user, &aud).await?;
        if entries.is_empty() {
            return Err(McpMintError::AudNotEntitled {
                principal: user.to_string(),
                aud,
            });
        }

        let scopes = expand_scopes(&self.bundles, &entries).await?;
        for s in &scopes {
            validate_grant(user.kind, *s)?;
        }

        let owns = match &camp_id {
            Some(id) => {
                let camp_principal = PrincipalId::camp(id);
                let rows = self.ownership.list_for_principal(&camp_principal).await?;
                rows_to_owns(&rows)
            }
            None => Owns::default(),
        };

        let mut claims = McpClaims::new(
            self.iss.clone(),
            aud,
            user,
            now,
            now + self.policy.access_ttl_seconds,
            generate_jti(),
            scopes,
        )
        .with_auth_strength(AuthStrength::UserFresh);
        if let Some(a) = actor {
            claims = claims.with_act(a);
        }
        if let Some(c) = camp_id {
            claims = claims.with_camp_id(c);
        }
        if !owns.is_empty() {
            claims = claims.with_owns(owns);
        }

        let token = self.minter.mint_mcp(&claims)?;
        Ok(MintedMcpToken { token, claims })
    }

    /// **Mint path 2** — bootstrapped camp, autonomous (R020-F7).
    ///
    /// For warden-hosted camps operating without a live user session: the
    /// camp's bootstrap credential authenticates upstream of this call, and
    /// the verified camp principal is what arrives here. Returns a token
    /// bearing
    /// `{sub: camp:<C>, camp_id: <C>, scope: [...], owns: {...}, auth_strength: "bootstrap"}`
    /// — note **no `act` claim** on this path, the camp itself is the
    /// principal (not a user acted-on-by an agent).
    ///
    /// Required inputs:
    ///
    /// - `camp`: the authenticated camp's principal (kind MUST be
    ///   [`PrincipalKind::Camp`]). `camp_id` on the resulting claim is the
    ///   bare id (sans `camp:` prefix), so a consumer doesn't have to re-
    ///   parse `sub` to learn it.
    /// - `aud`: the target resource URI for this call. Per composition rule
    ///   (5) the camp MUST hold at least one grant entry for `aud` — an empty
    ///   grant list returns [`McpMintError::AudNotEntitled`] before signing.
    /// - `now`: unix seconds. `iat = now`, `exp = now + policy.access_ttl`.
    ///
    /// Same pipeline as [`mint_user_fresh`](Self::mint_user_fresh): grants →
    /// [`expand_scopes`] → [`validate_grant`] per scope (rule (4) defence —
    /// catches a bundle that smuggles `ownership:write` into a camp grant) →
    /// ownership lookup → sign with `mint_mcp`.
    pub async fn mint_bootstrap(
        &self,
        camp: PrincipalId,
        aud: impl Into<String>,
        now: i64,
    ) -> Result<MintedMcpToken, McpMintError> {
        if camp.kind != PrincipalKind::Camp {
            return Err(McpMintError::WrongPrincipalKind {
                expected: PrincipalKind::Camp,
                got: camp.kind,
            });
        }
        let aud = aud.into();

        let entries = self.grants.list_for(&camp, &aud).await?;
        if entries.is_empty() {
            return Err(McpMintError::AudNotEntitled {
                principal: camp.to_string(),
                aud,
            });
        }

        let scopes = expand_scopes(&self.bundles, &entries).await?;
        for s in &scopes {
            validate_grant(camp.kind, *s)?;
        }

        let rows = self.ownership.list_for_principal(&camp).await?;
        let owns = rows_to_owns(&rows);

        let camp_id = camp.id.clone();
        let mut claims = McpClaims::new(
            self.iss.clone(),
            aud,
            camp,
            now,
            now + self.policy.access_ttl_seconds,
            generate_jti(),
            scopes,
        )
        .with_camp_id(camp_id)
        .with_auth_strength(AuthStrength::Bootstrap);
        if !owns.is_empty() {
            claims = claims.with_owns(owns);
        }

        let token = self.minter.mint_mcp(&claims)?;
        Ok(MintedMcpToken { token, claims })
    }

    /// **Mint path 3** — RFC 8693 token-exchange (R020-F8).
    ///
    /// The ONLY path that crosses principals: a multi-player camp daemon
    /// (`subject_token` = camp bootstrap credential) presents a human's
    /// session token (`actor_token` = user's session) and asks for a token
    /// attributed to the *human*, with the camp as call context. The result
    /// looks like a `mint_user_fresh` token — same `auth_strength=user-fresh`
    /// because the user authenticated locally — but the camp's grants
    /// constrain it.
    ///
    /// Inputs (already-verified principals — credential checks live at the
    /// HTTP `/token` endpoint, same way passkey assertion sits upstream of
    /// [`mint_user_fresh`](Self::mint_user_fresh)):
    ///
    /// - `user`: the verified user from `actor_token` (kind MUST be
    ///   [`PrincipalKind::User`]).
    /// - `camp`: the verified camp from `subject_token` (kind MUST be
    ///   [`PrincipalKind::Camp`]).
    /// - `actor`: the optional `act` claim — the agent variant acting on the
    ///   user's behalf (RFC 8693).
    /// - `aud`: target resource URI. BOTH principals must hold a grant for
    ///   it (composition rule (5) applies per side).
    /// - `requested_scope`: the scopes the exchange asks for. EVERY entry
    ///   must be in the intersection of the user's expanded-grant scopes AND
    ///   the camp's expanded-grant scopes for this aud. A requested scope
    ///   outside the intersection rejects the whole exchange with
    ///   [`McpMintError::InvalidScope`] — no partial token (RFC 8693 / doc
    ///   §Mint flows).
    /// - `now`: unix seconds. `iat = now`, `exp = now + policy.access_ttl`.
    ///
    /// Result claim:
    /// `{sub: user:<U>, act: {sub: agent:<V>}?, camp_id: <C>, scope: [...requested...], owns: {...}, auth_strength: "user-fresh"}`.
    /// `owns` is the CAMP's ownership (not the user's) — the call is scoped
    /// to the camp's resources. Audit (R020-F13) captures both legs from the
    /// resulting claim plus the endpoint's request context.
    pub async fn mint_token_exchange(
        &self,
        user: PrincipalId,
        camp: PrincipalId,
        actor: Option<Actor>,
        aud: impl Into<String>,
        requested_scope: Vec<Scope>,
        now: i64,
    ) -> Result<MintedMcpToken, McpMintError> {
        if user.kind != PrincipalKind::User {
            return Err(McpMintError::WrongPrincipalKind {
                expected: PrincipalKind::User,
                got: user.kind,
            });
        }
        if camp.kind != PrincipalKind::Camp {
            return Err(McpMintError::WrongPrincipalKind {
                expected: PrincipalKind::Camp,
                got: camp.kind,
            });
        }
        let aud = aud.into();

        // (1) User side — composition rule (5) per side.
        let user_entries = self.grants.list_for(&user, &aud).await?;
        if user_entries.is_empty() {
            return Err(McpMintError::AudNotEntitled {
                principal: user.to_string(),
                aud,
            });
        }
        let user_scopes = expand_scopes(&self.bundles, &user_entries).await?;
        for s in &user_scopes {
            validate_grant(user.kind, *s)?;
        }

        // (2) Camp side — same rule (5) check. Even though the result is
        //     user-attributed, the camp must also be entitled to the
        //     audience.
        let camp_entries = self.grants.list_for(&camp, &aud).await?;
        if camp_entries.is_empty() {
            return Err(McpMintError::AudNotEntitled {
                principal: camp.to_string(),
                aud,
            });
        }
        let camp_scopes = expand_scopes(&self.bundles, &camp_entries).await?;
        for s in &camp_scopes {
            validate_grant(camp.kind, *s)?;
        }

        // (3) RFC 8693 — every requested scope must be in BOTH principals'
        //     expanded grants. Any miss → reject the WHOLE exchange (not a
        //     partial token).
        for s in &requested_scope {
            if !user_scopes.contains(s) || !camp_scopes.contains(s) {
                return Err(McpMintError::InvalidScope {
                    scope: *s,
                    aud: aud.clone(),
                });
            }
        }

        // (4) `owns` comes from the CAMP — the camp is the resource context,
        //     even though `sub` is the user.
        let rows = self.ownership.list_for_principal(&camp).await?;
        let owns = rows_to_owns(&rows);

        let camp_id = camp.id.clone();
        let mut claims = McpClaims::new(
            self.iss.clone(),
            aud,
            user,
            now,
            now + self.policy.access_ttl_seconds,
            generate_jti(),
            requested_scope,
        )
        .with_camp_id(camp_id)
        .with_auth_strength(AuthStrength::UserFresh);
        if let Some(a) = actor {
            claims = claims.with_act(a);
        }
        if !owns.is_empty() {
            claims = claims.with_owns(owns);
        }

        let token = self.minter.mint_mcp(&claims)?;
        Ok(MintedMcpToken { token, claims })
    }
}

/// Convert ownership rows into the [`Owns`] claim shape. Revoked rows are
/// filtered out (the store already excludes them, but a belt-and-braces
/// check keeps the wire shape from leaking stale entries if the store
/// contract evolves). Unknown resource kinds spill into
/// [`Owns::extra`](cheers_core::Owns).
fn rows_to_owns(rows: &[OwnershipRow]) -> Owns {
    let mut o = Owns::default();
    for r in rows {
        if r.is_revoked() {
            continue;
        }
        match r.resource_kind.as_str() {
            "service" => o.service.push(r.resource_id.clone()),
            "arch_doc" => o.arch_doc.push(r.resource_id.clone()),
            other => o
                .extra
                .entry(other.to_owned())
                .or_default()
                .push(r.resource_id.clone()),
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundles::{BundleName, MemoryBundleStore, ScopeOrBundle};
    use crate::codec::PasetoV4SecretMinter;
    use crate::grants::MemoryGrantStore;
    use crate::ownership::{NewOwnership, OwnershipRow, OwnershipStore};
    use async_trait::async_trait;
    use cheers_core::{Scope, StoreError};
    use cheers_verify::PasetoV4PublicVerifier;
    use std::sync::Mutex;

    // ---- in-memory OwnershipStore (test-only) ------------------------------
    //
    // cheers-sqlx ships the persistent impls; cheers-server tests only need
    // a process-local one. Lives here rather than in ownership.rs because
    // F4 deliberately kept that module impl-free for the trait surface.

    #[derive(Default)]
    struct MemOwnershipStore {
        rows: Mutex<Vec<OwnershipRow>>,
        next_id: Mutex<u64>,
    }

    impl MemOwnershipStore {
        fn new() -> Self {
            Self::default()
        }
    }

    #[async_trait]
    impl OwnershipStore for MemOwnershipStore {
        async fn insert(
            &self,
            ownership: &NewOwnership,
            now: i64,
        ) -> Result<OwnershipRow, StoreError> {
            let mut id_g = self.next_id.lock().unwrap();
            *id_g += 1;
            let id = format!("row-{}", *id_g);
            drop(id_g);
            let row = OwnershipRow::new(
                id,
                ownership.principal_id.clone(),
                ownership.resource_kind.clone(),
                ownership.resource_id.clone(),
                ownership.relationship.clone(),
                ownership.granted_by.clone(),
                ownership.on_behalf_of.clone(),
                now,
                None,
            );
            self.rows.lock().unwrap().push(row.clone());
            Ok(row)
        }

        async fn get(&self, id: &str) -> Result<Option<OwnershipRow>, StoreError> {
            Ok(self.rows.lock().unwrap().iter().find(|r| r.id == id).cloned())
        }

        async fn revoke_by_id(&self, id: &str, now: i64) -> Result<(), StoreError> {
            let mut g = self.rows.lock().unwrap();
            let row = g
                .iter_mut()
                .find(|r| r.id == id)
                .ok_or(StoreError::NotFound)?;
            if row.revoked_at.is_none() {
                row.revoked_at = Some(now);
            }
            Ok(())
        }

        async fn revoke_by_on_behalf_of(
            &self,
            user: &PrincipalId,
            now: i64,
        ) -> Result<u64, StoreError> {
            let mut count = 0u64;
            for r in self.rows.lock().unwrap().iter_mut() {
                if r.revoked_at.is_none() && r.on_behalf_of.as_ref() == Some(user) {
                    r.revoked_at = Some(now);
                    count += 1;
                }
            }
            Ok(count)
        }

        async fn list_for_principal(
            &self,
            principal: &PrincipalId,
        ) -> Result<Vec<OwnershipRow>, StoreError> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.revoked_at.is_none() && r.principal_id == *principal)
                .cloned()
                .collect())
        }
    }

    // ---- assembly ----------------------------------------------------------

    fn rig() -> (
        McpAuthority<MemoryBundleStore, MemoryGrantStore, MemOwnershipStore>,
        PasetoV4PublicVerifier,
    ) {
        let (minter, verifier) = PasetoV4SecretMinter::generate().unwrap();
        let bundles = MemoryBundleStore::with_defaults();
        let grants = MemoryGrantStore::new();
        let ownership = MemOwnershipStore::new();
        let authority = McpAuthority::new(minter, bundles, grants, ownership, "https://cheers.example");
        (authority, verifier)
    }

    fn put_simple_grant(authority: &McpAuthority<MemoryBundleStore, MemoryGrantStore, MemOwnershipStore>, principal: PrincipalId, aud: &str, entries: Vec<ScopeOrBundle>) {
        authority.grants.put(principal, aud, entries);
    }

    // ---- McpPolicy ---------------------------------------------------------

    #[test]
    fn mcp_policy_default_is_ten_minutes() {
        let p = McpPolicy::default();
        assert_eq!(p.access_ttl_seconds, 10 * 60);
        let p = McpPolicy::new(300);
        assert_eq!(p.access_ttl_seconds, 300);
        let p = McpPolicy::default().with_access_ttl(5 * 60);
        assert_eq!(p.access_ttl_seconds, 5 * 60);
    }

    // ---- mint_user_fresh: success paths ------------------------------------

    #[test]
    fn mint_user_fresh_signs_token_verifiable_at_edge() {
        let (authority, verifier) = rig();
        let user = PrincipalId::user("alice");
        let aud = "https://constable.camp.example";
        put_simple_grant(
            &authority,
            user.clone(),
            aud,
            vec![ScopeOrBundle::Scope(Scope::CloudDeploy), ScopeOrBundle::Scope(Scope::CloudRead)],
        );

        pollster::block_on(async {
            let minted = authority
                .mint_user_fresh(user.clone(), None, None, aud, 1_000)
                .await
                .unwrap();

            // Token starts with v4.public — the doc-pinned envelope.
            assert!(minted.token.starts_with("v4.public."));
            // auth_strength is user-fresh on this path.
            assert_eq!(minted.claims.auth_strength, Some(AuthStrength::UserFresh));
            // jti is non-empty + iat/exp respect the default TTL (10 min).
            assert!(!minted.claims.jti.is_empty());
            assert_eq!(minted.claims.iat, 1_000);
            assert_eq!(
                minted.claims.exp,
                1_000 + McpPolicy::DEFAULT_ACCESS_TTL_SECONDS
            );
            // Edge verifies the freshly minted token under the public key.
            let back = verifier.verify_mcp_at(&minted.token, 1_100).unwrap();
            assert_eq!(back, minted.claims);
            assert_eq!(back.sub, user);
            assert_eq!(back.scope, vec![Scope::CloudDeploy, Scope::CloudRead]);
        });
    }

    #[test]
    fn mint_user_fresh_expands_bundles_at_mint_time() {
        // A grant of `{"bundle":"deploy-admin"}` lands on the wire as the
        // literal scope list (rule (2)). Edit the bundle, re-mint, see the
        // change without rewriting the grant.
        let (authority, _verifier) = rig();
        let user = PrincipalId::user("bob");
        let aud = "https://constable.example";
        put_simple_grant(
            &authority,
            user.clone(),
            aud,
            vec![ScopeOrBundle::Bundle(BundleName::new("deploy-admin"))],
        );

        pollster::block_on(async {
            let first = authority
                .mint_user_fresh(user.clone(), None, None, aud, 1_000)
                .await
                .unwrap();
            assert!(first.claims.scope.contains(&Scope::CloudDestroy));

            // Edit the bundle: drop CloudDestroy. Grant is untouched.
            authority
                .bundles
                .put(
                    &BundleName::new("deploy-admin"),
                    &[Scope::CloudRead, Scope::CloudDeploy],
                )
                .await
                .unwrap();

            let second = authority
                .mint_user_fresh(user, None, None, aud, 1_100)
                .await
                .unwrap();
            assert!(!second.claims.scope.contains(&Scope::CloudDestroy));
            assert_eq!(second.claims.scope, vec![Scope::CloudRead, Scope::CloudDeploy]);
        });
    }

    #[test]
    fn mint_user_fresh_populates_act_camp_id_and_owns() {
        let (authority, verifier) = rig();
        let user = PrincipalId::user("carol");
        let camp_id = "camp-xyz";
        let aud = "https://aud.example";
        put_simple_grant(
            &authority,
            user.clone(),
            aud,
            vec![ScopeOrBundle::Scope(Scope::CampRead)],
        );
        // Seed two owned resources under the camp principal.
        pollster::block_on(async {
            let svc = NewOwnership::new(
                PrincipalId::camp(camp_id),
                "service",
                "svc-a",
                "owns",
                PrincipalId::service("warden"),
                Some(user.clone()),
            )
            .unwrap();
            authority.ownership.insert(&svc, 500).await.unwrap();

            let doc = NewOwnership::new(
                PrincipalId::camp(camp_id),
                "arch_doc",
                "doc-1",
                "owns",
                PrincipalId::service("warden"),
                Some(user.clone()),
            )
            .unwrap();
            authority.ownership.insert(&doc, 500).await.unwrap();

            let minted = authority
                .mint_user_fresh(
                    user.clone(),
                    Some(Actor::new(PrincipalId::service("agent-claude"))),
                    Some(camp_id.to_owned()),
                    aud,
                    1_000,
                )
                .await
                .unwrap();

            assert_eq!(
                minted.claims.act.as_ref().unwrap().sub,
                PrincipalId::service("agent-claude")
            );
            assert_eq!(minted.claims.camp_id.as_deref(), Some(camp_id));
            assert_eq!(minted.claims.owns.service, vec!["svc-a".to_string()]);
            assert_eq!(minted.claims.owns.arch_doc, vec!["doc-1".to_string()]);

            // Edge accepts it.
            let back = verifier.verify_mcp_at(&minted.token, 1_100).unwrap();
            assert_eq!(back, minted.claims);
        });
    }

    #[test]
    fn mint_user_fresh_omits_owns_when_camp_owns_nothing() {
        // No ownership rows + camp_id present → owns is empty/omitted on the
        // wire. The claim skip_serializing_if guards this; the test pins it.
        let (authority, _verifier) = rig();
        let user = PrincipalId::user("dan");
        let aud = "https://aud.example";
        put_simple_grant(
            &authority,
            user.clone(),
            aud,
            vec![ScopeOrBundle::Scope(Scope::CampRead)],
        );

        pollster::block_on(async {
            let minted = authority
                .mint_user_fresh(user, None, Some("camp-empty".into()), aud, 1_000)
                .await
                .unwrap();
            assert!(minted.claims.owns.is_empty());
            let json = serde_json::to_string(&minted.claims).unwrap();
            assert!(!json.contains("\"owns\""), "empty owns must omit: {json}");
        });
    }

    // ---- mint_user_fresh: rejection paths ----------------------------------

    #[test]
    fn mint_user_fresh_rejects_unentitled_aud() {
        let (authority, _verifier) = rig();
        let user = PrincipalId::user("eve");
        // No grant placed for any aud.
        pollster::block_on(async {
            let err = authority
                .mint_user_fresh(user, None, None, "https://aud.example", 1_000)
                .await
                .unwrap_err();
            match err {
                McpMintError::AudNotEntitled { principal, aud } => {
                    assert_eq!(principal, "user:eve");
                    assert_eq!(aud, "https://aud.example");
                }
                other => panic!("expected AudNotEntitled, got {other:?}"),
            }
        });
    }

    #[test]
    fn mint_user_fresh_rejects_non_user_principal() {
        let (authority, _verifier) = rig();
        pollster::block_on(async {
            let err = authority
                .mint_user_fresh(
                    PrincipalId::service("warden"),
                    None,
                    None,
                    "https://aud.example",
                    1_000,
                )
                .await
                .unwrap_err();
            match err {
                McpMintError::WrongPrincipalKind { expected, got } => {
                    assert_eq!(expected, PrincipalKind::User);
                    assert_eq!(got, PrincipalKind::Service);
                }
                other => panic!("expected WrongPrincipalKind, got {other:?}"),
            }
        });
    }

    #[test]
    fn mint_user_fresh_rejects_service_only_scope_smuggled_via_bundle() {
        // Defence in depth for composition rule (4): if a bundle granted to
        // a User principal contains ownership:write, the mint path catches
        // it via validate_grant BEFORE signing — the misconfigured bundle
        // never becomes a mintable token.
        let (authority, _verifier) = rig();
        let user = PrincipalId::user("mallory");
        let aud = "https://aud.example";

        pollster::block_on(async {
            authority
                .bundles
                .put(
                    &BundleName::new("dangerous"),
                    &[Scope::CampRead, Scope::OwnershipWrite],
                )
                .await
                .unwrap();
            authority.grants.put(
                user.clone(),
                aud,
                vec![ScopeOrBundle::Bundle(BundleName::new("dangerous"))],
            );

            let err = authority
                .mint_user_fresh(user, None, None, aud, 1_000)
                .await
                .unwrap_err();
            match err {
                McpMintError::GrantMisconfigured(GrantError::ServiceOnlyScope { scope, kind }) => {
                    assert_eq!(scope, Scope::OwnershipWrite);
                    assert_eq!(kind, PrincipalKind::User);
                }
                other => panic!("expected GrantMisconfigured(ServiceOnlyScope), got {other:?}"),
            }
        });
    }

    // ---- mint_bootstrap: success paths -------------------------------------

    #[test]
    fn mint_bootstrap_signs_token_verifiable_at_edge() {
        let (authority, verifier) = rig();
        let camp = PrincipalId::camp("c-xyz");
        let aud = "https://constable.camp.example";
        put_simple_grant(
            &authority,
            camp.clone(),
            aud,
            vec![
                ScopeOrBundle::Scope(Scope::CloudDeploy),
                ScopeOrBundle::Scope(Scope::CloudRead),
            ],
        );

        pollster::block_on(async {
            let minted = authority
                .mint_bootstrap(camp.clone(), aud, 1_000)
                .await
                .unwrap();

            // Same v4.public envelope as mint path 1.
            assert!(minted.token.starts_with("v4.public."));
            // auth_strength is bootstrap on this path.
            assert_eq!(minted.claims.auth_strength, Some(AuthStrength::Bootstrap));
            // sub is the camp principal; camp_id is the bare id (no prefix) so
            // a consumer doesn't have to re-parse sub.
            assert_eq!(minted.claims.sub, camp);
            assert_eq!(minted.claims.camp_id.as_deref(), Some("c-xyz"));
            // No act claim — bootstrap is the camp acting as itself, not a
            // user acted-on-by an agent.
            assert!(minted.claims.act.is_none());
            assert!(!minted.claims.jti.is_empty());
            assert_eq!(minted.claims.iat, 1_000);
            assert_eq!(
                minted.claims.exp,
                1_000 + McpPolicy::DEFAULT_ACCESS_TTL_SECONDS
            );

            // Edge verifies the freshly minted token under the public key —
            // no per-call cheers round trip.
            let back = verifier.verify_mcp_at(&minted.token, 1_100).unwrap();
            assert_eq!(back, minted.claims);
            assert_eq!(back.scope, vec![Scope::CloudDeploy, Scope::CloudRead]);
        });
    }

    #[test]
    fn mint_bootstrap_owns_reflects_ownership_table_state() {
        let (authority, _verifier) = rig();
        let camp = PrincipalId::camp("c-with-owns");
        let user = PrincipalId::user("u-on-behalf");
        let aud = "https://aud.example";
        put_simple_grant(
            &authority,
            camp.clone(),
            aud,
            vec![ScopeOrBundle::Scope(Scope::CampRead)],
        );

        pollster::block_on(async {
            // Seed two owned resources under the camp principal — the camp is
            // the holder, the user is the human on whose behalf the grant
            // happened (W159 §audit / on_behalf_of).
            let svc = NewOwnership::new(
                camp.clone(),
                "service",
                "svc-a",
                "owns",
                PrincipalId::service("warden"),
                Some(user.clone()),
            )
            .unwrap();
            authority.ownership.insert(&svc, 500).await.unwrap();

            let doc = NewOwnership::new(
                camp.clone(),
                "arch_doc",
                "doc-1",
                "owns",
                PrincipalId::service("warden"),
                Some(user.clone()),
            )
            .unwrap();
            authority.ownership.insert(&doc, 500).await.unwrap();

            let minted = authority
                .mint_bootstrap(camp.clone(), aud, 1_000)
                .await
                .unwrap();

            assert_eq!(minted.claims.owns.service, vec!["svc-a".to_string()]);
            assert_eq!(minted.claims.owns.arch_doc, vec!["doc-1".to_string()]);
        });
    }

    #[test]
    fn mint_bootstrap_omits_owns_when_camp_owns_nothing() {
        // No ownership rows → owns is empty and omitted on the wire. Same
        // skip_serializing_if guard as mint path 1, pinned independently here
        // because the bootstrap mint path always sets camp_id (a token whose
        // sub is `camp:<C>` is always scoped to that camp).
        let (authority, _verifier) = rig();
        let camp = PrincipalId::camp("c-empty");
        let aud = "https://aud.example";
        put_simple_grant(
            &authority,
            camp.clone(),
            aud,
            vec![ScopeOrBundle::Scope(Scope::CampRead)],
        );

        pollster::block_on(async {
            let minted = authority
                .mint_bootstrap(camp, aud, 1_000)
                .await
                .unwrap();
            assert!(minted.claims.owns.is_empty());
            let json = serde_json::to_string(&minted.claims).unwrap();
            assert!(!json.contains("\"owns\""), "empty owns must omit: {json}");
            // camp_id is still present even when owns is empty.
            assert!(json.contains("\"camp_id\":\"c-empty\""), "camp_id must remain: {json}");
        });
    }

    #[test]
    fn mint_bootstrap_expands_bundles_at_mint_time() {
        // Same propagation property as F5/F6: a bundle edit shows up on the
        // next mint without rewriting the camp's grant.
        let (authority, _verifier) = rig();
        let camp = PrincipalId::camp("c-deploy");
        let aud = "https://aud.example";
        put_simple_grant(
            &authority,
            camp.clone(),
            aud,
            vec![ScopeOrBundle::Bundle(BundleName::new("deploy-admin"))],
        );

        pollster::block_on(async {
            let first = authority
                .mint_bootstrap(camp.clone(), aud, 1_000)
                .await
                .unwrap();
            assert!(first.claims.scope.contains(&Scope::CloudDestroy));

            authority
                .bundles
                .put(
                    &BundleName::new("deploy-admin"),
                    &[Scope::CloudRead, Scope::CloudDeploy],
                )
                .await
                .unwrap();

            let second = authority
                .mint_bootstrap(camp, aud, 1_100)
                .await
                .unwrap();
            assert!(!second.claims.scope.contains(&Scope::CloudDestroy));
            assert_eq!(second.claims.scope, vec![Scope::CloudRead, Scope::CloudDeploy]);
        });
    }

    // ---- mint_bootstrap: rejection paths -----------------------------------

    #[test]
    fn mint_bootstrap_rejects_non_camp_principal() {
        let (authority, _verifier) = rig();
        pollster::block_on(async {
            // A user principal handed to the bootstrap path is a programmer
            // error — surfaces WrongPrincipalKind, not a 403.
            let err = authority
                .mint_bootstrap(
                    PrincipalId::user("alice"),
                    "https://aud.example",
                    1_000,
                )
                .await
                .unwrap_err();
            match err {
                McpMintError::WrongPrincipalKind { expected, got } => {
                    assert_eq!(expected, PrincipalKind::Camp);
                    assert_eq!(got, PrincipalKind::User);
                }
                other => panic!("expected WrongPrincipalKind, got {other:?}"),
            }

            // Same for a service principal.
            let err = authority
                .mint_bootstrap(
                    PrincipalId::service("warden"),
                    "https://aud.example",
                    1_000,
                )
                .await
                .unwrap_err();
            match err {
                McpMintError::WrongPrincipalKind { expected, got } => {
                    assert_eq!(expected, PrincipalKind::Camp);
                    assert_eq!(got, PrincipalKind::Service);
                }
                other => panic!("expected WrongPrincipalKind, got {other:?}"),
            }
        });
    }

    #[test]
    fn mint_bootstrap_rejects_unentitled_aud() {
        let (authority, _verifier) = rig();
        let camp = PrincipalId::camp("c-no-grants");
        // No grant placed for any aud — composition rule (5).
        pollster::block_on(async {
            let err = authority
                .mint_bootstrap(camp, "https://aud.example", 1_000)
                .await
                .unwrap_err();
            match err {
                McpMintError::AudNotEntitled { principal, aud } => {
                    assert_eq!(principal, "camp:c-no-grants");
                    assert_eq!(aud, "https://aud.example");
                }
                other => panic!("expected AudNotEntitled, got {other:?}"),
            }
        });
    }

    #[test]
    fn mint_bootstrap_rejects_service_only_scope_smuggled_via_bundle() {
        // Composition rule (4) — `ownership:write` and `audit:write` are
        // grantable to kind=service ONLY. A bundle granted to a camp
        // principal that expands to a service-only scope is rejected by
        // validate_grant BEFORE signing, mirroring F6's defence in depth on
        // the user path.
        let (authority, _verifier) = rig();
        let camp = PrincipalId::camp("c-sneaky");
        let aud = "https://aud.example";

        pollster::block_on(async {
            authority
                .bundles
                .put(
                    &BundleName::new("dangerous"),
                    &[Scope::CampRead, Scope::OwnershipWrite],
                )
                .await
                .unwrap();
            authority.grants.put(
                camp.clone(),
                aud,
                vec![ScopeOrBundle::Bundle(BundleName::new("dangerous"))],
            );

            let err = authority
                .mint_bootstrap(camp, aud, 1_000)
                .await
                .unwrap_err();
            match err {
                McpMintError::GrantMisconfigured(GrantError::ServiceOnlyScope { scope, kind }) => {
                    assert_eq!(scope, Scope::OwnershipWrite);
                    assert_eq!(kind, PrincipalKind::Camp);
                }
                other => panic!("expected GrantMisconfigured(ServiceOnlyScope), got {other:?}"),
            }
        });
    }

    // ---- mint_token_exchange: success paths --------------------------------

    #[test]
    fn mint_token_exchange_attributes_to_user_with_camp_as_context() {
        let (authority, verifier) = rig();
        let user = PrincipalId::user("alice");
        let camp = PrincipalId::camp("c-multi");
        let aud = "https://constable.camp.example";

        // User holds CloudDeploy + CloudRead for this aud; camp holds the
        // same. Requested scope is a subset.
        put_simple_grant(
            &authority,
            user.clone(),
            aud,
            vec![
                ScopeOrBundle::Scope(Scope::CloudDeploy),
                ScopeOrBundle::Scope(Scope::CloudRead),
            ],
        );
        put_simple_grant(
            &authority,
            camp.clone(),
            aud,
            vec![
                ScopeOrBundle::Scope(Scope::CloudDeploy),
                ScopeOrBundle::Scope(Scope::CloudRead),
            ],
        );

        // Camp owns a service — owns claim must come from the camp.
        pollster::block_on(async {
            let svc = NewOwnership::new(
                camp.clone(),
                "service",
                "svc-prod",
                "owns",
                PrincipalId::service("warden"),
                Some(user.clone()),
            )
            .unwrap();
            authority.ownership.insert(&svc, 500).await.unwrap();

            let minted = authority
                .mint_token_exchange(
                    user.clone(),
                    camp.clone(),
                    Some(Actor::new(PrincipalId::service("agent-claude"))),
                    aud,
                    vec![Scope::CloudDeploy],
                    1_000,
                )
                .await
                .unwrap();

            assert!(minted.token.starts_with("v4.public."));
            // sub is the USER, not the camp — exchange attributes to the
            // human even though the camp is the bearer at the HTTP layer.
            assert_eq!(minted.claims.sub, user);
            // camp_id carries the camp context (bare id, no prefix).
            assert_eq!(minted.claims.camp_id.as_deref(), Some("c-multi"));
            // act carries the agent variant.
            assert_eq!(
                minted.claims.act.as_ref().unwrap().sub,
                PrincipalId::service("agent-claude"),
            );
            // user-fresh — the user authenticated locally.
            assert_eq!(minted.claims.auth_strength, Some(AuthStrength::UserFresh));
            // Result scope is the requested scope (verified in intersection).
            assert_eq!(minted.claims.scope, vec![Scope::CloudDeploy]);
            // owns comes from the CAMP, not the user.
            assert_eq!(minted.claims.owns.service, vec!["svc-prod".to_string()]);
            // jti present, iat/exp respect policy.
            assert!(!minted.claims.jti.is_empty());
            assert_eq!(minted.claims.iat, 1_000);
            assert_eq!(
                minted.claims.exp,
                1_000 + McpPolicy::DEFAULT_ACCESS_TTL_SECONDS
            );
            // Edge verifies.
            let back = verifier.verify_mcp_at(&minted.token, 1_100).unwrap();
            assert_eq!(back, minted.claims);
        });
    }

    #[test]
    fn mint_token_exchange_intersection_drops_scope_one_side_lacks() {
        // Verify intersection by removing a scope from one side and observing
        // it's rejected at the requested-scope check — proves the camp's
        // grants actually narrow the user's, not just rubber-stamp the
        // request.
        let (authority, _verifier) = rig();
        let user = PrincipalId::user("bob");
        let camp = PrincipalId::camp("c-narrow");
        let aud = "https://aud.example";

        // User has both; camp has only CloudRead.
        put_simple_grant(
            &authority,
            user.clone(),
            aud,
            vec![
                ScopeOrBundle::Scope(Scope::CloudDeploy),
                ScopeOrBundle::Scope(Scope::CloudRead),
            ],
        );
        put_simple_grant(
            &authority,
            camp.clone(),
            aud,
            vec![ScopeOrBundle::Scope(Scope::CloudRead)],
        );

        pollster::block_on(async {
            // Requesting CloudRead alone succeeds — in both.
            let minted = authority
                .mint_token_exchange(
                    user.clone(),
                    camp.clone(),
                    None,
                    aud,
                    vec![Scope::CloudRead],
                    1_000,
                )
                .await
                .unwrap();
            assert_eq!(minted.claims.scope, vec![Scope::CloudRead]);

            // Requesting CloudDeploy fails — camp lacks it. The whole
            // exchange rejects (not a partial token).
            let err = authority
                .mint_token_exchange(
                    user,
                    camp,
                    None,
                    aud,
                    vec![Scope::CloudRead, Scope::CloudDeploy],
                    1_000,
                )
                .await
                .unwrap_err();
            match err {
                McpMintError::InvalidScope { scope, aud: a } => {
                    assert_eq!(scope, Scope::CloudDeploy);
                    assert_eq!(a, aud);
                }
                other => panic!("expected InvalidScope, got {other:?}"),
            }
        });
    }

    #[test]
    fn mint_token_exchange_rejects_scope_user_lacks() {
        // Mirror case: camp has it, user doesn't. Same all-or-nothing reject.
        let (authority, _verifier) = rig();
        let user = PrincipalId::user("carol");
        let camp = PrincipalId::camp("c-wide");
        let aud = "https://aud.example";

        put_simple_grant(
            &authority,
            user.clone(),
            aud,
            vec![ScopeOrBundle::Scope(Scope::CloudRead)],
        );
        put_simple_grant(
            &authority,
            camp.clone(),
            aud,
            vec![
                ScopeOrBundle::Scope(Scope::CloudRead),
                ScopeOrBundle::Scope(Scope::CloudDeploy),
            ],
        );

        pollster::block_on(async {
            let err = authority
                .mint_token_exchange(
                    user,
                    camp,
                    None,
                    aud,
                    vec![Scope::CloudDeploy],
                    1_000,
                )
                .await
                .unwrap_err();
            match err {
                McpMintError::InvalidScope { scope, aud: _ } => {
                    assert_eq!(scope, Scope::CloudDeploy);
                }
                other => panic!("expected InvalidScope, got {other:?}"),
            }
        });
    }

    // ---- mint_token_exchange: rejection paths ------------------------------

    #[test]
    fn mint_token_exchange_rejects_wrong_user_kind() {
        let (authority, _verifier) = rig();
        pollster::block_on(async {
            let err = authority
                .mint_token_exchange(
                    PrincipalId::camp("c-as-user"),
                    PrincipalId::camp("c"),
                    None,
                    "https://aud.example",
                    vec![],
                    1_000,
                )
                .await
                .unwrap_err();
            match err {
                McpMintError::WrongPrincipalKind { expected, got } => {
                    assert_eq!(expected, PrincipalKind::User);
                    assert_eq!(got, PrincipalKind::Camp);
                }
                other => panic!("expected WrongPrincipalKind, got {other:?}"),
            }
        });
    }

    #[test]
    fn mint_token_exchange_rejects_wrong_camp_kind() {
        let (authority, _verifier) = rig();
        pollster::block_on(async {
            let err = authority
                .mint_token_exchange(
                    PrincipalId::user("alice"),
                    PrincipalId::service("warden"),
                    None,
                    "https://aud.example",
                    vec![],
                    1_000,
                )
                .await
                .unwrap_err();
            match err {
                McpMintError::WrongPrincipalKind { expected, got } => {
                    assert_eq!(expected, PrincipalKind::Camp);
                    assert_eq!(got, PrincipalKind::Service);
                }
                other => panic!("expected WrongPrincipalKind, got {other:?}"),
            }
        });
    }

    #[test]
    fn mint_token_exchange_rejects_unentitled_user() {
        let (authority, _verifier) = rig();
        let user = PrincipalId::user("eve");
        let camp = PrincipalId::camp("c");
        let aud = "https://aud.example";
        // Camp has a grant, user doesn't — must reject on the user side.
        put_simple_grant(
            &authority,
            camp.clone(),
            aud,
            vec![ScopeOrBundle::Scope(Scope::CloudRead)],
        );

        pollster::block_on(async {
            let err = authority
                .mint_token_exchange(user, camp, None, aud, vec![Scope::CloudRead], 1_000)
                .await
                .unwrap_err();
            match err {
                McpMintError::AudNotEntitled { principal, aud: _ } => {
                    assert_eq!(principal, "user:eve");
                }
                other => panic!("expected AudNotEntitled, got {other:?}"),
            }
        });
    }

    #[test]
    fn mint_token_exchange_rejects_unentitled_camp() {
        // Mirror: user has a grant, camp doesn't. Composition rule (5)
        // applies per side, so the camp's empty grant list rejects.
        let (authority, _verifier) = rig();
        let user = PrincipalId::user("frank");
        let camp = PrincipalId::camp("c-no-grants");
        let aud = "https://aud.example";
        put_simple_grant(
            &authority,
            user.clone(),
            aud,
            vec![ScopeOrBundle::Scope(Scope::CloudRead)],
        );

        pollster::block_on(async {
            let err = authority
                .mint_token_exchange(user, camp, None, aud, vec![Scope::CloudRead], 1_000)
                .await
                .unwrap_err();
            match err {
                McpMintError::AudNotEntitled { principal, aud: _ } => {
                    assert_eq!(principal, "camp:c-no-grants");
                }
                other => panic!("expected AudNotEntitled, got {other:?}"),
            }
        });
    }

    #[test]
    fn mint_token_exchange_catches_service_only_scope_smuggled_via_camp_bundle() {
        // Defence in depth — composition rule (4) — even on the exchange
        // path: a camp bundle that expands to OwnershipWrite is caught by
        // validate_grant(Camp, scope) BEFORE intersection is computed.
        let (authority, _verifier) = rig();
        let user = PrincipalId::user("g");
        let camp = PrincipalId::camp("c-sneaky");
        let aud = "https://aud.example";

        pollster::block_on(async {
            authority
                .bundles
                .put(
                    &BundleName::new("dangerous"),
                    &[Scope::CampRead, Scope::OwnershipWrite],
                )
                .await
                .unwrap();
            put_simple_grant(
                &authority,
                user.clone(),
                aud,
                vec![ScopeOrBundle::Scope(Scope::CampRead)],
            );
            put_simple_grant(
                &authority,
                camp,
                aud,
                vec![ScopeOrBundle::Bundle(BundleName::new("dangerous"))],
            );

            let err = authority
                .mint_token_exchange(
                    user,
                    PrincipalId::camp("c-sneaky"),
                    None,
                    aud,
                    vec![Scope::CampRead],
                    1_000,
                )
                .await
                .unwrap_err();
            match err {
                McpMintError::GrantMisconfigured(GrantError::ServiceOnlyScope { scope, kind }) => {
                    assert_eq!(scope, Scope::OwnershipWrite);
                    assert_eq!(kind, PrincipalKind::Camp);
                }
                other => panic!("expected GrantMisconfigured(ServiceOnlyScope), got {other:?}"),
            }
        });
    }

    // ---- McpMintError → Error conversion -----------------------------------

    #[test]
    fn mcp_mint_error_converts_to_umbrella_error() {
        let e: Error = McpMintError::AudNotEntitled {
            principal: "user:x".into(),
            aud: "a".into(),
        }
        .into();
        match e {
            Error::InvalidInput(msg) => assert!(msg.contains("aud")),
            other => panic!("expected InvalidInput, got {other:?}"),
        }

        let e: Error = McpMintError::Store(StoreError::Conflict).into();
        assert!(matches!(e, Error::Store(StoreError::Conflict)));

        let e: Error = McpMintError::Codec(CodecError::Malformed).into();
        assert!(matches!(e, Error::Codec(CodecError::Malformed)));
    }
}
