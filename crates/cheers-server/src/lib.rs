//! # cheers-server — the origin-side surface
//!
//! The mint half of edge-verifiable auth (R019): everything that can *create or
//! destroy* a session, plus the origin-homed stores. Holding any of this is
//! origin-only power, which is why it lives below `cheers-verify` in the DAG and
//! never leaks to the edge.
//!
//! - [`codec`] — the concrete token codecs. The symmetric [`PasetoV4Codec`]
//!   (v4.local, encrypted) and [`HmacBlobCodec`] (HMAC-SHA256) impl *both*
//!   [`TokenMinter`](cheers_core::TokenMinter) and
//!   [`TokenVerifier`](cheers_core::TokenVerifier) on one type, so they MUST live
//!   here — putting them in `cheers-verify` would re-grant mint to the edge. The
//!   asymmetric [`PasetoV4SecretMinter`] (Ed25519 secret key) mints only; its
//!   matching public verifier lives in `cheers-verify`.
//! - [`store`] — the origin stores [`UserStore`] and [`RefreshStore`]
//!   (`CredentialStore`, the device store, stays in `cheers-core`).
//! - [`refresh`] — refresh-token rotation with replay detection.
//! - [`revocation`] — [`RevocationWriter`], the cold-path write side (the edge
//!   holds `cheers_verify::RevocationReader`).
//! - [`standing`] — the [`StandingBinder`] that mints standing node bindings
//!   for LanPair sessions, and its per-device [`BindingSequenceStore`].
//! - [`session`] — the [`SessionAuthority`] facade that assembles the above.
//!
//! This crate depends on `cheers-verify` (and through it `cheers-core`); the
//! reverse never holds, which is what keeps the edge minter-free.

pub mod audit;
pub mod bundles;
pub mod camp;
pub mod codec;
pub mod grants;
pub mod knock;
pub mod mcp_authority;
pub mod ownership;
pub mod refresh;
pub mod revocation;
pub mod service_principal;
pub mod session;
pub mod snapshot;
pub mod standing;
pub mod store;
pub mod user_tokens;

pub use audit::{
    AuditCursor, AuditCursorError, AuditPage, AuditQuery, AuditQueryError, AuditRecord, AuditRow,
    AuditStore, AuditValidationError, DEFAULT_AUDIT_PAGE_LIMIT, MAX_AUDIT_PAGE_LIMIT,
    MemoryAuditStore,
};
pub use bundles::{
    BundleExpansionError, BundleName, BundleStore, MemoryBundleStore, ScopeOrBundle,
    expand_scopes,
};
pub use camp::{
    CampAuthority, CampAuthorityError, CampBootstrapCredential, CampBootstrapPolicy,
    CampPrincipalStore, MemoryCampPrincipalStore, MemoryUserSigningKeyStore, NewCampPrincipal,
    ProvisionedCamp, UserSigningKey, UserSigningKeyStatus, UserSigningKeyStore,
};
pub use codec::{HmacBlobCodec, PasetoV4Codec, PasetoV4SecretMinter};
pub use grants::{GrantStore, SchemaGrantStore};
pub use knock::{
    Admission, Admitted, KnockAuthority, KnockConfig, KnockFlowError, KnockStore, MemoryKnockStore, PendingKnock, Queued,
    Reconciled, Redeemed, StoredOffer,
};
pub use mcp_authority::{McpAuthority, McpMintError, McpPolicy, MintedMcpToken};
pub use ownership::{
    new_revocation_key, next_ownership_version, Inserted, MemoryOwnershipStore, NewOwnership, OwnershipRow, OwnershipStore,
    OwnershipTuples, OwnershipValidationError, SeedTuple, TupleLease, seed_ownership,
};
pub use refresh::{ChainId, LiveRefresh, RefreshRotator, RefreshToken, Rotated};
pub use revocation::{
    epoch_from_sql, next_epoch, revoked_columns, revoked_from_columns, MemoryRevocationStore, RevokedColumns,
    RevocationPublisher, RevocationSnapshot, RevocationWriter, SignedRevocationSet,
};
pub use service_principal::{
    MemoryServicePrincipalStore, NewServicePrincipal, OverlapPolicy, ProvisionedKey,
    ServicePrincipalAuthority, ServicePrincipalError, ServicePrincipalStore, SigningKey,
    SigningKeyStatus,
};
pub use session::{BindingResolver, NewSession, SessionAuthority, SessionPolicy};
pub use snapshot::{revoke_ownership, revoke_principal_ownership, SignedSetSnapshot, SnapshotIssuer};
pub use standing::{
    next_binding_seq, BindingSequenceStore, MemoryBindingSequenceStore, SignedStandingBinding,
    StandingBinder,
};
pub use user_tokens::{
    decode_scopes, encode_scopes, MemoryUserTokenStore, UserTokenRecord, UserTokenStore,
};
pub use store::{
    NewUser, PasskeyCredentialStore, ProviderKey, RefreshStore, RefreshTokenRecord, UserStore,
};

// Re-exported for convenience so an origin consumer can assemble the verify-side
// pieces (the public verifier + the EdgeVerifier facade) from one crate.
pub use cheers_verify::{
    EdgeVerifier, IssuerTrust, PasetoV4PublicVerifier, ReplicatedRevocations, RevocationReader,
    SnapshotVerifier, StandingVerifier,
};
