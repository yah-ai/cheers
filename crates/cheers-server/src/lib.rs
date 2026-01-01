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
//! - [`session`] — the [`SessionAuthority`] facade that assembles the above.
//!
//! This crate depends on `cheers-verify` (and through it `cheers-core`); the
//! reverse never holds, which is what keeps the edge minter-free.

pub mod bundles;
pub mod camp;
pub mod codec;
pub mod grants;
pub mod mcp_authority;
pub mod ownership;
pub mod refresh;
pub mod revocation;
pub mod service_principal;
pub mod session;
pub mod store;

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
pub use grants::{GrantStore, MemoryGrantStore};
pub use mcp_authority::{McpAuthority, McpMintError, McpPolicy, MintedMcpToken};
pub use ownership::{NewOwnership, OwnershipRow, OwnershipStore, OwnershipValidationError};
pub use refresh::{ChainId, RefreshRotator, RefreshToken, Rotated};
pub use revocation::RevocationWriter;
pub use service_principal::{
    MemoryServicePrincipalStore, NewServicePrincipal, OverlapPolicy, ProvisionedKey,
    ServicePrincipalAuthority, ServicePrincipalError, ServicePrincipalStore, SigningKey,
    SigningKeyStatus,
};
pub use session::{NewSession, SessionAuthority, SessionPolicy};
pub use store::{
    NewUser, PasskeyCredentialStore, ProviderKey, RefreshStore, RefreshTokenRecord, UserStore,
};

// Re-exported for convenience so an origin consumer can assemble the verify-side
// pieces (the public verifier + the EdgeVerifier facade) from one crate.
pub use cheers_verify::{EdgeVerifier, PasetoV4PublicVerifier, RevocationReader};
