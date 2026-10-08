//! Knock on the issuer side: online knocks, offers, and reconciliation of
//! offline `Admit`s (`knock.md`, "Reconciliation", "Sybil controls";
//! R734-F4).
//!
//! Every path ends in the same tuple: the requester's key holds the relation
//! on the resource, `granted_by` the approver (the user when the approver
//! proved one through a standing binding or an access token, else the
//! approver's own key), and the lease the admission carried. An online
//! knock-and-admit and an uploaded `Admit` for the same grant write the same
//! row.
//!
//! **The admit ability** is [`AdmissionPolicy::admitters`], read from the
//! live policy row and checked against live tuples with
//! [`SchemaRegistry::holds`] (implies-closure included). The edge reads the
//! same field off the signed snapshot, whose members are closure-expanded at
//! mint, so both answer the same question the same way.
//!
//! **Every path is evaluated under the live policy** with
//! [`evaluate_admit`]: an online admission obeys the dial exactly as an
//! offline one does, so `closed` stops online knocks too (an operator can
//! still write tuples through the ownership routes).
//!
//! **Renewal.** Writing an admitted tuple revokes any live *leased* tuple the
//! requester already holds for the same relation on the same resource, so a
//! re-admit (a `Knock` naming the prior `Admit` in `renews`, or simply a
//! fresh `Admit`) replaces the old lease with the new one. A standing
//! (unleased) tuple is never replaced; the admission returns it as is.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use cheers_core::{
    evaluate_admit, Admit, AdmissionPath, AdmissionPolicy, AdmissionRefusal, AdmitFacts, CodecError, Confirmation, Knock,
    KnockError, LeaseRequest, Offer, PeerKey, PrincipalId, PrincipalKind, Revoked, SchemaRegistry, StoreError, UserId,
};
use cheers_verify::{verify_device_artifact, PasetoV4PublicVerifier, RevocationReader, StandingError, StandingVerifier};
use serde::{Deserialize, Serialize};

use crate::codec::PasetoV4SecretMinter;
use crate::ownership::{NewOwnership, OwnershipRow, OwnershipStore, OwnershipTuples, TupleLease};
use crate::revocation::RevocationWriter;

/// Sybil bounds and lifetimes for the knock routes (`knock.md`, "Sybil
/// controls"). The rate limits are enforced by the HTTP layer
/// (`cheers-axum`), the rest here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnockConfig {
    /// Seconds a pending knock waits before it lapses.
    pub pending_ttl: i64,
    /// Pending knocks one resource holds at most.
    pub pending_cap: usize,
    /// `POST /knock` per source (client address) per minute.
    pub knocks_per_source_per_minute: u32,
    /// `POST /knock` per resource per minute.
    pub knocks_per_resource_per_minute: u32,
    /// Seconds an online `Offer` stays redeemable.
    pub offer_ttl: i64,
}

impl Default for KnockConfig {
    fn default() -> Self {
        Self {
            pending_ttl: 24 * 60 * 60,
            pending_cap: 64,
            knocks_per_source_per_minute: 10,
            knocks_per_resource_per_minute: 60,
            offer_ttl: 60 * 60,
        }
    }
}

/// A knock waiting for an approver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingKnock {
    pub id: String,
    pub resource_kind: String,
    pub resource_id: String,
    pub requester: PrincipalId,
    pub relation: String,
    pub label: String,
    /// The user the requester's standing binding proved, if it presented one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester_user: Option<UserId>,
    /// The prior `Admit` jti this knock renews.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renews: Option<String>,
    /// The signed `Knock`, verbatim.
    pub token: String,
    pub created_at: i64,
    pub expires_at: i64,
}

/// An online offer as the issuer recorded it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredOffer {
    pub jti: String,
    pub resource_kind: String,
    pub resource_id: String,
    pub relation: String,
    pub created_by: PrincipalId,
    pub max_uses: u32,
    pub created_at: i64,
    pub exp: i64,
}

/// What [`KnockStore::queue_knock`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Queued {
    Queued,
    /// The requester's earlier pending knock on this resource was replaced.
    Replaced,
    /// The resource already holds `cap` other pending knocks.
    Full,
}

/// What [`KnockStore::redeem_offer`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Redeemed {
    /// A new redemption by this key.
    Fresh(StoredOffer),
    /// This key had already redeemed it.
    Again(StoredOffer),
    Exhausted,
    Expired,
    Unknown,
}

/// An admission's recorded outcome, by jti.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum Admission {
    Accepted { ownership_id: String },
    Refused { refusal: String },
}

/// Persistence for knocks, offers and admission outcomes (migration 0017).
#[async_trait]
pub trait KnockStore: Send + Sync {
    /// Queue `knock`. Pending knocks on its resource that lapsed at `now` are
    /// dropped first; the requester's own earlier one is replaced in place;
    /// otherwise it is refused ([`Queued::Full`]) when `cap` others wait.
    async fn queue_knock(&self, knock: &PendingKnock, cap: usize, now: i64) -> Result<Queued, StoreError>;

    /// Unlapsed pending knocks on one resource, oldest first.
    async fn pending_knocks(&self, kind: &str, id: &str, now: i64) -> Result<Vec<PendingKnock>, StoreError>;

    /// One unlapsed pending knock by id.
    async fn pending_knock(&self, id: &str, now: i64) -> Result<Option<PendingKnock>, StoreError>;

    /// Remove a pending knock (it was answered). Idempotent.
    async fn drop_knock(&self, id: &str) -> Result<(), StoreError>;

    async fn put_offer(&self, offer: &StoredOffer) -> Result<(), StoreError>;

    /// Redeem `jti` for `redeemer`, atomically against `max_uses` (distinct
    /// keys) and `exp`.
    async fn redeem_offer(&self, jti: &str, redeemer: &PrincipalId, now: i64) -> Result<Redeemed, StoreError>;

    async fn admission(&self, jti: &str) -> Result<Option<Admission>, StoreError>;

    /// Record `outcome` for `jti` unless one is recorded already; returns the
    /// outcome that stands (the earlier one on a race).
    async fn record_admission(&self, jti: &str, outcome: &Admission, now: i64) -> Result<Admission, StoreError>;
}

#[async_trait]
impl<T: KnockStore + ?Sized> KnockStore for Arc<T> {
    async fn queue_knock(&self, knock: &PendingKnock, cap: usize, now: i64) -> Result<Queued, StoreError> {
        (**self).queue_knock(knock, cap, now).await
    }
    async fn pending_knocks(&self, kind: &str, id: &str, now: i64) -> Result<Vec<PendingKnock>, StoreError> {
        (**self).pending_knocks(kind, id, now).await
    }
    async fn pending_knock(&self, id: &str, now: i64) -> Result<Option<PendingKnock>, StoreError> {
        (**self).pending_knock(id, now).await
    }
    async fn drop_knock(&self, id: &str) -> Result<(), StoreError> {
        (**self).drop_knock(id).await
    }
    async fn put_offer(&self, offer: &StoredOffer) -> Result<(), StoreError> {
        (**self).put_offer(offer).await
    }
    async fn redeem_offer(&self, jti: &str, redeemer: &PrincipalId, now: i64) -> Result<Redeemed, StoreError> {
        (**self).redeem_offer(jti, redeemer, now).await
    }
    async fn admission(&self, jti: &str) -> Result<Option<Admission>, StoreError> {
        (**self).admission(jti).await
    }
    async fn record_admission(&self, jti: &str, outcome: &Admission, now: i64) -> Result<Admission, StoreError> {
        (**self).record_admission(jti, outcome, now).await
    }
}

/// In-process [`KnockStore`]. Clones share one table; each call takes one
/// lock, so every operation is atomic.
#[derive(Debug, Clone, Default)]
pub struct MemoryKnockStore(Arc<Mutex<MemoryKnocks>>);

#[derive(Debug, Default)]
struct MemoryKnocks {
    pending: Vec<PendingKnock>,
    offers: HashMap<String, StoredOffer>,
    redemptions: HashMap<String, Vec<PrincipalId>>,
    admissions: HashMap<String, Admission>,
}

impl MemoryKnockStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MemoryKnocks> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[async_trait]
impl KnockStore for MemoryKnockStore {
    async fn queue_knock(&self, knock: &PendingKnock, cap: usize, now: i64) -> Result<Queued, StoreError> {
        let mut t = self.lock();
        let on = |p: &PendingKnock| p.resource_kind == knock.resource_kind && p.resource_id == knock.resource_id;
        t.pending.retain(|p| !(on(p) && p.expires_at <= now));
        let replaced = t.pending.iter().any(|p| on(p) && p.requester == knock.requester);
        let others = t.pending.iter().filter(|p| on(p) && p.requester != knock.requester).count();
        if others >= cap {
            return Ok(Queued::Full);
        }
        t.pending.retain(|p| !(on(p) && p.requester == knock.requester));
        t.pending.push(knock.clone());
        Ok(if replaced { Queued::Replaced } else { Queued::Queued })
    }
    async fn pending_knocks(&self, kind: &str, id: &str, now: i64) -> Result<Vec<PendingKnock>, StoreError> {
        let mut out: Vec<_> = self
            .lock()
            .pending
            .iter()
            .filter(|p| p.resource_kind == kind && p.resource_id == id && p.expires_at > now)
            .cloned()
            .collect();
        out.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
        Ok(out)
    }
    async fn pending_knock(&self, id: &str, now: i64) -> Result<Option<PendingKnock>, StoreError> {
        Ok(self.lock().pending.iter().find(|p| p.id == id && p.expires_at > now).cloned())
    }
    async fn drop_knock(&self, id: &str) -> Result<(), StoreError> {
        self.lock().pending.retain(|p| p.id != id);
        Ok(())
    }
    async fn put_offer(&self, offer: &StoredOffer) -> Result<(), StoreError> {
        let mut t = self.lock();
        if t.offers.contains_key(&offer.jti) {
            return Err(StoreError::Conflict);
        }
        t.offers.insert(offer.jti.clone(), offer.clone());
        Ok(())
    }
    async fn redeem_offer(&self, jti: &str, redeemer: &PrincipalId, now: i64) -> Result<Redeemed, StoreError> {
        let mut t = self.lock();
        let Some(offer) = t.offers.get(jti).cloned() else {
            return Ok(Redeemed::Unknown);
        };
        let used = t.redemptions.entry(jti.to_owned()).or_default();
        if used.contains(redeemer) {
            return Ok(Redeemed::Again(offer));
        }
        if offer.exp <= now {
            return Ok(Redeemed::Expired);
        }
        if used.len() >= offer.max_uses as usize {
            return Ok(Redeemed::Exhausted);
        }
        used.push(redeemer.clone());
        Ok(Redeemed::Fresh(offer))
    }
    async fn admission(&self, jti: &str) -> Result<Option<Admission>, StoreError> {
        Ok(self.lock().admissions.get(jti).cloned())
    }
    async fn record_admission(&self, jti: &str, outcome: &Admission, _now: i64) -> Result<Admission, StoreError> {
        Ok(self.lock().admissions.entry(jti.to_owned()).or_insert_with(|| outcome.clone()).clone())
    }
}

/// Why a knock operation failed.
#[derive(Debug, thiserror::Error)]
pub enum KnockFlowError {
    #[error("artifact refused: {0}")]
    Artifact(#[from] CodecError),
    #[error("artifact invalid: {0}")]
    Invalid(#[from] KnockError),
    #[error(transparent)]
    Standing(#[from] StandingError),
    #[error("admit names authority {got}, expected {expected}")]
    WrongAuthority { expected: String, got: String },
    #[error("admit expired at {exp}")]
    Expired { exp: i64 },
    #[error("{0} does not hold the admit ability on this resource")]
    NotAnApprover(PrincipalId),
    #[error("this resource has too many pending knocks")]
    PendingFull,
    #[error("no such pending knock")]
    UnknownKnock,
    #[error("no such offer")]
    UnknownOffer,
    #[error("offer used up")]
    OfferExhausted,
    #[error("offer expired")]
    OfferExpired,
    #[error("knock does not match the offer: {0}")]
    OfferMismatch(&'static str),
    #[error("admission refused: {0}")]
    Refused(#[from] AdmissionRefusal),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// A tuple an admission wrote (or found).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admitted {
    /// The admission's jti: the uploaded `Admit`'s, `knock:<id>` for an
    /// online knock, `offer:<jti>:<key>` for a redemption. A later `Knock`
    /// may name it in `renews`.
    pub jti: String,
    pub row: OwnershipRow,
}

/// What reconciling an uploaded `Admit` decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reconciled {
    Accepted(Admitted),
    /// Refused and recorded as `Revoked::Jti`, so edges drop it.
    Refused { jti: String, refusal: String },
}

/// The issuer side of knock (module docs).
pub struct KnockAuthority<Rd> {
    schema: Arc<SchemaRegistry>,
    ownership: Arc<dyn OwnershipStore>,
    knocks: Arc<dyn KnockStore>,
    revocations: Arc<dyn RevocationWriter>,
    standing: StandingVerifier<Rd>,
    minter: PasetoV4SecretMinter,
    own_key: PasetoV4PublicVerifier,
    issuer: String,
    kid: String,
    config: KnockConfig,
}

impl<Rd> std::fmt::Debug for KnockAuthority<Rd> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KnockAuthority").field("issuer", &self.issuer).field("config", &self.config).finish_non_exhaustive()
    }
}

fn mint_id() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("OS CSPRNG must be available");
    URL_SAFE_NO_PAD.encode(bytes)
}

fn peer_key(key: &PrincipalId) -> Option<PeerKey> {
    let bytes: [u8; 32] = URL_SAFE_NO_PAD.decode(key.id.as_bytes()).ok()?.try_into().ok()?;
    Some(PeerKey::ed25519(bytes))
}

impl<Rd: RevocationReader + Send + Sync> KnockAuthority<Rd> {
    /// `standing` verifies the standing bindings approvers and requesters
    /// present; it must trust this issuer. `minter`/`kid` sign online offers.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        schema: Arc<SchemaRegistry>,
        ownership: Arc<dyn OwnershipStore>,
        knocks: Arc<dyn KnockStore>,
        revocations: Arc<dyn RevocationWriter>,
        standing: StandingVerifier<Rd>,
        minter: PasetoV4SecretMinter,
        issuer: impl Into<String>,
        kid: impl Into<String>,
    ) -> Result<Self, CodecError> {
        let public: [u8; 32] = minter.secret_key_bytes()[32..].try_into().map_err(|_| CodecError::Malformed)?;
        Ok(Self {
            schema,
            ownership,
            knocks,
            revocations,
            standing,
            own_key: PasetoV4PublicVerifier::from_public_key(&public)?,
            minter,
            issuer: issuer.into(),
            kid: kid.into(),
            config: KnockConfig::default(),
        })
    }

    pub fn with_config(mut self, config: KnockConfig) -> Self {
        self.config = config;
        self
    }

    pub fn config(&self) -> &KnockConfig {
        &self.config
    }

    /// The admitter relation `principal` holds on `(kind, id)` under the live
    /// policy row and live tuples, if any. `None` also when the resource has
    /// no policy or the policy names no admitters.
    pub async fn admit_relation(&self, principal: &PrincipalId, kind: &str, id: &str, now: i64) -> Result<Option<String>, StoreError> {
        let Some(policy) = self.ownership.admission_policy(kind, id).await? else {
            return Ok(None);
        };
        let tuples = OwnershipTuples::at(&*self.ownership, now);
        for relation in &policy.admitters {
            if self.schema.holds(&tuples, principal, kind, id, relation).await? {
                return Ok(Some(relation.clone()));
            }
        }
        Ok(None)
    }

    async fn require_admitter(&self, principal: &PrincipalId, kind: &str, id: &str, now: i64) -> Result<(), KnockFlowError> {
        match self.admit_relation(principal, kind, id, now).await? {
            Some(_) => Ok(()),
            None => Err(KnockFlowError::NotAnApprover(principal.clone())),
        }
    }

    /// The user a standing binding proves `key` belongs to.
    async fn bound_user(&self, key: &PrincipalId, binding: &str, now: i64) -> Result<UserId, KnockFlowError> {
        let peer = peer_key(key).ok_or_else(|| KnockError::NotAKey(key.clone()))?;
        Ok(self.standing.verify_standing_at(binding, &peer, now).await?.binding.sub)
    }

    /// Who approves for an approver key: the key itself when it holds an
    /// admitter relation, else the user its binding names when that user
    /// does. The answer is the tuple's `granted_by`.
    async fn approver_of(
        &self,
        key: &PrincipalId,
        binding: Option<&str>,
        kind: &str,
        id: &str,
        now: i64,
    ) -> Result<PrincipalId, KnockFlowError> {
        if key.kind == PrincipalKind::Key && self.admit_relation(key, kind, id, now).await?.is_some() {
            return Ok(key.clone());
        }
        let Some(binding) = binding else {
            return Err(KnockFlowError::NotAnApprover(key.clone()));
        };
        let user = PrincipalId::from(&self.bound_user(key, binding, now).await?);
        self.require_admitter(&user, kind, id, now).await?;
        Ok(user)
    }

    async fn policy(&self, kind: &str, id: &str) -> Result<Option<AdmissionPolicy>, StoreError> {
        self.ownership.admission_policy(kind, id).await
    }

    /// `POST /knock`: verify the signed `Knock` and queue it.
    pub async fn knock(&self, token: &str, now: i64) -> Result<(PendingKnock, Queued), KnockFlowError> {
        let knock: Knock = verify_device_artifact(token)?;
        knock.validate()?;
        let requester_user = match &knock.standing {
            Some(binding) => Some(self.bound_user(&knock.requester, binding, now).await?),
            None => None,
        };
        let pending = PendingKnock {
            id: mint_id(),
            resource_kind: knock.kind,
            resource_id: knock.id,
            requester: knock.requester,
            relation: knock.relation,
            label: knock.label,
            requester_user,
            renews: knock.renews,
            token: token.to_owned(),
            created_at: now,
            expires_at: now.saturating_add(self.config.pending_ttl),
        };
        match self.knocks.queue_knock(&pending, self.config.pending_cap, now).await? {
            Queued::Full => Err(KnockFlowError::PendingFull),
            q => Ok((pending, q)),
        }
    }

    /// `GET` pending knocks: only for a caller holding the admit ability.
    pub async fn pending(&self, caller: &PrincipalId, kind: &str, id: &str, now: i64) -> Result<Vec<PendingKnock>, KnockFlowError> {
        self.require_admitter(caller, kind, id, now).await?;
        Ok(self.knocks.pending_knocks(kind, id, now).await?)
    }

    /// `POST /knock/{id}/admit`: `caller` (an authenticated user) admits a
    /// pending knock at `confirmation`, with `lease` seconds or the path
    /// default.
    pub async fn admit_knock(
        &self,
        caller: &PrincipalId,
        knock_id: &str,
        confirmation: Confirmation,
        lease: Option<i64>,
        now: i64,
    ) -> Result<Admitted, KnockFlowError> {
        let pending = self.knocks.pending_knock(knock_id, now).await?.ok_or(KnockFlowError::UnknownKnock)?;
        let (kind, id) = (pending.resource_kind.as_str(), pending.resource_id.as_str());
        self.require_admitter(caller, kind, id, now).await?;
        let facts = AdmitFacts {
            relation: &pending.relation,
            path: if confirmation == Confirmation::Scan { AdmissionPath::Scan } else { AdmissionPath::Knock },
            confirmation: Some(confirmation),
            requester_is_user: pending.requester_user.is_some(),
        };
        let policy = self.policy(kind, id).await?;
        let resolved = evaluate_admit(policy.as_ref(), &facts, now, lease.map(LeaseRequest::Length))?;
        let jti = format!("knock:{}", pending.id);
        let admitted = self
            .write(&jti, &pending.requester, kind, id, &pending.relation, caller, TupleLease { iat: now, lease: resolved }, now)
            .await?;
        self.knocks.drop_knock(&pending.id).await?;
        Ok(admitted)
    }

    /// `POST /offer`: `caller` mints an issuer-signed `Offer` of `relation`
    /// on `(kind, id)` for up to `max_uses` keys.
    pub async fn offer(
        &self,
        caller: &PrincipalId,
        kind: &str,
        id: &str,
        relation: &str,
        max_uses: u32,
        now: i64,
    ) -> Result<(Offer, String), KnockFlowError> {
        self.require_admitter(caller, kind, id, now).await?;
        let offer = Offer {
            issuer: self.issuer.clone(),
            signer: None,
            kind: kind.to_owned(),
            id: id.to_owned(),
            relation: relation.to_owned(),
            max_uses: max_uses.max(1),
            jti: mint_id(),
            iat: now,
            exp: now.saturating_add(self.config.offer_ttl),
        };
        self.knocks
            .put_offer(&StoredOffer {
                jti: offer.jti.clone(),
                resource_kind: offer.kind.clone(),
                resource_id: offer.id.clone(),
                relation: offer.relation.clone(),
                created_by: caller.clone(),
                max_uses: offer.max_uses,
                created_at: now,
                exp: offer.exp,
            })
            .await?;
        let token = self.minter.mint_artifact(&offer, &self.kid)?;
        Ok((offer, token))
    }

    /// `POST /offer/redeem`: a key proves itself with a signed `Knock` for
    /// the offer's grant and redeems the offer. The offer's creator must
    /// still hold the admit ability, and the live policy is applied on the
    /// `offer` path.
    pub async fn redeem_offer(&self, offer_token: &str, knock_token: &str, now: i64) -> Result<Admitted, KnockFlowError> {
        let offer: Offer = self.own_key.verify_artifact(offer_token)?;
        let knock: Knock = verify_device_artifact(knock_token)?;
        knock.validate()?;
        if (knock.kind.as_str(), knock.id.as_str()) != (offer.kind.as_str(), offer.id.as_str()) {
            return Err(KnockFlowError::OfferMismatch("resource"));
        }
        if knock.relation != offer.relation {
            return Err(KnockFlowError::OfferMismatch("relation"));
        }
        let jti = format!("offer:{}:{}", offer.jti, knock.requester.id);
        let stored = match self.knocks.redeem_offer(&offer.jti, &knock.requester, now).await? {
            Redeemed::Fresh(s) => s,
            Redeemed::Again(_) => {
                if let Some(Admission::Accepted { ownership_id }) = self.knocks.admission(&jti).await? {
                    if let Some(row) = self.ownership.get(&ownership_id).await? {
                        return Ok(Admitted { jti, row });
                    }
                }
                return Err(KnockFlowError::OfferExhausted);
            }
            Redeemed::Exhausted => return Err(KnockFlowError::OfferExhausted),
            Redeemed::Expired => return Err(KnockFlowError::OfferExpired),
            Redeemed::Unknown => return Err(KnockFlowError::UnknownOffer),
        };
        let (kind, id) = (stored.resource_kind.as_str(), stored.resource_id.as_str());
        self.require_admitter(&stored.created_by, kind, id, now).await?;
        let requester_user = match &knock.standing {
            Some(binding) => Some(self.bound_user(&knock.requester, binding, now).await?),
            None => None,
        };
        let facts = AdmitFacts {
            relation: &stored.relation,
            path: AdmissionPath::Offer,
            confirmation: Some(Confirmation::Accept),
            requester_is_user: requester_user.is_some(),
        };
        let policy = self.policy(kind, id).await?;
        let resolved = evaluate_admit(policy.as_ref(), &facts, now, None)?;
        self.write(&jti, &knock.requester, kind, id, &stored.relation, &stored.created_by, TupleLease { iat: now, lease: resolved }, now)
            .await
    }

    /// `POST /admit`: reconcile an uploaded offline `Admit`. Accepted iff its
    /// approver holds the admit ability NOW (live tuples, live policy) and the
    /// live policy admits it; then the tuple is written with the `Admit`'s
    /// own lease. Otherwise its jti is revoked so edges drop it. Idempotent
    /// per jti: a repeat upload returns the recorded outcome. An artifact
    /// that does not verify, or has expired, is an error and records nothing.
    pub async fn reconcile(&self, token: &str, now: i64) -> Result<Reconciled, KnockFlowError> {
        let admit: Admit = verify_device_artifact(token)?;
        admit.validate()?;
        if admit.authority != self.issuer {
            return Err(KnockFlowError::WrongAuthority { expected: self.issuer.clone(), got: admit.authority });
        }
        if let Some(prior) = self.knocks.admission(&admit.jti).await? {
            return self.recorded(admit.jti, prior).await;
        }
        let exp = admit.lease.exp().unwrap_or(now);
        if exp <= now {
            return Err(KnockFlowError::Expired { exp });
        }
        match self.judge(&admit, now).await {
            Ok(granted_by) => {
                let lease = TupleLease { iat: admit.iat, lease: admit.lease };
                let admitted = self
                    .write(&admit.jti, &admit.requester, &admit.kind, &admit.id, &admit.relation, &granted_by, lease, now)
                    .await?;
                Ok(Reconciled::Accepted(admitted))
            }
            Err(e @ (KnockFlowError::NotAnApprover(_) | KnockFlowError::Refused(_) | KnockFlowError::Standing(_))) => {
                let refusal = e.to_string();
                let stood = self.knocks.record_admission(&admit.jti, &Admission::Refused { refusal }, now).await?;
                if matches!(stood, Admission::Refused { .. }) {
                    self.revocations.revoke(&Revoked::jti(admit.jti.clone(), admit.lease.exp())).await?;
                }
                self.recorded(admit.jti, stood).await
            }
            Err(e) => Err(e),
        }
    }

    /// The approver (`granted_by`) if `admit` is admissible now.
    async fn judge(&self, admit: &Admit, now: i64) -> Result<PrincipalId, KnockFlowError> {
        let granted_by = self.approver_of(&admit.approver, admit.approver_binding.as_deref(), &admit.kind, &admit.id, now).await?;
        let requester_user = match &admit.requester_binding {
            Some(binding) => Some(self.bound_user(&admit.requester, binding, now).await?),
            None => None,
        };
        let facts = AdmitFacts {
            relation: &admit.relation,
            path: admit.path(),
            confirmation: Some(admit.confirmation),
            requester_is_user: requester_user.is_some(),
        };
        let policy = self.policy(&admit.kind, &admit.id).await?;
        evaluate_admit(policy.as_ref(), &facts, admit.iat, Some(LeaseRequest::Exact(admit.lease)))?;
        Ok(granted_by)
    }

    async fn recorded(&self, jti: String, outcome: Admission) -> Result<Reconciled, KnockFlowError> {
        match outcome {
            Admission::Accepted { ownership_id } => {
                let row = self
                    .ownership
                    .get(&ownership_id)
                    .await?
                    .ok_or_else(|| StoreError::Backend(format!("admission {jti} names missing tuple {ownership_id}")))?;
                Ok(Reconciled::Accepted(Admitted { jti, row }))
            }
            Admission::Refused { refusal } => Ok(Reconciled::Refused { jti, refusal }),
        }
    }

    /// Write the admitted tuple (module docs, "Renewal") and record it
    /// against `jti`.
    #[allow(clippy::too_many_arguments)]
    async fn write(
        &self,
        jti: &str,
        requester: &PrincipalId,
        kind: &str,
        id: &str,
        relation: &str,
        granted_by: &PrincipalId,
        lease: TupleLease,
        now: i64,
    ) -> Result<Admitted, KnockFlowError> {
        if let Some(prior) = self.knocks.admission(jti).await? {
            return match self.recorded(jti.to_owned(), prior).await? {
                Reconciled::Accepted(a) => Ok(a),
                Reconciled::Refused { refusal, .. } => Err(StoreError::Backend(format!("admission {jti} was refused: {refusal}")).into()),
            };
        }
        let held: Vec<OwnershipRow> = self
            .ownership
            .list_for_principal(requester)
            .await?
            .into_iter()
            .filter(|r| r.resource_kind == kind && r.resource_id == id && r.relationship == relation && r.is_live_at(now))
            .collect();
        let row = match held.iter().find(|r| r.lease.is_none()) {
            Some(standing) => standing.clone(),
            None => {
                for old in &held {
                    self.ownership.revoke_by_id(&old.id, now).await?;
                }
                let new = NewOwnership::new(requester.clone(), kind, id, relation, granted_by.clone(), None)
                    .map_err(|e| StoreError::Backend(e.to_string()))?
                    .with_lease(Some(lease));
                self.ownership.insert(&new, now).await?.row
            }
        };
        let ours = Admission::Accepted { ownership_id: row.id.clone() };
        let stood = self.knocks.record_admission(jti, &ours, now).await?;
        if stood != ours && row.lease.is_some() {
            // Lost a race to a concurrent upload of the same jti: its tuple stands.
            self.ownership.revoke_by_id(&row.id, now).await?;
        }
        match self.recorded(jti.to_owned(), stood).await? {
            Reconciled::Accepted(a) => Ok(a),
            Reconciled::Refused { refusal, .. } => Err(StoreError::Backend(format!("admission {jti} was refused: {refusal}")).into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ownership::MemoryOwnershipStore;
    use crate::revocation::MemoryRevocationStore;
    use crate::snapshot::SnapshotIssuer;
    use crate::standing::{MemoryBindingSequenceStore, StandingBinder};
    use cheers_core::{
        AdmissionMode, AdmitSource, DeviceId, LeaseState, RelationDef, ResourceSchema, ScopeRegistry, SignedArtifact,
    };
    use cheers_verify::{
        artifact_hash, AdmitAuthority, IssuerAdmitAuthority, IssuerTrust, ReplicatedRevocations, SnapshotVerifier,
    };
    use pasetors::keys::{AsymmetricKeyPair, Generate};
    use pasetors::version4::{PublicToken, V4};

    const ISS: &str = "https://c.test";
    const IAT: i64 = 1_000_000;
    const DAY: i64 = 24 * 60 * 60;

    const NAMESPACE: ResourceSchema = ResourceSchema {
        kind: "namespace",
        relations: &[
            RelationDef { name: "owner", membership: true, implies: &["admin"], scopes: &[], grants: &["owner", "admin", "member", "guest"] },
            RelationDef { name: "admin", membership: true, implies: &["member"], scopes: &[], grants: &["admin", "member", "guest"] },
            RelationDef { name: "member", membership: true, implies: &["guest"], scopes: &[], grants: &[] },
            RelationDef { name: "guest", membership: true, implies: &[], scopes: &[], grants: &[] },
        ],
        kind_relations: &[],
    };

    fn schema() -> Arc<SchemaRegistry> {
        Arc::new(SchemaRegistry::build(&[NAMESPACE], &ScopeRegistry::builder().build().unwrap()).unwrap())
    }

    fn key_of(k: &AsymmetricKeyPair<V4>) -> PrincipalId {
        PrincipalId::from_public_key(k.public.as_bytes().try_into().unwrap())
    }

    fn device_sign<T: SignedArtifact + Serialize>(k: &AsymmetricKeyPair<V4>, payload: &T) -> String {
        let body = serde_json::to_vec(payload).unwrap();
        PublicToken::sign(&k.secret, &body, Some(br#"{"kid":"device"}"#), Some(T::IMPLICIT_ASSERTION)).unwrap()
    }

    struct Rig {
        store: MemoryOwnershipStore,
        revocations: MemoryRevocationStore,
        auth: KnockAuthority<Arc<ReplicatedRevocations>>,
        snapshots: SnapshotIssuer,
        edge: IssuerAdmitAuthority<Arc<ReplicatedRevocations>>,
        /// alice's device key and its standing binding; alice owns ed.
        device: AsymmetricKeyPair<V4>,
        binding: String,
        guest: AsymmetricKeyPair<V4>,
    }

    fn rig_with(config: KnockConfig) -> Rig {
        let (minter, verifier) = PasetoV4SecretMinter::generate().unwrap();
        let bytes: [u8; 64] = minter.secret_key_bytes().try_into().unwrap();
        let again = || PasetoV4SecretMinter::from_secret_key(&bytes).unwrap();
        let trust = IssuerTrust::pinned(ISS, verifier);
        let replica = Arc::new(ReplicatedRevocations::new(trust.clone()));
        let store = MemoryOwnershipStore::new();
        let revocations = MemoryRevocationStore::new();
        let auth = KnockAuthority::new(
            schema(),
            Arc::new(store.clone()),
            Arc::new(MemoryKnockStore::new()),
            Arc::new(revocations.clone()),
            StandingVerifier::new(trust.clone(), replica.clone()),
            minter,
            ISS,
            "k1",
        )
        .unwrap()
        .with_config(config);
        let device = AsymmetricKeyPair::<V4>::generate().unwrap();
        let binder = StandingBinder::new(MemoryBindingSequenceStore::new(), again(), ISS, "k1");
        let peer = PeerKey::ed25519(device.public.as_bytes().try_into().unwrap());
        let binding = pollster::block_on(binder.mint(UserId::new("alice"), DeviceId::new("d-alice"), peer, IAT)).unwrap().token;
        let r = Rig {
            snapshots: SnapshotIssuer::new(store.clone(), schema(), again(), ISS, "k1"),
            edge: IssuerAdmitAuthority::new(
                StandingVerifier::new(trust.clone(), replica.clone()),
                SnapshotVerifier::new(trust, replica),
            ),
            store,
            revocations,
            auth,
            device,
            binding,
            guest: AsymmetricKeyPair::<V4>::generate().unwrap(),
        };
        pollster::block_on(async {
            let own = NewOwnership::new(PrincipalId::user("alice"), "namespace", "ed", "owner", PrincipalId::service("seed"), None).unwrap();
            r.store.insert(&own, 10).await.unwrap();
            let policy = AdmissionPolicy::new(AdmissionMode::Knock, "guest").with_admitters(["admin"]);
            r.store.set_admission_policy("namespace", "ed", Some(&policy), 10).await.unwrap();
        });
        r
    }

    fn rig() -> Rig {
        rig_with(KnockConfig::default())
    }

    impl Rig {
        fn knock(&self, who: &AsymmetricKeyPair<V4>, label: &str) -> String {
            device_sign(
                who,
                &Knock {
                    requester: key_of(who),
                    kind: "namespace".into(),
                    id: "ed".into(),
                    relation: "guest".into(),
                    nonce: "n".into(),
                    label: label.into(),
                    standing: None,
                    renews: None,
                    iat: IAT,
                },
            )
        }

        fn admit(&self, jti: &str, lease: cheers_core::Lease) -> String {
            device_sign(
                &self.device,
                &Admit {
                    approver: key_of(&self.device),
                    approver_binding: Some(self.binding.clone()),
                    authority: ISS.into(),
                    requester: key_of(&self.guest),
                    requester_binding: None,
                    kind: "namespace".into(),
                    id: "ed".into(),
                    relation: "guest".into(),
                    source: AdmitSource::Knock(artifact_hash("knock")),
                    confirmation: Confirmation::Accept,
                    epoch: 1,
                    jti: jti.into(),
                    iat: IAT,
                    lease,
                },
            )
        }

        fn alice(&self) -> PrincipalId {
            PrincipalId::user("alice")
        }
    }

    fn week() -> cheers_core::Lease {
        cheers_core::Lease::new(IAT, IAT + DAY, Some(IAT + 7 * DAY)).unwrap()
    }

    fn same_grant(a: &OwnershipRow, b: &OwnershipRow) {
        assert_eq!(
            (&a.subject, &a.resource_kind, &a.resource_id, &a.relationship, &a.granted_by, &a.on_behalf_of, a.lease),
            (&b.subject, &b.resource_kind, &b.resource_id, &b.relationship, &b.granted_by, &b.on_behalf_of, b.lease)
        );
    }

    #[test]
    fn an_online_knock_and_an_offline_admit_write_the_same_tuple() {
        let r = rig();
        pollster::block_on(async {
            let (pending, q) = r.auth.knock(&r.knock(&r.guest, "phone"), IAT).await.unwrap();
            assert_eq!(q, Queued::Queued);
            let online = r.auth.admit_knock(&r.alice(), &pending.id, Confirmation::Accept, Some(7 * DAY), IAT).await.unwrap();
            assert_eq!(online.jti, format!("knock:{}", pending.id));
            assert_eq!(online.row.granted_by, r.alice());
            assert_eq!(online.row.lease, Some(TupleLease { iat: IAT, lease: week() }));
            // The knock was answered.
            assert!(r.auth.pending(&r.alice(), "namespace", "ed", IAT).await.unwrap().is_empty());
            // Undo it, then reconcile an offline Admit for the same grant.
            r.store.revoke_by_id(&online.row.id, IAT).await.unwrap();
            let Reconciled::Accepted(offline) = r.auth.reconcile(&r.admit("admit-1", week()), IAT).await.unwrap() else {
                panic!("refused")
            };
            same_grant(&online.row, &offline.row);
            // Idempotent per jti.
            let again = r.auth.reconcile(&r.admit("admit-1", week()), IAT + 5).await.unwrap();
            assert_eq!(again, Reconciled::Accepted(offline.clone()));
            assert_eq!(r.store.list_for_resource("namespace", "ed").await.unwrap().iter().filter(|x| x.lease.is_some()).count(), 1);
        });
    }

    #[test]
    fn an_admit_from_a_since_demoted_approver_is_refused_and_revoked() {
        let r = rig();
        pollster::block_on(async {
            let owner = r.store.list_for_principal(&r.alice()).await.unwrap();
            r.store.revoke_by_id(&owner[0].id, IAT).await.unwrap();
            let out = r.auth.reconcile(&r.admit("admit-2", week()), IAT).await.unwrap();
            assert!(matches!(&out, Reconciled::Refused { jti, .. } if jti == "admit-2"), "{out:?}");
            let set = r.revocations.snapshot().await.unwrap();
            assert!(set.revoked.contains(&Revoked::jti("admit-2", Some(IAT + 7 * DAY))));
            assert_eq!(r.auth.reconcile(&r.admit("admit-2", week()), IAT).await.unwrap(), out);
            assert!(r.store.list_for_resource("namespace", "ed").await.unwrap().is_empty());
        });
    }

    #[test]
    fn a_second_pending_knock_replaces_the_first_and_the_cap_holds() {
        let r = rig_with(KnockConfig { pending_cap: 1, ..KnockConfig::default() });
        pollster::block_on(async {
            let (first, _) = r.auth.knock(&r.knock(&r.guest, "one"), IAT).await.unwrap();
            let (second, q) = r.auth.knock(&r.knock(&r.guest, "two"), IAT + 1).await.unwrap();
            assert_eq!(q, Queued::Replaced);
            let pending = r.auth.pending(&r.alice(), "namespace", "ed", IAT + 1).await.unwrap();
            assert_eq!(pending.iter().map(|p| (&p.id, p.label.as_str())).collect::<Vec<_>>(), [(&second.id, "two")]);
            assert!(matches!(
                r.auth.admit_knock(&r.alice(), &first.id, Confirmation::Accept, None, IAT + 1).await,
                Err(KnockFlowError::UnknownKnock)
            ));
            let other = AsymmetricKeyPair::<V4>::generate().unwrap();
            assert!(matches!(r.auth.knock(&r.knock(&other, "three"), IAT + 2).await, Err(KnockFlowError::PendingFull)));
            // Only an admitter sees the queue.
            assert!(matches!(
                r.auth.pending(&PrincipalId::user("mallory"), "namespace", "ed", IAT).await,
                Err(KnockFlowError::NotAnApprover(_))
            ));
            // A pending knock lapses.
            let ttl = KnockConfig::default().pending_ttl;
            assert!(r.auth.pending(&r.alice(), "namespace", "ed", IAT + 1 + ttl).await.unwrap().is_empty());
        });
    }

    #[test]
    fn a_week_long_admit_reconciles_to_a_tuple_that_warns_and_lapses_with_it() {
        let r = rig();
        let guest = key_of(&r.guest);
        pollster::block_on(async {
            let Reconciled::Accepted(a) = r.auth.reconcile(&r.admit("admit-3", week()), IAT).await.unwrap() else {
                panic!("refused")
            };
            assert_eq!(a.row.lease.map(|l| l.lease), Some(week()));
            let holds = |now| {
                let tuples = OwnershipTuples::at(&r.store, now);
                let schema = schema();
                let guest = guest.clone();
                async move { schema.holds(&tuples, &guest, "namespace", "ed", "guest").await.unwrap() }
            };
            assert!(holds(IAT + 7 * DAY - 1).await);
            assert!(!holds(IAT + 7 * DAY).await);
            // The mint carries the lease; the edge reports Warning from the
            // same refresh_after and drops the guest at the same exp.
            let s = r.snapshots.mint("namespace", "ed", IAT + DAY).await.unwrap();
            let m = s.snapshot.members.iter().find(|m| m.principal == guest).unwrap();
            assert_eq!(m.lease, Some(week()));
            r.edge.hold_snapshot(&s.token).await.unwrap();
            let held = r.edge.snapshots().verify_snapshot_at(&s.token, IAT + DAY - 1).await.unwrap();
            assert_eq!(held.member_lease(&guest, "guest", IAT + DAY - 1), Some(LeaseState::Current));
            assert_eq!(held.member_lease(&guest, "guest", IAT + DAY), Some(LeaseState::Warning { exp: Some(IAT + 7 * DAY) }));
            assert!(!r.edge.snapshots().verify_snapshot_at(&s.token, IAT + 7 * DAY).await.unwrap().holds(&guest, "guest"));
            // Past exp the mint stops listing it.
            let late = r.snapshots.mint("namespace", "ed", IAT + 7 * DAY).await.unwrap();
            assert!(!late.snapshot.members.iter().any(|m| m.principal == guest));
            // The standing owner carries no lease.
            assert!(late.snapshot.members.iter().filter(|m| m.principal == r.alice()).all(|m| m.lease.is_none()));
        });
    }

    #[test]
    fn edge_and_server_agree_on_an_admitter_by_implication() {
        let r = rig();
        pollster::block_on(async {
            // alice holds owner only; admin (the admitter relation) by implication.
            assert_eq!(r.auth.admit_relation(&r.alice(), "namespace", "ed", IAT).await.unwrap().as_deref(), Some("admin"));
            let s = r.snapshots.mint("namespace", "ed", IAT).await.unwrap();
            r.edge.hold_snapshot(&s.token).await.unwrap();
            let approval = r.edge.approval_at(&key_of(&r.device), Some(&r.binding), "namespace", "ed", IAT).await.unwrap();
            assert_eq!(approval.relation, "admin");
            assert_eq!(approval.user, Some(UserId::new("alice")));
            // And both refuse a non-holder.
            assert_eq!(r.auth.admit_relation(&PrincipalId::user("bob"), "namespace", "ed", IAT).await.unwrap(), None);
            let stranger = AsymmetricKeyPair::<V4>::generate().unwrap();
            assert!(r.edge.approval_at(&key_of(&stranger), None, "namespace", "ed", IAT).await.is_err());
        });
    }

    #[test]
    fn a_renewing_knock_replaces_the_lease() {
        let r = rig();
        pollster::block_on(async {
            let Reconciled::Accepted(first) = r.auth.reconcile(&r.admit("admit-4", week()), IAT).await.unwrap() else {
                panic!("refused")
            };
            let renew = device_sign(
                &r.guest,
                &Knock {
                    requester: key_of(&r.guest),
                    kind: "namespace".into(),
                    id: "ed".into(),
                    relation: "guest".into(),
                    nonce: "n2".into(),
                    label: "phone".into(),
                    standing: None,
                    renews: Some("admit-4".into()),
                    iat: IAT + 6 * DAY,
                },
            );
            let (pending, _) = r.auth.knock(&renew, IAT + 6 * DAY).await.unwrap();
            assert_eq!(pending.renews.as_deref(), Some("admit-4"));
            let renewed = r.auth.admit_knock(&r.alice(), &pending.id, Confirmation::Accept, None, IAT + 6 * DAY).await.unwrap();
            assert_eq!(renewed.row.lease.and_then(|l| l.lease.exp()), Some(IAT + 13 * DAY));
            let live: Vec<_> = r.store.list_for_resource("namespace", "ed").await.unwrap().into_iter().filter(|x| x.lease.is_some()).collect();
            assert_eq!(live.len(), 1);
            assert_ne!(live[0].id, first.row.id);
        });
    }

    #[test]
    fn an_offer_is_redeemed_once_per_key_up_to_max_uses() {
        let r = rig();
        pollster::block_on(async {
            assert!(matches!(
                r.auth.offer(&PrincipalId::user("bob"), "namespace", "ed", "guest", 1, IAT).await,
                Err(KnockFlowError::NotAnApprover(_))
            ));
            let (offer, token) = r.auth.offer(&r.alice(), "namespace", "ed", "guest", 1, IAT).await.unwrap();
            assert_eq!(offer.max_uses, 1);
            let a = r.auth.redeem_offer(&token, &r.knock(&r.guest, "phone"), IAT).await.unwrap();
            assert_eq!(a.row.granted_by, r.alice());
            assert_eq!(a.row.lease.and_then(|l| l.lease.exp()), Some(IAT + 30 * DAY));
            assert_eq!(r.auth.redeem_offer(&token, &r.knock(&r.guest, "phone"), IAT + 1).await.unwrap(), a);
            let other = AsymmetricKeyPair::<V4>::generate().unwrap();
            assert!(matches!(
                r.auth.redeem_offer(&token, &r.knock(&other, "x"), IAT + 2).await,
                Err(KnockFlowError::OfferExhausted)
            ));
            // A forged offer does not verify.
            let forged = device_sign(&other, &offer);
            assert!(matches!(r.auth.redeem_offer(&forged, &r.knock(&other, "x"), IAT).await, Err(KnockFlowError::Artifact(_))));
        });
    }

    #[test]
    fn closed_stops_online_knocks_too() {
        let r = rig();
        pollster::block_on(async {
            let closed = AdmissionPolicy::new(AdmissionMode::Closed, "guest").with_admitters(["admin"]);
            r.store.set_admission_policy("namespace", "ed", Some(&closed), IAT).await.unwrap();
            let (pending, _) = r.auth.knock(&r.knock(&r.guest, "phone"), IAT).await.unwrap();
            assert!(matches!(
                r.auth.admit_knock(&r.alice(), &pending.id, Confirmation::Accept, None, IAT).await,
                Err(KnockFlowError::Refused(AdmissionRefusal::Mode(AdmissionMode::Closed)))
            ));
        });
    }
}
