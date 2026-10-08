//! Admission policy: who may come in offline, how sure the approver must be,
//! and how long a guest may stay (`knock.md`, "The dial", "Confirmation
//! levels", "Posted lease"; R734-F3).
//!
//! An [`AdmissionPolicy`] is signed resource data. The issuer stores it as a
//! row on the resource (so a change advances the ownership version) and ships
//! it inside the [`SetSnapshot`](crate::SetSnapshot) it mints. An edge
//! evaluates every `Admit` it holds against the policy it holds **now**, so
//! moving the dial is a class revocation that names nobody, and moving it back
//! restores every admit whose lease still runs.
//!
//! # The evaluation API
//!
//! [`evaluate_admit`] is the single entry point. `AdmitAuthority` (R734-F2)
//! calls it at verify time with the policy from the currently held snapshot
//! (`None` when the snapshot carries none, which reads as
//! [`AdmissionMode::Closed`]):
//!
//! ```text
//! evaluate_admit(policy: Option<&AdmissionPolicy>, admit: &AdmitFacts<'_>,
//!                iat: i64, lease: Option<LeaseRequest>)
//!     -> Result<Lease, AdmissionRefusal>
//! ```
//!
//! It answers both questions at once: is this admission permitted under the
//! held policy, and what lease does it carry. On the minting side the
//! approver passes `None` (the path default), or a [`LeaseRequest::Length`];
//! on the verifying side the edge passes the Admit's own lease as
//! [`LeaseRequest::Exact`], which is checked against the path maximum.
//! [`AdmitFacts::confirmation`] `None` is a bare key with no `Admit` at all,
//! the `open`-mode entry at the floor relation.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::lease::{Lease, LeaseError};

const DAY: i64 = 24 * 60 * 60;

/// The dial: how a new principal gets in offline (`knock.md`, "The dial").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdmissionMode {
    /// Any key at the floor relation with no approval; `Admit`s are valid.
    Open,
    /// An `Admit`.
    Knock,
    /// An `Admit` whose requester presented a standing binding. Key-only
    /// admits are inert.
    Users,
    /// Issuer tuples only. Every offline admit is inert.
    Closed,
}

/// How sure the approver was that the requester is who it claims
/// (`knock.md`, "Confirmation levels"). Ordered weakest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confirmation {
    Accept,
    Compare,
    Scan,
}

/// The route an admission took, each with its own posted lease terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdmissionPath {
    /// A `Knock` an approver admitted.
    Knock,
    /// A redeemed `Offer`.
    Offer,
    /// A QR scan in either direction.
    Scan,
}

/// Why a policy cannot be built (or read back).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("posted lease needs 0 < default <= max, got default {default}, max {max}")]
    LeaseBounds { default: i64, max: i64 },
    /// Every notice point must yield a valid [`Lease`] for the default
    /// length, so it may not pass the default's midpoint.
    #[error("notice {notice} must be in (0, {default} / 2]")]
    NoticePastMidpoint { notice: i64, default: i64 },
    /// `floor` or an `admitters` entry names a relation the snapshot does not
    /// list, so the edge could never see its holders (R734-B6).
    #[error("admission policy on '{kind}' names '{relation}', which is not a membership relation")]
    NotMembership { kind: String, relation: String },
}

/// Posted-lease terms for one admission path, in seconds from `iat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawPostedLease")]
pub struct PostedLease {
    default: i64,
    max: i64,
    notice: i64,
}

#[derive(Deserialize)]
struct RawPostedLease {
    default: i64,
    max: i64,
    notice: i64,
}

impl TryFrom<RawPostedLease> for PostedLease {
    type Error = PolicyError;
    fn try_from(r: RawPostedLease) -> Result<Self, PolicyError> {
        Self::new(r.default, r.max, r.notice)
    }
}

impl PostedLease {
    /// Refuses `default > max`, a non-positive length, and a `notice` past
    /// the default lease's midpoint.
    pub fn new(default: i64, max: i64, notice: i64) -> Result<Self, PolicyError> {
        if default <= 0 || default > max {
            return Err(PolicyError::LeaseBounds { default, max });
        }
        if notice <= 0 || notice > default / 2 {
            return Err(PolicyError::NoticePastMidpoint { notice, default });
        }
        Ok(Self { default, max, notice })
    }

    pub fn default_secs(&self) -> i64 {
        self.default
    }
    pub fn max_secs(&self) -> i64 {
        self.max
    }
    pub fn notice_secs(&self) -> i64 {
        self.notice
    }

    /// A lease `length` seconds long from `iat`, warning at the notice point
    /// or at the midpoint, whichever comes first.
    fn lease_of(&self, iat: i64, length: i64) -> Result<Lease, LeaseError> {
        let exp = iat.saturating_add(length);
        Lease::new(iat, iat.saturating_add(self.notice.min(length / 2)), Some(exp))
    }
}

/// Posted-lease terms for every admission path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathLeases {
    pub knock: PostedLease,
    pub offer: PostedLease,
    pub scan: PostedLease,
}

impl PathLeases {
    /// The seed (C1): a knock defaults to and tops out at a week, warning
    /// after day 1; everything else is 30 days, warning after week 1. No purge
    /// floor.
    pub fn seed() -> Self {
        let month = PostedLease { default: 30 * DAY, max: 30 * DAY, notice: 7 * DAY };
        Self { knock: PostedLease { default: 7 * DAY, max: 7 * DAY, notice: DAY }, offer: month, scan: month }
    }

    pub fn get(&self, path: AdmissionPath) -> &PostedLease {
        match path {
            AdmissionPath::Knock => &self.knock,
            AdmissionPath::Offer => &self.offer,
            AdmissionPath::Scan => &self.scan,
        }
    }
}

/// A resource's admission policy. Wire shape:
/// `{"mode":"knock","floor":"guest","min_confirmation":{"member":"scan"},"leases":{...}}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionPolicy {
    pub mode: AdmissionMode,
    /// The relation `open` mode hands any key with no approval.
    pub floor: String,
    /// Minimum [`Confirmation`] an `Admit` needs per relation. A relation not
    /// listed accepts any level.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub min_confirmation: BTreeMap<String, Confirmation>,
    /// The relations that carry the admit ability (R734-F4): a principal
    /// holding any of them on the resource, directly or by implication, may
    /// approve an admission. The one source of truth for both the edge
    /// (`IssuerAdmitAuthority`, over the snapshot's closure-expanded members)
    /// and the issuer (live tuples). Empty means nobody may admit, which fails
    /// closed.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub admitters: BTreeSet<String>,
    pub leases: PathLeases,
}

impl AdmissionPolicy {
    /// A policy at `mode` with floor relation `floor`, no confirmation
    /// minimums, and the seeded lease terms.
    pub fn new(mode: AdmissionMode, floor: impl Into<String>) -> Self {
        Self {
            mode,
            floor: floor.into(),
            min_confirmation: BTreeMap::new(),
            admitters: BTreeSet::new(),
            leases: PathLeases::seed(),
        }
    }

    /// Require at least `level` for an `Admit` at `relation`.
    pub fn with_min_confirmation(mut self, relation: impl Into<String>, level: Confirmation) -> Self {
        self.min_confirmation.insert(relation.into(), level);
        self
    }

    /// Relations that carry the admit ability (see [`Self::admitters`]).
    pub fn with_admitters(mut self, relations: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.admitters.extend(relations.into_iter().map(Into::into));
        self
    }

    pub fn with_leases(mut self, leases: PathLeases) -> Self {
        self.leases = leases;
        self
    }
}

/// What an edge (or an approver) knows about one offline admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmitFacts<'a> {
    /// The relation the admission grants.
    pub relation: &'a str,
    pub path: AdmissionPath,
    /// The level the `Admit` records; `None` is a bare key with no `Admit`.
    pub confirmation: Option<Confirmation>,
    /// The requester presented a standing binding naming a user.
    pub requester_is_user: bool,
}

/// The lease an approver asks for, or the one an `Admit` already carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseRequest {
    /// This many seconds from `iat`; the notice point is the path's, capped
    /// at the midpoint.
    Length(i64),
    /// A lease already signed into an `Admit`, checked as it stands.
    Exact(Lease),
}

/// Why [`evaluate_admit`] refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionRefusal {
    #[error("admission mode {0:?} permits no such offline admit")]
    Mode(AdmissionMode),
    #[error("a key with no Admit enters only at the floor relation {floor:?}")]
    NotFloor { floor: String },
    #[error("relation {relation:?} needs confirmation {needed:?}, got {got:?}")]
    BelowConfirmation { relation: String, needed: Confirmation, got: Confirmation },
    #[error("lease of {length}s exceeds the {path:?} maximum {max}s")]
    LeaseOverMax { path: AdmissionPath, length: i64, max: i64 },
    #[error("an Admit's lease must carry an exp after iat")]
    LeaseUnbounded,
    #[error(transparent)]
    Lease(#[from] LeaseError),
}

/// Whether `admit` is admissible under `policy` (`None` = closed), and the
/// lease it carries. The one evaluation API (module docs).
///
/// - `closed` (or no policy): refused.
/// - `users`: refused unless `requester_is_user`.
/// - `knock`: refused without an `Admit` (`confirmation: None`).
/// - `open`: a bare key is admitted at the floor relation only.
/// - An `Admit` below the relation's minimum confirmation is refused.
/// - `lease`: `None` resolves to the path default; a [`LeaseRequest::Length`]
///   or [`LeaseRequest::Exact`] longer than the path maximum is refused.
pub fn evaluate_admit(
    policy: Option<&AdmissionPolicy>,
    admit: &AdmitFacts<'_>,
    iat: i64,
    lease: Option<LeaseRequest>,
) -> Result<Lease, AdmissionRefusal> {
    let Some(policy) = policy else {
        return Err(AdmissionRefusal::Mode(AdmissionMode::Closed));
    };
    match (policy.mode, admit.confirmation) {
        (AdmissionMode::Closed, _) => return Err(AdmissionRefusal::Mode(AdmissionMode::Closed)),
        (AdmissionMode::Users, _) if !admit.requester_is_user => {
            return Err(AdmissionRefusal::Mode(AdmissionMode::Users));
        }
        (AdmissionMode::Open, None) if admit.relation != policy.floor => {
            return Err(AdmissionRefusal::NotFloor { floor: policy.floor.clone() });
        }
        (AdmissionMode::Open, None) => {}
        (mode, None) => return Err(AdmissionRefusal::Mode(mode)),
        (_, Some(got)) => {
            if let Some(&needed) = policy.min_confirmation.get(admit.relation) {
                if got < needed {
                    return Err(AdmissionRefusal::BelowConfirmation {
                        relation: admit.relation.to_owned(),
                        needed,
                        got,
                    });
                }
            }
        }
    }
    let terms = policy.leases.get(admit.path);
    let over = |length: i64| AdmissionRefusal::LeaseOverMax { path: admit.path, length, max: terms.max };
    match lease {
        None => Ok(terms.lease_of(iat, terms.default)?),
        Some(LeaseRequest::Length(length)) if length > terms.max => Err(over(length)),
        Some(LeaseRequest::Length(length)) => Ok(terms.lease_of(iat, length)?),
        Some(LeaseRequest::Exact(l)) => {
            l.validate(iat)?;
            let exp = l.exp().filter(|&e| e > iat).ok_or(AdmissionRefusal::LeaseUnbounded)?;
            if exp - iat > terms.max {
                return Err(over(exp - iat));
            }
            Ok(l)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IAT: i64 = 1_000;

    fn facts(relation: &str, confirmation: Option<Confirmation>, user: bool) -> AdmitFacts<'_> {
        AdmitFacts { relation, path: AdmissionPath::Knock, confirmation, requester_is_user: user }
    }

    fn eval(p: Option<&AdmissionPolicy>, f: &AdmitFacts<'_>) -> Result<Lease, AdmissionRefusal> {
        evaluate_admit(p, f, IAT, None)
    }

    #[test]
    fn open_admits_any_key_at_the_floor_relation() {
        let p = AdmissionPolicy::new(AdmissionMode::Open, "guest");
        assert!(eval(Some(&p), &facts("guest", None, false)).is_ok());
        assert_eq!(
            eval(Some(&p), &facts("member", None, false)),
            Err(AdmissionRefusal::NotFloor { floor: "guest".into() })
        );
        // An Admit above the floor is still valid under open.
        assert!(eval(Some(&p), &facts("member", Some(Confirmation::Accept), false)).is_ok());
    }

    #[test]
    fn knock_requires_an_admit() {
        let p = AdmissionPolicy::new(AdmissionMode::Knock, "guest");
        assert_eq!(eval(Some(&p), &facts("guest", None, false)), Err(AdmissionRefusal::Mode(AdmissionMode::Knock)));
        assert!(eval(Some(&p), &facts("guest", Some(Confirmation::Accept), false)).is_ok());
    }

    #[test]
    fn users_makes_key_only_admits_inert() {
        let p = AdmissionPolicy::new(AdmissionMode::Users, "guest");
        let key_only = facts("guest", Some(Confirmation::Scan), false);
        assert_eq!(eval(Some(&p), &key_only), Err(AdmissionRefusal::Mode(AdmissionMode::Users)));
        assert!(eval(Some(&p), &facts("guest", Some(Confirmation::Accept), true)).is_ok());
    }

    #[test]
    fn closed_and_no_policy_make_every_offline_admit_inert() {
        let p = AdmissionPolicy::new(AdmissionMode::Closed, "guest");
        for f in [facts("guest", None, false), facts("guest", Some(Confirmation::Scan), true)] {
            assert_eq!(eval(Some(&p), &f), Err(AdmissionRefusal::Mode(AdmissionMode::Closed)));
            assert_eq!(eval(None, &f), Err(AdmissionRefusal::Mode(AdmissionMode::Closed)));
        }
    }

    #[test]
    fn moving_the_dial_back_restores_admits() {
        let admit = facts("guest", Some(Confirmation::Accept), false);
        let mut p = AdmissionPolicy::new(AdmissionMode::Knock, "guest");
        let lease = eval(Some(&p), &admit).unwrap();
        let held = Some(LeaseRequest::Exact(lease));
        p.mode = AdmissionMode::Users;
        assert!(evaluate_admit(Some(&p), &admit, IAT, held).is_err());
        p.mode = AdmissionMode::Closed;
        assert!(evaluate_admit(Some(&p), &admit, IAT, held).is_err());
        p.mode = AdmissionMode::Knock;
        assert_eq!(evaluate_admit(Some(&p), &admit, IAT, held), Ok(lease));
    }

    #[test]
    fn an_admit_below_the_minimum_confirmation_is_refused() {
        let p = AdmissionPolicy::new(AdmissionMode::Knock, "guest").with_min_confirmation("member", Confirmation::Compare);
        assert!(matches!(
            eval(Some(&p), &facts("member", Some(Confirmation::Accept), false)),
            Err(AdmissionRefusal::BelowConfirmation { needed: Confirmation::Compare, got: Confirmation::Accept, .. })
        ));
        assert!(eval(Some(&p), &facts("member", Some(Confirmation::Scan), false)).is_ok());
        assert!(eval(Some(&p), &facts("guest", Some(Confirmation::Accept), false)).is_ok());
    }

    #[test]
    fn defaults_apply_when_no_lease_is_picked() {
        let p = AdmissionPolicy::new(AdmissionMode::Knock, "guest");
        let knock = eval(Some(&p), &facts("guest", Some(Confirmation::Accept), false)).unwrap();
        assert_eq!((knock.refresh_after(), knock.exp()), (IAT + DAY, Some(IAT + 7 * DAY)));
        let offer = AdmitFacts { path: AdmissionPath::Offer, ..facts("guest", Some(Confirmation::Accept), false) };
        let l = evaluate_admit(Some(&p), &offer, IAT, None).unwrap();
        assert_eq!((l.refresh_after(), l.exp()), (IAT + 7 * DAY, Some(IAT + 30 * DAY)));
        // A day-long knock warns at its midpoint, not after the default's day.
        let day = evaluate_admit(Some(&p), &facts("guest", Some(Confirmation::Accept), false), IAT, Some(LeaseRequest::Length(DAY)))
            .unwrap();
        assert_eq!((day.refresh_after(), day.exp()), (IAT + DAY / 2, Some(IAT + DAY)));
    }

    #[test]
    fn a_lease_over_the_path_maximum_is_refused() {
        let p = AdmissionPolicy::new(AdmissionMode::Knock, "guest");
        let f = facts("guest", Some(Confirmation::Accept), false);
        assert!(matches!(
            evaluate_admit(Some(&p), &f, IAT, Some(LeaseRequest::Length(8 * DAY))),
            Err(AdmissionRefusal::LeaseOverMax { path: AdmissionPath::Knock, max, .. }) if max == 7 * DAY
        ));
        let long = Lease::new(IAT, IAT + DAY, Some(IAT + 30 * DAY)).unwrap();
        assert!(matches!(
            evaluate_admit(Some(&p), &f, IAT, Some(LeaseRequest::Exact(long))),
            Err(AdmissionRefusal::LeaseOverMax { .. })
        ));
        let unbounded = Lease::new(IAT, IAT + DAY, None).unwrap();
        assert_eq!(
            evaluate_admit(Some(&p), &f, IAT, Some(LeaseRequest::Exact(unbounded))),
            Err(AdmissionRefusal::LeaseUnbounded)
        );
    }

    #[test]
    fn a_notice_past_the_midpoint_is_refused_on_build_and_on_read() {
        assert_eq!(PostedLease::new(DAY, DAY, DAY), Err(PolicyError::NoticePastMidpoint { notice: DAY, default: DAY }));
        assert_eq!(PostedLease::new(2 * DAY, DAY, 1), Err(PolicyError::LeaseBounds { default: 2 * DAY, max: DAY }));
        let mut v = serde_json::to_value(AdmissionPolicy::new(AdmissionMode::Open, "guest")).unwrap();
        v["leases"]["knock"]["notice"] = (5 * DAY).into();
        assert!(serde_json::from_value::<AdmissionPolicy>(v).is_err());
    }

    #[test]
    fn wire_round_trips() {
        let p = AdmissionPolicy::new(AdmissionMode::Users, "guest").with_min_confirmation("member", Confirmation::Scan);
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["mode"], "users");
        assert_eq!(v["min_confirmation"]["member"], "scan");
        assert_eq!(v["leases"]["knock"], serde_json::json!({"default": 604800, "max": 604800, "notice": 86400}));
        assert!(v.get("admitters").is_none(), "empty admitters stay off the wire");
        let p = p.with_admitters(["admin"]);
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["admitters"], serde_json::json!(["admin"]));
        assert_eq!(serde_json::from_value::<AdmissionPolicy>(v).unwrap(), p);
    }
}
