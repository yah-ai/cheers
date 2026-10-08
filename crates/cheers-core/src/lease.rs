//! The lease standard: one advisory-then-hard window every cheers artifact
//! that can lapse shares (`edge-verifiable-auth.md`, "Lease").
//!
//! A [`Lease`] is `refresh_after` plus an optional `exp`. [`Lease::state_at`]
//! reads it as [`LeaseState`]: `Current` before `refresh_after`, `Warning`
//! from `refresh_after` until `exp`, `Expired` from `exp`. With no `exp` the
//! lease never expires, and a due lease reads `Warning { exp: None }`.
//!
//! cheers only computes the state. It never notifies anyone: consumers
//! monitor [`LeaseState`] and surface the warning themselves.
//!
//! The wire shape is flattened into the owning artifact, so a lease with no
//! `exp` is the bare `"refresh_after": N` standing bindings and snapshots
//! have always carried.

use serde::{Deserialize, Serialize};

/// Where a [`Lease`] stands at a given instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseState {
    /// Before `refresh_after`: nothing to do.
    Current,
    /// At or past `refresh_after`: fetch a successor, renew or upgrade. `exp`
    /// is when it lapses, if it ever does.
    Warning { exp: Option<i64> },
    /// At or past `exp`.
    Expired,
}

/// An invariant [`Lease::new`] and [`Lease::validate`] refuse to see broken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LeaseError {
    /// With an `exp`, `refresh_after` must satisfy
    /// `iat < refresh_after <= iat + (exp - iat) / 2`: the holder gets at
    /// least half the lease as warning.
    #[error("lease refresh_after {refresh_after} is outside (iat {iat}, midpoint of exp {exp}]")]
    RefreshOutsideWindow { iat: i64, refresh_after: i64, exp: i64 },
}

/// When to start warning and, optionally, when to stop honoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    refresh_after: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exp: Option<i64>,
}

impl Lease {
    /// Build a lease for an artifact minted at `iat`. With an `exp`, refuses
    /// unless `iat < refresh_after <= iat + (exp - iat) / 2`. Without one there
    /// is no constraint.
    pub fn new(iat: i64, refresh_after: i64, exp: Option<i64>) -> Result<Self, LeaseError> {
        let lease = Self { refresh_after, exp };
        lease.validate(iat)?;
        Ok(lease)
    }

    /// Re-check the invariant against the artifact's `iat`. Verifiers call
    /// this on a decoded artifact, since deserialization alone cannot.
    pub fn validate(&self, iat: i64) -> Result<(), LeaseError> {
        if let Some(exp) = self.exp {
            let midpoint = iat.saturating_add(exp.saturating_sub(iat) / 2);
            if !(iat < self.refresh_after && self.refresh_after <= midpoint) {
                return Err(LeaseError::RefreshOutsideWindow { iat, refresh_after: self.refresh_after, exp });
            }
        }
        Ok(())
    }

    /// When the holder should start renewing (Unix seconds).
    pub fn refresh_after(&self) -> i64 {
        self.refresh_after
    }

    /// When the lease lapses, if it does (Unix seconds).
    pub fn exp(&self) -> Option<i64> {
        self.exp
    }

    /// The lease's state at `now`.
    pub fn state_at(&self, now: i64) -> LeaseState {
        if self.exp.is_some_and(|exp| now >= exp) {
            LeaseState::Expired
        } else if now >= self.refresh_after {
            LeaseState::Warning { exp: self.exp }
        } else {
            LeaseState::Current
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_without_exp_never_expires() {
        let l = Lease::new(1_000, 2_000, None).unwrap();
        assert_eq!(l.state_at(1_999), LeaseState::Current);
        assert_eq!(l.state_at(2_000), LeaseState::Warning { exp: None });
        assert_eq!(l.state_at(i64::MAX), LeaseState::Warning { exp: None });
    }

    #[test]
    fn state_at_each_boundary_with_exp() {
        let l = Lease::new(1_000, 1_500, Some(2_000)).unwrap();
        assert_eq!(l.state_at(1_499), LeaseState::Current);
        assert_eq!(l.state_at(1_500), LeaseState::Warning { exp: Some(2_000) });
        assert_eq!(l.state_at(1_999), LeaseState::Warning { exp: Some(2_000) });
        assert_eq!(l.state_at(2_000), LeaseState::Expired);
    }

    #[test]
    fn refresh_after_is_bounded_by_the_midpoint() {
        assert!(Lease::new(1_000, 1_500, Some(2_000)).is_ok());
        assert!(matches!(Lease::new(1_000, 1_501, Some(2_000)), Err(LeaseError::RefreshOutsideWindow { .. })));
        assert!(Lease::new(1_000, 1_000, Some(2_000)).is_err());
        assert!(Lease::new(1_000, 999, Some(2_000)).is_err());
        // no exp: today's (absent) constraint
        assert!(Lease::new(1_000, 999, None).is_ok());
    }

    #[test]
    fn wire_omits_exp_when_none() {
        let bare = serde_json::to_string(&Lease::new(1, 2, None).unwrap()).unwrap();
        assert_eq!(bare, r#"{"refresh_after":2}"#);
        let full = serde_json::to_string(&Lease::new(0, 5, Some(10)).unwrap()).unwrap();
        assert_eq!(full, r#"{"refresh_after":5,"exp":10}"#);
        assert_eq!(serde_json::from_str::<Lease>(&bare).unwrap().exp(), None);
    }
}
