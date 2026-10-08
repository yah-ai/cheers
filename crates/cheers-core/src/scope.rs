//! Scope vocabulary — the validated `<namespace>:<verb>` wire type, the
//! [`scopes!`](crate::scopes) declaration macro, and the [`ScopeRegistry`]
//! a deployment builds at startup (R731 §D1).
//!
//! The split of responsibilities:
//!
//! - [`Scope`] is *syntax only*. `FromStr` and `Deserialize` accept any
//!   string matching the grammar (`[a-z][a-z0-9-]*:[a-z][a-z0-9-]*`, exactly
//!   one colon, no `*`), so storage and verifiers decode scopes a product they
//!   have never heard of declared. Composition rule (1) — no wildcards — is
//!   enforced here.
//! - Products declare their vocabulary once with [`scopes!`](crate::scopes):
//!   a typed `pub const` per scope (a typo is a compile error, a malformed
//!   literal panics in const evaluation) plus a `DEFS` slice of
//!   [`ScopeDef`] metadata. The macro needs only cheers-core, so verify-only
//!   crates use it without linking cheers-server.
//! - [`ScopeRegistry`] is *semantics*: which scopes this deployment issues,
//!   which are service-only, and at which audiences each is valid. The
//!   grant/mint side consults it ([`validate_grant`](crate::validate_grant));
//!   verifiers do not — they compare claims against typed constants.
//!
//! There is no implication between scopes: `camp:admin` and `camp:read` are
//! two unrelated strings (composition rule (3)).

use std::borrow::Cow;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// One MCP scope, `<namespace>:<verb>`. Serializes as the literal wire
/// string (`"cloud:deploy"`).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Scope(Cow<'static, str>);

const fn is_part_char(b: u8, first: bool) -> bool {
    b.is_ascii_lowercase() || (!first && (b.is_ascii_digit() || b == b'-'))
}

/// Grammar check shared by the const constructor and the runtime parser.
const fn is_valid_scope(s: &[u8]) -> bool {
    let mut i = 0;
    let mut colons = 0;
    let mut at_part_start = true;
    while i < s.len() {
        let b = s[i];
        if b == b':' {
            if at_part_start {
                return false;
            }
            colons += 1;
            at_part_start = true;
        } else {
            if !is_part_char(b, at_part_start) {
                return false;
            }
            at_part_start = false;
        }
        i += 1;
    }
    colons == 1 && !at_part_start
}

impl Scope {
    /// Const constructor for declared scopes. Panics — at compile time when
    /// used in a `const` — on a string that is not `<namespace>:<verb>`.
    pub const fn from_static(s: &'static str) -> Self {
        assert!(
            is_valid_scope(s.as_bytes()),
            "scope must be <namespace>:<verb>, each side [a-z][a-z0-9-]*"
        );
        Self(Cow::Borrowed(s))
    }

    /// The literal wire string.
    pub fn as_wire(&self) -> &str {
        &self.0
    }

    /// The part before the colon (`cloud` in `cloud:deploy`).
    pub fn namespace(&self) -> &str {
        self.0.split_once(':').map(|(ns, _)| ns).unwrap_or_default()
    }

    /// The part after the colon (`deploy` in `cloud:deploy`).
    pub fn verb(&self) -> &str {
        self.0.split_once(':').map(|(_, v)| v).unwrap_or_default()
    }
}

impl std::fmt::Debug for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Scope({})", self.0)
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a string failed to parse as a [`Scope`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScopeParseError {
    /// Composition rule (1): wildcards are never accepted on the wire.
    #[error("wildcard scope '{0}' is not allowed on the wire")]
    Wildcard(String),
    /// Not `<namespace>:<verb>` with each side `[a-z][a-z0-9-]*`.
    #[error("malformed scope '{0}': expected <namespace>:<verb>, each side [a-z][a-z0-9-]*")]
    Malformed(String),
}

impl std::str::FromStr for Scope {
    type Err = ScopeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('*') {
            return Err(ScopeParseError::Wildcard(s.to_owned()));
        }
        if !is_valid_scope(s.as_bytes()) {
            return Err(ScopeParseError::Malformed(s.to_owned()));
        }
        Ok(Self(Cow::Owned(s.to_owned())))
    }
}

impl Serialize for Scope {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Scope {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// The audiences a scope may be minted for. There is no "valid everywhere":
/// a scope is locked to named audiences, either in its declaration or by the
/// deployment at registry build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Audiences {
    /// Valid only at these exact `aud` values.
    Only(&'static [&'static str]),
    /// Audiences are deployment configuration; the registry builder must
    /// bind them ([`ScopeRegistryBuilder::bind_audiences`]) or `build` fails.
    BoundAtStartup,
}

/// Metadata for one declared scope. Emitted by [`scopes!`](crate::scopes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeDef {
    pub scope: Scope,
    /// Composition rule (4): grantable to `Service` principals only.
    pub service_only: bool,
    pub description: &'static str,
    pub audiences: Audiences,
}

/// Declare a product's scope set once.
///
/// ```
/// mod issue_scopes {
///     cheers_core::scopes! {
///         /// Triage issues.
///         ISSUES_TRIAGE = "issues:triage" {
///             description: "Triage and label issues",
///             audiences: ["https://issues.example"],
///         };
///         INGEST = "issues:ingest" {
///             description: "Machine ingest",
///             service_only: true,
///         };
///     }
/// }
/// assert_eq!(issue_scopes::ISSUES_TRIAGE.as_wire(), "issues:triage");
/// assert_eq!(issue_scopes::DEFS.len(), 2);
/// ```
///
/// Emits one `pub const NAME: Scope` per entry and
/// `pub const DEFS: &[ScopeDef]`. `service_only` defaults to `false`;
/// omitting `audiences` means [`Audiences::BoundAtStartup`].
#[macro_export]
macro_rules! scopes {
    ($(
        $(#[$meta:meta])*
        $name:ident = $wire:literal {
            description: $desc:literal
            $(, service_only: $so:literal)?
            $(, audiences: [$($aud:literal),* $(,)?])?
            $(,)?
        };
    )*) => {
        $(
            $(#[$meta])*
            pub const $name: $crate::Scope = $crate::Scope::from_static($wire);
        )*

        /// Every scope this set declares, with its registry metadata.
        pub const DEFS: &[$crate::ScopeDef] = &[$(
            $crate::ScopeDef {
                scope: $name,
                service_only: $crate::scopes!(@so $($so)?),
                description: $desc,
                audiences: $crate::scopes!(@aud $([$($aud),*])?),
            },
        )*];
    };
    (@so) => { false };
    (@so $so:literal) => { $so };
    (@aud) => { $crate::Audiences::BoundAtStartup };
    (@aud [$($aud:literal),*]) => { $crate::Audiences::Only(&[$($aud),*]) };
}

/// Why [`ScopeRegistryBuilder::build`] refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScopeRegistryError {
    #[error("scope '{0}' is declared more than once")]
    Duplicate(Scope),
    #[error("scope '{0}' needs its audiences bound at startup and none were bound")]
    Unbound(Scope),
    #[error("scope '{0}' ends up with no audiences")]
    NoAudiences(Scope),
    #[error("audiences were bound for namespace '{0}', which declares no startup-bound scope")]
    UnusedBinding(String),
}

/// The scopes a deployment issues, built once at startup from one or more
/// [`scopes!`](crate::scopes) `DEFS` slices plus the deployment's audience
/// bindings. Iteration follows declaration order.
#[derive(Debug, Clone, Default)]
pub struct ScopeRegistry {
    defs: Vec<ScopeDef>,
    /// Resolved audiences, parallel to `defs`.
    audiences: Vec<Vec<String>>,
    index: HashMap<Scope, usize>,
}

/// Builder for [`ScopeRegistry`].
#[derive(Debug, Default)]
pub struct ScopeRegistryBuilder {
    defs: Vec<ScopeDef>,
    bindings: Vec<(String, Vec<String>)>,
}

impl ScopeRegistryBuilder {
    pub fn with(mut self, defs: &[ScopeDef]) -> Self {
        self.defs.extend_from_slice(defs);
        self
    }

    /// Bind every [`Audiences::BoundAtStartup`] scope in `namespace` to
    /// `auds`. Repeated calls for one namespace accumulate.
    pub fn bind_audiences(
        mut self,
        namespace: &str,
        auds: impl IntoIterator<Item = String>,
    ) -> Self {
        self.bindings.push((namespace.to_owned(), auds.into_iter().collect()));
        self
    }

    /// Fails on a duplicate scope, an unbound startup-bound scope, a scope
    /// left with zero audiences, or a binding no scope uses.
    pub fn build(self) -> Result<ScopeRegistry, ScopeRegistryError> {
        let mut bound: HashMap<&str, Vec<String>> = HashMap::new();
        for (ns, auds) in &self.bindings {
            let e = bound.entry(ns.as_str()).or_default();
            for a in auds {
                if !e.contains(a) {
                    e.push(a.clone());
                }
            }
        }
        let mut used = std::collections::HashSet::new();
        let mut index = HashMap::with_capacity(self.defs.len());
        let mut audiences = Vec::with_capacity(self.defs.len());
        for (i, d) in self.defs.iter().enumerate() {
            if index.insert(d.scope.clone(), i).is_some() {
                return Err(ScopeRegistryError::Duplicate(d.scope.clone()));
            }
            let resolved: Vec<String> = match d.audiences {
                Audiences::Only(list) => list.iter().map(|a| (*a).to_owned()).collect(),
                Audiences::BoundAtStartup => {
                    let ns = d.scope.namespace();
                    used.insert(ns.to_owned());
                    bound
                        .get(ns)
                        .cloned()
                        .ok_or_else(|| ScopeRegistryError::Unbound(d.scope.clone()))?
                }
            };
            if resolved.is_empty() {
                return Err(ScopeRegistryError::NoAudiences(d.scope.clone()));
            }
            audiences.push(resolved);
        }
        if let Some(ns) = bound.keys().find(|ns| !used.contains(**ns)) {
            return Err(ScopeRegistryError::UnusedBinding((*ns).to_owned()));
        }
        Ok(ScopeRegistry { defs: self.defs, audiences, index })
    }
}

impl ScopeRegistry {
    pub fn builder() -> ScopeRegistryBuilder {
        ScopeRegistryBuilder::default()
    }

    pub fn get(&self, scope: &Scope) -> Option<&ScopeDef> {
        self.index.get(scope).map(|&i| &self.defs[i])
    }

    pub fn contains(&self, scope: &Scope) -> bool {
        self.index.contains_key(scope)
    }

    /// `None` for a scope this registry does not declare.
    pub fn service_only(&self, scope: &Scope) -> Option<bool> {
        self.get(scope).map(|d| d.service_only)
    }

    pub fn description(&self, scope: &Scope) -> Option<&'static str> {
        self.get(scope).map(|d| d.description)
    }

    /// Declared AND valid at `aud`. An unknown scope is valid nowhere.
    pub fn is_valid_at(&self, scope: &Scope, aud: &str) -> bool {
        self.index
            .get(scope)
            .is_some_and(|&i| self.audiences[i].iter().any(|a| a == aud))
    }

    /// The audiences `scope` resolved to at build; `None` if undeclared.
    pub fn audiences(&self, scope: &Scope) -> Option<&[String]> {
        self.index.get(scope).map(|&i| self.audiences[i].as_slice())
    }

    pub fn iter(&self) -> impl Iterator<Item = &ScopeDef> {
        self.defs.iter()
    }

    pub fn len(&self) -> usize {
        self.defs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.defs.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    mod sample {
        crate::scopes! {
            TRIAGE = "issues:triage" {
                description: "triage",
                audiences: ["https://issues.example"],
            };
            INGEST = "issues:ingest" {
                description: "ingest",
                service_only: true,
            };
        }
    }

    #[test]
    fn grammar_accepts_namespace_verb() {
        for ok in ["cloud:deploy", "subagent:control", "issues:read-full", "a1:b2"] {
            assert_eq!(Scope::from_str(ok).unwrap().as_wire(), ok);
        }
    }

    #[test]
    fn grammar_rejects_malformed() {
        for bad in [
            "", "cloud", ":deploy", "cloud:", "cloud:deploy:x", "Cloud:deploy", "cloud:Deploy",
            "1cloud:deploy", "cloud:-x", "cloud :deploy", "cloud_x:deploy",
        ] {
            assert!(
                matches!(Scope::from_str(bad), Err(ScopeParseError::Malformed(_))),
                "{bad:?} must be Malformed"
            );
        }
    }

    #[test]
    fn grammar_rejects_wildcards() {
        for w in ["cloud:*", "*", "*:read", "ownership:*"] {
            assert!(matches!(Scope::from_str(w), Err(ScopeParseError::Wildcard(ref s)) if s == w));
        }
    }

    #[test]
    fn parsed_equals_declared_and_hashes_alike() {
        let parsed = Scope::from_str("issues:triage").unwrap();
        assert_eq!(parsed, sample::TRIAGE);
        let mut set = std::collections::HashSet::new();
        set.insert(sample::TRIAGE);
        assert!(set.contains(&parsed));
        assert_eq!(parsed.namespace(), "issues");
        assert_eq!(parsed.verb(), "triage");
    }

    #[test]
    fn macro_emits_defs_with_metadata() {
        assert_eq!(sample::DEFS.len(), 2);
        assert_eq!(sample::DEFS[0].scope, sample::TRIAGE);
        assert!(!sample::DEFS[0].service_only);
        assert_eq!(sample::DEFS[0].audiences, Audiences::Only(&["https://issues.example"]));
        assert!(sample::DEFS[1].service_only);
        assert_eq!(sample::DEFS[1].audiences, Audiences::BoundAtStartup);
    }

    fn sample_reg() -> ScopeRegistry {
        ScopeRegistry::builder()
            .with(sample::DEFS)
            .bind_audiences("issues", ["https://ingest.example".to_owned()])
            .build()
            .unwrap()
    }

    #[test]
    fn registry_answers_metadata_and_audience() {
        let reg = sample_reg();
        assert_eq!(reg.service_only(&sample::INGEST), Some(true));
        assert_eq!(reg.description(&sample::TRIAGE), Some("triage"));
        assert!(reg.is_valid_at(&sample::TRIAGE, "https://issues.example"));
        assert!(!reg.is_valid_at(&sample::TRIAGE, "https://other.example"));
        assert!(reg.is_valid_at(&sample::INGEST, "https://ingest.example"));
        assert!(!reg.is_valid_at(&sample::INGEST, "https://anything"), "bound, not open");
        assert!(!reg.is_valid_at(&sample::TRIAGE, "https://ingest.example"), "Only is untouched by binding");
        let unknown = Scope::from_str("issues:nuke").unwrap();
        assert!(!reg.contains(&unknown));
        assert!(!reg.is_valid_at(&unknown, "https://issues.example"));
        let order: Vec<_> = reg.iter().map(|d| d.scope.clone()).collect();
        assert_eq!(order, vec![sample::TRIAGE, sample::INGEST]);
    }

    #[test]
    fn registry_builder_rejects_duplicates() {
        let err = ScopeRegistry::builder()
            .with(sample::DEFS)
            .with(&sample::DEFS[..1])
            .bind_audiences("issues", ["a".to_owned()])
            .build()
            .unwrap_err();
        assert_eq!(err, ScopeRegistryError::Duplicate(sample::TRIAGE));
    }

    #[test]
    fn unbound_or_empty_or_unused_bindings_fail_build() {
        let err = ScopeRegistry::builder().with(sample::DEFS).build().unwrap_err();
        assert_eq!(err, ScopeRegistryError::Unbound(sample::INGEST));
        let err = ScopeRegistry::builder()
            .with(sample::DEFS)
            .bind_audiences("issues", Vec::<String>::new())
            .build()
            .unwrap_err();
        assert_eq!(err, ScopeRegistryError::NoAudiences(sample::INGEST));
        let err = ScopeRegistry::builder()
            .with(sample::DEFS)
            .bind_audiences("issues", ["a".to_owned()])
            .bind_audiences("nope", ["a".to_owned()])
            .build()
            .unwrap_err();
        assert_eq!(err, ScopeRegistryError::UnusedBinding("nope".into()));
    }
}
