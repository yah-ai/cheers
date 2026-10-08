//! yah's built-in MCP scope set — verbatim with W159 §Scope vocabulary.
//!
//! One namespace set among many (R731 §D1), declared with
//! [`scopes!`](crate::scopes). Every entry is
//! [`Audiences::BoundAtStartup`](crate::Audiences::BoundAtStartup): yah's
//! audiences are deployment configuration (`yah-cloud-admin`, yubaba's
//! control plane, kamaji's configured aud), so each deployment binds them per
//! namespace when it builds its registry, and an unbound namespace is a
//! startup error (R731-F3). `audit:write` is
//! service-only (composition rule (4)). `ownership:write` is gone (R731-F8):
//! ownership writes are authorized by relationship, not scope.

crate::scopes! {
    ARCH_READ = "arch:read" { description: "Read architecture docs and anchors" };
    ARCH_WRITE = "arch:write" { description: "Write architecture docs and anchors" };
    BOARD_READ = "board:read" { description: "Read the hack-board" };
    BOARD_WRITE = "board:write" { description: "Write hack-board tickets" };
    CAMP_READ = "camp:read" { description: "Read camp state" };
    CAMP_ADMIN = "camp:admin" { description: "Administer a camp (does not imply camp:read)" };
    CLOUD_READ = "cloud:read" { description: "Read cloud deployment state" };
    CLOUD_DEPLOY = "cloud:deploy" { description: "Deploy services to the cloud" };
    CLOUD_DESTROY = "cloud:destroy" { description: "Destroy cloud resources" };
    CLOUD_ADMIN = "cloud:admin" { description: "Administer cloud configuration" };
    PARTY_READ = "party:read" { description: "Read party / session state" };
    PARTY_WRITE = "party:write" { description: "Dispatch and message party members" };
    SUBAGENT_SPAWN = "subagent:spawn" { description: "Spawn subagents" };
    SUBAGENT_CONTROL = "subagent:control" { description: "Control running subagents" };
    SQL_READ = "sql:read" { description: "Read a database yah vends (the camp-token default)" };
    SQL_WRITE = "sql:write" { description: "Write a database yah vends (minted only when policy and action both allow it)" };
    AUDIT_READ = "audit:read" { description: "Read the audit log" };
    AUDIT_WRITE = "audit:write" {
        description: "Ingest audit events (service principals only)",
        service_only: true,
    };
}

/// Every namespace [`DEFS`] declares; each must be bound at startup.
pub const NAMESPACES: &[&str] = &[
    "arch", "board", "camp", "cloud", "party", "subagent", "sql", "audit",
];

/// A builder holding [`DEFS`]; bind each of [`NAMESPACES`] from deployment
/// config, then `build`.
pub fn builder() -> crate::ScopeRegistryBuilder {
    crate::ScopeRegistry::builder().with(DEFS)
}

/// The registry for a deployment that serves every yah namespace at the same
/// audiences (a single-consumer issuer, tests).
pub fn registry_at<S: Into<String>>(
    auds: impl IntoIterator<Item = S>,
) -> Result<crate::ScopeRegistry, crate::ScopeRegistryError> {
    let auds: Vec<String> = auds.into_iter().map(Into::into).collect();
    NAMESPACES
        .iter()
        .fold(builder(), |b, ns| b.bind_audiences(ns, auds.clone()))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_strings_are_the_w159_vocabulary() {
        let wires: Vec<&str> = DEFS.iter().map(|d| d.scope.as_wire()).collect();
        assert_eq!(
            wires,
            [
                "arch:read", "arch:write", "board:read", "board:write", "camp:read",
                "camp:admin", "cloud:read", "cloud:deploy", "cloud:destroy", "cloud:admin",
                "party:read", "party:write", "subagent:spawn", "subagent:control",
                "sql:read", "sql:write", "audit:read", "audit:write",
            ]
        );
    }

    #[test]
    fn only_audit_write_is_service_only() {
        let so: Vec<&str> =
            DEFS.iter().filter(|d| d.service_only).map(|d| d.scope.as_wire()).collect();
        assert_eq!(so, ["audit:write"]);
        assert!(DEFS.iter().all(|d| d.audiences == crate::Audiences::BoundAtStartup));
        assert_eq!(registry_at(["https://a"]).unwrap().len(), 18);
    }

    #[test]
    fn namespaces_cover_defs_and_unbound_fails() {
        let mut ns: Vec<&str> = DEFS.iter().map(|d| d.scope.namespace()).collect();
        ns.dedup();
        assert_eq!(ns, NAMESPACES);
        let err = NAMESPACES
            .iter()
            .filter(|n| **n != "cloud")
            .fold(builder(), |b, n| b.bind_audiences(n, ["https://a".to_owned()]))
            .build()
            .unwrap_err();
        assert_eq!(err, crate::ScopeRegistryError::Unbound(CLOUD_READ));
    }

    #[test]
    fn a_scope_is_valid_only_where_its_namespace_was_bound() {
        let reg = builder()
            .bind_audiences("cloud", ["yah-cloud-admin".to_owned()])
            .bind_audiences("arch", ["k".to_owned()])
            .bind_audiences("board", ["k".to_owned()])
            .bind_audiences("camp", ["k".to_owned()])
            .bind_audiences("party", ["k".to_owned()])
            .bind_audiences("subagent", ["k".to_owned()])
            .bind_audiences("sql",["k".to_owned()])
            .bind_audiences("audit", ["yubaba:control-plane".to_owned()])
            .build()
            .unwrap();
        assert!(reg.is_valid_at(&CLOUD_DEPLOY, "yah-cloud-admin"));
        assert!(!reg.is_valid_at(&CLOUD_DEPLOY, "yubaba:control-plane"));
        assert!(!reg.is_valid_at(&AUDIT_WRITE, "yah-cloud-admin"));
    }
}
