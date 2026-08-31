//! Single integration-test root for `cheers-axum` (R514 / parent W304).
//!
//! Every `tests/*.rs` sibling is a module of THIS binary rather than its own
//! test target. `autotests = false` in `Cargo.toml` is the load-bearing half:
//! without it cargo still auto-discovers each top-level `tests/*.rs` as a
//! separate target *in addition* to the modules declared here, and the binary
//! count doesn't drop. `tests/common/` is a module directory, not a target, so
//! it was already shared and is unaffected.
//!
//! Merge safety (audited before the consolidation): none of these tests bind a
//! fixed port — the OIDC ones stand up `wiremock::MockServer::start()`, which
//! takes an ephemeral port per instance, and everything else drives the router
//! through `tower::Service` with no listener at all. No test touches an
//! on-disk database, the environment, the process CWD, or a `static`, so
//! sharing one address space and libtest's thread pool introduces no coupling.
//!
//! Test names gain a module prefix (`google_basic::` etc.) since the binary
//! name no longer supplies it; the set of tests is otherwise identical.

mod common;

mod apple_basic;
mod audit_basic;
mod enrollment_basic;
mod google_basic;
mod google_round_trip;
mod magic_link_basic;
mod me_basic;
mod ownership_basic;
mod passkey_basic;
