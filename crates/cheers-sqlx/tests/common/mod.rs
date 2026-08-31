//! The shared store-contract scenarios, re-exported.
//!
//! These used to be defined here. They moved to
//! `cheers_test_support::store_scenarios` when `cheers-turso` landed as a
//! third implementation of the same traits: one suite run by every backend
//! makes "the backends behave identically" a checked property instead of two
//! copies that agree until someone edits one. See that module's docs.
//!
//! `sqlite.rs` and `pg.rs` call `common::*` exactly as before.

#[allow(unused_imports)]
pub use cheers_test_support::store_scenarios::*;
