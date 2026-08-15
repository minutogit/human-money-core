// tests/architecture/mod.rs
// cargo test --test architecture_tests
//!
//! Declares individual test files within the `architecture` module.

// Makes tests implemented in the files visible to the test runner.
pub mod hardening;
pub mod resilience_and_gossip;
mod security_hardening;
pub mod rollback_guard_tests;
pub mod gossip_decoupled_double_spend;
pub mod cloning_protection;
pub mod reproduce_integrity_bug;
pub mod security_audit_fixes;
