// tests/architecture/mod.rs
// cargo test --test architecture_tests
//!
//! Deklariert die einzelnen Test-Dateien innerhalb des `architecture`-Moduls.

// Macht die in der Datei implementierten Tests für den Runner sichtbar.
pub mod hardening;
pub mod resilience_and_gossip;
mod security_hardening;
pub mod rollback_guard_tests;
pub mod gossip_decoupled_double_spend;
pub mod cloning_protection;
pub mod reproduce_integrity_bug;
pub mod security_audit_fixes;
