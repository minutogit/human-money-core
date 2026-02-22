// tests/architecture/mod.rs
// cargo test --test architecture_tests
//!
//! Deklariert die einzelnen Test-Dateien innerhalb des `architecture`-Moduls.

// Macht die in der Datei implementierten Tests für den Runner sichtbar.
pub mod hardening;
pub mod resilience_and_gossip;
mod security_hardening;
