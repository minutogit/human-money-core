// tests/core_logic/mod.rs
// cargo test --test core_logic_tests

//! # Test-Modul für die Kernlogik
//!
//! Dieses Modul bündelt alle Tests, die sich auf die zentrale Geschäftslogik,
//! die mathematische Korrektheit von Transaktionen und die grundlegenden
//! Sicherheitsmechanismen konzentrieren.
//!
//! ## Enthaltene Module:
//!
//! - **`lifecycle`**: Tests den gesamten Lebenszyklus eines Gutscheins.
//! - **`math`**: Stellt die numerische Robustheit von Transaktionen sicher.
//! - **`security`**: Prüft auf Sicherheitslücken und die Double-Spend-Erkennung.

pub mod flow_integrity;
pub mod lifecycle;
pub mod math;
pub mod privacy_modes;
pub mod security;
pub mod wot_conformance;
pub mod privacy_traceability;
pub mod privacy_split_workflows;
pub mod voucher_traceability_deep;
