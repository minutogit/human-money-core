// tests/wallet_api/mod.rs
// cargo test --test wallet_api_tests
//!
//! Deklariert die Sub-Module für die API-Integrationstests.

pub mod general_workflows;
pub mod signature_workflows;

// Deklariert das neue Modul für komplexe Zustands- und Konflikttests.
mod state_management;
// Deklariert das neue Modul für Tests zur atomaren Zustandsverwaltung (Transaktionalität).
mod hostile_bundles;
mod hostile_standards;
mod lifecycle_and_data;
mod transactionality;
mod mixed_mode_vulnerability;
mod multi_identity_vulnerability;
