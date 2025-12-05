// tests/wallet_api_tests.rs
// cargo test --test wallet_api_tests
//!
//! Dieses Modul dient als Einstiegspunkt für alle Integrationstests,
//! die die öffentliche High-Level-API der `human_money_core` betreffen.
//! Es bindet die untergeordneten Testmodule für allgemeine Workflows
//! und Signatur-Workflows ein.

// Verzeichnis `tests/wallet_api` wird als Modul eingebunden
mod wallet_api;