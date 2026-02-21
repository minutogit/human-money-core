// tests/validation/mod.rs
// cargo test --test validation_tests
//!
//! Deklariert die einzelnen Test-Dateien innerhalb des `validation`-Moduls,
//! damit sie vom Test-Runner gefunden werden.

pub mod business_rules;
pub mod forward_compatibility;
pub mod standard_definition;
pub mod unit_service;
pub mod privacy_modes;
pub mod signature_reuse;
