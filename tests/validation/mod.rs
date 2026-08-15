// tests/validation/mod.rs
// cargo test --test validation_tests
//!
//! Declares the individual test files within the `validation` module
//! so they are discovered by the test runner.

pub mod business_rules;
pub mod forward_compatibility;
pub mod privacy_modes;
pub mod signature_reuse;
pub mod standard_definition;
pub mod unit_service;
pub mod logic_integrity;
pub mod voucher_naming;
pub mod validity_rounding;

