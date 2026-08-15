// tests/core_logic/mod.rs
// cargo test --test core_logic_tests

//! # Test module for core logic
//!
//! This module groups all tests focusing on central business logic,
//! mathematical correctness of transactions, and fundamental
//! security mechanisms.
//!
//! ## Contained Modules:
//!
//! - **`lifecycle`**: Tests the entire lifecycle of a voucher.
//! - **`math`**: Ensures numerical robustness of transactions.
//! - **`security`**: Tests for security vulnerabilities and double-spend detection.

pub mod flow_integrity;
pub mod lifecycle;
pub mod math;
pub mod privacy_modes;
pub mod security;
pub mod wot_conformance;
pub mod privacy_traceability;
pub mod privacy_split_workflows;
pub mod voucher_traceability_deep;
