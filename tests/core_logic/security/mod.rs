// tests/core_logic/security/mod.rs
// cargo test --test core_logic_tests

//! # Test suite for security aspects and fraud detection
//!
//! This file bundles two critical areas of voucher security:
//!
//! 1.  **Local double-spending detection:**
//!     - Verification of fingerprint management.
//!     - End-to-end scenario for detecting a fraud attempt.
//!
//! 2.  **Vulnerabilities & attack simulations:**
//!     - Simulation of attacks by a malicious actor ("hacker").
//!     - Robustness checks of validation logic (`voucher_validation.rs`).
//!     - Fuzzing tests to verify structural integrity.

// Import helper functions so they are available to submodules
// as `super::test_utils`.
use human_money_core::test_utils;

// Declare the test files as modules.
mod double_spend;
mod double_spend_identification;
mod privacy_evasion;
mod root_account;
mod standard_validation;
mod state_and_collaboration;
mod trap_verification;
mod vulnerabilities;
mod identity_trap_audit;
pub mod forced_double_spend_stealth_vulnerability;
pub mod privacy_mode_compliance;
pub mod concurrent_access_vulnerability;
