// tests/integration_tests.rs
// cargo test --test integration_tests
//!
//! Unified integration test suite for human_money_core.
//! Binds all integration test modules under tests/ to run within a single test binary,
//! reducing compile times and cleaning up the tests/ root directory.

pub mod app_service;
pub mod architecture;
pub mod core_logic;
pub mod persistence;
pub mod services;
pub mod validation;
pub mod wallet_api;
