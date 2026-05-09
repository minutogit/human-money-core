//! # src/lib.rs
//!
//! The core logic of a decentralized, trust-based electronic voucher payment system.
//! This library provides the data structures and functions for creating, managing
//! and verifying digital vouchers.

// Declare main modules of the library and make them public.
pub mod app_service;
pub mod archive;
pub mod error;
pub mod models;
pub mod services;
pub mod storage;
pub mod wallet;

// Re-export key public types for easier use.
// Instead of `human_money_core::models::voucher::Voucher`, users can now write `human_money_core::Voucher`.

// Models
pub use error::VoucherCoreError;
pub use models::profile::{UserIdentity, UserProfile, VoucherStore};
pub use models::seal::{LocalSealRecord, SealPayload, SealSyncState, SyncStatus, WalletSeal};
pub use models::voucher::{
    Address, Collateral, Transaction, ValueDefinition, Voucher, VoucherSignature, VoucherStandard,
};
pub use models::voucher_standard_definition::VoucherStandardDefinition;
pub use models::wallet_event::{EventBffData, WalletEvent, WalletEventType};
pub use wallet::instance::{ValidationFailureReason, VoucherInstance, VoucherStatus};

// Wallet & Storage Facades
pub use services::mnemonic::MnemonicLanguage;
pub use storage::file_storage::FileStorage;
pub use storage::{AuthMethod, Storage, StorageError};
pub use wallet::Wallet;

// Archive
pub use archive::file_archive::FileVoucherArchive;
pub use archive::{ArchiveError, VoucherArchive};

// Services
pub use services::crypto_utils;
pub use services::standard_manager::verify_and_parse_standard;
pub use services::utils;
pub use services::utils::to_canonical_json;
pub use services::voucher_manager::{
    NewVoucherData, create_transaction, create_voucher, from_json, get_spendable_balance, to_json,
};
pub use services::voucher_validation::validate_voucher_against_standard;

// =========================================================================
//  SAFETY FUSE & TEST UTILITIES
// =========================================================================

// 1. COMPILE-TIME BOMB
// Physically prevents a release build from being created with active test tools.
// If this error occurs, an attempt was made to use 'test-utils' in release mode -> FORBIDDEN.
#[cfg(all(not(debug_assertions), feature = "test-utils"))]
compile_error!(
    "CRITICAL SECURITY FAILURE: The 'test-utils' feature is enabled in a release build! This disables signature verification capabilities. Build aborted."
);

// 2. THREAD-LOCAL BYPASS STATE
#[cfg(feature = "test-utils")]
use std::cell::Cell;

#[cfg(feature = "test-utils")]
thread_local! {
    /// Stores the bypass status exclusively for the current thread.
    /// Default: false (security active).
    static SIGNATURE_BYPASS_ACTIVE: Cell<bool> = Cell::new(false);
}

// 3. PUBLIC API (Only available with feature="test-utils")

/// Activates (true) or deactivates (false) signature verification for the current thread.
/// Use this ONLY in integration tests.
#[cfg(feature = "test-utils")]
pub fn set_signature_bypass(bypass: bool) {
    SIGNATURE_BYPASS_ACTIVE.with(|f| f.set(bypass));
}

/// Checks if the bypass is active for the current thread.
#[cfg(feature = "test-utils")]
pub fn is_signature_bypass_active() -> bool {
    SIGNATURE_BYPASS_ACTIVE.with(|f| f.get())
}

// Makes the test module available for all tests (internal and external).
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
