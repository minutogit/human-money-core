//! # human_money_core
//!
//! Core library of a decentralized, trust-based electronic voucher payment system.
//! Provides data structures and stateless services for creating, managing and
//! verifying digital vouchers – persisted via the concrete [`FileStorage`](storage::file_storage::FileStorage)
//! encrypted-file backend.
//!
//! ## Architecture
//!
//! - **Concrete persistence:** [`Wallet`] persists via the concrete [`FileStorage`](storage::file_storage::FileStorage)
//!   encrypted-file backend (no abstract `Storage` trait). All file I/O is target-gated via
//!   `cfg(not(target_arch="wasm32"))` – the library compiles for `wasm32-unknown-unknown`.
//! - **Stateless services** (`services::*`): pure functions (crypto, CEL, validation, L2 gateway, …).
//!   Only `Wallet` and [`AppService`](app_service::AppService) hold state.
//! - **Offline-first:** no network calls in core. L2 locking/status is modeled by
//!   [`services::l2_gateway`] and executed by the host.
//! - **Fraud detection, not prevention:** double-spending is cryptographically provable via
//!   transaction fingerprints and L2 trap commitments.
//! - **Cryptographic stability:** core models serialize in canonical `snake_case` (serde without
//!   `camelCase` renames); JS/DTO transforms happen only at the app boundary (`AppService` / Tauri wrapper).
//!
//! ## Modules
//!
//! - [`app_service`]: high-level facade for client apps (profile lifecycle, transfers, bundles, seals).
//! - [`models`]: vouchers, identities, standards, seals, integrity records, wallet events, L2 API types.
//! - [`services`]: `crypto` (Ed25519/X25519/ChaCha20Poly1305), `voucher_validation`, `cel`, `l2_gateway`, `utils`, …
//! - [`storage`]: [`FileStorage`](storage::file_storage::FileStorage) with
//!   authenticated multi-file bindings, generation counters and file locking.
//! - [`archive`]: [`FileVoucherArchive`](archive::file_archive::FileVoucherArchive) for long-term voucher history.
//! - [`wallet`]: [`Wallet`] facade, Voucher lifecycle instances, trust checks and event logging.
//!
//! ## Safety fuses
//!
//! `test-utils` enables a thread-local signature bypass for integration tests and is
//! forbidden in release builds (compile_error). `cargo check --target wasm32-unknown-unknown`
//! and `cargo check --manifest-path bindings/wasm/Cargo.toml` must stay green.

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

// Models & Error
pub use error::{AppFacadeError, Error, StandardDefinitionError, ValidationError, VoucherCoreError};
pub use models::profile::{UserIdentity, UserProfile, VoucherStore};
pub use models::seal::{LocalSealRecord, SealPayload, SealSyncState, SyncStatus, WalletSeal};
pub use models::secure_container::{ContainerConfig, EncryptionType, PayloadType, PrivacyMode, SecureContainer};
pub use models::storage_integrity::{IntegrityPayload, IntegrityReport, LocalIntegrityRecord, StorageIntegrityRecord};
pub use models::voucher::{
    Address, Collateral, NewVoucherData, Transaction, TransactionSecrets, ValueDefinition, Voucher,
    VoucherSignature, VoucherStandard,
};
pub use models::voucher_standard_definition::VoucherStandardDefinition;
pub use models::wallet_event::{EventBffData, WalletEvent, WalletEventType};
pub use wallet::instance::{ValidationFailureReason, VoucherInstance, VoucherStatus};

// Wallet & Storage Facades
pub use services::mnemonic::MnemonicLanguage;
pub use storage::file_storage::FileStorage;
pub use storage::{AuthMethod, StorageError};
pub use wallet::Wallet;

// Archive
pub use archive::file_archive::FileVoucherArchive;

// Services
pub use services::crypto;
pub use services::trust_provider::{NoopTrustProvider, TrustProvider};
pub use services::utils;
pub use services::utils::to_canonical_json;
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
    static SIGNATURE_BYPASS_ACTIVE: Cell<bool> = const { Cell::new(false) };
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
