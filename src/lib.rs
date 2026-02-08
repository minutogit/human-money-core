//! # src/lib.rs
//!
//! Die Kernlogik eines dezentralen, vertrauensbasierten elektronischen Gutschein-Zahlungssystems.
//! Diese Bibliothek stellt die Datenstrukturen und Funktionen zur Erstellung, Verwaltung
//! und Verifizierung von digitalen Gutscheinen bereit.

// Deklariert die Hauptmodule der Bibliothek und macht sie öffentlich.
pub mod app_service;
pub mod archive;
pub mod error;
pub mod models;
pub mod services;
pub mod storage;
pub mod wallet;

// Re-exportiert die wichtigsten öffentlichen Typen für eine einfachere Nutzung.
// Anstatt `human_money_core::models::voucher::Voucher` können Benutzer nun `human_money_core::Voucher` schreiben.

// Modelle
pub use error::VoucherCoreError;
pub use models::profile::{UserIdentity, UserProfile, VoucherStore};
pub use models::voucher::{
    Address, Collateral, Transaction, ValueDefinition, Voucher, VoucherSignature, VoucherStandard,
};
pub use models::voucher_standard_definition::VoucherStandardDefinition;
pub use wallet::instance::{ValidationFailureReason, VoucherInstance, VoucherStatus};

// Wallet & Storage Fassaden
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
// Verhindert physikalisch, dass ein Release-Build mit aktiven Test-Tools erstellt wird.
// Wenn dieser Fehler auftritt, wurde versucht 'test-utils' im Release-Mode zu nutzen -> VERBOTEN.
#[cfg(all(not(debug_assertions), feature = "test-utils"))]
compile_error!("CRITICAL SECURITY FAILURE: The 'test-utils' feature is enabled in a release build! This disables signature verification capabilities. Build aborted.");

// 2. THREAD-LOCAL BYPASS STATE
#[cfg(feature = "test-utils")]
use std::cell::Cell;

#[cfg(feature = "test-utils")]
thread_local! {
    /// Speichert den Bypass-Status exklusiv für den aktuellen Thread.
    /// Standard: false (Sicherheit aktiv).
    static SIGNATURE_BYPASS_ACTIVE: Cell<bool> = Cell::new(false);
}

// 3. PUBLIC API (Nur verfügbar mit feature="test-utils")

/// Aktiviert (true) oder deaktiviert (false) die Signaturprüfung für den aktuellen Thread.
/// Nutze dies NUR in Integration-Tests.
#[cfg(feature = "test-utils")]
pub fn set_signature_bypass(bypass: bool) {
    SIGNATURE_BYPASS_ACTIVE.with(|f| f.set(bypass));
}

/// Prüft, ob der Bypass für den aktuellen Thread aktiv ist.
#[cfg(feature = "test-utils")]
pub fn is_signature_bypass_active() -> bool {
    SIGNATURE_BYPASS_ACTIVE.with(|f| f.get())
}

// Macht das Test-Modul für alle Tests (intern und extern) verfügbar.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
