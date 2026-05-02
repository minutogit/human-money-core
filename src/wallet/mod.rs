//! # src/wallet/mod.rs
//!
//! Definiert die `Wallet`-Fassade, die zentrale Verwaltungsstruktur für ein
//! Nutzerprofil. Sie kapselt den In-Memory-Zustand (`UserProfile`, `VoucherStore`)
//! und orchestriert die Interaktionen mit einem `Storage`-Backend und den
//! kryptographischen Operationen der `UserIdentity`.

// Deklariert das `instance`-Modul als öffentlichen Teil des `wallet`-Moduls.
pub mod instance;
// Deklariere die anderen Dateien als Teil dieses Moduls
mod conflict_handler;
mod queries;
mod signature_handler;
// NEU: Modul-Deklarationen für das Refactoring
mod lifecycle;
mod maintenance;
mod transaction_handler;
pub mod types;

// in src/wallet/mod.rs
// ...
#[cfg(test)]
mod tests;
#[cfg(test)]
mod reputation_tests;

// NEU: Exportiere alle öffentlichen Typen aus dem types-Modul
pub use types::*;

/// Hilfsfunktion zur Formatierung von Namen für die Benutzeroberfläche (BFF-Pattern).
/// Stellt sicher, dass Testgutscheine ein einheitliches "TEST-" Präfix erhalten.
pub(crate) fn format_bff_name(raw_name: &str, is_test: bool) -> String {
    if is_test && !raw_name.starts_with("TEST-") {
        format!("TEST-{}", raw_name)
    } else {
        raw_name.to_string()
    }
}

use crate::models::conflict::{
    CanonicalMetadataStore, KnownFingerprints, OwnFingerprints, ProofStore,
};
use crate::models::profile::{BundleMetadataStore, UserProfile, VoucherStore};

// ALLE STRUCT-DEFINITIONEN WURDEN NACH src/wallet/types.rs VERSCHOBEN.

/// Die zentrale Verwaltungsstruktur für ein Nutzer-Wallet.
/// Hält den In-Memory-Zustand und interagiert mit dem Speichersystem.
#[derive(Clone)]
pub struct Wallet {
    /// Die öffentlichen Profildaten und die Transaktionshistorie.
    pub profile: UserProfile,
    /// Der Bestand an Gutscheinen des Nutzers.
    pub voucher_store: VoucherStore,
    /// Die Historie der Transaktions-Metadaten.
    pub bundle_meta_store: BundleMetadataStore,
    /// Der Speicher für alle bekannten (eigenen und fremden) Transaktions-Fingerprints.
    pub known_fingerprints: KnownFingerprints,
    /// Die kritische, persistente Historie der eigenen **gesendeten** Transaktionen.
    pub own_fingerprints: OwnFingerprints,
    /// Der Speicher für kryptographisch bewiesene Double-Spend-Konflikte.
    pub proof_store: ProofStore,
    /// Zentraler, kanonischer Speicher für dynamische Metadaten.
    /// Enthält Metadaten für ALLE Fingerprints in den anderen Stores.
    pub fingerprint_metadata: CanonicalMetadataStore,
    /// Eindeutige ID des lokalen Geräts für Clone Protection.
    pub local_instance_id: String,
    /// Im RAM gehaltene Events, die noch nicht persistent auf die Festplatte
    /// geflusht wurden. Wird bei `Wallet::save` atomar gespeichert und geleert.
    pub pending_events: Vec<crate::models::wallet_event::WalletEvent>,
}

impl Wallet {
    // METHODEN FÜR lifecycle.rs WURDEN VERSCHOBEN
    // - new_from_mnemonic
    // - load
    // - save
    // - reset_password
    // - create_new_voucher

    // METHODEN FÜR transaction_handler.rs WURDEN VERSCHOBEN
    // - create_and_encrypt_transaction_bundle
    // - process_encrypted_transaction_bundle
    // - _execute_single_transfer
    // - execute_multi_transfer_and_bundle
}
