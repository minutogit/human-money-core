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
// in src/wallet/mod.rs
// ...
#[cfg(test)]
mod tests;

use crate::wallet::instance::{ValidationFailureReason, VoucherInstance, VoucherStatus};
use crate::archive::VoucherArchive;
use crate::error::{ValidationError, VoucherCoreError};
use crate::models::conflict::{
    CanonicalMetadataStore, FingerprintMetadata, KnownFingerprints, OwnFingerprints, ProofStore,
    TransactionFingerprint,
};
use crate::models::profile::{
    BundleMetadataStore, TransactionBundleHeader, TransactionDirection, UserIdentity, UserProfile, VoucherStore,
};
use crate::models::secure_container::{PayloadType, SecureContainer};
use crate::models::voucher::{Transaction, Voucher};
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::crypto_utils::{
    create_user_id, get_hash, get_pubkey_from_user_id, verify_ed25519,
};
use crate::services::utils::to_canonical_json;
use crate::services::{bundle_processor, conflict_manager, voucher_manager, voucher_validation};
use crate::storage::{AuthMethod, Storage, StorageError};
use chrono::{DateTime, Duration, Utc};
use crate::services::voucher_manager::NewVoucherData;
use ed25519_dalek::Signature;
use rust_decimal::Decimal; // NEU: Hinzufügen für Dezimal-Arithmetik
use std::str::FromStr; // NEU: Hinzufügen für `Decimal::from_str`
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Beschreibt einen Teil-Transfer von einem spezifischen Quell-Gutschein.
/// Wird verwendet, um die Quellen (lokale ID und Betrag) für einen Multi-Transfer zu definieren.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceTransfer {
    /// Die lokale ID des Gutscheins, von dem ein Betrag abgezogen werden soll.
    pub local_instance_id: String,
    /// Der Betrag, der von diesem Gutschein abgezogen werden soll, als String.
    pub amount_to_send: String,
}

/// Die aggregierte Anforderung für den universellen Transfer-Befehl.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiTransferRequest {
    /// Die User-ID des Empfängers.
    pub recipient_id: String,
    /// Eine Liste von Quell-Gutscheinen und den jeweils zu sendenden Beträgen (1 bis N).
    pub sources: Vec<SourceTransfer>,
    /// Optionale Notizen für das Bundle.
    pub notes: Option<String>,
    /// Optionaler Profilname des Senders.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_profile_name: Option<String>,
}

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
}

/// Fasst die Ergebnisse eines Transfers pro Standard zusammen.
/// Key: Währungseinheit (z.B. "Minuto"), Value: Summe als String (teilbar) oder Anzahl (nicht-teilbar).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct TransferSummary {
    /// Aufsummierte Beträge für teilbare/summierbare Gutscheine (z.B. "10.50 Minuto").
    /// Key: Währungseinheit (z.B. "Minuto"), Value: Summe als String.
    #[serde(default)]
    pub summable_amounts: HashMap<String, String>,
    /// Gezählte Einheiten für nicht-teilbare/nicht-summierbare Gutscheine (z.B. "3 Brote").
    /// Key: Währungseinheit (z.B. "Brot"), Value: Anzahl.
    #[serde(default)]
    pub countable_items: HashMap<String, u32>,
}

/// Das Ergebnis der Verarbeitung eines eingehenden Transaktionsbündels.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ProcessBundleResult {
    pub header: TransactionBundleHeader,
    pub check_result: DoubleSpendCheckResult,
    /// Detaillierte Zusammenfassung der transferierten Werte (Summen und Zähler).
    #[serde(default)]
    pub transfer_summary: TransferSummary,
    /// Liste der lokalen IDs der Gutscheine, die im Wallet des Empfängers
    /// durch diesen Transfer erstellt oder aktualisiert wurden.
    #[serde(default)]
    pub involved_vouchers: Vec<String>,
}

/// Das Ergebnis einer Double-Spend-Prüfung.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct DoubleSpendCheckResult {
    pub verifiable_conflicts: HashMap<String, Vec<crate::models::conflict::TransactionFingerprint>>,
    pub unverifiable_warnings: HashMap<String, Vec<crate::models::conflict::TransactionFingerprint>>,
}

/// Ein Bericht, der die Ergebnisse der Speicherbereinigung zusammenfasst.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CleanupReport {
    pub expired_fingerprints_removed: u32,
    pub limit_based_fingerprints_removed: u32,
}

/// Repräsentiert ein aggregiertes Guthaben für einen bestimmten Gutschein-Standard und eine Währungseinheit.
/// Wird verwendet, um eine zusammenfassende Dashboard-Ansicht der Guthaben zu erstellen. use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct AggregatedBalance {
    /// Der Name des Gutschein-Standards (z.B. "Minuto-Gutschein").
    pub standard_name: String,
    /// Die eindeutige UUID des Gutschein-Standards.
    pub standard_uuid: String,
    /// Die Währungseinheit des Guthabens (z.B. "Min", "€").
    pub unit: String,
    /// Der als String formatierte Gesamtbetrag.
    pub total_amount: String,
}

/// Eine zusammenfassende Ansicht eines Gutscheins für Listen-Darstellungen.
///
/// Diese Struktur wird von der Funktion `AppService::get_voucher_summaries`
/// zurückgegeben und dient dazu, eine übersichtliche Darstellung der
/// Gutschein-Daten zu liefern, ohne das gesamte, komplexe `Voucher`-Objekt
/// übertragen zu müssen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoucherSummary {
    /// Die eindeutige, lokale ID der Gutschein-Instanz im Wallet.
    pub local_instance_id: String,
    /// Der aktuelle Status des Gutscheins (z.B. `Active`, `Archived`).
    pub status: VoucherStatus,
    /// Die eindeutige ID des Erstellers (oft ein Public Key).
    pub creator_id: String,
    /// Das Gültigkeitsdatum des Gutscheins im ISO 8601-Format.
    pub valid_until: String,
    /// Eine allgemeine, menschenlesbare Beschreibung des Gutscheins.
    pub description: String,
    /// Der aktuelle, verfügbare Betrag des Gutscheins als String.
    pub current_amount: String,
    /// Die Einheit des Gutscheinwerts (z.B. "m" für Minuten).
    pub unit: String,
    /// Der Name des Standards, zu dem dieser Gutschein gehört (z.B. "Minuto-Gutschein").
    pub voucher_standard_name: String,
    /// Die eindeutige Kennung (UUID) des Standards, zu dem dieser Gutschein gehört.
    pub voucher_standard_uuid: String,
    /// Die Anzahl der Transaktionen, exklusive der initialen `init`-Transaktion.
    pub transaction_count: u32,
    /// Die Anzahl der vorhandenen Bürgen-Signaturen.
    pub guarantor_signatures_count: u32,
    /// Die Anzahl der vorhandenen zusätzlichen, optionalen Signaturen.
    pub additional_signatures_count: u32,
    /// Ein Flag, das anzeigt, ob der Gutschein besichert ist.
    pub has_collateral: bool,
    /// Der Vorname des ursprünglichen Erstellers.
    pub creator_first_name: String,
    /// Der Nachname des ursprünglichen Erstellers.
    pub creator_last_name: String,
    pub creator_coordinates: String,
    /// Eine Markierung, ob es sich um einen nicht einlösbaren Testgutschein handelt.
    pub non_redeemable_test_voucher: bool,
}

/// Eine zusammenfassende Ansicht eines Double-Spend-Beweises für Listen-Darstellungen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfDoubleSpendSummary {
    pub proof_id: String,
    pub offender_id: String,
    pub fork_point_prev_hash: String,
    pub report_timestamp: String,
    pub is_resolved: bool,
    pub has_l2_verdict: bool,
}

/// Eine detaillierte Ansicht eines Gutscheins inklusive seiner Transaktionshistorie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoucherDetails {
    pub local_instance_id: String,
    /// Der aktuelle Status des Gutscheins (z.B. `Active`, `Archived`).
    pub status: VoucherStatus,
    pub voucher: Voucher,
}

impl Wallet {
    /// Erstellt ein brandneues, leeres Wallet aus einer Mnemonic-Phrase.
    pub fn new_from_mnemonic(
        mnemonic_phrase: &str,
        passphrase: Option<&str>,
        user_prefix: Option<&str>,
    ) -> Result<(Self, UserIdentity), VoucherCoreError> {
        let (public_key, signing_key) = crate::services::crypto_utils::derive_ed25519_keypair(mnemonic_phrase, passphrase)?;

        let user_id = create_user_id(&public_key, user_prefix)
            .map_err(|e| VoucherCoreError::Crypto(e.to_string()))?;

        let identity = UserIdentity {
            signing_key,
            public_key,
            user_id: user_id.clone(),
        };

        let profile = UserProfile { user_id };

        let voucher_store = VoucherStore::default();
        let bundle_meta_store = BundleMetadataStore::default();
        let known_fingerprints = KnownFingerprints::default();
        let own_fingerprints = OwnFingerprints::default();
        let proof_store = ProofStore::default();
        let fingerprint_metadata = CanonicalMetadataStore::default();

        let wallet = Wallet {
            profile,
            voucher_store,
            bundle_meta_store,
            known_fingerprints,
            own_fingerprints,
            proof_store,
            fingerprint_metadata,
        };

        Ok((wallet, identity))
    }

    /// Lädt ein existierendes Wallet aus einem `Storage`-Backend.
    /// Gibt das Wallet und die entschlüsselte UserIdentity zurück.
    pub fn load<S: Storage>(
        storage: &S,
        auth: &AuthMethod,
    ) -> Result<(Self, UserIdentity), VoucherCoreError> {
        let (profile, voucher_store, identity) = storage.load_wallet(auth)?;

        if let AuthMethod::Mnemonic(..) = auth {
            println!("[Debug Wallet::load] Recovery successful! Decrypted identity with Mnemonic. User ID: {}", identity.user_id);
        }

        let bundle_meta_store = storage.load_bundle_metadata(&identity.user_id, auth)?;
        let known_fingerprints = storage.load_known_fingerprints(&identity.user_id, auth)?;
        let own_fingerprints = storage.load_own_fingerprints(&identity.user_id, auth)?;
        let proof_store = storage.load_proofs(&identity.user_id, auth)?;
        let fingerprint_metadata = storage.load_fingerprint_metadata(&identity.user_id, auth)?;

        // Sicherheitsüberprüfung, um sicherzustellen, dass die entschlüsselte Identität
        // mit den Profildaten übereinstimmt.
        if profile.user_id != identity.user_id {
            return Err(StorageError::AuthenticationFailed.into());
        }

        let mut wallet = Wallet {
            profile,
            voucher_store,
            bundle_meta_store,
            known_fingerprints,
            own_fingerprints,
            proof_store,
            fingerprint_metadata,
        };

        wallet.rebuild_derived_stores()?;
        Ok((wallet, identity))
    }

    /// Speichert den aktuellen Zustand des Wallets in einem `Storage`-Backend.
    pub fn save<S: Storage>(
        &self,
        storage: &mut S,
        identity: &UserIdentity,
        password: &str,
    ) -> Result<(), StorageError> {
        storage.save_wallet(&self.profile, &self.voucher_store, identity, password)?;
        storage.save_bundle_metadata(&identity.user_id, password, &self.bundle_meta_store)?;
        storage.save_known_fingerprints(&identity.user_id, password, &self.known_fingerprints)?;
        storage.save_own_fingerprints(&identity.user_id, password, &self.own_fingerprints)?;
        storage.save_proofs(&identity.user_id, password, &self.proof_store)?;
        storage.save_fingerprint_metadata(&identity.user_id, password, &self.fingerprint_metadata)?;
        Ok(())
    }

    /// Setzt das Passwort für ein Wallet in einem `Storage`-Backend zurück.
    pub fn reset_password<S: Storage>(
        storage: &mut S,
        identity: &UserIdentity,
        new_password: &str,
    ) -> Result<(), StorageError> {
        storage.reset_password(identity, new_password)
    }

    /// Führt die Speicherbereinigung für Fingerprints und deren Metadaten durch.
    ///
    /// Diese Funktion implementiert eine Zwei-Phasen-Bereinigung, um die Gesamtanzahl
    /// der gespeicherten Fingerprints zu verwalten und die Systemleistung zu gewährleisten.
    ///
    /// **Phase 1: Ablage abgelaufener Einträge**
    /// Zuerst werden alle Fingerprints aus `own_fingerprints`, `known_fingerprints` und
    /// die zugehörigen Metadaten aus `fingerprint_metadata` entfernt, deren `valid_until`
    /// Datum in der Vergangenheit liegt. Dies ist die primäre Wartungsroutine.
    ///
    /// **Phase 2: Selektive, limitbasierte Bereinigung**
    /// Wenn nach Phase 1 die Gesamtzahl der Fingerprints immer noch ein hartes Limit
    /// (`MAX_FINGERPRINTS`) überschreitet, wird eine prozentuale Reduzierung
    /// (`CLEANUP_PERCENTAGE`) durchgeführt. Die zu löschenden Fingerprints werden
    /// nach folgender Heuristik ausgewählt:
    /// 1.  **Höchste `depth` zuerst:** Fingerprints, die am weitesten im Netzwerk
    ///     verbreitet sind (höchster `depth`), werden als am wenigsten kritisch angesehen.
    /// 2.  **Älteste `t_time` als Tie-Breaker:** Innerhalb einer `depth`-Ebene werden
    ///     die ältesten Transaktionen zuerst entfernt.
    ///
    /// # Arguments
    /// * `max_fingerprints_override` - Ein optionaler Wert, um die `MAX_FINGERPRINTS`-Konstante
    ///                                 speziell für Test-Szenarien zu überschreiben.
    /// # Returns
    /// Ein `CleanupReport`, der die Anzahl der in beiden Phasen entfernten Einträge zusammenfasst.
    pub fn run_storage_cleanup(&mut self, max_fingerprints_override: Option<usize>) -> Result<CleanupReport, VoucherCoreError> {
        const MAX_FINGERPRINTS_CONST: usize = 20_000;
        const CLEANUP_PERCENTAGE: f32 = 0.10;

        let mut report = CleanupReport::default();
        let now = Utc::now();

        // --- Phase 1: Löschen abgelaufener Einträge ---
        let mut expired_keys = std::collections::HashSet::new();

        // Sammle alle abgelaufenen Schlüssel aus allen relevanten Stores
        for fp in self.own_fingerprints.history.values().flatten()
            .chain(self.known_fingerprints.local_history.values().flatten())
            .chain(self.known_fingerprints.foreign_fingerprints.values().flatten()) {
            if let Ok(valid_until) = DateTime::parse_from_rfc3339(&fp.valid_until) {
                if valid_until.with_timezone(&Utc) < now {
                    expired_keys.insert(fp.prvhash_senderid_hash.clone());
                }
            }
        }

        if !expired_keys.is_empty() {
            report.expired_fingerprints_removed = expired_keys.len() as u32;

            // Entferne die abgelaufenen Einträge aus allen Stores
            self.own_fingerprints.history.retain(|k, _| !expired_keys.contains(k));
            self.known_fingerprints.local_history.retain(|k, _| !expired_keys.contains(k));
            self.known_fingerprints.foreign_fingerprints.retain(|k, _| !expired_keys.contains(k));
            self.fingerprint_metadata.retain(|k, _| !expired_keys.contains(k));
        }

        // --- Phase 2: Selektive Löschung nach Tiefe und Rezenz ---
        let current_total_count = self.own_fingerprints.history.len()
            + self.known_fingerprints.local_history.len()
            + self.known_fingerprints.foreign_fingerprints.len();

        let max_fingerprints = max_fingerprints_override.unwrap_or(MAX_FINGERPRINTS_CONST);
        if current_total_count > max_fingerprints {
            let target_removal_count = (current_total_count as f32 * CLEANUP_PERCENTAGE).ceil() as usize;

            // Sammle alle Fingerprints mit Metadaten zur Sortierung
            let mut candidates_for_removal = Vec::new();
            let all_fingerprints = self.own_fingerprints.history.values().flatten()
                .chain(self.known_fingerprints.local_history.values().flatten())
                .chain(self.known_fingerprints.foreign_fingerprints.values().flatten());

            for fp in all_fingerprints {
                if let Some(meta) = self.fingerprint_metadata.get(&fp.prvhash_senderid_hash) {
                    // Wir verwenden die `t_id` als deterministischen Tie-Breaker anstelle des
                    // nicht verfügbaren `t_time`, um eine ineffiziente Entschlüsselung zu vermeiden.
                    candidates_for_removal
                        .push((meta.depth, fp.t_id.clone(), fp.prvhash_senderid_hash.clone()));
                }
            }

            // Sortiere: Höchste 'depth' zuerst, dann älteste 't_time' zuerst
            candidates_for_removal.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));

            let keys_to_remove: std::collections::HashSet<String> = candidates_for_removal
                .into_iter()
                .take(target_removal_count)
                .map(|(_, _, key)| key)
                .collect();

            report.limit_based_fingerprints_removed = keys_to_remove.len() as u32;

            // Entferne die ausgewählten Einträge aus allen Stores
            self.own_fingerprints.history.retain(|k, _| !keys_to_remove.contains(k));
            self.known_fingerprints.local_history.retain(|k, _| !keys_to_remove.contains(k));
            self.known_fingerprints.foreign_fingerprints.retain(|k, _| !keys_to_remove.contains(k));
            self.fingerprint_metadata.retain(|k, _| !keys_to_remove.contains(k));
        }

        Ok(report)
    }

    /// Erstellt ein `TransactionBundle`, verpackt es und aktualisiert den Wallet-Zustand.
    /// Dies ist nun eine private Hilfsmethode.
    pub fn create_and_encrypt_transaction_bundle(
        &mut self,
        identity: &UserIdentity,
        vouchers: Vec<Voucher>,
        recipient_id: &str,
        notes: Option<String>,
        forwarded_fingerprints: Vec<TransactionFingerprint>,
        fingerprint_depths: HashMap<String, u8>,
        sender_profile_name: Option<String>,
    ) -> Result<(Vec<u8>, TransactionBundleHeader), VoucherCoreError> {
        // DEBUG: Log sender and recipient to trace the NotAnIntendedRecipient error.
        println!(
            "[Debug Wallet::create_and_encrypt] Sender: {}, Recipient: {}",
            identity.user_id, recipient_id
        );

        for v in &vouchers {
            let local_id = Self::calculate_local_instance_id(v, &identity.user_id)?;
            if let Some(instance) = self.voucher_store.vouchers.get(&local_id) {
                if matches!(instance.status, VoucherStatus::Quarantined { .. }) {
                    return Err(VoucherCoreError::VoucherInQuarantine);
                }
            }
        }

        let (container_bytes, bundle) = bundle_processor::create_and_encrypt_bundle(
            identity,
            vouchers.clone(),
            recipient_id,
            notes,
            forwarded_fingerprints,
            fingerprint_depths,
            sender_profile_name,
        )?;

        let header = bundle.to_header(TransactionDirection::Sent);
        self.bundle_meta_store
            .history
            .insert(header.bundle_id.clone(), header.clone());

        Ok((container_bytes, header))
    }

    /// Verarbeitet einen serialisierten `SecureContainer`, der ein `TransactionBundle` enthält.
    pub fn process_encrypted_transaction_bundle(
        &mut self,
        identity: &UserIdentity,
        container_bytes: &[u8],
        archive: Option<&dyn VoucherArchive>,
        standard_definitions: &HashMap<String, VoucherStandardDefinition>,
    ) -> Result<ProcessBundleResult, VoucherCoreError> {
        let bundle = bundle_processor::open_and_verify_bundle(identity, container_bytes)?;

        // Kopiere die Daten, bevor 'bundle' verschoben wird
        let forwarded_fingerprints = bundle.forwarded_fingerprints.clone();
        let fingerprint_depths = bundle.fingerprint_depths.clone();
        let received_vouchers = bundle.vouchers.clone();

        // Initialisiere die neuen Ergebnis-Strukturen
        let mut transfer_summary = TransferSummary::default();
        let mut involved_vouchers = Vec::new();

        // --- NEUES DEBUGGING: Zustand des Voucher Stores VOR der Verarbeitung ---
        println!("\n[Debug Wallet Process] === Zustand VOR Verarbeitung des Bundles ===");
        for (id, instance) in &self.voucher_store.vouchers {
            println!("[Debug Wallet Process]   -> Vorhanden: local_id={}, voucher_id={}, status={:?}, tx_count={}", id, instance.voucher.voucher_id, instance.status, instance.voucher.transactions.len());
        }
        println!("[Debug Wallet Process] ===============================================");

        for voucher in bundle.vouchers.clone() {
            // KORREKTUR: Die `retain`-Logik wurde entfernt. Sie war die Ursache für die
            // fehlgeschlagene Double-Spend-Erkennung, da sie eine der beiden
            // widersprüchlichen Gutschein-Instanzen fälschlicherweise gelöscht hat.
            let local_id = Self::calculate_local_instance_id(&voucher, &identity.user_id)?;
            // --- NEUES DEBUGGING: Detaillierte Prüfung für jeden eingehenden Gutschein ---
            if let Some(existing_instance) = self.voucher_store.vouchers.values().find(|v| v.voucher.voucher_id == voucher.voucher_id) {
                println!("[Debug Wallet Process] >>> ACHTUNG: Instanz für voucher_id '{}' existiert bereits.", voucher.voucher_id);
                println!("[Debug Wallet Process]     Alte tx_count: {}, Neue tx_count: {}", existing_instance.voucher.transactions.len(), voucher.transactions.len());
            }
            println!("[Debug Wallet Process] Füge Instanz hinzu: local_id={}, voucher_id={}, tx_count={}", local_id, voucher.voucher_id, voucher.transactions.len());
            self.add_voucher_instance(local_id.clone(), voucher.clone(), VoucherStatus::Active);

            // --- NEU: TransferSummary-Logik ---
            // 1. Sammle die lokale ID
            involved_vouchers.push(local_id.clone());

            // 2. Finde den relevanten Standard
            let standard_uuid = &voucher.voucher_standard.uuid;
            let standard = standard_definitions.get(standard_uuid).ok_or_else(|| {
                VoucherCoreError::Generic(format!(
                    "Standard definition not found for UUID: {}",
                    standard_uuid
                ))
            })?;

            // 3. Finde die letzte Transaktion, um den erhaltenen Betrag zu ermitteln
            let last_tx = voucher.transactions.last().ok_or_else(|| {
                VoucherCoreError::Generic("Received voucher has no transactions.".to_string())
            })?;

            // 4. Bestimme die Einheit
            let unit = voucher.nominal_value.unit.clone();

            // 5. Akkumuliere den Wert, basierend auf 'is_summable'
            if standard.template.fixed.is_summable {
                let current_sum = transfer_summary
                    .summable_amounts
                    .entry(unit)
                    .or_insert_with(|| "0.0".to_string());

                // Verwende decimal_utils, um Strings sicher zu addieren
                // KORREKTUR: Verwende rust_decimal::Decimal für die Addition
                let val1 = Decimal::from_str(current_sum)
                    .map_err(|e| VoucherCoreError::Generic(format!("Invalid decimal amount in summary: {}", e)))?;
                let val2 = Decimal::from_str(&last_tx.amount)
                    .map_err(|e| VoucherCoreError::Generic(format!("Invalid decimal amount in transaction: {}", e)))?;
                
                *current_sum = (val1 + val2).to_string();
            } else {
                let count = transfer_summary
                    .countable_items
                    .entry(unit)
                    .or_insert(0);
                *count += 1;
            }
            // --- Ende TransferSummary-Logik ---
        }

        // Die 'bundle'-Variable ist hier noch verfügbar, da `bundle.vouchers.clone()`
        // verwendet wurde. Erstelle den Header (der `sender_profile_name` enthält,
        // da `to_header` in Patch 1 angepasst wurde).
        let header = bundle.to_header(TransactionDirection::Received);
        self.bundle_meta_store
            .history
            .insert(header.bundle_id.clone(), header.clone());

        // NEU: Verarbeite alle empfangenen Fingerprints (aktiv und implizit)
        self.process_received_fingerprints(
            &header,
            &received_vouchers,
            &forwarded_fingerprints,
            &fingerprint_depths)?;

        // --- NEUES DEBUGGING: Zustand des Voucher Stores NACH der Verarbeitung ---
        println!("[Debug Wallet Process] === Zustand NACH Verarbeitung des Bundles ===");
        for (id, instance) in &self.voucher_store.vouchers {
            println!("[Debug Wallet Process]   -> Vorhanden: local_id={}, voucher_id={}, status={:?}, tx_count={}", id, instance.voucher.voucher_id, instance.status, instance.voucher.transactions.len());
        }
        println!("[Debug Wallet Process] ===============================================");

        // Die Fingerprint-Stores werden bei jeder Änderung neu aus dem VoucherStore aufgebaut.
        let (own, known) = conflict_manager::scan_and_rebuild_fingerprints(&self.voucher_store, &identity.user_id)?;
        self.own_fingerprints = own;
        self.known_fingerprints = known;

        // Wenn eine Signatur empfangen wird, muss der Status des Gutscheins aktualisiert werden
        if let Ok(deserialized_container) = serde_json::from_slice::<SecureContainer>(container_bytes)
        {
            if matches!(
                deserialized_container.c,
                PayloadType::DetachedSignature
            ) {
                self.process_and_attach_signature(identity, container_bytes)?;
                return Ok(ProcessBundleResult::default());
            }
        }

        let check_result = conflict_manager::check_for_double_spend(
            &self.own_fingerprints,
            &self.known_fingerprints,
        );

        for (_conflict_hash, fingerprints) in &check_result.verifiable_conflicts {
            if let Some(archive_backend) = archive {
                // Die Logik zum Verifizieren und Erstellen von Beweisen ist nun hier im Wallet.
                let verified_proof = self.verify_and_create_proof(identity, fingerprints, archive_backend)?;

                if let Some(proof) = verified_proof {
                    // Der Beweis wurde erfolgreich erstellt und kann nun verwendet werden.
                    if let Some(verdict) = &proof.layer2_verdict {
                        // Logik zur Verarbeitung eines L2-Urteils
                        for tx in &proof.conflicting_transactions {
                            let instance_id_opt = self.find_local_voucher_by_tx_id(&tx.t_id).map(|i| i.local_instance_id.clone());
                            if let Some(instance_id) = instance_id_opt {
                                if let Some(instance_mut) = self.voucher_store.vouchers.get_mut(&instance_id) {
                                    instance_mut.status = if tx.t_id == verdict.valid_transaction_id {
                                        VoucherStatus::Active
                                    } else {
                                        VoucherStatus::Quarantined {
                                            reason: "L2 verdict".to_string(),
                                        }
                                    };
                                }
                            }
                        }
                    } else {
                        // Offline-Konfliktlösung, wenn kein L2-Urteil vorliegt
                        resolve_conflict_offline(&mut self.voucher_store, fingerprints);
                    }
                    // WICHTIG: Den erstellten Beweis persistent speichern.
                    self.proof_store.proofs.insert(proof.proof_id.clone(), proof);
                }
            } else {
                // KORREKTUR: Dieser `else`-Block fehlte. Er stellt sicher, dass die Offline-Logik auch
                // dann greift, wenn kein Layer-2-Backend (`archive`) konfiguriert ist.
                resolve_conflict_offline(&mut self.voucher_store, fingerprints);
            }
        }

        Ok(ProcessBundleResult {
            header,
            check_result,
            transfer_summary,
            involved_vouchers,
        })
    }

    /// Verifiziert einen Konflikt und erstellt einen Beweis. Interne Methode.
    fn verify_and_create_proof(
        &self,
        identity: &UserIdentity,
        fingerprints: &[TransactionFingerprint],
        archive: &dyn VoucherArchive,
    ) -> Result<Option<crate::models::conflict::ProofOfDoubleSpend>, VoucherCoreError> {
        let mut conflicting_transactions = Vec::new();

        // 1. Finde die vollständigen Transaktionen zu den Fingerprints.
        for fp in fingerprints {
            if let Some(tx) = self.find_transaction_in_stores(&fp.t_id, archive)? {
                conflicting_transactions.push(tx);
            }
        }

        if conflicting_transactions.len() < 2 {
            return Ok(None);
        }

        // 2. Extrahiere Kerndaten und verifiziere Signaturen.
        let offender_id = conflicting_transactions[0].sender_id.clone();
        let fork_point_prev_hash = conflicting_transactions[0].prev_hash.clone();
        let offender_pubkey = get_pubkey_from_user_id(&offender_id)?;

        let mut verified_tx_count = 0;
        for tx in &conflicting_transactions {
            if tx.sender_id != offender_id || tx.prev_hash != fork_point_prev_hash {
                return Ok(None);
            }

            let signature_payload = serde_json::json!({
                "prev_hash": &tx.prev_hash, "sender_id": &tx.sender_id, "t_id": &tx.t_id
            });
            let signature_payload_hash = get_hash(to_canonical_json(&signature_payload)?);
            let signature_bytes = bs58::decode(&tx.sender_signature).into_vec()?;
            let signature = Signature::from_slice(&signature_bytes)?;

            if verify_ed25519(&offender_pubkey, signature_payload_hash.as_bytes(), &signature) {
                verified_tx_count += 1;
            }
        }

        // 3. Wenn mindestens zwei Signaturen gültig sind, ist der Betrug bewiesen.
        if verified_tx_count < 2 {
            return Ok(None);
        }

        let voucher = self.find_voucher_for_transaction(&conflicting_transactions[0].t_id, archive)?
            .ok_or_else(|| VoucherCoreError::VoucherNotFound("for proof creation".to_string()))?;
        let voucher_valid_until = voucher.valid_until.clone();

        // 4. Rufe den Service auf, um das Beweis-Objekt zu erstellen.
        let proof = conflict_manager::create_proof_of_double_spend(
            offender_id,
            fork_point_prev_hash,
            conflicting_transactions,
            voucher_valid_until,
            identity,
        )?;

        Ok(Some(proof))
    }

    pub fn add_voucher_instance(
        &mut self,
        local_id: String,
        voucher: Voucher,
        status: VoucherStatus,
    ) {
        let instance = VoucherInstance {
            voucher,
            status,
            local_instance_id: local_id.clone(),
        };
        self.voucher_store
            .vouchers
            .insert(local_id, instance);
    }

    pub fn get_voucher_instance(&self, local_instance_id: &str) -> Option<&VoucherInstance> {
        self.voucher_store.vouchers.get(local_instance_id)
    }

    pub fn update_voucher_status(&mut self, local_instance_id: &str, new_status: VoucherStatus) {
        if let Some(instance) = self.voucher_store.vouchers.get_mut(local_instance_id) {
            instance.status = new_status;
        }
    }

    /// Berechnet eine deterministische, lokale ID für eine Gutschein-Instanz.
    pub fn calculate_local_instance_id(
        voucher: &Voucher,
        profile_owner_id: &str,
    ) -> Result<String, VoucherCoreError> {
        let mut defining_transaction_id: Option<String> = None;

        // Die definierende Transaktion ist einfach die letzte, in der der Benutzer
        // als Sender oder Empfänger auftaucht.
        for tx in voucher.transactions.iter().rev() {
            if tx.recipient_id == profile_owner_id || tx.sender_id == profile_owner_id {
                defining_transaction_id = Some(tx.t_id.clone());
                break;
            }
        }

        if let Some(t_id) = defining_transaction_id {
            Ok(get_hash(format!(
                "{}{}{}",
                voucher.voucher_id, t_id, profile_owner_id
            )))
        } else {
            Err(VoucherCoreError::VoucherOwnershipNotFound(format!(
                "User '{}' has no ownership history for voucher '{}'",
                profile_owner_id, voucher.voucher_id
            )))
        }
    }

    /// Führt die Zustandsveränderung für EINEN Gutschein im Wallet durch.
    ///
    /// Diese Funktion ist die Core-Logik des Transfers. Sie führt KEIN Bundling durch.
    fn _execute_single_transfer(
        &mut self,
        identity: &UserIdentity,
        standard_definition: &VoucherStandardDefinition,
        local_instance_id: &str,
        recipient_id: &str,
        amount_to_send: &str,
        archive: Option<&dyn VoucherArchive>,
    ) -> Result<Voucher, VoucherCoreError> {
        let instance = self
            .voucher_store
            .vouchers
            .get(local_instance_id)
            .ok_or_else(|| VoucherCoreError::VoucherNotFound(
                local_instance_id.to_string(),
            ))?;
        if !matches!(instance.status, VoucherStatus::Active) {
            return Err(VoucherCoreError::VoucherNotActive(instance.status.clone()));
        }
        let voucher_to_spend = instance.voucher.clone();

        let last_tx = voucher_to_spend
            .transactions
            .last()
            .ok_or_else(|| {
                VoucherCoreError::Generic("Cannot spend voucher with no transactions.".to_string())
            })?;
        let prev_hash = get_hash(to_canonical_json(last_tx)?);

        // PRÜFUNG GEGEN ALLE BEKANNTEN FINGERPRINTS:
        // Wir prüfen sowohl gegen die aktuell aktiven als auch gegen die gesamte
        // bekannte Historie, um einen Double Spend sicher auszuschließen.
        let new_fingerprint_hash = get_hash(format!("{}{}", prev_hash, identity.user_id));
        if self.own_fingerprints.active_fingerprints.contains_key(&new_fingerprint_hash)
            || self.own_fingerprints.history.contains_key(&new_fingerprint_hash) {
            return Err(VoucherCoreError::DoubleSpendAttemptBlocked);
        }

        let new_voucher_state = voucher_manager::create_transaction(
            &voucher_to_spend,
            standard_definition,
            &identity.user_id,
            &identity.signing_key,
            recipient_id,
            amount_to_send,
        )?;

        // KORREKTE LOGIK ZUR ZUSTANDSVERWALTUNG:
        // 1. Entferne die alte Instanz, die gerade ausgegeben wurde.
        self.voucher_store.vouchers.remove(local_instance_id);

        // 2. Bestimme den Status des neuen Gutschein-Zustands für den Sender.
        if let Some(last_tx) = new_voucher_state.transactions.last() {
            let (new_status, owner_id) =
                if last_tx.sender_id == identity.user_id && last_tx.sender_remaining_amount.is_some() {
                    // Es ist ein Split, der Sender behält einen aktiven Restbetrag.
                    (VoucherStatus::Active, &identity.user_id)
                } else {
                    // Es ist ein voller Transfer, die Kopie des Senders wird archiviert.
                    (VoucherStatus::Archived, &identity.user_id)
                };

            // 3. Ein neuer Zustand bekommt IMMER eine neue lokale ID.
            let new_local_id = Self::calculate_local_instance_id(&new_voucher_state, owner_id)?;

            // 4. Füge die neue Instanz mit der NEUEN ID und dem korrekten Status hinzu.
            self.add_voucher_instance(
                new_local_id,
                new_voucher_state.clone(),
                new_status,
            );
        }

        if let Some(archive_backend) = archive {
            archive_backend.archive_voucher(&new_voucher_state, &identity.user_id, standard_definition)?;
        }

        // Fingerprint-Erstellung und Speicherung im *historischen* Store
        let created_tx = new_voucher_state.transactions.last().unwrap();
        let fingerprint =
            conflict_manager::create_fingerprint_for_transaction(created_tx, &new_voucher_state)?;

        let history_entry = self.own_fingerprints
            .history
            .entry(fingerprint.prvhash_senderid_hash.clone())
            .or_default();
        if !history_entry.contains(&fingerprint) {
            history_entry.push(fingerprint.clone());
        }

        // WICHTIG: KEIN BUNDLE, NUR DER MUTIERTE VOUCHER WIRD ZURÜCKGEGEBEN
        Ok(new_voucher_state)
    }

    /// Führt eine 1-zu-N-Transaktion durch (Multi-Transfer) und erstellt ein einziges Bundle.
    pub fn execute_multi_transfer_and_bundle(
        &mut self,
        identity: &UserIdentity,
        standard_definitions: &HashMap<String, VoucherStandardDefinition>,
        request: MultiTransferRequest,
        archive: Option<&dyn VoucherArchive>,
    ) -> Result<(Vec<u8>, TransactionBundleHeader), VoucherCoreError> {
        // TRANSANKTIONALER ANSATZ:
        // 1. Erstelle eine temporäre Kopie des Wallets. Alle Änderungen werden
        //    zuerst auf dieser Kopie durchgeführt.
        let mut temp_wallet = self.clone();
        let mut vouchers_for_bundle: Vec<Voucher> = Vec::new();

        // 2. **Orchestrierung:** Führe `_execute_single_transfer` für jede Quelle auf der Kopie aus.
        for source in request.sources {
            let instance = temp_wallet
                .voucher_store
                .vouchers
                .get(&source.local_instance_id)
                .ok_or_else(|| VoucherCoreError::VoucherNotFound(source.local_instance_id.clone()))?;

            let standard_uuid = instance.voucher.voucher_standard.uuid.clone();
            let standard_definition = standard_definitions
                .get(&standard_uuid)
                .ok_or_else(|| VoucherCoreError::Generic(format!("Standard with UUID '{}' not found in provided definitions.", standard_uuid)))?;

            // Führe die Kernoperation auf der temporären Wallet-Instanz aus.
            let new_voucher = temp_wallet._execute_single_transfer(
                identity,
                standard_definition,
                &source.local_instance_id,
                &request.recipient_id,
                &source.amount_to_send,
                archive,
            )?;

            vouchers_for_bundle.push(new_voucher);
        }

        // 3. **Bündelung:** Erstelle ein einziges SecureContainer-Bundle.
        let (fingerprints_to_send, depths_to_send) = temp_wallet.select_fingerprints_for_bundle(
            &request.recipient_id,
            &vouchers_for_bundle,
        )?;

        let (container_bytes, header) = temp_wallet.create_and_encrypt_transaction_bundle(
            identity,
            vouchers_for_bundle,
            &request.recipient_id,
            request.notes,
            // NEU: Zusätzliche Argumente
            fingerprints_to_send,
            depths_to_send,
            request.sender_profile_name,
        )?;

        // 4. **Commit:** Wenn alle Operationen erfolgreich waren, ersetze den
        //    ursprünglichen Wallet-Zustand durch den der temporären Instanz.
        *self = temp_wallet;

        Ok((container_bytes, header))
    }

    /// Erstellt einen brandneuen Gutschein und fügt ihn direkt zum Wallet hinzu.
    ///
    /// Diese Methode orchestriert die Erstellung eines neuen Gutscheins basierend auf
    /// einem Standard, signiert ihn mit der Identität des Erstellers und speichert
    /// ihn sofort im `VoucherStore` mit dem Status `Active`.
    ///
    /// # Arguments
    /// * `identity` - Die Identität des Erstellers, enthält den Signierschlüssel.
    /// * `standard_definition` - Die Regeln und Vorlagen des Gutschein-Standards.
    /// * `data` - Die spezifischen Daten für den neuen Gutschein (z.B. Betrag).
    ///
    /// # Returns
    /// Ein `Result` mit dem vollständig erstellten `Voucher` bei Erfolg.
    pub fn create_new_voucher(
        &mut self,
        identity: &UserIdentity,
        // Die Signatur wird erweitert, um die verifizierten Daten zu erhalten
        verified_standard: &VoucherStandardDefinition,
        standard_hash: &str,
        lang_preference: &str,
        data: NewVoucherData,
    ) -> Result<Voucher, VoucherCoreError> {
        let new_voucher = voucher_manager::create_voucher(
            data,
            verified_standard,
            standard_hash,
            &identity.signing_key,
            lang_preference,
        )?;

        // KORREKTE LOGIK ZUR ZUSTANDSVERWALTUNG:
        // 1. Berechne die korrekte lokale ID basierend auf der `init`-Transaktion.
        let local_id = Self::calculate_local_instance_id(&new_voucher, &identity.user_id)?;

        // 2. Bestimme den initialen Status durch eine sofortige Validierung.
        let initial_status = match voucher_validation::validate_voucher_against_standard(&new_voucher, verified_standard) {
            Ok(_) => VoucherStatus::Active,
            // Wenn Bürgen fehlen, ist der Status `Incomplete`.
            Err(VoucherCoreError::Validation(ValidationError::CountOutOfBounds { field, min, max, found })) if field == "guarantor_signatures" => {
                VoucherStatus::Incomplete {
                    reasons: vec![ValidationFailureReason::GuarantorCountLow {
                        required: min,
                        max: max,
                        current: found as u32,
                    }],
                }
            },
            // Jeder andere Validierungsfehler bei der Erstellung ist ein fataler Fehler.
            Err(e) => return Err(e),
        };

        // 3. Füge die Instanz mit der korrekten ID und dem korrekten Status hinzu.
        self.add_voucher_instance(local_id, new_voucher.clone(), initial_status);

        // 4. WICHTIG: Baue die abgeleiteten Stores (Fingerprints, Metadaten) neu auf.
        self.rebuild_derived_stores()?;

        Ok(new_voucher)
    }

    /// Führt Wartungsarbeiten am Wallet-Speicher durch, um veraltete Daten zu entfernen.
    pub fn cleanup_storage(&mut self, archive_grace_period_years: i64) {
        // Schritt 1: Bereinige flüchtige Speicher sofort (ohne Frist).
        conflict_manager::cleanup_known_fingerprints(&mut self.known_fingerprints);

        let now = Utc::now();
        let grace_period = Duration::days(archive_grace_period_years * 365);

        // Schritt 2: Bereinige die persistente History mit der längeren Frist.
        conflict_manager::cleanup_expired_histories(&mut self.own_fingerprints, &mut self.known_fingerprints, &now, &grace_period);

        // Schritt 3: Bereinige Gutschein-Instanzen im Archiv mit derselben Frist.
        self.voucher_store
            .vouchers
            .retain(|_, instance| {
                if !matches!(instance.status, VoucherStatus::Archived) {
                    return true;
                }
                if let Ok(valid_until) = DateTime::parse_from_rfc3339(&instance.voucher.valid_until) {
                    let purge_date = valid_until.with_timezone(&Utc) + grace_period;
                    return now < purge_date;
                }
                true
            });

        // Schritt 4: Bereinige alte Double-Spend-Beweise mit derselben Frist.
        self.proof_store.proofs.retain(|_, proof| {
            if let Ok(valid_until) = DateTime::parse_from_rfc3339(&proof.voucher_valid_until) {
                let purge_date = valid_until.with_timezone(&Utc) + grace_period;
                return now < purge_date;
            }
            true
        });
    }

    /// Sucht eine Transaktion anhand ihrer ID (`t_id`) zuerst im aktiven
    /// `voucher_store` und dann im `VoucherArchive`.
    fn find_transaction_in_stores(
        &self,
        t_id: &str,
        archive: &dyn VoucherArchive,
    ) -> Result<Option<Transaction>, VoucherCoreError> {
        // Zuerst im aktiven Store suchen
        for instance in self.voucher_store.vouchers.values() {
            if let Some(tx) = instance.voucher.transactions.iter().find(|t| t.t_id == t_id) {
                return Ok(Some(tx.clone()));
            }
        }

        // Danach im Archiv suchen
        let result = archive.find_transaction_by_id(t_id)?;
        Ok(result.map(|(_, tx)| tx))
    }

    /// Sucht einen Gutschein anhand einer enthaltenen Transaktions-ID (`t_id`).
    /// Durchsucht zuerst den aktiven `voucher_store` und dann das `VoucherArchive`.
    fn find_voucher_for_transaction(
        &self,
        t_id: &str,
        archive: &dyn VoucherArchive,
    ) -> Result<Option<Voucher>, VoucherCoreError> {
        // Zuerst im aktiven Store suchen
        for instance in self.voucher_store.vouchers.values() {
            if instance.voucher.transactions.iter().any(|t| t.t_id == t_id) {
                return Ok(Some(instance.voucher.clone()));
            }
        }

        // Danach im Archiv suchen
        Ok(archive.find_voucher_by_tx_id(t_id)?)
    }

    /// Findet die lokale ID und den Status eines Gutscheins anhand einer enthaltenen Transaktions-ID.
    fn find_local_voucher_by_tx_id(&self, tx_id: &str) -> Option<&VoucherInstance> {
        self.voucher_store
            .vouchers
            .values()
            .find(|instance| instance.voucher.transactions.iter().any(|tx| tx.t_id == tx_id))
    }

    /// Wählt Fingerprints für die Weiterleitung in einem Bundle aus, basierend auf der Heuristik.
    ///
    /// # Logic
    /// 1. Markiert alle Fingerprints des zu sendenden Gutscheins als implizit bekannt für den Empfänger.
    /// 2. Iteriert von `depth = 0` aufwärts durch alle bekannten Fingerprints.
    /// 3. Wählt bis zu `MAX_FINGERPRINTS_TO_SEND` Kandidaten aus, die:
    ///    - die aktuelle `depth` haben.
    ///    - dem Empfänger noch nicht bekannt sind.
    /// 4. Aktualisiert die Metadaten (`known_by_peers`) für jeden ausgewählten Fingerprint.
    ///
    /// # Returns
    /// Ein Tupel aus (`Vec<TransactionFingerprint>`, `HashMap<String, u8>`) für das Bundle.
    pub fn select_fingerprints_for_bundle(
        &mut self,
        recipient_id: &str,
        vouchers_in_bundle: &[Voucher],
    ) -> Result<(Vec<TransactionFingerprint>, HashMap<String, u8>), VoucherCoreError> {
        const MAX_FINGERPRINTS_TO_SEND: usize = 150;
        
        // NEU: Verwende den speichereffizienten Kurz-Hash (gibt [u8; 4] zurück)
        let recipient_short_hash = crate::services::crypto_utils::get_short_hash_from_user_id(recipient_id);

        let mut selected_fingerprints = Vec::new();
        let mut selected_depths = HashMap::new();

        // Schritt 1: Implizit bekannte Fingerprints des aktuellen Transfers markieren
        for voucher in vouchers_in_bundle {
            for tx in &voucher.transactions {
                let fingerprint =
                    conflict_manager::create_fingerprint_for_transaction(tx, voucher)?;
                if let Some(meta) = self
                    .fingerprint_metadata
                    .get_mut(&fingerprint.prvhash_senderid_hash)
                {
                    meta.known_by_peers.insert(recipient_short_hash);
                }
            }
        }

        // Schritt 2: Heuristik zur Auswahl weiterer Fingerprints anwenden
        let mut all_known_fingerprints: Vec<TransactionFingerprint> = self
            .own_fingerprints.history.values().flatten()
            .chain(self.known_fingerprints.local_history.values().flatten())
            .chain(self.known_fingerprints.foreign_fingerprints.values().flatten())
            .cloned()
            .collect();

        // Um eine deterministische (wenngleich nicht perfekt zufällige) Auswahl zu gewährleisten, sortieren wir.
        all_known_fingerprints
            .sort_by(|a, b| a.prvhash_senderid_hash.cmp(&b.prvhash_senderid_hash));

        let mut current_depth = 0;
        while selected_fingerprints.len() < MAX_FINGERPRINTS_TO_SEND {
            let mut candidates_at_depth: Vec<_> = all_known_fingerprints
                .iter()
                .filter(|fp| {
                    if let Some(meta) = self.fingerprint_metadata.get(&fp.prvhash_senderid_hash) {
                        // Kriterien: Korrekte Tiefe UND Empfänger kennt ihn noch nicht
                        meta.depth == current_depth && !meta.known_by_peers.contains(&recipient_short_hash)
                    } else {
                        false
                    }
                })
                .collect();

            if candidates_at_depth.is_empty() && current_depth > 20 {
                // Abbruchbedingung
                break;
            }

            let space_left = MAX_FINGERPRINTS_TO_SEND - selected_fingerprints.len();
            candidates_at_depth.truncate(space_left);

            for fp in candidates_at_depth {
                // Metadaten aktualisieren: Empfänger als "wissend" markieren
                if let Some(meta) = self.fingerprint_metadata.get_mut(&fp.prvhash_senderid_hash) {
                    meta.known_by_peers.insert(recipient_short_hash);
                    selected_fingerprints.push(fp.clone());
                    selected_depths.insert(fp.prvhash_senderid_hash.clone(), meta.depth);
                }
            }
            current_depth += 1;
        }

        Ok((selected_fingerprints, selected_depths))
    }

    /// Verarbeitet empfangene Fingerprints (aktiv und implizit) und aktualisiert die Metadaten.
    fn process_received_fingerprints(
        &mut self,
        bundle_header: &TransactionBundleHeader,
        vouchers: &[Voucher],
        forwarded_fingerprints: &[TransactionFingerprint],
        fingerprint_depths: &HashMap<String, u8>,
    ) -> Result<(), VoucherCoreError> {
        
        // NEU: Verwende den speichereffizienten Kurz-Hash (gibt [u8; 4] zurück)
        let sender_short_hash = crate::services::crypto_utils::get_short_hash_from_user_id(&bundle_header.sender_id);

        // Phase 1: Aktiver Austausch (aus dem Bundle) - Min-Merge-Regel
        for fp in forwarded_fingerprints {
            let received_depth = fingerprint_depths.get(&fp.prvhash_senderid_hash).cloned().unwrap_or(u8::MAX);
            let new_depth = received_depth.saturating_add(1);

            let meta = self.fingerprint_metadata.entry(fp.prvhash_senderid_hash.clone()).or_default();

            // Min-Merge: Behalte den kleineren (besseren) depth-Wert
            if new_depth < meta.depth || meta.depth == 0 { // 0 ist der Default-Wert
                meta.depth = new_depth;
            }
            meta.known_by_peers.insert(sender_short_hash);
        }

        // Phase 2: Implizite Bestätigung (aus der Gutscheinkette)
        for voucher in vouchers {
            let tx_count = voucher.transactions.len();
            for (i, tx) in voucher.transactions.iter().enumerate() {
                let fingerprint = conflict_manager::create_fingerprint_for_transaction(tx, voucher)?;

                // Kettentiefe initialisieren: neueste = 0, vorletzte = 1, etc.
                let depth_in_chain = (tx_count - 1 - i) as u8;

                let meta = self.fingerprint_metadata.entry(fingerprint.prvhash_senderid_hash.clone()).or_insert_with(FingerprintMetadata::default);

                // Nur initialisieren, wenn der Wert noch nicht durch aktiven Austausch gesetzt wurde
                // KORREKTUR: Die Tiefe aus der Kette ist immer die aktuellste Information und sollte bestehende Werte überschreiben.
                meta.depth = depth_in_chain;
                meta.known_by_peers.insert(sender_short_hash);
            }
        }
        Ok(())
    }
    /// Baut alle abgeleiteten Speicher (`fingerprints`, `metadata`) aus dem `VoucherStore` neu auf.
    ///
    /// Diese Methode dient als Kern der Wiederherstellungslogik. Sie stellt sicher, dass der
    /// Zustand der Fingerprints und ihrer Metadaten immer konsistent mit der "Source of Truth"
    /// (den im Wallet gespeicherten Gutscheinen) ist.
    ///
    /// # Prozess
    /// 1. Leert die existierenden `own_fingerprints`, `known_fingerprints` und `fingerprint_metadata` Stores.
    /// 2. Iteriert über jeden Gutschein und jede Transaktion im `voucher_store`.
    /// 3. Generiert für jede Transaktion einen Fingerprint.
    /// 4. Kategorisiert den Fingerprint als "eigen" oder "bekannt" und speichert ihn.
    /// 5. Initialisiert die Metadaten (`depth`, `known_by_peers`) für jeden Fingerprint neu.
    pub fn rebuild_derived_stores(&mut self) -> Result<(), VoucherCoreError> {
        // Schritt 1: Bestehende abgeleitete Stores leeren
        self.own_fingerprints = OwnFingerprints::default();
        self.known_fingerprints = KnownFingerprints::default();
        self.fingerprint_metadata = CanonicalMetadataStore::default();

        // Schritt 2: Iteriere über ALLE Instanzen, um keine Fingerprints zu verlieren.
        // Die korrekte Depth wird durch die "min(depth) gewinnt"-Regel ermittelt.
        for instance in self.voucher_store.vouchers.values() {
            let tx_count = instance.voucher.transactions.len();
            for (i, tx) in instance.voucher.transactions.iter().enumerate() {
                // Schritt 3 & 4: Fingerprint generieren und kategorisieren
                let fingerprint =
                    conflict_manager::create_fingerprint_for_transaction(tx, &instance.voucher)?;

                if tx.sender_id == self.profile.user_id {
                    let entry = self.own_fingerprints
                        .history
                        .entry(fingerprint.prvhash_senderid_hash.clone())
                        .or_default();
                    if !entry.contains(&fingerprint) {
                        entry.push(fingerprint.clone());
                    }
                } else {
                    let entry = self.known_fingerprints
                        .local_history
                        .entry(fingerprint.prvhash_senderid_hash.clone())
                        .or_default();
                    if !entry.contains(&fingerprint) {
                        entry.push(fingerprint.clone());
                    }
                }

                // Schritt 5: Metadaten initialisieren oder mit "min gewinnt"-Regel aktualisieren
                let depth_in_chain = (tx_count - 1 - i) as u8;
                let meta = self
                    .fingerprint_metadata
                    .entry(fingerprint.prvhash_senderid_hash)
                    .or_insert_with(FingerprintMetadata::default);

                // Wende die "geringste depth gewinnt"-Regel an. Ein kleinerer Wert bedeutet
                // einen kürzeren, relevanteren Pfad im Netzwerk. Der Wert 0 ist der
                // initiale Default und wird immer überschrieben.
                if depth_in_chain < meta.depth || meta.depth == 0 {
                    meta.depth = depth_in_chain;
                }
                meta.known_by_peers = std::collections::HashSet::new(); // `known_by_peers` wird zurückgesetzt
            }
        }
        Ok(())
    }
}

/// Gekapselte Offline-Konfliktlösung via "Earliest Wins"-Heuristik.
fn resolve_conflict_offline(
    voucher_store: &mut VoucherStore,
    fingerprints: &[crate::models::conflict::TransactionFingerprint],
) {
    let tx_ids: std::collections::HashSet<_> = fingerprints.iter().map(|fp| &fp.t_id).collect();

    // --- 1. Lese-Phase: Finde den Gewinner, ohne den Store zu verändern ---
    let conflicting_txs: Vec<_> = voucher_store.vouchers.values().flat_map(|inst| &inst.voucher.transactions).filter(|tx| tx_ids.contains(&tx.t_id)).collect();

    let mut winner_tx: Option<&crate::models::voucher::Transaction> = None;
    let mut earliest_time = u128::MAX;

    for tx in &conflicting_txs {
        if let Some(fp) = fingerprints.iter().find(|f| f.t_id == tx.t_id) {
            if let Ok(decrypted_nanos) = conflict_manager::decrypt_transaction_timestamp(tx, fp.encrypted_timestamp) {
                if decrypted_nanos < earliest_time {
                    earliest_time = decrypted_nanos;
                    winner_tx = Some(tx);
                }
            }
        }
    }

    // --- 2. Schreib-Phase: Aktualisiere den Status basierend auf der Gewinner-ID ---
    // Die `conflicting_txs`-Liste ist nun nicht mehr im Scope, die unveränderliche Ausleihe ist beendet.
    if let Some(winner_id) = winner_tx.map(|tx| tx.t_id.clone()) {
        for instance in voucher_store.vouchers.values_mut() {
            // Finde heraus, ob diese Instanz eine der Konflikt-Transaktionen enthält.
            if let Some(tx) = instance.voucher.transactions.iter().find(|tx| tx_ids.contains(&tx.t_id)) {
                instance.status = if tx.t_id == winner_id {
                    VoucherStatus::Active
                } else {
                    VoucherStatus::Quarantined { reason: "Lost offline race".to_string() }
                };
            }
        }
    }
}