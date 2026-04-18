//! # src/wallet/maintenance.rs
//!
//! Sammelt alle Methoden für die interne Verwaltung, Wartung, Bereinigung
//! und Hilfsfunktionen des Wallets.

use super::types::CleanupReport;
use crate::archive::VoucherArchive;
use crate::error::VoucherCoreError;
use crate::models::conflict::{
    CanonicalMetadataStore, FingerprintMetadata, KnownFingerprints, OwnFingerprints,
};
use crate::models::voucher::{Transaction, Voucher};
use crate::services::conflict_manager;
use crate::services::crypto_utils::get_hash;
use crate::wallet::Wallet;
use crate::wallet::instance::{VoucherInstance, VoucherStatus};
use chrono::{DateTime, Duration, Utc};

impl Wallet {
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
    pub fn run_storage_cleanup(
        &mut self,
        max_fingerprints_override: Option<usize>,
    ) -> Result<CleanupReport, VoucherCoreError> {
        const MAX_FINGERPRINTS_CONST: usize = 20_000;
        const CLEANUP_PERCENTAGE: f32 = 0.10;

        let mut report = CleanupReport::default();
        let now = Utc::now();

        // --- Phase 1: Löschen abgelaufener Einträge ---
        let mut expired_keys = std::collections::HashSet::new();

        // Sammle alle abgelaufenen Schlüssel aus allen relevanten Stores
        for fp in self
            .own_fingerprints
            .history
            .values()
            .flatten()
            .chain(self.known_fingerprints.local_history.values().flatten())
            .chain(
                self.known_fingerprints
                    .foreign_fingerprints
                    .values()
                    .flatten(),
            )
        {
            if let Ok(valid_until) = DateTime::parse_from_rfc3339(&fp.deletable_at) {
                if valid_until.with_timezone(&Utc) < now {
                    expired_keys.insert(fp.ds_tag.clone());
                }
            }
        }

        if !expired_keys.is_empty() {
            report.expired_fingerprints_removed = expired_keys.len() as u32;

            // Entferne die abgelaufenen Einträge aus allen Stores
            self.own_fingerprints
                .history
                .retain(|k, _| !expired_keys.contains(k));
            self.known_fingerprints
                .local_history
                .retain(|k, _| !expired_keys.contains(k));
            self.known_fingerprints
                .foreign_fingerprints
                .retain(|k, _| !expired_keys.contains(k));
            self.fingerprint_metadata
                .retain(|k, _| !expired_keys.contains(k));
        }

        // --- Phase 2: Selektive Löschung nach Tiefe und Rezenz ---
        let current_total_count = self.own_fingerprints.history.len()
            + self.known_fingerprints.local_history.len()
            + self.known_fingerprints.foreign_fingerprints.len();

        let max_fingerprints = max_fingerprints_override.unwrap_or(MAX_FINGERPRINTS_CONST);
        if current_total_count > max_fingerprints {
            let target_removal_count =
                (current_total_count as f32 * CLEANUP_PERCENTAGE).ceil() as usize;

            // Sammle alle Fingerprints mit Metadaten zur Sortierung
            let mut candidates_for_removal = Vec::new();
            let all_fingerprints = self
                .own_fingerprints
                .history
                .values()
                .flatten()
                .chain(self.known_fingerprints.local_history.values().flatten())
                .chain(
                    self.known_fingerprints
                        .foreign_fingerprints
                        .values()
                        .flatten(),
                );

            for fp in all_fingerprints {
                if let Some(meta) = self.fingerprint_metadata.get(&fp.ds_tag) {
                    // Wir verwenden die `t_id` als deterministischen Tie-Breaker anstelle des
                    // nicht verfügbaren `t_time`, um eine ineffiziente Entschlüsselung zu vermeiden.
                    candidates_for_removal.push((meta.depth, fp.t_id.clone(), fp.ds_tag.clone()));
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
            self.own_fingerprints
                .history
                .retain(|k, _| !keys_to_remove.contains(k));
            self.known_fingerprints
                .local_history
                .retain(|k, _| !keys_to_remove.contains(k));
            self.known_fingerprints
                .foreign_fingerprints
                .retain(|k, _| !keys_to_remove.contains(k));
            self.fingerprint_metadata
                .retain(|k, _| !keys_to_remove.contains(k));
        }

        Ok(report)
    }

    /// Führt Wartungsarbeiten am Wallet-Speicher durch, um veraltete Daten zu entfernen.
    pub fn cleanup_storage(&mut self, archive_grace_period_years: i64) {
        // Schritt 1: Bereinige flüchtige Speicher sofort (ohne Frist).
        conflict_manager::cleanup_known_fingerprints(&mut self.known_fingerprints);

        let now = Utc::now();
        let grace_period = Duration::days(archive_grace_period_years * 365);

        // Schritt 2: Bereinige die persistente History mit der längeren Frist.
        conflict_manager::cleanup_expired_histories(
            &mut self.own_fingerprints,
            &mut self.known_fingerprints,
            &now,
            &grace_period,
        );

        // Schritt 3: Bereinige Gutschein-Instanzen im Archiv mit derselben Frist.
        self.voucher_store.vouchers.retain(|_, instance| {
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
        self.proof_store.proofs.retain(|_, entry| {
            if let Ok(valid_until) = DateTime::parse_from_rfc3339(&entry.proof.deletable_at) {
                let purge_date = valid_until.with_timezone(&Utc) + grace_period;
                return now < purge_date;
            }
            true
        });
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

                if tx.sender_id.as_ref() == Some(&self.profile.user_id) {
                    let entry = self
                        .own_fingerprints
                        .history
                        .entry(fingerprint.ds_tag.clone())
                        .or_default();
                    if !entry.contains(&fingerprint) {
                        entry.push(fingerprint.clone());
                    }
                } else {
                    let entry = self
                        .known_fingerprints
                        .local_history
                        .entry(fingerprint.ds_tag.clone())
                        .or_default();
                    if !entry.contains(&fingerprint) {
                        entry.push(fingerprint.clone());
                    }
                }

                // Schritt 5: Metadaten initialisieren oder mit "min gewinnt"-Regel aktualisieren
                let depth_in_chain = (tx_count - 1 - i) as i8;
                let meta = self
                    .fingerprint_metadata
                    .entry(fingerprint.ds_tag)
                    .or_insert_with(FingerprintMetadata::default);

                // Wende die "geringste depth gewinnt"-Regel an. Ein kleinerer Wert bedeutet
                // einen kürzeren, relevanteren Pfad im Netzwerk. Der Wert 0 ist der
                // initiale Default und wird immer überschrieben.
                // ACHTUNG: VIP-Fingerprints (negativ) gewinnen immer gegen positive.
                if meta.depth == 0 || depth_in_chain < meta.depth {
                    meta.depth = depth_in_chain;
                }
                meta.known_by_peers = std::collections::HashSet::new(); // `known_by_peers` wird zurückgesetzt
            }
        }
        Ok(())
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
        self.voucher_store.vouchers.insert(local_id, instance);
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
            if tx.recipient_id == profile_owner_id
                || tx.sender_id.as_deref() == Some(profile_owner_id)
            {
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

    /// Sucht eine Transaktion anhand ihrer ID (`t_id`) zuerst im aktiven
    /// `voucher_store` und dann im `VoucherArchive`.
    pub(super) fn find_transaction_in_stores(
        &self,
        t_id: &str,
        archive: &dyn VoucherArchive,
    ) -> Result<Option<Transaction>, VoucherCoreError> {
        // Zuerst im aktiven Store suchen
        for instance in self.voucher_store.vouchers.values() {
            if let Some(tx) = instance
                .voucher
                .transactions
                .iter()
                .find(|t| t.t_id == t_id)
            {
                return Ok(Some(tx.clone()));
            }
        }

        // Danach im Archiv suchen
        let result = archive.find_transaction_by_id(t_id)?;
        Ok(result.map(|(_, tx)| tx))
    }

    /// Sucht einen Gutschein anhand einer enthaltenen Transaktions-ID (`t_id`).
    /// Durchsucht zuerst den aktiven `voucher_store` und dann das `VoucherArchive`.
    pub(super) fn find_voucher_for_transaction(
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
    pub(super) fn find_local_voucher_by_tx_id(&self, tx_id: &str) -> Option<&VoucherInstance> {
        self.voucher_store.vouchers.values().find(|instance| {
            instance
                .voucher
                .transactions
                .iter()
                .any(|tx| tx.t_id == tx_id)
        })
    }
}
