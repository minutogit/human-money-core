//! # src/wallet/transaction_handler.rs
//!
//! Enthält die Kernlogik für das Erstellen und Verarbeiten von
//! Transaktionen und Bundles.

use super::types::{CreateBundleResult, MultiTransferRequest, ProcessBundleResult};
use crate::archive::VoucherArchive;
use crate::error::{ValidationError, VoucherCoreError};
use crate::models::profile::{TransactionBundleHeader, TransactionDirection, UserIdentity};
use crate::models::secure_container::{PayloadType, SecureContainer};
use crate::models::voucher::{Voucher};
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::crypto_utils::get_hash;
use crate::services::utils::to_canonical_json;
use crate::services::{bundle_processor, conflict_manager, voucher_manager};
use crate::wallet::instance::VoucherStatus;
use crate::wallet::Wallet;
use super::conflict_handler::resolve_conflict_offline;
use rust_decimal::Decimal;
use std::collections::HashMap;
use std::str::FromStr;

impl Wallet {
    /// Erstellt ein `TransactionBundle`, verpackt es und aktualisiert den Wallet-Zustand.
    /// Dies ist nun eine private Hilfsmethode.
    pub fn create_and_encrypt_transaction_bundle(
        &mut self,
        identity: &UserIdentity,
        vouchers: Vec<Voucher>,
        recipient_id: &str,
        notes: Option<String>,
        forwarded_fingerprints: Vec<crate::models::conflict::TransactionFingerprint>,
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

        // --- LAYER 1: BUNDLE-ID REPLAY-SCHUTZ ---
        // Weist ein identisches Bundle sofort ab, das bereits verarbeitet wurde.
        if self.bundle_meta_store.history.contains_key(&bundle.bundle_id) {
            return Err(VoucherCoreError::BundleAlreadyProcessed {
                bundle_id: bundle.bundle_id.clone(),
            });
        }

        // --- LAYER 2: FINGERPRINT REPLAY-SCHUTZ ---
        // Weist ein NEUES Bundle ab, das Gutscheine enthält, deren letzte Transaktion
        // (Fingerprint) bereits bekannt ist. Verhindert modifizierte Replay-Angriffe.
        self.check_bundle_fingerprints_against_history(&bundle.vouchers)?;

        // --- ENDE REPLAY-SCHUTZ ---

        // --- ZUSÄTZLICHE SICHERHEITSPRÜFUNG ---
        // Stelle sicher, dass jeder Gutschein im Bundle auch wirklich für DIESES
        // Wallet (identity.user_id) als Empfänger vorgesehen ist.
        let own_user_id = &identity.user_id;
        for voucher in &bundle.vouchers {
            if let Some(last_tx) = voucher.transactions.last() {
                if last_tx.recipient_id != *own_user_id {
                    // Dieser Gutschein ist nicht für uns! Breche die gesamte
                    // Bundle-Verarbeitung ab, um eine Selbst-Annahme zu verhindern.
                    return Err(VoucherCoreError::BundleRecipientMismatch {
                        expected: own_user_id.clone(),
                        found: last_tx.recipient_id.clone(),
                    });
                }
            } else {
                // Ein Gutschein ohne Transaktionen ist per se ungültig.
                return Err(VoucherCoreError::Validation(
                    ValidationError::InvalidTransaction(
                        "Received voucher has no transactions.".to_string(),
                    ),
                ));
            }
        }
        // --- Ende der Sicherheitsprüfung ---

        // Kopiere die Daten, bevor 'bundle' verschoben wird
        let forwarded_fingerprints = bundle.forwarded_fingerprints.clone();
        let fingerprint_depths = bundle.fingerprint_depths.clone();
        let received_vouchers = bundle.vouchers.clone();

        // Initialisiere die neuen Ergebnis-Strukturen
        let mut transfer_summary = super::types::TransferSummary::default();
        let mut involved_vouchers = Vec::new();
        let mut involved_vouchers_details = Vec::new();

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
            if let Some(existing_instance) = self
                .voucher_store
                .vouchers
                .values()
                .find(|v| v.voucher.voucher_id == voucher.voucher_id)
            {
                println!("[Debug Wallet Process] >>> ACHTUNG: Instanz für voucher_id '{}' existiert bereits.", voucher.voucher_id);
                println!(
                    "[Debug Wallet Process]     Alte tx_count: {}, Neue tx_count: {}",
                    existing_instance.voucher.transactions.len(),
                    voucher.transactions.len()
                );
            }
            println!(
                "[Debug Wallet Process] Füge Instanz hinzu: local_id={}, voucher_id={}, tx_count={}",
                local_id,
                voucher.voucher_id,
                voucher.transactions.len()
            );
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
                let val1 = Decimal::from_str(current_sum).map_err(|e| {
                    VoucherCoreError::Generic(format!("Invalid decimal amount in summary: {}", e))
                })?;
                let val2 = Decimal::from_str(&last_tx.amount).map_err(|e| {
                    VoucherCoreError::Generic(format!(
                        "Invalid decimal amount in transaction: {}",
                        e
                    ))
                })?;

                *current_sum = (val1 + val2).to_string();
            } else {
                let count = transfer_summary.countable_items.entry(unit).or_insert(0);
                *count += 1;
            }

            // --- NEU: InvolvedVoucherInfo erstellen ---
            involved_vouchers_details.push(super::types::InvolvedVoucherInfo {
                local_instance_id: local_id.clone(),
                voucher_id: voucher.voucher_id.clone(),
                standard_name: standard.metadata.name.clone(),
                unit: voucher.nominal_value.unit.clone(),
                amount: last_tx.amount.clone(),
                // HINWEIS: Wir verwenden voucher.divisible, da dies der korrekte
                // Pfad laut Gutschein-JSON-Struktur ist.
                is_divisible: voucher.divisible,
            });
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
            &fingerprint_depths,
        )?;

        // --- NEUES DEBUGGING: Zustand des Voucher Stores NACH der Verarbeitung ---
        println!("[Debug Wallet Process] === Zustand NACH Verarbeitung des Bundles ===");
        for (id, instance) in &self.voucher_store.vouchers {
            println!("[Debug Wallet Process]   -> Vorhanden: local_id={}, voucher_id={}, status={:?}, tx_count={}", id, instance.voucher.voucher_id, instance.status, instance.voucher.transactions.len());
        }
        println!("[Debug Wallet Process] ===============================================");

        // Die Fingerprint-Stores werden bei jeder Änderung neu aus dem VoucherStore aufgebaut.
        let (own, known) =
            conflict_manager::scan_and_rebuild_fingerprints(&self.voucher_store, &identity.user_id)?;
        self.own_fingerprints = own;
        self.known_fingerprints = known;

        // Wenn eine Signatur empfangen wird, muss der Status des Gutscheins aktualisiert werden
        if let Ok(deserialized_container) =
            serde_json::from_slice::<SecureContainer>(container_bytes)
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
                let verified_proof =
                    self.verify_and_create_proof(identity, fingerprints, archive_backend)?;

                if let Some(proof) = verified_proof {
                    // Der Beweis wurde erfolgreich erstellt und kann nun verwendet werden.
                    if let Some(verdict) = &proof.layer2_verdict {
                        // Logik zur Verarbeitung eines L2-Urteils
                        for tx in &proof.conflicting_transactions {
                            let instance_id_opt = self
                                .find_local_voucher_by_tx_id(&tx.t_id)
                                .map(|i| i.local_instance_id.clone());
                            if let Some(instance_id) = instance_id_opt {
                                if let Some(instance_mut) =
                                    self.voucher_store.vouchers.get_mut(&instance_id)
                                {
                                    instance_mut.status =
                                        if tx.t_id == verdict.valid_transaction_id {
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
                    self.proof_store
                        .proofs
                        .insert(proof.proof_id.clone(), proof);
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
            involved_vouchers_details,
        })
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
            .ok_or_else(|| VoucherCoreError::VoucherNotFound(local_instance_id.to_string()))?;
        if !matches!(instance.status, VoucherStatus::Active) {
            return Err(VoucherCoreError::VoucherNotActive(instance.status.clone()));
        }
        let voucher_to_spend = instance.voucher.clone();

        let last_tx = voucher_to_spend.transactions.last().ok_or_else(|| {
            VoucherCoreError::Generic("Cannot spend voucher with no transactions.".to_string())
        })?;
        let prev_hash = get_hash(to_canonical_json(last_tx)?);

        // PRÜFUNG GEGEN ALLE BEKANNTEN FINGERPRINTS:
        // Wir prüfen sowohl gegen die aktuell aktiven als auch gegen die gesamte
        // bekannte Historie, um einen Double Spend sicher auszuschließen.
        let new_fingerprint_hash = get_hash(format!("{}{}", prev_hash, identity.user_id));
        if self
            .own_fingerprints
            .active_fingerprints
            .contains_key(&new_fingerprint_hash)
            || self
            .own_fingerprints
            .history
            .contains_key(&new_fingerprint_hash)
        {
            // SELBSTHEILUNG: Gebe die ID des Gutscheins zurück, der die Inkonsistenz verursacht hat.
            // Der aufrufende AppService kann diesen Gutschein dann in Quarantäne verschieben.
            return Err(VoucherCoreError::DoubleSpendAttemptBlocked {
                local_instance_id: local_instance_id.to_string(),
            });
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
            let (new_status, owner_id) = if last_tx.sender_id == identity.user_id
                && last_tx.sender_remaining_amount.is_some()
            {
                // Es ist ein Split, der Sender behält einen aktiven Restbetrag.
                (VoucherStatus::Active, &identity.user_id)
            } else {
                // Es ist ein voller Transfer, die Kopie des Senders wird archiviert.
                (VoucherStatus::Archived, &identity.user_id)
            };

            // 3. Ein neuer Zustand bekommt IMMER eine neue lokale ID.
            let new_local_id = Self::calculate_local_instance_id(&new_voucher_state, owner_id)?;

            // 4. Füge die neue Instanz mit der NEUEN ID und dem korrekten Status hinzu.
            self.add_voucher_instance(new_local_id, new_voucher_state.clone(), new_status);
        }

        if let Some(archive_backend) = archive {
            archive_backend.archive_voucher(
                &new_voucher_state,
                &identity.user_id,
                standard_definition,
            )?;
        }

        // Fingerprint-Erstellung und Speicherung im *historischen* Store
        let created_tx = new_voucher_state.transactions.last().unwrap();
        let fingerprint =
            conflict_manager::create_fingerprint_for_transaction(created_tx, &new_voucher_state)?;

        let history_entry = self
            .own_fingerprints
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
    ) -> Result<CreateBundleResult, VoucherCoreError> {
        // TRANSANKTIONALER ANSATZ:
        // 1. Erstelle eine temporäre Kopie des Wallets. Alle Änderungen werden
        //    zuerst auf dieser Kopie durchgeführt.
        let mut temp_wallet = self.clone();
        let mut vouchers_for_bundle: Vec<Voucher> = Vec::new();
        // NEU: Liste für die Quelldetails initialisieren
        let mut involved_sources_details: Vec<super::types::InvolvedVoucherInfo> = Vec::new();

        // 2. **Orchestrierung:** Führe `_execute_single_transfer` für jede Quelle auf der Kopie aus.
        for source in request.sources {
            let instance = temp_wallet
                .voucher_store
                .vouchers
                .get(&source.local_instance_id)
                .ok_or_else(|| {
                    VoucherCoreError::VoucherNotFound(source.local_instance_id.clone())
                })?;

            let standard_uuid = instance.voucher.voucher_standard.uuid.clone();
            let standard_definition = standard_definitions.get(&standard_uuid).ok_or_else(
                || {
                    VoucherCoreError::Generic(format!(
                        "Standard with UUID '{}' not found in provided definitions.",
                        standard_uuid
                    ))
                },
            )?;

            // NEU: InvolvedVoucherInfo für die Quelle erstellen (VOR dem Transfer)
            involved_sources_details.push(super::types::InvolvedVoucherInfo {
                local_instance_id: source.local_instance_id.clone(),
                voucher_id: instance.voucher.voucher_id.clone(),
                standard_name: standard_definition.metadata.name.clone(),
                unit: instance.voucher.nominal_value.unit.clone(),
                amount: source.amount_to_send.clone(),
                // HINWEIS: Wir verwenden voucher.divisible, da dies der korrekte
                // Pfad laut Gutschein-JSON-Struktur ist.
                is_divisible: instance.voucher.divisible,
            });

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
        let (fingerprints_to_send, depths_to_send) = temp_wallet
            .select_fingerprints_for_bundle(&request.recipient_id, &vouchers_for_bundle)?;

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

        Ok(CreateBundleResult {
            bundle_bytes: container_bytes,
            bundle_id: header.bundle_id,
            involved_sources_details,
        })
    }
}