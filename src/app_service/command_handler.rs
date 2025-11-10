//! # src/app_service/command_handler.rs
//!
//! Enthält die zentralen, schreibenden Aktionen (Commands) des `AppService`,
//! die den Zustand des Wallets verändern und persistieren.

use super::{AppState, AppService};
use crate::archive::VoucherArchive;
use crate::models::conflict::ResolutionEndorsement;
use crate::models::voucher::{Voucher};
use crate::services::voucher_validation;
use crate::{ValidationFailureReason, VoucherCoreError};
use crate::error::ValidationError; // Import the specific error type for matching
use crate::wallet::instance::VoucherStatus;
use crate::services::{standard_manager, voucher_manager::NewVoucherData};
use crate::wallet::{CreateBundleResult, MultiTransferRequest, ProcessBundleResult};
use std::collections::HashMap;

impl AppService {
    // --- Aktionen (Commands) ---

    /// Erstellt einen brandneuen Gutschein, fügt ihn zum Wallet hinzu und speichert den Zustand.
    ///
    /// # Arguments
    /// * `standard_definition` - Die Regeln des Standards, nach dem der Gutschein erstellt wird.
    /// * `data` - Die spezifischen Daten für den neuen Gutschein (z.B. Betrag).
    /// * `password` - Das Passwort, um den aktualisierten Wallet-Zustand zu speichern.
    ///
    /// # Returns
    /// Das vollständig erstellte `Voucher`-Objekt.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt ist, die Erstellung fehlschlägt oder der Speicherzugriff misslingt.
    pub fn create_new_voucher(
        &mut self,
        standard_toml_content: &str,
        lang_preference: &str,
        data: NewVoucherData,
        password: &str,
    ) -> Result<Voucher, String> {
        let current_state = std::mem::replace(&mut self.state, AppState::Locked);

        let (result, new_state) = match current_state {
            AppState::Unlocked { mut storage, wallet, identity } => {
                match crate::services::standard_manager::verify_and_parse_standard(
                    standard_toml_content,
                ) {
                    Err(e) => (Err(e.to_string()), AppState::Unlocked { storage, wallet, identity }),
                    Ok((verified_standard, standard_hash)) => {
                        match crate::services::voucher_manager::create_voucher(
                            data,
                            &verified_standard,
                            &standard_hash,
                            &identity.signing_key,
                            lang_preference,
                        ) {
                            Err(e) => (Err(e.to_string()), AppState::Unlocked { storage, wallet, identity }),
                            Ok(new_voucher) => {
                                // --- START REPLACED LOGIC ---
                                // Ersetze den Aufruf an das fehlerhafte `determine_voucher_status`.
                                // Wir validieren hier inline und behandeln "Incomplete"-Fehler korrekt.
                                let validation_result = voucher_validation::validate_voucher_against_standard(&new_voucher, &verified_standard);

                                let (operation_result, initial_status) = match validation_result {
                                    Ok(_) => {
                                        // Der Gutschein ist (unerwartet) sofort gültig.
                                        (Ok(new_voucher.clone()), VoucherStatus::Active)
                                    },

                                    //--- Selektive Fehlerbehandlung für "Incomplete" ---
                                    // Fall 1: Ein *erwarteter* Validierungsfehler, der "Incomplete" bedeutet
                                    // (z.B. fehlende Bürgen-Signaturen, die durch 'gender' oder 'role' Regeln geprüft werden).
                                    Err(VoucherCoreError::Validation(ref validation_err @ ValidationError::FieldValueCountOutOfBounds { ref path, ref field, .. }))
                                        if path == "signatures" && (field == "role" || field == "gender") =>
                                    {
                                        let reasons = vec![ValidationFailureReason::RequiredSignatureMissing { role_description: validation_err.to_string() }];
                                        (Ok(new_voucher.clone()), VoucherStatus::Incomplete { reasons })
                                    },
                                    Err(VoucherCoreError::Validation(validation_err @ ValidationError::MissingRequiredSignature { .. })) =>
                                    {
                                        let reasons = vec![ValidationFailureReason::RequiredSignatureMissing { role_description: validation_err.to_string() }];
                                        (Ok(new_voucher.clone()), VoucherStatus::Incomplete { reasons })
                                    },

                                    // Fall 2: Jeder *andere* Fehler (einschließlich anderer ValidationErrors
                                    // wie `ValidityDurationTooLong`) ist ein fataler Erstellungsfehler.
                                    Err(fatal_error) => {
                                        (Err(fatal_error.to_string()), VoucherStatus::Quarantined { reason: fatal_error.to_string() })
                                    }
                                };
                                
                                match operation_result {
                                    Err(e) => (Err(e), AppState::Unlocked { storage, wallet, identity }), // Fataler Fehler, brich ab.
                                    Ok(voucher_to_return) => {
                                        // TRANSANKTIONALER ANSATZ:
                                        // 1. Erstelle eine temporäre Kopie des Wallets für die Änderungen.
                                        let mut temp_wallet = wallet.clone();
                                        let local_id = crate::wallet::Wallet::calculate_local_instance_id(&new_voucher, &identity.user_id).unwrap();
                                        temp_wallet.add_voucher_instance(local_id, new_voucher.clone(), initial_status);
                                        
                                        // 2. Aktualisiere die abgeleiteten Stores (Fingerprints, Metadaten).
                                        // Dies ist der entscheidende Fix für die fehlenden Daten.
                                        match temp_wallet.rebuild_derived_stores() {
                                            Ok(_) => {
                                                // 3. Versuche, die Kopie zu speichern. Dies ist der "Commit"-Punkt.
                                                match temp_wallet.save(&mut storage, &identity, password) {
                                                    Ok(_) => (
                                                        // 4a. Erfolg: Gib die modifizierte Kopie als neuen Zustand zurück.
                                                        Ok(voucher_to_return),
                                                        AppState::Unlocked { storage, wallet: temp_wallet, identity },
                                                    ),
                                                    Err(e) => (
                                                        // 4b. Speicherfehler: Verwirf die Kopie.
                                                        Err(e.to_string()),
                                                        AppState::Unlocked { storage, wallet, identity },
                                                    ),
                                                }
                                            }
                                            Err(e) => (
                                                Err(e.to_string()),
                                                AppState::Unlocked { storage, wallet, identity }
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            AppState::Locked => (Err("Wallet is locked.".to_string()), current_state),
        };

        self.state = new_state;
        result
    }

    /// Erstellt eine Transaktion, verpackt sie in ein `SecureContainer`-Bundle und speichert den neuen Wallet-Zustand.
    ///
    /// # Arguments
    /// * `local_instance_id` - Die ID des zu verwendenden Gutscheins.
    /// * `recipient_id` - Die User-ID des Empfängers.
    /// * `amount_to_send` - Der zu sendende Betrag als String.
    /// * `notes` - Optionale Notizen für den Empfänger.
    /// * `archive` - Ein optionaler `VoucherArchive`-Trait, um den neuen Zustand forensisch zu sichern.
    /// * `password` - Das Passwort, um den aktualisierten Wallet-Zustand zu speichern.
    ///
    /// # Returns
    /// Die serialisierten Bytes des verschlüsselten `SecureContainer`-Bundles, bereit zum Versand.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt ist, die Transaktion ungültig ist oder der Speicherzugriff misslingt.
    pub fn create_transfer_bundle(
        &mut self,
        // NEU: Nur noch die universelle Request-Struktur
        request: MultiTransferRequest,
        // NEU: Notwendig für die Orchestrierung
        standard_definitions_toml: &HashMap<String, String>,
        archive: Option<&dyn VoucherArchive>,
        password: &str,
    ) -> Result<CreateBundleResult, String> {
        let current_state = std::mem::replace(&mut self.state, AppState::Locked);

        // Vorab alle benötigten Standards parsen
        let mut verified_definitions = HashMap::new();
        for (_uuid, toml_content) in standard_definitions_toml {
            match crate::services::standard_manager::verify_and_parse_standard(toml_content) {
                Ok((def, _hash)) => { verified_definitions.insert(def.metadata.uuid.clone(), def); },
                Err(e) => return Err(e.to_string()),
            }
        }

        let (result, new_state) = match current_state {
            // HINWEIS: 'wallet' ist hier der *originale* Zustand VOR dem Klonen.
            AppState::Unlocked { mut storage, wallet, identity } => {
                // Die Transaktionalität wurde in die Wallet::execute_multi_transfer_and_bundle
                // Methode verschoben. Wir können sie direkt auf dem Wallet aufrufen.
                // Wir erstellen hier dennoch eine Kopie, um die AppService-Logik konsistent zu halten:
                // Der `wallet`-Zustand wird nur bei Erfolg durch `temp_wallet` ersetzt.
                let mut temp_wallet = wallet.clone();
                match temp_wallet.execute_multi_transfer_and_bundle(
                    // Änderungen werden auf 'temp_wallet' durchgeführt
                    // Das originale 'wallet' bleibt für die Fehlerbehandlung (Selbstheilung) erhalten.
                    &identity,
                    &verified_definitions,
                    request,
                    archive,
                ) {
                    Ok(create_result) => { // Fange die neue CreateBundleResult Struktur
                        // Speichere den neuen Zustand, der von der Wallet-Methode committet wurde.
                        match temp_wallet.save(&mut storage, &identity, password) {
                            Ok(_) => (
                                // 4a. Erfolg: Gib die modifizierte Kopie als neuen Zustand zurück.
                                Ok(create_result), // Gib die gesamte Struktur zurück
                                AppState::Unlocked { storage, wallet: temp_wallet, identity },
                            ),
                            Err(e) => (
                                // 4b. Fehler: Verwirf die Kopie und gib den originalen,
                                // unberührten Zustand zurück.
                                Err(e.to_string()),
                                AppState::Unlocked { storage, wallet, identity },
                            ),
                        }
                    }
                    // --- SELBSTHEILUNG (Self-Healing) ---
                    // Fange den spezifischen Fehler ab, bei dem die interne Fingerprint-Prüfung
                    // einen inkonsistenten Zustand erkannt hat (z.B. ein 'Active' Gutschein,
                    // der bereits versendet wurde).
                    Err(crate::error::VoucherCoreError::DoubleSpendAttemptBlocked { local_instance_id }) => {
                        // WICHTIG: Wir verwenden hier das *originale* 'wallet'-Objekt,
                        // nicht 'temp_wallet', um die Korrektur durchzuführen.
                        let mut wallet_to_correct = wallet; // Nimm das Original
                        
                        // 1. Setze den problematischen Gutschein auf Quarantäne
                        wallet_to_correct.update_voucher_status(
                            &local_instance_id,
                            crate::wallet::instance::VoucherStatus::Quarantined {
                                reason: "Self-healing: Detected state inconsistency during transfer attempt.".to_string(),
                            },
                        );

                        // 2. Speichere den korrigierten Zustand
                        match wallet_to_correct.save(&mut storage, &identity, password) {
                            Ok(_) => {
                                // 3a. Rückgabe des korrigierten Zustands
                                (
                                    Err(format!("Action blocked and wallet state corrected: Voucher {} was internally inconsistent and is now in quarantine.", local_instance_id)),
                                    AppState::Unlocked { storage, wallet: wallet_to_correct, identity }
                                )
                            }
                            Err(save_err) => {
                                // 3b. Fehler beim Speichern der Korrektur (schlimmster Fall)
                                (
                                    Err(format!("Critical Error: Failed to save wallet correction after detecting inconsistency. Error: {}", save_err)),
                                    AppState::Unlocked { storage, wallet: wallet_to_correct, identity } // Gib trotzdem den korrigierten In-Memory-Zustand zurück
                                )
                            }
                        }
                    }
                    // Alle anderen Fehler
                    Err(e) => (Err(e.to_string()), AppState::Unlocked { storage, wallet, identity }), // Gib das Original zurück
                }
            }
            AppState::Locked => (Err("Wallet is locked.".to_string()), AppState::Locked),
        };
        self.state = new_state;
        result
    }
 
    /// Verarbeitet ein empfangenes Transaktions- oder Signatur-Bundle und speichert den neuen Wallet-Zustand.
    ///
    /// # Arguments
    /// * `bundle_data` - Die rohen Bytes des empfangenen `SecureContainer`.
    /// * `archive` - Ein optionaler `VoucherArchive`-Trait, um die neuen Zustände zu sichern.
    /// * `password` - Das Passwort, um den aktualisierten Wallet-Zustand zu speichern.
    ///
    /// # Returns
    /// Ein `ProcessBundleResult`, das Metadaten und das Ergebnis einer eventuellen Double-Spend-Prüfung enthält.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt ist, das Bundle ungültig ist oder der Speicherzugriff misslingt.
    pub fn receive_bundle(
        &mut self,
        bundle_data: &[u8],
        // NEU: Caller muss die benötigten Standard-Definitionen als TOML-Strings bereitstellen.
        // Key: Standard-UUID, Value: TOML-Inhalt als String.
        standard_definitions_toml: &HashMap<String, String>,
        archive: Option<&dyn VoucherArchive>,
        password: &str,
    ) -> Result<ProcessBundleResult, String> {
        let current_state = std::mem::replace(&mut self.state, AppState::Locked);
 
        let (result, new_state) = match current_state {
            AppState::Unlocked { mut storage, wallet, identity } => {
                // NEU: Parse die TOML-Definitionen hier, damit sie an die Wallet-Methode
                // übergeben werden können.
                let mut verified_definitions = HashMap::new();
                for (uuid, toml_content) in standard_definitions_toml {
                    match standard_manager::verify_and_parse_standard(toml_content) {
                        Ok((def, _hash)) => {
                            verified_definitions.insert(uuid.clone(), def);
                        }
                        Err(e) => return Err(e.to_string()),
                    }
                }

                match self.validate_vouchers_in_bundle(
                    &identity,
                    bundle_data,
                    standard_definitions_toml,
                ) {
                    Err(e) => (Err(e), AppState::Unlocked { storage, wallet, identity }),
                    Ok(_) => {
                        // TRANSANKTIONALER ANSATZ:
                        let mut temp_wallet = wallet.clone();
                        match temp_wallet
                            .process_encrypted_transaction_bundle(&identity, bundle_data, archive, &verified_definitions)
                        {
                            Ok(proc_result) => {
                                match temp_wallet.save(&mut storage, &identity, password) {
                                    Ok(_) => (
                                        Ok(proc_result),
                                        AppState::Unlocked {
                                            storage,
                                            wallet: temp_wallet,
                                            identity,
                                        },
                                    ),
                                    Err(e) => (
                                        Err(e.to_string()),
                                        AppState::Unlocked { storage, wallet, identity },
                                    ),
                                }
                            }
                            Err(e) => (Err(e.to_string()), AppState::Unlocked { storage, wallet, identity }),
                        }
                    }
                }
            }
            AppState::Locked => (Err("Wallet is locked.".to_string()), AppState::Locked),
        };
        self.state = new_state;
        result
    }

    /// Importiert eine Beilegungserklärung und fügt sie dem entsprechenden Konfliktbeweis hinzu.
    ///
    /// Diese Operation verändert den Wallet-Zustand und speichert ihn bei Erfolg automatisch.
    ///
    /// # Arguments
    /// * `endorsement` - Die empfangene `ResolutionEndorsement`.
    /// * `password` - Das Passwort, um den aktualisierten Wallet-Zustand zu speichern.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt ist, der zugehörige Beweis nicht
    /// gefunden wird oder der Speicherzugriff misslingt.
    pub fn import_resolution_endorsement(
        &mut self,
        endorsement: ResolutionEndorsement,
        password: &str,
    ) -> Result<(), String> {
        let current_state = std::mem::replace(&mut self.state, AppState::Locked);
        let (result, new_state) = match current_state {
            AppState::Unlocked { mut storage, wallet, identity } => {
                // TRANSANKTIONALER ANSATZ:
                let mut temp_wallet = wallet.clone();
                match temp_wallet.add_resolution_endorsement(endorsement) {
                    Ok(_) => {
                        match temp_wallet.save(&mut storage, &identity, password) {
                            Ok(_) => (
                                Ok(()),
                                AppState::Unlocked {
                                    storage,
                                    wallet: temp_wallet,
                                    identity,
                                },
                            ),
                            Err(e) => (Err(e.to_string()), AppState::Unlocked { storage, wallet, identity }),
                        }
                    }
                    Err(e) => (Err(e.to_string()), AppState::Unlocked { storage, wallet, identity }),
                }
            }
            AppState::Locked => (Err("Wallet is locked.".to_string()), AppState::Locked),
        };
        self.state = new_state;
        result
    }
}

