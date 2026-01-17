//! # src/app_service/app_signature_handler.rs
//!
//! Enthält alle `AppService`-Funktionen, die sich auf den Signatur-Workflow beziehen,
//! wie das Anfordern, Erstellen und Anhängen von losgelösten Signaturen.

use super::{AppService, AppState};
use crate::models::signature::DetachedSignature;
use crate::models::voucher::{Voucher, VoucherSignature};
use crate::services::voucher_validation;
use crate::wallet::instance::VoucherStatus;
use crate::{AuthMethod, ValidationFailureReason, VoucherCoreError};

impl AppService {
    /// Erstellt ein Bundle, um einen Gutschein zur Unterzeichnung an einen Bürgen zu senden.
    ///
    /// Diese Operation verändert den Wallet-Zustand nicht und erfordert kein Speichern.
    ///
    /// # Returns
    /// Die serialisierten Bytes des `SecureContainer`, bereit zum Versand an den Bürgen.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt ist oder der angeforderte Gutschein nicht existiert.
    pub fn create_signing_request_bundle(
        &self,
        local_instance_id: &str,
        recipient_id: &str,
    ) -> Result<Vec<u8>, String> {
        let wallet = self.get_wallet()?;
        let identity = match &self.state {
            AppState::Unlocked { identity, .. } => identity,
            AppState::Locked => return Err("Wallet is locked".to_string()),
        };
        wallet
            .create_signing_request(identity, local_instance_id, recipient_id)
            .map_err(|e| e.to_string())
    }

    /// Erstellt eine losgelöste Signatur als Antwort auf eine Signaturanfrage.
    ///
    /// Diese Operation wird vom Bürgen aufgerufen und verändert dessen Wallet-Zustand nicht.
    ///
    /// # Returns
    /// Die serialisierten Bytes des `SecureContainer` mit der Signatur, bereit für den Rückversand.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet des Bürgen gesperrt ist.
    pub fn create_detached_signature_response_bundle(
        &self,
        voucher_to_sign: &Voucher,
        role: &str,
        include_details: bool,
        original_sender_id: &str,
    ) -> Result<Vec<u8>, String> {
        let identity = match &self.state {
            AppState::Unlocked { identity, .. } => identity,
            AppState::Locked => return Err("Wallet is locked".to_string()),
        };
        let wallet = self.get_wallet()?;

        // Erstelle das Wrapper-Objekt mit den Metadaten
        let signature_data = DetachedSignature::Signature(VoucherSignature {
            role: role.to_string(),
            ..Default::default()
        });

        wallet
            .create_detached_signature_response(
                identity,
                voucher_to_sign,
                signature_data,
                include_details,
                original_sender_id,
            )
            .map_err(|e| e.to_string())
    }

    /// Verarbeitet eine empfangene losgelöste Signatur, fügt sie dem lokalen Gutschein hinzu und speichert den Zustand.
    ///
    /// # Arguments
    /// * `container_bytes` - Die rohen Bytes des `SecureContainer`, der die Signatur enthält.
    /// * `password` - Das Passwort, um den aktualisierten Wallet-Zustand zu speichern.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt ist, die Signatur ungültig ist, der zugehörige Gutschein nicht gefunden
    /// wird oder der Speicherzugriff misslingt.
    pub fn process_and_attach_signature(
        &mut self,
        container_bytes: &[u8],
        standard_toml_content: &str,
        password: Option<&str>,
    ) -> Result<(), String> {
        println!("[DEBUG SIG] process_and_attach_signature called.");
        let current_state = std::mem::replace(&mut self.state, AppState::Locked);

        let (result, new_state) = match current_state {
            AppState::Unlocked {
                mut storage,
                wallet,
                identity,
                session_cache,
            } => {
                match crate::services::standard_manager::verify_and_parse_standard(
                    standard_toml_content,
                ) {
                    Err(e) => (
                        Err(e.to_string()),
                        AppState::Unlocked {
                            storage,
                            wallet,
                            identity,
                            session_cache,
                        },
                    ),
                    Ok((verified_standard, _)) => {
                        let auth_method;

                        match password {
                            Some(pwd_str) => {
                                println!(
                                    "[DEBUG SIG] process_and_attach: Mode A (Some(password)) detected."
                                );
                                // KORREKTUR: Modus A verwendet AuthMethod::Password
                                auth_method = AuthMethod::Password(pwd_str);
                            }
                            None => {
                                println!("[DEBUG SIG] process_and_attach: Mode B (None) detected.");
                                let session_key = self.get_session_key()
                                    .map_err(|e| { println!("[DEBUG SIG] process_and_attach: Mode B: get_session_key FAILED: {}", e); e })?;
                                auth_method = AuthMethod::SessionKey(session_key);
                            }
                        }
                        // --- BEGINN DER TRANSAKTION ---
                        let mut temp_wallet = wallet.clone();

                        // 1. Signatur an die temporäre Wallet-Instanz anhängen.
                        match temp_wallet.process_and_attach_signature(&identity, container_bytes) {
                            Err(e) => (
                                Err(e.to_string()),
                                AppState::Unlocked {
                                    storage,
                                    wallet,
                                    identity,
                                    session_cache,
                                },
                            ),
                            Ok(updated_instance_id) => {
                                // 2. Neuen Status basierend auf dem Ergebnis bestimmen.
                                let instance = temp_wallet
                                    .get_voucher_instance(&updated_instance_id)
                                    .cloned()
                                    .unwrap(); // Muss existieren

                                // --- START REPLACED LOGIC ---
                                // Die alte Logik rief `self.determine_voucher_status` auf, was
                                // fälschlicherweise Unvollständigkeit als fatalen Fehler behandelte.
                                // Wir rufen nun die Validierung direkt auf und interpretieren das Ergebnis korrekt.

                                let validation_result =
                                    voucher_validation::validate_voucher_against_standard(
                                        &instance.voucher,
                                        &verified_standard,
                                    );

                                let (operation_result, new_status) = match validation_result {
                                    Ok(_) => {
                                        // Validierung erfolgreich! Der Gutschein ist jetzt Active.
                                        (Ok(()), VoucherStatus::Active)
                                    }
                                    Err(VoucherCoreError::Validation(validation_err)) => {
                                        // Das ist KEIN fataler Fehler. Die Operation war erfolgreich,
                                        // der Gutschein ist nur weiterhin unvollständig.
                                        // Wir wandeln den ValidationError manuell in einen ValidationFailureReason um,
                                        // da keine `From`-Implementierung existiert.
                                        let reasons = vec![
                                            ValidationFailureReason::RequiredSignatureMissing {
                                                role_description: validation_err.to_string(),
                                            },
                                        ];
                                        (Ok(()), VoucherStatus::Incomplete { reasons })
                                    }
                                    Err(fatal_error) => {
                                        // DAS ist ein fataler Fehler (z.B. Standard-Mismatch, Crypto-Fehler).
                                        temp_wallet.update_voucher_status(
                                            &updated_instance_id,
                                            VoucherStatus::Quarantined {
                                                reason: fatal_error.to_string(),
                                            },
                                        );
                                        (
                                            Err(format!(
                                                "Voucher quarantined due to fatal validation error: {}",
                                                fatal_error
                                            )),
                                            VoucherStatus::Quarantined {
                                                reason: fatal_error.to_string(),
                                            },
                                        )
                                    }
                                };

                                temp_wallet.update_voucher_status(&updated_instance_id, new_status);
                                // 3. Versuchen, die Änderungen zu speichern ("Commit").
                                match temp_wallet.save(&mut storage, &identity, &auth_method) {
                                    Ok(_) => (
                                        // Erfolg: Gib das Ergebnis der Operation zurück und setze die neue Wallet-Instanz.
                                        operation_result,
                                        AppState::Unlocked {
                                            storage,
                                            wallet: temp_wallet,
                                            identity,
                                            session_cache,
                                        },
                                    ),
                                    Err(e) => (
                                        // Fehler: Verwirf die Änderungen und gib den Speicherfehler zurück.
                                        Err(e.to_string()),
                                        AppState::Unlocked {
                                            storage,
                                            wallet,
                                            identity,
                                            session_cache,
                                        },
                                    ),
                                }
                            }
                        }
                    }
                }
            }
            AppState::Locked => (Err("Wallet is locked.".to_string()), AppState::Locked),
        };

        self.state = new_state;
        result
    }
}
