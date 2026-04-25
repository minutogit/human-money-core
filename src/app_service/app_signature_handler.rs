//! # src/app_service/app_signature_handler.rs
//!
//! Enthält alle `AppService`-Funktionen, die sich auf den Signatur-Workflow beziehen,
//! wie das Anfordern, Erstellen und Anhängen von losgelösten Signaturen.

use super::{AppService, AppState};
use crate::models::secure_container::ContainerConfig;
use crate::models::signature::DetachedSignature;
use crate::models::voucher::{Voucher, VoucherSignature};
use crate::services::voucher_validation;
use crate::wallet::instance::VoucherStatus;
use crate::{ValidationFailureReason, VoucherCoreError};

impl AppService {
    /// Erstellt ein Bundle, um einen Gutschein zur Unterzeichnung an einen weiteren Teilnehmer (z. B. Bürge, Notar) zu senden.
    ///
    /// Diese Operation verändert den Wallet-Zustand nicht und erfordert kein Speichern.
    ///
    /// # Returns
    /// Die serialisierten Bytes des `SecureContainer`, bereit zum Versand an den Unterzeichner.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt ist oder der angeforderte Gutschein nicht existiert.
    pub fn create_signing_request_bundle(
        &self,
        local_instance_id: &str,
        config: ContainerConfig,
    ) -> Result<Vec<u8>, String> {
        let wallet = self.get_wallet()?;
        let identity = match &self.state {
            AppState::Unlocked { identity, .. } => identity,
            AppState::Locked => return Err("Wallet is locked".to_string()),
        };
        wallet
            .create_signing_request(identity, local_instance_id, config)
            .map_err(|e| e.to_string())
    }

    /// Öffnet einen empfangenen `SecureContainer`, der eine Signaturanfrage enthält,
    /// und gibt den Gutschein zur Überprüfung (Preview) zurück.
    ///
    /// Diese Operation verändert den Wallet-Zustand nicht.
    ///
    /// # Returns
    /// Das `Voucher`-Objekt, das unterzeichnet werden soll.
    pub fn open_voucher_signing_request(
        &self,
        container_bytes: &[u8],
        password: Option<&str>,
    ) -> Result<Voucher, String> {
        let identity = match &self.state {
            AppState::Unlocked { identity, .. } => identity,
            AppState::Locked => return Err("Wallet is locked".to_string()),
        };

        let container: crate::models::secure_container::SecureContainer =
            serde_json::from_slice(container_bytes).map_err(|e| e.to_string())?;

        if !matches!(
            container.c,
            crate::models::secure_container::PayloadType::VoucherForSigning
        ) {
            return Err("Invalid payload type: expected VoucherForSigning".to_string());
        }

        let payload = crate::services::secure_container_manager::open_secure_container(
            &container, identity, password,
        )
        .map_err(|e| e.to_string())?;

        let voucher: Voucher = serde_json::from_slice(&payload).map_err(|e| e.to_string())?;
        Ok(voucher)
    }

    /// Erstellt eine losgelöste Signatur als Antwort auf eine Signaturanfrage.
    ///
    /// Diese Operation wird vom Unterzeichner aufgerufen und speichert den bezeugten Gutschein
    /// im lokalen Wallet unter dem Status `Endorsed` als rechtssicheres Logbuch.
    ///
    /// # Returns
    /// Die serialisierten Bytes des `SecureContainer` mit der Signatur, bereit für den Rückversand.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet des Unterzeichners gesperrt ist oder das Speichern fehlschlägt.
    pub fn create_detached_signature_response_bundle(
        &mut self,
        voucher_to_sign: &Voucher,
        role: &str,
        include_details: bool,
        config: ContainerConfig,
        password: Option<&str>,
    ) -> Result<Vec<u8>, String> {
        // --- FORK-LOCK PRÜFUNG ---
        self.check_fork_lock(password).map_err(|e| e.to_string())?;

        // BUG-FIX: Determine AuthMethod BEFORE state replacement
        let auth_method = match password {
            Some(pwd_str) => crate::AuthMethod::Password(pwd_str),
            None => {
                let session_key = self.get_session_key().map_err(|e| e.to_string())?;
                crate::AuthMethod::SessionKey(session_key)
            }
        };

        let current_state = std::mem::replace(&mut self.state, AppState::Locked);

        let (result, new_state) = match current_state {
            AppState::Unlocked {
                mut storage,
                wallet,
                identity,
                session_cache,
            } => {
                // Erstelle das Wrapper-Objekt mit den Metadaten
                let signature_data = DetachedSignature::Signature(VoucherSignature {
                    role: role.to_string(),
                    ..Default::default()
                });

                // Erstelle die Signatur
                let bundle_bytes = wallet
                    .create_detached_signature_response(
                        &identity,
                        voucher_to_sign,
                        signature_data,
                        include_details,
                        config,
                    )
                    .map_err(|e| e.to_string())?;

                // Speichere den bezeugten Gutschein im lokalen Wallet
                let mut temp_wallet = wallet.clone();
                // Für Endorsed-Gutscheine verwenden wir eine andere ID-Generierung,
                // da der Unterzeichner keine Ownership-History für den Gutschein hat.
                // Wir verwenden voucher_id + signer_id + role als deterministische ID.
                use crate::services::crypto_utils::get_hash_from_slices;
                let voucher_id_bytes = voucher_to_sign.voucher_id.as_bytes();
                let signer_id_bytes = temp_wallet.profile.user_id.as_bytes();
                let role_bytes = role.as_bytes();
                let local_id = get_hash_from_slices(&[voucher_id_bytes, signer_id_bytes, role_bytes]);
                temp_wallet.add_voucher_instance(
                    local_id,
                    voucher_to_sign.clone(),
                    crate::wallet::instance::VoucherStatus::Endorsed {
                        role: role.to_string(),
                    },
                );

                // Speichere den Wallet-Zustand
                match temp_wallet.save(&mut storage, &identity, &auth_method) {
                    Ok(_) => (
                        Ok(bundle_bytes),
                        AppState::Unlocked {
                            storage,
                            wallet: temp_wallet,
                            identity,
                            session_cache,
                        },
                    ),
                    Err(e) => (
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
            AppState::Locked => (Err("Wallet is locked".to_string()), AppState::Locked),
        };

        self.state = new_state;
        result
    }

    /// Verarbeitet eine empfangene losgelöste Signatur, fügt sie dem lokalen Gutschein hinzu und speichert den Zustand.
    ///
    /// # Arguments
    /// * `container_bytes` - Die rohen Bytes des `SecureContainer`, der die Signatur enthält.
    /// * `standard_toml_content` - Der Inhalt des Standards für die Validierung.
    /// * `container_password` - Optionales Passwort zum Öffnen des Containers (für symmetrische Verschlüsselung).
    /// * `wallet_password` - Das Passwort, um den aktualisierten Wallet-Zustand zu speichern.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt ist, die Signatur ungültig ist, der zugehörige Gutschein nicht gefunden
    /// wird oder der Speicherzugriff misslingt.
    pub fn process_and_attach_signature(
        &mut self,
        container_bytes: &[u8],
        standard_toml_content: &str,
        container_password: Option<&str>,
        wallet_password: Option<&str>,
    ) -> Result<String, String> {
        // --- FORK-LOCK PRÜFUNG ---
        self.check_fork_lock(wallet_password).map_err(|e| e.to_string())?;

        // BUG-FIX: Determine AuthMethod BEFORE state replacement
        let auth_method = match wallet_password {
            Some(pwd_str) => crate::AuthMethod::Password(pwd_str),
            None => {
                let session_key = self.get_session_key().map_err(|e| e.to_string())?;
                crate::AuthMethod::SessionKey(session_key)
            }
        };

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
                        // --- BEGINN DER TRANSAKTION ---
                        let mut temp_wallet = wallet.clone();

                        // 1. Signatur an die temporäre Wallet-Instanz anhängen.
                        match temp_wallet.process_and_attach_signature(&identity, container_bytes, container_password) {
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
                                        (Ok(updated_instance_id.clone()), VoucherStatus::Active)
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
                                        (Ok(updated_instance_id.clone()), VoucherStatus::Incomplete { reasons })
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

    /// Evaluates the impact of a proposed signature (role and the user's current profile)
    ///
    /// # Returns
    /// The `SignatureImpact` detailing if the role is allowed, and any resulting conflicts, resolved rules, or gentle hints.
    pub fn evaluate_signature_suitability(
        &self,
        voucher: &Voucher,
        role: &str,
        standard_toml_content: &str,
    ) -> Result<crate::services::signature_manager::SignatureImpact, String> {
        let (verified_standard, _) = crate::services::standard_manager::verify_and_parse_standard(
            standard_toml_content,
        )
        .map_err(|e| e.to_string())?;

        let profile = self.get_public_profile()?;
        
        crate::services::signature_manager::evaluate_signature_impact(
            voucher,
            &verified_standard,
            role,
            &profile,
        )
        .map_err(|e| e.to_string())
    }

    /// Entfernt eine Zusatzsignatur (z. B. von Bürgen oder Zeugen) von einem Gutschein.
    ///
    /// Dieser Vorgang darf nur vom Ersteller des Gutscheins ausgeführt werden und nur,
    /// solange der Gutschein noch nicht in Umlauf ist (nur eine init-Transaktion vorhanden).
    ///
    /// # Arguments
    /// * `local_instance_id` - Die ID des Gutscheins im lokalen Wallet.
    /// * `signature_id` - Die ID der zu entfernenden Signatur.
    /// * `wallet_password` - Das Passwort, um den aktualisierten Wallet-Zustand zu speichern.
    ///
    /// # Returns
    /// Ein `Result`, das bei Erfolg `Ok(())` zurückgibt.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt ist, die Signatur nicht entfernt werden kann
    /// (z. B. weil der Gutschein bereits im Umlauf ist oder die anfragende Identität nicht der Ersteller ist),
    /// oder der Speicherzugriff misslingt.
    pub fn remove_voucher_signature(
        &mut self,
        local_instance_id: &str,
        signature_id: &str,
        wallet_password: Option<&str>,
    ) -> Result<(), String> {
        // --- FORK-LOCK PRÜFUNG ---
        self.check_fork_lock(wallet_password).map_err(|e| e.to_string())?;

        // Determine AuthMethod BEFORE state replacement
        let auth_method = match wallet_password {
            Some(pwd_str) => crate::AuthMethod::Password(pwd_str),
            None => {
                let session_key = self.get_session_key().map_err(|e| e.to_string())?;
                crate::AuthMethod::SessionKey(session_key)
            }
        };

        let current_state = std::mem::replace(&mut self.state, AppState::Locked);

        let (result, new_state) = match current_state {
            AppState::Unlocked {
                mut storage,
                wallet,
                identity,
                session_cache,
            } => {
                let mut temp_wallet = wallet.clone();

                match temp_wallet.remove_signature(&identity, local_instance_id, signature_id) {
                    Err(e) => (
                        Err(e.to_string()),
                        AppState::Unlocked {
                            storage,
                            wallet,
                            identity,
                            session_cache,
                        },
                    ),
                    Ok(_) => {
                        // Versuchen, die Änderungen zu speichern
                        match temp_wallet.save(&mut storage, &identity, &auth_method) {
                            Ok(_) => (
                                Ok(()),
                                AppState::Unlocked {
                                    storage,
                                    wallet: temp_wallet,
                                    identity,
                                    session_cache,
                                },
                            ),
                            Err(e) => (
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
            AppState::Locked => (Err("Wallet is locked.".to_string()), AppState::Locked),
        };

        self.state = new_state;
        result
    }
}


