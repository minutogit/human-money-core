use crate::app_service::{AppService, AppState};
use crate::models::layer2_api::{L2AuthPayload, L2StatusQuery};
use crate::services::l2_gateway::{self, VerdictAction};
use crate::storage::{AuthMethod, WalletLockGuard};
use crate::wallet::instance::VoucherStatus;

impl AppService {
    pub fn generate_l2_lock_request(&self, local_instance_id: &str) -> Result<Vec<u8>, String> {
        let (wallet, _identity) = match &self.state {
            AppState::Unlocked { wallet, identity, .. } => (wallet, identity),
            _ => return Err("Wallet is locked".to_string()),
        };

        let instance = wallet
            .get_voucher_instance(local_instance_id)
            .ok_or_else(|| format!("Voucher {} not found", local_instance_id))?;

        let transaction = instance
            .voucher
            .transactions
            .last()
            .ok_or_else(|| "No transactions found in voucher".to_string())?;

        // In the new Layer 2 semantics, the voucher id is derived from the first (init) transaction.
        let l2_voucher_id = l2_gateway::calculate_layer2_voucher_id(&instance.voucher.transactions[0])
            .map_err(|e| e.to_string())?;

        // TODO: In the future, derive a proper ephemeral key. For now, use dummy bytes.
        let ephemeral_key = [0u8; 32];
        let request = l2_gateway::generate_lock_request(
            &l2_voucher_id,
            transaction,
            &ephemeral_key,
        )
        .map_err(|e| e.to_string())?;

        serde_json::to_vec(&request).map_err(|e| e.to_string())
    }

    /// Generiert eine L2StatusQuery (Lese-Anfrage) für den aktuellen Stand eines Gutscheins.
    pub fn generate_l2_status_query(&self, local_instance_id: &str) -> Result<Vec<u8>, String> {
        let (wallet, _identity) = match &self.state {
            AppState::Unlocked { wallet, identity, .. } => (wallet, identity),
            _ => return Err("Wallet is locked".to_string()),
        };

        let instance = wallet
            .get_voucher_instance(local_instance_id)
            .ok_or_else(|| format!("Voucher {} not found", local_instance_id))?;

        let layer2_voucher_id = l2_gateway::calculate_layer2_voucher_id(&instance.voucher.transactions[0])
            .map_err(|e| e.to_string())?;

        let challenge_ds_tag = if let Some(last_tx) = instance.voucher.transactions.last() {
            l2_gateway::derive_challenge_tag(last_tx).map_err(|e| e.to_string())?
        } else {
            return Err("Voucher has no transactions".to_string());
        };

        let locator_prefixes = l2_gateway::generate_locator_prefixes(&instance.voucher);

        // TODO: derive proper ephemeral key
        let ephemeral_key = [0u8; 32];
        let auth = L2AuthPayload {
            ephemeral_pubkey: ephemeral_key,
            auth_signature: None,
        };

        let query = L2StatusQuery {
            auth,
            layer2_voucher_id,
            challenge_ds_tag,
            locator_prefixes,
        };

        serde_json::to_vec(&query).map_err(|e| e.to_string())
    }

    /// Verarbeitet ein L2Verdict und führt die entsprechende Aktion auf dem Wallet aus.
    pub fn process_l2_response(
        &mut self,
        local_instance_id: &str,
        response_bytes: &[u8],
        password: Option<&str>,
    ) -> Result<(), String> {
        let (wallet, _identity) = match &self.state {
            AppState::Unlocked { wallet, identity, .. } => (wallet, identity),
            _ => return Err("Wallet is locked".to_string()),
        };

        let instance = wallet
            .get_voucher_instance(local_instance_id)
            .ok_or_else(|| format!("Voucher {} not found", local_instance_id))?;

        let last_tx = instance.voucher.transactions.last()
            .ok_or_else(|| "No transactions found".to_string())?;
        let last_t_id = last_tx.t_id.clone();
        let challenge_ds_tag = l2_gateway::derive_challenge_tag(last_tx).map_err(|e| e.to_string())?;
        let expected_ephemeral_pub = last_tx.sender_ephemeral_pub.as_deref();
        let expected_voucher_id = l2_gateway::calculate_layer2_voucher_id(&instance.voucher.transactions[0]).map_err(|e| e.to_string())?;

        let server_pubkey = wallet.profile.l2_server_pubkey.ok_or_else(|| "L2 server public key not configured in wallet profile".to_string())?;

        let action = l2_gateway::process_l2_verdict(response_bytes, &server_pubkey, &last_t_id, &challenge_ds_tag, expected_ephemeral_pub, &expected_voucher_id)
            .map_err(|e| e.to_string())?;

        let current_state = std::mem::replace(&mut self.state, AppState::Locked);

        let (result, new_state) = match current_state {
            AppState::Unlocked {
                mut storage,
                wallet,
                identity,
                session_cache,
            } => {
                let _lock_guard = match WalletLockGuard::new(&storage) {
                    Ok(guard) => guard,
                    Err(e) => {
                        self.state = AppState::Unlocked {
                            storage,
                            wallet,
                            identity,
                            session_cache,
                        };
                        return Err(e.to_string());
                    }
                };

                match action {
                    VerdictAction::ConfirmLocal => {
                        // Erfolgreich verankert, hier in Zukunft Status anpassen z.B. L2Confirmed
                        (
                            Ok(()),
                            AppState::Unlocked {
                                storage,
                                wallet,
                                identity,
                                session_cache,
                            },
                        )
                    }
                    VerdictAction::TriggerQuarantine(conflicting_t_id) => {
                        let mut temp_wallet = wallet.clone();
                        temp_wallet.update_voucher_status(
                            local_instance_id,
                            VoucherStatus::Quarantined {
                                reason: format!(
                                    "Double spend detected for transaction {}",
                                    conflicting_t_id
                                ),
                            },
                        );

                        // ... Auth logic ...
                        let auth_method = match password {
                            Some(pwd_str) => AuthMethod::Password(pwd_str),
                            None => {
                                match &session_cache {
                                    Some(cache) => {
                                        if std::time::Instant::now() > cache.last_activity + cache.session_duration {
                                            AuthMethod::SessionKey([0u8; 32])
                                        } else {
                                            AuthMethod::SessionKey(cache.session_key)
                                        }
                                    }
                                    None => AuthMethod::SessionKey([0u8; 32]),
                                }
                            }
                        };

                        if let AuthMethod::SessionKey(k) = auth_method {
                            if k == [0u8; 32] {
                                self.state = AppState::Unlocked {
                                    storage,
                                    wallet,
                                    identity,
                                    session_cache,
                                };
                                return Err("Session timed out or password required.".to_string());
                            }
                        }

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
                    VerdictAction::TriggerSync { sync_point } => {
                        // Hier würde die Synchronisations-Logik starten.
                        // Im Moment geben wir einen Fehler zurück, der die Sync-Notwendigkeit beschreibt,
                        // oder wir loggen es einfach.
                        println!("Sync needed from: {}", sync_point);
                        (
                            Ok(()),
                            AppState::Unlocked {
                                storage,
                                wallet,
                                identity,
                                session_cache,
                            },
                        )
                    }
                }
            }
            AppState::Locked => (Err("Wallet is locked".to_string()), AppState::Locked),
        };

        self.state = new_state;
        result
    }
}
