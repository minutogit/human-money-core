use crate::app_service::{AppService, AppState};
use crate::models::layer2_api::{L2AuthPayload, L2StatusQuery};
use crate::services::crypto_utils;
use crate::services::l2_gateway::{self, VerdictAction};
use crate::storage::{AuthMethod, WalletLockGuard};
use crate::wallet::instance::VoucherStatus;

impl AppService {
    /// Generiert einen L2LockRequest für den neuesten Stand eines lokalen Gutscheins.
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

        // TODO: In the future, derive a proper ephemeral key. For now, use dummy bytes.
        let ephemeral_key = [0u8; 32];

        let request = l2_gateway::generate_lock_request(
            &instance.voucher.voucher_id,
            transaction,
            &ephemeral_key,
        )
        .map_err(|e| e.to_string())?;

        serde_json::to_vec(&request).map_err(|e| e.to_string())
    }

    /// Generiert eine L2StatusQuery (Lese-Anfrage) für alle ds_tags eines Gutscheins.
    pub fn generate_l2_status_query(&self, local_instance_id: &str) -> Result<Vec<u8>, String> {
        let (wallet, _identity) = match &self.state {
            AppState::Unlocked { wallet, identity, .. } => (wallet, identity),
            _ => return Err("Wallet is locked".to_string()),
        };

        let instance = wallet
            .get_voucher_instance(local_instance_id)
            .ok_or_else(|| format!("Voucher {} not found", local_instance_id))?;

        let mut target_ds_tags = Vec::new();

        // 1. Genesis (Hash der voucher_id)
        let genesis_hash_str = crypto_utils::get_hash(instance.voucher.voucher_id.as_bytes());
        let mut genesis_ds_tag = [0u8; 32];
        let decoded = bs58::decode(&genesis_hash_str).into_vec().map_err(|_| "Invalid base58 for genesis ds_tag".to_string())?;
        if decoded.len() == 32 {
            genesis_ds_tag.copy_from_slice(&decoded);
            target_ds_tags.push(genesis_ds_tag);
        }

        // 2. Alle weiteren Transaktionen
        for tx in &instance.voucher.transactions {
            if tx.t_type != "init" {
                if let Some(td) = &tx.trap_data {
                    let mut ds_tag = [0u8; 32];
                    let decoded_tx_tag = bs58::decode(&td.ds_tag).into_vec().map_err(|_| "Invalid base58 in tx ds_tag".to_string())?;
                    if decoded_tx_tag.len() == 32 {
                        ds_tag.copy_from_slice(&decoded_tx_tag);
                        target_ds_tags.push(ds_tag);
                    }
                }
            }
        }

        // TODO: derive proper ephemeral key
        let ephemeral_key = [0u8; 32];
        let auth = L2AuthPayload {
            ephemeral_pubkey: ephemeral_key,
            auth_signature: None,
        };

        let query = L2StatusQuery {
            auth,
            target_ds_tags,
        };

        serde_json::to_vec(&query).map_err(|e| e.to_string())
    }

    /// Verarbeitet ein L2Verdict und führt die entsprechende Aktion auf dem Wallet aus.
    pub fn process_l2_response(
        &mut self,
        response_bytes: &[u8],
        password: Option<&str>,
    ) -> Result<(), String> {
        let server_pubkey = [0u8; 32]; // Dummy für den Moment

        let action = l2_gateway::process_l2_verdict(response_bytes, &server_pubkey)
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
                        let mut target_instance_id = None;
                        
                        for (id, instance) in &temp_wallet.voucher_store.vouchers {
                            if instance.voucher.transactions.iter().any(|t| t.t_id == conflicting_t_id) {
                                target_instance_id = Some(id.clone());
                                break;
                            }
                        }

                        if let Some(id) = target_instance_id {
                            temp_wallet.update_voucher_status(
                                &id,
                                VoucherStatus::Quarantined {
                                    reason: format!(
                                        "Double spend detected for transaction {}",
                                        conflicting_t_id
                                    ),
                                },
                            );

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
                        } else {
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
            }
            AppState::Locked => (Err("Wallet is locked".to_string()), AppState::Locked),
        };

        self.state = new_state;
        result
    }
}
