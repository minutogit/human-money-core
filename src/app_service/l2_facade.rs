use crate::app_service::{AppService, AppState, AppFacadeError};
use crate::models::layer2_api::{L2AuthPayload, L2StatusQuery};
use crate::services::l2_gateway::{self, VerdictAction};
use crate::storage::WalletLockGuard;
use crate::wallet::instance::VoucherStatus;
use crate::wallet::Wallet;

impl AppService {
    pub fn generate_l2_lock_request(&self, local_instance_id: &str) -> Result<Vec<u8>, AppFacadeError> {
        let (wallet, _identity) = match &self.state {
            AppState::Unlocked {
                wallet, identity, ..
            } => (wallet, identity),
            _ => return Err(AppFacadeError::WalletLocked("Wallet is locked".to_string())),
        };

        let instance = wallet
            .get_voucher_instance(local_instance_id)
            .ok_or_else(|| AppFacadeError::VoucherNotFound(local_instance_id.to_string()))?;

        let transaction = instance
            .voucher
            .transactions
            .last()
            .ok_or_else(|| AppFacadeError::ValidationError("No transactions found in voucher".to_string()))?;

        // In the new Layer 2 semantics, the voucher id is derived from the first (init) transaction.
        let l2_voucher_id =
            l2_gateway::calculate_layer2_voucher_id(&instance.voucher.transactions[0])
                .map_err(AppFacadeError::from)?;

        // TODO: In the future, derive a proper ephemeral key. For now, use dummy bytes.
        let ephemeral_key = [0u8; 32];
        let request =
            l2_gateway::generate_lock_request(&l2_voucher_id, transaction, &ephemeral_key)
                .map_err(AppFacadeError::from)?;

        serde_json::to_vec(&request).map_err(AppFacadeError::from)
    }

    /// Generates an L2StatusQuery (read query) for the current status of a voucher.
    pub fn generate_l2_status_query(&self, local_instance_id: &str) -> Result<Vec<u8>, AppFacadeError> {
        let (wallet, _identity) = match &self.state {
            AppState::Unlocked {
                wallet, identity, ..
            } => (wallet, identity),
            _ => return Err(AppFacadeError::WalletLocked("Wallet is locked".to_string())),
        };

        let instance = wallet
            .get_voucher_instance(local_instance_id)
            .ok_or_else(|| AppFacadeError::VoucherNotFound(local_instance_id.to_string()))?;

        let layer2_voucher_id =
            l2_gateway::calculate_layer2_voucher_id(&instance.voucher.transactions[0])
                .map_err(AppFacadeError::from)?;

        let challenge_ds_tag = if let Some(last_tx) = instance.voucher.transactions.last() {
            l2_gateway::derive_challenge_tag(last_tx).map_err(AppFacadeError::from)?
        } else {
            return Err(AppFacadeError::ValidationError("Voucher has no transactions".to_string()));
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

        serde_json::to_vec(&query).map_err(AppFacadeError::from)
    }

    /// Processes an L2Verdict and executes the corresponding action on the wallet.
    ///
    /// # SECURITY (WH3-00-904 / WH3-00-905): transactional discipline
    /// This is a PERSISTING command and therefore runs under the same
    /// discipline as every other mutating `AppService` command (mirroring
    /// `with_transactional_mut`):
    /// 1. Fork-lock verification.
    /// 2. State isolation (`Locked` swap) against panic-poisoned states.
    /// 3. Exclusive physical file lock (RAII).
    /// 4. Panic-free session resolution (`elapsed()` pattern — an extreme
    ///    host-supplied duration must never overflow `Instant` arithmetic).
    /// 5. UNCONDITIONAL Reload-Before-Write with seal-consistency gate: the
    ///    plaintext `.wallet.generation` marker alone is forgeable, so the
    ///    fresh disk state itself is reloaded and verified against the
    ///    cryptographic seal before any quarantine is anchored. A quarantine
    ///    is therefore never committed onto resurrected/rolled-back state.
    /// 6. Sealed commit: save + seal update with the same compensation
    ///    contract as the transactional orchestrator (a failed seal phase
    ///    restores the pre-write data instead of stranding a diverging store).
    pub fn process_l2_response(
        &mut self,
        local_instance_id: &str,
        response_bytes: &[u8],
        password: Option<&str>,
    ) -> Result<(), AppFacadeError> {
        // 1. Fork-lock check (same first gate as with_transactional_mut).
        self.check_fork_lock(password).map_err(AppFacadeError::from)?;

        // 2. Unpack state (temporarily replace with Locked).
        let current_state = std::mem::replace(&mut self.state, AppState::Locked);

        let (result, new_state) = match current_state {
            AppState::Unlocked {
                mut storage,
                wallet,
                identity,
                session_cache,
            } => {
                let (result, final_wallet) = Self::execute_l2_verdict_disciplined(
                    &mut storage,
                    wallet,
                    &identity,
                    &session_cache,
                    local_instance_id,
                    response_bytes,
                    password,
                );
                (
                    result,
                    AppState::Unlocked {
                        storage,
                        wallet: final_wallet,
                        identity,
                        session_cache,
                    },
                )
            }
            AppState::Locked => (
                Err(AppFacadeError::WalletLocked("Wallet is locked".to_string())),
                AppState::Locked,
            ),
        };

        self.state = new_state;
        result
    }

    /// Disciplined execution core of [`Self::process_l2_response`].
    ///
    /// Returns the operation result together with the wallet state to be
    /// published (the original RAM wallet on every failure path, the
    /// mutated wallet only after a verified, sealed commit).
    fn execute_l2_verdict_disciplined(
        storage: &mut crate::storage::file_storage::FileStorage,
        ram_wallet: crate::wallet::Wallet,
        identity: &crate::models::profile::UserIdentity,
        session_cache: &Option<super::SessionCache>,
        local_instance_id: &str,
        response_bytes: &[u8],
        password: Option<&str>,
    ) -> (Result<(), AppFacadeError>, crate::wallet::Wallet) {
        // 3. Physical file lock (RAII).
        let _lock_guard = match WalletLockGuard::new(storage) {
            Ok(guard) => guard,
            Err(e) => return (Err(AppFacadeError::from(e)), ram_wallet),
        };

        // 4. Panic-free authentication (WH3-00-904): resolve_auth_method
        // compares `last_activity.elapsed()` against the configured duration,
        // so extreme host-supplied durations can never overflow.
        let auth = match Self::resolve_auth_method(password, session_cache) {
            Ok(auth) => auth,
            Err(_) => {
                return (
                    Err(AppFacadeError::SessionExpired(
                        "Session timed out or password required.".to_string(),
                    )),
                    ram_wallet,
                )
            }
        };

        // 5. UNCONDITIONAL Reload-Before-Write + seal-consistency gate
        // (WH3-00-905). The plaintext generation marker alone is forgeable
        // (it would defeat a generation-mismatch-triggered reload), so the
        // fresh disk state itself is reloaded and verified against the
        // cryptographic seal BEFORE any quarantine decision is anchored.
        let (mut fresh_wallet, _) =
            match Wallet::load(storage, &auth, ram_wallet.local_instance_id.clone()) {
                Ok(loaded) => loaded,
                Err(e) => {
                    return (
                        Err(AppFacadeError::ValidationError(format!(
                            "Failed to reload wallet before L2 write: {}",
                            e
                        ))),
                        ram_wallet,
                    )
                }
            };
        if let Err(gate_err) = Self::verify_state_matches_seal(storage, &auth, &fresh_wallet) {
            return (Err(gate_err), ram_wallet);
        }

        // Preserve the LIVE-SESSION L2 trust anchor across the mandatory
        // reload: `l2_server_pubkey` may have been configured on the
        // in-memory profile by the host application without an intermediate
        // persist. It is owner-controlled session configuration, NOT part of
        // the rolled-back disk content under attack here; every persisted-
        // content integrity gate above stays fully enforced on the fresh
        // state (the seal check has already passed at this point).
        if ram_wallet.profile.l2_server_pubkey.is_some() {
            fresh_wallet.profile.l2_server_pubkey = ram_wallet.profile.l2_server_pubkey;
        }

        // Carry unsaved UI events from the live session into the adopted
        // state so a reload cannot silently drop pending history; events
        // emitted by the load's own sweeps are appended after them.
        fresh_wallet.pending_events = {
            let mut events = ram_wallet.pending_events;
            events.append(&mut fresh_wallet.pending_events);
            events
        };

        // Re-derive the verdict against the SEAL-VERIFIED fresh state so a
        // quarantine can never be anchored onto stale expectations.
        let action = match Self::evaluate_l2_action(&fresh_wallet, local_instance_id, response_bytes)
        {
            Ok(action) => action,
            Err(e) => return (Err(e), fresh_wallet),
        };

        match action {
            VerdictAction::ConfirmLocal => {
                // Successfully anchored, update status in the future e.g. L2Confirmed.
                (Ok(()), fresh_wallet)
            }
            VerdictAction::TriggerSync { sync_point } => {
                // This is where the synchronization logic would start.
                // For now, we return an error describing the sync requirement,
                // or we simply log it.
                println!("Sync needed from: {}", sync_point);
                (Ok(()), fresh_wallet)
            }
            VerdictAction::TriggerQuarantine(conflicting_t_id) => {
                let mut temp_wallet = fresh_wallet.clone();
                temp_wallet.update_voucher_status(
                    local_instance_id,
                    VoucherStatus::Quarantined {
                        reason: format!(
                            "Double spend detected for transaction {}",
                            conflicting_t_id
                        ),
                    },
                );

                if let Err(e) = temp_wallet.save(storage, identity, &auth) {
                    return (Err(AppFacadeError::from(e)), fresh_wallet);
                }

                // Sealed commit (Wave-2 contract): advance the seal BEFORE
                // publishing the new state. If the seal phase fails after the
                // data was persisted, compensate by restoring the pre-write
                // data so disk matches the untouched seal again — identical
                // to the with_transactional_mut Commit arm.
                if let Err(seal_err) =
                    Self::persist_seal_for_wallet_state(storage, identity, &auth, &temp_wallet)
                {
                    let restored =
                        Self::compensate_failed_seal_phase(storage, &fresh_wallet, identity, &auth);
                    return (Err(seal_err), restored);
                }

                (Ok(()), temp_wallet)
            }
        }
    }

    /// Evaluates the L2 verdict against the given (verified) wallet state.
    fn evaluate_l2_action(
        wallet: &crate::wallet::Wallet,
        local_instance_id: &str,
        response_bytes: &[u8],
    ) -> Result<VerdictAction, AppFacadeError> {
        let instance = wallet
            .get_voucher_instance(local_instance_id)
            .ok_or_else(|| AppFacadeError::VoucherNotFound(local_instance_id.to_string()))?;

        let last_tx = instance.voucher.transactions.last().ok_or_else(|| {
            AppFacadeError::ValidationError("No transactions found".to_string())
        })?;
        let last_t_id = last_tx.t_id.clone();
        let challenge_ds_tag =
            l2_gateway::derive_challenge_tag(last_tx).map_err(AppFacadeError::from)?;
        let expected_ephemeral_pub = last_tx.sender_ephemeral_pub.as_deref();
        let expected_voucher_id =
            l2_gateway::calculate_layer2_voucher_id(&instance.voucher.transactions[0])
                .map_err(AppFacadeError::from)?;

        let server_pubkey = wallet.profile.l2_server_pubkey.ok_or_else(|| {
            AppFacadeError::ValidationError(
                "L2 server public key not configured in wallet profile".to_string(),
            )
        })?;

        l2_gateway::process_l2_verdict(
            response_bytes,
            &server_pubkey,
            &last_t_id,
            &challenge_ds_tag,
            expected_ephemeral_pub,
            &expected_voucher_id,
        )
        .map_err(AppFacadeError::from)
    }
}
