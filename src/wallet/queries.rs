//! # src/wallet/queries.rs
//!
//! Contains the implementation of `Wallet` methods that serve as "view-models".
//! They prepare data for display in client applications.

use super::types::format_bff_name;
use super::{AggregatedBalance, AssetClass, VoucherDetails, VoucherSummary, Wallet};
use crate::archive::FileVoucherArchive;
use crate::error::VoucherCoreError;
use crate::models::voucher::{Transaction, Voucher};
use crate::services::jws_profile_service::export_profile_as_jws;
use crate::wallet::instance::{VoucherInstance, VoucherStatus};
use rust_decimal::Decimal;
use rust_decimal::prelude::Zero;
use std::collections::HashMap;
use std::str::FromStr;

/// View-model / convenience functions for client applications.
impl Wallet {
    /// Returns a list of summaries of all vouchers in the wallet.
    ///
    /// This method is ideal for displaying an overview of all balances in a UI.
    ///
    /// # Returns
    /// A `Vec<VoucherSummary>` containing the key data of each voucher.
    pub fn list_vouchers(
        &self,
        identity: Option<&crate::models::profile::UserIdentity>,
        voucher_standard_uuid_filter: Option<&[String]>,
        status_filter: Option<&[VoucherStatus]>,
        test_filter: Option<bool>,
    ) -> Vec<VoucherSummary> {
        self.voucher_store
            .vouchers
            .iter()
            .filter(|(_, instance)| {
                let uuid_match = match voucher_standard_uuid_filter {
                    // If a list of UUIDs is present and not empty, check if the voucher's UUID is contained.
                    Some(uuids) if !uuids.is_empty() => {
                        uuids.contains(&instance.voucher.voucher_standard.uuid)
                    }
                    // If no list or an empty list is passed, the filter is considered satisfied.
                    _ => true,
                };

                let status_match = match status_filter {
                    // Same logic for the status filter.
                    Some(statuses) if !statuses.is_empty() => statuses.contains(&instance.status),
                    _ => true,
                };

                let test_match = match test_filter {
                    Some(is_test) => instance.voucher.non_redeemable_test_voucher == is_test,
                    None => true,
                };

                uuid_match && status_match && test_match
            })
            .map(|(local_id, instance)| {
                let voucher = &instance.voucher;

                // --- Balance calculation ---
                let current_amount = if matches!(instance.status, VoucherStatus::Archived)
                    || matches!(instance.status, VoucherStatus::Endorsed { .. })
                    || matches!(instance.status, VoucherStatus::Expired)
                {
                    "0".to_string()
                } else {
                    // Try to calculate holder hash (Stateless Re-Derivation)
                    let holder_pub_hash = identity.and_then(|id| {
                         self.rederive_secret_seed(voucher, id).ok()
                    }).map(|key| {
                        crate::services::crypto::get_hash(key.verifying_key().to_bytes())
                    });

                    // Use core service for precise calculation
                    // Fallback: If no identity is available, get_spendable_balance uses public-mode logic.
                    let _standard = crate::models::voucher_standard_definition::VoucherStandardDefinition::default(); // Dummy for decimal places (actually loaded in SM)
                    // NOTE: In a real environment, the actual standard would need to be loaded here.
                    // Since get_spendable_balance uses Decimal::from_str, this is often sufficient for display.
                    
                    // TODO: In an ideal world we load the real standard here.
                    // For the summary list we use simplified logic or the last_tx field directly.
                    
                    voucher.transactions.last().map(|tx| {
                         let is_own_sender = if let Some(id) = identity {
                             tx.sender_id.as_ref() == Some(&id.user_id)
                         } else {
                             tx.sender_id.is_some() // Public mode heuristic
                         };

                         // Prefer cryptographic check
                         if let Some(hash) = &holder_pub_hash {
                             if Some(hash) == tx.receiver_ephemeral_pub_hash.as_ref() {
                                 tx.amount.clone()
                             } else if Some(hash) == tx.change_ephemeral_pub_hash.as_ref() {
                                 tx.sender_remaining_amount.clone().unwrap_or_else(|| "0".to_string())
                             } else {
                                 "0".to_string()
                             }
                         } else {
                             // Classic heuristic for backwards compatibility / public mode
                             if is_own_sender && tx.sender_remaining_amount.is_some() {
                                 tx.sender_remaining_amount.clone().unwrap_or_else(|| "0".to_string())
                             } else {
                                 tx.amount.clone()
                             }
                         }
                    }).unwrap_or_else(|| "0".to_string())
                };

                VoucherSummary {
                    local_instance_id: local_id.clone(),
                    status: instance.status.clone(),
                    creator_id: voucher.creator_profile.id.clone().unwrap_or_default(),
                    valid_until: voucher.valid_until.clone(),
                    current_amount,
                    unit: voucher
                        .nominal_value
                        .abbreviation
                        .clone()
                        .unwrap_or_default(),
                    raw_standard_name: voucher.voucher_standard.name.clone(),
                    voucher_standard_uuid: voucher.voucher_standard.uuid.clone(),
                    // Count transactions excluding initial "init" transaction.
                    transaction_count: (voucher.transactions.len() as u32).saturating_sub(1),
                    signatures_count: voucher.signatures.len() as u32,
                    // A voucher is considered collateralized if the `collateral` object exists and has a `collateral_type`.
                    has_collateral: voucher.collateral.is_some(),
                    creator_first_name: voucher
                        .creator_profile
                        .first_name
                        .clone()
                        .unwrap_or_default(),
                    creator_last_name: voucher
                        .creator_profile
                        .last_name
                        .clone()
                        .unwrap_or_default(),
                    creator_coordinates: voucher
                        .creator_profile
                        .coordinates
                        .clone()
                        .unwrap_or_default(),
                    is_test_voucher: voucher.non_redeemable_test_voucher,
                    display_currency: format_bff_name(
                        voucher
                            .nominal_value
                            .abbreviation
                            .as_deref()
                            .unwrap_or(&voucher.nominal_value.unit),
                        voucher.non_redeemable_test_voucher,
                    ),
                    display_standard_name: format_bff_name(
                        &voucher.voucher_standard.name,
                        voucher.non_redeemable_test_voucher,
                    ),
                }
            })
            .collect()
    }

    /// Retrieves a detailed view for a single voucher by its local ID.
    ///
    /// # Arguments
    /// * `local_instance_id` - The local ID of the voucher in the wallet.
    ///
    /// # Returns
    /// A `Result` with `VoucherDetails` on success, or `VoucherCoreError` if
    /// the voucher is not found.
    pub fn get_voucher_details(
        &self,
        local_instance_id: &str,
    ) -> Result<VoucherDetails, VoucherCoreError> {
        // 1. Direct lookup (performance path)
        let instance = if let Some(inst) = self.voucher_store.vouchers.get(local_instance_id) {
            inst
        } else {
            // 2. Fuzzy search (fallback for historical IDs from logs)
            // Iterate over all existing vouchers and check whether the searched ID
            // could be a historical 'local_instance_id' of this voucher.
            self.voucher_store.vouchers.values().find(|inst| {
                inst.voucher.transactions.iter().any(|tx| {
                    // Check whether the user participated in this transaction
                    if tx.recipient_id == self.profile.user_id
                        || tx.recipient_id == crate::models::voucher::ANONYMOUS_ID
                        || tx.sender_id.as_deref() == Some(&self.profile.user_id)
                    {
                        // Calculate the historical ID that would have corresponded to this transaction.
                        // The ID is based on voucher_id + transaction_id + user_id.
                        let historical_id = crate::services::crypto::get_hash(format!(
                            "{}{}{}",
                            inst.voucher.voucher_id, tx.t_id, self.profile.user_id
                        ));
                        historical_id == local_instance_id
                    } else {
                        false
                    }
                })
            }).ok_or_else(|| crate::error::VoucherCoreError::VoucherNotFound(local_instance_id.to_string()))?
        };

        Ok(VoucherDetails {
            local_instance_id: instance.local_instance_id.clone(),
            status: instance.status.clone(),
            voucher: instance.voucher.clone(),
            display_currency: format_bff_name(
                instance
                    .voucher
                    .nominal_value
                    .abbreviation
                    .as_deref()
                    .unwrap_or(&instance.voucher.nominal_value.unit),
                instance.voucher.non_redeemable_test_voucher,
            ),
            display_standard_name: format_bff_name(
                &instance.voucher.voucher_standard.name,
                instance.voucher.non_redeemable_test_voucher,
            ),
            is_test_voucher: instance.voucher.non_redeemable_test_voucher,
        })
    }

    /// Determines the identity of the sender from whom we received this voucher.
    /// Iterates backward through all transactions and finds the first transaction
    /// whose actual sender is not the current user.
    pub fn get_voucher_source_sender(
        &self,
        local_instance_id: &str,
        identity: &crate::models::profile::UserIdentity,
    ) -> Result<Option<String>, VoucherCoreError> {
        let instance = self
            .voucher_store
            .vouchers
            .get(local_instance_id)
            .ok_or_else(|| VoucherCoreError::VoucherNotFound(local_instance_id.to_string()))?;

        // Iterate backward through all transactions of the voucher
        for tx in instance.voucher.transactions.iter().rev() {
            // Determine the actual sender of this transaction
            let actual_sender = if let Some(guard_base64) = &tx.privacy_guard {
                // Case A: privacy_guard present
                // Attempt to decrypt. If successful, use payload.sender_permanent_did.
                // If decryption fails (e.g. key unavailable), abort and return Ok(None)!
                match crate::services::crypto::decrypt_recipient_payload(
                    guard_base64,
                    &identity.signing_key,
                    &identity.user_id,
                ) {
                    Ok(decrypted_payload_bytes) => {
                        match serde_json::from_slice::<crate::models::voucher::RecipientPayload>(
                            &decrypted_payload_bytes,
                        ) {
                            Ok(payload) => payload.sender_permanent_did,
                            Err(_) => {
                                // JSON parsing failed - insecure state
                                return Ok(None);
                            }
                        }
                    }
                    Err(_) => {
                        // SECURITY CHECK: Distinguish between outbound and inbound.
                        // If we are the SENDER (e.g. we sent a split),
                        // it is expected that we cannot read the guard (for the other recipient).
                        let is_sender = tx.sender_id.as_deref() == Some(&identity.user_id);
                        
                        // If we are the RECIPIENT (explicit or anonymous) but cannot decrypt,
                        // there is a data/key issue with a transaction addressed to us.
                        let is_recipient = tx.recipient_id == identity.user_id || tx.recipient_id == crate::models::voucher::ANONYMOUS_ID;

                        if is_sender {
                            continue; // Outbound -> Continue search
                        } else if is_recipient {
                            // Inbound, but unreadable -> Abort (spoofing protection)
                            return Ok(None);
                        } else {
                            // Neither (e.g. a historical intermediate transaction) -> Continue search
                            continue;
                        }
                    }
                }
            } else {
                // Case B: No guard present (Public Mode)
                // Use plaintext tx.sender_id
                match &tx.sender_id {
                    Some(sender) => sender.clone(),
                    None => continue, // No sender_id, skip this transaction
                }
            };

            // If the actual sender is not the current user, we have found our source
            if actual_sender != identity.user_id {
                return Ok(Some(actual_sender));
            }
        }

        // No matching transaction found
        Ok(None)
    }

    /// Aggregates the balances of all active vouchers, grouped by currency/unit.
    ///
    /// This function sums up the values of all vouchers with status `Active`
    /// and returns a list mapping currency units (e.g. "Minutes", "EUR")
    /// to the total amount.
    ///
    /// # Returns
    /// A `Vec<AggregatedBalance>` containing total amounts per voucher standard and currency.
    pub fn get_total_balance_by_currency(
        &self,
        identity: Option<&crate::models::profile::UserIdentity>,
    ) -> Vec<AggregatedBalance> {
        // Key: AssetClass (standard_uuid, unit_abbreviation, is_test_voucher)
        // Value: (total_amount, standard_name)
        let mut balances: HashMap<AssetClass, (Decimal, String)> = HashMap::new();

        for instance in self.voucher_store.vouchers.values() {
            if matches!(instance.status, VoucherStatus::Active) {
                let voucher = &instance.voucher;
                let amount_str = instance
                    .voucher
                    .transactions
                    .last()
                    .map(|tx| {
                        // Prefer cryptographic check
                        if let Some(id) = identity
                            && let Ok(key) = self.rederive_secret_seed(voucher, id)
                        {
                            let hash = crate::services::crypto::get_hash(key.verifying_key().to_bytes());
                            if Some(&hash) == tx.receiver_ephemeral_pub_hash.as_ref() {
                                return tx.amount.clone();
                            } else if Some(&hash) == tx.change_ephemeral_pub_hash.as_ref() {
                                return tx.sender_remaining_amount.clone().unwrap_or_else(|| "0".to_string());
                            }
                        }

                        // Fallback: Heuristic
                        if tx.sender_id.as_ref() == Some(&self.profile.user_id)
                            && tx.sender_remaining_amount.is_some()
                        {
                            tx.sender_remaining_amount
                                .clone()
                                .unwrap_or_else(|| "0".to_string())
                        } else {
                            // Otherwise it is the full transaction amount.
                            tx.amount.clone()
                        }
                    })
                    .unwrap_or_else(|| "0".to_string());

                if let Ok(amount) = Decimal::from_str(&amount_str) {
                    // Skip vouchers with zero balance.
                    if amount.is_zero() {
                        continue;
                    }

                    let asset_class = AssetClass {
                        standard_uuid: voucher.voucher_standard.uuid.clone(),
                        unit: voucher
                            .nominal_value
                            .abbreviation
                            .clone()
                            .unwrap_or_else(|| voucher.nominal_value.unit.clone()),
                        is_test_voucher: voucher.non_redeemable_test_voucher,
                    };

                    let entry = balances.entry(asset_class).or_insert_with(|| {
                        (
                            Decimal::zero(),
                            voucher.voucher_standard.name.clone(),
                        )
                    });
                    // Use saturating_add to avoid panic on overflow (AUDIT-00-WILDCARD-10)
                    entry.0 = entry.0.saturating_add(amount);
                }
            }
        }

        balances
            .into_iter()
            .map(|(key, (total, standard_name))| {
                let display_currency = format_bff_name(&key.unit, key.is_test_voucher);
                let display_standard_name = format_bff_name(&standard_name, key.is_test_voucher);

                AggregatedBalance {
                    standard_uuid: key.standard_uuid,
                    standard_name,
                    unit: key.unit,
                    total_amount: total.to_string(),
                    display_currency,
                    display_standard_name,
                    is_test_voucher: key.is_test_voucher,
                }
            })
            .collect()
    }

    /// Determines all active asset classes in the wallet (standard + test status).
    /// Serves the UI for properly populating filter dropdowns.
    pub fn get_active_asset_classes(&self) -> Vec<super::types::AssetClassSummary> {
        let mut classes = std::collections::HashSet::new();

        for instance in self.voucher_store.vouchers.values() {
            if matches!(instance.status, VoucherStatus::Active) {
                let voucher = &instance.voucher;
                let unit = voucher
                    .nominal_value
                    .abbreviation
                    .clone()
                    .unwrap_or_else(|| voucher.nominal_value.unit.clone());
                
                let is_test = voucher.non_redeemable_test_voucher;
                
                classes.insert(super::types::AssetClassSummary {
                    standard_uuid: voucher.voucher_standard.uuid.clone(),
                    is_test_voucher: is_test,
                    display_standard_name: super::format_bff_name(&voucher.voucher_standard.name, is_test),
                    display_currency: super::format_bff_name(&unit, is_test),
                });
            }
        }

        classes.into_iter().collect()
    }

    /// Returns the user ID of the wallet owner.
    ///
    /// # Returns
    /// A reference to the user ID string.
    pub fn get_user_id(&self) -> &str {
        &self.profile.user_id
    }

    /// Checks the reputation of a user ID based on locally stored proofs.
    ///
    /// This function implements the implicit Web-of-Trust. It searches the
    /// `proof_store` for unresolved conflicts caused by `user_id`.
    pub fn check_reputation(&self, offender_id: &str) -> crate::models::conflict::TrustStatus {
        self.check_reputation_with_provider(offender_id, None)
    }

    /// Checks reputation with an optional external [`crate::services::trust_provider::TrustProvider`].
    ///
    /// Evaluation order (local-first):
    /// 1. Scan `proof_store` for unresolved conflicts (existing semantics).
    /// 2. If the local result is `Clean` and a provider is supplied, delegate
    ///    to `provider.check_reputation(offender_id)`.
    /// 3. Otherwise return the local verdict.
    ///
    /// This keeps the core WASM-compatible and dependency-free while allowing
    /// the `humoco-web-of-trust` crate to plug in graph-based scoring without
    /// modifying core.
    pub fn check_reputation_with_provider(
        &self,
        offender_id: &str,
        provider: Option<&dyn crate::services::trust_provider::TrustProvider>,
    ) -> crate::models::conflict::TrustStatus {
        use crate::models::conflict::TrustStatus;

        let mut latest_resolved = None;

        for entry in self.proof_store.proofs.values() {
            if entry.proof.offender_id == offender_id {
                let is_officially_resolved = entry.proof.resolutions.as_ref().is_some_and(|r| !r.is_empty())
                    || entry.proof.layer2_verdict.is_some();

                if is_officially_resolved || entry.local_override {
                    // Remember the latest resolved one in case no unresolved proof is found.
                    latest_resolved = Some(TrustStatus::Resolved {
                        proof_id: entry.proof.proof_id.clone(),
                        is_local: entry.local_override,
                        note: entry.local_note.clone(),
                    });
                } else {
                    // As soon as ONE unresolved proof is found, status is "KnownOffender".
                    return TrustStatus::KnownOffender(entry.proof.proof_id.clone());
                }
            }
        }

        if let Some(local) = latest_resolved {
            return local;
        }

        // Local is Clean -> delegate to WoT provider if present.
        if let Some(p) = provider {
            return p.check_reputation(offender_id);
        }

        TrustStatus::Clean
    }

    /// Exports own profile as a JWS Compact Serialization string.
    ///
    /// This follows RFC 7515 and produces a string in the format:
    /// base64url(header).base64url(payload).base64url(signature)
    ///
    /// # Arguments
    /// * `identity` - The UserIdentity containing the private signing key.
    ///
    /// # Returns
    /// A JWS compact string or an error.
    pub fn export_profile_jws(
        &self,
        identity: &crate::models::profile::UserIdentity,
    ) -> Result<String, VoucherCoreError> {
        let public_profile = self.profile.to_public_profile();
        export_profile_as_jws(&identity.signing_key, &public_profile)
    }

    /// Loads the event history of the wallet, combining persistent and RAM-based events.
    ///
    /// # Arguments
    /// * `storage` - The storage backend.
    /// * `auth` - The authentication method.
    /// * `offset` - The offset for pagination.
    /// * `limit` - The maximum number of events to return.
    ///
    /// # Returns
    /// A chronologically descending sorted list of `WalletEvent` objects.
    pub fn get_event_history(
        &self,
        storage: &crate::storage::FileStorage,
        auth: &crate::storage::AuthMethod,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<crate::models::wallet_event::WalletEvent>, VoucherCoreError> {
        let pending_len = self.pending_events.len();
        let mut result = Vec::with_capacity(limit);

        // 1. Fetch newest events first from RAM (pending_events are ascending, so rev())
        if offset < pending_len {
            let to_take = std::cmp::min(limit, pending_len - offset);
            let pending_page = self.pending_events.iter()
                .rev() // Converts ascending -> descending (newest first)
                .skip(offset)
                .take(to_take)
                .cloned();
            result.extend(pending_page);
        }

        // 2. If we haven't reached the limit, populate with storage events
        if result.len() < limit {
            let remaining_limit = limit - result.len();
            
            // Calculate the correct offset for storage.
            // If user offset is larger than what we have in RAM,
            // subtract the RAM size from the offset.
            let storage_offset = offset.saturating_sub(pending_len);

            // Here we pass the ACTUAL limit and offset! Chunking is optimally utilized.
            let persisted_page = storage
                .load_events(auth, storage_offset, remaining_limit)
                .map_err(VoucherCoreError::Storage)?;

            result.extend(persisted_page);
        }

        Ok(result)
    }

    /// Searches for a transaction by its ID (`t_id`), first in the active
    /// `voucher_store` and then in the `FileVoucherArchive` (if provided).
    pub(super) fn find_transaction_in_stores(
        &self,
        t_id: &str,
        archive: Option<&FileVoucherArchive>,
    ) -> Result<Option<Transaction>, VoucherCoreError> {
        // Search active store first
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

        // Then search archive if provided
        if let Some(archive) = archive {
            let result = archive.find_transaction_by_id(t_id)?;
            return Ok(result.map(|(_, tx)| tx));
        }

        Ok(None)
    }

    /// Searches for a voucher by a contained transaction ID (`t_id`).
    /// Searches first the active `voucher_store` and then the `FileVoucherArchive` (if provided).
    pub(super) fn find_voucher_for_transaction(
        &self,
        t_id: &str,
        archive: Option<&FileVoucherArchive>,
    ) -> Result<Option<Voucher>, VoucherCoreError> {
        // Search active store first
        for instance in self.voucher_store.vouchers.values() {
            if instance.voucher.transactions.iter().any(|t| t.t_id == t_id) {
                return Ok(Some(instance.voucher.clone()));
            }
        }

        // Then search archive if provided
        if let Some(archive) = archive {
            return Ok(archive.find_voucher_by_tx_id(t_id)?);
        }

        Ok(None)
    }

    /// Finds the local ID and status of a voucher by a contained transaction ID.
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

