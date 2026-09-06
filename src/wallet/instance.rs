//! # src/wallet/instance.rs
//!
//! Defines the core data structures for managing
//! voucher instances within the wallet.

use crate::error::VoucherCoreError;
use crate::models::voucher::Voucher;
use crate::services::crypto::get_hash;
use crate::wallet::Wallet;
use serde::{Deserialize, Serialize};

/// Captures the exact, user-remediable reason why a voucher
/// is classified as incomplete (`Incomplete`).
/// This allows the user interface to display a precise to-do list.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ValidationFailureReason {
    /// A business rule from the standard has not yet been satisfied.
    BusinessRule {
        message: String,
    },
    /// The number of additional signatures is too low.
    AdditionalSignatureCountLow { required: u32, current: u32 },
    /// A specific signature required by the standard is missing.
    RequiredSignatureMissing { role_description: String },
    // Extensible in the future for other fixable validation errors.
}

/// Represents the high-level lifecycle state of a voucher in the wallet.
/// This status is not stored in the voucher itself, but is
/// metadata managed by the wallet.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub enum VoucherStatus {
    /// The voucher is structurally valid, but does not yet satisfy all
    /// validation rules of the standard (e.g. missing signatures).
    Incomplete {
        reasons: Vec<ValidationFailureReason>,
    },
    /// The voucher is fully valid and can be used for transactions.
    #[default]
    Active,
    /// The voucher was completely spent or transferred to another user.
    /// It is kept only for historical purposes.
    Archived,
    /// The voucher was locked due to a fatal validation error or a
    /// verified double-spend conflict. It can no longer be used.
    Quarantined { reason: String },
    /// The voucher was signed by the user as a third party (e.g. as guarantor or notary).
    /// The voucher does not belong to the user, but is archived as an audit log for
    /// social commitments entered into.
    Endorsed { role: String },
    /// The validity period (`valid_until`) of the voucher has expired.
    /// It can no longer be used for transactions.
    Expired,
}

/// Serves as a wrapper in the wallet combining raw `Voucher` data with its
/// managed status and other wallet-internal metadata.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct VoucherInstance {
    /// Full voucher data.
    pub voucher: Voucher,
    /// Current lifecycle status of this voucher in the wallet.
    pub status: VoucherStatus,
    /// A unique local ID for this instance, serving as the key in `VoucherStore`.
    pub local_instance_id: String,
    // DEPRECATED: `current_secret_seed` was removed because we now operate statelessly.
    // The seed is re-derived from Voucher + Identity on demand.
    // #[serde(default, skip_serializing_if = "Option::is_none")]
    // pub current_secret_seed: Option<String>,
}

impl Wallet {
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
        let event_info = if let Some(instance) = self.voucher_store.vouchers.get_mut(local_instance_id) {
            let old_status = std::mem::replace(&mut instance.status, new_status.clone());

            // Event logging on important status changes
            let event_type = match (&old_status, &new_status) {
                // From Incomplete to Active
                (VoucherStatus::Incomplete { .. }, VoucherStatus::Active) => {
                    Some(crate::models::wallet_event::WalletEventType::VoucherActivated)
                }
                // Freshly quarantined (unless already quarantined before)
                (_, VoucherStatus::Quarantined { .. })
                    if !matches!(old_status, VoucherStatus::Quarantined { .. }) =>
                {
                    Some(crate::models::wallet_event::WalletEventType::VoucherQuarantined)
                }
                _ => None,
            };

            if let Some(et) = event_type {
                let voucher = &instance.voucher;
                let bff_data = crate::models::wallet_event::EventBffData {
                    display_currency: crate::wallet::format_bff_name(
                        voucher.nominal_value.abbreviation.as_deref().unwrap_or(&voucher.nominal_value.unit),
                        voucher.non_redeemable_test_voucher,
                    ),
                    amount: voucher.nominal_value.amount.clone(),
                    is_test_voucher: voucher.non_redeemable_test_voucher,
                    counterparty_id: None,
                    counterparty_name: None,
                };
                Some((et, voucher.voucher_id.clone(), bff_data))
            } else {
                None
            }
        } else {
            None
        };

        if let Some((et, voucher_id, bff_data)) = event_info {
            self.emit_event(
                et,
                local_instance_id,
                &voucher_id,
                bff_data,
            );
        }
    }

    /// Computes a deterministic, local ID for a voucher instance.
    pub fn calculate_local_instance_id(
        voucher: &Voucher,
        profile_owner_id: &str,
    ) -> Result<String, VoucherCoreError> {
        let mut defining_transaction_id: Option<String> = None;

        // The defining transaction is simply the last one in which the user
        // appears as sender or recipient.
        // NOTE: In Privacy Mode, recipient_id="anonymous". We accept this
        // as a match for the current profile owner (profile_owner_id), since
        // actual receipt authorization was already verified during bundle decryption.
        for tx in voucher.transactions.iter().rev() {
            if tx.recipient_id == profile_owner_id
                || tx.recipient_id == crate::models::voucher::ANONYMOUS_ID
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
}

