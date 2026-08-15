//! # src/wallet/instance.rs
//!
//! Defines the core data structures for managing
//! voucher instances within the wallet.

use crate::models::voucher::Voucher;
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

