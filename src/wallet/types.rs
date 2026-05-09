//! # src/wallet/types.rs
//!
//! Defines public data structures (structs) that serve as "view models"
//! or data containers for the wallet's API interaction.

use crate::models::conflict::TransactionFingerprint;
use crate::models::profile::TransactionBundleHeader;
use crate::models::voucher::Voucher;
use crate::wallet::instance::VoucherStatus;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Internal helper function to format names for the user interface (BFF pattern).
/// Ensures that test vouchers receive a consistent "TEST-" prefix.
pub(crate) fn format_bff_name(raw_name: &str, is_test: bool) -> String {
    if is_test && !raw_name.starts_with("TEST-") {
        format!("TEST-{}", raw_name)
    } else {
        raw_name.to_string()
    }
}

/// Describes a partial transfer from a specific source voucher.
/// Used to define sources (local ID and amount) for a multi-transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceTransfer {
    /// The local ID of the voucher from which an amount should be deducted.
    pub local_instance_id: String,
    /// The amount to be deducted from this voucher, as a string.
    pub amount_to_send: String,
}

/// The aggregated request for the universal transfer command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiTransferRequest {
    /// The recipient's user ID.
    pub recipient_id: String,
    /// A list of source vouchers and the amounts to be sent from each (1 to N).
    pub sources: Vec<SourceTransfer>,
    /// Optional notes for the bundle.
    pub notes: Option<String>,
    /// Optional sender profile name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_profile_name: Option<String>,
    /// Optional: Force or disable privacy mode (only for 'Flexible' standards).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_privacy_mode: Option<bool>,
}

/// Summarizes the results of a transfer per standard.
/// Key: Currency unit (e.g., "Minuto"), Value: Sum as a string (divisible) or count (non-divisible).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct TransferSummary {
    /// Aggregated amounts for divisible/summable vouchers (e.g., "10.50 Minuto").
    /// Key: Currency unit (e.g., "Minuto"), Value: Sum as a string.
    #[serde(default)]
    pub summable_amounts: HashMap<String, String>,
    /// Counted units for non-divisible/non-summable vouchers (e.g., "3 loaves").
    /// Key: Currency unit (e.g., "Bread"), Value: Count.
    #[serde(default)]
    pub countable_items: HashMap<String, u32>,
}

/// The result of processing an incoming transaction bundle.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ProcessBundleResult {
    pub header: TransactionBundleHeader,
    pub check_result: DoubleSpendCheckResult,
    /// Detailed summary of transferred values (sums and counters).
    #[serde(default)]
    pub transfer_summary: TransferSummary,
    /// List of local IDs of vouchers created or updated in the recipient's
    /// wallet by this transfer.
    #[serde(default)]
    pub involved_vouchers: Vec<String>,
    /// Detailed breakdown of each received voucher.
    #[serde(default)]
    pub involved_vouchers_details: Vec<InvolvedVoucherInfo>,
}

/// The result of a double-spend check.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct DoubleSpendCheckResult {
    pub verifiable_conflicts: HashMap<String, Vec<TransactionFingerprint>>,
    pub unverifiable_warnings: HashMap<String, Vec<TransactionFingerprint>>,
}

/// Contains detailed information about a single voucher involved in a
/// transaction (sending or receiving).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct InvolvedVoucherInfo {
    /// The local ID of the voucher instance in the user's wallet.
    pub local_instance_id: String,
    /// The global, immutable ID of the voucher.
    pub voucher_id: String,
    /// Human-readable name of the standard (e.g., "Minuto Voucher").
    pub standard_name: String,
    /// Currency unit (e.g., "Minuto", "Gram").
    pub unit: String,
    /// Amount sent or received from this voucher.
    pub amount: String,
    /// Indicates if the voucher is divisible.
    pub allow_partial_transfers: bool,
    /// Indicates if it is a test voucher.
    pub is_test_voucher: bool,
    /// Formatted currency for display (e.g., "TEST-Minuto").
    pub display_currency: String,
    /// Formatted standard name for display.
    pub display_standard_name: String,
}

/// The result of creating a transfer bundle.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct CreateBundleResult {
    /// Serialized bytes of the SecureContainer, ready for sending.
    pub bundle_bytes: Vec<u8>,
    /// Unique ID of the created bundle.
    pub bundle_id: String,
    /// Detailed breakdown of each source voucher used in the transaction.
    #[serde(default)]
    pub involved_sources_details: Vec<InvolvedVoucherInfo>,
}

/// A report summarizing the results of storage cleanup.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CleanupReport {
    pub expired_fingerprints_removed: usize,
    pub limit_based_fingerprints_removed: usize,
    pub archived_items_removed: usize,
}

/// Serves as a type-safe key for aggregating balances.
/// Distinguishes assets by standard, unit, and test status.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct AssetClass {
    pub standard_uuid: String,
    pub unit: String,
    pub is_test_voucher: bool,
}

/// Represents an aggregated balance for a specific voucher standard and currency unit.
/// Used to create a summary dashboard view of balances.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct AggregatedBalance {
    /// Name of the voucher standard (e.g., "Minuto Voucher").
    pub standard_name: String,
    /// Unique UUID of the voucher standard.
    pub standard_uuid: String,
    /// Currency unit of the balance (e.g., "Min", "€").
    pub unit: String,
    /// Total amount formatted as a string.
    pub total_amount: String,
    /// Formatted currency for display (e.g., "TEST-Minuto").
    pub display_currency: String,
    /// Formatted standard name for display.
    pub display_standard_name: String,
    /// Indicates if it is test balance.
    pub is_test_voucher: bool,
}

/// Summary information about an asset class (standard + test status).
/// Primarily used to populate filter dropdowns in the UI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AssetClassSummary {
    pub standard_uuid: String,
    pub is_test_voucher: bool,
    pub display_standard_name: String,
    pub display_currency: String,
}

/// A summary view of a voucher for list representations.
///
/// This structure is returned by `AppService::get_voucher_summaries`
/// and provides a concise representation of voucher data without
/// having to transfer the entire, complex `Voucher` object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoucherSummary {
    /// Unique local ID of the voucher instance in the wallet.
    pub local_instance_id: String,
    /// Current status of the voucher (e.g., `Active`, `Archived`).
    pub status: VoucherStatus,
    /// Unique ID of the creator (often a public key).
    pub creator_id: String,
    /// Validity date of the voucher in ISO 8601 format.
    pub valid_until: String,
    /// General human-readable description of the voucher.
    pub description: String,
    /// Current available amount of the voucher as a string.
    pub current_amount: String,
    /// Unit of the voucher value (e.g., "m" for minutes).
    pub unit: String,
    /// Name of the standard this voucher belongs to (e.g., "Minuto Voucher").
    pub raw_standard_name: String,
    /// Unique identifier (UUID) of the standard this voucher belongs to.
    pub voucher_standard_uuid: String,
    /// Number of transactions, excluding the initial `init` transaction.
    pub transaction_count: u32,
    /// Total number of existing signatures (including guarantors).
    pub signatures_count: u32,
    /// Flag indicating if the voucher is collateralized.
    pub has_collateral: bool,
    /// First name of the original creator.
    pub creator_first_name: String,
    /// Last name of the original creator.
    pub creator_last_name: String,
    pub creator_coordinates: String,
    /// Marker for whether it is a test voucher.
    pub is_test_voucher: bool,
    /// Formatted currency for display.
    pub display_currency: String,
    /// Formatted standard name for display.
    pub display_standard_name: String,
    /// Indicates if the voucher is divisible.
    pub allow_partial_transfers: bool,
}

/// A summary view of a double-spend proof for list representations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfDoubleSpendSummary {
    pub proof_id: String,
    pub offender_id: String,
    pub fork_point_prev_hash: String,
    pub report_timestamp: String,
    pub is_resolved: bool,
    pub has_l2_verdict: bool,
    pub local_override: bool,
    #[serde(default)]
    pub local_note: Option<String>,
    pub conflict_role: crate::models::conflict::ConflictRole,
    #[serde(default)]
    pub affected_voucher_name: Option<String>,
    #[serde(default)]
    pub display_affected_voucher_name: Option<String>,
    #[serde(default)]
    pub voucher_standard_uuid: Option<String>,
    pub is_test_voucher: bool,
}

/// A detailed view of a voucher including its transaction history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoucherDetails {
    pub local_instance_id: String,
    /// Current status of the voucher (e.g., `Active`, `Archived`).
    pub status: VoucherStatus,
    pub voucher: Voucher,
    /// Formatted currency for display.
    pub display_currency: String,
    /// Formatted standard name for display.
    pub display_standard_name: String,
    /// Indicates if it is a test balance.
    pub is_test_voucher: bool,
}
