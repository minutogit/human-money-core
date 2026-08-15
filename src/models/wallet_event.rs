//! # src/models/wallet_event.rs
//!
//! Defines the data structures for the wallet's lightweight event sourcing system.
//! Every relevant state change (voucher creation, transfer, expiration, etc.)
//! is recorded as an immutable `WalletEvent` to provide the UI with an instant, chronological
//! history without needing to parse the entire VoucherStore.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The typing of a wallet event.
///
/// `#[non_exhaustive]` ensures external crates do not break upon future
/// additions to the enum. The `Unknown` variant allows
/// error-resilient deserialization for older clients.
#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum WalletEventType {
    /// A new voucher was created by the wallet owner.
    VoucherCreated,
    /// A voucher (or parts thereof) was transferred to a counterparty.
    TransferSent,
    /// A voucher was received by the wallet (incoming transfer).
    TransferReceived,
    /// A voucher was placed in quarantine due to a verified double-spend conflict
    /// or a fatal validation error.
    VoucherQuarantined,
    /// A voucher transitioned from `Incomplete` to `Active`
    /// (e.g. by adding a missing signature).
    VoucherActivated,
    /// A voucher was explicitly voided by the user or through system logic.
    VoucherVoided,
    /// The validity duration (`valid_until`) of a voucher has expired.
    VoucherExpired,
    /// Fallback variant for error-resilient deserialization for older clients.
    Unknown(String),
}

/// UI-optimized data ("BFF data") that can be displayed directly in the event history
/// without requiring the UI to parse the voucher store.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct EventBffData {
    /// The formatted currency unit for display (e.g. "TEST-Minuto").
    pub display_currency: String,
    /// The amount associated with this event, as a string for
    /// precise decimal representation (e.g. "10.50").
    pub amount: String,
    /// Indicates whether this is a test voucher.
    pub is_test_voucher: bool,
    /// The user ID of the counterparty (sender or recipient), if known.
    /// Enables direct UI displays like "Sent to Bob".
    pub counterparty_id: Option<String>,
    /// The display name of the counterparty, if available.
    pub counterparty_name: Option<String>,
}

/// A single, immutable event in the wallet event log.
///
/// Each event has a global UUID (`event_id`), a global anchor
/// (`voucher_id`), and a local instance ID (`local_instance_id`) for
/// direct UI navigation.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WalletEvent {
    /// A unique, global event ID (UUID v4).
    pub event_id: String,
    /// The local instance ID of the affected voucher for UI navigation.
    pub local_instance_id: String,
    /// The global, immutable ID of the affected voucher.
    pub voucher_id: String,
    /// The timestamp of event detection (not necessarily persistence).
    pub timestamp: DateTime<Utc>,
    /// The type of the event.
    pub event_type: WalletEventType,
    /// UI-optimized display data for this event.
    pub bff_data: EventBffData,
}

impl WalletEvent {
    /// Creates a new WalletEvent with a freshly generated UUID.
    pub fn new(
        local_instance_id: String,
        voucher_id: String,
        event_type: WalletEventType,
        bff_data: EventBffData,
    ) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            local_instance_id,
            voucher_id,
            timestamp: Utc::now(),
            event_type,
            bff_data,
        }
    }
}
