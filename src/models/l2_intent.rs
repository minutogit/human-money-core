//! Private durable outbound L2 transport state; never part of the L1 deed.
use serde::{Deserialize, Serialize};
/// Terminal resolution outcome for an outbound L2 send intent.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum IntentTerminalResolution {
    /// Quorum-proven live state confirms the exact spend choice.
    Confirmed {
        resolved_at_ms: u64,
    },
    /// An independent query revealed a conflicting spend choice.
    Conflicted {
        resolved_at_ms: u64,
        observed_child: String,
    },
    /// Physical root validity expired without confirmation.
    Expired {
        resolved_at_ms: u64,
    },
}

/// Backend-owned pending transport state, included in the authenticated wallet.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct L2SendIntent {
    /// Exact local source, blocked from replacement while outcome is uncertain.
    pub local_instance_id: String,
    /// Exact serialized signed request, reused verbatim through every retry.
    pub request_bytes: Vec<u8>,
    /// Exact complete causal request when all original author proofs are available.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain_request_bytes: Vec<u8>,
    /// Exact signed L1 transaction, including its original outputs.
    pub transaction_bytes: Vec<u8>,
    /// Signed wallet creation time, never regenerated on retry.
    pub created_at_ms: u64,
    /// Frozen transport domain and root-bound verification context.
    pub network: u8,
    pub shard_id: u16,
    pub root_valid_until_ms: u64,
    /// True once first-party retained evidence has been observed. This does not
    /// authorize goods release, a replacement spend or an automatic refund.
    #[serde(default)]
    pub retained_original_observed: bool,
    /// Stored fresh recipient challenge for live quorum reconciliation.
    #[serde(default)]
    pub stored_challenge: Option<[u8; 32]>,
    /// Optional expiration timestamp for the stored recipient reconciliation challenge.
    #[serde(default)]
    pub challenge_expires_at_ms: Option<u64>,
    /// Stored regional committee at the time the challenge was generated or refreshed.
    #[serde(default)]
    pub stored_committee: Option<[[u8; 32]; 20]>,
    /// Local instance ID of any split-change voucher created during transfer.
    #[serde(default)]
    pub created_change_local_id: Option<String>,
    /// Explicit terminal resolution outcome if finalized.
    #[serde(default)]
    pub terminal_resolution: Option<IntentTerminalResolution>,
}
