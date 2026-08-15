//! # src/models/seal.rs
//!
//! Defines the data structures for the WalletSeal mechanism (Rollback Guard).
//! Protects against state rollbacks, multi-device forks, and old replay bundles
//! after a recovery.
//!
//! ## Architecture: Wire Format vs. Storage Format
//!
//! The design strictly separates the **Wire Format** (`WalletSeal` - sent to
//! the server/Layer 2) and the **Storage Format** (`LocalSealRecord` -
//! stored only locally on disk). This separation prevents:
//! - Accidental uploading of local metadata (e.g. `SyncStatus`).
//! - Infinite signature loops, since only the pure `WalletSeal` is signed and
//!   synchronized.

use serde::{Deserialize, Serialize};

/// Cryptographically signed envelope of the seal (wire format for uploads).
///
/// Contains the signed payload (`SealPayload`) and the Ed25519 signature
/// over the canonical JSON serialization of the payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WalletSeal {
    /// The actual payload of the seal.
    pub payload: SealPayload,
    /// Ed25519 signature over the canonical JSON serialization of the `payload`.
    /// Encoded as a Base58 string for consistent representation.
    pub signature: String,
}

/// The actual payload of the seal (counters, hashes, metadata).
///
/// This structure is canonically serialized and then signed to
/// cryptographically anchor the integrity of the wallet state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SealPayload {
    /// Schema version (currently 1). Allows future migration.
    pub version: u32,
    /// The full user ID (incl. SAI prefix), e.g. `pc:aB3@did:key:z...`
    pub user_id: String,
    /// Epoch of the seal: 0 = Initial (new wallet), +1 on each recovery.
    /// Strictly incremented and never reset.
    pub epoch: u32,
    /// ISO-8601 timestamp of the start of the current epoch.
    /// Used for the zone model during bundle reception to detect
    /// pre-epoch replays.
    pub epoch_start_time: String,
    /// Monotonic transaction counter within the current epoch.
    /// Incremented by 1 on every outgoing transaction.
    /// Reset to 0 on epoch change (recovery).
    pub tx_nonce: u64,
    /// Base58-encoded SHA3-256 hash of the previous `WalletSeal`.
    /// Forms a cryptographic hash chain for detecting forks.
    /// For the very first seal: hash of an empty string (deterministic genesis).
    pub prev_seal_hash: String,
    /// Base58-encoded SHA3-256 hash of the current `OwnFingerprints` store.
    /// Anchors the critical wallet state in the seal to detect rollbacks.
    pub state_hash: String,
    /// ISO-8601 timestamp of seal creation.
    pub timestamp: String,
    /// Unique ID of the device on which the wallet was initialized.
    /// Serves as protection against cloning wallet files to other devices.
    #[serde(default)]
    pub instance_id: String,
}

/// The local storage wrapper for disk (storage format).
///
/// Contains the pure cryptographic seal plus local metadata that
/// must never be sent to the server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LocalSealRecord {
    /// The pure cryptographic seal (wire format).
    pub seal: WalletSeal,
    /// The local upload status regarding cloud/Layer 2.
    pub sync_status: SyncStatus,
    /// Persistent lock if a multi-device fork was detected.
    /// Can only be cleared via `recover_wallet_and_set_new_password`.
    pub is_locked_due_to_fork: bool,
}

/// Status of the local seal regarding cloud/Layer 2.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SyncStatus {
    /// Seal was modified locally (new transaction, recovery), needs to be
    /// backed up online.
    PendingUpload,
    /// The current seal is verifiably backed up in the cloud.
    Synced,
}

/// The result of comparing a local and a remote seal.
///
/// Returned by `SealManager::compare_seals` and determines the
/// next action in the sync workflow.
#[derive(Debug, Clone, PartialEq)]
pub enum SealSyncState {
    /// Local and remote are exactly identical. No action needed.
    Synchronized,
    /// Local `tx_nonce` is higher and the hash chain builds up correctly.
    /// Push recommended (upload local seal).
    LocalIsNewer,
    /// Remote `tx_nonce` is higher and the hash chain builds up correctly.
    /// Pull required — local state is outdated!
    RemoteIsNewer,
    /// The hash chains do not match, even though one side is newer.
    /// Indicator of a multi-device conflict or backup restore.
    /// **Triggers a hard lock!**
    ForkDetected,
}

/// Result of a seal integrity check.
#[derive(Debug, Clone, PartialEq)]
pub enum SealValidationResult {
    /// The seal is valid and bound to the correct device.
    Valid,
    /// The seal is valid, but not yet bound to a device (legacy).
    LegacyValid,
    /// The signature is invalid.
    InvalidSignature,
    /// The user ID in the seal does not match the wallet.
    UserMismatch,
    /// The device ID (instance_id) in the seal does not match the current host.
    /// Indicator of a cloned wallet.
    DeviceMismatch { expected: String, actual: String },
}
