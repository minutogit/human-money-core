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
use ed25519_dalek::{SigningKey, VerifyingKey as EdPublicKey};
use chrono::Datelike;
use subtle::ConstantTimeEq;
use crate::error::VoucherCoreError;
use crate::models::profile::UserIdentity;
use crate::services::crypto::{get_hash, get_pubkey_from_user_id, sign_ed25519, verify_ed25519};
use crate::services::utils::{get_current_timestamp, to_canonical_json};

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

impl WalletSeal {
    /// Creates the very first seal for a brand-new wallet (Epoch 0).
    ///
    /// The initial seal has:
    /// - `epoch = 0`
    /// - `tx_nonce = 0`
    /// - `prev_seal_hash = Hash("")` (deterministic genesis)
    /// - `epoch_start_time = now()`
    /// - `epoch_valid_until = canonical_epoch_valid_until_for_timestamp(&now)`
    ///
    /// # Arguments
    /// * `user_id` - The full user ID (incl. SAI prefix).
    /// * `identity` - The cryptographic identity for signing.
    /// * `initial_state_hash` - Hash of the initial OwnFingerprints store.
    /// * `local_instance_id` - Unique ID of the local device.
    pub fn create_initial(
        user_id: &str,
        identity: &UserIdentity,
        initial_state_hash: &str,
        local_instance_id: &str,
    ) -> Result<Self, VoucherCoreError> {
        if local_instance_id.trim().is_empty() {
            return Err(VoucherCoreError::Validation(
                crate::error::ValidationError::InvalidTransaction(
                    "Local instance ID cannot be empty".to_string(),
                ),
            ));
        }

        let now = get_current_timestamp();
        let epoch_valid_until = canonical_epoch_valid_until_for_timestamp(&now);

        let payload = SealPayload {
            version: 1,
            user_id: user_id.to_string(),
            epoch: 0,
            epoch_start_time: now.clone(),
            epoch_valid_until,
            tx_nonce: 0,
            prev_seal_hash: get_hash(""), // Deterministic genesis hash
            state_hash: initial_state_hash.to_string(),
            timestamp: now,
            instance_id: local_instance_id.to_string(),
        };

        Self::sign_payload(payload, identity)
    }

    /// Updates a seal after a transaction.
    ///
    /// - Increments `tx_nonce` by 1
    /// - Chains the hash of the previous seal into `prev_seal_hash`
    /// - Updates `state_hash` and `timestamp`
    /// - Epoch and `epoch_start_time` remain unchanged
    ///
    /// # Arguments
    /// * `identity` - The cryptographic identity for signing.
    /// * `new_state_hash` - Hash of the updated OwnFingerprints store.
    /// * `local_instance_id` - Unique ID of the local device.
    pub fn update(
        &self,
        identity: &UserIdentity,
        new_state_hash: &str,
        local_instance_id: &str,
    ) -> Result<Self, VoucherCoreError> {
        if local_instance_id.trim().is_empty() {
            return Err(VoucherCoreError::Validation(
                crate::error::ValidationError::InvalidTransaction(
                    "Local instance ID cannot be empty".to_string(),
                ),
            ));
        }

        // Compute hash of previous seal (canonical serialization)
        let prev_seal_canonical = to_canonical_json(self)?;
        let prev_hash = get_hash(prev_seal_canonical.as_bytes());

        // SECURITY (AUDIT-00-WILDCARD-22 / CWE-190): checked arithmetic — wrap
        // at u64::MAX would silently produce nonce 0 without epoch bump,
        // breaking monotonicity and hash-chain invariants.
        let next_nonce = self.payload.tx_nonce.checked_add(1).ok_or_else(|| {
            crate::error::VoucherCoreError::Validation(
                crate::error::ValidationError::InvalidTransaction(
                    "Seal tx_nonce overflow: counter at u64::MAX, wallet requires recovery"
                        .to_string(),
                ),
            )
        })?;

        let payload = SealPayload {
            version: self.payload.version,
            user_id: self.payload.user_id.clone(),
            epoch: self.payload.epoch,
            epoch_start_time: self.payload.epoch_start_time.clone(),
            epoch_valid_until: self.payload.epoch_valid_until.clone(),
            tx_nonce: next_nonce,
            prev_seal_hash: prev_hash,
            state_hash: new_state_hash.to_string(),
            timestamp: get_current_timestamp(),
            instance_id: local_instance_id.to_string(),
        };

        Self::sign_payload(payload, identity)
    }

    /// Verifies the signature and integrity of a seal.
    ///
    /// Checks:
    /// 1. User ID in payload matches expected value.
    /// 2. instance_id matches local device (Clone Protection).
    /// 3. Expected public key can verify signature.
    /// 4. Schema version is supported.
    ///
    /// # Arguments
    /// * `expected_user_id` - The expected user ID.
    /// * `expected_pubkey_user_id` - The user ID from which the public key is extracted.
    /// * `local_instance_id` - Unique ID of the local device for clone checking.
    pub fn verify_integrity(
        &self,
        expected_user_id: &str,
        expected_pubkey_user_id: &str,
        local_instance_id: &str,
    ) -> Result<SealValidationResult, VoucherCoreError> {
        // 1. Check version
        if self.payload.version != 1 {
            return Err(crate::Error::Wallet(crate::error::WalletError::InvariantViolation { message: format!(
                "Unsupported seal version: {}. Expected: 1",
                self.payload.version
            ) }));
        }

        // 2. Check user ID
        if self.payload.user_id != expected_user_id {
            return Ok(SealValidationResult::UserMismatch);
        }

        // 3. Check instance ID (Cloning Protection)
        if self.payload.instance_id.is_empty() || self.payload.instance_id != local_instance_id {
            return Ok(SealValidationResult::DeviceMismatch {
                expected: self.payload.instance_id.clone(),
                actual: local_instance_id.to_string(),
            });
        }

        // 4. Extract public key and verify signature
        let pubkey = get_pubkey_from_user_id(expected_pubkey_user_id)?;

        let payload_canonical = to_canonical_json(&self.payload)?;
        let payload_hash = get_hash(payload_canonical.as_bytes());

        let signature_bytes = crate::services::crypto::decode_bs58_fixed::<64>(
            &self.signature,
            "seal signature",
        )
        .map_err(|e| VoucherCoreError::Bs58Decode(format!("Failed to decode seal signature: {}", e)))?;

        let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);

        if !verify_ed25519(&pubkey, payload_hash.as_bytes(), &signature) {
            return Ok(SealValidationResult::InvalidSignature);
        }

        Ok(SealValidationResult::Valid)
    }

    /// Initiates a new epoch (Recovery). Epoch is strictly incremented.
    ///
    /// Called after a successful wallet recovery.
    /// - `epoch` is incremented by 1 (or set to 1 if no previous seal exists).
    /// - `tx_nonce` is reset to 0.
    /// - `epoch_start_time` is set to current timestamp.
    /// - `epoch_valid_until` is deterministically computed from the current timestamp.
    /// - `prev_seal_hash` points to last known seal (if available).
    /// - `instance_id` is bound to the new device.
    ///
    /// # Arguments
    /// * `last_known_seal` - The last known seal (can be `None` in case of complete loss).
    /// * `user_id` - The user ID of the recovered wallet.
    /// * `identity` - The cryptographic identity for signing.
    /// * `current_state_hash` - Hash of current OwnFingerprints store after recovery.
    /// * `local_instance_id` - Unique ID of the local device.
    pub fn recover_epoch(
        last_known_seal: Option<&Self>,
        user_id: &str,
        identity: &UserIdentity,
        current_state_hash: &str,
        local_instance_id: &str,
    ) -> Result<Self, VoucherCoreError> {
        if local_instance_id.trim().is_empty() {
            return Err(VoucherCoreError::Validation(
                crate::error::ValidationError::InvalidTransaction(
                    "Local instance ID cannot be empty".to_string(),
                ),
            ));
        }

        let now = get_current_timestamp();
        let epoch_valid_until = canonical_epoch_valid_until_for_timestamp(&now);

        // SECURITY (AUDIT-00-WILDCARD-22 / CWE-190): checked epoch bump — wrap
        // at u32::MAX would collide with genesis epoch 0.
        let (new_epoch, prev_hash) = match last_known_seal {
            Some(seal) => {
                let seal_canonical = to_canonical_json(seal)?;
                let hash = get_hash(seal_canonical.as_bytes());
                let bumped = seal.payload.epoch.checked_add(1).ok_or_else(|| {
                    crate::error::VoucherCoreError::Validation(
                        crate::error::ValidationError::InvalidTransaction(
                            "Seal epoch overflow: counter at u32::MAX".to_string(),
                        ),
                    )
                })?;
                (bumped, hash)
            }
            None => {
                // Complete data loss: Start at Epoch 1 with genesis hash
                (1, get_hash(""))
            }
        };

        let payload = SealPayload {
            version: 1,
            user_id: user_id.to_string(),
            epoch: new_epoch,
            epoch_start_time: now.clone(),
            epoch_valid_until,
            tx_nonce: 0,
            prev_seal_hash: prev_hash,
            state_hash: current_state_hash.to_string(),
            timestamp: now,
            instance_id: local_instance_id.to_string(),
        };

        Self::sign_payload(payload, identity)
    }

    /// Compares two verified seals and determines synchronization state.
    ///
    /// # Logic
    /// 1. **Synchronized**: Both payloads are identical.
    /// 2. **LocalIsNewer**: Local `tx_nonce` is higher AND the hash chain
    ///    correctly builds upon the remote seal.
    /// 3. **RemoteIsNewer**: Vice versa – Remote is further advanced.
    /// 4. **ForkDetected**: Hash chains diverge (different
    ///    `prev_seal_hash` despite advanced nonce).
    ///
    /// # Arguments
    /// * `local` - The local seal.
    /// * `remote` - The seal downloaded from server.
    pub fn compare_seals(local: &Self, remote: &Self) -> SealSyncState {
        // Fast path: Identical payloads
        if local.payload == remote.payload {
            return SealSyncState::Synchronized;
        }

        // Calculate hash of each other's seal (for chain verification)
        // SECURITY (AUDIT-W5-HARDEN): Fail-closed with ForkDetected on serialization errors
        let local_canonical = match to_canonical_json(local) {
            Ok(s) => s,
            Err(_) => return SealSyncState::ForkDetected,
        };
        let local_hash = get_hash(local_canonical.as_bytes());

        let remote_canonical = match to_canonical_json(remote) {
            Ok(s) => s,
            Err(_) => return SealSyncState::ForkDetected,
        };
        let remote_hash = get_hash(remote_canonical.as_bytes());

        // Epoch comparison: Different epochs are a fork signal,
        // unless one side correctly performed a recovery.
        if local.payload.epoch != remote.payload.epoch {
            // If epochs differ, the hash chain must correctly reference the previous seal.
            if local.payload.epoch > remote.payload.epoch
                && local.payload.prev_seal_hash == remote_hash
            {
                return SealSyncState::LocalIsNewer;
            }
            if remote.payload.epoch > local.payload.epoch
                && remote.payload.prev_seal_hash == local_hash
            {
                return SealSyncState::RemoteIsNewer;
            }
            return SealSyncState::ForkDetected;
        }

        // Same epoch: Nonce-based comparison with hash chain check
        // SECURITY (AUDIT-00-WILDCARD-19 / Appendix 02-H2): gap>1 heuristic
        // removed — nonce gaps >1 without a verifiable hash chain must be
        // ForkDetected (fail-closed). The heuristic `gap>1 => Newer` bypassed
        // fork detection for cloned wallets with divergent chains (distance ≥2)
        // and let rolled-back state masquerade as newer.
        if local.payload.tx_nonce > remote.payload.tx_nonce {
            if local.payload.tx_nonce == remote.payload.tx_nonce + 1
                && local.payload.prev_seal_hash == remote_hash
            {
                return SealSyncState::LocalIsNewer;
            }
            // Gap >1 or mismatched prev_hash => ForkDetected (no heuristic trust)
            SealSyncState::ForkDetected
        } else if remote.payload.tx_nonce > local.payload.tx_nonce {
            if remote.payload.tx_nonce == local.payload.tx_nonce + 1
                && remote.payload.prev_seal_hash == local_hash
            {
                return SealSyncState::RemoteIsNewer;
            }
            SealSyncState::ForkDetected
        } else {
            // Same nonce, but different payload -> Fork
            SealSyncState::ForkDetected
        }
    }

    /// Compares this seal with a remote seal.
    pub fn compare_with(&self, remote: &Self) -> SealSyncState {
        Self::compare_seals(self, remote)
    }

    /// Computes the hash of a WalletSeal for comparisons and sync purposes.
    ///
    /// Uses canonical JSON serialization followed by SHA3-256/Base58.
    pub fn compute_hash(&self) -> Result<String, VoucherCoreError> {
        let canonical = to_canonical_json(self)?;
        Ok(get_hash(canonical.as_bytes()))
    }

    // --- Private helper methods ---

    /// Signs a `SealPayload` and creates a complete `WalletSeal`.
    fn sign_payload(
        payload: SealPayload,
        identity: &UserIdentity,
    ) -> Result<Self, VoucherCoreError> {
        let payload_canonical = to_canonical_json(&payload)?;
        let payload_hash = get_hash(payload_canonical.as_bytes());
        let signature = sign_ed25519(&identity.signing_key, payload_hash.as_bytes());
        let signature_str = bs58::encode(signature.to_bytes()).into_string();

        Ok(Self {
            payload,
            signature: signature_str,
        })
    }
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
    /// Canonical voucher-indistinguishable RFC3339 expiration timestamp.
    /// Defaults to YYYY-12-31T23:59:59Z where YYYY = epoch_start_year + 2.
    pub epoch_valid_until: String,
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
    pub instance_id: String,
}

/// Checkpoint of the last state anchor verifiably confirmed on Layer 2.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncedAnchorCheckpoint {
    pub epoch: u32,
    pub tx_nonce: u64,
    pub l2_slot: u64,
    pub seal_hash: String,
    pub state_hash: String,
    pub causal_state_hash: [u8; 32],
    pub epoch_valid_until: String,
}

/// Reason for wallet lockdown if superseded by handover, concurrent clone, or fork.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SealLockReason {
    SupersededByHandover {
        target_epoch: u32,
        is_seed_recovery: bool,
        detected_at: String,
    },
    ConcurrentCloneDetected {
        detected_at: String,
    },
    ForkDetected,
}

/// Pending epoch tombstone to upload to Layer 2 to decommission a predecessor epoch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingEpochTombstone {
    pub old_epoch: u32,
    pub old_epoch_valid_until: String,
    pub target_epoch: u32,
    pub kind: AnchorLockKind,
    pub last_known_checkpoint: Option<SyncedAnchorCheckpoint>,
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
    /// Reason for wallet lockdown if superseded by handover, concurrent clone, or fork.
    pub lock_reason: Option<SealLockReason>,
    /// Pending epoch tombstones to upload to Layer 2 to decommission predecessor epochs.
    pub pending_tombstones: Vec<PendingEpochTombstone>,
    /// The last anchor checkpoint verifiably confirmed on Layer 2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_synced_anchor: Option<SyncedAnchorCheckpoint>,
}

impl LocalSealRecord {
    pub fn is_locked(&self) -> bool {
        self.lock_reason.is_some()
    }
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
/// Returned by `WalletSeal::compare_seals` and determines the
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
    /// The signature is invalid.
    InvalidSignature,
    /// The user ID in the seal does not match the wallet.
    UserMismatch,
    /// The device ID (instance_id) in the seal does not match the current host.
    /// Indicator of a cloned wallet.
    DeviceMismatch { expected: String, actual: String },
}

// --- Deterministic Key Derivation & Anchor Tree Functions ---

/// Canonical voucher-indistinguishable RFC3339 timestamp.
///
/// Computes year from `iso_ts[0..4]` parsed as `i32` (defaulting to current UTC year) + 2,
/// formatted as `YYYY-12-31T23:59:59Z`.
pub fn canonical_epoch_valid_until_for_timestamp(iso_ts: &str) -> String {
    let year = if iso_ts.len() >= 4 {
        iso_ts[0..4].parse::<i32>().unwrap_or_else(|_| chrono::Utc::now().year())
    } else {
        chrono::Utc::now().year()
    };
    format!("{:04}-12-31T23:59:59Z", year + 2)
}

/// Parses an RFC3339 timestamp string into epoch milliseconds.
pub fn parse_epoch_valid_until_ms(rfc3339: &str) -> Result<u64, VoucherCoreError> {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .map_err(|e| {
            VoucherCoreError::Validation(crate::error::ValidationError::InvalidTransaction(format!(
                "invalid epoch_valid_until timestamp: {e}"
            )))
        })
        .and_then(|dt| {
            u64::try_from(dt.timestamp_millis()).map_err(|_| {
                VoucherCoreError::Validation(crate::error::ValidationError::InvalidTransaction(
                    "negative or overflowing epoch_valid_until timestamp".into(),
                ))
            })
        })
}

/// Derives the anchor master seed strictly binding the user's master signing key and
/// full user ID (including SAI prefix).
pub fn derive_anchor_master_seed(identity: &UserIdentity) -> [u8; 32] {
    let mut key_material = Vec::with_capacity(32 + 4 + identity.user_id.len());
    key_material.extend_from_slice(&identity.signing_key.to_bytes());
    key_material.extend_from_slice(&(identity.user_id.len() as u32).to_le_bytes());
    key_material.extend_from_slice(identity.user_id.as_bytes());
    blake3::derive_key("HUMOCO_V1_WALLET_ANCHOR_MASTER", &key_material)
}

/// Derives the ephemeral step key pair for an anchor slot without storing keys on disk.
///
/// Binds master seed, epoch, and contiguous L2 slot counter (`0, 1, 2, ...`).
pub fn derive_anchor_step_key(
    identity: &UserIdentity,
    epoch: u64,
    l2_slot: u64,
) -> (SigningKey, EdPublicKey) {
    let master_seed = derive_anchor_master_seed(identity);
    let mut hasher = blake3::Hasher::new_keyed(&master_seed);
    hasher.update(b"STEP_KEY");
    hasher.update(&epoch.to_le_bytes());
    hasher.update(&l2_slot.to_le_bytes());
    let seed = hasher.finalize();
    crate::services::crypto::derive_ephemeral_key_pair(
        &identity.signing_key,
        seed.as_bytes(),
        "anchor_step",
        None,
    )
    .expect("HKDF expansion for 32 bytes never fails")
}

/// Derives the deterministic transaction ID for slot 0 (Genesis root).
///
/// Independent of local device instance ID so 24-word Cold Recovery can compute it.
pub fn derive_anchor_genesis_t_id(identity: &UserIdentity, epoch: u64) -> [u8; 32] {
    let master_seed = derive_anchor_master_seed(identity);
    let mut hasher = blake3::Hasher::new_keyed(&master_seed);
    hasher.update(b"GENESIS_TID");
    hasher.update(&epoch.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Derives the deterministic causal state hash for slot 0 (Genesis root).
///
/// Deterministic from `(master_seed, epoch)` only, so blank-disk cold recovery
/// can query slot 1 challenge tag without knowing previous wallet state hash.
pub fn derive_anchor_genesis_causal_state_hash(identity: &UserIdentity, epoch: u64) -> [u8; 32] {
    let master_seed = derive_anchor_master_seed(identity);
    let mut hasher = blake3::Hasher::new_keyed(&master_seed);
    hasher.update(b"ANCHOR_GENESIS_CAUSAL_STATE");
    hasher.update(&epoch.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Derives the Layer 2 anchor ID (virtual voucher ID) deterministically.
///
/// Matches `human-money-node` canonical L1 root preimage check:
/// `Sha256(genesis_t_id || step_pub(epoch, 0) || Sha3_256(step_pub(epoch, 1)) || epoch_valid_until.as_bytes())`
/// encoded as 64-char lowercase hex.
pub fn derive_l2_anchor_id(identity: &UserIdentity, epoch: u64, epoch_valid_until: &str) -> String {
    let genesis_t_id = derive_anchor_genesis_t_id(identity, epoch);
    let (_sk0, step_pub0) = derive_anchor_step_key(identity, epoch, 0);
    let (_sk1, step_pub1) = derive_anchor_step_key(identity, epoch, 1);
    use sha3::Digest as Sha3Digest;
    let step_pub1_hash: [u8; 32] = sha3::Sha3_256::digest(step_pub1.as_bytes()).into();

    let mut hasher = sha2::Sha256::new();
    hasher.update(genesis_t_id);
    hasher.update(step_pub0.as_bytes());
    hasher.update(step_pub1_hash);
    hasher.update(epoch_valid_until.as_bytes());
    hex::encode(hasher.finalize())
}

/// Derives the canonical SST challenge/DS tag for an anchor spend step from the
/// predecessor causal state hash and step ephemeral public key.
///
/// `Sha3_256(32u32.to_le_bytes() || prev_causal_state_hash || 32u32.to_le_bytes() || step_pub_bytes)` encoded with `bs58`.
pub fn derive_anchor_canonical_ds_tag(
    prev_causal_state_hash: &[u8; 32],
    step_pub_bytes: &[u8; 32],
) -> String {
    use sha3::Digest;
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(32u32.to_le_bytes());
    hasher.update(prev_causal_state_hash);
    hasher.update(32u32.to_le_bytes());
    hasher.update(step_pub_bytes);
    bs58::encode(hasher.finalize()).into_string()
}

/// Derives a 48-bit (6-byte) device attribution fingerprint.
pub fn derive_anchor_device_fp48(identity: &UserIdentity, local_instance_id: &str) -> [u8; 6] {
    let master_seed = derive_anchor_master_seed(identity);
    let mut hasher = blake3::Hasher::new_keyed(&master_seed);
    hasher.update(b"DEVICE_FP48");
    hasher.update(local_instance_id.as_bytes());
    let mut fp = [0u8; 6];
    fp.copy_from_slice(&hasher.finalize().as_bytes()[0..6]);
    fp
}

/// Derives the transaction ID `t_id` for an anchor step lock.
pub fn derive_anchor_step_t_id(
    identity: &UserIdentity,
    epoch: u64,
    l2_slot: u64,
    kind: AnchorLockKind,
    target_epoch: u32,
    origin_device_fp48: &[u8; 6],
    payload_commitment: &[u8; 32],
) -> [u8; 32] {
    let master_seed = derive_anchor_master_seed(identity);
    let mut t_hasher = blake3::Hasher::new_keyed(&master_seed);
    t_hasher.update(b"ANCHOR_STEP_TID");
    t_hasher.update(&[kind as u8]);
    t_hasher.update(&epoch.to_le_bytes());
    t_hasher.update(&l2_slot.to_le_bytes());
    t_hasher.update(&target_epoch.to_le_bytes());
    t_hasher.update(payload_commitment);
    t_hasher.update(origin_device_fp48);
    *t_hasher.finalize().as_bytes()
}

/// Derives the causal state hash for an anchor step lock.
pub fn derive_anchor_step_causal_hash(
    identity: &UserIdentity,
    epoch: u64,
    l2_slot: u64,
    t_id: &[u8; 32],
) -> [u8; 32] {
    let master_seed = derive_anchor_master_seed(identity);
    let mut c_hasher = blake3::Hasher::new_keyed(&master_seed);
    c_hasher.update(b"ANCHOR_CAUSAL_STATE");
    c_hasher.update(&epoch.to_le_bytes());
    c_hasher.update(&l2_slot.to_le_bytes());
    c_hasher.update(t_id);
    *c_hasher.finalize().as_bytes()
}

/// Derives indistinguishable SST trap data (`trap_r` and `trap_s`) for non-genesis anchor locks.
///
/// `trap_r`: valid Ed25519 curve point encoded as Base58.
/// `trap_s`: 32-byte scalar candidate with top 4 bits cleared (< 16) encoded as Base58.
pub fn derive_anchor_indistinguishable_traps(
    identity: &UserIdentity,
    epoch: u64,
    l2_slot: u64,
    t_id: &[u8; 32],
) -> (String, String) {
    let master_seed = derive_anchor_master_seed(identity);

    let mut r_hasher = blake3::Hasher::new_keyed(&master_seed);
    r_hasher.update(b"ANCHOR_TRAP_R");
    r_hasher.update(&epoch.to_le_bytes());
    r_hasher.update(&l2_slot.to_le_bytes());
    r_hasher.update(t_id);
    let r_seed = *r_hasher.finalize().as_bytes();
    let r_point = SigningKey::from_bytes(&r_seed).verifying_key().to_bytes();
    let trap_r = bs58::encode(r_point).into_string();

    let mut s_hasher = blake3::Hasher::new_keyed(&master_seed);
    s_hasher.update(b"ANCHOR_TRAP_S");
    s_hasher.update(&epoch.to_le_bytes());
    s_hasher.update(&l2_slot.to_le_bytes());
    s_hasher.update(t_id);
    let mut s_bytes = *s_hasher.finalize().as_bytes();
    s_bytes[31] &= 0x0F;
    let trap_s = bs58::encode(s_bytes).into_string();

    (trap_r, trap_s)
}

/// Kind of lock operation represented in an anchor lock descriptor.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AnchorLockKind {
    RegularStateUpdate = 1,
    HandoverTombstone = 2,
    SeedRecoveryTombstone = 3,
}

impl AnchorLockKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::RegularStateUpdate),
            2 => Some(Self::HandoverTombstone),
            3 => Some(Self::SeedRecoveryTombstone),
            _ => None,
        }
    }
}

/// Self-readable 128-bit descriptor embedded into `encrypted_timestamp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchorLockDescriptor {
    pub kind: AnchorLockKind,
    pub target_epoch: u32,
    pub origin_device_fp48: [u8; 6],
}

impl AnchorLockDescriptor {
    /// Encodes this descriptor into a 128-bit masked `encrypted_timestamp`.
    pub fn encode_encrypted_timestamp(
        &self,
        identity: &UserIdentity,
        anchor_id: &str,
        epoch: u64,
        l2_slot: u64,
        t_id: &[u8; 32],
    ) -> u128 {
        let master_seed = derive_anchor_master_seed(identity);

        let mut p = [0u8; 16];
        p[0] = 0xA1;
        p[1] = self.kind as u8;
        p[2..6].copy_from_slice(&self.target_epoch.to_le_bytes());
        p[6..12].copy_from_slice(&self.origin_device_fp48);

        let mut mac_hasher = blake3::Hasher::new_keyed(&master_seed);
        mac_hasher.update(b"ANCHOR_DESC_MAC");
        mac_hasher.update(&(anchor_id.len() as u32).to_le_bytes());
        mac_hasher.update(anchor_id.as_bytes());
        mac_hasher.update(&epoch.to_le_bytes());
        mac_hasher.update(&l2_slot.to_le_bytes());
        mac_hasher.update(t_id);
        mac_hasher.update(&p[0..12]);
        let mac = mac_hasher.finalize();
        p[12..16].copy_from_slice(&mac.as_bytes()[0..4]);

        let mut pad_hasher = blake3::Hasher::new_keyed(&master_seed);
        pad_hasher.update(b"ANCHOR_DESC_PAD");
        pad_hasher.update(&epoch.to_le_bytes());
        pad_hasher.update(&l2_slot.to_le_bytes());
        pad_hasher.update(t_id);
        let pad = pad_hasher.finalize();
        let pad_16 = &pad.as_bytes()[0..16];

        let mut cipher = [0u8; 16];
        for i in 0..16 {
            cipher[i] = p[i] ^ pad_16[i];
        }

        u128::from_le_bytes(cipher)
    }

    /// Decodes and verifies this descriptor from a 128-bit `encrypted_timestamp`.
    pub fn decode_encrypted_timestamp(
        identity: &UserIdentity,
        anchor_id: &str,
        epoch: u64,
        l2_slot: u64,
        t_id: &[u8; 32],
        encrypted_timestamp: u128,
    ) -> Option<Self> {
        let master_seed = derive_anchor_master_seed(identity);

        let mut pad_hasher = blake3::Hasher::new_keyed(&master_seed);
        pad_hasher.update(b"ANCHOR_DESC_PAD");
        pad_hasher.update(&epoch.to_le_bytes());
        pad_hasher.update(&l2_slot.to_le_bytes());
        pad_hasher.update(t_id);
        let pad = pad_hasher.finalize();
        let pad_16 = &pad.as_bytes()[0..16];

        let cipher = encrypted_timestamp.to_le_bytes();
        let mut p = [0u8; 16];
        for i in 0..16 {
            p[i] = cipher[i] ^ pad_16[i];
        }

        if p[0] != 0xA1 {
            return None;
        }

        let kind = AnchorLockKind::from_u8(p[1])?;

        let mut mac_hasher = blake3::Hasher::new_keyed(&master_seed);
        mac_hasher.update(b"ANCHOR_DESC_MAC");
        mac_hasher.update(&(anchor_id.len() as u32).to_le_bytes());
        mac_hasher.update(anchor_id.as_bytes());
        mac_hasher.update(&epoch.to_le_bytes());
        mac_hasher.update(&l2_slot.to_le_bytes());
        mac_hasher.update(t_id);
        mac_hasher.update(&p[0..12]);
        let expected_mac = mac_hasher.finalize();
        let expected_mac32 = &expected_mac.as_bytes()[0..4];

        if p[12..16].ct_eq(expected_mac32).unwrap_u8() != 1 {
            return None;
        }

        let mut epoch_bytes = [0u8; 4];
        epoch_bytes.copy_from_slice(&p[2..6]);
        let target_epoch = u32::from_le_bytes(epoch_bytes);

        let mut origin_device_fp48 = [0u8; 6];
        origin_device_fp48.copy_from_slice(&p[6..12]);

        Some(Self {
            kind,
            target_epoch,
            origin_device_fp48,
        })
    }
}

/// Canonical 32-byte representation of a seal state hash.
///
/// Decodes 32-byte hex; otherwise falls back to BLAKE3 hash of the string bytes.
pub fn seal_state_hash_bytes(state_hash: &str) -> [u8; 32] {
    if let Ok(bytes) = hex::decode(state_hash) {
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return arr;
        }
    }
    *blake3::hash(state_hash.as_bytes()).as_bytes()
}

/// Calculates the Merkle root of all active (non-archived) vouchers in the wallet.
///
/// Hashes `(voucher_id || current_leaf_hash)` for each non-archived voucher with
/// length prefixes, sorts them lexicographically, and hashes them with the count.
pub fn calculate_voucher_merkle_root(
    vouchers: &std::collections::HashMap<String, crate::models::voucher::VoucherInstance>,
) -> String {
    let mut leaf_hashes: Vec<[u8; 32]> = Vec::new();
    for instance in vouchers.values() {
        if matches!(instance.status, crate::wallet::instance::VoucherStatus::Archived) {
            continue;
        }
        let voucher_id = &instance.voucher.voucher_id;
        let leaf_tx_hash = instance
            .voucher
            .transactions
            .last()
            .map(|t| t.t_id.as_str())
            .unwrap_or("");
        let mut h = blake3::Hasher::new();
        h.update(b"HMC_VOUCHER_LEAF_V1");
        h.update(&(voucher_id.len() as u32).to_le_bytes());
        h.update(voucher_id.as_bytes());
        h.update(&(leaf_tx_hash.len() as u32).to_le_bytes());
        h.update(leaf_tx_hash.as_bytes());
        leaf_hashes.push(*h.finalize().as_bytes());
    }

    leaf_hashes.sort();

    let mut root_hasher = blake3::Hasher::new();
    let count = leaf_hashes.len() as u64;
    root_hasher.update(&count.to_le_bytes());
    for h in leaf_hashes {
        root_hasher.update(&h);
    }
    hex::encode(root_hasher.finalize().as_bytes())
}

/// Summary report after automated rollback reconciliation against Layer 2 network state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollbackReconciliationReport {
    pub quarantined_voucher_ids: Vec<String>,
    pub archived_voucher_ids: Vec<String>,
    pub retained_voucher_ids: Vec<String>,
    pub new_tx_nonce: u64,
    pub consolidated_state_hash: String,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::crypto::{generate_ed25519_keypair_for_tests, create_user_id};

    fn test_identity() -> UserIdentity {
        let (public_key, signing_key) = generate_ed25519_keypair_for_tests(Some("seal_test_seed"));
        let user_id = create_user_id(&public_key, Some("test")).unwrap();
        UserIdentity {
            signing_key,
            public_key,
            user_id,
        }
    }

    #[test]
    fn test_create_initial_seal() {
        let identity = test_identity();
        let state_hash = get_hash("initial_state");
        let instance_id = "device_a";

        let seal = WalletSeal::create_initial(
            &identity.user_id,
            &identity,
            &state_hash,
            instance_id,
        ).unwrap();

        assert_eq!(seal.payload.version, 1);
        assert_eq!(seal.payload.user_id, identity.user_id);
        assert_eq!(seal.payload.epoch, 0);
        assert_eq!(seal.payload.tx_nonce, 0);
        assert_eq!(seal.payload.state_hash, state_hash);
        assert_eq!(seal.payload.prev_seal_hash, get_hash(""));
        assert_eq!(seal.payload.instance_id, instance_id);
        assert!(!seal.signature.is_empty());

        // Signature must be verifiable
        let result = seal.verify_integrity(&identity.user_id, &identity.user_id, instance_id)
            .expect("Verification call should succeed");
        assert_eq!(result, SealValidationResult::Valid);
    }

    #[test]
    fn test_update_seal_chain() {
        let identity = test_identity();
        let state_hash_1 = get_hash("state_1");
        let state_hash_2 = get_hash("state_2");
        let instance_id = "device_a";

        let seal_1 = WalletSeal::create_initial(
            &identity.user_id,
            &identity,
            &state_hash_1,
            instance_id,
        ).unwrap();

        let seal_2 = seal_1.update(&identity, &state_hash_2, instance_id).unwrap();

        assert_eq!(seal_2.payload.tx_nonce, 1);
        assert_eq!(seal_2.payload.epoch, 0); // Epoch remains
        assert_eq!(seal_2.payload.state_hash, state_hash_2);
        assert_eq!(seal_2.payload.instance_id, instance_id);

        // prev_seal_hash must reference seal_1
        let seal_1_hash = seal_1.compute_hash().unwrap();
        assert_eq!(seal_2.payload.prev_seal_hash, seal_1_hash);

        // Signature valid
        let result = seal_2.verify_integrity(&identity.user_id, &identity.user_id, instance_id)
            .expect("Verification call should succeed");
        assert_eq!(result, SealValidationResult::Valid);
    }

    #[test]
    fn test_tamper_detection() {
        let identity = test_identity();
        let state_hash = get_hash("state");
        let instance_id = "device_a";

        let mut seal = WalletSeal::create_initial(
            &identity.user_id,
            &identity,
            &state_hash,
            instance_id,
        ).unwrap();

        // Manipulate tx_nonce
        seal.payload.tx_nonce = 999;

        let result = seal.verify_integrity(&identity.user_id, &identity.user_id, instance_id).unwrap();
        assert_eq!(result, SealValidationResult::InvalidSignature);
    }

    #[test]
    fn test_cloning_protection() {
        let identity = test_identity();
        let state_hash = get_hash("state");
        let instance_a = "device_a";
        let instance_b = "device_b";

        let seal = WalletSeal::create_initial(
            &identity.user_id,
            &identity,
            &state_hash,
            instance_a,
        ).unwrap();

        // Verification on device A succeeds
        let result_a = seal.verify_integrity(&identity.user_id, &identity.user_id, instance_a).unwrap();
        assert_eq!(result_a, SealValidationResult::Valid);

        // Verification on device B fails with DeviceMismatch
        let result_b = seal.verify_integrity(&identity.user_id, &identity.user_id, instance_b).unwrap();
        assert!(matches!(result_b, SealValidationResult::DeviceMismatch { .. }));
    }

    #[test]
    fn test_recover_seal_epoch() {
        let identity = test_identity();
        let state_hash_1 = get_hash("state_1");
        let state_hash_2 = get_hash("state_after_recovery");
        let instance_a = "device_a";
        let instance_b = "device_b"; // New device after recovery

        let seal_1 = WalletSeal::create_initial(
            &identity.user_id,
            &identity,
            &state_hash_1,
            instance_a,
        ).unwrap();

        let recovered_seal = WalletSeal::recover_epoch(
            Some(&seal_1),
            &identity.user_id,
            &identity,
            &state_hash_2,
            instance_b,
        ).unwrap();

        assert_eq!(recovered_seal.payload.epoch, 1);
        assert_eq!(recovered_seal.payload.tx_nonce, 0);
        assert_eq!(recovered_seal.payload.state_hash, state_hash_2);
        assert_eq!(recovered_seal.payload.instance_id, instance_b);

        let result = recovered_seal.verify_integrity(&identity.user_id, &identity.user_id, instance_b)
            .expect("Verification call should succeed");
        assert_eq!(result, SealValidationResult::Valid);
    }

    #[test]
    fn test_compare_seals_synchronized() {
        let identity = test_identity();
        let instance_id = "device_a";
        let seal = WalletSeal::create_initial(
            &identity.user_id,
            &identity,
            &get_hash("state"),
            instance_id,
        ).unwrap();

        assert_eq!(
            WalletSeal::compare_seals(&seal, &seal),
            SealSyncState::Synchronized
        );
        assert_eq!(
            seal.compare_with(&seal),
            SealSyncState::Synchronized
        );
    }

    #[test]
    fn test_compare_seals_local_is_newer() {
        let identity = test_identity();
        let instance_id = "device_a";
        let seal_1 = WalletSeal::create_initial(
            &identity.user_id,
            &identity,
            &get_hash("state_1"),
            instance_id,
        ).unwrap();

        let seal_2 = seal_1.update(&identity, &get_hash("state_2"), instance_id).unwrap();

        assert_eq!(
            WalletSeal::compare_seals(&seal_2, &seal_1),
            SealSyncState::LocalIsNewer
        );
    }

    #[test]
    fn test_compare_seals_remote_is_newer() {
        let identity = test_identity();
        let instance_id = "device_a";
        let seal_1 = WalletSeal::create_initial(
            &identity.user_id,
            &identity,
            &get_hash("state_1"),
            instance_id,
        ).unwrap();

        let seal_2 = seal_1.update(&identity, &get_hash("state_2"), instance_id).unwrap();

        assert_eq!(
            WalletSeal::compare_seals(&seal_1, &seal_2),
            SealSyncState::RemoteIsNewer
        );
    }

    #[test]
    fn test_compare_seals_fork_detected() {
        let identity = test_identity();
        let instance_id = "device_a";
        let seal_base = WalletSeal::create_initial(
            &identity.user_id,
            &identity,
            &get_hash("state_base"),
            instance_id,
        ).unwrap();

        // Two independent updates on the same base seal -> Fork
        let seal_branch_a = seal_base.update(&identity, &get_hash("state_a"), instance_id).unwrap();
        let seal_branch_b = seal_base.update(&identity, &get_hash("state_b"), instance_id).unwrap();

        // Both have nonce 1, but different payloads -> Fork
        assert_eq!(
            WalletSeal::compare_seals(&seal_branch_a, &seal_branch_b),
            SealSyncState::ForkDetected
        );
    }

    #[test]
    fn test_empty_local_instance_id_rejected() {
        let identity = test_identity();
        let state_hash = get_hash("initial_state");

        assert!(WalletSeal::create_initial(&identity.user_id, &identity, &state_hash, "").is_err());
        assert!(WalletSeal::create_initial(&identity.user_id, &identity, &state_hash, "   ").is_err());

        let seal = WalletSeal::create_initial(&identity.user_id, &identity, &state_hash, "valid_device").unwrap();
        assert!(seal.update(&identity, &get_hash("state2"), "").is_err());
        assert!(seal.update(&identity, &get_hash("state2"), "   ").is_err());

        assert!(WalletSeal::recover_epoch(Some(&seal), &identity.user_id, &identity, &get_hash("state2"), "").is_err());
        assert!(WalletSeal::recover_epoch(Some(&seal), &identity.user_id, &identity, &get_hash("state2"), "   ").is_err());
    }

    #[test]
    fn test_prefix_isolation_and_device_convergence() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let (pubkey, signing_key) = crate::services::crypto::derive_ed25519_keypair(
            mnemonic,
            None,
            crate::services::mnemonic::MnemonicLanguage::English,
        ).unwrap();

        let user_id_pc = create_user_id(&pubkey, Some("pc")).unwrap();
        let user_id_mobil = create_user_id(&pubkey, Some("mobil")).unwrap();

        let identity_pc_device_a = UserIdentity {
            signing_key: SigningKey::from_bytes(&signing_key.to_bytes()),
            public_key: pubkey,
            user_id: user_id_pc.clone(),
        };

        let identity_pc_device_b = UserIdentity {
            signing_key: SigningKey::from_bytes(&signing_key.to_bytes()),
            public_key: pubkey,
            user_id: user_id_pc,
        };

        let identity_mobil = UserIdentity {
            signing_key: SigningKey::from_bytes(&signing_key.to_bytes()),
            public_key: pubkey,
            user_id: user_id_mobil,
        };

        let epoch = 0u64;
        let valid_until = canonical_epoch_valid_until_for_timestamp("2026-11-06T12:00:00Z");

        // Device A and Device B with SAME prefix have identical master seed and anchor id
        let seed_a = derive_anchor_master_seed(&identity_pc_device_a);
        let seed_b = derive_anchor_master_seed(&identity_pc_device_b);
        assert_eq!(seed_a, seed_b);

        let anchor_id_a = derive_l2_anchor_id(&identity_pc_device_a, epoch, &valid_until);
        let anchor_id_b = derive_l2_anchor_id(&identity_pc_device_b, epoch, &valid_until);
        assert_eq!(anchor_id_a, anchor_id_b);

        let (sk_a, pk_a) = derive_anchor_step_key(&identity_pc_device_a, epoch, 0);
        let (sk_b, pk_b) = derive_anchor_step_key(&identity_pc_device_b, epoch, 0);
        assert_eq!(sk_a.to_bytes(), sk_b.to_bytes());
        assert_eq!(pk_a.to_bytes(), pk_b.to_bytes());

        // Same mnemonic with DIFFERENT prefix ("pc" vs "mobil") has completely distinct master seed & anchor id
        let seed_mobil = derive_anchor_master_seed(&identity_mobil);
        assert_ne!(seed_a, seed_mobil);

        let anchor_id_mobil = derive_l2_anchor_id(&identity_mobil, epoch, &valid_until);
        assert_ne!(anchor_id_a, anchor_id_mobil);

        let (_sk_m, pk_m) = derive_anchor_step_key(&identity_mobil, epoch, 0);
        assert_ne!(pk_a.to_bytes(), pk_m.to_bytes());
    }

    #[test]
    fn test_node_root_preimage_compliance() {
        let identity = test_identity();
        let epoch = 0u64;
        let valid_until = "2028-12-31T23:59:59Z";

        let anchor_id = derive_l2_anchor_id(&identity, epoch, valid_until);
        assert_eq!(anchor_id.len(), 64);
        assert!(anchor_id.chars().all(|c| c.is_ascii_hexdigit()));

        let genesis_t_id = derive_anchor_genesis_t_id(&identity, epoch);
        let (_sk0, step_pub0) = derive_anchor_step_key(&identity, epoch, 0);
        let (_sk1, step_pub1) = derive_anchor_step_key(&identity, epoch, 1);
        use sha3::Digest as Sha3Digest;
        let step_pub1_hash: [u8; 32] = sha3::Sha3_256::digest(step_pub1.as_bytes()).into();

        let mut hasher = sha2::Sha256::new();
        hasher.update(genesis_t_id);
        hasher.update(step_pub0.as_bytes());
        hasher.update(step_pub1_hash);
        hasher.update(valid_until.as_bytes());
        let expected_anchor_id = hex::encode(hasher.finalize());

        assert_eq!(anchor_id, expected_anchor_id);
    }

    #[test]
    fn test_anchor_lock_descriptor_roundtrip_and_tamper_rejection() {
        let identity = test_identity();
        let anchor_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let epoch = 1u64;
        let l2_slot = 3u64;
        let t_id = [0x5Au8; 32];
        let origin_device_fp48 = derive_anchor_device_fp48(&identity, "device_origin");

        let desc = AnchorLockDescriptor {
            kind: AnchorLockKind::HandoverTombstone,
            target_epoch: 2,
            origin_device_fp48,
        };

        let encrypted = desc.encode_encrypted_timestamp(&identity, anchor_id, epoch, l2_slot, &t_id);

        // Honest decode
        let decoded = AnchorLockDescriptor::decode_encrypted_timestamp(
            &identity,
            anchor_id,
            epoch,
            l2_slot,
            &t_id,
            encrypted,
        );
        assert_eq!(decoded, Some(desc));

        // Wrong identity fails MAC check
        let (other_pub, other_sk) = generate_ed25519_keypair_for_tests(Some("other_identity_seed"));
        let other_identity = UserIdentity {
            signing_key: other_sk,
            public_key: other_pub,
            user_id: "other@did:key:z6M...".to_string(),
        };
        assert_eq!(
            AnchorLockDescriptor::decode_encrypted_timestamp(
                &other_identity,
                anchor_id,
                epoch,
                l2_slot,
                &t_id,
                encrypted,
            ),
            None
        );

        // Wrong slot fails
        assert_eq!(
            AnchorLockDescriptor::decode_encrypted_timestamp(
                &identity,
                anchor_id,
                epoch,
                l2_slot + 1,
                &t_id,
                encrypted,
            ),
            None
        );

        // Wrong epoch fails
        assert_eq!(
            AnchorLockDescriptor::decode_encrypted_timestamp(
                &identity,
                anchor_id,
                epoch + 1,
                l2_slot,
                &t_id,
                encrypted,
            ),
            None
        );

        // Wrong t_id fails
        let mut corrupted_tid = t_id;
        corrupted_tid[0] ^= 0x01;
        assert_eq!(
            AnchorLockDescriptor::decode_encrypted_timestamp(
                &identity,
                anchor_id,
                epoch,
                l2_slot,
                &corrupted_tid,
                encrypted,
            ),
            None
        );

        // Bit flip in encrypted timestamp fails
        let corrupted_encrypted = encrypted ^ 0x0001_0000;
        assert_eq!(
            AnchorLockDescriptor::decode_encrypted_timestamp(
                &identity,
                anchor_id,
                epoch,
                l2_slot,
                &t_id,
                corrupted_encrypted,
            ),
            None
        );
    }
}
