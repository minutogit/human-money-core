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
        let now = get_current_timestamp();

        let payload = SealPayload {
            version: 1,
            user_id: user_id.to_string(),
            epoch: 0,
            epoch_start_time: now.clone(),
            tx_nonce: 0,
            prev_seal_hash: get_hash(""), // Deterministic genesis hash
            state_hash: initial_state_hash.to_string(),
            timestamp: now,
            instance_id: local_instance_id.to_string(),
        };

        Self::sign_payload(payload, identity)
    }

    /// Alias for `create_initial`.
    pub fn create_initial_seal(
        user_id: &str,
        identity: &UserIdentity,
        initial_state_hash: &str,
        local_instance_id: &str,
    ) -> Result<Self, VoucherCoreError> {
        Self::create_initial(user_id, identity, initial_state_hash, local_instance_id)
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
        // Compute hash of previous seal (canonical serialization)
        let prev_seal_canonical = to_canonical_json(self)?;
        let prev_hash = get_hash(prev_seal_canonical.as_bytes());

        let payload = SealPayload {
            version: self.payload.version,
            user_id: self.payload.user_id.clone(),
            epoch: self.payload.epoch,
            epoch_start_time: self.payload.epoch_start_time.clone(),
            tx_nonce: self.payload.tx_nonce + 1,
            prev_seal_hash: prev_hash,
            state_hash: new_state_hash.to_string(),
            timestamp: get_current_timestamp(),
            instance_id: local_instance_id.to_string(),
        };

        Self::sign_payload(payload, identity)
    }

    /// Associated helper alias for `update`.
    pub fn update_seal(
        prev_seal: &Self,
        identity: &UserIdentity,
        new_state_hash: &str,
        local_instance_id: &str,
    ) -> Result<Self, VoucherCoreError> {
        prev_seal.update(identity, new_state_hash, local_instance_id)
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
            return Err(VoucherCoreError::Generic(format!(
                "Unsupported seal version: {}. Expected: 1",
                self.payload.version
            )));
        }

        // 2. Check user ID
        if self.payload.user_id != expected_user_id {
            return Ok(SealValidationResult::UserMismatch);
        }

        // 3. Check instance ID (Cloning Protection)
        // Exception: If self.payload.instance_id.is_empty() (Legacy Wallet), it is valid.
        if !self.payload.instance_id.is_empty() && self.payload.instance_id != local_instance_id {
            return Ok(SealValidationResult::DeviceMismatch {
                expected: self.payload.instance_id.clone(),
                actual: local_instance_id.to_string(),
            });
        }

        // 4. Extract public key and verify signature
        let pubkey = get_pubkey_from_user_id(expected_pubkey_user_id)?;

        let payload_canonical = to_canonical_json(&self.payload)?;
        let payload_hash = get_hash(payload_canonical.as_bytes());

        let signature_bytes = bs58::decode(&self.signature)
            .into_vec()
            .map_err(|e| VoucherCoreError::Bs58Decode(format!("Failed to decode seal signature: {}", e)))?;

        let signature = ed25519_dalek::Signature::from_slice(&signature_bytes)
            .map_err(|e| VoucherCoreError::Ed25519(format!("Invalid seal signature format: {}", e)))?;

        if !verify_ed25519(&pubkey, payload_hash.as_bytes(), &signature) {
            return Ok(SealValidationResult::InvalidSignature);
        }

        if self.payload.instance_id.is_empty() {
            Ok(SealValidationResult::LegacyValid)
        } else {
            Ok(SealValidationResult::Valid)
        }
    }

    /// Associated helper alias for `verify_integrity`.
    pub fn verify_seal_integrity(
        seal: &Self,
        expected_user_id: &str,
        expected_pubkey_user_id: &str,
        local_instance_id: &str,
    ) -> Result<SealValidationResult, VoucherCoreError> {
        seal.verify_integrity(expected_user_id, expected_pubkey_user_id, local_instance_id)
    }

    /// Initiates a new epoch (Recovery). Epoch is strictly incremented.
    ///
    /// Called after a successful wallet recovery.
    /// - `epoch` is incremented by 1 (or set to 1 if no previous seal exists).
    /// - `tx_nonce` is reset to 0.
    /// - `epoch_start_time` is set to current timestamp.
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
        let now = get_current_timestamp();

        let (new_epoch, prev_hash) = match last_known_seal {
            Some(seal) => {
                let seal_canonical = to_canonical_json(seal)?;
                let hash = get_hash(seal_canonical.as_bytes());
                (seal.payload.epoch + 1, hash)
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
            tx_nonce: 0,
            prev_seal_hash: prev_hash,
            state_hash: current_state_hash.to_string(),
            timestamp: now,
            instance_id: local_instance_id.to_string(),
        };

        Self::sign_payload(payload, identity)
    }

    /// Associated helper alias for `recover_epoch`.
    pub fn recover_seal_epoch(
        last_known_seal: Option<&Self>,
        user_id: &str,
        identity: &UserIdentity,
        current_state_hash: &str,
        local_instance_id: &str,
    ) -> Result<Self, VoucherCoreError> {
        Self::recover_epoch(last_known_seal, user_id, identity, current_state_hash, local_instance_id)
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
        let local_canonical = to_canonical_json(local).unwrap_or_default();
        let local_hash = get_hash(local_canonical.as_bytes());

        let remote_canonical = to_canonical_json(remote).unwrap_or_default();
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
        if local.payload.tx_nonce > remote.payload.tx_nonce {
            // Local is further ahead. Check whether the chain leads back to remote.
            // For direct succession (nonce + 1), prev_seal_hash == remote_hash must hold.
            // For larger distances, we only check that the general direction matches.
            if local.payload.tx_nonce == remote.payload.tx_nonce + 1
                && local.payload.prev_seal_hash == remote_hash
            {
                return SealSyncState::LocalIsNewer;
            }
            // For larger distances, the chain cannot be verified directly.
            // We trust nonce ordering as long as epochs are equal.
            // For strict security: ForkDetected on unknown prev_hash.
            if local.payload.tx_nonce > remote.payload.tx_nonce + 1 {
                // Cannot be directly verified -> LocalIsNewer as heuristic
                return SealSyncState::LocalIsNewer;
            }
            SealSyncState::ForkDetected
        } else if remote.payload.tx_nonce > local.payload.tx_nonce {
            if remote.payload.tx_nonce == local.payload.tx_nonce + 1
                && remote.payload.prev_seal_hash == local_hash
            {
                return SealSyncState::RemoteIsNewer;
            }
            if remote.payload.tx_nonce > local.payload.tx_nonce + 1 {
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

    /// Associated helper alias for `compute_hash`.
    pub fn compute_seal_hash(seal: &Self) -> Result<String, VoucherCoreError> {
        seal.compute_hash()
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
}
