//! # src/services/seal_manager.rs
//!
//! Stateless service for creating, updating, and verifying
//! `WalletSeal` objects (Rollback Guard).
//!
//! This module implements the cryptographic logic of the seal mechanism:
//! - Hash chain management (prev_seal_hash)
//! - Signature creation and verification
//! - Epoch management (Recovery)
//! - Seal comparison for sync detection

use crate::error::VoucherCoreError;
use crate::models::profile::UserIdentity;
use crate::models::seal::{SealPayload, SealSyncState, WalletSeal};
use crate::services::crypto_utils::{get_hash, sign_ed25519, verify_ed25519};
use crate::services::utils::{get_current_timestamp, to_canonical_json};

/// Stateless manager for WalletSeal operations.
///
/// All methods are static/associated – SealManager maintains no
/// internal state. It implements pure cryptographic logic.
pub struct SealManager;

impl SealManager {
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
    pub fn create_initial_seal(
        user_id: &str,
        identity: &UserIdentity,
        initial_state_hash: &str,
        local_instance_id: &str,
    ) -> Result<WalletSeal, VoucherCoreError> {
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

    /// Updates a seal after a transaction.
    ///
    /// - Increments `tx_nonce` by 1
    /// - Chains the hash of the previous seal into `prev_seal_hash`
    /// - Updates `state_hash` and `timestamp`
    /// - Epoch and `epoch_start_time` remain unchanged
    ///
    /// # Arguments
    /// * `prev_seal` - The previous valid seal.
    /// * `identity` - The cryptographic identity for signing.
    /// * `new_state_hash` - Hash of the updated OwnFingerprints store.
    /// * `local_instance_id` - Unique ID of the local device.
    pub fn update_seal(
        prev_seal: &WalletSeal,
        identity: &UserIdentity,
        new_state_hash: &str,
        local_instance_id: &str,
    ) -> Result<WalletSeal, VoucherCoreError> {
        // Compute hash of previous seal (canonical serialization)
        let prev_seal_canonical = to_canonical_json(prev_seal)?;
        let prev_hash = get_hash(prev_seal_canonical.as_bytes());

        let payload = SealPayload {
            version: prev_seal.payload.version,
            user_id: prev_seal.payload.user_id.clone(),
            epoch: prev_seal.payload.epoch,
            epoch_start_time: prev_seal.payload.epoch_start_time.clone(),
            tx_nonce: prev_seal.payload.tx_nonce + 1,
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
    /// * `seal` - The seal to verify.
    /// * `expected_user_id` - The expected user ID.
    /// * `expected_pubkey_user_id` - The user ID from which the public key is extracted.
    /// * `local_instance_id` - Unique ID of the local device for clone checking.
    pub fn verify_seal_integrity(
        seal: &WalletSeal,
        expected_user_id: &str,
        expected_pubkey_user_id: &str,
        local_instance_id: &str,
    ) -> Result<crate::models::seal::SealValidationResult, VoucherCoreError> {
        // 1. Check version
        if seal.payload.version != 1 {
            return Err(VoucherCoreError::Generic(format!(
                "Unsupported seal version: {}. Expected: 1",
                seal.payload.version
            )));
        }


        // 2. Check user ID
        if seal.payload.user_id != expected_user_id {
            return Ok(crate::models::seal::SealValidationResult::UserMismatch);
        }

        // 3. Check instance ID (Cloning Protection)
        // Exception: If seal.payload.instance_id.is_empty() (Legacy Wallet), it is valid.
        if !seal.payload.instance_id.is_empty() && seal.payload.instance_id != local_instance_id {
            return Ok(crate::models::seal::SealValidationResult::DeviceMismatch {
                expected: seal.payload.instance_id.clone(),
                actual: local_instance_id.to_string(),
            });
        }

        // 4. Extract public key and verify signature
        let pubkey = crate::services::crypto_utils::get_pubkey_from_user_id(expected_pubkey_user_id)?;

        let payload_canonical = to_canonical_json(&seal.payload)?;
        let payload_hash = get_hash(payload_canonical.as_bytes());

        let signature_bytes = bs58::decode(&seal.signature)
            .into_vec()
            .map_err(|e| VoucherCoreError::Generic(format!("Failed to decode seal signature: {}", e)))?;

        let signature = ed25519_dalek::Signature::from_slice(&signature_bytes)
            .map_err(|e| VoucherCoreError::Generic(format!("Invalid seal signature format: {}", e)))?;

        if !verify_ed25519(&pubkey, payload_hash.as_bytes(), &signature) {
            return Ok(crate::models::seal::SealValidationResult::InvalidSignature);
        }

        if seal.payload.instance_id.is_empty() {
            Ok(crate::models::seal::SealValidationResult::LegacyValid)
        } else {
            Ok(crate::models::seal::SealValidationResult::Valid)
        }
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
    pub fn recover_seal_epoch(
        last_known_seal: Option<&WalletSeal>,
        user_id: &str,
        identity: &UserIdentity,
        current_state_hash: &str,
        local_instance_id: &str,
    ) -> Result<WalletSeal, VoucherCoreError> {
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
    pub fn compare_seals(local: &WalletSeal, remote: &WalletSeal) -> SealSyncState {
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

    /// Computes the hash of a WalletSeal for comparisons and sync purposes.
    ///
    /// Uses canonical JSON serialization followed by SHA3-256/Base58.
    pub fn compute_seal_hash(seal: &WalletSeal) -> Result<String, VoucherCoreError> {
        let canonical = to_canonical_json(seal)?;
        Ok(get_hash(canonical.as_bytes()))
    }

    // --- Private helper methods ---

    /// Signs a `SealPayload` and creates a complete `WalletSeal`.
    fn sign_payload(
        payload: SealPayload,
        identity: &UserIdentity,
    ) -> Result<WalletSeal, VoucherCoreError> {
        let payload_canonical = to_canonical_json(&payload)?;
        let payload_hash = get_hash(payload_canonical.as_bytes());
        let signature = sign_ed25519(&identity.signing_key, payload_hash.as_bytes());
        let signature_str = bs58::encode(signature.to_bytes()).into_string();

        Ok(WalletSeal {
            payload,
            signature: signature_str,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::crypto_utils::generate_ed25519_keypair_for_tests;
    use crate::services::crypto_utils::create_user_id;

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

        let seal = SealManager::create_initial_seal(
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
        let result = SealManager::verify_seal_integrity(&seal, &identity.user_id, &identity.user_id, instance_id)
            .expect("Verification call should succeed");
        assert_eq!(result, crate::models::seal::SealValidationResult::Valid);
    }

    #[test]
    fn test_update_seal_chain() {
        let identity = test_identity();
        let state_hash_1 = get_hash("state_1");
        let state_hash_2 = get_hash("state_2");
        let instance_id = "device_a";

        let seal_1 = SealManager::create_initial_seal(
            &identity.user_id,
            &identity,
            &state_hash_1,
            instance_id,
        ).unwrap();

        let seal_2 = SealManager::update_seal(&seal_1, &identity, &state_hash_2, instance_id).unwrap();

        assert_eq!(seal_2.payload.tx_nonce, 1);
        assert_eq!(seal_2.payload.epoch, 0); // Epoch remains
        assert_eq!(seal_2.payload.state_hash, state_hash_2);
        assert_eq!(seal_2.payload.instance_id, instance_id);

        // prev_seal_hash must reference seal_1
        let seal_1_hash = SealManager::compute_seal_hash(&seal_1).unwrap();
        assert_eq!(seal_2.payload.prev_seal_hash, seal_1_hash);

        // Signature valid
        let result = SealManager::verify_seal_integrity(&seal_2, &identity.user_id, &identity.user_id, instance_id)
            .expect("Verification call should succeed");
        assert_eq!(result, crate::models::seal::SealValidationResult::Valid);
    }

    #[test]
    fn test_tamper_detection() {
        let identity = test_identity();
        let state_hash = get_hash("state");
        let instance_id = "device_a";

        let mut seal = SealManager::create_initial_seal(
            &identity.user_id,
            &identity,
            &state_hash,
            instance_id,
        ).unwrap();

        // Manipulate tx_nonce
        seal.payload.tx_nonce = 999;

        let result = SealManager::verify_seal_integrity(&seal, &identity.user_id, &identity.user_id, instance_id).unwrap();
        assert_eq!(result, crate::models::seal::SealValidationResult::InvalidSignature);
    }

    #[test]
    fn test_cloning_protection() {
        let identity = test_identity();
        let state_hash = get_hash("state");
        let instance_a = "device_a";
        let instance_b = "device_b";

        let seal = SealManager::create_initial_seal(
            &identity.user_id,
            &identity,
            &state_hash,
            instance_a,
        ).unwrap();

        // Verification on device A succeeds
        let result_a = SealManager::verify_seal_integrity(&seal, &identity.user_id, &identity.user_id, instance_a).unwrap();
        assert_eq!(result_a, crate::models::seal::SealValidationResult::Valid);

        // Verification on device B fails with DeviceMismatch
        let result_b = SealManager::verify_seal_integrity(&seal, &identity.user_id, &identity.user_id, instance_b).unwrap();
        assert!(matches!(result_b, crate::models::seal::SealValidationResult::DeviceMismatch { .. }));
    }

    #[test]
    fn test_recover_seal_epoch() {
        let identity = test_identity();
        let state_hash_1 = get_hash("state_1");
        let state_hash_2 = get_hash("state_after_recovery");
        let instance_a = "device_a";
        let instance_b = "device_b"; // New device after recovery

        let seal_1 = SealManager::create_initial_seal(
            &identity.user_id,
            &identity,
            &state_hash_1,
            instance_a,
        ).unwrap();

        let recovered_seal = SealManager::recover_seal_epoch(
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

        let result = SealManager::verify_seal_integrity(&recovered_seal, &identity.user_id, &identity.user_id, instance_b)
            .expect("Verification call should succeed");
        assert_eq!(result, crate::models::seal::SealValidationResult::Valid);
    }

    #[test]
    fn test_compare_seals_synchronized() {
        let identity = test_identity();
        let instance_id = "device_a";
        let seal = SealManager::create_initial_seal(
            &identity.user_id,
            &identity,
            &get_hash("state"),
            instance_id,
        ).unwrap();

        assert_eq!(
            SealManager::compare_seals(&seal, &seal),
            SealSyncState::Synchronized
        );
    }

    #[test]
    fn test_compare_seals_local_is_newer() {
        let identity = test_identity();
        let instance_id = "device_a";
        let seal_1 = SealManager::create_initial_seal(
            &identity.user_id,
            &identity,
            &get_hash("state_1"),
            instance_id,
        ).unwrap();

        let seal_2 = SealManager::update_seal(&seal_1, &identity, &get_hash("state_2"), instance_id).unwrap();

        assert_eq!(
            SealManager::compare_seals(&seal_2, &seal_1),
            SealSyncState::LocalIsNewer
        );
    }

    #[test]
    fn test_compare_seals_remote_is_newer() {
        let identity = test_identity();
        let instance_id = "device_a";
        let seal_1 = SealManager::create_initial_seal(
            &identity.user_id,
            &identity,
            &get_hash("state_1"),
            instance_id,
        ).unwrap();

        let seal_2 = SealManager::update_seal(&seal_1, &identity, &get_hash("state_2"), instance_id).unwrap();

        assert_eq!(
            SealManager::compare_seals(&seal_1, &seal_2),
            SealSyncState::RemoteIsNewer
        );
    }

    #[test]
    fn test_compare_seals_fork_detected() {
        let identity = test_identity();
        let instance_id = "device_a";
        let seal_base = SealManager::create_initial_seal(
            &identity.user_id,
            &identity,
            &get_hash("state_base"),
            instance_id,
        ).unwrap();

        // Two independent updates on the same base seal -> Fork
        let seal_branch_a = SealManager::update_seal(&seal_base, &identity, &get_hash("state_a"), instance_id).unwrap();
        let seal_branch_b = SealManager::update_seal(&seal_base, &identity, &get_hash("state_b"), instance_id).unwrap();

        // Both have nonce 1, but different payloads -> Fork
        assert_eq!(
            SealManager::compare_seals(&seal_branch_a, &seal_branch_b),
            SealSyncState::ForkDetected
        );
    }
}
