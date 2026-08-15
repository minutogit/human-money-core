//! # src/services/integrity_manager.rs
//!
//! Service for verifying storage integrity and generating
//! integrity reports based on Storage Integrity.

use crate::error::VoucherCoreError;
use crate::models::storage_integrity::{IntegrityReport, LocalIntegrityRecord, IntegrityPayload, INTEGRITY_FILE_NAME};
use crate::models::profile::UserIdentity;
use crate::models::seal::WalletSeal;
use crate::services::crypto_utils::{get_hash, sign_ed25519, verify_ed25519};
use crate::services::seal_manager::SealManager;
use crate::services::utils::{get_current_timestamp, to_canonical_json};
use std::collections::HashMap;

pub struct IntegrityManager;

impl IntegrityManager {
    /// Creates a new signed Storage Integrity Record based on the current state.
    pub fn create_integrity_record(
        identity: &UserIdentity,
        current_seal: &WalletSeal,
        item_hashes: HashMap<String, String>,
    ) -> Result<LocalIntegrityRecord, VoucherCoreError> {
        let seal_hash = SealManager::compute_seal_hash(current_seal)?;

        let payload = IntegrityPayload {
            version: 1,
            seal_hash,
            item_hashes,
            timestamp: get_current_timestamp(),
        };

        let payload_canonical = to_canonical_json(&payload)?;
        let payload_hash = get_hash(payload_canonical.as_bytes());
        let signature = sign_ed25519(&identity.signing_key, payload_hash.as_bytes());
        let signature_str = bs58::encode(signature.to_bytes()).into_string();

        Ok(LocalIntegrityRecord {
            payload,
            signature: signature_str,
        })
    }

    /// Verifies an Integrity Record and creates an integrity report.
    pub fn verify_integrity(
        integrity_record: &LocalIntegrityRecord,
        current_seal: &WalletSeal,
        actual_item_hashes: HashMap<String, String>,
        expected_pubkey_user_id: &str,
    ) -> Result<IntegrityReport, VoucherCoreError> {
        // 1. Verify signature of Integrity Record
        let pubkey = crate::services::crypto_utils::get_pubkey_from_user_id(expected_pubkey_user_id)?;
        let payload_canonical = to_canonical_json(&integrity_record.payload)?;
        let payload_hash = get_hash(payload_canonical.as_bytes());

        let signature_bytes = bs58::decode(&integrity_record.signature)
            .into_vec()
            .map_err(|e| VoucherCoreError::Generic(format!("Failed to decode integrity signature: {}", e)))?;

        let signature = ed25519_dalek::Signature::from_slice(&signature_bytes)
            .map_err(|e| VoucherCoreError::Generic(format!("Invalid integrity signature format: {}", e)))?;

        if !verify_ed25519(&pubkey, payload_hash.as_bytes(), &signature) {
            return Ok(IntegrityReport::InvalidSignature);
        }

        // 2. Epoch check (Rollback Protection)
        let current_seal_hash = SealManager::compute_seal_hash(current_seal)?;
        if integrity_record.payload.seal_hash != current_seal_hash {
            return Ok(IntegrityReport::IntegrityOutdated);
        }

        let mut missing = Vec::new();
        let mut manipulated = Vec::new();
        let mut unknown = Vec::new();

        // 3. Check items from Integrity Record
        for (name, expected_hash) in &integrity_record.payload.item_hashes {
            match actual_item_hashes.get(name) {
                Some(actual_hash) => {
                    if actual_hash != expected_hash {
                        manipulated.push(name.clone());
                    }
                }
                None => {
                    missing.push(name.clone());
                }
            }
        }

        // 4. Unknown items in storage
        for name in actual_item_hashes.keys() {
            if !integrity_record.payload.item_hashes.contains_key(name) {
                // Some files are ignored (e.g. the Integrity Record itself or hidden files)
                if name != INTEGRITY_FILE_NAME && !name.starts_with('.') {
                    unknown.push(name.clone());
                }
            }
        }

        if missing.is_empty() && manipulated.is_empty() && unknown.is_empty() {
            Ok(IntegrityReport::Valid)
        } else {
            if !missing.is_empty() {
                Ok(IntegrityReport::MissingItems(missing))
            } else if !manipulated.is_empty() {
                Ok(IntegrityReport::ManipulatedItems(manipulated))
            } else {
                Ok(IntegrityReport::UnknownItems(unknown))
            }
        }
    }
}
