//! # src/storage/file_storage.rs
//!
//! Concrete `FileStorage` facade — slim wrapper delegating to modular sub-stores.
//!
//! Streamline Phase-2 splits the former 1 500-line `FileStorage` into
//! `key_manager`, `encrypted_store`, `event_store`, `lock` and `integrity`
//! submodules. This file retains the public `FileStorage` API, the on-disk
//! container schemas (`ProfileStorageContainer`, `EncryptedStorageContainer`)
//! and the atomic-write / profile-container helpers. All behavioural code is
//! delegated to the submodules, preserving 100 % binary compatibility and the
//! exact `save_wallet` store-binding serialization order:
//! `vouchers.enc` bytes → `HMAC-SHA3` → embedded in `profile.enc` → atomic writes.

use super::{AuthMethod, StorageError};
use crate::models::conflict::CanonicalMetadataStore;
use crate::models::conflict::{KnownFingerprints, OwnFingerprints, ProofStore};
use crate::models::profile::{BundleMetadataStore, UserIdentity, UserProfile, VoucherStore};
use crate::services::crypto;
use crate::storage::key_manager::{KEY_SIZE, SALT_SIZE};
use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{fs, path::{Path, PathBuf}};

// Re-export key-manager helpers for internal crate use (keeps import paths stable)
use crate::storage::key_manager::{
    derive_key_from_password, derive_key_from_signing_key, derive_store_binding_hash, get_file_key,
};

// --- Internal Constants and Structures ---

pub(crate) const LOCK_FILE_NAME: &str = ".wallet.lock";
pub(crate) const PROFILE_FILE_NAME: &str = "profile.enc";
pub(crate) const VOUCHER_STORE_FILE_NAME: &str = "vouchers.enc";
pub(crate) const BUNDLE_META_FILE_NAME: &str = "bundles.meta.enc";
pub(crate) const KNOWN_FINGERPRINTS_FILE_NAME: &str = "known_fingerprints.enc";
pub(crate) const PROOF_STORE_FILE_NAME: &str = "proofs.enc";
pub(crate) const OWN_FINGERPRINTS_FILE_NAME: &str = "own_fingerprints.enc";
pub(crate) const FINGERPRINT_METADATA_FILE_NAME: &str = "fingerprint_metadata.enc";
pub(crate) const SEAL_FILE_NAME: &str = "seal.enc";
pub(crate) const LEGACY_EVENTS_FILE_NAME: &str = "events.json.enc";
pub(crate) const EVENTS_DIR_NAME: &str = "events";

/// Private module to encapsulate Serde logic for Base64 encoding of vectors.
mod base64_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    /// Serializes a `&[u8]` slice as a Base64 string.
    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&general_purpose::STANDARD.encode(bytes))
    }

    /// Deserializes a Base64 string into a `Vec<u8>`.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        general_purpose::STANDARD
            .decode(s)
            .map_err(serde::de::Error::custom)
    }
}

/// Private module to encapsulate Serde logic for Base64 encoding of fixed arrays.
mod base64_array_serde {
    use super::*;
    use serde::{Deserializer, Serializer};
    use std::convert::TryInto;

    /// Serializes a `&[u8; N]` array as a Base64 string.
    pub fn serialize<S, const N: usize>(array: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&general_purpose::STANDARD.encode(array))
    }

    /// Deserializes a Base64 string into a `[u8; N]` array.
    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = general_purpose::STANDARD
            .decode(s)
            .map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom(format!("Expected a byte array of length {}", N)))
    }
}

/// Container for the encrypted user profile, including key-wrapping information.
#[derive(Serialize, Deserialize)]
pub(crate) struct ProfileStorageContainer {
    #[serde(with = "base64_array_serde")]
    pub(crate) password_kdf_salt: [u8; SALT_SIZE],
    #[serde(with = "base64_serde")]
    pub(crate) password_wrapped_key_with_nonce: Vec<u8>,
    #[serde(with = "base64_array_serde")]
    pub(crate) mnemonic_kdf_salt: [u8; SALT_SIZE],
    #[serde(with = "base64_serde")]
    pub(crate) mnemonic_wrapped_key_with_nonce: Vec<u8>,
    #[serde(with = "base64_serde")]
    pub(crate) encrypted_profile_payload: Vec<u8>,
    /// Crash-consistency binding (HMSEC-SA05-04/-07): keyed SHA3-256
    /// commitment over the exact serialized bytes of the
    /// `VoucherStorageContainer` written in the same `save_wallet` cycle,
    /// mixed with the secret file key (`derive_store_binding_hash`).
    #[serde(default)]
    pub(crate) store_binding_hash: Option<String>,
}

/// Bundles the profile and the private key for storage.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct ProfilePayload {
    pub(crate) profile: UserProfile,
    pub(crate) signing_key_bytes: Vec<u8>,
}

/// Generic container for any encrypted store payload (consolidated from 8 identical containers).
#[derive(Serialize, Deserialize)]
pub(crate) struct EncryptedStorageContainer {
    #[serde(with = "base64_serde")]
    pub(crate) encrypted_store_payload: Vec<u8>,
}

// Type alias for readability at call sites (all identical to the generic container).
pub(crate) type VoucherStorageContainer = EncryptedStorageContainer;

// --- FileStorage Implementation ---

/// An implementation of the `Storage` trait that stores data in encrypted files.
pub struct FileStorage {
    /// The path to the user's specific, anonymous subdirectory.
    pub user_storage_path: PathBuf,
    /// The path to the lock file for this wallet.
    lock_file_path: PathBuf,
}

impl FileStorage {
    /// Creates a new `FileStorage` instance for a specific user directory.
    pub fn new(user_storage_path: impl Into<PathBuf>) -> Self {
        let path_buf = user_storage_path.into();
        FileStorage {
            lock_file_path: path_buf.join(LOCK_FILE_NAME),
            user_storage_path: path_buf,
        }
    }

    /// Loads the `ProfileStorageContainer` to access the key metadata.
    pub(crate) fn load_profile_container(&self) -> Result<ProfileStorageContainer, StorageError> {
        let profile_path = self.user_storage_path.join(PROFILE_FILE_NAME);
        if !profile_path.exists() {
            return Err(StorageError::NotFound);
        }
        let container_bytes = fs::read(profile_path)?;
        serde_json::from_slice(&container_bytes)
            .map_err(|e| StorageError::InvalidFormat(e.to_string()))
    }

    /// Fetches the master file key using any `AuthMethod`.
    pub(crate) fn get_master_key_from_auth(&self, auth: &AuthMethod) -> Result<[u8; KEY_SIZE], StorageError> {
        let profile_container = self.load_profile_container()?;
        let file_key_bytes = get_file_key(auth, &profile_container)?;

        file_key_bytes
            .try_into()
            .map_err(|_| StorageError::InvalidFormat("Invalid file key length".to_string()))
    }

    /// Atomic write helper: writes `data` to `relative_path` via tmp-file + rename.
    ///
    /// Durability: on non-WASM targets the tmp file is `fsync`'d before rename
    /// and the parent directory is `fsync`'d after rename (torn-write protection).
    pub(crate) fn write_atomic(
        &self,
        relative_path: impl AsRef<Path>,
        data: &[u8],
    ) -> Result<(), StorageError> {
        let dest = self.user_storage_path.join(relative_path.as_ref());
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = PathBuf::from(format!("{}.tmp", dest.display()));
        fs::write(&tmp, data)?;
        #[cfg(not(target_arch = "wasm32"))]
        {
            let file = fs::File::open(&tmp)?;
            file.sync_all()?;
        }
        fs::rename(&tmp, &dest)?;
        #[cfg(not(target_arch = "wasm32"))]
        {
            if let Some(parent) = dest.parent() {
                if let Ok(dir) = fs::File::open(parent) {
                    let _ = dir.sync_all();
                }
            }
        }
        Ok(())
    }

    /// Generic helper: loads, decrypts and deserializes an encrypted payload.
    /// Delegates to `encrypted_store::load_encrypted_payload`.
    fn load_encrypted_payload<T>(
        &self,
        relative_path: impl AsRef<Path>,
        auth: &AuthMethod,
    ) -> Result<Option<T>, StorageError>
    where
        T: for<'de> Deserialize<'de>,
    {
        crate::storage::encrypted_store::load_encrypted_payload(self, relative_path, auth)
    }

    /// Generic helper: encrypts and atomically persists a payload.
    /// Delegates to `encrypted_store::save_encrypted_payload`.
    fn save_encrypted_payload<T>(
        &mut self,
        relative_path: impl AsRef<Path>,
        auth: &AuthMethod,
        value: &T,
    ) -> Result<(), StorageError>
    where
        T: Serialize,
    {
        crate::storage::encrypted_store::save_encrypted_payload(self, relative_path, auth, value)
    }

    pub fn derive_key_for_session(&self, password: &str) -> Result<[u8; 32], StorageError> {
        let profile_container = self.load_profile_container()?;
        derive_key_from_password(password, &profile_container.password_kdf_salt)
    }

    pub fn profile_exists(&self) -> bool {
        self.user_storage_path.join(PROFILE_FILE_NAME).exists()
    }

    pub fn load_wallet(
        &self,
        auth: &AuthMethod,
    ) -> Result<(UserProfile, VoucherStore, UserIdentity), StorageError> {
        if !self.user_storage_path.exists() {
            return Err(StorageError::NotFound);
        }

        let profile_path = self.user_storage_path.join(PROFILE_FILE_NAME);
        let store_path = self.user_storage_path.join(VOUCHER_STORE_FILE_NAME);

        let profile_container_bytes = fs::read(profile_path)?;
        let profile_container: ProfileStorageContainer =
            serde_json::from_slice(&profile_container_bytes)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        // Decrypt the master file key based on the authentication method.
        let file_key_bytes = get_file_key(auth, &profile_container)?;
        let file_key: [u8; KEY_SIZE] = file_key_bytes
            .try_into()
            .map_err(|_| StorageError::InvalidFormat("Invalid file key length".to_string()))?;

        // Decrypt the payload containing the profile and private key.
        let payload_bytes =
            crypto::decrypt_data(&file_key, &profile_container.encrypted_profile_payload)
                .map_err(|e| {
                    StorageError::InvalidFormat(format!("Failed to decrypt profile payload: {}", e))
                })?;
        let payload: ProfilePayload = serde_json::from_slice(&payload_bytes)
            .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        // Load the VoucherStore.
        let store = if store_path.exists() {
            let store_container_bytes = fs::read(store_path)?;

            let expected_hash = profile_container.store_binding_hash.as_ref().ok_or_else(|| {
                StorageError::StateConflict(
                    "profile.enc does not carry an authenticated store_binding_hash \
                     (field stripped or pre-hardening container); refusing to load \
                     possibly rolled-back wallet state"
                        .to_string(),
                )
            })?;
            let actual_hash = derive_store_binding_hash(&file_key, &store_container_bytes);
            if actual_hash != *expected_hash {
                return Err(StorageError::StateConflict(
                    "vouchers.enc does not match the store generation bound in \
                     profile.enc (possible rollback or torn write); refusing to \
                     load stale wallet state"
                        .to_string(),
                ));
            }

            let store_container: VoucherStorageContainer =
                serde_json::from_slice(&store_container_bytes)
                    .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
            let store_bytes =
                crypto::decrypt_data(&file_key, &store_container.encrypted_store_payload)
                    .map_err(|e| {
                        StorageError::InvalidFormat(format!("Failed to decrypt store: {}", e))
                    })?;

            // Schema gate (HMSEC-SA05-08)
            crate::storage::encrypted_store::gate_legacy_transaction_schema(&store_bytes)?;

            serde_json::from_slice(&store_bytes)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?
        } else {
            VoucherStore::default()
        };

        // Reconstruct the UserIdentity.
        let signing_key_bytes: &[u8; 32] = payload
            .signing_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| {
                StorageError::InvalidFormat("Invalid signing key length in storage".to_string())
            })?;
        let signing_key = SigningKey::from_bytes(signing_key_bytes);
        let public_key = signing_key.verifying_key();

        let identity = UserIdentity {
            signing_key,
            public_key,
            user_id: payload.profile.user_id.clone(),
        };

        Ok((payload.profile, store, identity))
    }

    fn write_profile_and_voucher_store_containers(
        &self,
        profile: &UserProfile,
        store: &VoucherStore,
        identity: &UserIdentity,
        auth: &AuthMethod,
    ) -> Result<[u8; KEY_SIZE], StorageError> {
        fs::create_dir_all(&self.user_storage_path)?;
        let profile_path = self.user_storage_path.join(PROFILE_FILE_NAME);

        let file_key: [u8; KEY_SIZE];
        let mut profile_container: ProfileStorageContainer;

        let payload = ProfilePayload {
            profile: profile.clone(),
            signing_key_bytes: identity.signing_key.to_bytes().to_vec(),
        };

        if !profile_path.exists() {
            // Initial save: Generate all keys and salts.
            let mut new_file_key = [0u8; KEY_SIZE];
            OsRng.fill_bytes(&mut new_file_key);
            file_key = new_file_key;

            let mut pw_salt = [0u8; SALT_SIZE];
            OsRng.fill_bytes(&mut pw_salt);
            let password_key = match auth {
                AuthMethod::Password(p) => {
                    if p.is_empty() {
                        return Err(StorageError::EmptyPassword);
                    }
                    derive_key_from_password(p, &pw_salt)?
                }
                _ => {
                    return Err(StorageError::InvalidAuthMethod {
                        reason: "Only Password auth supported for initial save".to_string(),
                    });
                }
            };
            let pw_wrapped_key = crypto::encrypt_data(&password_key, &file_key)
                .map_err(|e| StorageError::EncryptionFailed { reason: e.to_string() })?;

            let mut mn_salt = [0u8; SALT_SIZE];
            OsRng.fill_bytes(&mut mn_salt);
            let mnemonic_key = derive_key_from_signing_key(&identity.signing_key, &mn_salt)?;
            let mn_wrapped_key = crypto::encrypt_data(&mnemonic_key, &file_key)
                .map_err(|e| StorageError::EncryptionFailed { reason: e.to_string() })?;

            let profile_payload =
                crypto::encrypt_data(&file_key, &serde_json::to_vec(&payload)
                    .map_err(|e| StorageError::InvalidFormat(e.to_string()))?)
                    .map_err(|e| StorageError::EncryptionFailed { reason: e.to_string() })?;

            profile_container = ProfileStorageContainer {
                password_kdf_salt: pw_salt,
                password_wrapped_key_with_nonce: pw_wrapped_key,
                mnemonic_kdf_salt: mn_salt,
                mnemonic_wrapped_key_with_nonce: mn_wrapped_key,
                encrypted_profile_payload: profile_payload,
                // Bound to the store generation below (HMSEC-SA05-04).
                store_binding_hash: None,
            };
        } else {
            // Update an existing wallet: Load container, decrypt key, and encrypt new payload.
            let existing_container_bytes = fs::read(&profile_path)?;
            let mut existing_container: ProfileStorageContainer =
                serde_json::from_slice(&existing_container_bytes)
                    .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

            let decrypted_file_key = get_file_key(auth, &existing_container)?;

            file_key = decrypted_file_key
                .try_into()
                .map_err(|_| StorageError::InvalidFormat("Invalid file key".to_string()))?;

            existing_container.encrypted_profile_payload =
                crypto::encrypt_data(&file_key, &serde_json::to_vec(&payload)
                    .map_err(|e| StorageError::InvalidFormat(e.to_string()))?)
                    .map_err(|e| StorageError::EncryptionFailed { reason: e.to_string() })?;
            profile_container = existing_container;
        }

        // Save the VoucherStore.
        let store_payload =
            crypto::encrypt_data(&file_key, &serde_json::to_vec(store)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?)
                .map_err(|e| StorageError::EncryptionFailed { reason: e.to_string() })?;
        let store_container = VoucherStorageContainer {
            encrypted_store_payload: store_payload,
        };

        // Bind the exact serialized store generation to this profile
        // generation (HMSEC-SA05-04/-07): the commitment is keyed under the
        // secret file key so a local attacker cannot recompute it over stale
        // bytes; a rolled-back or torn-written vouchers.enc is rejected on load.
        // IMPORTANT: preserve exact serialization order (vouchers.enc bytes →
        // HMAC → embed in profile.enc → atomic writes) for wire compatibility.
        let store_container_bytes = serde_json::to_vec(&store_container)
            .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
        profile_container.store_binding_hash =
            Some(derive_store_binding_hash(&file_key, &store_container_bytes));

        self.write_atomic(
            PROFILE_FILE_NAME,
            &serde_json::to_vec(&profile_container)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?,
        )?;
        self.write_atomic(VOUCHER_STORE_FILE_NAME, &store_container_bytes)?;

        Ok(file_key)
    }

    pub fn save_wallet(
        &mut self,
        profile: &UserProfile,
        store: &VoucherStore,
        identity: &UserIdentity,
        auth: &AuthMethod,
    ) -> Result<(), StorageError> {
        self.write_profile_and_voucher_store_containers(profile, store, identity, auth)?;
        Ok(())
    }

    pub fn reset_password(
        &mut self,
        identity: &UserIdentity,
        new_password: &str,
    ) -> Result<(), StorageError> {
        if new_password.is_empty() {
            return Err(StorageError::EmptyPassword);
        }
        let profile_path = self.user_storage_path.join(PROFILE_FILE_NAME);
        if !profile_path.exists() {
            return Err(StorageError::NotFound);
        }

        let container_bytes = fs::read(&profile_path)?;
        let mut container: ProfileStorageContainer = serde_json::from_slice(&container_bytes)
            .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        let mnemonic_key =
            derive_key_from_signing_key(&identity.signing_key, &container.mnemonic_kdf_salt)?;
        let file_key =
            crypto::decrypt_data(&mnemonic_key, &container.mnemonic_wrapped_key_with_nonce)
                .map_err(|_| StorageError::AuthenticationFailed)?;

        let mut new_pw_salt = [0u8; SALT_SIZE];
        OsRng.fill_bytes(&mut new_pw_salt);
        let new_password_key = derive_key_from_password(new_password, &new_pw_salt)?;
        let new_pw_wrapped_key = crypto::encrypt_data(&new_password_key, &file_key)
            .map_err(|e| StorageError::EncryptionFailed { reason: e.to_string() })?;

        container.password_kdf_salt = new_pw_salt;
        container.password_wrapped_key_with_nonce = new_pw_wrapped_key;

        self.write_atomic(
            PROFILE_FILE_NAME,
            &serde_json::to_vec(&container)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?,
        )?;

        Ok(())
    }

    pub fn load_known_fingerprints(
        &self,
        auth: &AuthMethod,
    ) -> Result<KnownFingerprints, StorageError> {
        Ok(self
            .load_encrypted_payload::<KnownFingerprints>(KNOWN_FINGERPRINTS_FILE_NAME, auth)?
            .unwrap_or_default())
    }

    pub fn save_known_fingerprints(
        &mut self,
        auth: &AuthMethod,
        fingerprints: &KnownFingerprints,
    ) -> Result<(), StorageError> {
        self.save_encrypted_payload(KNOWN_FINGERPRINTS_FILE_NAME, auth, fingerprints)
    }

    pub fn load_own_fingerprints(
        &self,
        auth: &AuthMethod,
    ) -> Result<OwnFingerprints, StorageError> {
        Ok(self
            .load_encrypted_payload::<OwnFingerprints>(OWN_FINGERPRINTS_FILE_NAME, auth)?
            .unwrap_or_default())
    }

    pub fn save_own_fingerprints(
        &mut self,
        auth: &AuthMethod,
        fingerprints: &OwnFingerprints,
    ) -> Result<(), StorageError> {
        self.save_encrypted_payload(OWN_FINGERPRINTS_FILE_NAME, auth, fingerprints)
    }

    pub fn load_bundle_metadata(
        &self,
        auth: &AuthMethod,
    ) -> Result<BundleMetadataStore, StorageError> {
        let meta_path = self.user_storage_path.join(BUNDLE_META_FILE_NAME);
        if !meta_path.exists() {
            // Preserve NotFound when profile is missing (original checked profile first).
            self.get_master_key_from_auth(auth)?;
            return Ok(BundleMetadataStore::default());
        }
        Ok(self
            .load_encrypted_payload::<BundleMetadataStore>(BUNDLE_META_FILE_NAME, auth)?
            .unwrap_or_default())
    }

    pub fn save_bundle_metadata(
        &mut self,
        auth: &AuthMethod,
        metadata: &BundleMetadataStore,
    ) -> Result<(), StorageError> {
        self.save_encrypted_payload(BUNDLE_META_FILE_NAME, auth, metadata)
    }

    pub fn load_proofs(&self, auth: &AuthMethod) -> Result<ProofStore, StorageError> {
        let proof_path = self.user_storage_path.join(PROOF_STORE_FILE_NAME);
        if !proof_path.exists() {
            self.get_master_key_from_auth(auth)?;
            return Ok(ProofStore::default());
        }
        Ok(self
            .load_encrypted_payload::<ProofStore>(PROOF_STORE_FILE_NAME, auth)?
            .unwrap_or_default())
    }

    pub fn save_proofs(
        &mut self,
        auth: &AuthMethod,
        proof_store: &ProofStore,
    ) -> Result<(), StorageError> {
        if proof_store.proofs.is_empty() {
            self.get_master_key_from_auth(auth)?;
            let proof_path = self.user_storage_path.join(PROOF_STORE_FILE_NAME);
            if proof_path.exists() {
                fs::remove_file(proof_path)?;
            }
            return Ok(());
        }
        self.save_encrypted_payload(PROOF_STORE_FILE_NAME, auth, proof_store)
    }

    pub fn load_fingerprint_metadata(
        &self,
        auth: &AuthMethod,
    ) -> Result<CanonicalMetadataStore, StorageError> {
        Ok(self
            .load_encrypted_payload::<CanonicalMetadataStore>(
                FINGERPRINT_METADATA_FILE_NAME,
                auth,
            )?
            .unwrap_or_default())
    }

    pub fn save_fingerprint_metadata(
        &mut self,
        auth: &AuthMethod,
        metadata: &CanonicalMetadataStore,
    ) -> Result<(), StorageError> {
        if metadata.is_empty() {
            self.get_master_key_from_auth(auth)?;
            let metadata_path = self.user_storage_path.join(FINGERPRINT_METADATA_FILE_NAME);
            if metadata_path.exists() {
                fs::remove_file(metadata_path)?;
            }
            return Ok(());
        }
        self.save_encrypted_payload(FINGERPRINT_METADATA_FILE_NAME, auth, metadata)
    }

    /// Stores an arbitrary, named data block encrypted.
    pub fn save_arbitrary_data(
        &mut self,
        auth: &AuthMethod,
        name: &str,
        data: &[u8],
    ) -> Result<(), StorageError> {
        if name.contains('/') || name.contains('\\') || name.contains("..") {
            return Err(StorageError::InvalidDataBlockName { name: name.to_string() });
        }

        let master_key = self.get_master_key_from_auth(auth)?;

        let ciphertext = crypto::encrypt_data(&master_key, data)
            .map_err(|e| StorageError::EncryptionFailed { reason: e.to_string() })?;
        self.write_atomic(format!("generic_{}.enc", name), &ciphertext)?;

        Ok(())
    }

    /// Loads any named and encrypted data block.
    pub fn load_arbitrary_data(
        &self,
        auth: &AuthMethod,
        name: &str,
    ) -> Result<Vec<u8>, StorageError> {
        if name.contains('/') || name.contains('\\') || name.contains("..") {
            return Err(StorageError::InvalidDataBlockName { name: name.to_string() });
        }

        let master_key = self.get_master_key_from_auth(auth)?;

        let path = self
            .user_storage_path
            .join(format!("generic_{}.enc", name));

        if !path.exists() {
            return Err(StorageError::NotFound);
        }

        let ciphertext = fs::read(&path).map_err(StorageError::from)?;
        crypto::decrypt_data(&master_key, &ciphertext)
            .map_err(|_| StorageError::AuthenticationFailed)
    }

    pub fn test_session_key(&self, session_key: &[u8; 32]) -> Result<(), StorageError> {
        let profile_container = self.load_profile_container()?;

        let _decrypted = crypto::decrypt_data(
            session_key,
            &profile_container.password_wrapped_key_with_nonce,
        )
        .map_err(|_| StorageError::AuthenticationFailed)?;

        Ok(())
    }

    // --- Lock Logic (delegated) ---

    pub fn lock(&self) -> Result<bool, StorageError> {
        crate::storage::lock::acquire_lock(self)
    }

    pub fn unlock(&self) -> Result<(), StorageError> {
        crate::storage::lock::release_lock(self)
    }

    pub fn get_lock_file_path(&self) -> &std::path::PathBuf {
        &self.lock_file_path
    }

    pub fn read_generation(&self) -> Result<u64, StorageError> {
        let path = self.user_storage_path.join(".wallet.generation");
        if !path.exists() {
            return Ok(0);
        }
        let content = fs::read_to_string(&path)?;
        let gen_count = content.trim().parse::<u64>().map_err(|e| {
            StorageError::InvalidFormat(format!("Failed to parse generation counter: {}", e))
        })?;
        Ok(gen_count)
    }

    pub fn write_generation(&mut self, expected: u64, new: u64) -> Result<(), StorageError> {
        fs::create_dir_all(&self.user_storage_path)?;
        let current = self.read_generation()?;
        if current != expected {
            return Err(StorageError::StateConflict(format!(
                "Generation counter mismatch: expected {}, found {}",
                expected, current
            )));
        }
        self.write_atomic(".wallet.generation", new.to_string().as_bytes())
    }

    /// Atomically commits the entire wallet state (2-phase commit).
    ///
    /// **Phase 1 – Staging:** Encodes `vouchers.enc`, computes the keyed
    /// `store_binding_hash` (SHA3-256 over `file_key || store_container_bytes`)
    /// and embeds it byte-identically into `profile.enc`, then writes all
    /// modified containers (`profile.enc`, `vouchers.enc`, `bundles.meta.enc`,
    /// `known_fingerprints.enc`, `own_fingerprints.enc`, `proofs.enc`,
    /// `fingerprint_metadata.enc` and `events`) via atomic tmp+rename.
    ///
    /// **Phase 2 – Commit:** Only after every container has been durably
    /// staged the generation counter is bumped via `write_generation`. This
    /// single file is the atomic commit point; a crash before it leaves the
    /// previous consistent generation on disk, a crash after it leaves the
    /// fully staged new generation – never a torn mix where generation is new
    /// but data is old (or vice-versa).
    ///
    /// The `store_binding_hash` computation preserves exact byte identity with
    /// the historical `save_wallet` implementation:
    /// `vouchers.enc` bytes → `derive_store_binding_hash(file_key, bytes)` →
    /// `profile.store_binding_hash`.
    pub fn commit_wallet_atomic(
        &mut self,
        wallet: &mut crate::wallet::Wallet,
        identity: &crate::models::profile::UserIdentity,
        auth: &AuthMethod,
    ) -> Result<(), StorageError> {
        // --- Generation check (optimistic concurrency) ---
        let current_generation = self.read_generation()?;
        if current_generation != wallet.loaded_generation {
            return Err(StorageError::StateConflict(
                "State was modified externally!".to_string(),
            ));
        }
        let new_generation = current_generation + 1;

        let file_key = self.write_profile_and_voucher_store_containers(
            &wallet.profile,
            &wallet.voucher_store,
            identity,
            auth,
        )?;

        // --- 2. Staging: write all remaining containers atomically via tmp+rename ---

        // Helper to stage an encrypted store with the same file_key
        let stage_store = |this: &Self, rel: &str, plain_bytes: Vec<u8>| -> Result<(), StorageError> {
            let enc = crypto::encrypt_data(&file_key, &plain_bytes)
                .map_err(|e| StorageError::EncryptionFailed { reason: e.to_string() })?;
            let container = EncryptedStorageContainer {
                encrypted_store_payload: enc,
            };
            let data = serde_json::to_vec(&container)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
            this.write_atomic(rel, &data)
        };

        // Bundle metadata
        stage_store(
            self,
            BUNDLE_META_FILE_NAME,
            serde_json::to_vec(&wallet.bundle_meta_store)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?,
        )?;
        // Known fingerprints
        stage_store(
            self,
            KNOWN_FINGERPRINTS_FILE_NAME,
            serde_json::to_vec(&wallet.known_fingerprints)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?,
        )?;
        // Own fingerprints
        stage_store(
            self,
            OWN_FINGERPRINTS_FILE_NAME,
            serde_json::to_vec(&wallet.own_fingerprints)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?,
        )?;
        // Proofs (may be empty → delete file if present, matching save_proofs semantics)
        if wallet.proof_store.proofs.is_empty() {
            let proof_path = self.user_storage_path.join(PROOF_STORE_FILE_NAME);
            if proof_path.exists() {
                fs::remove_file(proof_path)?;
            }
        } else {
            stage_store(
                self,
                PROOF_STORE_FILE_NAME,
                serde_json::to_vec(&wallet.proof_store)
                    .map_err(|e| StorageError::InvalidFormat(e.to_string()))?,
            )?;
        }
        // Fingerprint metadata (may be empty → delete file if present)
        if wallet.fingerprint_metadata.is_empty() {
            let meta_path = self.user_storage_path.join(FINGERPRINT_METADATA_FILE_NAME);
            if meta_path.exists() {
                fs::remove_file(meta_path)?;
            }
        } else {
            stage_store(
                self,
                FINGERPRINT_METADATA_FILE_NAME,
                serde_json::to_vec(&wallet.fingerprint_metadata)
                    .map_err(|e| StorageError::InvalidFormat(e.to_string()))?,
            )?;
        }

        // Events: staging via append_events (uses same file_key now on disk)
        if !wallet.pending_events.is_empty() {
            self.append_events(auth, &wallet.pending_events)?;
        }

        // --- 3. Commit-Punkt: generation bump as atomic commit ---
        self.write_generation(current_generation, new_generation)?;
        wallet.loaded_generation = new_generation;

        // --- 4. Clear pending_events after durable commit ---
        if !wallet.pending_events.is_empty() {
            wallet.pending_events.clear();
        }

        Ok(())
    }

    /// Alias for `commit_wallet_atomic` (spec names `save_wallet_transaction`).
    #[deprecated(note = "Use `commit_wallet_atomic` instead. This alias will be removed in a future version.")]
    pub fn save_wallet_transaction(
        &mut self,
        wallet: &mut crate::wallet::Wallet,
        identity: &crate::models::profile::UserIdentity,
        auth: &AuthMethod,
    ) -> Result<(), StorageError> {
        self.commit_wallet_atomic(wallet, identity, auth)
    }

    pub fn save_seal(
        &mut self,
        auth: &AuthMethod,
        record: &crate::models::seal::LocalSealRecord,
    ) -> Result<(), StorageError> {
        self.save_encrypted_payload(SEAL_FILE_NAME, auth, record)
    }

    pub fn load_seal(
        &self,
        auth: &AuthMethod,
    ) -> Result<Option<crate::models::seal::LocalSealRecord>, StorageError> {
        self.load_encrypted_payload::<crate::models::seal::LocalSealRecord>(SEAL_FILE_NAME, auth)
    }

    pub fn get_item_hash(&self, name: &str) -> Result<String, StorageError> {
        crate::storage::integrity::get_item_hash(self, name)
    }

    pub fn save_integrity(
        &mut self,
        record: &crate::models::storage_integrity::LocalIntegrityRecord,
    ) -> Result<(), StorageError> {
        let json = serde_json::to_vec_pretty(record)
            .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
        self.write_atomic(crate::models::storage_integrity::INTEGRITY_FILE_NAME, &json)
    }

    pub fn load_integrity(
        &self,
    ) -> Result<Option<crate::models::storage_integrity::LocalIntegrityRecord>, StorageError> {
        let path = self
            .user_storage_path
            .join(crate::models::storage_integrity::INTEGRITY_FILE_NAME);
        if !path.exists() {
            return Ok(None);
        }

        let json = fs::read(path)?;
        let record = serde_json::from_slice(&json)
            .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        Ok(Some(record))
    }

    pub fn get_all_item_hashes(&self) -> Result<std::collections::HashMap<String, String>, StorageError> {
        crate::storage::integrity::get_all_item_hashes(self)
    }

    pub fn append_events(
        &mut self,
        auth: &AuthMethod,
        events: &[crate::models::wallet_event::WalletEvent],
    ) -> Result<(), StorageError> {
        crate::storage::event_store::append_events(self, auth, events)
    }

    pub fn load_events(
        &self,
        auth: &AuthMethod,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<crate::models::wallet_event::WalletEvent>, StorageError> {
        crate::storage::event_store::load_events(self, auth, offset, limit)
    }
}
