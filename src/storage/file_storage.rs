//! # src/storage/file_storage.rs
//!
//! An implementation of the `Storage` trait that stores data in multiple encrypted
//! files in the file system.

use super::{AuthMethod, Storage, StorageError};
use crate::models::conflict::CanonicalMetadataStore;
use crate::models::conflict::{KnownFingerprints, OwnFingerprints, ProofStore};
use crate::models::storage_integrity::INTEGRITY_FILE_NAME;
use crate::models::profile::{BundleMetadataStore, UserIdentity, UserProfile, VoucherStore};
mod crypto_utils {
    pub use crate::services::crypto_keys::derive_ed25519_keypair;
    pub use crate::services::crypto_symmetric::{decrypt_data, encrypt_data};
    pub use crate::services::crypto_utils::get_hash;
}
#[cfg(not(any(test, feature = "test-utils")))]
use argon2::Argon2;
use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{fs, io::Write, path::PathBuf};
use sysinfo::{Pid, System};

// --- Internal Constants and Structures ---

const SALT_SIZE: usize = 16;
const KEY_SIZE: usize = 32;
const LOCK_FILE_NAME: &str = ".wallet.lock";
const PROFILE_FILE_NAME: &str = "profile.enc";
const VOUCHER_STORE_FILE_NAME: &str = "vouchers.enc";
const BUNDLE_META_FILE_NAME: &str = "bundles.meta.enc";
const KNOWN_FINGERPRINTS_FILE_NAME: &str = "known_fingerprints.enc";
const PROOF_STORE_FILE_NAME: &str = "proofs.enc";
const OWN_FINGERPRINTS_FILE_NAME: &str = "own_fingerprints.enc";
const FINGERPRINT_METADATA_FILE_NAME: &str = "fingerprint_metadata.enc";
const SEAL_FILE_NAME: &str = "seal.enc";
const LEGACY_EVENTS_FILE_NAME: &str = "events.json.enc";
const EVENTS_DIR_NAME: &str = "events";

/// Private module to encapsulate Serde logic for Base64 encoding of vectors.
mod base64_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    /// Serialisiert einen `&[u8]`-Slice als Base64-String.
    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&general_purpose::STANDARD.encode(bytes))
    }

    /// Deserialisiert einen Base64-String in einen `Vec<u8>`.
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

    /// Serialisiert ein `&[u8; N]`-Array als Base64-String.
    pub fn serialize<S, const N: usize>(array: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&general_purpose::STANDARD.encode(array))
    }

    /// Deserialisiert einen Base64-String in ein `[u8; N]`-Array.
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
struct ProfileStorageContainer {
    #[serde(with = "base64_array_serde")]
    password_kdf_salt: [u8; SALT_SIZE],
    #[serde(with = "base64_serde")]
    password_wrapped_key_with_nonce: Vec<u8>,
    #[serde(with = "base64_array_serde")]
    mnemonic_kdf_salt: [u8; SALT_SIZE],
    #[serde(with = "base64_serde")]
    mnemonic_wrapped_key_with_nonce: Vec<u8>,
    #[serde(with = "base64_serde")]
    encrypted_profile_payload: Vec<u8>,
}

/// Bundles the profile and the private key for storage.
#[derive(Serialize, Deserialize, Clone)]
struct ProfilePayload {
    profile: UserProfile,
    signing_key_bytes: Vec<u8>,
}

/// Container for the encrypted voucher store.
#[derive(Serialize, Deserialize)]
struct VoucherStorageContainer {
    #[serde(with = "base64_serde")]
    encrypted_store_payload: Vec<u8>,
}

/// Container for the encrypted bundle metadata.
#[derive(Serialize, Deserialize)]
struct BundleMetadataContainer {
    #[serde(with = "base64_serde")]
    encrypted_store_payload: Vec<u8>,
}

/// Container for the `KnownFingerprints` store.
#[derive(Serialize, Deserialize)]
struct KnownFingerprintsContainer {
    #[serde(with = "base64_serde")]
    encrypted_store_payload: Vec<u8>,
}

/// Container for the `OwnFingerprints` store.
#[derive(Serialize, Deserialize)]
struct OwnFingerprintsContainer {
    #[serde(with = "base64_serde")]
    encrypted_store_payload: Vec<u8>,
}

/// Container for the encrypted proof store.
#[derive(Serialize, Deserialize)]
struct ProofStorageContainer {
    #[serde(with = "base64_serde")]
    encrypted_store_payload: Vec<u8>,
}

/// Container for the `CanonicalMetadataStore`.
#[derive(Serialize, Deserialize)]
struct FingerprintMetadataContainer {
    #[serde(with = "base64_serde")]
    encrypted_store_payload: Vec<u8>,
}

/// Container for the encrypted `LocalSealRecord`.
#[derive(Serialize, Deserialize)]
struct SealStorageContainer {
    #[serde(with = "base64_serde")]
    encrypted_store_payload: Vec<u8>,
}

/// Container for the encrypted wallet event log.
#[derive(Serialize, Deserialize)]
struct EventsStorageContainer {
    #[serde(with = "base64_serde")]
    encrypted_store_payload: Vec<u8>,
}

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
    ///
    /// This method is now decoupled from the path name generation logic
    /// and accepts the full path to the user directory directly.
    ///
    /// # Arguments
    /// * `user_storage_path` - The full path to the directory where the
    ///   encrypted wallet files of this profile are or should be stored.
    pub fn new(user_storage_path: impl Into<PathBuf>) -> Self {
        let path_buf = user_storage_path.into();
        FileStorage {
            lock_file_path: path_buf.join(LOCK_FILE_NAME),
            user_storage_path: path_buf,
        }
    }

    /// Loads the `ProfileStorageContainer` to access the key metadata.
    fn load_profile_container(&self) -> Result<ProfileStorageContainer, StorageError> {
        let profile_path = self.user_storage_path.join(PROFILE_FILE_NAME);
        if !profile_path.exists() {
            return Err(StorageError::NotFound);
        }
        let container_bytes = fs::read(profile_path)?;
        serde_json::from_slice(&container_bytes)
            .map_err(|e| StorageError::InvalidFormat(e.to_string()))
    }

    /// Holt den Master-Dateischlüssel unter Verwendung eines Passworts.

    /// Holt den Master-Dateischlüssel unter Verwendung einer beliebigen `AuthMethod`.
    /// This logic is required by all `load_*` methods.
    fn get_master_key_from_auth(&self, auth: &AuthMethod) -> Result<[u8; KEY_SIZE], StorageError> {
        let profile_container = self.load_profile_container()?;
        let file_key_bytes = get_file_key(auth, &profile_container)?;

        file_key_bytes
            .try_into()
            .map_err(|_| StorageError::InvalidFormat("Invalid file key length".to_string()))
    }
}

impl Storage for FileStorage {
    fn derive_key_for_session(&self, password: &str) -> Result<[u8; 32], StorageError> {
        let profile_container = self.load_profile_container()?;
        derive_key_from_password(password, &profile_container.password_kdf_salt)
    }

    fn profile_exists(&self) -> bool {
        self.user_storage_path.join(PROFILE_FILE_NAME).exists()
    }

    fn load_wallet(
        &self,
        auth: &AuthMethod,
    ) -> Result<(UserProfile, VoucherStore, UserIdentity), StorageError> {
        // Ensure the directory exists before reading.
        // Creation is the task of `save_wallet` or `create_profile`.
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
            crypto_utils::decrypt_data(&file_key, &profile_container.encrypted_profile_payload)
                .map_err(|e| {
                    StorageError::InvalidFormat(format!("Failed to decrypt profile payload: {}", e))
                })?;
        let payload: ProfilePayload = serde_json::from_slice(&payload_bytes)
            .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        // Load the VoucherStore.
        let store = if store_path.exists() {
            let store_container_bytes = fs::read(store_path)?;
            let store_container: VoucherStorageContainer =
                serde_json::from_slice(&store_container_bytes)
                    .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
            let store_bytes =
                crypto_utils::decrypt_data(&file_key, &store_container.encrypted_store_payload)
                    .map_err(|e| {
                        StorageError::InvalidFormat(format!("Failed to decrypt store: {}", e))
                    })?;
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

    fn save_wallet(
        &mut self,
        profile: &UserProfile,
        store: &VoucherStore,
        identity: &UserIdentity,
        auth: &AuthMethod,
    ) -> Result<(), StorageError> {
        fs::create_dir_all(&self.user_storage_path)?; // Creates the folder if not present
        let profile_path = self.user_storage_path.join(PROFILE_FILE_NAME);
        let store_path = self.user_storage_path.join(VOUCHER_STORE_FILE_NAME);

        let file_key: [u8; KEY_SIZE];
        let profile_container: ProfileStorageContainer;

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
                AuthMethod::Password(p) => derive_key_from_password(p, &pw_salt)?,
                _ => {
                    return Err(StorageError::Generic(
                        "Only Password auth supported for initial save".to_string(),
                    ));
                }
            };
            let pw_wrapped_key = crypto_utils::encrypt_data(&password_key, &file_key)
                .map_err(|e| StorageError::Generic(e.to_string()))?;

            let mut mn_salt = [0u8; SALT_SIZE];
            OsRng.fill_bytes(&mut mn_salt);
            let mnemonic_key = derive_key_from_signing_key(&identity.signing_key, &mn_salt)?;
            let mn_wrapped_key = crypto_utils::encrypt_data(&mnemonic_key, &file_key)
                .map_err(|e| StorageError::Generic(e.to_string()))?;

            let profile_payload =
                crypto_utils::encrypt_data(&file_key, &serde_json::to_vec(&payload).unwrap())
                    .map_err(|e| StorageError::Generic(e.to_string()))?;

            profile_container = ProfileStorageContainer {
                password_kdf_salt: pw_salt,
                password_wrapped_key_with_nonce: pw_wrapped_key,
                mnemonic_kdf_salt: mn_salt,
                mnemonic_wrapped_key_with_nonce: mn_wrapped_key,
                encrypted_profile_payload: profile_payload,
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
                crypto_utils::encrypt_data(&file_key, &serde_json::to_vec(&payload).unwrap())
                    .map_err(|e| StorageError::Generic(e.to_string()))?;
            profile_container = existing_container;
        }

        // Save the VoucherStore.
        let store_payload =
            crypto_utils::encrypt_data(&file_key, &serde_json::to_vec(store).unwrap())
                .map_err(|e| StorageError::Generic(e.to_string()))?;
        let store_container = VoucherStorageContainer {
            encrypted_store_payload: store_payload,
        };

        // Atomic write via temporary files.
        let profile_tmp_path = self
            .user_storage_path
            .join(format!("{}.tmp", PROFILE_FILE_NAME));
        let store_tmp_path = self
            .user_storage_path
            .join(format!("{}.tmp", VOUCHER_STORE_FILE_NAME));

        fs::write(
            &profile_tmp_path,
            serde_json::to_vec(&profile_container).unwrap(),
        )?;
        fs::write(
            &store_tmp_path,
            serde_json::to_vec(&store_container).unwrap(),
        )?;

        fs::rename(&profile_tmp_path, &profile_path)?;
        fs::rename(&store_tmp_path, &store_path)?;

        Ok(())
    }

    fn reset_password(
        &mut self,
        identity: &UserIdentity,
        new_password: &str,
    ) -> Result<(), StorageError> {
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
            crypto_utils::decrypt_data(&mnemonic_key, &container.mnemonic_wrapped_key_with_nonce)
                .map_err(|_| StorageError::AuthenticationFailed)?;

        let mut new_pw_salt = [0u8; SALT_SIZE];
        OsRng.fill_bytes(&mut new_pw_salt);
        let new_password_key = derive_key_from_password(new_password, &new_pw_salt)?;
        let new_pw_wrapped_key = crypto_utils::encrypt_data(&new_password_key, &file_key)
            .map_err(|e| StorageError::Generic(e.to_string()))?;

        container.password_kdf_salt = new_pw_salt;
        container.password_wrapped_key_with_nonce = new_pw_wrapped_key;

        let profile_tmp_path = self
            .user_storage_path
            .join(format!("{}.tmp", PROFILE_FILE_NAME));
        fs::write(&profile_tmp_path, serde_json::to_vec(&container).unwrap())?;
        fs::rename(&profile_tmp_path, &profile_path)?;

        Ok(())
    }

    fn load_known_fingerprints(
        &self,
        _user_id: &str,
        auth: &AuthMethod,
    ) -> Result<KnownFingerprints, StorageError> {
        let fingerprint_path = self.user_storage_path.join(KNOWN_FINGERPRINTS_FILE_NAME);
        if !fingerprint_path.exists() {
            return Ok(KnownFingerprints::default());
        }

        let file_key = self.get_master_key_from_auth(auth)?;

        let fingerprint_container_bytes = fs::read(fingerprint_path)?;
        let fingerprint_container: KnownFingerprintsContainer =
            serde_json::from_slice(&fingerprint_container_bytes)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        let store_bytes =
            crypto_utils::decrypt_data(&file_key, &fingerprint_container.encrypted_store_payload)
                .map_err(|e| {
                StorageError::InvalidFormat(format!("Failed to decrypt known fingerprints: {}", e))
            })?;

        serde_json::from_slice(&store_bytes).map_err(|e| StorageError::InvalidFormat(e.to_string()))
    }

    fn save_known_fingerprints(
        &mut self,
        _user_id: &str,
        auth: &AuthMethod,
        fingerprints: &KnownFingerprints,
    ) -> Result<(), StorageError> {
        let fingerprint_path = self.user_storage_path.join(KNOWN_FINGERPRINTS_FILE_NAME);

        let file_key = self.get_master_key_from_auth(auth)?;

        let store_payload =
            crypto_utils::encrypt_data(&file_key, &serde_json::to_vec(fingerprints).unwrap())
                .map_err(|e| StorageError::Generic(e.to_string()))?;
        let store_container = KnownFingerprintsContainer {
            encrypted_store_payload: store_payload,
        };

        let store_tmp_path = self
            .user_storage_path
            .join(format!("{}.tmp", KNOWN_FINGERPRINTS_FILE_NAME));
        fs::write(
            &store_tmp_path,
            serde_json::to_vec(&store_container).unwrap(),
        )?;
        fs::rename(&store_tmp_path, &fingerprint_path)?;

        Ok(())
    }

    fn load_own_fingerprints(
        &self,
        _user_id: &str,
        auth: &AuthMethod,
    ) -> Result<OwnFingerprints, StorageError> {
        let fingerprint_path = self.user_storage_path.join(OWN_FINGERPRINTS_FILE_NAME);
        if !fingerprint_path.exists() {
            return Ok(OwnFingerprints::default());
        }

        let file_key = self.get_master_key_from_auth(auth)?;

        let fingerprint_container_bytes = fs::read(fingerprint_path)?;
        let fingerprint_container: OwnFingerprintsContainer =
            serde_json::from_slice(&fingerprint_container_bytes)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        let store_bytes =
            crypto_utils::decrypt_data(&file_key, &fingerprint_container.encrypted_store_payload)
                .map_err(|e| {
                StorageError::InvalidFormat(format!("Failed to decrypt own fingerprints: {}", e))
            })?;

        serde_json::from_slice(&store_bytes).map_err(|e| StorageError::InvalidFormat(e.to_string()))
    }

    fn save_own_fingerprints(
        &mut self,
        _user_id: &str,
        auth: &AuthMethod,
        fingerprints: &OwnFingerprints,
    ) -> Result<(), StorageError> {
        let fingerprint_path = self.user_storage_path.join(OWN_FINGERPRINTS_FILE_NAME);

        let file_key = self.get_master_key_from_auth(auth)?;

        let store_payload =
            crypto_utils::encrypt_data(&file_key, &serde_json::to_vec(fingerprints).unwrap())
                .map_err(|e| StorageError::Generic(e.to_string()))?;
        let store_container = OwnFingerprintsContainer {
            encrypted_store_payload: store_payload,
        };

        let store_tmp_path = self
            .user_storage_path
            .join(format!("{}.tmp", OWN_FINGERPRINTS_FILE_NAME));
        fs::write(
            &store_tmp_path,
            serde_json::to_vec(&store_container).unwrap(),
        )?;
        fs::rename(&store_tmp_path, &fingerprint_path)?;

        Ok(())
    }

    fn load_bundle_metadata(
        &self,
        _user_id: &str,
        auth: &AuthMethod,
    ) -> Result<BundleMetadataStore, StorageError> {
        let profile_path = self.user_storage_path.join(PROFILE_FILE_NAME);
        let meta_path = self.user_storage_path.join(BUNDLE_META_FILE_NAME);

        if !profile_path.exists() {
            return Err(StorageError::NotFound);
        }

        if !meta_path.exists() {
            return Ok(BundleMetadataStore::default());
        }

        let profile_container_bytes = fs::read(&profile_path)?;
        let profile_container: ProfileStorageContainer =
            serde_json::from_slice(&profile_container_bytes)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        let file_key_bytes = get_file_key(auth, &profile_container)?;
        let file_key: [u8; KEY_SIZE] = file_key_bytes
            .try_into()
            .map_err(|_| StorageError::InvalidFormat("Invalid file key length".to_string()))?;

        let meta_container_bytes = fs::read(meta_path)?;
        let meta_container: BundleMetadataContainer = serde_json::from_slice(&meta_container_bytes)
            .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        let store_bytes =
            crypto_utils::decrypt_data(&file_key, &meta_container.encrypted_store_payload)
                .map_err(|e| {
                    StorageError::InvalidFormat(format!("Failed to decrypt bundle metadata: {}", e))
                })?;

        serde_json::from_slice(&store_bytes).map_err(|e| StorageError::InvalidFormat(e.to_string()))
    }

    fn save_bundle_metadata(
        &mut self,
        _user_id: &str,
        auth: &AuthMethod,
        metadata: &BundleMetadataStore,
    ) -> Result<(), StorageError> {
        let profile_path = self.user_storage_path.join(PROFILE_FILE_NAME);
        let meta_path = self.user_storage_path.join(BUNDLE_META_FILE_NAME);

        if !profile_path.exists() {
            return Err(StorageError::NotFound);
        }

        let profile_container_bytes = fs::read(profile_path)?;
        let profile_container: ProfileStorageContainer =
            serde_json::from_slice(&profile_container_bytes)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        let file_key_bytes = get_file_key(auth, &profile_container)?;

        let file_key: [u8; KEY_SIZE] = file_key_bytes
            .try_into()
            .map_err(|_| StorageError::InvalidFormat("Invalid file key length".to_string()))?;

        let store_payload =
            crypto_utils::encrypt_data(&file_key, &serde_json::to_vec(metadata).unwrap())
                .map_err(|e| StorageError::Generic(e.to_string()))?;
        let store_container = BundleMetadataContainer {
            encrypted_store_payload: store_payload,
        };

        let store_tmp_path = self
            .user_storage_path
            .join(format!("{}.tmp", BUNDLE_META_FILE_NAME));
        fs::write(
            &store_tmp_path,
            serde_json::to_vec(&store_container).unwrap(),
        )?;
        fs::rename(&store_tmp_path, &meta_path)?;

        Ok(())
    }

    fn load_proofs(&self, _user_id: &str, auth: &AuthMethod) -> Result<ProofStore, StorageError> {
        let profile_path = self.user_storage_path.join(PROFILE_FILE_NAME);
        let proof_path = self.user_storage_path.join(PROOF_STORE_FILE_NAME);

        if !profile_path.exists() {
            return Err(StorageError::NotFound);
        }

        if !proof_path.exists() {
            return Ok(ProofStore::default());
        }

        let profile_container_bytes = fs::read(&profile_path)?;
        let profile_container: ProfileStorageContainer =
            serde_json::from_slice(&profile_container_bytes)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        let file_key_bytes = get_file_key(auth, &profile_container)?;
        let file_key: [u8; KEY_SIZE] = file_key_bytes
            .try_into()
            .map_err(|_| StorageError::InvalidFormat("Invalid file key length".to_string()))?;

        let proof_container_bytes = fs::read(proof_path)?;
        let proof_container: ProofStorageContainer = serde_json::from_slice(&proof_container_bytes)
            .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        let store_bytes =
            crypto_utils::decrypt_data(&file_key, &proof_container.encrypted_store_payload)
                .map_err(|e| {
                    StorageError::InvalidFormat(format!("Failed to decrypt proof store: {}", e))
                })?;

        serde_json::from_slice(&store_bytes).map_err(|e| StorageError::InvalidFormat(e.to_string()))
    }

    fn save_proofs(
        &mut self,
        _user_id: &str,
        auth: &AuthMethod,
        proof_store: &ProofStore,
    ) -> Result<(), StorageError> {
        let profile_path = self.user_storage_path.join(PROFILE_FILE_NAME);
        let proof_path = self.user_storage_path.join(PROOF_STORE_FILE_NAME);

        if !profile_path.exists() {
            return Err(StorageError::NotFound);
        }

        let profile_container_bytes = fs::read(profile_path)?;
        let profile_container: ProfileStorageContainer =
            serde_json::from_slice(&profile_container_bytes)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        let file_key_bytes = get_file_key(auth, &profile_container)?;

        let file_key: [u8; KEY_SIZE] = file_key_bytes
            .try_into()
            .map_err(|_| StorageError::InvalidFormat("Invalid file key length".to_string()))?;

        if proof_store.proofs.is_empty() {
            if proof_path.exists() {
                fs::remove_file(proof_path)?;
            }
            return Ok(());
        }

        let store_payload =
            crypto_utils::encrypt_data(&file_key, &serde_json::to_vec(proof_store).unwrap())
                .map_err(|e| StorageError::Generic(e.to_string()))?;
        let store_container = ProofStorageContainer {
            encrypted_store_payload: store_payload,
        };

        let store_tmp_path = self
            .user_storage_path
            .join(format!("{}.tmp", PROOF_STORE_FILE_NAME));
        fs::write(
            &store_tmp_path,
            serde_json::to_vec(&store_container).unwrap(),
        )?;
        fs::rename(&store_tmp_path, &proof_path)?;

        Ok(())
    }

    fn load_fingerprint_metadata(
        &self,
        _user_id: &str,
        auth: &AuthMethod,
    ) -> Result<CanonicalMetadataStore, StorageError> {
        let metadata_path = self.user_storage_path.join(FINGERPRINT_METADATA_FILE_NAME);
        if !metadata_path.exists() {
            return Ok(CanonicalMetadataStore::default());
        }

        let file_key = self.get_master_key_from_auth(auth)?;

        let metadata_container_bytes = fs::read(metadata_path)?;
        let metadata_container: FingerprintMetadataContainer =
            serde_json::from_slice(&metadata_container_bytes)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        let store_bytes =
            crypto_utils::decrypt_data(&file_key, &metadata_container.encrypted_store_payload)
                .map_err(|e| {
                    StorageError::InvalidFormat(format!(
                        "Failed to decrypt fingerprint metadata: {}",
                        e
                    ))
                })?;

        serde_json::from_slice(&store_bytes).map_err(|e| StorageError::InvalidFormat(e.to_string()))
    }

    fn save_fingerprint_metadata(
        &mut self,
        _user_id: &str,
        auth: &AuthMethod,
        metadata: &CanonicalMetadataStore,
    ) -> Result<(), StorageError> {
        let metadata_path = self.user_storage_path.join(FINGERPRINT_METADATA_FILE_NAME);

        let file_key = self.get_master_key_from_auth(auth)?;

        // If the store is empty, we delete the file if it exists.
        if metadata.is_empty() {
            if metadata_path.exists() {
                fs::remove_file(metadata_path)?;
            }
            return Ok(());
        }

        let store_payload =
            crypto_utils::encrypt_data(&file_key, &serde_json::to_vec(metadata).unwrap())
                .map_err(|e| StorageError::Generic(e.to_string()))?;
        let store_container = FingerprintMetadataContainer {
            encrypted_store_payload: store_payload,
        };

        let store_tmp_path = self
            .user_storage_path
            .join(format!("{}.tmp", FINGERPRINT_METADATA_FILE_NAME));
        fs::write(
            &store_tmp_path,
            serde_json::to_vec(&store_container).unwrap(),
        )?;
        fs::rename(&store_tmp_path, &metadata_path)?;

        Ok(())
    }

    /// Speichert einen beliebigen, benannten Datenblock verschlüsselt.
    fn save_arbitrary_data(
        &mut self,
        _user_id: &str,
        auth: &AuthMethod,
        name: &str,
        data: &[u8],
    ) -> Result<(), StorageError> {
        // 1. Get the master key used for all operations of this wallet.
        let master_key = self.get_master_key_from_auth(auth)?;

        // 2. Create a secure file path (isolated in the profile folder).
        // We do not use the user_hash in the file name to avoid privacy leaks.
        let path = self
            .user_storage_path
            .join(format!("generic_{}.enc", name));

        // 3. Encrypt the data and save it.
        let ciphertext = crypto_utils::encrypt_data(&master_key, data)
            .map_err(|e| StorageError::Generic(e.to_string()))?;
        fs::write(&path, ciphertext).map_err(StorageError::Io)?;

        Ok(())
    }

    /// Loads any named and encrypted data block.
    fn load_arbitrary_data(
        &self,
        _user_id: &str,
        auth: &AuthMethod,
        name: &str,
    ) -> Result<Vec<u8>, StorageError> {
        // 1. Derive the master key from the authentication method.
        let master_key = self.get_master_key_from_auth(auth)?;

        // 2. Construct the path where the data is expected.
        let path = self
            .user_storage_path
            .join(format!("generic_{}.enc", name));

        if !path.exists() {
            return Err(StorageError::NotFound);
        }

        // 3. Read and decrypt the data.
        let ciphertext = fs::read(&path).map_err(StorageError::Io)?;
        crypto_utils::decrypt_data(&master_key, &ciphertext)
            .map_err(|_| StorageError::AuthenticationFailed)
    }

    fn test_session_key(&self, session_key: &[u8; 32]) -> Result<(), StorageError> {
        // Load the profile container
        let profile_container = self.load_profile_container()?;

        // Try to decrypt the encrypted file key with the given session key
        // This will fail if the session key was not derived with the correct password
        let _decrypted = crypto_utils::decrypt_data(
            session_key,
            &profile_container.password_wrapped_key_with_nonce,
        )
        .map_err(|_| StorageError::AuthenticationFailed)?;

        Ok(())
    }

    // --- Lock Logic Implementation ---

    fn lock(&self) -> Result<bool, StorageError> {
        // Ensure the directory exists.
        fs::create_dir_all(&self.user_storage_path)?;

        let current_pid = std::process::id();

        if self.lock_file_path.exists() {
            let pid_str = fs::read_to_string(&self.lock_file_path).map_err(|e| {
                StorageError::Generic(format!("Konnte Lock-Datei nicht lesen: {}", e))
            })?;

            let pid_val = pid_str.trim().parse::<u32>().map_err(|_| {
                StorageError::Generic(format!("Ungültige PID in Lock-Datei: {}", pid_str))
            })?;

            // --- RE-ENTRANCY CHECK ---
            // If the PID in the file is OURS, we already have the lock. All good.
            if pid_val == current_pid {
                return Ok(false);
            }

            // Check if the process is still running
            let mut s = System::new();
            s.refresh_processes();

            if s.process(Pid::from_u32(pid_val)).is_some() {
                // Process still running -> Error!
                return Err(StorageError::LockFailed(format!(
                    "Wallet wird bereits von einem anderen Prozess (PID: {}) verwendet.",
                    pid_val // FIX: Here the argument was missing
                )));
            } else {
                // Process dead -> Stale Lock
                eprintln!(
                    "Veraltete Sperre (Stale Lock) von PID {} gefunden und entfernt.",
                    pid_val
                ); // FIX: Variable pid -> pid_val
            }
        }

        // Acquire lock: Write own PID into lock file.
        let mut file = fs::File::create(&self.lock_file_path)?;
        file.write_all(current_pid.to_string().as_bytes())?;

        Ok(true)
    }

    fn unlock(&self) -> Result<(), StorageError> {
        if self.lock_file_path.exists() {
            // We should check if WE are the owner, but for RAII
            // we assume that `unlock` is only called if `lock`
            // was successful. A simple deletion is sufficient here.
            fs::remove_file(&self.lock_file_path)?;
        }
        // If the file does not exist, it is also "unlocked".
        Ok(())
    }

    fn get_lock_file_path(&self) -> &std::path::PathBuf {
        &self.lock_file_path
    }

    fn read_generation(&self) -> Result<u64, StorageError> {
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

    fn write_generation(&mut self, expected: u64, new: u64) -> Result<(), StorageError> {
        fs::create_dir_all(&self.user_storage_path)?;
        let path = self.user_storage_path.join(".wallet.generation");
        let current = self.read_generation()?;
        if current != expected {
            return Err(StorageError::StateConflict(format!(
                "Generation counter mismatch: expected {}, found {}",
                expected, current
            )));
        }

        let tmp_path = self.user_storage_path.join(".wallet.generation.tmp");
        fs::write(&tmp_path, new.to_string())?;
        fs::rename(&tmp_path, &path)?;
        Ok(())
    }

    fn save_seal(
        &mut self,
        _user_id: &str,
        auth: &AuthMethod,
        record: &crate::models::seal::LocalSealRecord,
    ) -> Result<(), StorageError> {
        let seal_path = self.user_storage_path.join(SEAL_FILE_NAME);
        let file_key = self.get_master_key_from_auth(auth)?;

        let store_payload =
            crypto_utils::encrypt_data(&file_key, &serde_json::to_vec(record).unwrap())
                .map_err(|e| StorageError::Generic(e.to_string()))?;
        let store_container = SealStorageContainer {
            encrypted_store_payload: store_payload,
        };

        let store_tmp_path = self
            .user_storage_path
            .join(format!("{}.tmp", SEAL_FILE_NAME));
        fs::write(
            &store_tmp_path,
            serde_json::to_vec(&store_container).unwrap(),
        )?;
        fs::rename(&store_tmp_path, &seal_path)?;

        Ok(())
    }

    fn load_seal(
        &self,
        _user_id: &str,
        auth: &AuthMethod,
    ) -> Result<Option<crate::models::seal::LocalSealRecord>, StorageError> {
        let seal_path = self.user_storage_path.join(SEAL_FILE_NAME);
        if !seal_path.exists() {
            return Ok(None);
        }

        let file_key = self.get_master_key_from_auth(auth)?;

        let seal_container_bytes = fs::read(seal_path)?;
        let seal_container: SealStorageContainer =
            serde_json::from_slice(&seal_container_bytes)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        let store_bytes =
            crypto_utils::decrypt_data(&file_key, &seal_container.encrypted_store_payload)
                .map_err(|e| {
                    StorageError::InvalidFormat(format!("Failed to decrypt seal: {}", e))
                })?;

        let record: crate::models::seal::LocalSealRecord = serde_json::from_slice(&store_bytes)
            .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        Ok(Some(record))
    }

    fn get_item_hash(&self, name: &str) -> Result<String, StorageError> {
        let path = self.user_storage_path.join(name);
        if !path.exists() {
            return Err(StorageError::NotFound);
        }
        let bytes = fs::read(path)?;
        Ok(crypto_utils::get_hash(&bytes))
    }

    fn save_integrity(
        &mut self,
        _user_id: &str,
        record: &crate::models::storage_integrity::LocalIntegrityRecord,
    ) -> Result<(), StorageError> {
        let path = self.user_storage_path.join(INTEGRITY_FILE_NAME);
        let tmp_path = self
            .user_storage_path
            .join(format!("{}.tmp", INTEGRITY_FILE_NAME));

        let json = serde_json::to_vec_pretty(record)
            .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        fs::write(&tmp_path, json)?;
        fs::rename(&tmp_path, &path)?;

        Ok(())
    }

    fn load_integrity(
        &self,
        _user_id: &str,
    ) -> Result<Option<crate::models::storage_integrity::LocalIntegrityRecord>, StorageError> {
        let path = self.user_storage_path.join(INTEGRITY_FILE_NAME);
        if !path.exists() {
            return Ok(None);
        }

        let json = fs::read(path)?;
        let record = serde_json::from_slice(&json)
            .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        Ok(Some(record))
    }

    fn get_all_item_hashes(&self) -> Result<std::collections::HashMap<String, String>, StorageError> {
        let mut hashes = std::collections::HashMap::new();
        
        let entries = fs::read_dir(&self.user_storage_path).map_err(StorageError::Io)?;
        // Scan main directory
        for entry in entries {
            let entry = entry.map_err(StorageError::Io)?;
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();

            // Ignore directories
            if entry.file_type().map_err(StorageError::Io)?.is_dir() {
                continue;
            }

            // Ignore the integrity file itself (avoid circular reference)
            if name_str == INTEGRITY_FILE_NAME {
                continue;
            }

            // Ignore hidden files (e.g. .lock)
            if name_str.starts_with('.') {
                continue;
            }

            // Ignore the session anchor (new and old, to avoid privacy leaks in integrity reports)
            if name_str.starts_with("generic___storage_session_anchor") {
                continue;
            }

            // Ignore seal files (these are already logically protected via the seal_hash in the IntegrityRecord)
            if name_str == SEAL_FILE_NAME || (name_str.starts_with("seal_") && name_str.ends_with(".json")) {
                continue;
            }

            if let Ok(hash) = self.get_item_hash(&name_str) {
                hashes.insert(name_str.to_string(), hash);
            }
        }

        // Scan events subdirectory
        let events_dir = self.user_storage_path.join(EVENTS_DIR_NAME);
        if events_dir.exists() && events_dir.is_dir() {
            let event_entries = fs::read_dir(&events_dir).map_err(StorageError::Io)?;
            for entry in event_entries {
                let entry = entry.map_err(StorageError::Io)?;
                if entry.file_type().map_err(StorageError::Io)?.is_file() {
                    let file_name = entry.file_name();
                    let name_str = file_name.to_string_lossy();
                    if name_str.ends_with(".json.enc") {
                        let relative_path = format!("{}/{}", EVENTS_DIR_NAME, name_str);
                        if let Ok(hash) = self.get_item_hash(&relative_path) {
                            hashes.insert(relative_path, hash);
                        }
                    }
                }
            }
        }

        Ok(hashes)
    }

    fn append_events(
        &mut self,
        _user_id: &str,
        auth: &AuthMethod,
        events: &[crate::models::wallet_event::WalletEvent],
    ) -> Result<(), StorageError> {
        if events.is_empty() {
            return Ok(());
        }

        let file_key = self.get_master_key_from_auth(auth)?;

        // 1. Lazy Migration
        let legacy_path = self.user_storage_path.join(LEGACY_EVENTS_FILE_NAME);
        if legacy_path.exists() {
            let container_bytes = fs::read(&legacy_path)?;
            let container: EventsStorageContainer = serde_json::from_slice(&container_bytes)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
            let decrypted = crypto_utils::decrypt_data(&file_key, &container.encrypted_store_payload)
                .map_err(|e| {
                    StorageError::InvalidFormat(format!("Failed to decrypt legacy events: {}", e))
                })?;
            let legacy_events: Vec<crate::models::wallet_event::WalletEvent> = serde_json::from_slice(&decrypted)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

            // Group and write in chunks
            let mut groups: std::collections::HashMap<String, Vec<crate::models::wallet_event::WalletEvent>> = std::collections::HashMap::new();
            for ev in legacy_events {
                let month = ev.timestamp.format("%Y_%m").to_string();
                groups.entry(month).or_default().push(ev);
            }

            let events_dir = self.user_storage_path.join(EVENTS_DIR_NAME);
            fs::create_dir_all(&events_dir)?;

            for (month, m_events) in groups {
                let chunk_path = events_dir.join(format!("{}.json.enc", month));
                // Since we are migrating, we overwrite or append (if new chunks already existed)
                let existing_events: Vec<crate::models::wallet_event::WalletEvent> = if chunk_path.exists() {
                    let c_bytes = fs::read(&chunk_path)?;
                    let c_container: EventsStorageContainer = serde_json::from_slice(&c_bytes)
                        .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
                    let c_decrypted = crypto_utils::decrypt_data(&file_key, &c_container.encrypted_store_payload)
                        .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
                    serde_json::from_slice(&c_decrypted)
                        .map_err(|e| StorageError::InvalidFormat(e.to_string()))?
                } else {
                    Vec::new()
                };
                
                // Deduplication in O(N): Filter m_events to only append those
                // that do not already exist in existing_events. Preserves strict order!
                let existing_ids: std::collections::HashSet<String> = 
                    existing_events.iter().map(|e| e.event_id.clone()).collect();
                
                let mut merged = existing_events;
                let new_unique_events = m_events.into_iter().filter(|e| !existing_ids.contains(&e.event_id));
                merged.extend(new_unique_events);
                
                let e_bytes = serde_json::to_vec(&merged)
                    .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
                let e_payload = crypto_utils::encrypt_data(&file_key, &e_bytes)
                    .map_err(|e| StorageError::Generic(e.to_string()))?;
                let e_container = EventsStorageContainer { encrypted_store_payload: e_payload };
                let e_container_bytes = serde_json::to_vec(&e_container)
                    .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

                let tmp_path = events_dir.join(format!("{}.json.enc.tmp", month));
                fs::write(&tmp_path, e_container_bytes)?;
                fs::rename(&tmp_path, &chunk_path)?;
            }

            // Completion of migration
            fs::remove_file(&legacy_path)?;
        }

        // 2. Group and append new events
        let mut groups: std::collections::HashMap<String, Vec<crate::models::wallet_event::WalletEvent>> = std::collections::HashMap::new();
        for ev in events {
            let month = ev.timestamp.format("%Y_%m").to_string();
            groups.entry(month).or_default().push(ev.clone());
        }

        let events_dir = self.user_storage_path.join(EVENTS_DIR_NAME);
        fs::create_dir_all(&events_dir)?;

        for (month, m_events) in groups {
            let chunk_path = events_dir.join(format!("{}.json.enc", month));
            let mut all_m_events: Vec<crate::models::wallet_event::WalletEvent> = if chunk_path.exists() {
                let c_bytes = fs::read(&chunk_path)?;
                let c_container: EventsStorageContainer = serde_json::from_slice(&c_bytes)
                    .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
                let c_decrypted = crypto_utils::decrypt_data(&file_key, &c_container.encrypted_store_payload)
                    .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
                serde_json::from_slice(&c_decrypted)
                    .map_err(|e| StorageError::InvalidFormat(e.to_string()))?
            } else {
                Vec::new()
            };

            // Deduplication during regular append (protection against partial crashes)
            let existing_ids: std::collections::HashSet<String> = 
                all_m_events.iter().map(|e| e.event_id.clone()).collect();
            
            let new_unique_events = m_events.into_iter().filter(|e| !existing_ids.contains(&e.event_id));
            all_m_events.extend(new_unique_events);

            let e_bytes = serde_json::to_vec(&all_m_events)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
            let e_payload = crypto_utils::encrypt_data(&file_key, &e_bytes)
                .map_err(|e| StorageError::Generic(e.to_string()))?;
            let e_container = EventsStorageContainer { encrypted_store_payload: e_payload };
            let e_container_bytes = serde_json::to_vec(&e_container)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

            let tmp_path = events_dir.join(format!("{}.json.enc.tmp", month));
            fs::write(&tmp_path, e_container_bytes)?;
            fs::rename(&tmp_path, &chunk_path)?;
        }

        Ok(())
    }

    fn load_events(
        &self,
        _user_id: &str,
        auth: &AuthMethod,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<crate::models::wallet_event::WalletEvent>, StorageError> {
        let file_key = self.get_master_key_from_auth(auth)?;
        let mut result = Vec::new();
        let mut current_offset = offset;
        let mut remaining_limit = limit;

        // 1. List all chunks
        let events_dir = self.user_storage_path.join(EVENTS_DIR_NAME);
        let mut chunks = Vec::new();
        if events_dir.exists() && events_dir.is_dir() {
            let entries = fs::read_dir(&events_dir).map_err(StorageError::Io)?;
            for entry in entries {
                let entry = entry.map_err(StorageError::Io)?;
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.ends_with(".json.enc") && !name.ends_with(".tmp") {
                    chunks.push(name);
                }
            }
        }

        // Sort descending (newest first)
        chunks.sort_by(|a, b| b.cmp(a));

        // 2. Load chunks sequentially
        for chunk_name in chunks {
            if remaining_limit == 0 { break; }

            let chunk_path = events_dir.join(chunk_name);
            let c_bytes = fs::read(&chunk_path)?;
            let c_container: EventsStorageContainer = serde_json::from_slice(&c_bytes)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
            let c_decrypted = crypto_utils::decrypt_data(&file_key, &c_container.encrypted_store_payload)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
            let mut m_events: Vec<crate::models::wallet_event::WalletEvent> = serde_json::from_slice(&c_decrypted)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
            
            // Inside a chunk, events are sorted in ascending order.
            // Since we want the NEWEST first, we must reverse them or read from the back.
            m_events.reverse();

            let len = m_events.len();
            if current_offset >= len {
                current_offset -= len;
                continue;
            }

            let to_take = std::cmp::min(remaining_limit, len - current_offset);
            let page: Vec<_> = m_events.into_iter().skip(current_offset).take(to_take).collect();
            
            result.extend(page);
            remaining_limit -= to_take;
            current_offset = 0;
        }

        // 3. Legacy support (if migration has not run yet)
        if remaining_limit > 0 {
            let legacy_path = self.user_storage_path.join(LEGACY_EVENTS_FILE_NAME);
            if legacy_path.exists() {
                let l_bytes = fs::read(&legacy_path)?;
                let l_container: EventsStorageContainer = serde_json::from_slice(&l_bytes)
                    .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
                let l_decrypted = crypto_utils::decrypt_data(&file_key, &l_container.encrypted_store_payload)
                    .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
                let mut l_events: Vec<crate::models::wallet_event::WalletEvent> = serde_json::from_slice(&l_decrypted)
                    .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
                
                l_events.reverse();
                
                let len = l_events.len();
                if current_offset < len {
                    let to_take = std::cmp::min(remaining_limit, len - current_offset);
                    let page: Vec<_> = l_events.into_iter().skip(current_offset).take(to_take).collect();
                    result.extend(page);
                }
            }
        }

        Ok(result)
    }
}

// --- Private Helper Functions ---

/// Decrypts the master file key (`file_key`) based on the authentication method.
fn get_file_key(
    auth: &AuthMethod,
    container: &ProfileStorageContainer,
) -> Result<Vec<u8>, StorageError> {
    match auth {
        AuthMethod::Password(password) => {
            let password_key = derive_key_from_password(password, &container.password_kdf_salt)?;
            crypto_utils::decrypt_data(&password_key, &container.password_wrapped_key_with_nonce)
                .map_err(|_| StorageError::AuthenticationFailed)
        }
        AuthMethod::SessionKey(session_key) => {
            crypto_utils::decrypt_data(session_key, &container.password_wrapped_key_with_nonce)
                .map_err(|_| StorageError::AuthenticationFailed)
        }
        AuthMethod::Mnemonic(mnemonic, passphrase, language) => {
            let (_, signing_key) = crypto_utils::derive_ed25519_keypair(mnemonic, *passphrase, *language)
                .map_err(|e| {
                    StorageError::Generic(format!("Key derivation from mnemonic failed: {}", e))
                })?;
            let mnemonic_key =
                derive_key_from_signing_key(&signing_key, &container.mnemonic_kdf_salt)?;
            crypto_utils::decrypt_data(&mnemonic_key, &container.mnemonic_wrapped_key_with_nonce)
                .map_err(|_| StorageError::AuthenticationFailed)
        }
        AuthMethod::RecoveryIdentity(identity) => {
            let mnemonic_key =
                derive_key_from_signing_key(&identity.signing_key, &container.mnemonic_kdf_salt)?;
            crypto_utils::decrypt_data(&mnemonic_key, &container.mnemonic_wrapped_key_with_nonce)
                .map_err(|_| StorageError::AuthenticationFailed)
        }
    }
}

/// Helper to get Argon2 instance with appropriate parameters for the environment.
#[cfg(not(any(test, feature = "test-utils")))]
fn get_argon2() -> Argon2<'static> {
    Argon2::default()
}

/// Derives a cryptographic key from a password and salt.
fn derive_key_from_password(
    password: &str,
    salt: &[u8; SALT_SIZE],
) -> Result<[u8; KEY_SIZE], StorageError> {
    #[cfg(any(test, feature = "test-utils"))]
    {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        let result = hasher.finalize();
        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(&result[..KEY_SIZE]);
        Ok(key)
    }
    #[cfg(not(any(test, feature = "test-utils")))]
    {
        let mut key = [0u8; KEY_SIZE];
        get_argon2()
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| StorageError::Generic(format!("Password key derivation failed: {}", e)))?;
        Ok(key)
    }
}

/// Derives a cryptographic key from the private key of the identity.
fn derive_key_from_signing_key(
    signing_key: &SigningKey,
    salt: &[u8; SALT_SIZE],
) -> Result<[u8; KEY_SIZE], StorageError> {
    #[cfg(any(test, feature = "test-utils"))]
    {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(signing_key.to_bytes());
        hasher.update(salt);
        let result = hasher.finalize();
        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(&result[..KEY_SIZE]);
        Ok(key)
    }
    #[cfg(not(any(test, feature = "test-utils")))]
    {
        let mut key = [0u8; KEY_SIZE];
        get_argon2()
            .hash_password_into(signing_key.to_bytes().as_ref(), salt, &mut key)
            .map_err(|e| StorageError::Generic(format!("Identity key derivation failed: {}", e)))?;
        Ok(key)
    }
}
