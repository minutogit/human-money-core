//! # src/storage/file_storage.rs
//!
//! Eine Implementierung des `Storage`-Traits, die Daten in mehreren verschlüsselten
//! Dateien im Dateisystem speichert.

use super::{AuthMethod, Storage, StorageError};
use crate::models::conflict::CanonicalMetadataStore;
use crate::models::conflict::{KnownFingerprints, OwnFingerprints, ProofStore};
use crate::models::storage_integrity::INTEGRITY_FILE_NAME;
use crate::models::profile::{BundleMetadataStore, UserIdentity, UserProfile, VoucherStore};
use crate::services::crypto_utils;
#[cfg(not(any(test, feature = "test-utils")))]
use argon2::Argon2;
use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{fs, io::Write, path::PathBuf};
use sysinfo::{Pid, System};

// --- Interne Konstanten und Strukturen ---

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

/// Privates Modul zur Kapselung der Serde-Logik für Base64-Kodierung von Vektoren.
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

/// Privates Modul zur Kapselung der Serde-Logik für Base64-Kodierung von festen Arrays.
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

/// Container für das verschlüsselte Nutzerprofil, inklusive Key-Wrapping-Informationen.
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

/// Bündelt das Profil und den privaten Schlüssel für die Speicherung.
#[derive(Serialize, Deserialize, Clone)]
struct ProfilePayload {
    profile: UserProfile,
    signing_key_bytes: Vec<u8>,
}

/// Container für den verschlüsselten Gutschein-Store.
#[derive(Serialize, Deserialize)]
struct VoucherStorageContainer {
    #[serde(with = "base64_serde")]
    encrypted_store_payload: Vec<u8>,
}

/// Container für die verschlüsselten Bundle-Metadaten.
#[derive(Serialize, Deserialize)]
struct BundleMetadataContainer {
    #[serde(with = "base64_serde")]
    encrypted_store_payload: Vec<u8>,
}

/// Container für den `KnownFingerprints`-Store.
#[derive(Serialize, Deserialize)]
struct KnownFingerprintsContainer {
    #[serde(with = "base64_serde")]
    encrypted_store_payload: Vec<u8>,
}

/// Container für den `OwnFingerprints`-Store.
#[derive(Serialize, Deserialize)]
struct OwnFingerprintsContainer {
    #[serde(with = "base64_serde")]
    encrypted_store_payload: Vec<u8>,
}

/// Container für den verschlüsselten Proof-Store.
#[derive(Serialize, Deserialize)]
struct ProofStorageContainer {
    #[serde(with = "base64_serde")]
    encrypted_store_payload: Vec<u8>,
}

/// Container für den `CanonicalMetadataStore`.
#[derive(Serialize, Deserialize)]
struct FingerprintMetadataContainer {
    #[serde(with = "base64_serde")]
    encrypted_store_payload: Vec<u8>,
}

/// Container für den verschlüsselten `LocalSealRecord`.
#[derive(Serialize, Deserialize)]
struct SealStorageContainer {
    #[serde(with = "base64_serde")]
    encrypted_store_payload: Vec<u8>,
}

/// Container für das verschlüsselte Wallet-Event-Log.
#[derive(Serialize, Deserialize)]
struct EventsStorageContainer {
    #[serde(with = "base64_serde")]
    encrypted_store_payload: Vec<u8>,
}

// --- FileStorage Implementierung ---

/// Eine Implementierung des `Storage`-Traits, die Daten in verschlüsselten Dateien speichert.
pub struct FileStorage {
    /// Der Pfad zum spezifischen, anonymen Unterordner des Benutzers.
    pub user_storage_path: PathBuf,
    /// Der Pfad zur Sperrdatei für dieses Wallet.
    lock_file_path: PathBuf,
}

impl FileStorage {
    /// Erstellt eine neue `FileStorage`-Instanz für ein spezifisches Benutzerverzeichnis.
    ///
    /// Diese Methode ist nun entkoppelt von der Logik zur Erzeugung des Pfadnamens
    /// und nimmt den vollständigen Pfad zum Benutzerverzeichnis direkt entgegen.
    ///
    /// # Arguments
    /// * `user_storage_path` - Der vollständige Pfad zum Verzeichnis, in dem die
    ///   verschlüsselten Wallet-Dateien dieses Profils gespeichert sind oder werden sollen.
    pub fn new(user_storage_path: impl Into<PathBuf>) -> Self {
        let path_buf = user_storage_path.into();
        FileStorage {
            lock_file_path: path_buf.join(LOCK_FILE_NAME),
            user_storage_path: path_buf,
        }
    }

    /// Lädt den `ProfileStorageContainer`, um an die Schlüssel-Metadaten zu gelangen.
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
    /// Diese Logik wird von allen `load_*`-Methoden benötigt.
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
        // Stelle sicher, dass der Ordner existiert, bevor wir lesen.
        // Das Erstellen ist Aufgabe von `save_wallet` oder `create_profile`.
        if !self.user_storage_path.exists() {
            return Err(StorageError::NotFound);
        }

        let profile_path = self.user_storage_path.join(PROFILE_FILE_NAME);
        let store_path = self.user_storage_path.join(VOUCHER_STORE_FILE_NAME);

        let profile_container_bytes = fs::read(profile_path)?;
        let profile_container: ProfileStorageContainer =
            serde_json::from_slice(&profile_container_bytes)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        // Entschlüssle den Master-Dateischlüssel basierend auf der Authentifizierungsmethode.
        let file_key_bytes = get_file_key(auth, &profile_container)?;
        let file_key: [u8; KEY_SIZE] = file_key_bytes
            .try_into()
            .map_err(|_| StorageError::InvalidFormat("Invalid file key length".to_string()))?;

        // Entschlüssele den Payload, der Profil und privaten Schlüssel enthält.
        let payload_bytes =
            crypto_utils::decrypt_data(&file_key, &profile_container.encrypted_profile_payload)
                .map_err(|e| {
                    StorageError::InvalidFormat(format!("Failed to decrypt profile payload: {}", e))
                })?;
        let payload: ProfilePayload = serde_json::from_slice(&payload_bytes)
            .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        // Lade den VoucherStore.
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

        // Rekonstruiere die UserIdentity.
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
        fs::create_dir_all(&self.user_storage_path)?; // Erstellt den Ordner, falls nicht vorhanden
        let profile_path = self.user_storage_path.join(PROFILE_FILE_NAME);
        let store_path = self.user_storage_path.join(VOUCHER_STORE_FILE_NAME);

        let file_key: [u8; KEY_SIZE];
        let profile_container: ProfileStorageContainer;

        let payload = ProfilePayload {
            profile: profile.clone(),
            signing_key_bytes: identity.signing_key.to_bytes().to_vec(),
        };

        if !profile_path.exists() {
            // Erstmaliges Speichern: Generiere alle Schlüssel und Salze.
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
            // Aktualisieren eines bestehenden Wallets: Lade Container, entschlüssele Schlüssel und verschlüssele neuen Payload.
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

        // Speichere den VoucherStore.
        let store_payload =
            crypto_utils::encrypt_data(&file_key, &serde_json::to_vec(store).unwrap())
                .map_err(|e| StorageError::Generic(e.to_string()))?;
        let store_container = VoucherStorageContainer {
            encrypted_store_payload: store_payload,
        };

        // Atomares Schreiben über temporäre Dateien.
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

        // Wenn der Store leer ist, löschen wir die Datei, falls sie existiert.
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
        // 1. Hole den Master-Schlüssel, der für alle Operationen dieses Wallets verwendet wird.
        let master_key = self.get_master_key_from_auth(auth)?;

        // 2. Erstelle einen sicheren Dateipfad (isoliert im Profil-Ordner).
        // Wir verzichten auf den user_hash im Dateinamen, um Privacy-Leaks zu vermeiden.
        let path = self
            .user_storage_path
            .join(format!("generic_{}.enc", name));

        // 3. Verschlüssele die Daten und speichere sie.
        let ciphertext = crypto_utils::encrypt_data(&master_key, data)
            .map_err(|e| StorageError::Generic(e.to_string()))?;
        fs::write(&path, ciphertext).map_err(StorageError::Io)?;

        Ok(())
    }

    /// Lädt einen beliebigen, benannten und verschlüsselten Datenblock.
    fn load_arbitrary_data(
        &self,
        _user_id: &str,
        auth: &AuthMethod,
        name: &str,
    ) -> Result<Vec<u8>, StorageError> {
        // 1. Leite den Master-Schlüssel aus der Authentifizierungsmethode ab.
        let master_key = self.get_master_key_from_auth(auth)?;

        // 2. Konstruiere den Pfad, unter dem die Daten erwartet werden.
        let path = self
            .user_storage_path
            .join(format!("generic_{}.enc", name));

        if !path.exists() {
            return Err(StorageError::NotFound);
        }

        // 3. Lese und entschlüssele die Daten.
        let ciphertext = fs::read(&path).map_err(StorageError::Io)?;
        crypto_utils::decrypt_data(&master_key, &ciphertext)
            .map_err(|_| StorageError::AuthenticationFailed)
    }

    fn test_session_key(&self, session_key: &[u8; 32]) -> Result<(), StorageError> {
        // Lade den Profil-Container
        let profile_container = self.load_profile_container()?;

        // Versuche, den verschlüsselten Dateischlüssel mit dem gegebenen Session-Key zu entschlüsseln
        // Dies wird fehlschlagen, wenn der Session-Key nicht mit dem richtigen Passwort abgeleitet wurde
        let _decrypted = crate::services::crypto_utils::decrypt_data(
            session_key,
            &profile_container.password_wrapped_key_with_nonce,
        )
        .map_err(|_| StorageError::AuthenticationFailed)?;

        Ok(())
    }

    // --- Implementierung der Sperrlogik ---

    fn lock(&self) -> Result<(), StorageError> {
        // Stelle sicher, dass das Verzeichnis existiert.
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
            // Wenn die PID in der Datei UNSERE ist, haben wir den Lock schon. Alles gut.
            if pid_val == current_pid {
                return Ok(());
            }

            // Prüfe, ob der Prozess noch läuft
            let mut s = System::new();
            s.refresh_processes();

            if s.process(Pid::from_u32(pid_val)).is_some() {
                // Prozess läuft noch -> Fehler!
                return Err(StorageError::LockFailed(format!(
                    "Wallet wird bereits von einem anderen Prozess (PID: {}) verwendet.",
                    pid_val // FIX: Hier fehlte das Argument
                )));
            } else {
                // Prozess tot -> Stale Lock
                eprintln!(
                    "Veraltete Sperre (Stale Lock) von PID {} gefunden und entfernt.",
                    pid_val
                ); // FIX: Variable pid -> pid_val
            }
        }

        // Sperre erlangen: Eigene PID in die Lock-Datei schreiben.
        let mut file = fs::File::create(&self.lock_file_path)?;
        file.write_all(current_pid.to_string().as_bytes())?;

        Ok(())
    }

    fn unlock(&self) -> Result<(), StorageError> {
        if self.lock_file_path.exists() {
            // Wir sollten prüfen, ob WIR der Besitzer sind, aber für RAII
            // gehen wir davon aus, dass `unlock` nur aufgerufen wird, wenn `lock`
            // erfolgreich war. Ein einfaches Löschen ist hier ausreichend.
            fs::remove_file(&self.lock_file_path)?;
        }
        // Wenn die Datei nicht existiert, ist das auch "unlocked".
        Ok(())
    }

    fn get_lock_file_path(&self) -> &std::path::PathBuf {
        &self.lock_file_path
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
        // Scanne Hauptverzeichnis
        for entry in entries {
            let entry = entry.map_err(StorageError::Io)?;
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();

            // Ignoriere Verzeichnisse
            if entry.file_type().map_err(StorageError::Io)?.is_dir() {
                continue;
            }

            // Ignoriere die Integrity-Datei selbst (Zirkelbezug vermeiden)
            if name_str == INTEGRITY_FILE_NAME {
                continue;
            }

            // Ignoriere versteckte Dateien (z.B. .lock)
            if name_str.starts_with('.') {
                continue;
            }

            // Ignoriere den Session-Anker (neu und alt, um Privacy-Leaks in Integrity-Reports zu vermeiden)
            if name_str.starts_with("generic___storage_session_anchor") {
                continue;
            }

            // Ignoriere Seal-Dateien (diese werden bereits logisch über den seal_hash im IntegrityRecord geschützt)
            if name_str == SEAL_FILE_NAME || (name_str.starts_with("seal_") && name_str.ends_with(".json")) {
                continue;
            }

            if let Ok(hash) = self.get_item_hash(&name_str) {
                hashes.insert(name_str.to_string(), hash);
            }
        }

        // Scanne Events-Unterverzeichnis
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

            // Gruppiere und schreibe in Chunks
            let mut groups: std::collections::HashMap<String, Vec<crate::models::wallet_event::WalletEvent>> = std::collections::HashMap::new();
            for ev in legacy_events {
                let month = ev.timestamp.format("%Y_%m").to_string();
                groups.entry(month).or_default().push(ev);
            }

            let events_dir = self.user_storage_path.join(EVENTS_DIR_NAME);
            fs::create_dir_all(&events_dir)?;

            for (month, m_events) in groups {
                let chunk_path = events_dir.join(format!("{}.json.enc", month));
                // Da wir migrieren, überschreiben wir oder hängen an (falls schon neue Chunks existierten)
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
                
                // Deduplizierung in O(N): Filtere m_events, um nur solche anzuhängen, 
                // die noch nicht in existing_events existieren. Bewahrt die strikte Reihenfolge!
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

            // Abschluss der Migration
            fs::remove_file(&legacy_path)?;
        }

        // 2. Neue Events gruppieren und anhängen
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

            // Deduplizierung beim regulären Append (Schutz vor partiellen Abstürzen)
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

        // 1. Liste alle Chunks auf
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

        // Sortiere absteigend (neueste zuerst)
        chunks.sort_by(|a, b| b.cmp(a));

        // 2. Chunks sequenziell laden
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
            
            // Innerhalb eines Chunks sind Events aufsteigend sortiert.
            // Da wir die NEUESTEN zuerst wollen, müssen wir sie umkehren oder von hinten lesen.
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

        // 3. Legacy-Support (falls Migration noch nicht lief)
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

// --- Private Hilfsfunktionen ---

/// Entschlüsselt den Master-Dateischlüssel (`file_key`) basierend auf der Authentifizierungsmethode.
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

/// Leitet einen kryptographischen Schlüssel aus einem Passwort und Salt ab.
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

/// Leitet einen kryptographischen Schlüssel aus dem privaten Schlüssel der Identität ab.
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
