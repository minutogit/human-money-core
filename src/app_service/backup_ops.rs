//! Authenticated differential backup export, inspection and staged restore.
use super::{AppService, AppState, ProfileInfo};
use crate::storage::key_manager::*;
use crate::{
    Error,
    models::{
        backup::*,
        profile::UserIdentity,
        seal::{SealValidationResult, WalletSeal},
        storage_integrity::{IntegrityReport, StorageIntegrityRecord},
    },
    services::crypto,
    storage::{AuthMethod, FileStorage, StorageError, WalletLockGuard},
    wallet::Wallet,
};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use std::{
    collections::{HashMap, HashSet},
    fs,
};

fn invalid(message: &str) -> Error {
    StorageError::IntegrityViolation(message.into()).into()
}
fn verify_raw_state(
    storage: &FileStorage,
    auth: &AuthMethod<'_>,
    seal: &WalletSeal,
) -> Result<(), Error> {
    let (_, store, _) = storage.load_wallet(auth)?;
    let root = crate::models::seal::calculate_voucher_merkle_root(&store.vouchers);
    let fp = crate::storage::seal_service::SealService::calculate_state_hash(
        &storage.load_own_fingerprints(auth)?,
    )?;
    let expected = crate::storage::seal_service::SealService::calculate_comprehensive_state_hash(
        seal.payload.epoch as u64,
        seal.payload.tx_nonce,
        &root,
        &fp,
    );
    if expected != seal.payload.state_hash {
        return Err(invalid("Backup state does not match seal"));
    }
    Ok(())
}
fn blob_name(key: &[u8; 32], path: &str) -> String {
    let mut mac = Hmac::<sha3::Sha3_256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(path.as_bytes());
    format!(
        "blob_{}.enc",
        hex::encode(&mac.finalize().into_bytes()[..16])
    )
}
fn decode(s: &str) -> Result<Vec<u8>, Error> {
    B64.decode(s)
        .map_err(|_| invalid("Invalid backup encoding"))
}
fn decrypt(key: &[u8; 32], bytes: &[u8]) -> Result<Vec<u8>, Error> {
    crypto::decrypt_data(key, bytes).map_err(|_| StorageError::AuthenticationFailed.into())
}
fn encrypt(key: &[u8; 32], bytes: &[u8]) -> Result<Vec<u8>, Error> {
    crypto::encrypt_data(key, bytes).map_err(|e| Error::Crypto(e.to_string()))
}
fn validate(payload: &BackupManifestPayload, key: &[u8; 32]) -> Result<(), Error> {
    if payload.blob_map.len() > 4096 {
        return Err(invalid("Backup inventory exceeds file limit"));
    }
    if payload.format_version != 1 || payload.integrity.payload.version != 1 {
        return Err(invalid("Unsupported backup version"));
    }
    let folder = &payload.folder_name;
    if folder.is_empty()
        || !folder
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(invalid("Invalid backup folder"));
    }
    let seal = &payload.seal;
    if !matches!(
        seal.verify_integrity(
            &seal.payload.user_id,
            &seal.payload.user_id,
            &seal.payload.instance_id
        )?,
        SealValidationResult::Valid | SealValidationResult::LegacyValid
    ) {
        return Err(invalid("Invalid backup seal"));
    }
    if payload.integrity.verify(
        seal,
        payload.integrity.payload.item_hashes.clone(),
        &seal.payload.user_id,
    )? != IntegrityReport::Valid
    {
        return Err(invalid("Invalid backup integrity signature"));
    }
    if payload.source_integrity.verify(
        seal,
        payload.source_integrity.payload.item_hashes.clone(),
        &seal.payload.user_id,
    )? != IntegrityReport::Valid
        || payload
            .source_integrity
            .payload
            .item_hashes
            .keys()
            .collect::<HashSet<_>>()
            != payload
                .integrity
                .payload
                .item_hashes
                .keys()
                .collect::<HashSet<_>>()
    {
        return Err(invalid("Invalid backup source integrity"));
    }
    let mut paths = HashSet::new();
    for (blob, path) in &payload.blob_map {
        crate::storage::integrity::validate_item_name(path)
            .map_err(|_| invalid("Invalid backup path"))?;
        // Restrict restore to canonical encrypted wallet files; never restore locks or journals.
        if path.is_empty()
            || path
                .split('/')
                .any(|p| p.is_empty() || p == "." || p.starts_with('.'))
            || !path.ends_with(".enc")
            || (path.contains('/')
                && !(path.starts_with("events/")
                    && path.matches('/').count() == 1
                    && path.ends_with(".json.enc")))
            || blob != &blob_name(key, path)
            || !paths.insert(path.clone())
        {
            return Err(invalid("Invalid backup inventory"));
        }
    }
    if paths
        != payload
            .integrity
            .payload
            .item_hashes
            .keys()
            .cloned()
            .collect()
        || !paths.contains("profile.enc")
        || !paths.contains("vouchers.enc")
        || !paths.contains("seal.enc")
    {
        return Err(invalid("Incomplete backup inventory"));
    }
    Ok(())
}
fn open_with_key(bytes: &[u8], key: &[u8; 32]) -> Result<BackupManifestPayload, Error> {
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(invalid("Backup manifest exceeds size limit"));
    }
    let header: EncryptedBackupManifest = serde_json::from_slice(bytes)?;
    if header.format != "hmc-backup-manifest-v1" {
        return Err(invalid("Unsupported backup format"));
    }
    let payload = serde_json::from_slice(&decrypt(key, &decode(&header.ciphertext)?)?)?;
    validate(&payload, key)?;
    Ok(payload)
}
fn credentials_key(
    bytes: &[u8],
    credentials: &BackupRestoreCredentials<'_>,
) -> Result<[u8; 32], Error> {
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(invalid("Backup manifest exceeds size limit"));
    }
    let header: EncryptedBackupManifest = serde_json::from_slice(bytes)?;
    if header.format != "hmc-backup-manifest-v1" {
        return Err(invalid("Unsupported backup format"));
    }
    match credentials {
        BackupRestoreCredentials::BackupPassword(password)
            if header.protection_mode == "backup_password" =>
        {
            let salt: [u8; 16] = decode(
                header
                    .kdf_salt
                    .as_deref()
                    .ok_or_else(|| invalid("Missing salt"))?,
            )?
            .try_into()
            .map_err(|_| invalid("Invalid salt"))?;
            Ok(derive_key_from_password(password, &salt)?)
        }
        BackupRestoreCredentials::Mnemonic {
            phrase,
            passphrase,
            prefix,
            language,
        } => {
            let (_, identity) =
                Wallet::new_from_mnemonic(phrase, *passphrase, *prefix, *language, String::new())?;
            let recovery = derive_backup_envelope_key_from_identity(&identity);
            match header.protection_mode.as_str() {
                "mnemonic"
                    if header.kdf_salt.is_none()
                        && header.mnemonic_wrapped_envelope_key.is_none() =>
                {
                    Ok(recovery)
                }
                "backup_password" => decrypt(
                    &recovery,
                    &decode(
                        header
                            .mnemonic_wrapped_envelope_key
                            .as_deref()
                            .ok_or_else(|| invalid("Missing recovery slot"))?,
                    )?,
                )?
                .try_into()
                .map_err(|_| invalid("Invalid envelope key")),
                _ => Err(invalid("Invalid protection mode")),
            }
        }
        _ => Err(StorageError::AuthenticationFailed.into()),
    }
}
impl AppService {
    /// Exports opaque blobs without changing the local profile. Previous manifests must belong to this account and protection mode.
    pub fn create_differential_backup(
        &mut self,
        previous_manifest_bytes: Option<&[u8]>,
        protection: BackupProtection<'_>,
        password: Option<&str>,
    ) -> Result<BackupDiff, Error> {
        let AppState::Unlocked {
            storage,
            identity,
            session_cache,
            ..
        } = &self.state
        else {
            return Err(Error::WalletLocked);
        };
        let _guard = WalletLockGuard::new(storage)?;
        let auth = Self::resolve_auth_method(password, session_cache)?;
        let record = storage
            .load_integrity()?
            .ok_or_else(|| invalid("Missing local integrity record"))?;
        let seal = storage
            .load_seal(&auth)?
            .ok_or_else(|| invalid("Missing local seal"))?
            .seal;
        verify_raw_state(storage, &auth, &seal)?;
        let source_hashes = storage.get_all_item_hashes()?;
        if record.verify(&seal, source_hashes.clone(), &identity.user_id)? != IntegrityReport::Valid
        {
            return Err(invalid("Local integrity check failed"));
        }
        let recovery = zeroize::Zeroizing::new(derive_backup_envelope_key_from_identity(identity));
        let mode = match protection {
            BackupProtection::MnemonicOnly => "mnemonic",
            _ => "backup_password",
        };
        let mut salt = [0; 16];
        OsRng.fill_bytes(&mut salt);
        if let Some(bytes) = previous_manifest_bytes {
            let old: EncryptedBackupManifest = serde_json::from_slice(bytes)?;
            if old.protection_mode != mode {
                return Err(invalid("Protection mode changed; start a full backup"));
            }
            if mode == "backup_password" {
                salt = decode(
                    old.kdf_salt
                        .as_deref()
                        .ok_or_else(|| invalid("Missing salt"))?,
                )?
                .try_into()
                .map_err(|_| invalid("Invalid salt"))?;
            }
        }
        let key = zeroize::Zeroizing::new(match protection {
            BackupProtection::MnemonicOnly => *recovery,
            BackupProtection::CustomBackupPassword(p) => {
                if p.is_empty() {
                    return Err(StorageError::EmptyPassword.into());
                }
                derive_key_from_password(p, &salt)?
            }
        });
        let previous = previous_manifest_bytes
            .map(|b| open_with_key(b, &key))
            .transpose()?;
        if previous
            .as_ref()
            .is_some_and(|p| p.seal.payload.user_id != identity.user_id)
        {
            return Err(invalid("Backup account mismatch"));
        }
        let folder_name = storage
            .user_storage_path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| invalid("Invalid local folder"))?
            .to_string();
        let profile_name = self
            .list_profiles()?
            .into_iter()
            .find(|p| p.folder_name == folder_name)
            .ok_or_else(|| invalid("Profile not indexed"))?
            .profile_name;
        let mut hashes = HashMap::new();
        let mut blob_map = HashMap::new();
        let mut put_blobs = HashMap::new();
        let mut sources = source_hashes.clone();
        sources.insert("seal.enc".into(), storage.get_item_hash("seal.enc")?);
        for (path, source_hash) in &sources {
            let name = blob_name(&key, path);
            blob_map.insert(name.clone(), path.clone());
            let reuse = previous.as_ref().filter(|p| {
                p.source_integrity.payload.item_hashes.get(path) == Some(source_hash)
                    && p.blob_map.get(&name) == Some(path)
            });
            if let Some(old) = reuse {
                hashes.insert(
                    path.clone(),
                    old.integrity.payload.item_hashes[path].clone(),
                );
                continue;
            }
            let mut bytes = fs::read(storage.user_storage_path.join(path))?;
            if crypto::get_hash(&bytes) != *source_hash {
                return Err(invalid("Storage changed during backup"));
            }
            if path == "profile.enc" {
                bytes = repackage_profile_for_backup(&bytes, &auth, &protection)?;
            }
            hashes.insert(path.clone(), crypto::get_hash(&bytes));
            put_blobs.insert(name, bytes);
        }
        let integrity = StorageIntegrityRecord::create_record(identity, &seal, hashes)?;
        let payload = BackupManifestPayload {
            format_version: 1,
            profile_name,
            folder_name,
            seal: seal.clone(),
            integrity,
            blob_map,
            source_integrity: StorageIntegrityRecord::create_record(identity, &seal, sources)?,
        };
        validate(&payload, &key)?;
        let delete_blobs: Vec<_> = previous
            .iter()
            .flat_map(|p| p.blob_map.keys())
            .filter(|n| !payload.blob_map.contains_key(*n))
            .cloned()
            .collect();
        let header = EncryptedBackupManifest {
            format: "hmc-backup-manifest-v1".into(),
            protection_mode: mode.into(),
            kdf_salt: (mode == "backup_password").then(|| B64.encode(salt)),
            mnemonic_wrapped_envelope_key: if mode == "backup_password" {
                Some(B64.encode(encrypt(&recovery, &*key)?))
            } else {
                None
            },
            ciphertext: B64.encode(encrypt(&key, &serde_json::to_vec(&payload)?)?),
        };
        let encrypted_manifest_bytes = serde_json::to_vec(&header)?;
        let summary = BackupSummary {
            total_blobs: payload.blob_map.len(),
            changed_blobs: put_blobs.len(),
            deleted_blobs: delete_blobs.len(),
            upload_bytes: encrypted_manifest_bytes.len()
                + put_blobs.values().map(Vec::len).sum::<usize>(),
        };
        Ok(BackupDiff {
            encrypted_manifest_bytes,
            put_blobs,
            delete_blobs,
            summary,
        })
    }
    /// Decrypts and authenticates metadata before requesting blobs from the backup provider.
    pub fn inspect_backup(
        &self,
        bytes: &[u8],
        credentials: &BackupRestoreCredentials<'_>,
    ) -> Result<BackupInspectionReport, Error> {
        let key = zeroize::Zeroizing::new(credentials_key(bytes, credentials)?);
        let manifest = open_with_key(bytes, &key)?;
        let sync_state = if let AppState::Unlocked {
            storage, identity, ..
        } = &self.state
        {
            if identity.user_id == manifest.seal.payload.user_id {
                storage
                    .load_seal(&AuthMethod::RecoveryIdentity(identity))?
                    .map(|s| WalletSeal::compare_seals(&s.seal, &manifest.seal))
            } else {
                None
            }
        } else {
            None
        };
        Ok(BackupInspectionReport {
            manifest,
            sync_state,
        })
    }
    /// Verifies all bytes before staging, binds a new epoch, and activates a fresh local profile.
    /// Existing profiles are preserved; restored copies receive a fresh anonymous folder.
    pub fn restore_backup(
        &mut self,
        bytes: &[u8],
        blobs: &HashMap<String, Vec<u8>>,
        credentials: BackupRestoreCredentials<'_>,
        new_local_password: &str,
        local_instance_id: String,
    ) -> Result<RestoreOutcome, Error> {
        if new_local_password.is_empty() {
            return Err(StorageError::EmptyPassword.into());
        }
        if local_instance_id.is_empty() {
            return Err(invalid("A device instance ID is required"));
        }
        let key = zeroize::Zeroizing::new(credentials_key(bytes, &credentials)?);
        let payload = open_with_key(bytes, &key)?;
        if blobs.len() != payload.blob_map.len() {
            return Err(invalid("Backup blob set does not match manifest"));
        }
        for (name, path) in &payload.blob_map {
            let data = blobs
                .get(name)
                .ok_or_else(|| invalid("Missing backup blob"))?;
            if crypto::get_hash(data) != payload.integrity.payload.item_hashes[path] {
                return Err(invalid("Backup blob hash mismatch"));
            }
        }
        let folder_name = format!("restore_{}", uuid::Uuid::new_v4().simple());
        let staging = self
            .base_storage_path
            .join(format!("{}.restore_tmp", folder_name));
        fs::create_dir(&staging)?;
        let stage_storage = FileStorage::new(staging.clone());
        let result = (|| {
            for (name, path) in &payload.blob_map {
                let target = staging.join(path);
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }
                stage_storage.write_atomic(path, &blobs[name])?;
            }
            let mut storage = FileStorage::new(staging.clone());
            let auth = match &credentials {
                BackupRestoreCredentials::BackupPassword(p) => AuthMethod::Password(p),
                BackupRestoreCredentials::Mnemonic {
                    phrase,
                    passphrase,
                    language,
                    ..
                } => AuthMethod::Mnemonic(phrase, *passphrase, *language),
            };
            verify_raw_state(&storage, &auth, &payload.seal)?;
            let (mut wallet, identity): (Wallet, UserIdentity) =
                Wallet::load(&storage, &auth, local_instance_id.clone())?;
            if identity.user_id != payload.seal.payload.user_id {
                return Err(invalid("Restored identity mismatch"));
            }
            let stored = storage
                .load_seal(&auth)?
                .ok_or_else(|| invalid("Missing restored seal"))?;
            if stored.seal != payload.seal {
                return Err(invalid("Restored seal mismatch"));
            }
            let anchor_tag = crate::models::seal::derive_anchor_step_tag(
                &payload.seal.payload.prev_seal_hash,
                payload.seal.payload.tx_nonce,
            );
            let anchor_query = crate::services::l2_gateway::build_anchor_status_query(
                &identity,
                payload.seal.payload.epoch as u64,
                payload.seal.payload.tx_nonce,
                &anchor_tag,
                vec![],
                1,
            )?;
            let mut voucher_queries = HashMap::new();
            for (id, instance) in &wallet.voucher_store.vouchers {
                if instance.status == crate::wallet::instance::VoucherStatus::Active {
                    voucher_queries.insert(id.clone(), wallet.build_voucher_status_query(id, 1)?);
                }
            }
            // Loading may expire vouchers or migrate protocol state. Persist that state
            // in staging before signing the recovery seal over it.
            wallet.save(&mut storage, &identity, &auth)?;
            storage.reset_password(&identity, new_local_password)?;
            let merkle =
                crate::models::seal::calculate_voucher_merkle_root(&wallet.voucher_store.vouchers);
            let fp = crate::storage::seal_service::SealService::calculate_state_hash(
                &wallet.own_fingerprints,
            )?;
            // Advance beyond the newest locally known epoch when restoring an older copy.
            let mut last_known_seal = payload.seal.clone();
            for profile in self.list_profiles()? {
                if profile.folder_name.is_empty()
                    || !profile
                        .folder_name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    continue;
                }
                let known = FileStorage::new(self.base_storage_path.join(profile.folder_name));
                if let Ok(Some(record)) = known.load_seal(&AuthMethod::RecoveryIdentity(&identity))
                {
                    if record.seal.payload.user_id == identity.user_id
                        && (record.seal.payload.epoch, record.seal.payload.tx_nonce)
                            > (
                                last_known_seal.payload.epoch,
                                last_known_seal.payload.tx_nonce,
                            )
                        && matches!(
                            record.seal.verify_integrity(
                                &identity.user_id,
                                &identity.user_id,
                                &record.seal.payload.instance_id
                            )?,
                            SealValidationResult::Valid | SealValidationResult::LegacyValid
                        )
                    {
                        last_known_seal = record.seal;
                    }
                }
            }
            let epoch = last_known_seal
                .payload
                .epoch
                .checked_add(1)
                .ok_or_else(|| invalid("Epoch exhausted"))?;
            let state_hash =
                crate::storage::seal_service::SealService::calculate_comprehensive_state_hash(
                    epoch as u64,
                    0,
                    &merkle,
                    &fp,
                );
            let seal = WalletSeal::recover_epoch(
                Some(&last_known_seal),
                &identity.user_id,
                &identity,
                &state_hash,
                &local_instance_id,
            )?;
            storage.save_seal(
                &AuthMethod::Password(new_local_password),
                &crate::models::seal::LocalSealRecord {
                    seal: seal.clone(),
                    sync_status: crate::models::seal::SyncStatus::PendingUpload,
                    is_locked_due_to_fork: false,
                },
            )?;
            storage.save_integrity(&StorageIntegrityRecord::create_record(
                &identity,
                &seal,
                storage.get_all_item_hashes()?,
            )?)?;
            // Validate the staged wallet with the same checks as normal login before activation.
            let mut probe = AppService::new(&self.base_storage_path)?;
            probe.login(
                staging.file_name().unwrap().to_str().unwrap(),
                new_local_password,
                false,
                local_instance_id.clone(),
            )?;
            probe.logout();
            let target = self.base_storage_path.join(&folder_name);
            stage_storage.sync_directory(&staging)?;
            fs::rename(&staging, &target)?;
            stage_storage.sync_directory(&self.base_storage_path)?;
            let mut candidate = AppService::new(&self.base_storage_path)?;
            let activation = (|| {
                candidate.login(&folder_name, new_local_password, false, local_instance_id)?;
                let mut profiles = self.list_profiles()?;
                profiles.push(ProfileInfo {
                    profile_name: payload.profile_name.clone(),
                    folder_name: folder_name.clone(),
                });
                let index_storage = FileStorage::new(self.base_storage_path.clone());
                index_storage
                    .write_atomic("profiles.json", &serde_json::to_vec_pretty(&profiles)?)?;
                self.logout();
                self.state = std::mem::replace(&mut candidate.state, AppState::Locked);
                Ok::<_, Error>(RestoreOutcome {
                    folder_name: folder_name.clone(),
                    anchor_query,
                    voucher_queries,
                })
            })();
            if activation.is_err() {
                candidate.logout();
                // A failed index write leaves a recoverable orphan, never replaces an existing profile.
            }
            activation
        })();
        if staging.exists() {
            let _ = fs::remove_dir_all(&staging);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    fn setup() -> (tempfile::TempDir, AppService) {
        let dir = tempfile::tempdir().unwrap();
        let mut app = AppService::new(dir.path()).unwrap();
        app.create_profile(
            "Backup test",
            PHRASE,
            None,
            Some("pc"),
            "1234",
            crate::MnemonicLanguage::English,
            "device-a".into(),
        )
        .unwrap();
        (dir, app)
    }
    fn mnemonic() -> BackupRestoreCredentials<'static> {
        BackupRestoreCredentials::Mnemonic {
            phrase: PHRASE,
            passphrase: None,
            prefix: Some("pc"),
            language: crate::MnemonicLanguage::English,
        }
    }
    #[test]
    fn mnemonic_backup_excludes_local_password_and_restores() {
        let (_dir, mut app) = setup();
        let folder = app.list_profiles().unwrap()[0].folder_name.clone();
        let local_profile =
            fs::read(app.base_storage_path.join(&folder).join("profile.enc")).unwrap();
        let backup = app
            .create_differential_backup(None, BackupProtection::MnemonicOnly, Some("1234"))
            .unwrap();
        assert!(
            app.inspect_backup(
                &backup.encrypted_manifest_bytes,
                &BackupRestoreCredentials::BackupPassword("1234")
            )
            .is_err()
        );
        let inspection = app
            .inspect_backup(&backup.encrypted_manifest_bytes, &mnemonic())
            .unwrap();
        let profile_blob = inspection
            .manifest
            .blob_map
            .iter()
            .find(|(_, p)| *p == "profile.enc")
            .unwrap()
            .0;
        let container = serde_json::from_slice(&backup.put_blobs[profile_blob]).unwrap();
        assert!(get_file_key(&AuthMethod::Password("1234"), &container).is_err());
        assert_eq!(
            local_profile,
            fs::read(app.base_storage_path.join(folder).join("profile.enc")).unwrap()
        );
        let target = tempfile::tempdir().unwrap();
        let mut restored = AppService::new(target.path()).unwrap();
        let result = restored
            .restore_backup(
                &backup.encrypted_manifest_bytes,
                &backup.put_blobs,
                mnemonic(),
                "new-password",
                "device-b".into(),
            )
            .unwrap();
        assert!(result.voucher_queries.is_empty());
        assert_eq!(
            restored.check_integrity(Some("new-password")).unwrap(),
            IntegrityReport::Valid
        );
        restored.logout();
        restored
            .login(
                &result.folder_name,
                "new-password",
                false,
                "device-b".into(),
            )
            .unwrap();
    }
    #[test]
    fn custom_password_supports_both_recovery_routes_and_noop_diff() {
        let (_dir, mut app) = setup();
        let backup = app
            .create_differential_backup(
                None,
                BackupProtection::CustomBackupPassword("Strong cloud password!99"),
                Some("1234"),
            )
            .unwrap();
        for credentials in [
            mnemonic(),
            BackupRestoreCredentials::BackupPassword("Strong cloud password!99"),
        ] {
            app.inspect_backup(&backup.encrypted_manifest_bytes, &credentials)
                .unwrap();
            let target = tempfile::tempdir().unwrap();
            AppService::new(target.path())
                .unwrap()
                .restore_backup(
                    &backup.encrypted_manifest_bytes,
                    &backup.put_blobs,
                    credentials,
                    "new-local",
                    "device-c".into(),
                )
                .unwrap();
        }
        assert!(
            app.inspect_backup(
                &backup.encrypted_manifest_bytes,
                &BackupRestoreCredentials::BackupPassword("1234")
            )
            .is_err()
        );
        let next = app
            .create_differential_backup(
                Some(&backup.encrypted_manifest_bytes),
                BackupProtection::CustomBackupPassword("Strong cloud password!99"),
                Some("1234"),
            )
            .unwrap();
        assert!(next.put_blobs.is_empty());
        assert!(next.delete_blobs.is_empty());
    }
    #[test]
    fn tampered_blob_and_authenticated_traversal_are_rejected_before_staging() {
        let (_dir, mut app) = setup();
        let mut backup = app
            .create_differential_backup(None, BackupProtection::MnemonicOnly, Some("1234"))
            .unwrap();
        let target = tempfile::tempdir().unwrap();
        let mut restored = AppService::new(target.path()).unwrap();
        backup.put_blobs.values_mut().next().unwrap()[0] ^= 1;
        assert!(
            restored
                .restore_backup(
                    &backup.encrypted_manifest_bytes,
                    &backup.put_blobs,
                    mnemonic(),
                    "new",
                    "device-b".into()
                )
                .is_err()
        );
        assert_eq!(fs::read_dir(target.path()).unwrap().count(), 0);
        let key = credentials_key(&backup.encrypted_manifest_bytes, &mnemonic()).unwrap();
        let mut payload = open_with_key(&backup.encrypted_manifest_bytes, &key).unwrap();
        payload
            .blob_map
            .insert(blob_name(&key, "../outside.enc"), "../outside.enc".into());
        let mut header: EncryptedBackupManifest =
            serde_json::from_slice(&backup.encrypted_manifest_bytes).unwrap();
        header.ciphertext =
            B64.encode(encrypt(&key, &serde_json::to_vec(&payload).unwrap()).unwrap());
        assert!(
            restored
                .inspect_backup(&serde_json::to_vec(&header).unwrap(), &mnemonic())
                .is_err()
        );
        assert_eq!(fs::read_dir(target.path()).unwrap().count(), 0);
    }
    #[test]
    fn differential_inventory_reuses_unchanged_files_and_deletes_removed_blobs() {
        let (_dir, mut app) = setup();
        app.save_encrypted_data("backup-test", b"one", Some("1234"))
            .unwrap();
        let first = app
            .create_differential_backup(None, BackupProtection::MnemonicOnly, Some("1234"))
            .unwrap();
        let old = app
            .inspect_backup(&first.encrypted_manifest_bytes, &mnemonic())
            .unwrap()
            .manifest;
        if let AppState::Unlocked { storage, .. } = &app.state {
            fs::remove_file(storage.user_storage_path.join("generic_backup-test.enc")).unwrap();
        }
        app.repair_integrity(Some("1234")).unwrap();
        let next = app
            .create_differential_backup(
                Some(&first.encrypted_manifest_bytes),
                BackupProtection::MnemonicOnly,
                Some("1234"),
            )
            .unwrap();
        assert!(next.put_blobs.is_empty());
        assert_eq!(
            next.delete_blobs,
            vec![
                old.blob_map
                    .iter()
                    .find(|(_, p)| *p == "generic_backup-test.enc")
                    .unwrap()
                    .0
                    .clone()
            ]
        );
    }
    #[test]
    fn old_backup_restores_queries_and_reconciles_spent_voucher() {
        let (_dir, mut app) = setup();
        let id = "backup-voucher".to_string();
        let (_, _, _, _, voucher, _) = crate::test_utils::setup_voucher_with_one_tx();
        app.get_wallet_mut().unwrap().add_voucher_instance(
            id.clone(),
            voucher,
            crate::wallet::instance::VoucherStatus::Active,
        );
        app.update_seal_after_state_change(Some("1234")).unwrap();
        let backup = app
            .create_differential_backup(None, BackupProtection::MnemonicOnly, Some("1234"))
            .unwrap();
        app.reconcile_rollback_with_diagnostics(std::slice::from_ref(&id), Some(42), Some("1234"))
            .unwrap();
        let target = tempfile::tempdir().unwrap();
        let mut restored = AppService::new(target.path()).unwrap();
        let outcome = restored
            .restore_backup(
                &backup.encrypted_manifest_bytes,
                &backup.put_blobs,
                mnemonic(),
                "new",
                "device-b".into(),
            )
            .unwrap();
        assert!(outcome.voucher_queries.contains_key(&id));
        let report = restored
            .reconcile_rollback_with_diagnostics(std::slice::from_ref(&id), Some(42), Some("new"))
            .unwrap();
        assert!(report.archived_voucher_ids.contains(&id));
        assert_eq!(report.new_tx_nonce, 42);
        assert_eq!(
            restored
                .with_wallet(|w| w.voucher_store.vouchers[&id].status.clone())
                .unwrap(),
            crate::wallet::instance::VoucherStatus::Archived
        );
        assert_eq!(
            restored.check_integrity(Some("new")).unwrap(),
            IntegrityReport::Valid
        );
    }
    proptest::proptest! {
        #[test]
        fn blob_names_are_opaque_and_path_specific(path in "[a-zA-Z0-9_/.-]{1,120}", key in proptest::array::uniform32(proptest::num::u8::ANY)) {
            let name = blob_name(&key, &path);
            proptest::prop_assert_eq!(name.len(), 41);
            proptest::prop_assert!(name.starts_with("blob_") && name.ends_with(".enc"));
            proptest::prop_assert_ne!(name, blob_name(&key, &(path + "x")));
        }
        #[test]
        fn aead_detects_every_single_byte_mutation(data in proptest::collection::vec(proptest::num::u8::ANY, 0..1024), index in proptest::num::usize::ANY) {
            let key = [17;32];
            let mut encrypted = encrypt(&key, &data).unwrap();
            let offset = index % encrypted.len();
            encrypted[offset] ^= 1;
            proptest::prop_assert!(decrypt(&key, &encrypted).is_err());
        }
    }
}
