//! Local crash recovery for full, sealed wallet mutations.
//!
//! The encrypted undo journal is temporary. The constant-size commit record
//! identifies the latest completed local transaction; neither stores L2 receipts.
//! Callers must hold `WalletLockGuard` throughout recovery and mutation.

use super::file_storage::{EncryptedStorageContainer, ProfileStorageContainer};
use super::key_manager::get_file_key;
use super::{AuthMethod, FileStorage, StorageError};
use crate::services::crypto;
use serde::{Deserialize, Serialize};
use rand_core::RngCore;
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use zeroize::Zeroizing;

const JOURNAL: &str = ".wallet.undo.enc";
const MARKER: &str = ".wallet.commit.enc";
const MAX_JOURNAL_BYTES: usize = 64 * 1024 * 1024;
const MAX_FILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_FILES: usize = 4096;

fn invalid(message: &str) -> StorageError {
    StorageError::StateConflict(format!("Wallet transaction: {message}"))
}

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
struct SavedFile(#[serde(with = "super::file_storage::base64_serde")] Vec<u8>);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Undo {
    version: u8,
    wallet_path: String,
    id: String,
    generation: u64,
    previous_commit: Option<String>,
    files: BTreeMap<String, SavedFile>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    // Allows authentication even while profile.enc is being replaced.
    #[serde(with = "super::file_storage::base64_serde")]
    key_profile: Vec<u8>,
    #[serde(with = "super::file_storage::base64_serde")]
    encrypted_store_payload: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Commit {
    version: u8,
    wallet_path: String,
    id: String,
    generation: u64,
}

pub(crate) struct WalletTransaction {
    key: Zeroizing<[u8; 32]>,
    undo: Undo,
}

fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>, StorageError> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(invalid("expected a regular file"));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err(invalid("file exceeds transaction size limit"));
    }
    Ok(bytes)
}

fn wallet_path(storage: &FileStorage) -> Result<String, StorageError> {
    Ok(storage
        .user_storage_path
        .canonicalize()?
        .to_string_lossy()
        .into_owned())
}

fn managed_base(name: &str) -> bool {
    if name.len() > 512 || name.contains('\\') || name.contains("..") {
        return false;
    }
    if let Some(event) = name.strip_prefix("events/") {
        return !event.contains('/')
            && event.ends_with(".json.enc")
            && event
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.');
    }
    if name.contains('/') {
        return false;
    }
    matches!(
        name,
        "profile.enc"
            | "vouchers.enc"
            | "bundles.meta.enc"
            | "known_fingerprints.enc"
            | "own_fingerprints.enc"
            | "proofs.enc"
            | "active_gossip.enc"
            | "seal.enc"
            | "storage_integrity.json"
            | "events.json.enc"
            | ".wallet.generation"
    ) || (name.starts_with("generic_") && name.ends_with(".enc"))
}

pub(crate) fn is_recognized_temp_file(name: &str) -> bool {
    if name.len() > 512 || name.contains('\\') || name.contains("..") {
        return false;
    }
    if let Some((base, nonce)) = name.rsplit_once(".tmp.") {
        if nonce.len() == 32 && nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
            return base == JOURNAL || base == MARKER || managed_base(base);
        }
    }
    false
}

fn managed(name: &str) -> bool {
    if is_recognized_temp_file(name) {
        return true;
    }
    managed_base(name)
}

fn list_managed(storage: &FileStorage) -> Result<Vec<String>, StorageError> {
    let mut names = Vec::new();
    for entry in fs::read_dir(&storage.user_storage_path)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| invalid("non-UTF8 file name"))?
            .to_owned();
        if name == "events" {
            if !entry.file_type()?.is_dir() {
                return Err(invalid("events must be a directory"));
            }
            for event in fs::read_dir(entry.path())? {
                let event = event?;
                let file = event
                    .file_name()
                    .to_str()
                    .ok_or_else(|| invalid("non-UTF8 event name"))?
                    .to_owned();
                let relative = format!("events/{file}");
                if managed(&relative) {
                    if !event.file_type()?.is_file() {
                        return Err(invalid("event must be a regular file"));
                    }
                    names.push(relative);
                }
                if names.len() > MAX_FILES {
                    return Err(invalid("too many transaction files"));
                }
            }
        } else if managed(&name) {
            if !entry.file_type()?.is_file() {
                return Err(invalid("managed path must be a regular file"));
            }
            names.push(name);
        }
        if names.len() > MAX_FILES {
            return Err(invalid("too many transaction files"));
        }
    }
    names.sort();
    Ok(names)
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, StorageError> {
    serde_json::from_slice(bytes).map_err(|e| StorageError::InvalidFormat(e.to_string()))
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, StorageError> {
    serde_json::to_vec(value).map_err(|e| StorageError::InvalidFormat(e.to_string()))
}

fn encrypted<T: Serialize>(key: &[u8; 32], value: &T) -> Result<Vec<u8>, StorageError> {
    let plain = encode(value)?;
    let encrypted_store_payload =
        crypto::encrypt_data(key, &plain).map_err(|e| StorageError::EncryptionFailed {
            reason: e.to_string(),
        })?;
    encode(&EncryptedStorageContainer {
        encrypted_store_payload,
    })
}

fn load_commit(storage: &FileStorage, key: &[u8; 32]) -> Result<Option<Commit>, StorageError> {
    let path = storage.user_storage_path.join(MARKER);
    if !path.try_exists()? {
        return Ok(None);
    }
    let container: EncryptedStorageContainer = decode(&read_bounded(&path, 64 * 1024)?)?;
    let plain = crypto::decrypt_data(key, &container.encrypted_store_payload)
        .map_err(|_| invalid("commit record authentication failed"))?;
    let record: Commit = decode(&plain)?;
    // A completed wallet directory may move. The AEAD key identifies its
    // owner; only an outstanding undo journal is bound to an absolute path.
    if record.version != 1 || record.id.len() != 36 {
        return Err(invalid("invalid commit record version or identifier"));
    }
    Ok(Some(record))
}

fn load_seal_record(
    storage: &FileStorage,
    key: &[u8; 32],
) -> Result<Option<crate::models::seal::LocalSealRecord>, StorageError> {
    let path = storage.user_storage_path.join(super::file_storage::SEAL_FILE_NAME);
    if !path.try_exists()? {
        return Ok(None);
    }
    let container: EncryptedStorageContainer = decode(&read_bounded(&path, MAX_FILE_BYTES)?)?;
    let plain = crypto::decrypt_data(key, &container.encrypted_store_payload)
        .map_err(|_| invalid("seal authentication failed"))?;
    let record: crate::models::seal::LocalSealRecord = decode(&plain)?;
    Ok(Some(record))
}

fn decode_seal_bytes(
    key: &[u8; 32],
    bytes: &[u8],
) -> Result<crate::models::seal::LocalSealRecord, StorageError> {
    let container: EncryptedStorageContainer = decode(bytes)?;
    let plain = crypto::decrypt_data(key, &container.encrypted_store_payload)
        .map_err(|_| invalid("undo seal authentication failed"))?;
    let record: crate::models::seal::LocalSealRecord = decode(&plain)?;
    Ok(record)
}

impl FileStorage {
    /// Cleans recognized journal, marker, and managed-file random-nonce temporary files.
    /// Preserves unknown files. Callers must hold the exclusive wallet lock.
    pub(crate) fn clean_orphaned_transaction_temps(&self) -> Result<(), StorageError> {
        if !self.user_storage_path.exists() {
            return Ok(());
        }
        let mut cleaned = false;
        for entry in fs::read_dir(&self.user_storage_path)? {
            let entry = entry?;
            let name = match entry.file_name().to_str() {
                Some(n) => n.to_string(),
                None => continue,
            };
            if is_recognized_temp_file(&name) {
                if entry.file_type()?.is_file() {
                    let _ = fs::remove_file(entry.path());
                    cleaned = true;
                }
            } else if name == "events" && entry.file_type()?.is_dir() {
                for sub in fs::read_dir(entry.path())? {
                    let sub = sub?;
                    if let Some(sub_name) = sub.file_name().to_str() {
                        let relative = format!("events/{sub_name}");
                        if is_recognized_temp_file(&relative) && sub.file_type()?.is_file() {
                            let _ = fs::remove_file(sub.path());
                            cleaned = true;
                        }
                    }
                }
            }
        }
        if cleaned {
            let _ = self.sync_directory(&self.user_storage_path);
        }
        Ok(())
    }

    pub(crate) fn record_commit_marker(
        &self,
        auth: &AuthMethod,
        generation: u64,
    ) -> Result<(), StorageError> {
        let key = zeroize::Zeroizing::new(self.get_master_key_from_auth(auth)?);
        let commit = Commit {
            version: 1,
            wallet_path: wallet_path(self)?,
            id: uuid::Uuid::new_v4().to_string(),
            generation,
        };
        let bytes = encrypted(&key, &commit)?;
        self.write_atomic(MARKER, &bytes)
    }

    /// Starts a bounded undo transaction before invoking a mutating closure.
    /// Requires the caller's exclusive `WalletLockGuard`.
    pub(crate) fn begin_wallet_transaction(
        &self,
        auth: &AuthMethod,
    ) -> Result<WalletTransaction, StorageError> {
        #[cfg(not(unix))]
        return Err(invalid(
            "durable wallet transactions require directory fsync support",
        ));
        #[cfg(unix)]
        {
            self.clean_orphaned_transaction_temps()?;
            if self.user_storage_path.join(JOURNAL).try_exists()? {
                return Err(invalid(
                    "recover the previous transaction before starting another",
                ));
            }
            let key = Zeroizing::new(self.get_master_key_from_auth(auth)?);
            let previous = load_commit(self, &key)?;
            let generation = self.read_generation()?;
            if previous.as_ref().is_some_and(|m| m.generation > generation) {
                return Err(invalid("commit record/generation mismatch"));
            }
            generation
                .checked_add(1)
                .ok_or_else(|| invalid("generation exhausted"))?;
            let mut files = BTreeMap::new();
            let mut total = 0usize;
            for name in list_managed(self)? {
                let bytes = read_bounded(&self.user_storage_path.join(&name), MAX_FILE_BYTES)?;
                total = total
                    .checked_add(bytes.len())
                    .ok_or_else(|| invalid("snapshot size overflow"))?;
                if total > MAX_JOURNAL_BYTES / 4 {
                    return Err(invalid("wallet exceeds undo snapshot limit"));
                }
                files.insert(name, SavedFile(bytes));
            }
            let undo = Undo {
                version: 1,
                wallet_path: wallet_path(self)?,
                id: uuid::Uuid::new_v4().to_string(),
                generation,
                previous_commit: previous.map(|m| m.id),
                files,
            };
            let plain = encode(&undo)?;
            if plain.len() > MAX_JOURNAL_BYTES / 2 {
                return Err(invalid("encoded snapshot exceeds limit"));
            }
            let key_profile = undo
                .files
                .get("profile.enc")
                .ok_or_else(|| invalid("missing profile"))?
                .0
                .clone();
            let encrypted_store_payload =
                crypto::encrypt_data(&key, &plain).map_err(|e| StorageError::EncryptionFailed {
                    reason: e.to_string(),
                })?;
            let bytes = encode(&Envelope {
                key_profile,
                encrypted_store_payload,
            })?;
            if bytes.len() > MAX_JOURNAL_BYTES {
                return Err(invalid("journal exceeds limit"));
            }

            let dest = self.user_storage_path.join(JOURNAL);
            let mut nonce_bytes = [0u8; 16];
            rand_core::OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = hex::encode(nonce_bytes);
            let tmp = PathBuf::from(format!("{}.tmp.{}", dest.display(), nonce));
            {
                use std::fs::OpenOptions;
                use std::io::Write;
                let mut tmp_file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&tmp)?;
                tmp_file.write_all(&bytes)?;
                tmp_file.sync_all()?;
            }
            checkpoint("staged:.wallet.undo.enc");
            fs::rename(&tmp, &dest)?;
            if let Some(parent) = dest.parent() {
                self.sync_directory(parent)?;
            }
            checkpoint("journal-ready");
            Ok(WalletTransaction { key, undo })
        }
    }

    /// Recovers an interrupted local transaction before loading wallet state.
    /// Authenticates all metadata and preflights paths before touching data.
    /// Requires the caller's exclusive `WalletLockGuard`.
    pub(crate) fn recover_wallet_transaction(
        &self,
        auth: &AuthMethod,
    ) -> Result<bool, StorageError> {
        self.clean_orphaned_transaction_temps()?;
        let path = self.user_storage_path.join(JOURNAL);
        if !path.try_exists()? {
            return Ok(false);
        }
        let envelope: Envelope = decode(&read_bounded(&path, MAX_JOURNAL_BYTES)?)?;
        if envelope.key_profile.len() > MAX_FILE_BYTES {
            return Err(invalid("oversized profile header"));
        }
        let profile: ProfileStorageContainer = decode(&envelope.key_profile)?;
        let key: [u8; 32] = get_file_key(auth, &profile)?
            .try_into()
            .map_err(|_| invalid("invalid journal key length"))?;
        let key = Zeroizing::new(key);
        let plain = crypto::decrypt_data(&key, &envelope.encrypted_store_payload)
            .map_err(|_| invalid("undo journal authentication failed"))?;
        let undo: Undo = decode(&plain)?;
        if undo.files.get("profile.enc").map(|file| &file.0) != Some(&envelope.key_profile) {
            return Err(invalid("unauthenticated profile header"));
        }
        let transaction = WalletTransaction { key, undo };
        transaction.recover(self)?;
        Ok(true)
    }
}

impl WalletTransaction {
    fn validate(&self, storage: &FileStorage) -> Result<Vec<String>, StorageError> {
        if self.undo.version != 1
            || self.undo.wallet_path != wallet_path(storage)?
            || self.undo.files.len() > MAX_FILES
            || self.undo.id.len() != 36
        {
            return Err(invalid("foreign or invalid undo journal"));
        }
        for (name, bytes) in &self.undo.files {
            if !managed(name)
                || bytes.0.len() > MAX_FILE_BYTES
                || Path::new(name)
                    .components()
                    .any(|c| !matches!(c, Component::Normal(_)))
            {
                return Err(invalid("invalid undo entry"));
            }
        }
        let generation = storage.read_generation()?;
        if generation != self.undo.generation
            && Some(generation) != self.undo.generation.checked_add(1)
        {
            return Err(invalid("journal does not match current generation"));
        }
        list_managed(storage)
    }

    fn recover(&self, storage: &FileStorage) -> Result<(), StorageError> {
        storage.clean_orphaned_transaction_temps()?;
        let current_files = self.validate(storage)?;

        // Ensure recovery does not restore an unlocked seal over an active fork lock
        if let Ok(Some(current_seal)) = load_seal_record(storage, &self.key) {
            if current_seal.is_locked_due_to_fork {
                if let Some(undo_seal_file) = self.undo.files.get(super::file_storage::SEAL_FILE_NAME) {
                    if let Ok(undo_seal) = decode_seal_bytes(&self.key, &undo_seal_file.0) {
                        if !undo_seal.is_locked_due_to_fork {
                            return Err(invalid("refusing to restore unlocked seal over active fork lock"));
                        }
                    }
                }
            }
        }

        let current_commit = load_commit(storage, &self.key)?;
        if current_commit
            .as_ref()
            .is_some_and(|m| m.id == self.undo.id)
        {
            if current_commit.as_ref().map(|m| m.generation) != self.undo.generation.checked_add(1)
                || current_commit.as_ref().map(|m| m.wallet_path.as_str())
                    != Some(self.undo.wallet_path.as_str())
                || storage.read_generation()? != self.undo.generation + 1
            {
                return Err(invalid("invalid committed generation"));
            }
            return self.remove_journal(storage);
        }
        if current_commit.as_ref().map(|m| &m.id) != self.undo.previous_commit.as_ref() {
            return Err(invalid("unexpected commit record; refusing rollback"));
        }
        // Keep the journal throughout restoration: an interrupted recovery is repeatable.
        for (name, bytes) in &self.undo.files {
            let path = storage.user_storage_path.join(name);
            // An unchanged old seal need not be rewritten when the failing
            // storage operation itself was a seal replacement. This also makes
            // repeat recovery cheap while preserving fail-closed read errors.
            if !path.try_exists()? || read_bounded(&path, MAX_FILE_BYTES)? != bytes.0 {
                storage.write_atomic(name, &bytes.0)?;
            }
            checkpoint(&format!("recover:{name}"));
        }
        for name in current_files {
            if !self.undo.files.contains_key(&name) {
                storage.remove_durable(&name)?;
                checkpoint(&format!("recover-delete:{name}"));
            }
        }
        self.remove_journal(storage)
    }

    pub(crate) fn abort(self, storage: &FileStorage) -> Result<(), StorageError> {
        self.recover(storage)
    }

    pub(crate) fn commit(&self, storage: &FileStorage) -> Result<(), StorageError> {
        let expected_generation = self
            .undo
            .generation
            .checked_add(1)
            .ok_or_else(|| invalid("generation exhausted"))?;
        if storage.read_generation()? != expected_generation {
            return Err(invalid("sealed commit must advance exactly one generation"));
        }

        let commit_data = encrypted(
            &self.key,
            &Commit {
                version: 1,
                wallet_path: self.undo.wallet_path.clone(),
                id: self.undo.id.clone(),
                generation: expected_generation,
            },
        )?;

        let dest = storage.user_storage_path.join(MARKER);
        let mut nonce_bytes = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = hex::encode(nonce_bytes);
        let tmp = PathBuf::from(format!("{}.tmp.{}", dest.display(), nonce));

        {
            use std::fs::OpenOptions;
            use std::io::Write;
            let mut tmp_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)?;
            tmp_file.write_all(&commit_data)?;
            tmp_file.sync_all()?;
        }
        checkpoint("staged:.wallet.commit.enc");
        fs::rename(&tmp, &dest)?;

        let sync_res = (|| -> Result<(), StorageError> {
            #[cfg(all(test, feature = "test-utils"))]
            {
                if let Ok(inject_target) = std::env::var("HMC_INJECT_COMMIT_DIR_FSYNC_FAIL") {
                    if inject_target == "1" || dest.to_string_lossy().contains(&inject_target) {
                        return Err(StorageError::Io("injected directory fsync failure".to_string()));
                    }
                }
            }
            if let Some(parent) = dest.parent() {
                storage.sync_directory(parent)?;
            }
            Ok(())
        })();

        if let Err(err) = sync_res {
            return Err(StorageError::UncertainCommit {
                reason: format!("commit marker renamed but directory fsync failed: {err}"),
                transaction_id: self.undo.id.clone(),
                generation: expected_generation,
            });
        }

        checkpoint("commit-durable");
        // Cleanup failure after the durable commit is not transaction failure.
        // The next guarded opener authenticates the marker and completes cleanup.
        if let Err(error) = self.remove_journal(storage) {
            log::warn!("Committed wallet journal cleanup deferred: {error}");
        }
        Ok(())
    }

    fn remove_journal(&self, storage: &FileStorage) -> Result<(), StorageError> {
        storage.remove_durable(JOURNAL)
    }
}

/// Deterministic child-process barriers; physically absent from release builds.
#[cfg(all(debug_assertions, feature = "test-utils"))]
static ARM_BARRIERS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(all(debug_assertions, feature = "test-utils"))]
pub(crate) fn checkpoint(name: &str) {
    if !ARM_BARRIERS.load(std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    if std::env::var("HMC_WALLET_CRASH_POINT").ok().as_deref() == Some(name)
        && let Ok(ready) = std::env::var("HMC_WALLET_CRASH_READY")
    {
        if fs::write(ready, name).is_err() {
            std::process::abort();
        }
        loop {
            std::thread::park_timeout(std::time::Duration::from_secs(1));
        }
    }
}
#[cfg(not(all(debug_assertions, feature = "test-utils")))]
pub(crate) fn checkpoint(_name: &str) {}

#[cfg(all(test, feature = "test-utils", unix))]
mod tests {
    use super::*;
    use crate::app_service::AppService;
    use crate::test_utils::{ACTORS, setup_service_with_profile};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const PASSWORD: &str = "crash-atomic-test-password";
    const CHILD: &str = "storage::wallet_transaction::tests::crash_child";
    const FOLDER: &str = "fixture-folder";

    fn fixture(base: &Path) -> String {
        let (mut service, profile) =
            setup_service_with_profile(base, &ACTORS.alice, "atomic", PASSWORD);
        let storage = FileStorage::new(base.join(&profile.folder_name));
        let key = storage
            .get_master_key_from_auth(&AuthMethod::Password(PASSWORD))
            .expect("fixture key");
        // Valid empty encrypted stores exercise physical proof deletion and event migration.
        storage
            .write_atomic(
                "proofs.enc",
                &encrypted(&key, &crate::models::conflict::ProofStore::default()).expect("proofs"),
            )
            .expect("seed proofs");
        storage
            .write_atomic(
                "events.json.enc",
                &encrypted(
                    &key,
                    &Vec::<crate::models::wallet_event::WalletEvent>::new(),
                )
                .expect("events"),
            )
            .expect("seed events");
        service.logout();
        fs::write(base.join(FOLDER), &profile.folder_name).expect("folder");
        profile.folder_name
    }

    fn snapshot(storage: &FileStorage) -> BTreeMap<String, Vec<u8>> {
        list_managed(storage)
            .expect("paths")
            .into_iter()
            .filter(|p| !p.starts_with("generic___storage_session_anchor"))
            .map(|p| {
                let b = fs::read(storage.user_storage_path.join(&p)).expect("bytes");
                (p, b)
            })
            .collect()
    }

    fn open(base: &Path, folder: &str) -> AppService {
        let mut service = AppService::new(base).expect("service");
        service
            .login(folder, PASSWORD, false, "test-id".to_owned())
            .expect("recovered login");
        service
    }

    fn kill_at(base: &Path, point: &str, mode: &str) {
        let ready = base.join("child-ready");
        let _ = fs::remove_file(&ready);
        let mut child = Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", CHILD, "--nocapture"])
            .env("HMC_WALLET_TEST_BASE", base)
            .env("HMC_WALLET_TEST_MODE", mode)
            .env("HMC_WALLET_CRASH_POINT", point)
            .env("HMC_WALLET_CRASH_READY", &ready)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn child");
        let deadline = Instant::now() + Duration::from_secs(30);
        while !ready.exists() {
            if let Some(status) = child.try_wait().expect("poll child") {
                panic!("child exited before {point}: {status}");
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("child did not reach {point}");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let folder = fs::read_to_string(base.join(FOLDER)).expect("folder");
        let storage = FileStorage::new(base.join(folder));
        assert!(
            crate::storage::WalletLockGuard::new(&storage).is_err(),
            "exclusive lock at {point}"
        );
        child.kill().expect("kill at deterministic barrier");
        assert!(!child.wait().expect("reap child").success());
    }

    #[test]
    fn crash_child() {
        let Ok(base) = std::env::var("HMC_WALLET_TEST_BASE") else {
            return;
        };
        let base = Path::new(&base);
        let folder = fs::read_to_string(base.join(FOLDER)).expect("folder");
        let mode = std::env::var("HMC_WALLET_TEST_MODE").expect("mode");
        if mode == "recover" {
            ARM_BARRIERS.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        let mut service = open(base, &folder);
        if mode == "recover" {
            return;
        }
        ARM_BARRIERS.store(true, std::sync::atomic::Ordering::SeqCst);
        let standard = crate::test_utils::generate_signed_standard_toml(
            "voucher_standards/freetaler_v1/standard.toml",
        );
        let data = crate::NewVoucherData {
            creator_profile: crate::models::profile::PublicProfile {
                id: Some(
                    service
                        .with_wallet(|w| w.get_user_id().to_owned())
                        .expect("owner"),
                ),
                ..Default::default()
            },
            nominal_value: crate::models::voucher::ValueDefinition {
                amount: "10.00".to_owned(),
                ..Default::default()
            },
            validity_duration: Some("P1Y".to_owned()),
            ..Default::default()
        };
        service
            .create_new_voucher(&standard, data, Some(PASSWORD))
            .expect("create");
        service.logout();
    }

    #[test]
    fn subprocess_cuts_restore_old_state_until_durable_commit() {
        let event = format!(
            "write:events/{}.json.enc",
            chrono::Utc::now().format("%Y_%m")
        );
        let points = [
            "staged:.wallet.undo.enc",
            "journal-ready",
            "staged:vouchers.enc",
            "write:vouchers.enc",
            "write:profile.enc",
            "write:bundles.meta.enc",
            "write:known_fingerprints.enc",
            "write:own_fingerprints.enc",
            "delete:proofs.enc",
            "write:active_gossip.enc",
            &event,
            "delete:events.json.enc",
            "write:.wallet.generation",
            "write:seal.enc",
            "write:storage_integrity.json",
            "staged:.wallet.commit.enc",
            "commit-durable",
        ];
        for point in points {
            let dir = tempfile::tempdir().expect("tempdir");
            let folder = fixture(dir.path());
            let storage = FileStorage::new(dir.path().join(&folder));
            let old = snapshot(&storage);
            kill_at(dir.path(), point, "write");
            let mut service = open(dir.path(), &folder);
            let count = service
                .with_wallet(|w| w.voucher_store.vouchers.len())
                .expect("wallet");
            assert_eq!(
                count,
                usize::from(point == "commit-durable"),
                "cut at {point}"
            );
            if point != "commit-durable" {
                assert_eq!(snapshot(&storage), old, "cut at {point}");
            }
            service.logout();
            assert!(!storage.user_storage_path.join(JOURNAL).exists());
            let settled = snapshot(&storage);
            open(dir.path(), &folder).logout();
            assert_eq!(snapshot(&storage), settled, "second login at {point}");
        }
    }

    #[test]
    fn subprocess_recovery_can_itself_be_killed_and_repeated() {
        let dir = tempfile::tempdir().expect("tempdir");
        let folder = fixture(dir.path());
        let storage = FileStorage::new(dir.path().join(&folder));
        let old = snapshot(&storage);
        kill_at(dir.path(), "write:seal.enc", "write");
        kill_at(dir.path(), "recover:profile.enc", "recover");
        assert!(storage.user_storage_path.join(JOURNAL).exists());
        open(dir.path(), &folder).logout();
        assert_eq!(snapshot(&storage), old);
    }

    #[test]
    fn oversized_snapshot_is_rejected_before_any_mutation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let folder = fixture(dir.path());
        let storage = FileStorage::new(dir.path().join(folder));
        let _guard = crate::storage::WalletLockGuard::new(&storage).expect("guard");
        let before_generation = storage.read_generation().expect("generation");
        let path = storage.user_storage_path.join("generic_large.enc");
        fs::File::create(&path).expect("file").set_len(MAX_FILE_BYTES as u64 + 1).expect("length");
        assert!(storage.begin_wallet_transaction(&AuthMethod::Password(PASSWORD)).is_err());
        assert!(!storage.user_storage_path.join(JOURNAL).exists());
        assert_eq!(storage.read_generation().expect("generation"), before_generation);
        assert_eq!(fs::metadata(path).expect("metadata").len(), MAX_FILE_BYTES as u64 + 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_directory_fsync_errors_are_propagated() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = FileStorage::new(dir.path());
        // procfs permits opening its directory but rejects fsync with EINVAL.
        // This exercises the real syscall error, not a mocked return value.
        assert!(storage.sync_directory(Path::new("/proc")).is_err());
    }

    #[test]
    fn corrupt_wrong_auth_and_foreign_journals_do_not_overwrite_wallets() {
        let dir = tempfile::tempdir().expect("tempdir");
        let folder = fixture(dir.path());
        let storage = FileStorage::new(dir.path().join(&folder));
        kill_at(dir.path(), "journal-ready", "write");
        let journal = fs::read(storage.user_storage_path.join(JOURNAL)).expect("journal");
        let before = snapshot(&storage);
        let guard = crate::storage::WalletLockGuard::new(&storage).expect("guard");
        assert!(
            storage
                .recover_wallet_transaction(&AuthMethod::Password("wrong"))
                .is_err()
        );
        assert_eq!(snapshot(&storage), before);
        fs::write(storage.user_storage_path.join(JOURNAL), b"{broken}").expect("corrupt");
        assert!(
            storage
                .recover_wallet_transaction(&AuthMethod::Password(PASSWORD))
                .is_err()
        );
        assert_eq!(snapshot(&storage), before);
        fs::write(storage.user_storage_path.join(JOURNAL), &journal).expect("restore journal");
        drop(guard);
        let foreign = tempfile::tempdir().expect("foreign");
        // Copy the SAME key material to prove path binding, independently of AEAD key mismatch.
        for (name, bytes) in &before {
            let path = foreign.path().join(name);
            fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            fs::write(path, bytes).expect("copy");
        }
        fs::write(foreign.path().join(JOURNAL), journal).expect("foreign journal");
        let foreign_storage = FileStorage::new(foreign.path());
        let foreign_before = snapshot(&foreign_storage);
        let _guard = crate::storage::WalletLockGuard::new(&foreign_storage).expect("foreign guard");
        assert!(
            foreign_storage
                .recover_wallet_transaction(&AuthMethod::Password(PASSWORD))
                .is_err()
        );
        assert_eq!(snapshot(&foreign_storage), foreign_before);
    }

    #[test]
    fn post_rename_directory_fsync_error_yields_uncertain_outcome_and_blocks_replacement_spend() {
        let dir = tempfile::tempdir().expect("tempdir");
        let folder = fixture(dir.path());
        let mut service = open(dir.path(), &folder);

        let standard = crate::test_utils::generate_signed_standard_toml(
            "voucher_standards/freetaler_v1/standard.toml",
        );
        let data = crate::NewVoucherData {
            creator_profile: crate::models::profile::PublicProfile {
                id: Some(
                    service
                        .with_wallet(|w| w.get_user_id().to_owned())
                        .expect("owner"),
                ),
                ..Default::default()
            },
            nominal_value: crate::models::voucher::ValueDefinition {
                amount: "10.00".to_owned(),
                ..Default::default()
            },
            validity_duration: Some("P1Y".to_owned()),
            ..Default::default()
        };

        // Inject directory fsync failure on commit marker for this test directory only
        let test_dir_str = dir.path().to_string_lossy().to_string();
        unsafe { std::env::set_var("HMC_INJECT_COMMIT_DIR_FSYNC_FAIL", &test_dir_str) };
        let create_res = service.create_new_voucher(&standard, data, Some(PASSWORD));
        unsafe { std::env::remove_var("HMC_INJECT_COMMIT_DIR_FSYNC_FAIL") };

        // 1. Must return an explicit UncertainOutcome error, not an ordinary rollback error
        match create_res {
            Err(crate::Error::UncertainOutcome { reason, transaction_id, recovered_generation }) => {
                assert!(reason.contains("directory fsync failed"));
                assert_eq!(transaction_id.len(), 36);
                assert!(recovered_generation > 0);
            }
            other => panic!("Expected UncertainOutcome, got: {other:?}"),
        }

        // 2. The voucher was installed locally into memory and disk
        let count = service.with_wallet(|w| w.voucher_store.vouchers.len()).expect("count");
        assert_eq!(count, 1, "voucher was installed despite directory fsync failure");
        let voucher_instance_id = service.with_wallet(|w| {
            w.voucher_store.vouchers.values().next().unwrap().local_instance_id.clone()
        }).expect("id");

        // 3. Prevent replacement spend / conflicting creation
        let spend_guard = service.with_wallet(|w| {
            w.voucher_store.vouchers.values().next().unwrap().status == crate::wallet::instance::VoucherStatus::Active
        }).expect("status");
        assert!(spend_guard, "installed voucher is present and tracked");

        // 4. Clean reopen/recovery preserves the installed state
        service.logout();
        let service2 = open(dir.path(), &folder);
        let count2 = service2.with_wallet(|w| w.voucher_store.vouchers.len()).expect("count");
        assert_eq!(count2, 1, "recovered state retains the installed voucher");
        assert_eq!(
            service2.with_wallet(|w| {
                w.voucher_store.vouchers.values().next().unwrap().local_instance_id.clone()
            }).expect("id"),
            voucher_instance_id
        );
    }

    #[test]
    fn stale_journal_after_abort_plus_newer_fork_lock_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let folder = fixture(dir.path());
        let mut storage = FileStorage::new(dir.path().join(&folder));

        // 1. Create a valid journal at the initial generation
        kill_at(dir.path(), "journal-ready", "write");
        let journal = fs::read(storage.user_storage_path.join(JOURNAL)).expect("journal");

        // Clean up the journal so the wallet can proceed to normal operations
        fs::remove_file(storage.user_storage_path.join(JOURNAL)).expect("remove journal");

        // 2. Simulate a newer fork-lock write under the lock, advancing generation and commit marker
        let auth = AuthMethod::Password(PASSWORD);
        {
            let _guard = crate::storage::WalletLockGuard::new(&storage).expect("guard");
            let mut record = storage.load_seal(&auth).expect("load seal").unwrap();
            record.is_locked_due_to_fork = true;
            storage.save_seal(&auth, &record).expect("save seal");
            let current_gen = storage.read_generation().expect("read gen");
            let new_gen = storage.advance_generation(current_gen).expect("advance gen");
            storage.record_commit_marker(&auth, new_gen).expect("record commit marker");
        }

        // 3. Inject the authentic stale undo journal from before the fork-lock
        fs::write(storage.user_storage_path.join(JOURNAL), &journal).expect("write stale journal");

        // 4. Attempt recovery using the storage directly under the lock
        let guard = crate::storage::WalletLockGuard::new(&storage).expect("guard");
        let auth = AuthMethod::Password(PASSWORD);
        let recovery_res = storage.recover_wallet_transaction(&auth);

        // Must be rejected!
        assert!(recovery_res.is_err(), "Recovery must reject stale journal over fork lock");
        drop(guard);

        // 5. Verify the fork lock is STILL active and was NOT erased/unlocked
        let seal_after = storage.load_seal(&auth).expect("load").unwrap();
        assert!(seal_after.is_locked_due_to_fork, "Fork lock must remain active");

        // 6. Login with stale journal present fails during recovery check
        let mut service_with_stale = AppService::new(dir.path()).expect("service");
        let login_with_stale = service_with_stale.login(&folder, PASSWORD, false, "test-id".to_owned());
        assert!(login_with_stale.is_err(), "Login must fail with stale journal");

        // Clean up the rejected stale journal to test normal login with the locked seal
        fs::remove_file(storage.user_storage_path.join(JOURNAL)).expect("remove rejected journal");

        // 7. Login without stale journal must still be refused because of the active fork lock
        let mut service2 = AppService::new(dir.path()).expect("service");
        let login_res = service2.login(&folder, PASSWORD, false, "test-id".to_owned());
        assert!(matches!(login_res, Err(crate::Error::WalletLockedDueToFork)));
    }

    #[test]
    fn cleanup_of_nonce_temporary_files_preserves_unknown_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let folder = fixture(dir.path());
        let storage = FileStorage::new(dir.path().join(&folder));

        // Create recognized temp files without a completed journal
        let journal_tmp = storage.user_storage_path.join(".wallet.undo.enc.tmp.0123456789abcdef0123456789abcdef");
        fs::write(&journal_tmp, b"temporary snapshot data").expect("write journal tmp");

        let marker_tmp = storage.user_storage_path.join(".wallet.commit.enc.tmp.fedcba9876543210fedcba9876543210");
        fs::write(&marker_tmp, b"temporary commit data").expect("write marker tmp");

        let voucher_tmp = storage.user_storage_path.join("vouchers.enc.tmp.aabbccddeeff00112233445566778899");
        fs::write(&voucher_tmp, b"temporary voucher data").expect("write voucher tmp");

        // Create unknown files that MUST be preserved
        let unknown_file = storage.user_storage_path.join("unknown_notes.txt");
        fs::write(&unknown_file, b"user notes").expect("write unknown");

        let unknown_tmp = storage.user_storage_path.join("unknown.tmp");
        fs::write(&unknown_tmp, b"other tmp").expect("write unknown tmp");

        // Acquire lock and run recovery
        let _guard = crate::storage::WalletLockGuard::new(&storage).expect("guard");
        let auth = AuthMethod::Password(PASSWORD);
        let recovered = storage.recover_wallet_transaction(&auth).expect("recover");
        assert!(!recovered, "no completed journal to recover");

        // Recognized temp files must be removed
        assert!(!journal_tmp.exists(), "journal tmp must be cleaned");
        assert!(!marker_tmp.exists(), "marker tmp must be cleaned");
        assert!(!voucher_tmp.exists(), "voucher tmp must be cleaned");

        // Unknown files must be preserved
        assert!(unknown_file.exists(), "unknown file must be preserved");
        assert_eq!(fs::read(&unknown_file).expect("read"), b"user notes");
        assert!(unknown_tmp.exists(), "unknown tmp must be preserved");
        assert_eq!(fs::read(&unknown_tmp).expect("read"), b"other tmp");
    }
}
