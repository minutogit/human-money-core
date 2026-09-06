//! # src/archive/file_archive.rs
//!
//! An implementation of the `VoucherArchive` trait that stores each voucher state
//! as an encrypted, integrity-checked record in a structured directory hierarchy.
//!
//! ## Encryption-at-rest design (remediation of HMSEC-SA05-01)
//!
//! Every archived state is written as a JSON *envelope* of the shape
//!
//! ```text
//! {"format":"hmc-archive-v1","kdf":"pbkdf2-sha512"|"raw",
//!  "kdf_salt":"<base64>"|null,"ciphertext":"<base64>"}
//! ```
//!
//! where `ciphertext` is the ChaCha20-Poly1305 AEAD encryption of the canonical
//! voucher JSON. Two key sources are supported:
//!
//! * **Password mode** ([`FileVoucherArchive::new_secure`]): the record key is
//!   derived per record via PBKDF2-HMAC-SHA512 (100k rounds in release) from the
//!   wallet password and a fresh random 16-byte salt stored alongside the
//!   ciphertext. This mirrors the `ProfileStorageContainer` pattern of the
//!   encrypted wallet store.
//! * **Raw-key mode** ([`FileVoucherArchive::with_key`]): an already-derived
//!   32-byte key is used directly (`"kdf":"raw"`), skipping repeated KDF work
//!   when callers hold a session key.
//!
//! Threat model: a local attacker with read access to the disk (stolen laptop,
//! malware, cloud-synced backup folders) must not learn any voucher material
//! (amounts, identities, signatures) from the archive files alone.
//!
//! Legacy records written by unencrypted archive versions are NOT readable:
//! unsealed records are strictly rejected as integrity violations so the
//! sealed format can never be downgraded away (HMSEC-SA05-05).
//!
//! ## Whole-record detection design (remediation of HMSEC-SA05-09)
//!
//! An AEAD seal authenticates CONTENT, never CONTEXT. Two whole-record
//! attacks therefore require additional binding:
//!
//! * **Location binding:** every decrypted record must carry the same
//!   `voucher_id` as the directory it was loaded from; relocated/smuggled
//!   envelopes are rejected as integrity violations before they can poison
//!   attribution (including during global scans).
//! * **Per-voucher manifest:** each voucher directory contains a sealed
//!   `archive_manifest.sealed` envelope listing the exact set of archived
//!   record IDs. Readers verify set equality against the files actually on
//!   disk, so deleting (or injecting) whole records is detected instead of
//!   silently serving a rolled-back history. The manifest is sealed under the
//!   same key source, making undetected manifest edits impossible.
use crate::storage::StorageError;
use crate::models::voucher::Transaction;
use crate::models::voucher::Voucher;
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::crypto::symmetric::{
    decrypt_data, decrypt_symmetric_password, encrypt_data, encrypt_symmetric_password,
};
use crate::services::utils::to_canonical_json;
use base64::{Engine as _, engine::general_purpose};
use std::{fs, path::Path, path::PathBuf};

/// Format identifier stored in every sealed archive envelope.
const FORMAT_ID: &str = "hmc-archive-v1";
/// KDF identifier for records keyed via PBKDF2-HMAC-SHA512 from a password.
const KDF_PBKDF2_SHA512: &str = "pbkdf2-sha512";
/// KDF identifier for records keyed with an already-derived raw 32-byte key.
const KDF_RAW: &str = "raw";
/// File name of the sealed per-voucher manifest (extension deliberately not
/// `.json` so record scanners never mistake it for a state record).
const MANIFEST_FILE_NAME: &str = "archive_manifest.sealed";
/// Legacy manifest format identifier (v1, plain id entries without freshness
/// binding). Still READ for pre-existing installations; new writes always use
/// [`MANIFEST_FORMAT_ID_V2`].
#[allow(dead_code)]
const MANIFEST_FORMAT_ID: &str = "hmc-archive-manifest-v1";
/// Manifest format v2 (AUDIT-W4-STO-001): entries carry the SHA-3 hash of
/// each record's envelope bytes so whole-record content substitution is
/// detectable.
const MANIFEST_FORMAT_ID_V2: &str = "hmc-archive-manifest-v2";

/// A single record entry of a sealed archive manifest.
#[derive(Debug, Clone)]
struct ManifestEntry {
    /// Basename (without `.json`) of the archived state.
    id: String,
    /// SHA-3 hash of the envelope bytes on disk. `None` for legacy v1
    /// manifests (no freshness binding available).
    sha3: Option<String>,
}

/// Key source used to protect the archive records.
enum ArchiveKeySource {
    /// Records are keyed via PBKDF2-HMAC-SHA512 from this password and a
    /// fresh random per-record salt (see `encrypt_symmetric_password`).
    Password(String),
    /// Records are keyed directly with this already-derived 32-byte key.
    RawKey([u8; 32]),
}

/// An implementation of the `VoucherArchive` trait based on the file system.
///
/// The directory layout is unchanged: `base_path/voucher_id/transaction_id.json`.
/// However, each file does NOT contain the voucher itself; it contains a sealed
/// envelope (see the module documentation) whose ciphertext is the
/// ChaCha20-Poly1305 encryption of the canonical voucher JSON.
///
/// # Integrity invariant (remediation of HMSEC-SA05-02)
///
/// Manipulations MUST be detected deterministically BEFORE any domain object is
/// deserialized. This is satisfied by the AEAD authentication tag of
/// ChaCha20-Poly1305: the tag authenticates the entire plaintext (nonce +
/// ciphertext are bound to the derived key), so any bit-level modification of
/// the stored record causes decryption to fail. All readers surface such
/// failures as [`StorageError::IntegrityViolation`] instead of silently
/// skipping or returning tampered data. Only after successful authenticated
/// decryption is the plaintext handed to `serde_json`.
pub struct FileVoucherArchive {
    archive_directory: PathBuf,
    key_source: ArchiveKeySource,
}

impl FileVoucherArchive {
    /// Creates a new encrypted `FileVoucherArchive` instance for a specific
    /// base directory.
    ///
    /// Each record is encrypted with ChaCha20-Poly1305 under a key derived from
    /// `password` via PBKDF2-HMAC-SHA512 and a fresh random per-record salt.
    ///
    /// # Arguments
    /// * `path` - The base directory of the archive.
    /// * `password` - The password from which the record keys are derived.
    pub fn new_secure(path: impl Into<PathBuf>, password: &str) -> Self {
        FileVoucherArchive {
            archive_directory: path.into(),
            key_source: ArchiveKeySource::Password(password.to_string()),
        }
    }

    /// Creates a new encrypted `FileVoucherArchive` instance that skips the
    /// per-record KDF and uses an already-derived 32-byte key directly.
    ///
    /// Use this variant when a session/file key was derived elsewhere (e.g.
    /// from the wallet master key) to avoid redundant key derivation cost.
    ///
    /// # Arguments
    /// * `path` - The base directory of the archive.
    /// * `key` - The 32-byte key used to protect every record.
    pub fn with_key(path: impl Into<PathBuf>, key: [u8; 32]) -> Self {
        FileVoucherArchive {
            archive_directory: path.into(),
            key_source: ArchiveKeySource::RawKey(key),
        }
    }

    /// Encrypts `plaintext` (canonical voucher JSON) into a JSON envelope
    /// value according to the configured key source.
    fn seal_record(&self, plaintext: &[u8]) -> Result<serde_json::Value, StorageError> {
        // Empty credential guard (HMSEC-SA05-10): an empty password yields a
        // fully deterministic PBKDF2("") key that any offline scanner can
        // reconstruct from the public envelope format; an all-zero raw key is
        // equally degenerate. Both are rejected BEFORE any bytes touch disk.
        match &self.key_source {
            ArchiveKeySource::Password(password) if password.is_empty() => {
                return Err(StorageError::Generic(
                    "Refusing to seal archive records under an EMPTY password \
                     (zero-entropy key material)."
                        .to_string(),
                ));
            }
            ArchiveKeySource::RawKey(key) if key.iter().all(|&b| b == 0) => {
                return Err(StorageError::Generic(
                    "Refusing to seal archive records under a degenerate \
                     all-zero key."
                        .to_string(),
                ));
            }
            _ => {}
        }

        match &self.key_source {
            ArchiveKeySource::Password(password) => {
                let (ciphertext, salt) = encrypt_symmetric_password(plaintext, password)
                    .map_err(|e| StorageError::Generic(format!("Archive encryption failed: {}", e)))?;
                Ok(serde_json::json!({
                    "format": FORMAT_ID,
                    "kdf": KDF_PBKDF2_SHA512,
                    "kdf_salt": general_purpose::STANDARD.encode(salt),
                    "ciphertext": general_purpose::STANDARD.encode(ciphertext),
                }))
            }
            ArchiveKeySource::RawKey(key) => {
                let ciphertext = encrypt_data(key, plaintext)
                    .map_err(|e| StorageError::Generic(format!("Archive encryption failed: {}", e)))?;
                Ok(serde_json::json!({
                    "format": FORMAT_ID,
                    "kdf": KDF_RAW,
                    "kdf_salt": serde_json::Value::Null,
                    "ciphertext": general_purpose::STANDARD.encode(ciphertext),
                }))
            }
        }
    }

    /// Reads, verifies and decrypts the sealed envelope stored in `bytes`.
    ///
    /// Sealed envelopes are authenticated (AEAD tag verification) BEFORE the
    /// decrypted plaintext is returned; any failure in this chain yields
    /// [`StorageError::IntegrityViolation`] and tampered data is never
    /// returned. Records without sealed-envelope markers (e.g. plaintext
    /// files written by pre-encryption archive versions, or attacker
    /// supplied downgraded records) are likewise rejected with
    /// [`StorageError::IntegrityViolation`] — accepting unauthenticated
    /// plaintext would bypass the AEAD integrity check entirely
    /// (HMSEC-SA05-05).
    fn open_envelope(&self, bytes: &[u8], path: &Path) -> Result<Vec<u8>, StorageError> {
        let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| {
            StorageError::IntegrityViolation(format!(
                "Archive record {} is not valid JSON and may have been tampered with.",
                path.display()
            ))
        })?;

        if !looks_like_envelope(&value) {
            // Security hardening (HMSEC-SA05-05): records without sealed-envelope
            // markers are REJECTED instead of being parsed as "legacy plaintext".
            // The former read-only compatibility fallback turned at-rest
            // encryption into an opt-in integrity mechanism: an attacker could
            // bypass the AEAD verification entirely by replacing a record with
            // canonical plaintext voucher JSON. Since the HMSEC-SA05-01
            // remediation every writer seals records, so unsealed content can
            // only be attacker-supplied or tampered; it must never reach
            // deserialization.
            //
            // Documented compatibility decision: archives written by
            // pre-encryption versions are no longer readable here. Re-import
            // such states via the public API instead of accepting
            // unauthenticated forensic data.
            return Err(StorageError::IntegrityViolation(format!(
                "Archive record {} is not a sealed envelope; unauthenticated \
                 plaintext records are rejected to prevent the legacy downgrade \
                 bypass.",
                path.display()
            )));
        }

        let ciphertext_b64 = value
            .get("ciphertext")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                StorageError::IntegrityViolation(format!(
                    "Archive record {} is missing a valid ciphertext field.",
                    path.display()
                ))
            })?;
        let ciphertext = general_purpose::STANDARD.decode(ciphertext_b64).map_err(|_| {
            StorageError::IntegrityViolation(format!(
                "Archive record {} contains corrupt ciphertext material.",
                path.display()
            ))
        })?;

        let kdf = value.get("kdf").and_then(|v| v.as_str()).unwrap_or_default();

        match kdf {
            KDF_PBKDF2_SHA512 => {
                let password = match &self.key_source {
                    ArchiveKeySource::Password(p) => p,
                    ArchiveKeySource::RawKey(_) => {
                        return Err(StorageError::IntegrityViolation(format!(
                            "Archive record {} requires a password key source.",
                            path.display()
                        )));
                    }
                };
                let salt_b64 = value
                    .get("kdf_salt")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        StorageError::IntegrityViolation(format!(
                            "Archive record {} is missing its KDF salt.",
                            path.display()
                        ))
                    })?;
                let salt_bytes = general_purpose::STANDARD.decode(salt_b64).map_err(|_| {
                    StorageError::IntegrityViolation(format!(
                        "Archive record {} contains a corrupt KDF salt.",
                        path.display()
                    ))
                })?;
                let salt: [u8; 16] = salt_bytes.try_into().map_err(|_| {
                    StorageError::IntegrityViolation(format!(
                        "Archive record {} contains a KDF salt of invalid length.",
                        path.display()
                    ))
                })?;

                decrypt_symmetric_password(&ciphertext, password, &salt).map_err(|e| {
                    StorageError::IntegrityViolation(format!(
                        "AEAD verification failed for {}: {}",
                        path.display(),
                        e
                    ))
                })
            }
            KDF_RAW => {
                let key = match &self.key_source {
                    ArchiveKeySource::RawKey(k) => k,
                    ArchiveKeySource::Password(_) => {
                        return Err(StorageError::IntegrityViolation(format!(
                            "Archive record {} requires a raw key source.",
                            path.display()
                        )));
                    }
                };
                decrypt_data(key, &ciphertext).map_err(|e| {
                    StorageError::IntegrityViolation(format!(
                        "AEAD verification failed for {}: {}",
                        path.display(),
                        e
                    ))
                })
            }
            other => Err(StorageError::IntegrityViolation(format!(
                "Archive record {} uses an unknown KDF identifier '{}'.",
                path.display(),
                other
            ))),
        }
    }

    /// Reads, verifies and decrypts a single archive record from disk.
    ///
    /// Beyond AEAD verification (via [`Self::open_envelope`]) this enforces
    /// the whole-record LOCATION binding (HMSEC-SA05-09): the decrypted
    /// voucher's `voucher_id` must match the directory context it was loaded
    /// from, so relocated or smuggled envelopes can never be attributed to
    /// another voucher.
    fn read_record(&self, path: &Path) -> Result<Voucher, StorageError> {
        let bytes = fs::read(path)?;
        self.decode_record(&bytes, path)
    }

    /// Decodes and verifies a single archived voucher from raw envelope bytes.
    ///
    /// Beyond AEAD verification (via [`Self::open_envelope`]) this enforces
    /// the whole-record LOCATION binding (HMSEC-SA05-09): the decrypted
    /// voucher's `voucher_id` must match the directory context it was loaded
    /// from, so relocated or smuggled envelopes can never be attributed to
    /// another voucher.
    fn decode_record(&self, bytes: &[u8], path: &Path) -> Result<Voucher, StorageError> {
        let plaintext = self.open_envelope(bytes, path)?;

        // The AEAD tag already authenticates this plaintext; deserialization
        // failures therefore indicate a corrupted writer, not attacker-controlled
        // content, and are surfaced as integrity violations as well.
        let voucher: Voucher = serde_json::from_slice(&plaintext).map_err(|e| {
            StorageError::IntegrityViolation(format!(
                "Decrypted archive record {} does not contain a valid voucher: {}",
                path.display(),
                e
            ))
        })?;

        // Location/context binding (HMSEC-SA05-09): the AEAD seal
        // authenticates content, not storage context. A genuine envelope
        // relocated into another voucher's directory must be rejected instead
        // of re-attributing its history to that voucher.
        let context_voucher_id = path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .ok_or_else(|| {
                StorageError::IntegrityViolation(format!(
                    "Archive record {} has no resolvable voucher directory context.",
                    path.display()
                ))
            })?;
        if context_voucher_id != voucher.voucher_id {
            return Err(StorageError::IntegrityViolation(format!(
                "Archive record {} was relocated: directory context '{}' does \
                 not match the sealed voucher_id '{}'.",
                path.display(),
                context_voucher_id,
                voucher.voucher_id
            )));
        }

        Ok(voucher)
    }

    /// Returns the record entries from the sealed per-voucher manifest.
    ///
    /// SECURITY (AUDIT-W4-STO-001): since manifest format v2 every entry
    /// carries the SHA-3 hash of the record's ENVELOPE BYTES as written, so
    /// whole-record content substitution (copying an older genuine record
    /// over a newer filename — AEAD authenticates content, not freshness)
    /// is detected deterministically. Legacy v1 manifests (plain id strings)
    /// are tolerated for pre-existing installations; their entries carry no
    /// hash and get no freshness binding until the next manifest rewrite.
    fn read_manifest(&self, voucher_dir: &Path) -> Result<Vec<ManifestEntry>, StorageError> {
        let path = voucher_dir.join(MANIFEST_FILE_NAME);
        let bytes = fs::read(&path)?;
        let plaintext = self.open_envelope(&bytes, &path)?;

        // The AEAD tag authenticates the manifest payload; malformed content
        // after successful decryption indicates a corrupted writer.
        let value: serde_json::Value = serde_json::from_slice(&plaintext)?;
        let records = value
            .get("records")
            .and_then(|r| r.as_array())
            .ok_or_else(|| {
                StorageError::IntegrityViolation(format!(
                    "Archive manifest {} is missing its records list.",
                    path.display()
                ))
            })?
            .iter()
            .map(|entry| {
                if let Some(s) = entry.as_str() {
                    // Legacy v1 entry: id only, no freshness binding.
                    return Ok(ManifestEntry {
                        id: s.to_string(),
                        sha3: None,
                    });
                }
                let obj = entry.as_object().ok_or_else(|| {
                    StorageError::IntegrityViolation(format!(
                        "Archive manifest {} contains an invalid record entry.",
                        path.display()
                    ))
                })?;
                let id = obj.get("id").and_then(|v| v.as_str()).ok_or_else(|| {
                    StorageError::IntegrityViolation(format!(
                        "Archive manifest {} contains a record entry without id.",
                        path.display()
                    ))
                })?;
                let sha3 = obj.get("sha3").and_then(|v| v.as_str()).map(String::from);
                Ok(ManifestEntry {
                    id: id.to_string(),
                    sha3,
                })
            })
            .collect::<Result<Vec<ManifestEntry>, StorageError>>()?;
        Ok(records)
    }

    /// Seals and atomically writes the per-voucher manifest.
    ///
    /// `entries` maps each record id to the SHA-3 hash of its envelope bytes
    /// on disk (manifest format v2).
    fn write_manifest(
        &self,
        voucher_dir: &Path,
        mut entries: Vec<(String, String)>,
    ) -> Result<(), StorageError> {
        entries.sort();
        entries.dedup();
        let records: Vec<serde_json::Value> = entries
            .into_iter()
            .map(|(id, sha3)| serde_json::json!({ "id": id, "sha3": sha3 }))
            .collect();
        let payload = serde_json::json!({
            "format": MANIFEST_FORMAT_ID_V2,
            "records": records,
        });
        let envelope = self.seal_record(payload.to_string().as_bytes())?;

        let path = voucher_dir.join(MANIFEST_FILE_NAME);
        let tmp_path = voucher_dir.join(format!("{}.tmp", MANIFEST_FILE_NAME));
        fs::write(&tmp_path, serde_json::to_vec(&envelope)?)?;
        fs::rename(&tmp_path, &path)?;
        Ok(())
    }

    /// Computes the current manifest entries from disk contents: each record
    /// id with the SHA-3 hash of its envelope bytes.
    fn collect_manifest_entries(voucher_dir: &Path) -> Result<Vec<(String, String)>, StorageError> {
        let mut entries = Vec::new();
        for id in Self::collect_record_ids(voucher_dir)? {
            let path = voucher_dir.join(format!("{}.json", id));
            let bytes = fs::read(&path)?;
            entries.push((id, crate::services::crypto::get_hash(&bytes)));
        }
        Ok(entries)
    }

    /// Collects the sorted IDs of the state records currently on disk in a
    /// voucher directory (basenames of all `*.json` files).
    fn collect_record_ids(voucher_dir: &Path) -> Result<Vec<String>, StorageError> {
        let mut ids = Vec::new();
        for entry in fs::read_dir(voucher_dir)? {
            let path = entry?.path();
            if path.is_file() && path.extension().is_some_and(|s| s == "json") {
                let stem = path.file_stem().and_then(|s| s.to_str()).ok_or_else(|| {
                    StorageError::IntegrityViolation(format!(
                        "Archive record {} has an unusable file name.",
                        path.display()
                    ))
                })?;
                ids.push(stem.to_string());
            }
        }
        ids.sort();
        Ok(ids)
    }

    /// Synchronizes the per-voucher manifest with the records actually on
    /// disk after an archive write (HMSEC-SA05-09 bookkeeping side).
    ///
    /// * Missing manifest over a directory with AT MOST ONE record (fresh
    ///   archive, or a single crash between record and manifest write):
    ///   bootstrapped from current disk contents.
    /// * Missing manifest over a MULTI-record directory: refused — the
    ///   baseline needed to rule out whole-record deletion is gone
    ///   (AUDIT-W4-STO-002b); silent bootstrap would launder it.
    /// * In-sync manifest: no rewrite (avoids redundant KDF work).
    /// * Grow-only divergence (intact manifest + unknown extra files): each
    ///   extra file must authenticate as a genuine envelope of this voucher
    ///   (crash residue) before it is adopted; anything inauthentic — e.g.
    ///   injected junk designed to later brick readers — is rejected
    ///   immediately.
    /// * Shrunken or mixed divergence (records vanished while the manifest
    ///   was intact): refuses to rewrite. Silently re-syncing the
    ///   bookkeeping would launder a whole-record deletion executed between
    ///   two legitimate archiving operations (AUDIT-W4-STO-002a).
    fn sync_manifest(&self, voucher_dir: &Path) -> Result<(), StorageError> {
        let actual = Self::collect_record_ids(voucher_dir)?;
        let manifest_path = voucher_dir.join(MANIFEST_FILE_NAME);

        if !manifest_path.exists() {
            if actual.len() <= 1 {
                return self.write_manifest(voucher_dir, Self::collect_manifest_entries(voucher_dir)?);
            }
            return Err(StorageError::IntegrityViolation(format!(
                "Refusing to bootstrap archive manifest for {}: directory \
                 holds multiple records but no manifest; deletion of records \
                 and manifest cannot be ruled out.",
                voucher_dir.display()
            )));
        }

        let expected = self.read_manifest(voucher_dir)?;
        let expected_ids: std::collections::HashSet<&str> =
            expected.iter().map(|e| e.id.as_str()).collect();
        let actual_set: std::collections::HashSet<&str> =
            actual.iter().map(String::as_str).collect();

        if actual_set == expected_ids {
            return Ok(());
        }

        if actual_set.is_superset(&expected_ids) {
            // Grow-only: adopt ONLY authentic crash residue. Every unknown
            // file must decrypt and pass the location binding as a record of
            // THIS voucher; junk or foreign envelopes are a tampering signal,
            // not bookkeeping drift.
            for extra in actual_set.difference(&expected_ids) {
                let path = voucher_dir.join(format!("{}.json", extra));
                self.read_record(&path)?;
            }
            return self
                .write_manifest(voucher_dir, Self::collect_manifest_entries(voucher_dir)?);
        }

        Err(StorageError::IntegrityViolation(format!(
            "Refusing to update archive manifest for {}: record set diverged \
             from the sealed manifest (deletion and/or substitution); possible \
             tampering or rollback of archive records.",
            voucher_dir.display()
        )))
    }

    // TODO: Implement a cleanup function (`purge_deep_archive`)
    //       that deletes states after a retention period has expired.
}

/// Returns `true` if the JSON value carries the markers of a sealed archive
/// envelope. Values without these markers are unauthenticated content and are
/// rejected by `read_record`; the distinction is deterministic.
fn looks_like_envelope(value: &serde_json::Value) -> bool {
    value.get("format").and_then(|f| f.as_str()) == Some(FORMAT_ID)
        || value.get("ciphertext").is_some()
        || value.get("kdf_salt").is_some()
}

impl FileVoucherArchive {
    pub fn archive_voucher(
        &self,
        voucher: &Voucher,
        _owner_id: &str,
        _standard: &VoucherStandardDefinition,
    ) -> Result<(), StorageError> {
        // Each state is uniquely identified by the ID of the last transaction.
        let last_tx = voucher.transactions.last().ok_or_else(|| {
            StorageError::Generic("Cannot archive voucher with no transactions.".to_string())
        })?;

        // Create a subdirectory for each voucher to group the states.
        let voucher_dir = self.archive_directory.join(&voucher.voucher_id);
        fs::create_dir_all(&voucher_dir)?;

        let file_path = voucher_dir.join(format!("{}.json", &last_tx.t_id));
        if file_path.exists() {
            // Already archived, all good — but still keep the sealed manifest
            // in sync (bootstrap/repair after crashes, HMSEC-SA05-09).
            self.sync_manifest(&voucher_dir)?;
            return Ok(());
        }

        // Seal the canonical voucher JSON into an encrypted envelope before it
        // touches the disk (encryption at rest, HMSEC-SA05-01).
        let json_content = to_canonical_json(voucher)?;
        let envelope = self.seal_record(json_content.as_bytes())?;
        let envelope_bytes = serde_json::to_vec(&envelope)?;

        // Atomic write
        let temp_file_path = voucher_dir.join(format!("{}.json.tmp", &last_tx.t_id));
        fs::write(&temp_file_path, envelope_bytes)?;
        fs::rename(&temp_file_path, &file_path)?;

        // Manifest bookkeeping (HMSEC-SA05-09): keep the sealed record list in
        // sync with the states on disk so whole-record deletions are detected
        // by readers. Also runs for already-archived records to bootstrap or
        // repair manifests after crashes.
        self.sync_manifest(&voucher_dir)?;

        Ok(())
    }

    pub fn get_archived_voucher(&self, voucher_id: &str) -> Result<Voucher, StorageError> {
        let voucher_dir = self.archive_directory.join(voucher_id);
        if !voucher_dir.is_dir() {
            return Err(StorageError::NotFound);
        }

        // Whole-record loss detection (HMSEC-SA05-09): the sealed manifest
        // pins the exact set of archived records. A missing manifest means
        // deletion cannot be ruled out; any divergence between the manifest
        // and the files actually on disk is a whole-record deletion/injection.
        let manifest_path = voucher_dir.join(MANIFEST_FILE_NAME);
        if !manifest_path.exists() {
            return Err(StorageError::IntegrityViolation(format!(
                "Archive record manifest missing for {}; whole-record deletion \
                 cannot be ruled out.",
                voucher_dir.display()
            )));
        }
        let expected_entries = self.read_manifest(&voucher_dir)?;

        // Decrypt and verify every archived state of this voucher. Any integrity
        // violation aborts the lookup (detect-before-deserialize invariant).
        let mut expected: Vec<String> =
            expected_entries.iter().map(|e| e.id.clone()).collect();
        expected.sort();
        let actual = Self::collect_record_ids(&voucher_dir)?;
        if actual != expected {
            return Err(StorageError::IntegrityViolation(format!(
                "Archive record set mismatch for {}: manifest lists {} \
                 record(s), found {} on disk; whole-record deletion or \
                 injection detected.",
                voucher_dir.display(),
                expected.len(),
                actual.len()
            )));
        }

        // SECURITY (AUDIT-W4-STO-001): per-record freshness binding. The
        // sealed manifest v2 stores the SHA-3 hash of each record's envelope
        // bytes, so substituting a record's CONTENT (e.g. rolling the newest
        // state back to an older genuine record by copying files within the
        // directory) is detected even though AEAD authenticates both records.
        let hash_by_id: std::collections::HashMap<&str, &str> = expected_entries
            .iter()
            .filter_map(|e| e.sha3.as_deref().map(|h| (e.id.as_str(), h)))
            .collect();

        let mut states: Vec<Voucher> = Vec::new();
        for entry in fs::read_dir(&voucher_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() && path.extension().is_some_and(|s| s == "json") {
                let bytes = fs::read(&path)?;
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str())
                    && let Some(expected_hash) = hash_by_id.get(stem) {
                        let actual_hash =
                            crate::services::crypto::get_hash(&bytes);
                        if actual_hash != *expected_hash {
                            return Err(StorageError::IntegrityViolation(format!(
                                "Archive record {} does not match its sealed \
                                 manifest entry (content substituted or rolled \
                                 back).",
                                path.display()
                            )));
                        }
                    }
                states.push(self.decode_record(&bytes, &path)?);
            }
        }

        // The newest state is the one with the longest transaction chain;
        // ties are broken deterministically by the last transaction ID so the
        // result is stable across runs.
        states.sort_by(|a, b| {
            a.transactions
                .len()
                .cmp(&b.transactions.len())
                .then_with(|| {
                    let last_a = a.transactions.last().map(|t| t.t_id.as_str()).unwrap_or("");
                    let last_b = b.transactions.last().map(|t| t.t_id.as_str()).unwrap_or("");
                    last_a.cmp(last_b)
                })
        });

        states.pop().ok_or(StorageError::NotFound)
    }

    pub fn find_transaction_by_id(
        &self,
        t_id: &str,
    ) -> Result<Option<(Voucher, Transaction)>, StorageError> {
        // Search all subdirectories (each `voucher_id` directory).
        // Corrupt/tampered records propagate their IntegrityViolation instead
        // of being silently skipped (HMSEC-SA05-02).
        for voucher_dir_entry in fs::read_dir(&self.archive_directory)? {
            let voucher_dir_path = voucher_dir_entry?.path();
            if voucher_dir_path.is_dir() {
                for entry in fs::read_dir(voucher_dir_path)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.is_file() && path.extension().is_some_and(|s| s == "json") {
                        let voucher = self.read_record(&path)?;
                        if let Some(tx) = voucher.transactions.iter().find(|t| t.t_id == t_id) {
                            return Ok(Some((voucher.clone(), tx.clone())));
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    pub fn find_voucher_by_tx_id(&self, t_id: &str) -> Result<Option<Voucher>, StorageError> {
        // Use the existing logic of `find_transaction_by_id`.
        if let Some((voucher, _)) = self.find_transaction_by_id(t_id)? {
            Ok(Some(voucher))
        } else {
            Ok(None)
        }
    }
}
