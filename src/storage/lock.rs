//! # src/storage/lock.rs
//!
//! File-based wallet locking with stale-lock detection.
//!
//! Extracted from `file_storage.rs` (Streamline Phase-2). On non-WASM targets
//! this module encapsulates the `sysinfo`-backed PID scan and stale-lock
//! removal; on WASM it degrades to a no-op filesystem check. The public
//! `WalletLockGuard` RAII guard is preserved for transactional operations.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

#[cfg(not(target_arch = "wasm32"))]
use sysinfo::{Pid, System};

use super::StorageError;
use crate::storage::file_storage::FileStorage;

// ---------------------------------------------------------------------------
// RAII guard (moved from `storage::mod`)
// ---------------------------------------------------------------------------

/// An RAII guard that ensures a lock is automatically released when the guard
/// goes out of scope.
///
/// This guard should be used for *transactional* operations like
/// `create_transfer_bundle` or `receive_bundle`.
///
/// The guard never panics: `Drop` swallows I/O errors and logs them, and
/// `new` returns a typed `StorageError::LockFailed` instead of panicking.
pub struct WalletLockGuard {
    lock_file_path: PathBuf,
    was_already_locked: bool,
}

impl WalletLockGuard {
    /// Creates a new guard and immediately attempts to acquire the lock.
    pub fn new(storage: &FileStorage) -> Result<Self, StorageError> {
        let is_newly_locked = acquire_lock(storage)?; // Acquire lock upon creation
        let lock_file_path = storage.get_lock_file_path().clone();
        Ok(Self {
            lock_file_path,
            was_already_locked: !is_newly_locked,
        })
    }
}

impl Drop for WalletLockGuard {
    fn drop(&mut self) {
        // Delete the file ONLY if we created it ourselves (was_already_locked == false)
        if !self.was_already_locked && self.lock_file_path.exists()
            && let Err(e) = fs::remove_file(&self.lock_file_path)
        {
            // IMPORTANT: Never panic in `drop`!
            eprintln!(
                "Schwerwiegender Fehler: Wallet-Sperre konnte nicht freigegeben werden: {:?}",
                e
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Lock primitives
// ---------------------------------------------------------------------------

/// Attempts to acquire the wallet lock.
///
/// Returns `Ok(true)` when the lock was newly acquired, `Ok(false)` when the
/// current process already holds it (re-entrancy), and `Err` when another
/// live process holds the lock. Stale locks (dead PID or unparseable content)
/// are removed and the lock is re-acquired.
///
/// This function contains the `#[cfg(not(target_arch = "wasm32"))]` PID-scan
/// that was previously inlined in `FileStorage::lock`, preserving exact error
/// messages and atomic `create_new` semantics.
pub(crate) fn acquire_lock(storage: &FileStorage) -> Result<bool, StorageError> {
    // Ensure the directory exists.
    fs::create_dir_all(&storage.user_storage_path)?;

    let current_pid = std::process::id();
    let pid_str = current_pid.to_string();

    // --- Atomic lock acquisition (TOCTOU-free) ---
    // Use create_new() which atomically creates the file and fails if it
    // already exists (O_CREAT | O_EXCL).
    match fs::File::create_new(storage.get_lock_file_path()) {
        Ok(mut file) => {
            // File was created atomically -> we have the exclusive lock.
            file.write_all(pid_str.as_bytes())?;
            Ok(true)
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                // Lock file already exists -> another process created it first.
                // Read the existing PID and apply the same checks as before.
                let pid_result = fs::read_to_string(storage.get_lock_file_path())
                    .map(|s| s.trim().parse::<u32>());
                let pid_val = match pid_result {
                    Ok(v) => v.unwrap_or(0),
                    Err(_) => {
                        // Unparseable content -> treat as stale, re-acquire.
                        let _ = fs::remove_file(storage.get_lock_file_path());
                        let mut file = fs::File::create(storage.get_lock_file_path()).map_err(|e| {
                            StorageError::LockAcquisitionFailed { reason: format!(
                                "Konnte Lock-Datei nach Bereinigung nicht erstellen: {}",
                                e
                            )}
                        })?;
                        file.write_all(pid_str.as_bytes())?;
                        return Ok(true);
                    }
                };

                // --- RE-ENTRANCY CHECK ---
                if pid_val == current_pid {
                    return Ok(false);
                }

                // Check if the process is still running
                #[cfg(not(target_arch = "wasm32"))]
                {
                    let mut s = System::new();
                    s.refresh_processes();

                    if s.process(Pid::from_u32(pid_val)).is_some() {
                        // Process still running -> Error! Another live process holds the lock.
                        return Err(StorageError::LockFailed(format!(
                            "Wallet wird bereits von einem anderen Prozess (PID: {}) verwendet.",
                            pid_val
                        )));
                    } else {
                        // Process dead -> Stale Lock
                        eprintln!(
                            "Veraltete Sperre (Stale Lock) von PID {} gefunden und entfernt.",
                            pid_val
                        );
                        // Remove stale lock and create fresh one.
                        let _ = fs::remove_file(storage.get_lock_file_path());
                        let mut file =
                            fs::File::create(storage.get_lock_file_path()).map_err(|e| {
                                StorageError::LockAcquisitionFailed { reason: format!(
                                    "Konnte Lock-Datei nach Bereinigung nicht erstellen: {}",
                                    e
                                )}
                            })?;
                        file.write_all(pid_str.as_bytes())?;
                        return Ok(true);
                    }
                }
                // If we reached here without returning, the lock is in an indeterminate
                // state; try to re-acquire atomically.
                #[cfg(target_arch = "wasm32")]
                {
                    let mut file = fs::File::create(storage.get_lock_file_path()).map_err(|e| {
                        StorageError::LockAcquisitionFailed { reason: format!("Konnte Lock-Datei nicht erstellen: {}", e)}
                    })?;
                    file.write_all(pid_str.as_bytes())?;
                    Ok(true)
                }
            } else {
                // Other I/O error
                Err(StorageError::LockAcquisitionFailed { reason: format!(
                    "Fehler beim Erstellen der Lock-Datei: {}",
                    e
                )})
            }
        }
    }
}

/// Releases the wallet lock.
///
/// Preserves the `FileStorage::unlock` security check: a live foreign lock
/// holder is never removed; stale/unparseable locks are cleaned up so crash
/// recovery keeps working.
pub(crate) fn release_lock(storage: &FileStorage) -> Result<(), StorageError> {
    if storage.get_lock_file_path().exists() {
        // SECURITY: Never remove a lock owned by ANOTHER LIVE process.
        #[cfg(not(target_arch = "wasm32"))]
        if let Ok(pid_str) = fs::read_to_string(storage.get_lock_file_path())
            && let Ok(pid_val) = pid_str.trim().parse::<u32>()
            && pid_val != std::process::id()
        {
            let mut s = System::new();
            s.refresh_processes();
            if s.process(Pid::from_u32(pid_val)).is_some() {
                return Err(StorageError::LockFailed(format!(
                    "Refusing to release wallet lock held by another live process (PID: {}).",
                    pid_val
                )));
            }
        }
        fs::remove_file(storage.get_lock_file_path())?;
    }
    // If the file does not exist, it is also "unlocked".
    Ok(())
}
