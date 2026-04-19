//! # src/storage/mod.rs
//!
//! Definiert die Abstraktion für die persistente Speicherung von Wallet-Daten.
//! Dies ermöglicht es, die Kernlogik von der konkreten Speichermethode zu entkoppeln.

use crate::models::conflict::{
    CanonicalMetadataStore, KnownFingerprints, OwnFingerprints, ProofStore,
};
use crate::models::profile::{BundleMetadataStore, UserIdentity, UserProfile, VoucherStore};
pub mod file_storage;
use thiserror::Error;

/// Ein generischer Fehler-Typ für alle Speicheroperationen.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Authentication failed: Invalid password or recovery identity.")]
    AuthenticationFailed,

    #[error("Data not found for the given identifier.")]
    NotFound,

    #[error("Data is corrupted or has an invalid format: {0}")]
    InvalidFormat(String),

    #[error("Underlying I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("An unexpected error occurred: {0}")]
    Generic(String),

    #[error("Wallet-Sperre fehlgeschlagen: {0}")]
    LockFailed(String),

    #[error("Veraltete Sperre (Stale Lock) gefunden und entfernt: {0}")]
    StaleLock(String),
}

/// Authentifizierungsmethode für den Speicherzugriff
pub enum AuthMethod<'a> {
    /// Das Passwort des Benutzers (wird zur Key-Ableitung verwendet)
    Password(&'a str),
    /// Ein bereits abgeleiteter Session-Key (überspringt die Key-Ableitung)
    SessionKey([u8; 32]),
    /// Authentifizierung mittels einer Mnemonic-Phrase (für die Wiederherstellung).
    Mnemonic(&'a str, Option<&'a str>, crate::services::mnemonic::MnemonicLanguage),
    /// Authentifizierung mittels der kryptographischen Identität (für die Wiederherstellung).
    RecoveryIdentity(&'a UserIdentity),
}

impl<'a> AuthMethod<'a> {
    /// Extrahiert das Passwort als `&str`, wenn die Methode `Password` ist.
    pub fn get_password(&self) -> Result<&'a str, StorageError> {
        match self {
            AuthMethod::Password(p) => Ok(p),
            _ => Err(StorageError::Generic(
                "Password not available for this auth method".to_string(),
            )),
        }
    }

    /// Extrahiert den Session-Key, wenn die Methode `SessionKey` ist.
    pub fn get_session_key(&self) -> Result<[u8; 32], StorageError> {
        match self {
            AuthMethod::SessionKey(key) => Ok(*key),
            _ => Err(StorageError::Generic(
                "Session key not available for this auth method".to_string(),
            )),
        }
    }
}

/// Die Schnittstelle für persistente Speicherung.
/// Jede Methode ist eine atomare Operation für ein komplettes Wallet.
pub trait Storage {
    /// Leitet den Speicherschlüssel (SessionKey) aus dem Passwort ab.
    fn derive_key_for_session(&self, password: &str) -> Result<[u8; 32], StorageError>;

    /// Lädt und entschlüsselt das Kern-Wallet (Profil und VoucherStore).
    fn load_wallet(
        &self,
        auth: &AuthMethod,
    ) -> Result<(UserProfile, VoucherStore, UserIdentity), StorageError>;

    /// Speichert und verschlüsselt das Kern-Wallet (Profil und VoucherStore).
    /// Muss auch die `UserIdentity` erhalten, um beim ersten Speichern den Wiederherstellungs-Schlüssel zu erstellen.
    fn save_wallet(
        &mut self,
        profile: &UserProfile,
        store: &VoucherStore,
        identity: &UserIdentity,
        auth: &AuthMethod,
    ) -> Result<(), StorageError>;

    /// Setzt das Passwort zurück, indem es das Passwort-Schloss mit dem Wiederherstellungs-Schlüssel neu erstellt.
    fn reset_password(
        &mut self,
        identity: &UserIdentity,
        new_password: &str,
    ) -> Result<(), StorageError>;

    /// Prüft, ob bereits ein Profil am Speicherort existiert.
    fn profile_exists(&self) -> bool;

    /// Lädt und entschlüsselt den `KnownFingerprints`-Store.
    fn load_known_fingerprints(
        &self,
        user_id: &str,
        auth: &AuthMethod,
    ) -> Result<KnownFingerprints, StorageError>;

    /// Speichert und verschlüsselt den `KnownFingerprints`-Store.
    fn save_known_fingerprints(
        &mut self,
        user_id: &str,
        auth: &AuthMethod,
        fingerprints: &KnownFingerprints,
    ) -> Result<(), StorageError>;

    /// Lädt und entschlüsselt den kritischen `OwnFingerprints`-Store.
    fn load_own_fingerprints(
        &self,
        user_id: &str,
        auth: &AuthMethod,
    ) -> Result<OwnFingerprints, StorageError>;

    /// Speichert und verschlüsselt den kritischen `OwnFingerprints`-Store.
    fn save_own_fingerprints(
        &mut self,
        user_id: &str,
        auth: &AuthMethod,
        fingerprints: &OwnFingerprints,
    ) -> Result<(), StorageError>;

    /// Lädt und entschlüsselt die Metadaten der Transaktionsbündel.
    fn load_bundle_metadata(
        &self,
        user_id: &str,
        auth: &AuthMethod,
    ) -> Result<BundleMetadataStore, StorageError>;

    /// Speichert und verschlüsselt die Metadaten der Transaktionsbündel.
    fn save_bundle_metadata(
        &mut self,
        user_id: &str,
        auth: &AuthMethod,
        metadata: &BundleMetadataStore,
    ) -> Result<(), StorageError>;

    /// Lädt und entschlüsselt den ProofStore.
    fn load_proofs(&self, user_id: &str, auth: &AuthMethod) -> Result<ProofStore, StorageError>;

    /// Speichert und verschlüsselt den ProofStore.
    fn save_proofs(
        &mut self,
        user_id: &str,
        auth: &AuthMethod,
        proof_store: &ProofStore,
    ) -> Result<(), StorageError>;

    /// Lädt den kanonischen Speicher für Fingerprint-Metadaten.
    fn load_fingerprint_metadata(
        &self,
        user_id: &str,
        auth: &AuthMethod,
    ) -> Result<CanonicalMetadataStore, StorageError>;

    /// Speichert den kanonischen Speicher für Fingerprint-Metadaten.
    fn save_fingerprint_metadata(
        &mut self,
        user_id: &str,
        auth: &AuthMethod,
        metadata: &CanonicalMetadataStore,
    ) -> Result<(), StorageError>;

    /// Speichert einen beliebigen, benannten Datenblock verschlüsselt.
    ///
    /// Diese Funktion ermöglicht es der Anwendung, eigene Daten sicher im Kontext des
    /// Wallets zu speichern, ohne eigene Schlüssel verwalten zu müssen.
    ///
    /// # Arguments
    /// * `user_id` - Die ID des Benutzers, dem die Daten zugeordnet sind.
    /// * `auth` - Die Authentifizierungsmethode zum Verschlüsseln.
    /// * `name` - Ein eindeutiger Name für den Datenblock (z.B. "app_settings").
    /// * `data` - Die zu verschlüsselnden Rohdaten.
    fn save_arbitrary_data(
        &mut self,
        user_id: &str,
        auth: &AuthMethod,
        name: &str,
        data: &[u8],
    ) -> Result<(), StorageError>;

    /// Lädt einen beliebigen, benannten und verschlüsselten Datenblock.
    ///
    /// # Arguments
    /// * `user_id` - Die ID des Benutzers, dem die Daten zugeordnet sind.
    /// * `auth` - Die Authentifizierungsmethode zum Entschlüsseln.
    /// * `name` - Der Name des zu ladenden Datenblocks.
    fn load_arbitrary_data(
        &self,
        user_id: &str,
        auth: &AuthMethod,
        name: &str,
    ) -> Result<Vec<u8>, StorageError>;

    /// Überprüft, ob ein abgeleiteter Session-Key gültig ist, indem versucht wird,
    /// damit auf verschlüsselte Daten zuzugreifen.
    fn test_session_key(&self, session_key: &[u8; 32]) -> Result<(), StorageError>;

    /// Versucht, eine exklusive, prozessweite Sperre für den Wallet-Speicher zu erlangen.
    /// Muss die "Stale Lock"-Prüfung (z.B. PID) implementieren.
    ///
    /// Gibt `Ok(())` zurück, wenn die Sperre erfolgreich erlangt wurde.
    /// Gibt `Err(StorageError::LockFailed)` zurück, wenn die Sperre aktiv von einem
    /// *anderen lebenden* Prozess gehalten wird.
    fn lock(&self) -> Result<(), StorageError>;

    /// Gibt die exklusive Sperre wieder frei.
    /// Diese Methode sollte nur bei einem sauberen Logout aufgerufen werden.
    /// Für Operationen sollte der `WalletLockGuard` verwendet werden.
    fn unlock(&self) -> Result<(), StorageError>;

    /// Gibt den Pfad zur Sperrdatei zurück (für den RAII Guard).
    fn get_lock_file_path(&self) -> &std::path::PathBuf;
}

// --- RAII Lock Guard ---

/// Ein RAII-Guard, der sicherstellt, dass eine Sperre automatisch
/// freigegeben wird, wenn der Guard aus dem Geltungsbereich (Scope) fällt.
///
/// Dieser Guard sollte für *transaktionale* Operationen wie `create_transfer_bundle`
/// oder `receive_bundle` verwendet werden.
pub struct WalletLockGuard {
    lock_file_path: std::path::PathBuf,
}

impl WalletLockGuard {
    /// Erstellt einen neuen Guard und versucht sofort, die Sperre zu erlangen.
    pub fn new(storage: &dyn Storage) -> Result<Self, StorageError> {
        storage.lock()?; // Sperre beim Erstellen erlangen
        let lock_file_path = storage.get_lock_file_path().clone();
        Ok(Self { lock_file_path })
    }
}

/// Wird automatisch aufgerufen, wenn die Variable `_lock_guard` den Scope verlässt.
impl Drop for WalletLockGuard {
    fn drop(&mut self) {
        use std::fs;
        if self.lock_file_path.exists() {
            if let Err(e) = fs::remove_file(&self.lock_file_path) {
                // WICHTIG: In `drop` niemals paniken!
                eprintln!(
                    "Schwerwiegender Fehler: Wallet-Sperre konnte nicht freigegeben werden: {:?}",
                    e
                );
            }
        }
    }
}
