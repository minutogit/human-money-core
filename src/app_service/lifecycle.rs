//! # src/app_service/lifecycle.rs
//!
//! Enthält alle Funktionen, die den Lebenszyklus des `AppService` steuern,
//! wie Initialisierung, Login/Logout und Wiederherstellung.

use super::{AppService, AppState, ProfileInfo, AppFacadeError};
use crate::models::seal::{LocalSealRecord, SyncStatus};
use crate::services::seal_manager::SealManager;
use crate::storage::{AuthMethod, Storage, file_storage::FileStorage};
use crate::wallet::Wallet;
use crate::services::mnemonic::MnemonicLanguage;
use crate::services::crypto_utils::{generate_mnemonic, validate_mnemonic_phrase, get_hash};
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

const PROFILES_INDEX_FILE: &str = "profiles.json";

impl AppService {
    // --- Lebenszyklus-Management ---

    /// Initialisiert einen neuen `AppService` im `Locked`-Zustand.
    ///
    /// # Arguments
    /// * `base_storage_path` - Der Pfad zum Basisverzeichnis, in dem alle
    ///   Profil-Unterverzeichnisse und die `profiles.json` gespeichert werden.
    pub fn new(base_storage_path: &Path) -> Result<Self, AppFacadeError> {
        fs::create_dir_all(base_storage_path)
            .map_err(|e| AppFacadeError::StorageError(format!("Failed to create base storage directory: {}", e)))?;
        Ok(AppService {
            base_storage_path: base_storage_path.to_path_buf(),
            state: AppState::Locked,
        })
    }

    /// Returns true if the service is in the `Unlocked` state.
    pub fn is_wallet_unlocked(&self) -> bool {
        matches!(self.state, AppState::Unlocked { .. })
    }

    /// Listet alle verfügbaren, im Basisverzeichnis konfigurierten Profile auf.
    ///
    /// Liest die zentrale `profiles.json`-Datei und gibt eine Liste von `ProfileInfo`-
    /// Objekten zurück, die für die Anzeige in einem Login-Screen verwendet werden kann.
    ///
    /// # Returns
    /// Ein `Result` mit einem Vektor von `ProfileInfo` oder einer Fehlermeldung,
    /// falls die Indexdatei nicht gelesen oder geparst werden kann.
    pub fn list_profiles(&self) -> Result<Vec<ProfileInfo>, AppFacadeError> {
        let index_path = self.base_storage_path.join(PROFILES_INDEX_FILE);
        if !index_path.exists() {
            return Ok(Vec::new()); // Keine Profile vorhanden, kein Fehler.
        }

        let content = fs::read_to_string(index_path)
            .map_err(|e| AppFacadeError::StorageError(format!("Could not read profiles index file: {}", e)))?;
        if content.trim().is_empty() {
            return Ok(Vec::new());
        }

        serde_json::from_str(&content)
            .map_err(|e| AppFacadeError::JsonError(format!("Could not parse profiles index file: {}", e)))
    }

    /// Generiert eine neue BIP-39 Mnemonic-Phrase (Seed-Wörter).
    ///
    /// Diese Methode ist statisch und kann ohne geladenes Wallet aufgerufen werden.
    pub fn generate_mnemonic(word_count: u32, language: MnemonicLanguage) -> Result<String, AppFacadeError> {
        generate_mnemonic(word_count as usize, language)
            .map_err(|e| AppFacadeError::CryptoError(e.to_string()))
    }

    /// Gibt die Wortliste für eine bestimmte Sprache zurück.
    pub fn get_mnemonic_wordlist(language: MnemonicLanguage) -> Vec<&'static str> {
        crate::services::mnemonic::MnemonicProcessor::get_wordlist(language)
    }

    /// Validiert eine vom Benutzer eingegebene BIP-39 Mnemonic-Phrase.
    ///
    /// Diese Methode ist statisch und kann ohne geladenes Wallet aufgerufen werden.
    pub fn validate_mnemonic(mnemonic: &str, language: MnemonicLanguage) -> Result<(), AppFacadeError> {
        validate_mnemonic_phrase(mnemonic, language)
            .map_err(|e| AppFacadeError::CryptoError(e.to_string()))
    }

    /// Erstellt ein komplett neues Benutzerprofil und Wallet und speichert es verschlüsselt.
    ///
    /// Diese Funktion leitet einen anonymen Ordnernamen aus den Secrets ab, speichert
    /// das Wallet in diesem Ordner und fügt einen Eintrag zur zentralen `profiles.json` hinzu.
    /// Bei Erfolg wird der Service in den `Unlocked`-Zustand versetzt.
    ///
    /// # Arguments
    /// * `profile_name` - Der menschenlesbare Name für das neue Profil. Muss eindeutig sein.
    /// * `mnemonic` - Die BIP39 Mnemonic-Phrase zur Generierung der Master-Keys.
    /// * `passphrase` - Eine optionale, zusätzliche Passphrase für die Mnemonic.
    /// * `user_prefix` - Ein optionales Präfix für die `did:key`-basierte User-ID.
    /// * `password` - Das Passwort, mit dem das neue Wallet verschlüsselt wird.
    pub fn create_profile(
        &mut self,
        profile_name: &str,
        mnemonic: &str,
        passphrase: Option<&str>,
        user_prefix: Option<&str>,
        password: &str,
        language: MnemonicLanguage,
        local_instance_id: String,
    ) -> Result<(), AppFacadeError> {
        let mut profiles = self.list_profiles()?;
        if profiles.iter().any(|p| p.profile_name == profile_name) {
            return Err(AppFacadeError::ProfileAlreadyExists(format!(
                "A profile with the name '{}' already exists.",
                profile_name
            )));
        }

        let folder_name = Self::derive_folder_name(mnemonic, passphrase, user_prefix);
        let profile_path = self.base_storage_path.join(&folder_name);

        // --- SECURITY GUARD: Detect bad instance_id storage ---
        self.check_instance_id_trap(&profile_path)?;

        if profile_path.exists() {
            return Err(AppFacadeError::ProfileAlreadyExists(
                "A profile with these secrets already exists (folder collision).".to_string()
            ));
        }

        let mut storage = FileStorage::new(profile_path);

        let (mut wallet, identity) = Wallet::new_from_mnemonic(mnemonic, passphrase, user_prefix, language, local_instance_id.clone())
            .map_err(AppFacadeError::from)?;

        wallet
            .save(&mut storage, &identity, &AuthMethod::Password(password))
            .map_err(AppFacadeError::from)?;

        // --- WALLET SEAL: Initiales Siegel erstellen (Epoch 0) ---
        let state_hash = {
            let canonical = crate::services::utils::to_canonical_json(&wallet.own_fingerprints)
                .map_err(AppFacadeError::from)?;
            get_hash(canonical.as_bytes())
        };
        let initial_seal = SealManager::create_initial_seal(
            &identity.user_id,
            &identity,
            &state_hash,
            &local_instance_id,
        ).map_err(AppFacadeError::from)?;

        let seal_record = LocalSealRecord {
            seal: initial_seal,
            sync_status: SyncStatus::PendingUpload,
            is_locked_due_to_fork: false,
        };
        storage
            .save_seal(&identity.user_id, &AuthMethod::Password(password), &seal_record)
            .map_err(AppFacadeError::from)?;
        // --- WALLET SEAL ENDE ---

        // Sperre erlangen
        storage
            .lock()
            .map_err(AppFacadeError::from)?;

        // Füge das neue Profil zur Indexdatei hinzu
        profiles.push(ProfileInfo {
            profile_name: profile_name.to_string(),
            folder_name,
        });
        let index_path = self.base_storage_path.join(PROFILES_INDEX_FILE);
        let updated_index = serde_json::to_string_pretty(&profiles)
            .map_err(AppFacadeError::from)?;
        fs::write(index_path, updated_index)
            .map_err(AppFacadeError::from)?;

        self.state = AppState::Unlocked {
            storage,
            wallet,
            identity,
            session_cache: None,
        };

        // BUG-FIX: Initialisiere den "Session-Anker".
        let _ = self.save_encrypted_data("__storage_session_anchor", b"init", Some(password));

        // --- INTEGRITY & SEAL UPDATE ---
        // Dies muss NACH allen initialen Schreiboperationen (auch dem Anker) geschehen.
        let _ = self.update_seal_after_state_change(Some(password));

        Ok(())
    }

    /// Entsperrt ein existierendes Wallet und lädt es in den Speicher.
    ///
    /// # Arguments
    /// * `folder_name` - Der anonyme Ordnername des zu ladenden Profils.
    /// * `password` - Das Passwort zum Entschlüsseln des Wallets.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Profil nicht existiert, das Passwort falsch ist oder
    /// die Wallet-Dateien nicht gelesen werden können.
    pub fn login(
        &mut self,
        folder_name: &str,
        password: &str,
        cleanup_on_login: bool,
        local_instance_id: String,
    ) -> Result<(), AppFacadeError> {
        let profile_path = self.base_storage_path.join(folder_name);
        if !profile_path.exists() {
            return Err(AppFacadeError::ProfileNotFound("Profile directory not found.".to_string()));
        }

        // --- SECURITY GUARD: Detect bad instance_id storage ---
        self.check_instance_id_trap(&profile_path)?;

        let mut storage = FileStorage::new(profile_path);

        // --- WALLET SEAL: Siegel laden und ROHEN State-Hash verifizieren ---
        let needs_legacy_binding = Self::verify_seal_on_login(&storage, password, &local_instance_id)
            .map_err(AppFacadeError::from)?;
        // --- WALLET SEAL: Pre-Check ENDE ---

        let (mut wallet, identity) = Wallet::load(&storage, &AuthMethod::Password(password), local_instance_id)
            .map_err(|e| AppFacadeError::CryptoError(format!("Login failed (check password): {}", e)))?;

        // --- EVENT FLUSH ---
        if !wallet.pending_events.is_empty() {
            wallet
                .save(&mut storage, &identity, &AuthMethod::Password(password))
                .map_err(AppFacadeError::from)?;
        }

        if cleanup_on_login {
            // Bevor wir aufräumen, prüfen wir die Integrität.
            let auth = AuthMethod::Password(password);
            let integrity_record = storage.load_integrity("").unwrap_or(None);
            let seal_record = storage.load_seal(&identity.user_id, &auth).unwrap_or(None);
            let hashes = storage.get_all_item_hashes().unwrap_or_default();

            let is_valid = match (integrity_record, seal_record) {
                (Some(ir), Some(ref s)) => {
                    matches!(
                        crate::services::integrity_manager::IntegrityManager::verify_integrity(&ir, &s.seal, hashes, &identity.user_id),
                        Ok(crate::models::storage_integrity::IntegrityReport::Valid)
                    )
                }
                (None, _) => true, // Migration: wir erlauben Cleanup.
                _ => false,
            };

            if is_valid {
                let report = wallet
                    .run_storage_cleanup(None, super::DEFAULT_ARCHIVE_GRACE_PERIOD_YEARS)
                    .map_err(AppFacadeError::from)?;
                
                if report.expired_fingerprints_removed > 0 
                    || report.limit_based_fingerprints_removed > 0 
                    || report.archived_items_removed > 0 
                {
                    wallet
                        .save(&mut storage, &identity, &auth)
                        .map_err(AppFacadeError::from)?;
                    
                    let new_hashes = storage.get_all_item_hashes().unwrap_or_default();
                    let seal = storage.load_seal(&identity.user_id, &auth).unwrap_or(None).map(|s| s.seal);
                    if let Some(s) = seal {
                        if let Ok(ir) = crate::services::integrity_manager::IntegrityManager::create_integrity_record(&identity, &s, new_hashes) {
                            let _ = storage.save_integrity(&identity.user_id, &ir);
                        }
                    }
                }
            } else {
                eprintln!("Skipping storage cleanup during login because integrity is compromised.");
            }
        }

        // --- WALLET SEAL: Migration für bestehende Wallets ohne Siegel oder ohne InstanceID ---
        Self::migrate_seal_on_login(&mut storage, &wallet, &identity, password, needs_legacy_binding)
            .map_err(AppFacadeError::from)?;
        // --- WALLET SEAL ENDE ---

        // Sperre erlangen
        storage
            .lock()
            .map_err(AppFacadeError::from)?;

        self.state = AppState::Unlocked {
            storage,
            wallet,
            identity,
            session_cache: None,
        };

        // BUG-FIX: Initialisiere den "Session-Anker". (Siehe create_profile)
        // Dies stellt sicher, dass Modus A / Modus B Operationen nach einem
        // Login funktionieren.
        let _ = self.save_encrypted_data("__storage_session_anchor", b"init", Some(password));

        Ok(())
    }

    /// Stellt ein Wallet mit der Mnemonic-Phrase wieder her und setzt ein neues Passwort.
    ///
    /// # Arguments
    /// * `folder_name` - Der anonyme Ordnername des wiederherzustellenden Profils.
    /// * `mnemonic` - Die Mnemonic-Phrase zur Wiederherstellung des Wallets.
    /// * `passphrase` - Die optionale Passphrase, die bei der Erstellung verwendet wurde.
    /// * `new_password` - Das neue Passwort, mit dem das Wallet verschlüsselt werden soll.
    pub fn recover_wallet_and_set_new_password(
        &mut self,
        folder_name: &str,
        mnemonic: &str,
        passphrase: Option<&str>,
        new_password: &str,
        language: MnemonicLanguage,
        local_instance_id: String,
    ) -> Result<(), AppFacadeError> {
        let profile_path = self.base_storage_path.join(folder_name);
        if !profile_path.exists() {
            return Err(AppFacadeError::ProfileNotFound("Profile directory not found.".to_string()));
        }

        // --- SECURITY GUARD: Detect bad instance_id storage ---
        self.check_instance_id_trap(&profile_path)?;

        let mut storage = FileStorage::new(profile_path);

        // 1. Lade das Wallet mit der Mnemonic-Phrase (öffnet das "zweite Schloss").
        let auth_method = AuthMethod::Mnemonic(mnemonic, passphrase, language);
        let (mut wallet, identity) = Wallet::load(&storage, &auth_method, local_instance_id.clone()).map_err(|e| {
            AppFacadeError::CryptoError(format!(
                "Recovery failed (check mnemonic phrase and passphrase): {}",
                e
            ))
        })?;

        // --- EVENT FLUSH ---
        if !wallet.pending_events.is_empty() {
            // Hinweis: Wir nutzen hier noch die Mnemonic-Auth, da das neue Passwort 
            // erst im nächsten Schritt gesetzt wird.
            wallet
                .save(&mut storage, &identity, &auth_method)
                .map_err(AppFacadeError::from)?;
        }

        // 2. Setze das Passwort zurück, indem das Mnemonic-Schloss geöffnet und das Passwort-Schloss neu geschrieben wird.
        Wallet::reset_password(&mut storage, &identity, new_password)
            .map_err(AppFacadeError::from)?;

        // --- WALLET SEAL: Neue Epoche einleiten (Recovery) ---
        {
            let auth_for_seal = AuthMethod::Password(new_password);
            let existing_seal = storage
                .load_seal(&identity.user_id, &auth_for_seal)
                .ok()
                .flatten();

            let current_state_hash = {
                let canonical = crate::services::utils::to_canonical_json(&wallet.own_fingerprints)
                    .map_err(AppFacadeError::from)?;
                get_hash(canonical.as_bytes())
            };

            let recovered_seal = SealManager::recover_seal_epoch(
                existing_seal.as_ref().map(|r| &r.seal),
                &identity.user_id,
                &identity,
                &current_state_hash,
                &local_instance_id,
            ).map_err(AppFacadeError::from)?;

            let new_record = LocalSealRecord {
                seal: recovered_seal,
                sync_status: SyncStatus::PendingUpload,
                is_locked_due_to_fork: false, // Recovery hebt den Fork-Lock auf!
            };
            storage
                .save_seal(&identity.user_id, &auth_for_seal, &new_record)
                .map_err(AppFacadeError::from)?;

            // --- INTEGRITY UPDATE ---
            // Nach der Wiederherstellung des Siegels müssen wir den Integrity Record aktualisieren,
            // da sich seal.enc geändert hat. Sonst warnt der nächste Login vor Manipulation.
            let item_hashes = storage.get_all_item_hashes().map_err(AppFacadeError::from)?;
            let integrity_record = crate::services::integrity_manager::IntegrityManager::create_integrity_record(
                &identity,
                &new_record.seal,
                item_hashes,
            ).map_err(AppFacadeError::from)?;

            storage
                .save_integrity(&identity.user_id, &integrity_record)
                .map_err(AppFacadeError::from)?;
        }
        // --- WALLET SEAL ENDE ---

        // Sperre erlangen
        storage
            .lock()
            .map_err(AppFacadeError::from)?;

        self.state = AppState::Unlocked {
            storage,
            wallet,
            identity,
            session_cache: None,
        };

        Ok(())
    }

    /// Sperrt das Wallet und entfernt sensible Daten (privater Schlüssel, Session Key) aus dem Speicher.
    ///
    /// Setzt den Zustand zurück auf `Locked`. Diese Operation kann nicht fehlschlagen.
    pub fn logout(&mut self) {
        if let AppState::Unlocked { storage, .. } = &self.state {
            let _ = storage.unlock(); // Ignoriere Fehler beim Unlock
        }
        self.state = AppState::Locked;
    }

    /// Aktiviert die "Passwort merken"-Funktion für eine bestimmte Dauer (in Sekunden).
    ///
    /// Verifiziert das Passwort, leitet den Speicherschlüssel ab und hält diesen im Speicher.
    /// Dies ist die Voraussetzung, um Aktionen ohne erneute Passworteingabe durchzuführen.
    ///
    /// # Arguments
    /// * `password` - Das Passwort zur Verifizierung und Key-Ableitung.
    /// * `duration_seconds` - Die Dauer der Sitzung in Sekunden.
    pub fn unlock_session(&mut self, password: &str, duration_seconds: u64) -> Result<(), AppFacadeError> {
        match &mut self.state {
            AppState::Unlocked {
                storage,
                wallet: _,
                identity: _,
                session_cache,
            } => {
                // Verifiziere das Passwort, indem wir versuchen, den Session-Key abzuleiten
                let session_key = storage.derive_key_for_session(password)
                    .map_err(AppFacadeError::from)?;

                // Teste, ob der abgeleitete Schlüssel gültig ist, indem wir ihn verwenden,
                // um den verschlüsselten Dateischlüssel zu entschlüsseln.
                // Dies validiert, dass das Passwort korrekt war.
                storage
                    .test_session_key(&session_key)
                    .map_err(AppFacadeError::from)?;

                // Erstelle den Session-Cache
                *session_cache = Some(super::SessionCache {
                    session_key,
                    session_duration: Duration::from_secs(duration_seconds),
                    last_activity: Instant::now(),
                });

                Ok(())
            }
            AppState::Locked => Err(AppFacadeError::WalletLocked("Wallet is locked. Please login first.".to_string())),
        }
    }

    /// Deaktiviert die "Passwort merken"-Funktion sofort und löscht den zwischengespeicherten Speicherschlüssel aus dem RAM.
    ///
    /// Der `AppService` bleibt `Unlocked` (Lesezugriff geht), aber Aktionen erfordern nun `unlock_session` oder `password`-Argument.
    pub fn lock_session(&mut self) {
        if let AppState::Unlocked { session_cache, .. } = &mut self.state {
            *session_cache = None;
        }
    }

    /// Setzt den Inaktivitäts-Timer der "Passwort merken"-Sitzung zurück.
    ///
    /// Ideal, um dies bei UI-Aktivität (Klicks, Mausbewegung) aufzurufen, damit die Sitzung nicht abläuft, während der Benutzer aktiv ist.
    ///
    /// # Returns
    /// * `Ok(())` - Wenn die Session aktiv war und erfolgreich verlängert wurde.
    /// * `Err(String)` - Wenn die Session bereits abgelaufen war (wird gesperrt), keine Session aktiv ist oder das Wallet gesperrt ist.
    pub fn refresh_session_activity(&mut self) -> Result<(), AppFacadeError> {
        if let AppState::Unlocked { session_cache, .. } = &mut self.state {
            // Prüfen, ob überhaupt eine Session existiert
            if let Some(cache) = session_cache {
                // BUGFIX: Validieren, ob die Session physisch abgelaufen ist
                if cache.last_activity.elapsed() > cache.session_duration {
                    // Session ist abgelaufen: Cache löschen und Fehler zurückgeben
                    *session_cache = None;
                    return Err(AppFacadeError::SessionExpired("Session expired.".to_string()));
                } else {
                    // Session gültig: Timer erneuern.
                    cache.last_activity = Instant::now();
                    return Ok(());
                }
            }
            return Err(AppFacadeError::SessionNotActive("No active session to refresh.".to_string()));
        }
        Err(AppFacadeError::WalletLocked("Wallet is locked.".to_string()))
    }

    /// Erzwingt die Bindung des Wallets an das aktuelle Gerät (Handover).
    /// Dies wird aufgerufen, wenn der Login aufgrund eines `DeviceMismatch` fehlschlägt.
    pub fn handover_to_this_device(
        &mut self,
        folder_name: &str,
        password: &str,
        local_instance_id: String,
    ) -> Result<(), AppFacadeError> {
        let profile_path = self.base_storage_path.join(folder_name);
        if !profile_path.exists() {
            return Err(AppFacadeError::ProfileNotFound("Profile directory not found.".to_string()));
        }

        let mut storage = FileStorage::new(profile_path);
        let auth = AuthMethod::Password(password);

        // 1. Wallet laden
        let (mut wallet, identity) = Wallet::load(&storage, &auth, local_instance_id)
            .map_err(|e| AppFacadeError::CryptoError(format!("Loading for handover failed: {}", e)))?;

        // 2. Handover durchführen
        let new_seal = wallet.force_device_handover(&mut storage, &identity, &auth)
            .map_err(AppFacadeError::from)?;

        // --- INTEGRITY UPDATE ---
        let item_hashes = storage.get_all_item_hashes().map_err(AppFacadeError::from)?;
        let integrity_record = crate::services::integrity_manager::IntegrityManager::create_integrity_record(
            &identity,
            &new_seal,
            item_hashes,
        ).map_err(AppFacadeError::from)?;

        storage
            .save_integrity(&identity.user_id, &integrity_record)
            .map_err(AppFacadeError::from)?;

        // 3. Login durchführen
        storage.lock().map_err(AppFacadeError::from)?;
        
        self.state = AppState::Unlocked {
            storage,
            wallet,
            identity,
            session_cache: None,
        };

        Ok(())
    }

    /// Prüft, ob der App-Entwickler die `instance_id` unsicher als Datei gespeichert hat.
    /// Klettert auch eine Ebene nach oben, um typische Tauri/Electron AppData-Ordner zu erwischen.
    fn check_instance_id_trap(&self, profile_path: &Path) -> Result<(), AppFacadeError> {
        let mut bad_paths = vec![
            self.base_storage_path.join("instance_id"),
            profile_path.join("instance_id"),
        ];

        // Prüfe auch das übergeordnete Verzeichnis (Parent)
        if let Some(parent) = self.base_storage_path.parent() {
            bad_paths.push(parent.join("instance_id"));
        }

        for path in bad_paths {
            if path.exists() {
                return Err(AppFacadeError::Generic(
                    "CRITICAL SECURITY VIOLATION: The App Developer has stored the 'instance_id' inside the application data directory. \
                    This defeats the cloning protection! The instance_id MUST be stored securely in the OS Keyring or a separate isolated Config directory. \
                    Execution halted to protect user funds.".to_string()
                ));
            }
        }
        Ok(())
    }

    /// Löscht ein Benutzerprofil dauerhaft vom Gerät.
    /// Erfordert das Passwort zur Bestätigung.
    pub fn delete_profile(&mut self, folder_name: &str, password: &str) -> Result<(), AppFacadeError> {
        let profile_path = self.base_storage_path.join(folder_name);
        if !profile_path.exists() {
            return Err(AppFacadeError::ProfileNotFound("Profile directory not found.".to_string()));
        }

        // 1. Passwort verifizieren
        // Wir nutzen eine temporäre Instanz von FileStorage, um zu prüfen, ob wir das Wallet laden können.
        let storage = FileStorage::new(profile_path.clone());
        let auth = AuthMethod::Password(password);
        
        // Versuche das Wallet zu laden, um das Passwort zu prüfen.
        // Die instance_id ist hier zweitrangig für den bloßen Passwort-Check, 
        // wir nutzen einen Platzhalter um DeviceMismatch-Checks zu umgehen falls möglich,
        // aber Wallet::load() selbst macht keine Seal-Prüfung (das macht nur AppService::login).
        let _ = Wallet::load(&storage, &auth, "password_check".to_string())
            .map_err(|e| AppFacadeError::CryptoError(format!("Password verification failed (check password): {}", e)))?;

        // 2. Profil aus dem Index (profiles.json) entfernen
        let mut profiles = self.list_profiles()?;
        let original_len = profiles.len();
        profiles.retain(|p| p.folder_name != folder_name);
        
        if profiles.len() == original_len {
             return Err(AppFacadeError::ProfileNotFound("Profile not found in index.".to_string()));
        }

        let index_path = self.base_storage_path.join(PROFILES_INDEX_FILE);
        let updated_index = serde_json::to_string_pretty(&profiles)
            .map_err(AppFacadeError::from)?;
        fs::write(index_path, updated_index)
            .map_err(AppFacadeError::from)?;

        // 3. Verzeichnis physisch löschen
        fs::remove_dir_all(profile_path)
            .map_err(AppFacadeError::from)?;

        Ok(())
    }

    /// Verifiziert das Passwort eines Profils und gibt die User-ID (DID) zurück.
    /// Nützlich für Sicherheits-Bestätigungen vor kritischen Aktionen (wie Löschen).
    pub fn get_profile_id_with_password(&self, folder_name: &str, password: &str) -> Result<String, AppFacadeError> {
        let profile_path = self.base_storage_path.join(folder_name);
        if !profile_path.exists() {
            return Err(AppFacadeError::ProfileNotFound("Profile directory not found.".to_string()));
        }

        let storage = FileStorage::new(profile_path);
        let auth = AuthMethod::Password(password);
        
        // Versuche das Wallet zu laden, um die Identität zu erhalten.
        let (_, identity) = Wallet::load(&storage, &auth, "password_check".to_string())
            .map_err(|e| AppFacadeError::CryptoError(format!("Password verification failed: {}", e)))?;

        Ok(identity.user_id.clone())
    }
}


