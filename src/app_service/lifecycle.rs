//! # src/app_service/lifecycle.rs
//!
//! Enthält alle Funktionen, die den Lebenszyklus des `AppService` steuern,
//! wie Initialisierung, Login/Logout und Wiederherstellung.

use super::{AppService, AppState, ProfileInfo};
use crate::models::seal::{LocalSealRecord, SyncStatus};
use crate::services::seal_manager::SealManager;
use crate::storage::{AuthMethod, Storage, file_storage::FileStorage};
use crate::wallet::Wallet;
use crate::services::mnemonic::MnemonicLanguage;
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
    pub fn new(base_storage_path: &Path) -> Result<Self, String> {
        fs::create_dir_all(base_storage_path)
            .map_err(|e| format!("Failed to create base storage directory: {}", e))?;
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
    pub fn list_profiles(&self) -> Result<Vec<ProfileInfo>, String> {
        let index_path = self.base_storage_path.join(PROFILES_INDEX_FILE);
        if !index_path.exists() {
            return Ok(Vec::new()); // Keine Profile vorhanden, kein Fehler.
        }

        let content = fs::read_to_string(index_path)
            .map_err(|e| format!("Could not read profiles index file: {}", e))?;
        if content.trim().is_empty() {
            return Ok(Vec::new());
        }

        serde_json::from_str(&content)
            .map_err(|e| format!("Could not parse profiles index file: {}", e))
    }

    /// Generiert eine neue BIP-39 Mnemonic-Phrase (Seed-Wörter).
    ///
    /// Diese Methode ist statisch und kann ohne geladenes Wallet aufgerufen werden.
    pub fn generate_mnemonic(word_count: u32, language: MnemonicLanguage) -> Result<String, String> {
        crate::services::crypto_utils::generate_mnemonic(word_count as usize, language)
            .map_err(|e| e.to_string())
    }

    /// Gibt die Wortliste für eine bestimmte Sprache zurück.
    pub fn get_mnemonic_wordlist(language: MnemonicLanguage) -> Vec<&'static str> {
        crate::services::mnemonic::MnemonicProcessor::get_wordlist(language)
    }

    /// Validiert eine vom Benutzer eingegebene BIP-39 Mnemonic-Phrase.
    ///
    /// Diese Methode ist statisch und kann ohne geladenes Wallet aufgerufen werden.
    pub fn validate_mnemonic(mnemonic: &str, language: MnemonicLanguage) -> Result<(), String> {
        crate::services::crypto_utils::validate_mnemonic_phrase(mnemonic, language)
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
    ) -> Result<(), String> {
        let mut profiles = self.list_profiles()?;
        if profiles.iter().any(|p| p.profile_name == profile_name) {
            return Err(format!(
                "A profile with the name '{}' already exists.",
                profile_name
            ));
        }

        let folder_name = Self::derive_folder_name(mnemonic, passphrase, user_prefix);
        let profile_path = self.base_storage_path.join(&folder_name);

        // --- SECURITY GUARD: Detect bad instance_id storage ---
        self.check_instance_id_trap(&profile_path)?;

        if profile_path.exists() {
            return Err(
                "A profile with these secrets already exists (folder collision).".to_string(),
            );
        }

        let mut storage = FileStorage::new(profile_path);

        let (wallet, identity) = Wallet::new_from_mnemonic(mnemonic, passphrase, user_prefix, language, local_instance_id.clone())
            .map_err(|e| format!("Failed to create new wallet: {}", e))?;

        wallet
            .save(&mut storage, &identity, &AuthMethod::Password(password))
            .map_err(|e| format!("Failed to save new wallet: {}", e))?;

        // --- WALLET SEAL: Initiales Siegel erstellen (Epoch 0) ---
        let state_hash = {
            let canonical = crate::services::utils::to_canonical_json(&wallet.own_fingerprints)
                .map_err(|e| format!("Failed to compute state hash: {}", e))?;
            crate::services::crypto_utils::get_hash(canonical.as_bytes())
        };
        let initial_seal = SealManager::create_initial_seal(
            &identity.user_id,
            &identity,
            &state_hash,
            &local_instance_id,
        ).map_err(|e| format!("Failed to create initial wallet seal: {}", e))?;

        let seal_record = LocalSealRecord {
            seal: initial_seal,
            sync_status: SyncStatus::PendingUpload,
            is_locked_due_to_fork: false,
        };
        storage
            .save_seal(&identity.user_id, &AuthMethod::Password(password), &seal_record)
            .map_err(|e| format!("Failed to save initial wallet seal: {}", e))?;
        // --- WALLET SEAL ENDE ---

        // Sperre erlangen
        storage
            .lock()
            .map_err(|e| format!("Failed to lock wallet: {}", e))?;

        // Füge das neue Profil zur Indexdatei hinzu
        profiles.push(ProfileInfo {
            profile_name: profile_name.to_string(),
            folder_name,
        });
        let index_path = self.base_storage_path.join(PROFILES_INDEX_FILE);
        let updated_index = serde_json::to_string_pretty(&profiles)
            .map_err(|e| format!("Failed to serialize profile index: {}", e))?;
        fs::write(index_path, updated_index)
            .map_err(|e| format!("Failed to write profile index file: {}", e))?;

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
    ) -> Result<(), String> {
        let profile_path = self.base_storage_path.join(folder_name);
        if !profile_path.exists() {
            return Err("Profile directory not found.".to_string());
        }

        // --- SECURITY GUARD: Detect bad instance_id storage ---
        self.check_instance_id_trap(&profile_path)?;

        let mut storage = FileStorage::new(profile_path);
        let mut needs_legacy_binding = false;

        // --- WALLET SEAL: Siegel laden und ROHEN State-Hash verifizieren ---
        // WICHTIG: Die Verifikation erfolgt VOR Wallet::load(), da load()
        // intern rebuild_derived_stores() aufruft, was own_fingerprints
        // aus dem VoucherStore neu aufbaut. Dabei kann sich die Vec-Reihenfolge
        // ändern (HashMap-Iterationsreihenfolge), was den Hash verfälscht.
        // Wir prüfen stattdessen gegen den unveränderten, gespeicherten Zustand.
        {
            let auth = AuthMethod::Password(password);
            let seal_record = storage
                .load_seal("", &auth)
                .ok()
                .flatten();

            if let Some(record) = &seal_record {
                // Fork-Lock prüfen
                if record.is_locked_due_to_fork {
                    return Err("Security Lockdown: Wallet is locked due to a detected fork. Recovery required.".to_string());
                }

                // Siegel-Integrität und Instance-ID prüfen
                let validation = SealManager::verify_seal_integrity(&record.seal, &record.seal.payload.user_id, &record.seal.payload.user_id, &local_instance_id)
                    .map_err(|e| format!("Seal verification error: {}", e))?;

                match validation {
                    crate::models::seal::SealValidationResult::Valid => {},
                    crate::models::seal::SealValidationResult::LegacyValid => {
                        println!("Legacy Wallet detected. Will bind to this device after login.");
                        needs_legacy_binding = true;
                    },
                    crate::models::seal::SealValidationResult::DeviceMismatch { expected, actual } => {
                        let err_msg = format!(
                            "Device Mismatch: This wallet is bound to device '{}', but you are on '{}'. \
                            To prevent double-spending and permanent reputation loss, a wallet profile (specific User Prefix) \
                            must only be active on ONE device at a time.\n\n\
                            - OPTION A (Move): Perform a 'Device Handover' to permanently move the wallet here. \
                            IMPORTANT: Once handed over, you MUST NOT use this profile on the old device anymore. Please delete the wallet folder on the old device to prevent accidental usage.\n\
                            - OPTION B (Concurrent): Create a NEW profile on this device \
                            with the same Seed Phrase but a DIFFERENT 'User Prefix', then transfer vouchers between them.",
                            expected, actual
                        );
                        return Err(err_msg);
                    },
                    other => {
                        return Err(format!("Seal integrity check failed: {:?}", other));
                    },
                }

                // Lade den ROHEN own_fingerprints Store direkt aus dem Storage
                // (vor dem Rebuild durch Wallet::load)
                let raw_own_fingerprints = storage
                    .load_own_fingerprints("", &auth)
                    .map_err(|e| format!("Failed to load own_fingerprints for seal check: {}", e))?;

                let current_state_hash = {
                    let canonical = crate::services::utils::to_canonical_json(&raw_own_fingerprints)
                        .map_err(|e| format!("Failed to compute state hash: {}", e))?;
                    crate::services::crypto_utils::get_hash(canonical.as_bytes())
                };

                if record.seal.payload.state_hash != current_state_hash {
                    return Err("Critical Error: Wallet state does not match the security seal. Possible rollback or corruption detected. Recovery required.".to_string());
                }
            }
        }
        // --- WALLET SEAL: Pre-Check ENDE ---

        let (mut wallet, identity) = Wallet::load(&storage, &AuthMethod::Password(password), local_instance_id)
            .map_err(|e| format!("Login failed (check password): {}", e))?;

        if cleanup_on_login {
            // Bevor wir aufräumen, prüfen wir die Integrität. Wir dürfen die Dateien nur neu
            // schreiben (was ihre Hashes durch neue Verschlüsselungs-Nonces ändert),
            // wenn der aktuelle Zustand der Festplatte intakt ist. Sonst würden wir
            // bestehende Manipulationen/Löschungen überschreiben und maskieren!
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
                    .map_err(|e| format!("Storage cleanup on login failed: {}", e))?;
                
                if report.expired_fingerprints_removed > 0 
                    || report.limit_based_fingerprints_removed > 0 
                    || report.archived_items_removed > 0 
                {
                    wallet
                        .save(&mut storage, &identity, &auth)
                        .map_err(|e| format!("Failed to save wallet after cleanup: {}", e))?;
                    
                    // Da wir die Wallet-Dateien neu geschrieben haben (neue Nonces = neue Hashes),
                    // MÜSSEN wir jetzt zwingend den IntegrityRecord updaten, damit der nächste Check nicht
                    // sofort ManipulatedItems meldet. Da wir vorher geprüft haben, dass alles OK war,
                    // ist das sicher.
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
        {
            let auth = AuthMethod::Password(password);
            let seal_record = storage
                .load_seal(&identity.user_id, &auth)
                .map_err(|e| format!("Failed to load wallet seal: {}", e))?;

            // Nur migrieren, wenn nötig (Legacy-Binding oder kein Siegel vorhanden)
            if needs_legacy_binding || seal_record.is_none() {
                let state_hash = {
                    let canonical = crate::services::utils::to_canonical_json(&wallet.own_fingerprints)
                        .map_err(|e| format!("Failed to compute state hash: {}", e))?;
                    crate::services::crypto_utils::get_hash(canonical.as_bytes())
                };

                let migrated_seal = if needs_legacy_binding && seal_record.is_some() {
                    // Legacy Migration: Existierendes Siegel updaten, um den tx_nonce zu erhalten
                    let existing_record = seal_record.unwrap();
                    SealManager::update_seal(
                        &existing_record.seal,
                        &identity,
                        &state_hash,
                        &wallet.local_instance_id,
                    )
                    .map_err(|e| format!("Failed to migrate legacy seal: {}", e))?
                } else {
                    // Komplett neues Siegel (Genesis)
                    SealManager::create_initial_seal(
                        &identity.user_id,
                        &identity,
                        &state_hash,
                        &wallet.local_instance_id,
                    )
                    .map_err(|e| format!("Failed to create initial seal: {}", e))?
                };

                let new_record = LocalSealRecord {
                    seal: migrated_seal.clone(),
                    sync_status: SyncStatus::PendingUpload,
                    is_locked_due_to_fork: false,
                };
                storage
                    .save_seal(&identity.user_id, &auth, &new_record)
                    .map_err(|e| format!("Failed to save migration seal: {}", e))?;

                // Integrität für das neue migrierte Siegel initialisieren
                let hashes = storage.get_all_item_hashes().unwrap_or_default();
                if let Ok(ir) = crate::services::integrity_manager::IntegrityManager::create_integrity_record(&identity, &migrated_seal, hashes) {
                    let _ = storage.save_integrity(&identity.user_id, &ir);
                }
            }
        }
        // --- WALLET SEAL ENDE ---

        // Sperre erlangen
        storage
            .lock()
            .map_err(|e| format!("Failed to lock wallet: {}", e))?;

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
    ) -> Result<(), String> {
        let profile_path = self.base_storage_path.join(folder_name);
        if !profile_path.exists() {
            return Err("Profile directory not found.".to_string());
        }

        // --- SECURITY GUARD: Detect bad instance_id storage ---
        self.check_instance_id_trap(&profile_path)?;

        let mut storage = FileStorage::new(profile_path);

        // 1. Lade das Wallet mit der Mnemonic-Phrase (öffnet das "zweite Schloss").
        let auth_method = AuthMethod::Mnemonic(mnemonic, passphrase, language);
        let (wallet, identity) = Wallet::load(&storage, &auth_method, local_instance_id.clone()).map_err(|e| {
            format!(
                "Recovery failed (check mnemonic phrase and passphrase): {}",
                e
            )
        })?;

        // 2. Setze das Passwort zurück, indem das Mnemonic-Schloss geöffnet und das Passwort-Schloss neu geschrieben wird.
        Wallet::reset_password(&mut storage, &identity, new_password)
            .map_err(|e| format!("Failed to set new password: {}", e))?;

        // --- WALLET SEAL: Neue Epoche einleiten (Recovery) ---
        {
            let auth_for_seal = AuthMethod::Password(new_password);
            let existing_seal = storage
                .load_seal(&identity.user_id, &auth_for_seal)
                .ok()
                .flatten();

            let current_state_hash = {
                let canonical = crate::services::utils::to_canonical_json(&wallet.own_fingerprints)
                    .map_err(|e| format!("Failed to compute state hash: {}", e))?;
                crate::services::crypto_utils::get_hash(canonical.as_bytes())
            };

            let recovered_seal = SealManager::recover_seal_epoch(
                existing_seal.as_ref().map(|r| &r.seal),
                &identity.user_id,
                &identity,
                &current_state_hash,
                &local_instance_id,
            ).map_err(|e| format!("Failed to create recovery seal: {}", e))?;

            let new_record = LocalSealRecord {
                seal: recovered_seal,
                sync_status: SyncStatus::PendingUpload,
                is_locked_due_to_fork: false, // Recovery hebt den Fork-Lock auf!
            };
            storage
                .save_seal(&identity.user_id, &auth_for_seal, &new_record)
                .map_err(|e| format!("Failed to save recovery seal: {}", e))?;

            // --- INTEGRITY UPDATE ---
            // Nach der Wiederherstellung des Siegels müssen wir den Integrity Record aktualisieren,
            // da sich seal.enc geändert hat. Sonst warnt der nächste Login vor Manipulation.
            let item_hashes = storage.get_all_item_hashes().map_err(|e| format!("Failed to get hashes for integrity: {}", e))?;
            let integrity_record = crate::services::integrity_manager::IntegrityManager::create_integrity_record(
                &identity,
                &new_record.seal,
                item_hashes,
            ).map_err(|e| format!("Failed to create integrity record: {}", e))?;

            storage
                .save_integrity(&identity.user_id, &integrity_record)
                .map_err(|e| format!("Failed to save integrity record: {}", e))?;
        }
        // --- WALLET SEAL ENDE ---

        // Sperre erlangen
        storage
            .lock()
            .map_err(|e| format!("Failed to lock wallet: {}", e))?;

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
    pub fn unlock_session(&mut self, password: &str, duration_seconds: u64) -> Result<(), String> {
        match &mut self.state {
            AppState::Unlocked {
                storage,
                wallet: _,
                identity: _,
                session_cache,
            } => {
                // Verifiziere das Passwort, indem wir versuchen, den Session-Key abzuleiten
                let session_key = storage.derive_key_for_session(password).map_err(|e| {
                    format!("Password verification failed: {}", e)
                })?;

                // Teste, ob der abgeleitete Schlüssel gültig ist, indem wir ihn verwenden,
                // um den verschlüsselten Dateischlüssel zu entschlüsseln.
                // Dies validiert, dass das Passwort korrekt war.
                storage
                    .test_session_key(&session_key)
                    .map_err(|e| format!("Password verification failed: {}", e))?;

                // Erstelle den Session-Cache
                *session_cache = Some(super::SessionCache {
                    session_key,
                    session_duration: Duration::from_secs(duration_seconds),
                    last_activity: Instant::now(),
                });

                Ok(())
            }
            AppState::Locked => Err("Wallet is locked. Please login first.".to_string()),
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
    pub fn refresh_session_activity(&mut self) -> Result<(), String> {
        if let AppState::Unlocked { session_cache, .. } = &mut self.state {
            // Prüfen, ob überhaupt eine Session existiert
            if let Some(cache) = session_cache {
                // BUGFIX: Validieren, ob die Session physisch abgelaufen ist
                if cache.last_activity.elapsed() > cache.session_duration {
                    // Session ist abgelaufen: Cache löschen und Fehler zurückgeben
                    *session_cache = None;
                    return Err("Session expired.".to_string());
                } else {
                    // Session gültig: Timer erneuern.
                    cache.last_activity = Instant::now();
                    return Ok(());
                }
            }
            return Err("No active session to refresh.".to_string());
        }
        Err("Wallet is locked.".to_string())
    }

    /// Erzwingt die Bindung des Wallets an das aktuelle Gerät (Handover).
    /// Dies wird aufgerufen, wenn der Login aufgrund eines `DeviceMismatch` fehlschlägt.
    pub fn handover_to_this_device(
        &mut self,
        folder_name: &str,
        password: &str,
        local_instance_id: String,
    ) -> Result<(), String> {
        let profile_path = self.base_storage_path.join(folder_name);
        if !profile_path.exists() {
            return Err("Profile directory not found.".to_string());
        }

        let mut storage = FileStorage::new(profile_path);
        let auth = AuthMethod::Password(password);

        // 1. Wallet laden
        let (mut wallet, identity) = Wallet::load(&storage, &auth, local_instance_id)
            .map_err(|e| format!("Loading for handover failed: {}", e))?;

        // 2. Handover durchführen
        let new_seal = wallet.force_device_handover(&mut storage, &identity, &auth)
            .map_err(|e| format!("Handover failed: {}", e))?;

        // --- INTEGRITY UPDATE ---
        let item_hashes = storage.get_all_item_hashes().map_err(|e| format!("Failed to get hashes for integrity: {}", e))?;
        let integrity_record = crate::services::integrity_manager::IntegrityManager::create_integrity_record(
            &identity,
            &new_seal,
            item_hashes,
        ).map_err(|e| format!("Failed to create integrity record: {}", e))?;

        storage
            .save_integrity(&identity.user_id, &integrity_record)
            .map_err(|e| format!("Failed to save integrity record: {}", e))?;

        // 3. Login durchführen
        storage.lock().map_err(|e| format!("Lock failed: {}", e))?;
        
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
    fn check_instance_id_trap(&self, profile_path: &Path) -> Result<(), String> {
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
                return Err(
                    "CRITICAL SECURITY VIOLATION: The App Developer has stored the 'instance_id' inside the application data directory. \
                    This defeats the cloning protection! The instance_id MUST be stored securely in the OS Keyring or a separate isolated Config directory. \
                    Execution halted to protect user funds.".to_string()
                );
            }
        }
        Ok(())
    }
}


