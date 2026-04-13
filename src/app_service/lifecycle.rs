//! # src/app_service/lifecycle.rs
//!
//! Enthält alle Funktionen, die den Lebenszyklus des `AppService` steuern,
//! wie Initialisierung, Login/Logout und Wiederherstellung.

use super::{AppService, AppState, ProfileInfo};
use crate::storage::{AuthMethod, Storage, file_storage::FileStorage};
use crate::wallet::Wallet;
use bip39::Language;
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
    pub fn generate_mnemonic(word_count: u32) -> Result<String, String> {
        crate::services::crypto_utils::generate_mnemonic(word_count as usize, Language::English)
            .map_err(|e| e.to_string())
    }

    /// Validiert eine vom Benutzer eingegebene BIP-39 Mnemonic-Phrase.
    ///
    /// Diese Methode ist statisch und kann ohne geladenes Wallet aufgerufen werden.
    pub fn validate_mnemonic(mnemonic: &str) -> Result<(), String> {
        crate::services::crypto_utils::validate_mnemonic_phrase(mnemonic)
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

        if profile_path.exists() {
            return Err(
                "A profile with these secrets already exists (folder collision).".to_string(),
            );
        }

        let mut storage = FileStorage::new(profile_path);

        let (wallet, identity) = Wallet::new_from_mnemonic(mnemonic, passphrase, user_prefix)
            .map_err(|e| format!("Failed to create new wallet: {}", e))?;

        wallet
            .save(&mut storage, &identity, &AuthMethod::Password(password))
            .map_err(|e| format!("Failed to save new wallet: {}", e))?;

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
        // Die Funktion storage.derive_key_for_session scheint (fälschlicherweise)
        // eine existierende Datei vorauszusetzen, die nur von save_arbitrary_data
        // geschrieben wird. Wir rufen dies hier einmalig auf, um sicherzustellen,
        // dass alle Modus A / Modus B Operationen danach funktionieren.
        // Wir ignorieren das Ergebnis, da der Aufruf nur zum Initialisieren dient.
        let _ = self.save_encrypted_data("__storage_session_anchor", b"init", Some(password));
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
    ) -> Result<(), String> {
        let profile_path = self.base_storage_path.join(folder_name);
        if !profile_path.exists() {
            return Err("Profile directory not found.".to_string());
        }

        let mut storage = FileStorage::new(profile_path);

        let (mut wallet, identity) = Wallet::load(&storage, &AuthMethod::Password(password))
            .map_err(|e| format!("Login failed (check password): {}", e))?;

        if cleanup_on_login {
            wallet
                .run_storage_cleanup(None)
                .map_err(|e| format!("Storage cleanup on login failed: {}", e))?;
            wallet
                .save(&mut storage, &identity, &AuthMethod::Password(password))
                .map_err(|e| format!("Failed to save wallet after cleanup: {}", e))?;
        }

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
    ) -> Result<(), String> {
        let profile_path = self.base_storage_path.join(folder_name);
        if !profile_path.exists() {
            return Err("Profile directory not found.".to_string());
        }

        let mut storage = FileStorage::new(profile_path);

        // 1. Lade das Wallet mit der Mnemonic-Phrase (öffnet das "zweite Schloss").
        let auth_method = AuthMethod::Mnemonic(mnemonic, passphrase);
        let (wallet, identity) = Wallet::load(&storage, &auth_method).map_err(|e| {
            format!(
                "Recovery failed (check mnemonic phrase and passphrase): {}",
                e
            )
        })?;

        // 2. Setze das Passwort zurück, indem das Mnemonic-Schloss geöffnet und das Passwort-Schloss neu geschrieben wird.
        Wallet::reset_password(&mut storage, &identity, new_password)
            .map_err(|e| format!("Failed to set new password: {}", e))?;

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
        println!("[DEBUG LIFECYCLE] Attempting to unlock session...");
        match &mut self.state {
            AppState::Unlocked {
                storage,
                wallet: _,
                identity: _,
                session_cache,
            } => {
                // Verifiziere das Passwort, indem wir versuchen, den Session-Key abzuleiten
                let session_key = storage.derive_key_for_session(password).map_err(|e| {
                    println!(
                        "[DEBUG LIFECYCLE] storage.derive_key_for_session FAILED: {}",
                        e
                    );
                    format!("Password verification failed: {}", e)
                })?;

                // Teste, ob der abgeleitete Schlüssel gültig ist, indem wir ihn verwenden,
                // um den verschlüsselten Dateischlüssel zu entschlüsseln.
                // Dies validiert, dass das Passwort korrekt war.
                storage
                    .test_session_key(&session_key)
                    .map_err(|e| format!("Password verification failed: {}", e))?;

                println!("[DEBUG LIFECYCLE] storage.derive_key_for_session SUCCEEDED.");
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
}


