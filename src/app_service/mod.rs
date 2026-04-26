//! # src/app_service/mod.rs
//!
//! Definiert den `AppService`, eine Fassade über dem `Wallet`, um die
//! Kernlogik für Client-Anwendungen (z.B. GUIs) zu vereinfachen.
//!
//! Diese Schicht verwaltet den Anwendungszustand (Locked/Unlocked), kapselt
//! die `UserIdentity` und stellt sicher, dass Zustandsänderungen im Wallet
//! automatisch gespeichert werden.
//!
//! ## Konzept: Profil-Management
//!
//! Der `AppService` unterstützt mehrere, voneinander getrennte Benutzerprofile.
//! Jedes Profil wird in einem eigenen, anonym benannten Unterverzeichnis gespeichert.
//! Eine zentrale `profiles.json`-Datei im Basisverzeichnis ordnet benutzerfreundliche
//! Profilnamen den anonymen Ordnern zu, um den Login zu erleichtern.
//!
//! ## Beispiel: Typischer Lebenszyklus
//!
//! ```no_run
//! use human_money_core::app_service::AppService;
//! use human_money_core::MnemonicLanguage;
//! use std::path::Path;
//! # use human_money_core::services::voucher_manager::NewVoucherData;
//! # use human_money_core::models::voucher_standard_definition::VoucherStandardDefinition;
//!
//! // 1. Initialisierung des Services mit einem Basis-Speicherpfad.
//! let storage_path = Path::new("/tmp/my_wallets");
//! let mut app = AppService::new(storage_path).expect("Service konnte nicht erstellt werden.");
//!
//! // 2. Neues Profil erstellen (dies entsperrt das Wallet).
//! let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
//! app.create_profile("Mein Wallet", &mnemonic, None, Some("user"), "sicheres-passwort-123", MnemonicLanguage::English)
//!    .expect("Profil konnte nicht erstellt werden.");
//!
//! // 3. Eine Aktion ausführen (z.B. Guthaben prüfen).
//! let balance = app.get_total_balance_by_currency().unwrap();
//! assert!(balance.is_empty());
//!
//! // 4. Wallet sperren (Logout).
//! app.logout();
//!
//! // 5. Profile für den Login-Screen abrufen.
//! let profiles = app.list_profiles().expect("Profile konnten nicht geladen werden.");
//! let profile_to_load = profiles.first().unwrap();
//!
//! // 6. Erneut anmelden mit dem Ordnernamen des Profils und dem Passwort.
//! app.login(&profile_to_load.folder_name, "sicheres-passwort-123", false)
//!    .expect("Login fehlgeschlagen.");
//!
//! // 7. Die User-ID abrufen.
//! let user_id = app.get_user_id().unwrap();
//! println!("Angemeldet als: {}", user_id);
//! ```

use crate::models::profile::UserIdentity;
use crate::services::{bundle_processor, crypto_utils};
use crate::storage::file_storage::FileStorage;
use crate::wallet::Wallet;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub const DEFAULT_ARCHIVE_GRACE_PERIOD_YEARS: i64 = 2;

// Deklaration der neuen Handler als öffentliche Sub-Module.
// Jede Datei enthält einen `impl AppService`-Block für ihren spezifischen Bereich.
pub mod app_profile_handler;
pub mod app_queries;
pub mod app_signature_handler;
pub mod command_handler;
pub mod conflict_handler;
pub mod data_encryption;
pub mod l2_facade;
pub mod lifecycle;
pub mod seal_handler;

/// Repräsentiert die öffentlich sichtbaren Informationen eines Profils.
/// Wird verwendet, um dem Frontend eine Liste der verfügbaren Profile zu übergeben.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProfileInfo {
    /// Der vom Benutzer gewählte, menschenlesbare Name des Profils.
    #[serde(rename = "profileName")]
    pub profile_name: String,
    /// Der anonyme, abgeleitete Name des Ordners, in dem die Profildaten gespeichert sind.
    #[serde(rename = "folderName")]
    pub folder_name: String,
}

/// Cache für die "Passwort merken"-Funktion.
pub struct SessionCache {
    /// Der abgeleitete Speicherschlüssel.
    session_key: [u8; 32],
    /// Die konfigurierte Dauer der Inaktivität (z.B. 900 Sek).
    session_duration: Duration,
    /// Der Zeitpunkt der letzten erkannten Aktivität (für "Sliding Window").
    last_activity: Instant,
}

/// Repräsentiert den Kernzustand der Anwendung.
pub enum AppState {
    /// Es ist kein Wallet geladen und keine `UserIdentity` im Speicher.
    Locked,
    /// Ein Wallet ist geladen und die `UserIdentity` (inkl. privatem Schlüssel)
    /// ist für Operationen verfügbar.
    Unlocked {
        storage: FileStorage,
        wallet: Wallet,
        identity: UserIdentity,
        /// Der Cache für die "Passwort merken"-Funktion.
        /// Wenn Some(...), sind Aktionen ohne Passworteingabe möglich.
        session_cache: Option<SessionCache>,
    },
}

/// Die `AppService`-Fassade.
///
/// Dient als primäre Schnittstelle für Client-Anwendungen. Sie vereinfacht die
/// Interaktion mit der `human_money_core`-Bibliothek, indem sie das Zustandsmanagement
/// und die Persistenzabläufe kapselt.
pub struct AppService {
    /// Der Basispfad, in dem die anonymen Wallet-Verzeichnisse gespeichert werden.
    base_storage_path: PathBuf,
    /// Der aktuelle Zustand des Services (Locked oder Unlocked).
    state: AppState,
}

// --- Interne Hilfsmethoden ---

impl AppService {
    /// Leitet den anonymen Ordnernamen aus den Benutzergeheimnissen ab.
    ///
    /// Diese Methode kapselt die Logik zur Erzeugung eines kryptographisch sicheren,
    /// anonymen und eindeutigen Ordnernamens für ein neues Profil.
    fn derive_folder_name(
        mnemonic: &str,
        passphrase: Option<&str>,
        prefix: Option<&str>,
    ) -> String {
        // 1. Erstelle den eindeutigen, geheimen String für dieses Konto.
        let secret_string = format!(
            "{}{}{}",
            mnemonic,
            passphrase.unwrap_or(""),
            prefix.unwrap_or("")
        );

        // 2. Verwende Argon2id Key Stretching für den anonymen Ordnernamen (Mobile/WASM tuned).
        // Dies bietet deutlich höheren Schutz gegen Brute-Force-Angriffe auf den Ordnernamen.
        const SALT: &[u8] = b"human-money-profile-folder-v1";
        crypto_utils::derive_argon2_id(secret_string.as_bytes(), SALT)
            .unwrap_or_else(|_| crypto_utils::get_hash(secret_string.as_bytes()))
    }

    /// Validiert alle Gutscheine innerhalb eines verschlüsselten Bundles.
    /// Diese Methode wird vom `command_handler` vor der Verarbeitung eines Bundles
    /// aufgerufen und bleibt daher hier zentral verfügbar.
    fn validate_vouchers_in_bundle(
        &self,
        identity: &UserIdentity,
        bundle_data: &[u8],
        standard_definitions_toml: &HashMap<String, String>,
    ) -> Result<(), String> {
        let bundle = bundle_processor::open_and_verify_bundle(identity, bundle_data)
            .map_err(|e| e.to_string())?;

        for voucher in &bundle.vouchers {
            let standard_uuid = &voucher.voucher_standard.uuid;
            let standard_toml = standard_definitions_toml
                .get(standard_uuid)
                .ok_or_else(|| {
                    format!(
                        "Required standard definition for UUID '{}' not provided.",
                        standard_uuid
                    )
                })?;

            let (verified_standard, _) =
                crate::services::standard_manager::verify_and_parse_standard(standard_toml)
                    .map_err(|e| e.to_string())?;

            crate::services::voucher_validation::validate_voucher_against_standard(
                voucher,
                &verified_standard,
            )
            .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// Prüft die "Passwort merken"-Sitzung, verwaltet den Timeout
    /// und das "Sliding Window" (setzt 'last_activity' neu).
    pub fn get_session_key(&mut self) -> Result<[u8; 32], String> {
        match &mut self.state {
            AppState::Unlocked {
                storage: _,
                wallet: _,
                identity: _,
                session_cache,
            } => {
                if let Some(cache) = session_cache {
                    let now = Instant::now();
                    if now > cache.last_activity + cache.session_duration {
                        // --- Timeout! ---
                        *session_cache = None; // Key löschen
                        Err("Session timed out. Please provide password.".to_string())
                    } else {
                        // --- OK, Aktivität erkannt ---
                        cache.last_activity = now; // "Sliding Window"
                        Ok(cache.session_key)
                    }
                } else {
                    Err("Password required. Please use 'unlock_session'.".to_string())
                }
            }
            AppState::Locked => Err("Wallet is locked.".to_string()),
        }
    }
}

// --- Interne Hilfsmethoden für Tests ---
// #[cfg(debug_assertions)]`, damit diese Funktionen für Integrationstests (z.B. in `tests/wallet_api/`)
// sichtbar sind, aber nicht in Release-Builds.
#[cfg(debug_assertions)]
impl AppService {
    /// Fügt einen Gutschein *direkt* zum In-Memory-Wallet-Zustand hinzu und
    /// NUR FÜR TESTS.
    pub fn get_wallet_for_test(&self) -> Option<&crate::wallet::Wallet> {
        if let AppState::Unlocked { wallet, .. } = &self.state {
            Some(wallet)
        } else {
            None
        }
    }

    /// Gibt eine mutable Referenz auf das interne Wallet zurück.
    /// NUR FÜR TESTS.
    pub fn get_wallet_mut(&mut self) -> Option<&mut crate::wallet::Wallet> {
        if let AppState::Unlocked { wallet, .. } = &mut self.state {
            Some(wallet)
        } else {
            None
        }
    }

    /// Eine Hilfsmethoden nur für Tests, um Zugriff auf die interne Identität zu bekommen.
    #[doc(hidden)]
    pub fn get_unlocked_mut_for_test(&mut self) -> (&mut Wallet, &UserIdentity) {
        match &mut self.state {
            AppState::Unlocked {
                wallet, identity, ..
            } => (wallet, identity),
            _ => panic!("Service must be unlocked for this test helper"),
        }
    }
}
