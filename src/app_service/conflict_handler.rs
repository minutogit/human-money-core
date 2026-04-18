//! # src/app_service/conflict_handler.rs
//!
//! Enthält alle `AppService`-Funktionen, die sich auf das Management von
//! Double-Spend-Konflikten beziehen.

use super::{AppService, AppState};
use crate::models::conflict::{ProofOfDoubleSpend, ResolutionEndorsement};
use crate::wallet::ProofOfDoubleSpendSummary;
use crate::{error::VoucherCoreError, wallet::CleanupReport};

impl AppService {
    // --- Konflikt-Management ---

    /// Gibt eine Liste von Zusammenfassungen aller bekannten Double-Spend-Konflikte zurück.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt (`Locked`) ist.
    pub fn list_conflicts(&self) -> Result<Vec<ProofOfDoubleSpendSummary>, String> {
        Ok(self.get_wallet()?.list_conflicts())
    }

    /// Ruft einen vollständigen `ProofOfDoubleSpend` anhand seiner ID ab.
    ///
    /// Ideal, um die Details eines Konflikts anzuzeigen oder ihn für den
    /// manuellen Austausch zu exportieren.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt ist oder kein Beweis mit dieser ID existiert.
    pub fn get_proof_of_double_spend(&self, proof_id: &str) -> Result<ProofOfDoubleSpend, String> {
        self.get_wallet()?
            .get_proof_of_double_spend(proof_id)
            .map_err(|e| e.to_string())
    }

    /// Erstellt eine signierte Beilegungserklärung (`ResolutionEndorsement`) für einen Konflikt.
    ///
    /// Diese Operation verändert den Wallet-Zustand nicht. Sie erzeugt ein
    /// signiertes Objekt, das an andere Parteien gesendet werden kann, um zu
    /// signalisieren, dass der Konflikt aus Sicht des Wallet-Inhabers (des Opfers)
    /// gelöst wurde.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt ist oder der referenzierte Beweis nicht existiert.
    pub fn create_resolution_endorsement(
        &self,
        proof_id: &str,
        notes: Option<String>,
    ) -> Result<ResolutionEndorsement, String> {
        match &self.state {
            AppState::Unlocked {
                wallet, identity, ..
            } => wallet
                .create_resolution_endorsement(identity, proof_id, notes)
                .map_err(|e| e.to_string()),
            AppState::Locked => Err("Wallet is locked.".to_string()),
        }
    }

    /// Setzt den lokalen Override für einen spezifischen Konflikt.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt ist oder der Beweis nicht existiert.
    pub fn set_conflict_local_override(&mut self, proof_id: &str, value: bool) -> Result<(), String> {
        if let AppState::Unlocked { wallet, .. } = &mut self.state {
            wallet
                .set_conflict_local_override(proof_id, value)
                .map_err(|e| e.to_string())
        } else {
            Err("Wallet is locked.".to_string())
        }
    }

    /// Importiert einen Beweis aus einem Base64-kodierten JSON-String (Klartext-Export).
    ///
    /// # Immunitätsd-Regel:
    /// Lokale Entscheidungen (Overrides) werden durch den Import niemals überschrieben.
    pub fn import_proof_from_json(&mut self, json_base64: &str) -> Result<(), String> {
        if let AppState::Unlocked { wallet, .. } = &mut self.state {
            let json_bytes = bs58::decode(json_base64)
                .into_vec()
                .map_err(|_| "Invalid base64 encoding".to_string())?;
            let proof: ProofOfDoubleSpend =
                serde_json::from_slice(&json_bytes).map_err(|e| e.to_string())?;

            wallet.import_proof(proof).map_err(|e| e.to_string())
        } else {
            Err("Wallet is locked.".to_string())
        }
    }

    /// Importiert einen Beweis aus einem `SecureContainer` (Sicherer Austausch).
    pub fn import_proof_from_container(&mut self, container_bytes: &[u8]) -> Result<(), String> {
        if let AppState::Unlocked {
            wallet, identity, ..
        } = &mut self.state
        {
            let container: crate::models::secure_container::SecureContainer =
                serde_json::from_slice(container_bytes).map_err(|e| e.to_string())?;

            if container.c != crate::models::secure_container::PayloadType::ProofOfDoubleSpend {
                return Err("Container does not contain a Double-Spend-Proof.".to_string());
            }

            // Wallet-Identity wird benötigt, um den Container zu öffnen
            let decrypted_payload = crate::services::secure_container_manager::open_secure_container(
                &container,
                identity,
                None,
            )
            .map_err(|e: crate::error::VoucherCoreError| e.to_string())?;

            let proof: ProofOfDoubleSpend =
                serde_json::from_slice(&decrypted_payload).map_err(|e| e.to_string())?;

            wallet.import_proof(proof).map_err(|e| e.to_string())
        } else {
            Err("Wallet is locked.".to_string())
        }
    }

    /// Führt die Speicherbereinigung für Fingerprints und deren Metadaten durch.
    ///
    /// Diese Methode implementiert die in der Architektur-Spezifikation definierte
    /// Logik:
    /// 1. Löschen aller abgelaufenen Fingerprints.
    /// 2. Wenn das Speicherlimit (`MAX_FINGERPRINTS`) immer noch überschritten ist,
    ///    werden die Fingerprints mit der höchsten `depth` (und ältestem `t_time`)
    ///    gelöscht, bis das Limit wieder unterschritten ist.
    ///
    /// # Returns
    /// Ein `Result` mit einem `CleanupReport`, der Details über die Bereinigung
    /// enthält, oder einen Fehler, falls der Prozess fehlschlägt.
    pub fn run_storage_cleanup(&mut self) -> Result<CleanupReport, VoucherCoreError> {
        if let AppState::Unlocked { wallet, .. } = &mut self.state {
            let report = wallet.run_storage_cleanup(None)?;
            // Hinweis: Das Speichern des Wallets nach dem Cleanup wird dem Aufrufer
            // überlassen (z.B. am Ende einer Operation), um mehrfaches Schreiben
            // zu vermeiden.
            Ok(report)
        } else {
            Err(VoucherCoreError::WalletLocked)
        }
    }
}
