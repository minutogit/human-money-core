//! # src/app_service/app_queries.rs
//!
//! Enthält alle reinen Lese-Operationen (Queries) des `AppService`.
use super::{AppService, AppState};
use crate::models::profile::{PublicProfile, UserIdentity};
use crate::wallet::{AggregatedBalance, AssetClassSummary, instance::VoucherStatus};
use crate::wallet::{VoucherDetails, VoucherSummary, Wallet};

impl AppService {
    // --- Datenabfragen (Queries) ---

    /// Eine private Hilfsfunktion für den Nur-Lese-Zugriff auf das Wallet.
    /// Stellt sicher, dass das Wallet entsperrt ist, bevor eine Operation ausgeführt wird.
    ///
    /// Diese Funktion ist `pub(super)`, damit sie von allen Handlern innerhalb
    /// des `app_service`-Moduls verwendet werden kann.
    pub(super) fn get_wallet(&self) -> Result<&Wallet, String> {
        match &self.state {
            AppState::Unlocked { wallet, .. } => Ok(wallet),
            AppState::Locked => Err("Wallet is locked.".to_string()),
        }
    }

    /// Eine private Hilfsfunktion für den Zugriff auf die Identität.
    pub(super) fn get_identity(&self) -> Result<&UserIdentity, String> {
        match &self.state {
            AppState::Unlocked { identity, .. } => Ok(identity),
            AppState::Locked => Err("Wallet is locked.".to_string()),
        }
    }

    /// Gibt eine Liste von Zusammenfassungen aller Gutscheine im Wallet zurück.
    /// Die Liste kann optional nach Gutschein-Standards (UUIDs), Status und Test-Status gefiltert werden.
    ///
    /// # Arguments
    /// * `voucher_standard_uuid_filter` - Ein optionaler Slice (`&[String]`) von UUIDs.
    /// * `status_filter`                - Ein optionaler Slice (`&[VoucherStatus]`) von Status-Enums.
    /// * `test_filter`                  - Ein optionaler Boolean. Wenn `Some(true)`, werden nur Testgutscheine zurückgegeben.
    ///                                    Wenn `None`, wird nicht nach Test-Status gefiltert.
    ///
    /// # Returns
    /// Ein `Vec<VoucherSummary>` mit den wichtigsten Daten jedes Gutscheins, basierend auf den Filtern.
    pub fn get_voucher_summaries(
        &self,
        voucher_standard_uuid_filter: Option<&[String]>,
        status_filter: Option<&[VoucherStatus]>,
        test_filter: Option<bool>,
    ) -> Result<Vec<VoucherSummary>, String> {
        let identity = self.get_identity()?;
        Ok(self.get_wallet()?.list_vouchers(
            Some(identity),
            voucher_standard_uuid_filter,
            status_filter,
            test_filter,
        ))
    }

    /// Aggregiert die Guthaben aller aktiven Gutscheine, gruppiert nach Währung.
    ///
    /// # Returns
    /// Eine `HashMap`, die von der Währungseinheit (z.B. "Minuten") auf den Gesamtbetrag abbildet.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt (`Locked`) ist.
    pub fn get_total_balance_by_currency(&self) -> Result<Vec<AggregatedBalance>, String> {
        let identity = self.get_identity()?;
        Ok(self.get_wallet()?.get_total_balance_by_currency(Some(identity)))
    }

    /// Ermittelt alle im Wallet aktiven Asset-Klassen (Standard + Test-Status).
    /// Dies dient der UI zum sauberen Befüllen von Filter-Dropdowns.
    pub fn get_active_asset_classes(&self) -> Result<Vec<AssetClassSummary>, String> {
        Ok(self.get_wallet()?.get_active_asset_classes())
    }

    /// Ruft eine detaillierte Ansicht für einen einzelnen Gutschein ab.
    ///
    /// # Arguments
    /// * `local_id` - Die lokale, eindeutige ID der Gutschein-Instanz im Wallet.
    ///
    /// # Returns
    /// Die `VoucherDetails`-Struktur mit dem vollständigen Gutschein-Objekt.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt ist oder keine Gutschein-Instanz mit dieser ID existiert.
    pub fn get_voucher_details(&self, local_id: &str) -> Result<VoucherDetails, String> {
        self.get_wallet()?
            .get_voucher_details(local_id)
            .map_err(|e| e.to_string())
    }

    /// Gibt die User-ID des Wallet-Inhabers zurück.
    ///
    /// # Returns
    /// Die `did:key`-basierte User-ID als String.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt (`Locked`) ist.
    pub fn get_user_id(&self) -> Result<String, String> {
        Ok(self.get_wallet()?.get_user_id().to_string())
    }

    /// Hilfsfunktion für Apps: Extrahiert die Liste der erlaubten Signatur-Rollen
    /// aus einem Gutschein-Standard (TOML).
    ///
    /// # Arguments
    /// * `standard_toml_content` - Der Inhalt der Standard-Definitionsdatei (TOML).
    ///
    /// # Returns
    /// Ein `Vec<String>` mit den Rollen-Namen (z.B. ["guarantor", "notary", "approver"]).
    pub fn get_allowed_signature_roles_from_standard(
        &self,
        standard_toml_content: &str,
    ) -> Result<Vec<String>, String> {
        let (verified_standard, _) = crate::services::standard_manager::verify_and_parse_standard(
            standard_toml_content,
        )
        .map_err(|e| e.to_string())?;
        Ok(verified_standard.immutable.issuance.allowed_signature_roles)
    }

    /// Returns the public profile of the wallet owner.
    pub fn get_public_profile(&self) -> Result<PublicProfile, String> {
        let wallet = self.get_wallet()?;
        let profile = &wallet.profile;
        Ok(PublicProfile {
            protocol_version: Some("v1".to_string()),
            id: Some(profile.user_id.clone()),
            first_name: profile.first_name.clone(),
            last_name: profile.last_name.clone(),
            organization: profile.organization.clone(),
            community: profile.community.clone(),
            address: profile.address.clone(),
            gender: profile.gender.clone(),
            email: profile.email.clone(),
            phone: profile.phone.clone(),
            coordinates: profile.coordinates.clone(),
            url: profile.url.clone(),
            service_offer: profile.service_offer.clone(),
            needs: profile.needs.clone(),
            picture_url: profile.picture_url.clone(),
        })
    }

    /// Prüft den Ruf einer User-ID basierend auf den lokalen Beweisen.
    /// Wird von der GUI vor Transaktionen aufgerufen, um Warnungen anzuzeigen.
    pub fn check_reputation(
        &self,
        offender_id: &str,
    ) -> Result<crate::models::conflict::TrustStatus, String> {
        Ok(self.get_wallet()?.check_reputation(offender_id))
    }

    /// Ermittelt die Identität des Absenders eines Gutscheins (ggf. durch Entschlüsselung).
    pub fn get_voucher_source_sender(&self, local_instance_id: &str) -> Result<Option<String>, String> {
        let wallet = self.get_wallet()?;
        let identity = self.get_identity()?;
        wallet
            .get_voucher_source_sender(local_instance_id, &identity)
            .map_err(|e| e.to_string())
    }

    /// Lädt die Event-Historie des Wallets (BFF-Query).
    pub fn get_event_history(
        &self,
        offset: usize,
        limit: usize,
        password: &str,
    ) -> Result<Vec<crate::models::wallet_event::WalletEvent>, String> {
        let wallet = self.get_wallet()?;
        let auth = crate::storage::AuthMethod::Password(password);
        
        // Da AppService den Storage besitzt, können wir ihn hier nutzen.
        match &self.state {
            AppState::Unlocked { storage, .. } => {
                wallet.get_event_history(storage, &auth, offset, limit)
                    .map_err(|e| e.to_string())
            }
            AppState::Locked => Err("Wallet is locked.".to_string()),
        }
    }
}


