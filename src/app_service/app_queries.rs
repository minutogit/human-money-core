//! # src/app_service/app_queries.rs
//!
//! Enthält alle reinen Lese-Operationen (Queries) des `AppService`.
use super::{AppService, AppState, AppFacadeError};
use crate::models::profile::PublicProfile;
use crate::wallet::{AggregatedBalance, AssetClassSummary, instance::VoucherStatus};
use crate::wallet::{VoucherDetails, VoucherSummary};

impl AppService {
    // --- Datenabfragen (Queries) ---

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
    ) -> Result<Vec<VoucherSummary>, AppFacadeError> {
        self.with_unlocked_ref(|wallet, identity, _| {
            Ok(wallet.list_vouchers(
                Some(identity),
                voucher_standard_uuid_filter,
                status_filter,
                test_filter,
            ))
        })
    }

    /// Aggregiert die Guthaben aller aktiven Gutscheine, gruppiert nach Währung.
    ///
    /// # Returns
    /// Eine `HashMap`, die von der Währungseinheit (z.B. "Minuten") auf den Gesamtbetrag abbildet.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt (`Locked`) ist.
    pub fn get_total_balance_by_currency(&self) -> Result<Vec<AggregatedBalance>, AppFacadeError> {
        self.with_unlocked_ref(|wallet, identity, _| {
            Ok(wallet.get_total_balance_by_currency(Some(identity)))
        })
    }

    /// Ermittelt alle im Wallet aktiven Asset-Klassen (Standard + Test-Status).
    /// Dies dient der UI zum sauberen Befüllen von Filter-Dropdowns.
    pub fn get_active_asset_classes(&self) -> Result<Vec<AssetClassSummary>, AppFacadeError> {
        self.with_unlocked_ref(|wallet, _, _| Ok(wallet.get_active_asset_classes()))
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
    pub fn get_voucher_details(&self, local_id: &str) -> Result<VoucherDetails, AppFacadeError> {
        self.with_unlocked_ref(|wallet, _, _| {
            wallet.get_voucher_details(local_id).map_err(AppFacadeError::from)
        })
    }

    /// Gibt die User-ID des Wallet-Inhabers zurück.
    ///
    /// # Returns
    /// Die `did:key`-basierte User-ID als String.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt (`Locked`) ist.
    pub fn get_user_id(&self) -> Result<String, AppFacadeError> {
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
    ) -> Result<Vec<String>, AppFacadeError> {
        let verified_standard = self.parse_voucher_standard(standard_toml_content)?;
        Ok(verified_standard.immutable.issuance.allowed_signature_roles)
    }

    /// Parst einen Gutschein-Standard (TOML) in ein typsicheres Objekt.
    /// Dient als Single Source of Truth für Client-Applikationen.
    ///
    /// Diese Funktion verifiziert auch die kryptographische Signatur des Standards.
    pub fn parse_voucher_standard(
        &self,
        standard_toml_content: &str,
    ) -> Result<crate::models::voucher_standard_definition::VoucherStandardDefinition, AppFacadeError> {
        let (verified_standard, _) = crate::services::standard_manager::verify_and_parse_standard(
            standard_toml_content,
        )
        .map_err(AppFacadeError::from)?;
        Ok(verified_standard)
    }

    /// Returns the public profile of the wallet owner.
    pub fn get_public_profile(&self) -> Result<PublicProfile, AppFacadeError> {
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
    ) -> Result<crate::models::conflict::TrustStatus, AppFacadeError> {
        Ok(self.get_wallet()?.check_reputation(offender_id))
    }

    /// Ermittelt die Identität des Absenders eines Gutscheins (ggf. durch Entschlüsselung).
    pub fn get_voucher_source_sender(&self, local_instance_id: &str) -> Result<Option<String>, AppFacadeError> {
        let wallet = self.get_wallet()?;
        let identity = self.get_identity()?;
        wallet
            .get_voucher_source_sender(local_instance_id, &identity)
            .map_err(AppFacadeError::from)
    }

    /// Lädt die Event-Historie des Wallets (BFF-Query).
    ///
    /// **Achtung Architektur/API:** Da diese Abfrage den Session-Timer (Sliding Window) 
    /// aktualisiert, erfordert sie eine mutable Referenz (`&mut self`). Wenn der `AppService` 
    /// hinter einem `RwLock` liegt, muss für diese Abfrage ein Write-Lock angefordert werden!
    pub fn get_event_history(
        &mut self,
        offset: usize,
        limit: usize,
        password: Option<&str>,
    ) -> Result<Vec<crate::models::wallet_event::WalletEvent>, AppFacadeError> {
        let auth = match password {
            Some(pwd) => crate::storage::AuthMethod::Password(pwd),
            None => {
                let session_key = self.get_session_key()?;
                crate::storage::AuthMethod::SessionKey(session_key)
            }
        };
        
        let wallet = self.get_wallet()?;
        
        // Da AppService den Storage besitzt, können wir ihn hier nutzen.
        match &self.state {
            AppState::Unlocked { storage, .. } => {
                wallet.get_event_history(storage, &auth, offset, limit)
                    .map_err(AppFacadeError::from)
            }
            AppState::Locked => Err(AppFacadeError::WalletLocked("Wallet is locked.".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::app_service::AppService;
    use std::path::Path;

    #[test]
    fn test_parse_voucher_standard_and_serialization() {
        // Wir nutzen den Bypass, um keine echte Signatur für den Test-TOML generieren zu müssen.
        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(true);

        let toml_content = r#"
[immutable.identity]
uuid = "123-test-uuid"
name = "Test Standard"
abbreviation = "TST"

[immutable.blueprint]
unit = "TestUnit"
primary_redemption_type = "goods_or_services"
collateral_type = "personal_guarantee"

[immutable.features]
allow_partial_transfers = true
balances_are_summable = true
amount_decimal_places = 2
privacy_mode = "public"
allowed_t_types = ["init", "transfer"]

[immutable.issuance]
validity_duration_range = ["P1M", "P1Y"]
issuance_minimum_validity_duration = "P1M"
additional_signatures_range = [0, 1]
allowed_signature_roles = ["issuer"]

[mutable.metadata]
issuer_name = "Test Issuer"

[signature]
issuer_id = "0:riw@did:key:z6Mki8QqVMb66hjtTwcceVXbZuSHTk61jqiprRvEhuotZmSA"
signature = "5aomSjj76rEb4VVjhAd6p6qvmU79wkkTpj84AnY3D9p8xRDNfxBqKL4EbEHTKfPevggafJeJuzhgYV4rvhLgMs5m"
"#;

        let base_path = Path::new("/tmp/test_parse_standard");
        let service = AppService::new(base_path).unwrap();

        let result = service.parse_voucher_standard(toml_content);
        assert!(result.is_ok(), "Parsing should succeed with bypass: {:?}", result.err());
        
        let standard = result.unwrap();
        assert_eq!(standard.immutable.identity.name, "Test Standard");
        assert_eq!(standard.immutable.blueprint.unit, "TestUnit");

        // Test Serialisierung (Sollte snake_case bleiben um kryptographische Stabilität zu wahren)
        let json_str = serde_json::to_string(&standard).unwrap();
        
        // Überprüfe, ob Felder in Rust-idiomatischem snake_case ausgegeben werden
        assert!(json_str.contains("\"issuer_name\""));
        assert!(json_str.contains("\"allow_partial_transfers\""));
        assert!(json_str.contains("\"primary_redemption_type\""));
        assert!(json_str.contains("\"amount_decimal_places\""));

        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(false);
    }

    #[test]
    fn test_parse_voucher_standard_invalid_toml() {
        let base_path = Path::new("/tmp/test_parse_standard_err");
        let service = AppService::new(base_path).unwrap();

        let invalid_toml = "this is not toml [[]]";
        let result = service.parse_voucher_standard(invalid_toml);
        assert!(result.is_err());
    }
}


