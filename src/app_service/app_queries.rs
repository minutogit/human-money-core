//! # src/app_service/app_queries.rs
//!
//! Contains all read-only operations (Queries) of the `AppService`.
use super::{AppService, AppState, AppFacadeError};
use crate::models::profile::PublicProfile;
use crate::wallet::{AggregatedBalance, AssetClassSummary, instance::VoucherStatus};
use crate::wallet::{VoucherDetails, VoucherSummary};

impl AppService {
    // --- Data Queries (Queries) ---

    /// Returns a list of summaries of all vouchers in the wallet.
    /// The list can optionally be filtered by voucher standards (UUIDs), status, and test status.
    ///
    /// # Arguments
    /// * `voucher_standard_uuid_filter` - An optional slice (`&[String]`) of UUIDs.
    /// * `status_filter`                - An optional slice (`&[VoucherStatus]`) of status enums.
    /// * `test_filter`                  - An optional boolean. If `Some(true)`, only test vouchers are returned.
    ///                                    If `None`, it is not filtered by test status.
    ///
    /// # Returns
    /// A `Vec<VoucherSummary>` containing the most important data of each voucher, based on the filters.
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

    /// Aggregates the balances of all active vouchers, grouped by currency.
    ///
    /// # Returns
    /// A `Vec<AggregatedBalance>` containing the balances grouped by currency.
    ///
    /// # Errors
    /// Fails if the wallet is locked (`Locked`).
    pub fn get_total_balance_by_currency(&self) -> Result<Vec<AggregatedBalance>, AppFacadeError> {
        self.with_unlocked_ref(|wallet, identity, _| {
            Ok(wallet.get_total_balance_by_currency(Some(identity)))
        })
    }

    /// Determines all active asset classes in the wallet (standard + test status).
    /// This serves the UI for cleanly populating filter dropdowns.
    pub fn get_active_asset_classes(&self) -> Result<Vec<AssetClassSummary>, AppFacadeError> {
        self.with_unlocked_ref(|wallet, _, _| Ok(wallet.get_active_asset_classes()))
    }

    /// Retrieves a detailed view for a single voucher.
    ///
    /// # Arguments
    /// * `local_id` - The local, unique ID of the voucher instance in the wallet.
    ///
    /// # Returns
    /// The `VoucherDetails` structure with the full voucher object.
    ///
    /// # Errors
    /// Fails if the wallet is locked or no voucher instance with this ID exists.
    pub fn get_voucher_details(&self, local_id: &str) -> Result<VoucherDetails, AppFacadeError> {
        self.with_unlocked_ref(|wallet, _, _| {
            wallet.get_voucher_details(local_id).map_err(AppFacadeError::from)
        })
    }

    /// Returns the user ID of the wallet owner.
    ///
    /// # Returns
    /// The `did:key`-based user ID as a string.
    ///
    /// # Errors
    /// Fails if the wallet is locked (`Locked`).
    pub fn get_user_id(&self) -> Result<String, AppFacadeError> {
        Ok(self.get_wallet()?.get_user_id().to_string())
    }

    /// Helper function for apps: Extracts the list of allowed signature roles
    /// from a voucher standard (TOML).
    ///
    /// # Arguments
    /// * `standard_toml_content` - The content of the standard definition file (TOML).
    ///
    /// # Returns
    /// A `Vec<String>` containing the role names (e.g. ["guarantor", "notary", "approver"]).
    pub fn get_allowed_signature_roles_from_standard(
        &self,
        standard_toml_content: &str,
    ) -> Result<Vec<String>, AppFacadeError> {
        let verified_standard = self.parse_voucher_standard(standard_toml_content)?;
        Ok(verified_standard.immutable.issuance.allowed_signature_roles)
    }

    /// Parses a voucher standard (TOML) into a type-safe object.
    /// Serves as the Single Source of Truth for client applications.
    ///
    /// This function also verifies the cryptographic signature of the standard.
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

    /// Checks the reputation of a user ID based on local proofs.
    /// Called by the GUI before transactions to display warnings.
    pub fn check_reputation(
        &self,
        offender_id: &str,
    ) -> Result<crate::models::conflict::TrustStatus, AppFacadeError> {
        Ok(self.get_wallet()?.check_reputation(offender_id))
    }

    /// Determines the identity of the sender of a voucher (possibly by decryption).
    pub fn get_voucher_source_sender(&self, local_instance_id: &str) -> Result<Option<String>, AppFacadeError> {
        let wallet = self.get_wallet()?;
        let identity = self.get_identity()?;
        wallet
            .get_voucher_source_sender(local_instance_id, &identity)
            .map_err(AppFacadeError::from)
    }

    /// Loads the event history of the wallet (BFF query).
    ///
    /// **Note Architecture/API:** Since this query updates the session timer (sliding window),
    /// it requires a mutable reference (`&mut self`). If the `AppService`
    /// is behind an `RwLock`, a write lock must be requested for this query!
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
        // We use the bypass to avoid having to generate a real signature for the test TOML.
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

        // Test serialization (should remain snake_case to preserve cryptographic stability)
        let json_str = serde_json::to_string(&standard).unwrap();
        
        // Check if fields are outputted in Rust-idiomatic snake_case
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


