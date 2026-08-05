//! # src/app_service/standard_container_handler.rs
//!
//! Handles On-Demand import, export, and inspection of `.standard` container files
//! containing `VoucherStandardDefinition` TOML files wrapped in a `SecureContainer`.

use super::{AppFacadeError, AppService, AppState};
use crate::models::profile::UserIdentity;
use crate::models::secure_container::{ContainerConfig, PayloadType, SecureContainer};
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::secure_container_manager::{create_secure_container, open_secure_container};
use crate::services::standard_manager::verify_and_parse_standard;
use std::fs;
use std::path::Path;

impl AppService {
    /// Exports a `VoucherStandardDefinition` (TOML content) as a serialized `SecureContainer` (`.standard` file).
    ///
    /// The container is signed by the active user's identity and wrapped according to `config`
    /// (Cleartext, Password, or TargetDid).
    ///
    /// # Arguments
    /// * `standard_toml` - The raw `standard.toml` content to export.
    /// * `config` - The encryption configuration (Cleartext, Password, etc.).
    ///
    /// # Returns
    /// Serialized JSON bytes of the `SecureContainer`.
    pub fn export_voucher_standard(
        &self,
        standard_toml: &str,
        config: ContainerConfig,
    ) -> Result<Vec<u8>, AppFacadeError> {
        // 1. Verify that the TOML content is a valid, signed standard definition.
        let _ = verify_and_parse_standard(standard_toml).map_err(AppFacadeError::from)?;

        // 2. Ensure wallet is unlocked to get sender identity.
        let identity = self.get_identity()?;

        // 3. Create the secure container with VoucherStandardDefinition payload type.
        let container = create_secure_container(
            identity,
            config,
            standard_toml.as_bytes(),
            PayloadType::VoucherStandardDefinition,
        )
        .map_err(AppFacadeError::from)?;

        // 4. Serialize container to JSON bytes.
        serde_json::to_vec(&container).map_err(|e| AppFacadeError::JsonError(e.to_string()))
    }

    /// Inspects a `.standard` container file (`SecureContainer` JSON bytes) without saving it.
    ///
    /// Opens the container, parses the internal TOML string, verifies its signature,
    /// and returns the parsed `VoucherStandardDefinition`.
    ///
    /// # Arguments
    /// * `container_bytes` - JSON-serialized `SecureContainer` bytes.
    /// * `password` - Optional password if the container is symmetrically encrypted.
    ///
    /// # Returns
    /// The verified `VoucherStandardDefinition`.
    pub fn inspect_voucher_standard_container(
        &self,
        container_bytes: &[u8],
        password: Option<&str>,
    ) -> Result<VoucherStandardDefinition, AppFacadeError> {
        let toml_str = match serde_json::from_slice::<SecureContainer>(container_bytes) {
            Ok(container) => {
                if container.c != PayloadType::VoucherStandardDefinition {
                    return Err(AppFacadeError::ValidationError(
                        "Invalid payload type: expected VoucherStandardDefinition".to_string(),
                    ));
                }

                let dummy_identity = UserIdentity::default();
                let identity = match &self.state {
                    AppState::Unlocked { identity, .. } => identity,
                    AppState::Locked => &dummy_identity,
                };

                let payload_bytes = open_secure_container(&container, identity, password)
                    .map_err(AppFacadeError::from)?;

                String::from_utf8(payload_bytes)
                    .map_err(|e| AppFacadeError::ValidationError(format!("Invalid UTF-8 in container payload: {}", e)))?
            }
            Err(_) => {
                String::from_utf8(container_bytes.to_vec())
                    .map_err(|e| AppFacadeError::ValidationError(format!("Invalid UTF-8 in standard file: {}", e)))?
            }
        };

        let (verified_standard, _) = verify_and_parse_standard(&toml_str).map_err(AppFacadeError::from)?;
        Ok(verified_standard)
    }

    /// Imports a `.standard` container file or a raw `standard.toml` file into `voucher_standards/`.
    ///
    /// The method opens the container or parses raw TOML, verifies the standard, extracts its UUID,
    /// creates the subdirectory `target_dir/<standard_uuid>/`, and writes `standard.toml`.
    ///
    /// # Arguments
    /// * `container_bytes` - JSON-serialized `SecureContainer` bytes OR raw UTF-8 `standard.toml` bytes.
    /// * `password` - Optional password if the container is symmetrically encrypted.
    /// * `target_dir` - Path to the `voucher_standards` base directory.
    ///
    /// # Returns
    /// The `uuid` string of the imported standard.
    pub fn import_voucher_standard(
        &self,
        container_bytes: &[u8],
        password: Option<&str>,
        target_dir: &Path,
    ) -> Result<String, AppFacadeError> {
        let toml_str = match serde_json::from_slice::<SecureContainer>(container_bytes) {
            Ok(container) => {
                if container.c != PayloadType::VoucherStandardDefinition {
                    return Err(AppFacadeError::ValidationError(
                        "Invalid payload type: expected VoucherStandardDefinition".to_string(),
                    ));
                }

                let dummy_identity = UserIdentity::default();
                let identity = match &self.state {
                    AppState::Unlocked { identity, .. } => identity,
                    AppState::Locked => &dummy_identity,
                };

                let payload_bytes = open_secure_container(&container, identity, password)
                    .map_err(AppFacadeError::from)?;

                String::from_utf8(payload_bytes)
                    .map_err(|e| AppFacadeError::ValidationError(format!("Invalid UTF-8 in container payload: {}", e)))?
            }
            Err(_) => {
                String::from_utf8(container_bytes.to_vec())
                    .map_err(|e| AppFacadeError::ValidationError(format!("Invalid UTF-8 in standard file: {}", e)))?
            }
        };

        let (verified_standard, _) = verify_and_parse_standard(&toml_str).map_err(AppFacadeError::from)?;
        let standard_uuid = verified_standard.immutable.identity.uuid;

        let standard_folder = target_dir.join(&standard_uuid);
        fs::create_dir_all(&standard_folder)
            .map_err(|e| AppFacadeError::StorageError(format!("Failed to create standard directory: {}", e)))?;

        let file_path = standard_folder.join("standard.toml");
        fs::write(&file_path, &toml_str)
            .map_err(|e| AppFacadeError::StorageError(format!("Failed to write standard.toml: {}", e)))?;

        Ok(standard_uuid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MnemonicLanguage;
    use std::path::PathBuf;

    fn setup_test_app(dir_name: &str) -> (AppService, PathBuf) {
        let temp_dir = std::env::temp_dir().join(dir_name);
        if temp_dir.exists() {
            let _ = fs::remove_dir_all(&temp_dir);
        }
        let _ = fs::create_dir_all(&temp_dir);

        let mut app = AppService::new(&temp_dir).unwrap();
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        app.create_profile(
            "Test Profile",
            mnemonic,
            None,
            Some("test"),
            "password123",
            MnemonicLanguage::English,
            "device-id".to_string(),
        )
        .unwrap();

        (app, temp_dir)
    }

    const SAMPLE_TOML: &str = r#"
[immutable.identity]
uuid = "test-standard-uuid-12345"
name = "Test Currency Standard"
abbreviation = "TCS"

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

    #[test]
    fn test_export_inspect_import_standard_cleartext() {
        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(true);

        let (app, temp_dir) = setup_test_app("test_standard_cleartext");
        let target_standards_dir = temp_dir.join("voucher_standards");

        // 1. Export standard as Cleartext
        let container_bytes = app
            .export_voucher_standard(SAMPLE_TOML, ContainerConfig::Cleartext)
            .expect("Export cleartext standard failed");
        assert!(!container_bytes.is_empty());

        // 2. Inspect standard
        let def = app
            .inspect_voucher_standard_container(&container_bytes, None)
            .expect("Inspect standard failed");
        assert_eq!(def.immutable.identity.uuid, "test-standard-uuid-12345");
        assert_eq!(def.immutable.identity.name, "Test Currency Standard");

        // 3. Import standard
        let uuid = app
            .import_voucher_standard(&container_bytes, None, &target_standards_dir)
            .expect("Import standard failed");
        assert_eq!(uuid, "test-standard-uuid-12345");

        // 4. Verify file on disk
        let saved_file = target_standards_dir
            .join("test-standard-uuid-12345")
            .join("standard.toml");
        assert!(saved_file.exists());
        let content = fs::read_to_string(&saved_file).unwrap();
        assert!(content.contains("test-standard-uuid-12345"));

        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(false);
    }

    #[test]
    fn test_export_inspect_import_standard_password() {
        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(true);

        let (app, temp_dir) = setup_test_app("test_standard_password");
        let target_standards_dir = temp_dir.join("voucher_standards");

        // 1. Export with Password
        let password = "SecretStandardPassword123";
        let container_bytes = app
            .export_voucher_standard(SAMPLE_TOML, ContainerConfig::Password(password.to_string()))
            .expect("Export password standard failed");

        // 2. Inspect with wrong password should fail
        let wrong_inspect = app.inspect_voucher_standard_container(&container_bytes, Some("WrongPassword"));
        assert!(wrong_inspect.is_err());

        // 3. Inspect with correct password
        let def = app
            .inspect_voucher_standard_container(&container_bytes, Some(password))
            .expect("Inspect with correct password failed");
        assert_eq!(def.immutable.identity.uuid, "test-standard-uuid-12345");

        // 4. Import with correct password
        let uuid = app
            .import_voucher_standard(&container_bytes, Some(password), &target_standards_dir)
            .expect("Import with correct password failed");
        assert_eq!(uuid, "test-standard-uuid-12345");

        let saved_file = target_standards_dir
            .join("test-standard-uuid-12345")
            .join("standard.toml");
        assert!(saved_file.exists());

        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(false);
    }

    #[test]
    fn test_inspect_invalid_payload_type() {
        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(true);

        let (app, _) = setup_test_app("test_standard_invalid_payload");
        let identity = app.get_identity().unwrap();

        // Create container with VoucherForSigning payload type instead of VoucherStandardDefinition
        let container = create_secure_container(
            identity,
            ContainerConfig::Cleartext,
            SAMPLE_TOML.as_bytes(),
            PayloadType::VoucherForSigning,
        )
        .unwrap();
        let bytes = serde_json::to_vec(&container).unwrap();

        let result = app.inspect_voucher_standard_container(&bytes, None);
        assert!(result.is_err());
        if let Err(AppFacadeError::ValidationError(msg)) = result {
            assert!(msg.contains("Invalid payload type"));
        } else {
            panic!("Expected ValidationError for invalid payload type");
        }

        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(false);
    }

    #[test]
    fn test_inspect_import_raw_toml() {
        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(true);

        let (app, temp_dir) = setup_test_app("test_standard_raw_toml");
        let target_standards_dir = temp_dir.join("voucher_standards");

        let raw_toml_bytes = SAMPLE_TOML.as_bytes();

        // 1. Inspect raw TOML bytes directly
        let def = app
            .inspect_voucher_standard_container(raw_toml_bytes, None)
            .expect("Inspect raw TOML failed");
        assert_eq!(def.immutable.identity.uuid, "test-standard-uuid-12345");

        // 2. Import raw TOML bytes directly
        let uuid = app
            .import_voucher_standard(raw_toml_bytes, None, &target_standards_dir)
            .expect("Import raw TOML failed");
        assert_eq!(uuid, "test-standard-uuid-12345");

        // 3. Verify file saved on disk
        let saved_file = target_standards_dir
            .join("test-standard-uuid-12345")
            .join("standard.toml");
        assert!(saved_file.exists());

        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(false);
    }
}
