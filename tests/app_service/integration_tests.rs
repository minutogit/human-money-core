use human_money_core::app_service::AppService;
use human_money_core::models::profile::PublicProfile;
use std::path::PathBuf;

#[test]
fn test_update_public_profile_locked() {
    let mut app_service = AppService::new(&PathBuf::from("/tmp/test")).unwrap();
    let profile = PublicProfile::default();
    let result = app_service.update_public_profile(profile, Some("password"));
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "Wallet is locked.");
}

#[test]
fn test_get_allowed_signature_roles_from_standard() {
    let app_service = AppService::new(&PathBuf::from("/tmp/test")).unwrap();
    
    #[cfg(feature = "test-utils")]
    human_money_core::set_signature_bypass(true);

    let valid_toml = include_str!("../test_data/standards/standard_required_signatures.toml");

    let result = app_service.get_allowed_signature_roles_from_standard(valid_toml);
    match result {
        Ok(roles) => assert!(roles.contains(&"Official Approver".to_string())),
        Err(e) => panic!("Failed: {}", e),
    }
}

#[test]
fn test_get_public_profile_locked() {
    let app_service = AppService::new(&PathBuf::from("/tmp/test")).unwrap();
    let result = app_service.get_public_profile();
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "Wallet is locked.");
}

#[test]
fn test_is_wallet_unlocked() {
    let app_service = AppService::new(&PathBuf::from("/tmp/test")).unwrap();
    assert!(!app_service.is_wallet_unlocked());
}

#[test]
fn test_open_voucher_signing_request_locked() {
    let app_service = AppService::new(&PathBuf::from("/tmp/test")).unwrap();
    let result = app_service.open_voucher_signing_request(&[], None);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "Wallet is locked");
}
