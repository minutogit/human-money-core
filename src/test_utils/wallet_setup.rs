use crate::app_service::{AppService, ProfileInfo};
use crate::models::conflict::{CanonicalMetadataStore, KnownFingerprints, OwnFingerprints, ProofStore};
use crate::models::profile::{BundleMetadataStore, PublicProfile, UserProfile, VoucherStore};
use crate::models::voucher::{Address, ValueDefinition};
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::crypto::{create_user_id, generate_ed25519_keypair_for_tests, get_hash};
use crate::services::mnemonic::MnemonicLanguage;
use crate::services::utils::to_canonical_json;
use crate::services::bundle_processor;
use super::ACTORS;
use super::voucher_setup::{create_guarantor_signature_data, create_voucher_for_manipulation};
use crate::wallet::Wallet;
use crate::{UserIdentity, VoucherCoreError, VoucherInstance, VoucherStatus, models::signature::DetachedSignature, models::voucher::Voucher};
use std::path::Path;

#[allow(dead_code)]
pub fn setup_in_memory_wallet(identity: &UserIdentity) -> Wallet {
    let profile = UserProfile {
        user_id: identity.user_id.clone(),
        ..Default::default()
    };
    Wallet {
        profile,
        voucher_store: VoucherStore::default(),
        bundle_meta_store: BundleMetadataStore::default(),
        known_fingerprints: KnownFingerprints::default(),
        own_fingerprints: OwnFingerprints::default(),
        proof_store: ProofStore::default(),
        fingerprint_metadata: CanonicalMetadataStore::default(),
        local_instance_id: "memory-instance".to_string(),
        pending_events: Vec::new(),
        loaded_generation: 0,
    }
}

#[allow(dead_code)]
pub fn create_test_wallet(
    seed_phrase_extra: &str,
    local_instance_id: String,
) -> Result<(Wallet, UserIdentity), VoucherCoreError> {
    let (public_key, signing_key) = generate_ed25519_keypair_for_tests(Some(seed_phrase_extra));
    let user_id = create_user_id(&public_key, Some("test"))
        .map_err(|e| VoucherCoreError::Crypto(e.to_string()))?;

    let identity = UserIdentity {
        signing_key,
        public_key,
        user_id: user_id.clone(),
    };

    let profile = UserProfile {
        user_id,
        ..Default::default()
    };

    let wallet = Wallet {
        profile,
        voucher_store: VoucherStore::default(),
        bundle_meta_store: BundleMetadataStore::default(),
        known_fingerprints: KnownFingerprints::default(),
        own_fingerprints: OwnFingerprints::default(),
        proof_store: ProofStore::default(),
        fingerprint_metadata: CanonicalMetadataStore::default(),
        local_instance_id,
        pending_events: Vec::new(),
        loaded_generation: 0,
    };

    Ok((wallet, identity))
}

#[allow(dead_code)]
pub fn add_voucher_to_wallet(
    wallet: &mut Wallet,
    identity: &UserIdentity,
    amount: &str,
    standard: &VoucherStandardDefinition,
    with_valid_guarantors: bool,
) -> Result<String, VoucherCoreError> {
    let creator_info = PublicProfile {
        id: Some(identity.user_id.clone()),
        first_name: Some("Test".to_string()),
        last_name: Some("User".to_string()),
        address: Some(Address::default()),
        ..Default::default()
    };

    let nominal_value_info = ValueDefinition {
        amount: amount.to_string(),
        ..Default::default()
    };

    let new_voucher_data = crate::models::voucher::NewVoucherData {
        creator_profile: creator_info,
        nominal_value: nominal_value_info,
        validity_duration: Some("P4Y".to_string()),
        ..Default::default()
    };

    let standard_hash = get_hash(to_canonical_json(&standard.immutable)?);

    let mut voucher = create_voucher_for_manipulation(
        new_voucher_data,
        standard,
        &standard_hash,
        &identity.signing_key,
    );

    if with_valid_guarantors {
        let sig_data1 = create_guarantor_signature_data(
            &ACTORS.guarantor1.identity,
            "1",
            &voucher.voucher_id,
        );
        let sig_data2 = create_guarantor_signature_data(
            &ACTORS.guarantor2.identity,
            "2",
            &voucher.voucher_id,
        );

        let details1 = match &sig_data1 {
            DetachedSignature::Signature(s) => s.details.clone(),
        };
        let details2 = match &sig_data2 {
            DetachedSignature::Signature(s) => s.details.clone(),
        };

        let init_t_id = &voucher.transactions[0].t_id;

        let signed_sig1 = sig_data1.complete_and_sign(
            &ACTORS.guarantor1.identity,
            details1,
            &voucher.voucher_id,
            init_t_id,
        )?;
        let signed_sig2 = sig_data2.complete_and_sign(
            &ACTORS.guarantor2.identity,
            details2,
            &voucher.voucher_id,
            init_t_id,
        )?;

        let DetachedSignature::Signature(s1) = signed_sig1;
        let DetachedSignature::Signature(s2) = signed_sig2;
        voucher.signatures.push(s1);
        voucher.signatures.push(s2);
    }

    let local_id = Wallet::calculate_local_instance_id(&voucher, &identity.user_id)?;
    let status = if with_valid_guarantors {
        VoucherStatus::Active
    } else {
        VoucherStatus::Incomplete {
            reasons: vec![crate::ValidationFailureReason::RequiredSignatureMissing {
                role_description: "Missing guarantors in test setup".to_string(),
            }],
        }
    };

    wallet.voucher_store.vouchers.insert(
        local_id.clone(),
        VoucherInstance {
            voucher: voucher.clone(),
            status,
            local_instance_id: local_id.clone(),
        },
    );

    Ok(local_id.clone())
}

#[allow(dead_code)]
pub fn setup_service_with_profile(
    base_path: &Path,
    user: &crate::test_utils::actors::TestUser,
    profile_name: &str,
    password: &str,
) -> (AppService, ProfileInfo) {
    let mut service =
        AppService::new(base_path).expect("Failed to create AppService in test setup");

    service
        .create_profile(
            profile_name,
            &user.mnemonic,
            user.passphrase,
            user.prefix,
            password,
            MnemonicLanguage::English,
            "test-id".to_string(),
        )
        .unwrap_or_else(|e| {
            panic!(
                "Failed to create profile '{}' in test setup: {}",
                profile_name, e
            )
        });

    let profile_info = service
        .list_profiles()
        .expect("Failed to list profiles after creation")
        .into_iter()
        .find(|p| p.profile_name == profile_name)
        .expect("Could not find freshly created profile in index");

    (service, profile_info)
}

#[allow(dead_code)]
pub fn debug_open_container(
    container_bytes: &[u8],
    recipient_identity: &UserIdentity,
) -> Result<Voucher, VoucherCoreError> {
    let container: crate::models::secure_container::SecureContainer =
        serde_json::from_slice(container_bytes)?;
    let payload = container.open(recipient_identity, None)?;
    let voucher: Voucher = serde_json::from_slice(&payload)?;
    Ok(voucher)
}

#[allow(dead_code)]
pub fn create_test_bundle(
    sender_identity: &UserIdentity,
    vouchers: Vec<Voucher>,
    recipient_id: &str,
    message: Option<&str>,
) -> Result<Vec<u8>, VoucherCoreError> {
    let result = bundle_processor::create_and_encrypt_bundle(
        sender_identity,
        vouchers,
        recipient_id,
        message.map(|s| s.to_string()),
        Vec::new(),
        std::collections::HashMap::new(),
        None,
    )?;
    Ok(result.0)
}
