use crate::models::profile::PublicProfile;
use crate::models::signature::DetachedSignature;
use crate::models::voucher::{Collateral, Transaction, ValueDefinition, Voucher, VoucherSignature};
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::crypto_utils::{self, get_hash, get_hash_from_slices, sign_ed25519};
use crate::services::utils::{to_canonical_json};
use crate::services::voucher_manager::{create_transaction, NewVoucherData};
use super::{ACTORS};
use crate::{UserIdentity, VoucherCoreError};
use ed25519_dalek::SigningKey;

#[allow(dead_code)]
pub fn setup_voucher_with_one_tx() -> (
    &'static VoucherStandardDefinition,
    String,
    &'static UserIdentity,
    &'static UserIdentity,
    Voucher,
    crate::services::voucher_manager::TransactionSecrets,
) {
    let (standard, standard_hash) = (
        &super::standards::FREETALER_STANDARD.0,
        &super::standards::FREETALER_STANDARD.1,
    );
    let creator = &ACTORS.alice.identity;
    let recipient = &ACTORS.bob.identity;

    let voucher_data = NewVoucherData {
        creator_profile: PublicProfile {
            id: Some(creator.user_id.clone()),
            ..Default::default()
        },
        nominal_value: ValueDefinition {
            amount: "100.00".to_string(),
            ..Default::default()
        },
        validity_duration: Some("P4Y".to_string()),
        ..Default::default()
    };

    let initial_voucher = crate::services::voucher_manager::create_voucher(
        voucher_data,
        standard,
        standard_hash,
        &creator.signing_key,
        "en",
    )
    .unwrap();

    let holder_key = derive_holder_key(&initial_voucher, &creator.signing_key);
    let (voucher_after_tx1, secrets) = create_transaction(
        &initial_voucher,
        standard,
        &creator.user_id,
        &creator.signing_key,
        &holder_key,
        &recipient.user_id,
        "40.00",
        None,
    )
    .unwrap();

    (
        standard,
        standard_hash.to_string(),
        creator,
        recipient,
        voucher_after_tx1,
        secrets,
    )
}

pub fn create_transaction_with_auto_decrypt(
    voucher: &Voucher,
    standard: &VoucherStandardDefinition,
    sender_id: &str,
    sender_permanent_key: &SigningKey,
    sender_ephemeral_key: &SigningKey,
    recipient_id: &str,
    _recipient_permanent_key: &SigningKey,
    amount: &str,
) -> Result<(Voucher, SigningKey), VoucherCoreError> {
    let (new_voucher, secrets) = create_transaction(
        voucher,
        standard,
        sender_id,
        sender_permanent_key,
        sender_ephemeral_key,
        recipient_id,
        amount,
        None,
    )?;

    let seed_bytes = bs58::decode(secrets.recipient_seed)
        .into_vec()
        .map_err(|e| VoucherCoreError::Crypto(format!("Invalid seed base58: {}", e)))?;

    let seed_arr: [u8; 32] = seed_bytes.try_into().expect("Seed must be 32 bytes");
    let next_key = SigningKey::from_bytes(&seed_arr);

    Ok((new_voucher, next_key))
}

pub fn create_guarantor_signature_data(
    guarantor_identity: &UserIdentity,
    gender: &str,
    voucher_id: &str,
) -> DetachedSignature {
    let data = VoucherSignature {
        voucher_id: voucher_id.to_string(),
        signer_id: guarantor_identity.user_id.clone(),
        role: "guarantor".to_string(),
        details: Some(PublicProfile {
            first_name: Some("Guarantor".to_string()),
            last_name: Some("Test".to_string()),
            gender: Some(gender.to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };
    DetachedSignature::Signature(data)
}

#[allow(dead_code)]
pub fn create_additional_signature_data(
    signer_identity: &UserIdentity,
    description: &str,
) -> DetachedSignature {
    let data = VoucherSignature {
        signer_id: signer_identity.user_id.clone(),
        role: description.to_string(),
        ..Default::default()
    };
    DetachedSignature::Signature(data)
}

#[allow(dead_code)]
pub fn create_additional_signature_data_with_voucher_id(
    signer_identity: &UserIdentity,
    description: &str,
    voucher_id: &str,
) -> DetachedSignature {
    let data = VoucherSignature {
        voucher_id: voucher_id.to_string(),
        signer_id: signer_identity.user_id.clone(),
        role: description.to_string(),
        ..Default::default()
    };
    DetachedSignature::Signature(data)
}

#[allow(dead_code)]
pub fn create_minuto_voucher_data(creator_profile: PublicProfile) -> NewVoucherData {
    NewVoucherData {
        validity_duration: Some("P4Y".to_string()),
        non_redeemable_test_voucher: true,
        nominal_value: ValueDefinition {
            unit: "".to_string(),
            amount: "60".to_string(),
            abbreviation: Some("".to_string()),
            description: Some("Qualitative Leistung".to_string()),
        },
        collateral: Some(Collateral {
            value: ValueDefinition {
                unit: "".to_string(),
                amount: "".to_string(),
                abbreviation: Some("".to_string()),
                description: Some("".to_string()),
            },
            collateral_type: Some("".to_string()),
            redeem_condition: Some("".to_string()),
        }),
        creator_profile,
    }
}

#[allow(dead_code)]
pub fn create_voucher_for_manipulation(
    data: NewVoucherData,
    standard: &VoucherStandardDefinition,
    standard_hash: &str,
    signing_key: &SigningKey,
    lang_preference: &str,
) -> Voucher {
    let creation_date_str = crate::services::utils::get_current_timestamp();
    let creation_dt = chrono::DateTime::parse_from_rfc3339(&creation_date_str).unwrap();
    let duration_str = data.validity_duration.as_deref().unwrap_or_else(|| {
        panic!(
            "Test voucher creation requires a validity_duration. Voucher details: creator='{}', amount='{}'",
            data.creator_profile.id.as_ref().unwrap_or(&"N/A".to_string()), data.nominal_value.amount
        )
    });
    let mut valid_until_dt =
        crate::services::voucher_manager::add_iso8601_duration(creation_dt.into(), duration_str)
            .expect("Failed to calculate validity in test helper");

    if let Some(rule) = &standard.mutable.app_config.round_up_validity_to {
        if rule == "end_of_year" {
            use chrono::{Datelike, TimeZone};
            let rounded_date =
                chrono::NaiveDate::from_ymd_opt(valid_until_dt.year(), 12, 31).unwrap();
            let rounded_time = chrono::NaiveTime::from_hms_micro_opt(23, 59, 59, 999_999).unwrap();
            valid_until_dt = chrono::Utc.from_utc_datetime(&rounded_date.and_time(rounded_time));
        }
    }

    let valid_until = valid_until_dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);

    let mut nonce_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
    let voucher_nonce = bs58::encode(nonce_bytes).into_string();

    let description_template = crate::services::standard_manager::get_localized_text(
        &standard.mutable.i18n.descriptions,
        lang_preference,
    )
    .unwrap_or("");
    let final_description = description_template.replace("{{amount}}", &data.nominal_value.amount);

    let mut final_nominal_value = data.nominal_value;
    final_nominal_value.unit = standard.immutable.blueprint.unit.clone();
    final_nominal_value.abbreviation = Some(standard.immutable.identity.abbreviation.clone());

    let final_collateral = Some(Collateral {
        value: ValueDefinition {
            unit: data
                .collateral
                .as_ref()
                .map_or(String::new(), |c| c.value.unit.clone()),
            amount: data
                .collateral
                .as_ref()
                .map_or(String::new(), |c| c.value.amount.clone()),
            abbreviation: data
                .collateral
                .as_ref()
                .and_then(|c| c.value.abbreviation.clone()),
            description: data
                .collateral
                .as_ref()
                .and_then(|c| c.value.description.clone()),
        },
        collateral_type: serde_json::to_value(&standard.immutable.blueprint.collateral_type)
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string())),
        redeem_condition: None,
    });

    let mut voucher = Voucher {
        voucher_standard: crate::models::voucher::VoucherStandard {
            name: standard.immutable.identity.name.clone(),
            uuid: standard.immutable.identity.uuid.clone(),
            standard_definition_hash: standard_hash.to_string(),
            template: crate::models::voucher::VoucherTemplateData {
                description: final_description,
                primary_redemption_type: serde_json::to_value(&standard.immutable.blueprint.primary_redemption_type)
                    .ok()
                    .and_then(|v| v.as_str().map(|s| s.to_string()))
                    .unwrap_or_default(),
                allow_partial_transfers: standard.immutable.features.allow_partial_transfers,
                issuance_minimum_validity_duration: standard.immutable.issuance.issuance_minimum_validity_duration.clone(),
                footnote: crate::services::standard_manager::get_localized_text(&standard.mutable.i18n.footnotes, lang_preference).unwrap_or("").to_string(),
            },
        },
        voucher_id: "".to_string(),
        voucher_nonce,
        creation_date: creation_date_str.clone(),
        valid_until: valid_until.clone(),
        non_redeemable_test_voucher: false,
        nominal_value: final_nominal_value,
        collateral: final_collateral,
        creator_profile: data.creator_profile,
        transactions: vec![],
        signatures: vec![],
    };

    let voucher_json = to_canonical_json(&voucher).unwrap();
    let voucher_hash = crypto_utils::get_hash(voucher_json);
    voucher.voucher_id = voucher_hash.clone();

    let prefix = voucher
        .creator_profile
        .id
        .as_ref()
        .and_then(|id| crypto_utils::get_prefix_from_user_id(id));

    let (genesis_secret, genesis_public) = crypto_utils::derive_ephemeral_key_pair(
        signing_key,
        &nonce_bytes,
        "genesis",
        prefix,
    )
    .expect("Failed to derive genesis key");
    let genesis_pub_str = bs58::encode(genesis_public.to_bytes()).into_string();

    let (_, holder_public) =
        crypto_utils::derive_ephemeral_key_pair(signing_key, &nonce_bytes, "holder", prefix)
            .expect("Failed to derive holder key");
    let holder_anchor_hash = crypto_utils::get_hash(holder_public.to_bytes());

    let prev_hash = {
        let v_id_bytes = bs58::decode(&voucher.voucher_id)
            .into_vec()
            .expect("Invalid voucher_id");
        let v_nonce_bytes = bs58::decode(&voucher.voucher_nonce)
            .into_vec()
            .expect("Invalid voucher_nonce");
        get_hash_from_slices(&[&v_id_bytes, &v_nonce_bytes])
    };

    let mut init_tx = Transaction {
        t_id: "".to_string(),
        prev_hash,
        t_type: "init".to_string(),
        t_time: creation_date_str.clone(),
        sender_id: Some(voucher.creator_profile.id.as_ref().unwrap().clone()),
        recipient_id: voucher.creator_profile.id.as_ref().unwrap().clone(),
        amount: voucher.nominal_value.amount.clone(),
        sender_remaining_amount: None,
        sender_identity_signature: None,
        receiver_ephemeral_pub_hash: Some(holder_anchor_hash),
        sender_ephemeral_pub: Some(genesis_pub_str.clone()),
        change_ephemeral_pub_hash: None,
        privacy_guard: None,
        trap_data: None,
        layer2_signature: None,
        deletable_at: Some(valid_until.clone()),
    };

    let tx_json_for_id = to_canonical_json(&init_tx).unwrap();
    let init_t_id = get_hash(tx_json_for_id);
    init_tx.t_id = init_t_id.clone();

    let mut creator_sig_obj = VoucherSignature {
        voucher_id: voucher_hash.clone(),
        signature_id: "".to_string(),
        signer_id: voucher.creator_profile.id.as_ref().unwrap().clone(),
        signature: "".to_string(),
        signature_time: creation_date_str.clone(),
        role: "creator".to_string(),
        details: None,
    };

    creator_sig_obj.signature_id = get_hash_from_slices(&[
        to_canonical_json(&creator_sig_obj).unwrap().as_bytes(),
        init_t_id.as_bytes(),
    ]);

    let digital_signature =
        crypto_utils::sign_ed25519(signing_key, creator_sig_obj.signature_id.as_bytes());
    creator_sig_obj.signature = bs58::encode(digital_signature.to_bytes()).into_string();

    voucher.signatures.push(creator_sig_obj);

    let v_id = crate::services::l2_gateway::calculate_layer2_voucher_id(&init_tx)
        .expect("Failed to calculate v_id");
    voucher.transactions.push(resign_transaction_ext(
        init_tx,
        signing_key,
        &v_id,
        Some(&genesis_secret),
    ));

    voucher
}

#[allow(dead_code)]
pub fn create_guarantor_signature_with_time(
    voucher: &Voucher,
    guarantor_identity: &UserIdentity,
    guarantor_first_name: &str,
    role: &str,
    guarantor_gender: &str,
    signature_time: &str,
) -> VoucherSignature {
    let mut signature_data = VoucherSignature {
        voucher_id: voucher.voucher_id.clone(),
        signature_id: "".to_string(),
        signer_id: guarantor_identity.user_id.clone(),
        signature_time: signature_time.to_string(),
        role: role.to_string(),
        details: Some(PublicProfile {
            first_name: Some(guarantor_first_name.to_string()),
            last_name: Some("Guarantor".to_string()),
            gender: Some(guarantor_gender.to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let mut data_for_id_hash = signature_data.clone();
    data_for_id_hash.signature_id = "".to_string();
    data_for_id_hash.signature = "".to_string();

    let init_t_id = &voucher.transactions[0].t_id;
    signature_data.signature_id = get_hash_from_slices(&[
        to_canonical_json(&data_for_id_hash).unwrap().as_bytes(),
        init_t_id.as_bytes(),
    ]);

    let digital_signature = sign_ed25519(
        &guarantor_identity.signing_key,
        signature_data.signature_id.as_bytes(),
    );
    signature_data.signature = bs58::encode(digital_signature.to_bytes()).into_string();
    signature_data
}

#[allow(dead_code)]
pub fn create_guarantor_signature(
    voucher: &Voucher,
    guarantor_identity: &UserIdentity,
    guarantor_first_name: &str,
    role: &str,
    guarantor_gender: &str,
) -> VoucherSignature {
    let creation_dt = chrono::DateTime::parse_from_rfc3339(&voucher.creation_date).unwrap();
    let signature_time = (creation_dt + chrono::Duration::days(1)).to_rfc3339();
    create_guarantor_signature_with_time(
        voucher,
        guarantor_identity,
        guarantor_first_name,
        role,
        guarantor_gender,
        &signature_time,
    )
}

#[allow(dead_code)]
pub fn create_male_guarantor_signature(voucher: &Voucher) -> VoucherSignature {
    create_guarantor_signature(
        voucher,
        &ACTORS.male_guarantor.identity,
        "Martin",
        "guarantor",
        "1",
    )
}

#[allow(dead_code)]
pub fn create_female_guarantor_signature(voucher: &Voucher) -> VoucherSignature {
    create_guarantor_signature(
        voucher,
        &ACTORS.female_guarantor.identity,
        "Frida",
        "guarantor",
        "2",
    )
}

#[allow(dead_code)]
pub fn resign_transaction(
    tx: Transaction,
    signer_key: &SigningKey,
    v_id: &str,
) -> Transaction {
    resign_transaction_ext(tx, signer_key, v_id, None)
}

#[allow(dead_code)]
pub fn resign_transaction_ext(
    mut tx: Transaction,
    signer_key: &SigningKey,
    v_id: &str,
    l2_signer_key: Option<&SigningKey>,
) -> Transaction {
    tx.t_id = "".to_string();
    tx.layer2_signature = None;
    tx.sender_identity_signature = None;

    tx.t_id = get_hash(to_canonical_json(&tx).unwrap());

    let t_id_raw = bs58::decode(&tx.t_id).into_vec().unwrap();

    let sender_pub_raw = tx
        .sender_ephemeral_pub
        .as_ref()
        .map(|s| bs58::decode(s).into_vec().unwrap_or_default())
        .unwrap_or_default();
    let receiver_hash_raw = tx
        .receiver_ephemeral_pub_hash
        .as_ref()
        .map(|h| bs58::decode(h).into_vec().unwrap());
    let change_hash_raw = tx
        .change_ephemeral_pub_hash
        .as_ref()
        .map(|h| bs58::decode(h).into_vec().unwrap());

    let challenge_ds_tag = if tx.t_type == "init" {
        tx.t_id.clone()
    } else {
        tx.trap_data
            .as_ref()
            .map(|td| td.ds_tag.clone())
            .unwrap_or_else(|| tx.t_id.clone())
    };

    let to_32_bytes = |vec: Vec<u8>| -> [u8; 32] { vec[..32].try_into().unwrap() };

    let payload_hash = crate::services::l2_gateway::calculate_l2_payload_hash_raw(
        &challenge_ds_tag,
        v_id,
        &to_32_bytes(t_id_raw.clone()),
        &to_32_bytes(sender_pub_raw),
        receiver_hash_raw
            .as_ref()
            .map(|v| to_32_bytes(v.clone()))
            .as_ref(),
        change_hash_raw
            .as_ref()
            .map(|v| to_32_bytes(v.clone()))
            .as_ref(),
        tx.deletable_at.as_deref(),
    );

    let proof_key = l2_signer_key.unwrap_or(signer_key);
    let l2_sig = crypto_utils::sign_ed25519(proof_key, &payload_hash);
    tx.layer2_signature = Some(bs58::encode(l2_sig.to_bytes()).into_string());

    if tx.sender_id.is_some() {
        let identity_sig = crypto_utils::sign_ed25519(signer_key, &t_id_raw);
        tx.sender_identity_signature = Some(bs58::encode(identity_sig.to_bytes()).into_string());
    }

    tx
}

pub fn attach_privacy_guard(tx: &mut Transaction, recipient_id: &str, sender_id: &str) {
    let payload = crate::models::voucher::RecipientPayload {
        sender_permanent_did: sender_id.to_string(),
        target_prefix: recipient_id.split(':').next().unwrap_or("").to_string(),
        timestamp: chrono::Utc::now().timestamp() as u64,
        next_key_seed: "test_seed_123".to_string(),
        ..Default::default()
    };
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let recipient_pubkey = crypto_utils::get_pubkey_from_user_id(recipient_id).unwrap();

    tx.privacy_guard = Some(crypto_utils::encrypt_recipient_payload(
        &payload_bytes,
        &recipient_pubkey,
        recipient_id,
    ).unwrap());
}

#[allow(dead_code)]
pub fn resign_transaction_with_privacy(
    mut tx: Transaction,
    signer_key: &SigningKey,
    v_id: &str,
    l2_signer_key: Option<&SigningKey>,
    recipient_id: &str,
) -> Transaction {
    if tx.recipient_id == crate::models::voucher::ANONYMOUS_ID && tx.privacy_guard.is_none() {
        let sender_id = tx.sender_id.clone().unwrap_or_else(|| {
            crypto_utils::create_user_id(&signer_key.verifying_key(), Some("test")).unwrap()
        });
        attach_privacy_guard(&mut tx, recipient_id, &sender_id);
    }
    resign_transaction_ext(tx, signer_key, v_id, l2_signer_key)
}

pub fn derive_holder_key(
    voucher: &Voucher,
    creator_signing_key: &SigningKey,
) -> SigningKey {
    let nonce_bytes = bs58::decode(&voucher.voucher_nonce).into_vec().unwrap();
    let nonce_arr: [u8; 16] = nonce_bytes.try_into().unwrap();

    let prefix = voucher
        .creator_profile
        .id
        .as_ref()
        .and_then(|id| crypto_utils::get_prefix_from_user_id(id));

    let (holder_key, _) = crypto_utils::derive_ephemeral_key_pair(
        creator_signing_key,
        &nonce_arr,
        "holder",
        prefix,
    )
    .unwrap();
    holder_key
}
