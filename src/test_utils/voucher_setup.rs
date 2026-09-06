use crate::models::profile::PublicProfile;
use crate::models::signature::DetachedSignature;
use crate::models::voucher::{
    Collateral, NewVoucherData, Transaction, TransactionSecrets, ValueDefinition, Voucher,
    VoucherSignature,
};
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::models::conflict::TransactionFingerprint;
use crate::services::crypto::{self, get_hash, get_hash_from_slices, sign_ed25519};
use crate::services::utils::{get_timestamp, to_canonical_json};
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
    TransactionSecrets,
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

    let initial_voucher = Voucher::create_with_key(
        voucher_data,
        standard,
        standard_hash,
        &creator.signing_key,
    )
    .unwrap();

    let holder_key = derive_holder_key(&initial_voucher, &creator.signing_key);
    let (voucher_after_tx1, secrets) = initial_voucher.create_transaction(
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

#[allow(clippy::too_many_arguments)]
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
    let (new_voucher, secrets) = voucher.create_transaction(
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
        crate::services::utils::add_iso8601_duration(creation_dt.into(), duration_str)
            .expect("Failed to calculate validity in test helper");

    if let Some(rule) = &standard.mutable.app_config.round_up_validity_to
        && let Ok(rounded) = crate::services::utils::round_up_date(valid_until_dt, rule)
    {
        valid_until_dt = rounded;
    }

    let valid_until = valid_until_dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);

    let mut nonce_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
    let voucher_nonce = bs58::encode(nonce_bytes).into_string();

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
    let voucher_hash = crypto::get_hash(voucher_json);
    voucher.voucher_id = voucher_hash.clone();

    let prefix = voucher
        .creator_profile
        .id
        .as_ref()
        .and_then(|id| crypto::get_prefix_from_user_id(id));

    let (genesis_secret, genesis_public) = crypto::derive_ephemeral_key_pair(
        signing_key,
        &nonce_bytes,
        "genesis",
        prefix,
    )
    .expect("Failed to derive genesis key");
    let genesis_pub_str = bs58::encode(genesis_public.to_bytes()).into_string();

    let (_, holder_public) =
        crypto::derive_ephemeral_key_pair(signing_key, &nonce_bytes, "holder", prefix)
            .expect("Failed to derive holder key");
    let holder_anchor_hash = crypto::get_hash(holder_public.to_bytes());

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
        crypto::sign_ed25519(signing_key, creator_sig_obj.signature_id.as_bytes());
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
    // V3 Protocol (audit_02_11): the voucher id is signature-bound again.
    // Genesis transactions sign the canonical "none" placeholder.
    v_id: &str,
    l2_signer_key: Option<&SigningKey>,
) -> Transaction {
    // V3 Protocol (SST): the t_id preimage excludes `trap_data` and
    // `privacy_guard` — both are attached only after t_id computation at
    // creation time, and validators blank them before hashing as well. The
    // trap shards AND the privacy guard are restored afterwards so the signed
    // tx still carries them.
    let stored_trap_data = tx.trap_data.take();
    let stored_privacy_guard = tx.privacy_guard.take();
    tx.t_id = "".to_string();
    tx.layer2_signature = None;
    tx.sender_identity_signature = None;

    tx.t_id = get_hash(to_canonical_json(&tx).unwrap());

    tx.trap_data = stored_trap_data;
    tx.privacy_guard = stored_privacy_guard;

    let t_id_raw = bs58::decode(&tx.t_id).into_vec().unwrap();

    let sender_pub_raw = tx
        .sender_ephemeral_pub
        .as_ref()
        .map(|s| bs58::decode(s).into_vec().unwrap_or_default())
        .unwrap_or_default();

    let challenge_ds_tag = if tx.t_type == "init" {
        tx.t_id.clone()
    } else {
        tx.trap_data
            .as_ref()
            .map(|td| td.ds_tag.clone())
            .unwrap_or_else(|| tx.t_id.clone())
    };

    let to_32_bytes = |vec: Vec<u8>| -> [u8; 32] { vec[..32].try_into().unwrap() };

    // V3 Protocol (HMC_TX_AUTH_V3): bind trap shards + encrypted timestamp.
    let (trap_r, trap_s) = match &tx.trap_data {
        Some(td) => (td.trap_r.as_str(), td.trap_s.as_str()),
        None => (
            crate::services::l2_gateway::TRAP_NONE_PLACEHOLDER,
            crate::services::l2_gateway::TRAP_NONE_PLACEHOLDER,
        ),
    };
    let encrypted_timestamp =
        crate::services::conflict_manager::encrypt_transaction_timestamp(&tx)
            .unwrap_or(0);

    let payload_hash = crate::services::l2_gateway::calculate_l2_payload_hash_raw(
        if tx.t_type == "init" {
            crate::services::l2_gateway::TRAP_NONE_PLACEHOLDER
        } else {
            v_id
        },
        &challenge_ds_tag,
        &to_32_bytes(t_id_raw.clone()),
        &to_32_bytes(sender_pub_raw),
        trap_r,
        trap_s,
        encrypted_timestamp,
        tx.deletable_at.as_deref(),
        &crate::services::l2_gateway::privacy_guard_commitment(tx.privacy_guard.as_deref()),
    );

    let proof_key = l2_signer_key.unwrap_or(signer_key);
    let l2_sig = crypto::sign_ed25519(proof_key, &payload_hash);
    tx.layer2_signature = Some(bs58::encode(l2_sig.to_bytes()).into_string());

    if tx.sender_id.is_some() {
        let identity_sig = crypto::sign_ed25519(signer_key, &t_id_raw);
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
    let recipient_pubkey = crypto::get_pubkey_from_user_id(recipient_id).unwrap();

    tx.privacy_guard = Some(crypto::encrypt_recipient_payload(
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
            crypto::create_user_id(&signer_key.verifying_key(), Some("test")).unwrap()
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
        .and_then(|id| crypto::get_prefix_from_user_id(id));

    let (holder_key, _) = crypto::derive_ephemeral_key_pair(
        creator_signing_key,
        &nonce_arr,
        "holder",
        prefix,
    )
    .unwrap();
    holder_key
}

/// Creates a fully self-authenticating (V3) gossip fingerprint for tests.
///
/// The fingerprint carries a valid `layer2_signature` over the canonical
/// `HMC_TX_AUTH_V3` digest, signed by a freshly generated ephemeral key that
/// is revealed in `sender_ephemeral_pub` — exactly like fingerprints created
/// from real spend transactions.
#[allow(dead_code)]
pub fn make_signed_fingerprint(
    ds_tag: &str,
    t_id: &str,
    encrypted_timestamp: u128,
) -> TransactionFingerprint {
    use crate::services::l2_gateway::calculate_l2_payload_hash_raw;
    use rand::RngCore;

    // Use the caller-provided t_id when it is a valid base58-32 hash;
    // otherwise fall back to a random one.
    let t_id_bytes: [u8; 32] = match bs58::decode(t_id).into_vec() {
        Ok(v) if v.len() == 32 => v.try_into().unwrap(),
        _ => {
            let mut b = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut b);
            b
        }
    };
    let t_id = bs58::encode(t_id_bytes).into_string();

    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let eph_key = SigningKey::from_bytes(&seed);
    let eph_pub = eph_key.verifying_key().to_bytes();

    // Synthetic gossip fixtures bind the canonical "none" voucher-id
    // placeholder and an empty guard commitment; the fingerprint carries the
    // same values so the ingress gate reproduces the digest exactly.
    let payload_hash = calculate_l2_payload_hash_raw(
        crate::services::l2_gateway::TRAP_NONE_PLACEHOLDER,
        ds_tag,
        &t_id_bytes,
        &eph_pub,
        "test_u",
        "test_blinded_id",
        encrypted_timestamp,
        None,
        "",
    );
    let sig = crypto::sign_ed25519(&eph_key, &payload_hash);

    TransactionFingerprint {
        ds_tag: ds_tag.to_string(),
        trap_r: "test_u".to_string(),
        trap_s: "test_blinded_id".to_string(),
        t_id,
        layer2_signature: bs58::encode(sig.to_bytes()).into_string(),
        sender_ephemeral_pub: bs58::encode(eph_pub).into_string(),
        deletable_at: get_timestamp(1, true),
        encrypted_timestamp,
        layer2_voucher_id: crate::services::l2_gateway::TRAP_NONE_PLACEHOLDER.to_string(),
        privacy_guard_hash: String::new(),
    }
}

/// Signs an existing fingerprint in place with a fresh ephemeral key so it
/// passes the V3 ingress signature gate.
#[allow(dead_code)]
pub fn sign_fingerprint_in_place(fp: &mut TransactionFingerprint) {
    use crate::services::l2_gateway::calculate_l2_payload_hash_raw;
    use crate::services::conflict_manager::is_init_fingerprint;
    use rand::RngCore;

    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let eph_key = SigningKey::from_bytes(&seed);
    let eph_pub = eph_key.verifying_key().to_bytes();

    let t_id_bytes: [u8; 32] = bs58::decode(&fp.t_id)
        .into_vec()
        .unwrap_or_else(|_| {
            let mut b = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut b);
            fp.t_id = bs58::encode(b).into_string();
            b.to_vec()
        })
        .try_into()
        .unwrap();

    let (challenge_tag, deletable_at) = if is_init_fingerprint(fp) {
        (fp.t_id.clone(), Some(fp.deletable_at.as_str()))
    } else {
        (fp.ds_tag.clone(), None)
    };

    // Genesis fingerprints signed the canonical "none" placeholder for the
    // voucher-id field; spends bind fp.layer2_voucher_id verbatim.
    let effective_voucher_id = if fp.layer2_voucher_id.is_empty()
        && is_init_fingerprint(fp)
    {
        crate::services::l2_gateway::TRAP_NONE_PLACEHOLDER.to_string()
    } else {
        fp.layer2_voucher_id.clone()
    };

    let payload_hash = calculate_l2_payload_hash_raw(
        &effective_voucher_id,
        &challenge_tag,
        &t_id_bytes,
        &eph_pub,
        &fp.trap_r,
        &fp.trap_s,
        fp.encrypted_timestamp,
        deletable_at,
        &fp.privacy_guard_hash,
    );
    let sig = crypto::sign_ed25519(&eph_key, &payload_hash);
    fp.layer2_signature = bs58::encode(sig.to_bytes()).into_string();
    fp.sender_ephemeral_pub = bs58::encode(eph_pub).into_string();
}
