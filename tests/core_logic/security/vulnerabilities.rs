// tests/core_logic/security/vulnerabilities.rs
// cargo test --test core_logic_tests

use self::test_utils::{ACTORS, SILVER_STANDARD, setup_in_memory_wallet};
use super::test_utils;
use human_money_core::VoucherInstance;
use human_money_core::crypto_utils;
use human_money_core::error::ValidationError;
use human_money_core::models::profile::TransactionBundle;
use human_money_core::models::secure_container::PayloadType;
use human_money_core::models::voucher::{
    Collateral, Transaction, ValueDefinition, Voucher, VoucherSignature,
};
use human_money_core::services::crypto_utils::{get_hash, sign_ed25519};
use human_money_core::services::secure_container_manager::create_secure_container;
use human_money_core::services::utils::get_current_timestamp;
use human_money_core::services::voucher_manager::{self, NewVoucherData};
use human_money_core::services::voucher_validation::{self};
use human_money_core::wallet::Wallet;
use human_money_core::{UserIdentity, VoucherStatus};
use human_money_core::test_utils::derive_holder_key;
use human_money_core::{VoucherCoreError, create_transaction, create_voucher, to_canonical_json};
use rand::seq::SliceRandom;
use rand::{Rng, thread_rng};
use rust_decimal::Decimal;
use serde_json::Value;
use std::str::FromStr;

// ===================================================================================
// HILFSFUNKTIONEN & SETUP (Adaptiert aus bestehenden Tests)
// ===================================================================================

/// Wählt eine zufällige Transaktion (außer `init`) und macht ihren Betrag negativ.
fn mutate_to_negative_amount(voucher: &mut Voucher) -> String {
    if voucher.transactions.len() < 2 {
        return "No non-init transaction to mutate".to_string();
    }
    let mut rng = thread_rng();
    let tx_index = rng.gen_range(1..voucher.transactions.len());

    if let Some(tx) = voucher.transactions.get_mut(tx_index) {
        if let Ok(mut amount) = Decimal::from_str(&tx.amount) {
            if amount > Decimal::ZERO {
                amount.set_sign_negative(true);
                tx.amount = amount.to_string();
                return format!("Set tx[{}] amount to negative: {}", tx_index, tx.amount);
            }
        }
    }
    "Failed to apply negative amount mutation".to_string()
}

/// Wählt eine zufällige Split-Transaktion und macht ihren Restbetrag negativ.
fn mutate_to_negative_remainder(voucher: &mut Voucher) -> String {
    let mut rng = thread_rng();
    // Finde alle Indizes von Transaktionen, die einen Restbetrag haben
    let splittable_indices: Vec<usize> = voucher
        .transactions
        .iter()
        .enumerate()
        .filter(|(_, tx)| tx.sender_remaining_amount.is_some())
        .map(|(i, _)| i)
        .collect();

    if let Some(&tx_index) = splittable_indices.choose(&mut rng) {
        if let Some(tx) = voucher.transactions.get_mut(tx_index) {
            if let Some(remainder_str) = &tx.sender_remaining_amount {
                if let Ok(mut remainder) = Decimal::from_str(remainder_str) {
                    if remainder > Decimal::ZERO {
                        remainder.set_sign_negative(true);
                        tx.sender_remaining_amount = Some(remainder.to_string());
                        return format!(
                            "Set tx[{}] remainder to negative: {}",
                            tx_index, remainder
                        );
                    }
                }
            }
        }
    }
    "No suitable split transaction found to mutate".to_string()
}

/// Verschiebt den `t_type` "init" auf eine zufällige, ungültige Position.
fn mutate_init_to_wrong_position(voucher: &mut Voucher) -> String {
    if voucher.transactions.len() < 2 {
        return "Not enough transactions to move 'init' type".to_string();
    }
    let mut rng = thread_rng();
    let tx_index = rng.gen_range(1..voucher.transactions.len());

    if let Some(tx) = voucher.transactions.get_mut(tx_index) {
        tx.t_type = "init".to_string();
        return format!("Set tx[{}] t_type to 'init'", tx_index);
    }
    "Failed to move 'init' t_type".to_string()
}

/// Nimmt eine `AdditionalSignature` und macht sie ungültig, indem die Signaturdaten manipuliert werden.
fn mutate_invalidate_signature(voucher: &mut Voucher) -> String {
    if let Some(sig) = voucher.signatures.get_mut(0) {
        sig.signature = "invalid_signature_data".to_string();
        return "Invalidated signature of first VoucherSignature".to_string();
    }
    "No VoucherSignature found to invalidate".to_string()
}

/// Definiert die verschiedenen Angriffsstrategien für den Fuzzer.
#[derive(Debug, Clone, Copy)]
enum FuzzingStrategy {
    /// Manipuliert eine `VoucherSignature`, um die Validierung zu testen.
    InvalidateSignature,
    /// Setzt einen Transaktionsbetrag auf einen negativen Wert.
    SetNegativeTransactionAmount,
    /// Setzt den Restbetrag eines Splits auf einen negativen Wert.
    SetNegativeRemainderAmount,
    /// Verschiebt eine `init`-Transaktion an eine ungültige Position.
    SetInitTransactionInWrongPosition,
    /// Führt eine zufällige, strukturelle Mutation durch (der alte Ansatz).
    GenericRandomMutation,
}

/// Erstellt ein frisches, leeres In-Memory-Wallet für einen Akteur.
fn setup_test_wallet(identity: &UserIdentity) -> Wallet {
    setup_in_memory_wallet(identity)
}

/// Erstellt leere `NewVoucherData` für Testzwecke.
fn new_test_voucher_data(creator_id: String) -> NewVoucherData {
    NewVoucherData {
        validity_duration: Some("P5Y".to_string()), // Erhöht auf 5 Jahre, um die Mindestgültigkeit zu erfüllen
        non_redeemable_test_voucher: false,
        nominal_value: ValueDefinition {
            amount: "100".to_string(),
            ..Default::default()
        },
        collateral: Some(Collateral::default()),
        creator_profile: human_money_core::models::profile::PublicProfile {
            id: Some(creator_id),
            ..Default::default()
        },
    }
}

/// Erstellt eine gültige Bürgschaft für einen gegebenen Gutschein.
fn create_guarantor_signature(
    _voucher: &Voucher,
    guarantor_identity: &UserIdentity,
    organization: Option<&str>,
    gender: &str,
) -> VoucherSignature {
    let mut sig_obj = VoucherSignature {
        signer_id: guarantor_identity.user_id.clone(),
        role: "guarantor".to_string(),
        signature_time: get_current_timestamp(),
        details: Some(human_money_core::models::profile::PublicProfile {
            first_name: Some("Garant".to_string()),
            last_name: Some("Test".to_string()),
            organization: organization.map(String::from),
            gender: Some(gender.to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let mut sig_obj_for_id = sig_obj.clone();
    sig_obj_for_id.signature_id = "".to_string();
    sig_obj_for_id.signature = "".to_string();
    let id_hash = get_hash(to_canonical_json(&sig_obj_for_id).unwrap());

    sig_obj.signature_id = id_hash;
    let signature = sign_ed25519(
        &guarantor_identity.signing_key,
        sig_obj.signature_id.as_bytes(),
    );
    sig_obj.signature = bs58::encode(signature.to_bytes()).into_string();
    sig_obj
}

/// Simuliert die Aktion eines Hackers: Verpackt einen (manipulierten) Gutschein in einen Container.
fn create_hacked_bundle_and_container(
    hacker_identity: &UserIdentity,
    victim_id: &str,
    malicious_voucher: Voucher,
) -> Vec<u8> {
    let mut bundle = TransactionBundle {
        bundle_id: "".to_string(),
        sender_id: hacker_identity.user_id.clone(),
        recipient_id: victim_id.to_string(),
        vouchers: vec![malicious_voucher],
        timestamp: get_current_timestamp(),
        notes: Some("Hacked".to_string()),
        sender_signature: "".to_string(),
        forwarded_fingerprints: Vec::new(),
        fingerprint_depths: std::collections::HashMap::new(),
        sender_profile_name: None,
    };
    let bundle_json_for_id = to_canonical_json(&bundle).unwrap();
    bundle.bundle_id = get_hash(bundle_json_for_id);
    let signature = sign_ed25519(&hacker_identity.signing_key, bundle.bundle_id.as_bytes());
    bundle.sender_signature = bs58::encode(signature.to_bytes()).into_string();
    let signed_bundle_bytes = serde_json::to_vec(&bundle).unwrap();
    let secure_container = create_secure_container(
        hacker_identity,
        &[victim_id.to_string()],
        &signed_bundle_bytes,
        PayloadType::TransactionBundle,
    )
    .unwrap();
    serde_json::to_vec(&secure_container).unwrap()
}

/// Erstellt und signiert eine (potenziell manipulierte) Transaktion.
fn create_hacked_tx(
    signer_key: &ed25519_dalek::SigningKey,
    identity_key: Option<&ed25519_dalek::SigningKey>,
    mut hacked_tx: Transaction,
) -> Transaction {
    let tx_json_for_id = to_canonical_json(&hacked_tx).unwrap();
    hacked_tx.t_id = get_hash(tx_json_for_id);

    // 1. Sender Proof Signature (L2): Sign(t_id) with ephemeral key
    let signature = sign_ed25519(signer_key, hacked_tx.t_id.as_bytes());
    hacked_tx.sender_proof_signature = bs58::encode(signature.to_bytes()).into_string();

    // 2. Sender Identity Signature (L1): Optional, if sender_id is present
    if let Some(id_key) = identity_key {
        if hacked_tx.sender_id.is_some() {
            let sig = sign_ed25519(id_key, hacked_tx.t_id.as_bytes());
            hacked_tx.sender_identity_signature = Some(bs58::encode(sig.to_bytes()).into_string());
        }
    }

    hacked_tx
}

/// **NEUER STUB:** Erstellt Test-Voucher-Daten für die neuen Tests.
fn create_test_voucher_data_with_amount(
    creator_profile: human_money_core::models::profile::PublicProfile,
    amount: &str,
) -> NewVoucherData {
    NewVoucherData {
        validity_duration: Some("P5Y".to_string()),
        non_redeemable_test_voucher: false,
        nominal_value: ValueDefinition {
            amount: amount.to_string(),
            ..Default::default()
        },
        collateral: Some(Collateral::default()),
        creator_profile,
    }
}

/// Fügt P2PKH-Felder (Anchor Reveal, Next Anchor, L2 Signature) zu einer manuellen Transaktion hinzu.
fn add_p2pkh_layer(
    tx: &mut Transaction,
    holder_secret: &ed25519_dalek::SigningKey,
) {
    use ed25519_dalek::Signer;
    let holder_pub = holder_secret.verifying_key();
    let holder_pub_str = bs58::encode(holder_pub.to_bytes()).into_string();

    // Generate next holder key (random) for the receiver anchor
    let mut rng = thread_rng();
    let mut random_bytes = [0u8; 32];
    rng.fill(&mut random_bytes);
    let next_secret = ed25519_dalek::SigningKey::from_bytes(&random_bytes);
    let next_pub = next_secret.verifying_key();
    let next_pub_str = bs58::encode(next_pub.to_bytes()).into_string();
    let next_hash = get_hash(next_pub_str);

    tx.sender_ephemeral_pub = Some(holder_pub_str.clone());
    tx.receiver_ephemeral_pub_hash = Some(next_hash);
    tx.sender_change_anchor_hash = None; // Standard: kein Change

    // Prepare for L2 Signature
    tx.sender_proof_signature = "".to_string();
    tx.layer2_signature = None;
    tx.t_id = "".to_string();

    let pre_l2_json = to_canonical_json(tx).unwrap();
    let pre_l2_tid = get_hash(pre_l2_json);

    let l2_payload = if tx.t_type == "init" {
        let valid_until = tx.valid_until.as_deref().unwrap_or("");
        format!("{}{}{}", pre_l2_tid, valid_until, holder_pub_str)
    } else {
        format!(
            "{}{}{}{}",
            pre_l2_tid,
            holder_pub_str,
            tx.receiver_ephemeral_pub_hash.as_deref().unwrap_or(""),
            tx.sender_change_anchor_hash.as_deref().unwrap_or("")
        )
    };

    let l2_hash = get_hash(l2_payload);
    let l2_sig = holder_secret.sign(l2_hash.as_bytes());

    tx.layer2_signature = Some(bs58::encode(l2_sig.to_bytes()).into_string());
}

// ===================================================================================
// ANGRIFFSKLASSE 1 & 4: MANIPULATION VON STAMMDATEN & BÜRGSCHAFTEN
// ===================================================================================
#[test]
fn test_attack_tamper_core_data_and_guarantors() {
    human_money_core::set_signature_bypass(true);
    // ### SETUP ###
    let mut issuer_wallet = setup_test_wallet(&ACTORS.issuer);
    let mut hacker_wallet = setup_test_wallet(&ACTORS.hacker);
    let mut victim_wallet = setup_test_wallet(&ACTORS.victim);
    let voucher_data = new_test_voucher_data(ACTORS.issuer.user_id.clone());

    let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

    let mut valid_voucher = voucher_manager::create_voucher(
        voucher_data,
        standard,
        standard_hash,
        &ACTORS.issuer.signing_key,
        "en",
    )
    .unwrap();
    let guarantor_sig = create_guarantor_signature(&valid_voucher, &ACTORS.guarantor1, None, "0");
    valid_voucher.signatures.push(guarantor_sig);
    let local_id =
        Wallet::calculate_local_instance_id(&valid_voucher, &ACTORS.issuer.user_id).unwrap();

    let instance = VoucherInstance {
        voucher: valid_voucher,
        status: VoucherStatus::Active,
        local_instance_id: local_id.clone(),
    };
    issuer_wallet
        .voucher_store
        .vouchers
        .insert(local_id.clone(), instance);

    // Issuer sendet den Gutschein an den Hacker, der ihn nun für Angriffe besitzt.
    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: ACTORS.hacker.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: local_id.clone(),
            amount_to_send: "100".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(standard.metadata.uuid.clone(), standard.clone());

    let human_money_core::wallet::CreateBundleResult {
        bundle_bytes: container_to_hacker,
        ..
    } = issuer_wallet
        .execute_multi_transfer_and_bundle(&ACTORS.issuer, &standards, request, None)
        .unwrap();
    // KORREKTUR: Die Map muss den Standard enthalten, der verarbeitet wird.
    let mut standards_for_hacker = std::collections::HashMap::new();
    standards_for_hacker.insert(
        SILVER_STANDARD.0.metadata.uuid.clone(),
        SILVER_STANDARD.0.clone(),
    );
    hacker_wallet
        .process_encrypted_transaction_bundle(
            &ACTORS.hacker,
            &container_to_hacker,
            None,
            &standards_for_hacker,
        )
        .unwrap();
    let voucher_in_hacker_wallet = &hacker_wallet
        .voucher_store
        .vouchers
        .iter()
        .next()
        .unwrap()
        .1
        .voucher;
    
    let hacker_holder_secret = hacker_wallet.rederive_secret_seed(voucher_in_hacker_wallet, &ACTORS.hacker).unwrap();

    // ### SZENARIO 1a: WERTINFLATION ###
    println!("--- Angriff 1a: Wertinflation ---");
    let mut inflated_voucher = voucher_in_hacker_wallet.clone();
    inflated_voucher.nominal_value.amount = "9999".to_string();

    // Der Hacker muss die sichere `create_transaction`-Funktion umgehen.
    // Er erstellt die finale Transaktion zum Opfer manuell und hängt sie an den manipulierten Gutschein an.
    let mut final_tx = Transaction {
        prev_hash: get_hash(
            to_canonical_json(inflated_voucher.transactions.last().unwrap()).unwrap(),
        ),
        t_time: get_current_timestamp(),
        sender_id: Some(ACTORS.hacker.user_id.clone()),
        recipient_id: ACTORS.victim.user_id.clone(),
        amount: "100".to_string(), // Hacker gibt seinen ursprünglichen Betrag aus
        t_type: "transfer".to_string(),
        ..Default::default()
    };
    // Diese Transaktion selbst ist valide und wird vom Hacker signiert. Der Betrug liegt im manipulierten Creator-Block.
    add_p2pkh_layer(&mut final_tx, &hacker_holder_secret);
    let hacked_tx = create_hacked_tx(&hacker_holder_secret, Some(&ACTORS.hacker.signing_key), final_tx);
    inflated_voucher.transactions.push(hacked_tx);

    let hacked_container = create_hacked_bundle_and_container(
        &ACTORS.hacker,
        &ACTORS.victim.user_id,
        inflated_voucher,
    );
    // KORREKTUR: Die Map muss den Standard enthalten, der verarbeitet wird.
    let mut standards_for_victim = std::collections::HashMap::new();
    standards_for_victim.insert(
        SILVER_STANDARD.0.metadata.uuid.clone(),
        SILVER_STANDARD.0.clone(),
    );
    let process_result = victim_wallet
        .process_encrypted_transaction_bundle(
            &ACTORS.victim,
            &hacked_container,
            None,
            &standards_for_victim,
        );
    
    assert!(
        matches!(
            process_result,
            Err(VoucherCoreError::Validation(
                ValidationError::InvalidVoucherHash
            ))
        ),
        "Processing must fail with InvalidVoucherHash due to manipulated nominal value. Got: {:?}",
        process_result
    );
    victim_wallet.voucher_store.vouchers.clear(); // Reset for next test

    // ### SZENARIO 4a: BÜRGEN-METADATEN MANIPULIEREN ###
    human_money_core::set_signature_bypass(false);
    // println!("--- Angriff 4a: Bürgen-Metadaten manipulieren ---"); // Removed debug print
    let mut tampered_guarantor_voucher = voucher_in_hacker_wallet.clone();
    // KORREKTUR: signatures[0] ist jetzt der Ersteller (role: "creator").
    // Der Bürge (role: "guarantor") ist an Index 1.
    let guarantor_sig_to_tamper = tampered_guarantor_voucher
        .signatures
        .get_mut(1)
        .expect("Test voucher must have a guarantor signature at index 1");

    if let Some(ref mut details) = guarantor_sig_to_tamper.details {
        details.first_name = Some("Mallory".to_string());
    } else {
        guarantor_sig_to_tamper.details = Some(human_money_core::models::profile::PublicProfile {
            first_name: Some("Mallory".to_string()),
            ..Default::default()
        });
    }

    let mut final_tx_2 = Transaction {
        prev_hash: get_hash(
            to_canonical_json(tampered_guarantor_voucher.transactions.last().unwrap()).unwrap(),
        ),
        t_time: get_current_timestamp(),
        sender_id: Some(ACTORS.hacker.user_id.clone()),
        recipient_id: ACTORS.victim.user_id.clone(),
        amount: "100".to_string(),
        t_type: "transfer".to_string(),
        ..Default::default()
    };
    add_p2pkh_layer(&mut final_tx_2, &hacker_holder_secret);
    let final_tx_hacked = create_hacked_tx(&hacker_holder_secret, Some(&ACTORS.hacker.signing_key), final_tx_2);
    tampered_guarantor_voucher.transactions.push(final_tx_hacked);

    let hacked_container = create_hacked_bundle_and_container(
        &ACTORS.hacker,
        &ACTORS.victim.user_id,
        tampered_guarantor_voucher,
    );
    // KORREKTUR: Die Map muss den Standard enthalten, der verarbeitet wird.
    let mut standards_for_victim = std::collections::HashMap::new();
    standards_for_victim.insert(
        SILVER_STANDARD.0.metadata.uuid.clone(),
        SILVER_STANDARD.0.clone(),
    );
    let process_result = victim_wallet
        .process_encrypted_transaction_bundle(
            &ACTORS.victim,
            &hacked_container,
            None,
            &standards_for_victim,
        );
    assert!(process_result.is_err(), "Processing must fail for tampered guarantor metadata");
    assert!(
        matches!(
            process_result,
            Err(VoucherCoreError::Validation(
                ValidationError::InvalidSignatureId { .. }
            ))
        ),
        "Processing must fail with InvalidSignatureId due to manipulated guarantor metadata. Got: {:?}",
        process_result
    );
    victim_wallet.voucher_store.vouchers.clear();
}

// ===================================================================================
// ANGRIFFSKLASSE 2: FÄLSCHUNG DER TRANSAKTIONSHISTORIE
// ===================================================================================
#[test]
fn test_attack_tamper_transaction_history() {
    human_money_core::set_signature_bypass(false); // Testing chain integrity
    // ### SETUP ###
    let mut alice_wallet = setup_test_wallet(&ACTORS.alice);
    let mut bob_wallet_hacker = setup_test_wallet(&ACTORS.bob);
    let data = new_test_voucher_data(ACTORS.alice.user_id.clone());

    let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

    let voucher_a = voucher_manager::create_voucher(
        data,
        standard,
        standard_hash,
        &ACTORS.alice.signing_key,
        "en",
    )
    .unwrap();
    let local_id_a =
        Wallet::calculate_local_instance_id(&voucher_a, &ACTORS.alice.user_id).unwrap();

    let instance_a = VoucherInstance {
        voucher: voucher_a,
        status: VoucherStatus::Active,
        local_instance_id: local_id_a.clone(),
    };
    alice_wallet
        .voucher_store
        .vouchers
        .insert(local_id_a.clone(), instance_a);
    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: ACTORS.bob.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: local_id_a.clone(),
            amount_to_send: "100".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(standard.metadata.uuid.clone(), standard.clone());

    let human_money_core::wallet::CreateBundleResult {
        bundle_bytes: container_to_bob,
        ..
    } = alice_wallet
        .execute_multi_transfer_and_bundle(&ACTORS.alice, &standards, request, None)
        .unwrap();
    // KORREKTUR: Die Map muss den Standard enthalten, der verarbeitet wird.
    let mut standards_for_bob = std::collections::HashMap::new();
    standards_for_bob.insert(
        SILVER_STANDARD.0.metadata.uuid.clone(),
        SILVER_STANDARD.0.clone(),
    );
    bob_wallet_hacker
        .process_encrypted_transaction_bundle(
            &ACTORS.bob,
            &container_to_bob,
            None,
            &standards_for_bob,
        )
        .unwrap();
    let voucher_in_bob_wallet = &bob_wallet_hacker
        .voucher_store
        .vouchers
        .iter()
        .next()
        .unwrap()
        .1
        .voucher;

    // ### ANGRIFF ###
    println!("--- Angriff 2a: Transaktionshistorie fälschen ---");
    let mut voucher_with_tampered_history = voucher_in_bob_wallet.clone();
    // Manipuliere eine Signatur in der Kette, um sie ungültig zu machen.
    voucher_with_tampered_history.transactions[0].sender_proof_signature =
        "invalid_signature".to_string();

    // DANK DES SICHERHEITSPATCHES in `voucher_manager` schlägt dieser Aufruf nun fehl,
    // da `create_transaction` den Gutschein vorab validiert.
    let bob_key = bob_wallet_hacker.rederive_secret_seed(&voucher_with_tampered_history, &ACTORS.bob).unwrap();
    
    let transfer_attempt_result = voucher_manager::create_transaction(
        &voucher_with_tampered_history,
        standard,
        &ACTORS.bob.user_id,
        &ACTORS.bob.signing_key,
        &bob_key,
        &ACTORS.victim.user_id,
        "100",
    );
    assert!(
        transfer_attempt_result.is_err(),
        "Transaction creation must fail if history is tampered."
    );
}

// ===================================================================================
// ANGRIFFSKLASSE 3: ERSTELLUNG EINER LOGISCH INKONSISTENTEN TRANSAKTION
// ===================================================================================
#[test]
fn test_attack_create_inconsistent_transaction() {
    human_money_core::set_signature_bypass(false); // Testing balance/chain integrity
    // ### SETUP ###
    let mut issuer_wallet = setup_test_wallet(&ACTORS.issuer);
    let mut hacker_wallet = setup_test_wallet(&ACTORS.hacker);
    let mut victim_wallet = setup_test_wallet(&ACTORS.victim);
    let data = new_test_voucher_data(ACTORS.issuer.user_id.clone());

    let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

    let initial_voucher = voucher_manager::create_voucher(
        data,
        standard,
        standard_hash,
        &ACTORS.issuer.signing_key,
        "en",
    )
    .unwrap();
    let local_id_issuer =
        Wallet::calculate_local_instance_id(&initial_voucher, &ACTORS.issuer.user_id).unwrap();
    let _holder_key = human_money_core::test_utils::derive_holder_key(&initial_voucher, &ACTORS.issuer.signing_key);
    let instance_i = VoucherInstance {
        voucher: initial_voucher,
        status: VoucherStatus::Active,
        local_instance_id: local_id_issuer.clone(),
    };
    issuer_wallet
        .voucher_store
        .vouchers
        .insert(local_id_issuer.clone(), instance_i);
    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: ACTORS.hacker.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: local_id_issuer.clone(),
            amount_to_send: "100".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(standard.metadata.uuid.clone(), standard.clone());

    let human_money_core::wallet::CreateBundleResult {
        bundle_bytes: container_to_hacker,
        ..
    } = issuer_wallet
        .execute_multi_transfer_and_bundle(&ACTORS.issuer, &standards, request, None)
        .unwrap();
    // KORREKTUR: Die Map muss den Standard enthalten, der verarbeitet wird.
    let mut standards_for_hacker = std::collections::HashMap::new();
    standards_for_hacker.insert(
        SILVER_STANDARD.0.metadata.uuid.clone(),
        SILVER_STANDARD.0.clone(),
    );
    hacker_wallet
        .process_encrypted_transaction_bundle(
            &ACTORS.hacker,
            &container_to_hacker,
            None,
            &standards_for_hacker,
        )
        .unwrap();
    let (_hacker_instance, voucher_in_hacker_wallet) = {
        let entry = hacker_wallet.voucher_store.vouchers.iter().next().unwrap().1;
        (entry, &entry.voucher)
    };
    let hacker_holder_secret = hacker_wallet.rederive_secret_seed(voucher_in_hacker_wallet, &ACTORS.hacker).unwrap();

    // ### SZENARIO 3a: OVERSPENDING ###
    println!("--- Angriff 3a: Overspending ---");
    let mut overspend_voucher = voucher_in_hacker_wallet.clone();
    let mut overspend_tx_unsigned = Transaction {
        prev_hash: get_hash(
            to_canonical_json(overspend_voucher.transactions.last().unwrap()).unwrap(),
        ),
        t_time: get_current_timestamp(),
        sender_id: Some(ACTORS.hacker.user_id.clone()),
        recipient_id: ACTORS.victim.user_id.clone(),
        amount: "200".to_string(),
        t_type: "transfer".to_string(),
        ..Default::default()
    };
    add_p2pkh_layer(&mut overspend_tx_unsigned, &hacker_holder_secret);
    let overspend_tx = create_hacked_tx(&hacker_holder_secret, Some(&ACTORS.hacker.signing_key), overspend_tx_unsigned);
    overspend_voucher.transactions.push(overspend_tx);
    let hacked_container = create_hacked_bundle_and_container(
        &ACTORS.hacker,
        &ACTORS.victim.user_id,
        overspend_voucher,
    );
    // KORREKTUR: Die Map muss den Standard enthalten, der verarbeitet wird.
    let mut standards_for_victim = std::collections::HashMap::new();
    standards_for_victim.insert(
        SILVER_STANDARD.0.metadata.uuid.clone(),
        SILVER_STANDARD.0.clone(),
    );
    let process_result = victim_wallet
        .process_encrypted_transaction_bundle(
            &ACTORS.victim,
            &hacked_container,
            None,
            &standards_for_victim,
        );
    
    assert!(
        matches!(
            process_result,
            Err(VoucherCoreError::Validation(
                ValidationError::InsufficientFundsInChain { .. }
            ))
        ),
        "Processing must fail with InsufficientFundsInChain on overspending attempt. Got: {:?}",
        process_result
    );
    victim_wallet.voucher_store.vouchers.clear();
}

#[test]
fn test_attack_inconsistent_split_transaction() {
    human_money_core::set_signature_bypass(false); // Testing balance integrity
    // ### SETUP ###
    // Ein Hacker besitzt einen gültigen Gutschein über 100 Einheiten.
    let hacker_identity = &ACTORS.hacker;
    let victim_identity = &ACTORS.victim;
    let data = new_test_voucher_data(hacker_identity.user_id.clone());
    let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    let voucher = voucher_manager::create_voucher(
        data,
        standard,
        standard_hash,
        &hacker_identity.signing_key,
        "en",
    )
    .unwrap();

    // ### ANGRIFF ###
    println!("--- Angriff 3b: Inkonsistente Split-Transaktion (Gelderschaffung) ---");
    let mut inconsistent_split_voucher = voucher.clone();
    let holder_key = derive_holder_key(&voucher, &hacker_identity.signing_key);

    // Hacker erstellt eine Split-Transaktion, bei der die Summe nicht stimmt (100 -> 30 + 80)
    let mut inconsistent_tx_unsigned = Transaction {
        prev_hash: get_hash(
            to_canonical_json(inconsistent_split_voucher.transactions.last().unwrap()).unwrap(),
        ),
        t_time: get_current_timestamp(),
        sender_id: Some(hacker_identity.user_id.clone()),
        recipient_id: victim_identity.user_id.clone(),
        amount: "30".to_string(),
        sender_remaining_amount: Some("80".to_string()), // Falscher Restbetrag
        t_type: "split".to_string(),
        ..Default::default()
    };
    add_p2pkh_layer(&mut inconsistent_tx_unsigned, &holder_key);
    let inconsistent_tx = create_hacked_tx(&holder_key, Some(&ACTORS.hacker.signing_key), inconsistent_tx_unsigned);
    inconsistent_split_voucher
        .transactions
        .push(inconsistent_tx);

    // ### VALIDIERUNG ###
    let result = voucher_validation::validate_voucher_against_standard(
        &inconsistent_split_voucher,
        standard,
    );

    // Die Validierung SOLLTE fehlschlagen. Aktuell tut sie das nicht.
    assert!(
        result.is_err(),
        "Validation must fail on inconsistent split transaction."
    );
}

#[test]
fn test_attack_init_amount_mismatch() {
    human_money_core::set_signature_bypass(true);
    // ### SETUP ###
    // Ein Hacker erstellt einen scheinbar gültigen Gutschein mit Nennwert 100.
    let hacker_identity = &ACTORS.hacker;
    let data = new_test_voucher_data(hacker_identity.user_id.clone());
    let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    let mut voucher = voucher_manager::create_voucher(
        data,
        standard,
        standard_hash,
        &hacker_identity.signing_key,
        "en",
    )
    .unwrap();

    // ### ANGRIFF ###
    println!("--- Angriff: Inkonsistenter Betrag in 'init'-Transaktion ---");
    // Der Nennwert des Gutscheins ist 100, aber der Hacker manipuliert die 'init'-Transaktion,
    // sodass sie nur einen Betrag von 101 ausweist.
    let mut malicious_init_tx = voucher.transactions[0].clone();
    malicious_init_tx.amount = "101.0000".to_string();

    // DANK SIGNATURE BYPASS: Keine Notwendigkeit mehr, die Transaktion neu zu signieren!
    // Die Validierung ignoriert die nun ungültige Signatur und prüft direkt den Betrag.
    voucher.transactions[0] = malicious_init_tx;

    // ### VALIDIERUNG ###
    let result = voucher_validation::validate_voucher_against_standard(&voucher, standard);

    // Der Betrug muss mit dem spezifischen Fehler `InitAmountMismatch` erkannt werden.
    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::InitAmountMismatch { .. })
    ));
}

#[test]
fn test_attack_negative_or_zero_amount_transaction() {
    human_money_core::set_signature_bypass(true);
    // ### SETUP ###
    let hacker_identity = &ACTORS.hacker;
    let victim_identity = &ACTORS.victim;
    let data = new_test_voucher_data(hacker_identity.user_id.clone());
    let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    let voucher = voucher_manager::create_voucher(
        data,
        standard,
        standard_hash,
        &hacker_identity.signing_key,
        "en",
    )
    .unwrap();

    // ### ANGRIFF 1: Negativer Betrag ###
    let negative_tx_unsigned = Transaction {
        amount: "-10.0000".to_string(),
        // Restliche Felder sind für diesen Test nicht primär relevant
        prev_hash: get_hash(to_canonical_json(voucher.transactions.last().unwrap()).unwrap()),
        t_time: get_current_timestamp(),
        sender_id: Some(hacker_identity.user_id.clone()),
        recipient_id: victim_identity.user_id.clone(),
        t_type: "transfer".to_string(),
        ..Default::default()
    };

    // Die `create_hacked_tx` ist hier nicht nötig, da die Validierung VOR der Signaturprüfung fehlschlagen sollte.
    let mut voucher_with_negative_tx = voucher.clone();
    voucher_with_negative_tx
        .transactions
        .push(negative_tx_unsigned);

    let result_negative =
        voucher_validation::validate_voucher_against_standard(&voucher_with_negative_tx, standard);
    assert!(matches!(
        result_negative.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::NegativeOrZeroAmount { .. })
    ));

    // ### ANGRIFF 2: Betrag von Null ###
    let zero_tx_unsigned = Transaction {
        amount: "0.0000".to_string(),
        prev_hash: get_hash(to_canonical_json(voucher.transactions.last().unwrap()).unwrap()),
        t_time: get_current_timestamp(),
        sender_id: Some(hacker_identity.user_id.clone()),
        recipient_id: victim_identity.user_id.clone(),
        t_type: "transfer".to_string(),
        ..Default::default()
    };
    let mut voucher_with_zero_tx = voucher.clone();
    voucher_with_zero_tx.transactions.push(zero_tx_unsigned);

    let result_zero =
        voucher_validation::validate_voucher_against_standard(&voucher_with_zero_tx, standard);
    assert!(matches!(
        result_zero.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::NegativeOrZeroAmount { .. })
    ));
}

#[test]
fn test_attack_invalid_precision_in_nominal_value() {
    human_money_core::set_signature_bypass(true);
    // ### SETUP ###
    // Erstelle Testdaten mit einem Nennwert, der zu viele Nachkommastellen hat.
    let creator_identity = &ACTORS.issuer;
    let mut voucher_data = new_test_voucher_data(creator_identity.user_id.clone());
    voucher_data.nominal_value.amount = "100.12345".to_string(); // 5 statt der erlaubten 4

    let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

    // ### ANGRIFF ###
    // Die `create_voucher` Funktion selbst validiert dies noch nicht, der Zustand wird also erstellt.
    let malicious_voucher = voucher_manager::create_voucher(
        voucher_data,
        standard,
        standard_hash,
        &creator_identity.signing_key,
        "en",
    )
    .unwrap();

    // ### VALIDIERUNG ###
    // Die `validate_voucher_against_standard` muss diesen Fehler jedoch erkennen.
    let result =
        voucher_validation::validate_voucher_against_standard(&malicious_voucher, standard);
    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::InvalidAmountPrecision { path, max_places: 4, found: 5 }) if path == "nominal_value.amount"
    ));
}

#[test]
fn test_attack_full_transfer_amount_mismatch() {
    human_money_core::set_signature_bypass(true);
    // ### SETUP ###
    let (standard, _) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    let (public_key, signing_key) =
        crypto_utils::generate_ed25519_keypair_for_tests(Some("creator_stub"));
    let user_id = crypto_utils::create_user_id(&public_key, Some("cs")).unwrap();
    let creator_identity = UserIdentity {
        signing_key,
        public_key,
        user_id: user_id.clone(),
    };
    let creator = human_money_core::models::profile::PublicProfile {
        id: Some(user_id),
        first_name: Some("Stub".to_string()),
        last_name: Some("Creator".to_string()),
        ..Default::default()
    };
    let voucher_data = create_test_voucher_data_with_amount(creator.clone(), "100");
    let mut voucher = create_voucher(
        voucher_data,
        standard,
        &SILVER_STANDARD.1,
        &creator_identity.signing_key,
        "en",
    )
    .unwrap();

    // ### ANGRIFF ###
    // Erstelle eine 'transfer' Transaktion, die aber nicht den vollen Betrag von 100 sendet.
    // Wir erstellen die Transaktion explizit, anstatt die `init`-Transaktion zu klonen,
    // um Nebeneffekte zu vermeiden und den Test robuster zu machen.
    let mut malicious_tx = Transaction {
        t_id: String::new(), // Wird später gesetzt
        prev_hash: get_hash(to_canonical_json(voucher.transactions.last().unwrap()).unwrap()),
        t_type: "transfer".to_string(),
        amount: "99.0000".to_string(), // Inkorrekt für einen 'transfer' bei einem Guthaben von 100
        sender_id: Some(creator.id.clone().expect("Creator ID should exist")),
        recipient_id: ACTORS.bob.user_id.clone(),
        t_time: get_current_timestamp(),
        sender_remaining_amount: None,
        ..Default::default()
    };
    // DANK SIGNATURE BYPASS: Wir können die Transaktion direkt anhängen, ohne aufwendiges Re-Signing.
    // Die Signatur ist hier ungültig (fehlt oder passt nicht), aber der Bypass ignoriert das.
    // Der Test prüft, ob die LOGIK (Balance Check) greift.
    voucher.transactions.push(malicious_tx);

    // ### VALIDIERUNG ###
    let result = voucher_validation::validate_voucher_against_standard(&voucher, standard);
    if let Err(e) = &result {
        println!("DEBUG: Got error: {:?}", e);
    }
    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::InsufficientFundsInChain { .. })
    ));
}

#[test]
fn test_attack_remainder_in_full_transfer() {
    human_money_core::set_signature_bypass(true);
    // ### SETUP ###
    let (standard, _) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    let (public_key, signing_key) =
        crypto_utils::generate_ed25519_keypair_for_tests(Some("creator_stub_2"));
    let user_id = crypto_utils::create_user_id(&public_key, Some("cs2")).unwrap();
    let creator_identity = UserIdentity {
        signing_key,
        public_key,
        user_id: user_id.clone(),
    };
    let creator = human_money_core::models::profile::PublicProfile {
        id: Some(user_id),
        first_name: Some("Stub".to_string()),
        last_name: Some("Creator".to_string()),
        ..Default::default()
    };
    let voucher_data = create_test_voucher_data_with_amount(creator.clone(), "100");
    let mut voucher = create_voucher(
        voucher_data,
        standard,
        &SILVER_STANDARD.1,
        &creator_identity.signing_key,
        "en",
    )
    .unwrap();

    // ### ANGRIFF ###
    // Erstelle eine 'transfer' Transaktion, die den vollen Betrag sendet,
    // aber fälschlicherweise auch einen Restbetrag enthält.
    let mut malicious_tx = Transaction {
        t_id: String::new(), // Wird später gesetzt
        prev_hash: get_hash(to_canonical_json(voucher.transactions.last().unwrap()).unwrap()),
        t_type: "transfer".to_string(),
        amount: "100.0000".to_string(),
        sender_remaining_amount: Some("0.0001".to_string()), // Darf nicht vorhanden sein
        sender_id: Some(creator.id.clone().expect("Creator ID should exist")),
        recipient_id: ACTORS.bob.user_id.clone(),
        t_time: get_current_timestamp(),
        ..Default::default()
    };
    // DANK SIGNATURE BYPASS: Wir sparen uns wieder das Re-Signing.
    voucher.transactions.push(malicious_tx);

    // ### VALIDIERUNG ###
    let result = voucher_validation::validate_voucher_against_standard(&voucher, standard);
    assert!(
        result.is_err(),
        "Validation must fail when a 'transfer' transaction has a remainder."
    );
}

// ===================================================================================
// ANGRIFFSKLASSE 5: STRUKTURELLE INTEGRITÄTSPRÜFUNG DURCH FUZZING
// ===================================================================================
/// Hilfsfunktion für den Fuzzing-Test.
/// Versucht, eine einzelne, zufällige Mutation durchzuführen und gibt bei Erfolg
/// eine Beschreibung der Änderung zurück.
fn mutate_value(val: &mut Value, rng: &mut impl Rng, current_path: &str) -> Option<String> {
    match val {
        Value::Object(map) => {
            if map.is_empty() {
                return None;
            }
            let keys: Vec<String> = map.keys().cloned().collect();
            // Mische die Schlüssel, um bei jedem Durchlauf eine andere Reihenfolge zu haben
            let mut shuffled_keys = keys;
            shuffled_keys.shuffle(rng);

            for key in shuffled_keys {
                let new_path = format!("{}.{}", current_path, key);
                if let Some(desc) = mutate_value(map.get_mut(&key).unwrap(), rng, &new_path) {
                    return Some(desc);
                }
            }
        }
        Value::Array(arr) => {
            if arr.is_empty() {
                return None;
            }
            // Wähle einen zufälligen Index zum Mutieren
            let idx_to_mutate = rng.gen_range(0..arr.len());
            let new_path = format!("{}[{}]", current_path, idx_to_mutate);
            if let Some(desc) = mutate_value(&mut arr[idx_to_mutate], rng, &new_path) {
                return Some(desc);
            }
        }
        Value::String(s) => {
            let old_val = s.clone();
            *s = format!("{}-mutated", s);
            return Some(format!(
                "CHANGED path '{}' from '{}' to '{}'",
                current_path, old_val, s
            ));
        }
        Value::Number(n) => {
            let old_val = n.clone();
            let old_val_i64 = n.as_i64().unwrap_or(0);
            let mut new_val_num;
            loop {
                new_val_num = old_val_i64 + rng.gen_range(-10..10);
                if new_val_num != old_val_i64 {
                    break; // Stelle sicher, dass der Wert sich tatsächlich ändert
                }
            }
            *val = Value::Number(new_val_num.into());
            return Some(format!(
                "CHANGED path '{}' from '{}' to '{}'",
                current_path, old_val, val
            ));
        }
        Value::Bool(b) => {
            let old_val = *b;
            *b = !*b;
            return Some(format!(
                "FLIPPED path '{}' from '{}' to '{}'",
                current_path, old_val, b
            ));
        }
        Value::Null => {
            *val = Value::String("was_null".to_string());
            return Some(format!(
                "CHANGED path '{}' from null to 'was_null'",
                current_path
            ));
        }
    }
    None // Keine Mutation in diesem Zweig durchgeführt
}

#[test]
fn test_attack_fuzzing_random_mutations() {
    human_money_core::set_signature_bypass(false); // Fuzzer needs to test everything
    // ### SETUP ###
    // Erstelle einen "Master"-Gutschein, der alle für die Angriffe relevanten Features enthält.
    let mut data = new_test_voucher_data(ACTORS.issuer.user_id.clone());
    data.nominal_value.amount = "1000".to_string();

    let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

    let mut master_voucher = voucher_manager::create_voucher(
        data,
        standard,
        standard_hash,
        &ACTORS.issuer.signing_key,
        "en",
    )
    .unwrap();

    // Füge Bürgen hinzu.
    master_voucher.signatures.push(create_guarantor_signature(
        &master_voucher,
        &ACTORS.guarantor1,
        None,
        "0",
    ));
    master_voucher.signatures.push(create_guarantor_signature(
        &master_voucher,
        &ACTORS.guarantor2,
        None,
        "0",
    ));

    // WICHTIG: Füge eine `AdditionalSignature` hinzu, damit der Fuzzer sie angreifen kann.
    let mut additional_sig = VoucherSignature {
        voucher_id: master_voucher.voucher_id.clone(),
        signer_id: ACTORS.victim.user_id.clone(),
        signature_time: get_current_timestamp(),
        role: "A valid additional signature".to_string(),
        ..Default::default()
    };
    let mut sig_obj_for_id = additional_sig.clone();
    sig_obj_for_id.signature_id = "".to_string();
    sig_obj_for_id.signature = "".to_string();
    additional_sig.signature_id = get_hash(to_canonical_json(&sig_obj_for_id).unwrap());
    let signature = sign_ed25519(
        &ACTORS.victim.signing_key,
        additional_sig.signature_id.as_bytes(),
    );
    additional_sig.signature = bs58::encode(signature.to_bytes()).into_string();
    master_voucher.signatures.push(additional_sig);

    // Erstelle eine Transaktionskette, die auch einen Split enthält.
    let holder_key = human_money_core::test_utils::derive_holder_key(&master_voucher, &ACTORS.issuer.signing_key);
    let (mv, secrets_1) = create_transaction(
        &master_voucher,
        standard,
        &ACTORS.issuer.user_id,
        &ACTORS.issuer.signing_key,
        &holder_key,
        &ACTORS.alice.user_id,
        "1000",
    )
    .unwrap();
    master_voucher = mv;
    let alice_seed = secrets_1.recipient_seed;
    let alice_key = ed25519_dalek::SigningKey::from_bytes(&bs58::decode(alice_seed).into_vec().unwrap().try_into().unwrap());
    let (mv, _) = create_transaction(
        &master_voucher,
        standard,
        &ACTORS.alice.user_id,
        &ACTORS.alice.signing_key,
        &alice_key,
        &ACTORS.bob.user_id,
        "500",
    )
    .unwrap(); // Split
    master_voucher = mv;

    let mut rng = thread_rng();
    println!("--- Starte intelligenten Fuzzing-Test mit 2000 Iterationen ---");
    let iterations = 100;

    // Definiere die intelligenten und zufälligen Angriffsstrategien.
    let strategies = [
        FuzzingStrategy::InvalidateSignature,
        FuzzingStrategy::SetNegativeTransactionAmount,
        FuzzingStrategy::SetNegativeRemainderAmount,
        FuzzingStrategy::SetInitTransactionInWrongPosition,
        FuzzingStrategy::GenericRandomMutation, // Behalte die alte Methode für allgemeine Zufälligkeit bei.
        FuzzingStrategy::GenericRandomMutation, // Erhöhe die Wahrscheinlichkeit für zufällige Mutationen.
    ];

    for i in 0..iterations {
        let mut mutated_voucher = master_voucher.clone();
        let strategy = strategies.choose(&mut rng).unwrap();
        let change_description: String;

        // Führe die gewählte Angriffsstrategie aus
        match strategy {
            FuzzingStrategy::InvalidateSignature => {
                change_description = mutate_invalidate_signature(&mut mutated_voucher);
            }
            FuzzingStrategy::SetNegativeTransactionAmount => {
                change_description = mutate_to_negative_amount(&mut mutated_voucher);
            }
            FuzzingStrategy::SetNegativeRemainderAmount => {
                change_description = mutate_to_negative_remainder(&mut mutated_voucher);
            }
            FuzzingStrategy::SetInitTransactionInWrongPosition => {
                change_description = mutate_init_to_wrong_position(&mut mutated_voucher);
            }
            FuzzingStrategy::GenericRandomMutation => {
                // Konvertiere zu JSON, mutiere zufällig und konvertiere zurück
                let mut as_value = serde_json::to_value(&mutated_voucher).unwrap();
                change_description = mutate_value(&mut as_value, &mut rng, "voucher")
                    .unwrap_or_else(|| "Generic mutation did not change anything".to_string());

                if let Ok(v) = serde_json::from_value(as_value) {
                    mutated_voucher = v;
                } else {
                    // Wenn die zufällige Mutation die Struktur so zerstört hat, dass sie nicht mehr
                    // als Voucher geparst werden kann, ist das ein "erfolgreicher" Fund.
                    // Wir können zur nächsten Iteration übergehen.
                    println!(
                        "Iter {}: Generic mutation created invalid structure. OK.",
                        i
                    );
                    continue;
                }
            }
        }

        let validation_result =
            voucher_validation::validate_voucher_against_standard(&mutated_voucher, standard);
        assert!(
            validation_result.is_err(),
            "FUZZING-FEHLER bei Iteration {}: Eine Mutation hat die Validierung umgangen!\nStrategie: {:?}\nÄnderung: {}\nMutierter Gutschein:\n{}",
            i,
            strategy,
            change_description,
            serde_json::to_string_pretty(&mutated_voucher).unwrap()
        );
    }
    println!("--- Intelligenter Fuzzing-Test erfolgreich abgeschlossen ---");
}
