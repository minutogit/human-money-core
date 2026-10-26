//! Regression tests for the second SST security audit.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use human_money_core::models::conflict::TransactionFingerprint;
use human_money_core::models::voucher::{Transaction, TrapData};
use human_money_core::services::crypto::{
    derive_stealth_ephemeral_point, ed25519_pk_to_curve_point, get_secret_scalar,
};
use human_money_core::services::trap_manager::{
    compute_sst_challenge, compute_tau, compute_trap_message_mu, extract_sst_identity,
    generate_sst_trap, verify_sst_witness, verify_stored_trap_shards_against_identity,
};
use rand::RngCore;

fn rand32() -> [u8; 32] {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

fn rand_scalar() -> Scalar {
    let mut b = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut b);
    Scalar::from_bytes_mod_order_wide(&b)
}

fn did_of(sk: &ed25519_dalek::SigningKey) -> String {
    let mut mc = vec![0xed, 0x01];
    mc.extend_from_slice(sk.verifying_key().as_bytes());
    format!("did:key:z{}", bs58::encode(mc).into_string())
}

fn fp(t_id: &str, trap: &TrapData, eph: &[u8; 32]) -> TransactionFingerprint {
    TransactionFingerprint {
        ds_tag: trap.ds_tag.clone(),
        t_id: t_id.to_string(),
        trap_r: trap.trap_r.clone(),
        trap_s: trap.trap_s.clone(),
        sender_ephemeral_pub: bs58::encode(eph).into_string(),
        ..Default::default()
    }
}

fn pt(sk: &ed25519_dalek::SigningKey) -> EdwardsPoint {
    ed25519_pk_to_curve_point(&sk.verifying_key()).unwrap()
}

/// FINDING A: the trap identity is NOT bound to the spent output.
///
/// The owner of the stealth output (Bob) signs fork A with his real did:key
/// and fork B with a second, throw-away did:key Z. Both recipients run the
/// full L1 witness check against the DID that was *declared to them* - both
/// pass. The two shards lie on two different lines, so the collision
/// reconstructs a random point that is neither Bob nor Z.
#[test]
fn poc_identity_swap_between_forks_evades_extraction() {
    let bob = ed25519_dalek::SigningKey::from_bytes(&rand32());
    let throwaway = ed25519_dalek::SigningKey::from_bytes(&rand32());
    let ds_tag = bs58::encode(rand32()).into_string();
    let input_seed = rand32();
    let eph = derive_stealth_ephemeral_point(&bob.verifying_key(), &input_seed)
        .unwrap()
        .compress()
        .to_bytes();
    let t_a = bs58::encode(rand32()).into_string();
    let t_b = bs58::encode(rand32()).into_string();

    let (trap_a, wit_a) = generate_sst_trap(&bob, &ds_tag, &eph, &t_a, "", &input_seed).unwrap();
    verify_sst_witness(&wit_a, &trap_a, &did_of(&bob), &ds_tag, &eph, &t_a, "").unwrap();
    assert!(generate_sst_trap(&throwaway, &ds_tag, &eph, &t_b, "", &input_seed).is_err());
    // A malicious client can still create a trap for another output, then lie
    // about E. Both handover and public collision verification must reject it.
    let fake_eph = derive_stealth_ephemeral_point(&throwaway.verifying_key(), &input_seed)
        .unwrap()
        .compress()
        .to_bytes();
    let (trap_b, wit_b) =
        generate_sst_trap(&throwaway, &ds_tag, &fake_eph, &t_b, "", &input_seed).unwrap();
    assert!(
        verify_sst_witness(
            &wit_b,
            &trap_b,
            &did_of(&throwaway),
            &ds_tag,
            &eph,
            &t_b,
            ""
        )
        .is_err()
    );
    assert!(
        extract_sst_identity(
            &ds_tag,
            &eph,
            &fp(&t_a, &trap_a, &eph),
            &fp(&t_b, &trap_b, &eph)
        )
        .is_err()
    );
}

/// Builds a junk shard for `t_junk` such that the line through
/// (`tau_h`, `trap_h`) and the junk shard reconstructs a valid Schnorr
/// signature under the attacker-chosen key `target` (secret known).
fn steer_junk_shard(
    target: &ed25519_dalek::SigningKey,
    ds_tag: &str,
    eph: &[u8; 32],
    t_honest: &str,
    trap_h: &TrapData,
    t_junk: &str,
) -> TrapData {
    let mu = compute_trap_message_mu(ds_tag, eph);
    let nonce = rand_scalar();
    let r_hat = nonce * ED25519_BASEPOINT_POINT;
    let challenge = compute_sst_challenge(&mu, &r_hat);
    let s_hat = nonce + challenge * get_secret_scalar(target);
    assert_eq!(
        (s_hat * ED25519_BASEPOINT_POINT - r_hat) * challenge.invert(),
        pt(target)
    );

    let r_h = curve25519_dalek::edwards::CompressedEdwardsY::from_slice(
        &bs58::decode(&trap_h.trap_r).into_vec().unwrap(),
    )
    .unwrap()
    .decompress()
    .unwrap();
    let s_h = Scalar::from_canonical_bytes(
        bs58::decode(&trap_h.trap_s).into_vec().unwrap()[..32]
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let tau_h = compute_tau(ds_tag, t_honest, "");
    let tau_j = compute_tau(ds_tag, t_junk, "");
    let inv = tau_h.invert();
    let m_r = (r_h - r_hat) * inv;
    let m_s = (s_h - s_hat) * inv;
    TrapData {
        ds_tag: ds_tag.to_string(),
        trap_r: bs58::encode((r_hat + tau_j * m_r).compress().as_bytes()).into_string(),
        trap_s: bs58::encode((s_hat + tau_j * m_s).as_bytes()).into_string(),
    }
}

/// FINDING B: a single non-witness-verified shard (sock-puppet recipient, or
/// an extra E-signed fingerprint broadcast by the offender) lets the
/// offender STEER the extracted identity to any key whose secret he knows.
/// "Extraction succeeded" is a tautology - every pair of shards yields a
/// verifying Schnorr signature under *some* key.
#[test]
fn poc_junk_shard_steers_attribution_to_attacker_chosen_key() {
    let bob = ed25519_dalek::SigningKey::from_bytes(&rand32());
    let scapegoat = ed25519_dalek::SigningKey::from_bytes(&rand32()); // attacker-owned
    let ds_tag = bs58::encode(rand32()).into_string();
    let eph = human_money_core::test_utils::bound_test_point(&bob);
    let t_a = bs58::encode(rand32()).into_string();
    let t_j = bs58::encode(rand32()).into_string();

    let (trap_a, _) = generate_sst_trap(&bob, &ds_tag, &eph, &t_a, "", &[0u8; 32]).unwrap();
    let trap_j = steer_junk_shard(&scapegoat, &ds_tag, &eph, &t_a, &trap_a, &t_j);

    assert!(
        extract_sst_identity(
            &ds_tag,
            &eph,
            &fp(&t_a, &trap_a, &eph),
            &fp(&t_j, &trap_j, &eph)
        )
        .is_err(),
        "a steered junk shard must not produce an attribution"
    );
}

/// FINDING B (import gate): with two honest forks plus one junk shard the
/// "any consistent pair" gate accepts BOTH the true offender and an
/// attacker-chosen scapegoat as "proven" identity - mutually contradictory
/// definitive attributions.
#[test]
fn poc_import_gate_accepts_contradicting_identities() {
    let bob = ed25519_dalek::SigningKey::from_bytes(&rand32());
    let scapegoat = ed25519_dalek::SigningKey::from_bytes(&rand32());
    let ds_tag = bs58::encode(rand32()).into_string();
    let eph = human_money_core::test_utils::bound_test_point(&bob);
    let eph_s = bs58::encode(eph).into_string();
    let t_a = bs58::encode(rand32()).into_string();
    let t_b = bs58::encode(rand32()).into_string();
    let t_j = bs58::encode(rand32()).into_string();

    let (trap_a, _) = generate_sst_trap(&bob, &ds_tag, &eph, &t_a, "", &[0u8; 32]).unwrap();
    let (trap_b, _) = generate_sst_trap(&bob, &ds_tag, &eph, &t_b, "", &[0u8; 32]).unwrap();
    let trap_j = steer_junk_shard(&scapegoat, &ds_tag, &eph, &t_a, &trap_a, &t_j);

    let tx = |t: &str, trap: &TrapData| Transaction {
        t_id: t.to_string(),
        sender_ephemeral_pub: Some(eph_s.clone()),
        trap_data: Some(trap.clone()),
        ..Default::default()
    };
    let txs = vec![tx(&t_a, &trap_a), tx(&t_b, &trap_b), tx(&t_j, &trap_j)];

    assert!(verify_stored_trap_shards_against_identity(&txs, &pt(&bob)).is_ok());
    assert!(
        verify_stored_trap_shards_against_identity(&txs, &pt(&scapegoat)).is_err(),
        "same evidence 'proves' a second, attacker-chosen identity"
    );
}

#[test]
fn spent_output_cannot_be_reassigned_to_a_throwaway_identity() {
    use human_money_core::test_utils::{
        ACTORS, derive_recipient_holder_key, setup_voucher_with_one_tx,
    };
    let (standard, _, _, bob, voucher, secrets) = setup_voucher_with_one_tx();
    let key = derive_recipient_holder_key(bob, &secrets.recipient_seed);
    let fake = &ACTORS.charlie.identity;
    let result = voucher.create_transaction(
        standard,
        &fake.user_id,
        &fake.signing_key,
        &key,
        &ACTORS.alice.identity.user_id,
        "40",
        Some(true),
    );
    assert!(
        result.is_err(),
        "knowing the input key must not permit swapping its owner DID"
    );
}

#[test]
fn legacy_recipient_seed_does_not_confer_output_ownership() {
    use human_money_core::test_utils::{setup_in_memory_wallet, setup_voucher_with_one_tx};
    let (_, _, _, bob, mut voucher, secrets) = setup_voucher_with_one_tx();
    let seed: [u8; 32] = bs58::decode(&secrets.recipient_seed)
        .into_vec()
        .unwrap()
        .try_into()
        .unwrap();
    let legacy_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    voucher
        .transactions
        .last_mut()
        .unwrap()
        .receiver_ephemeral_pub_hash = Some(human_money_core::services::crypto::get_hash(
        legacy_key.verifying_key().to_bytes(),
    ));
    let wallet = setup_in_memory_wallet(bob);
    assert!(
        wallet.rederive_secret_seed(&voucher, bob).is_err(),
        "raw seed keys known by the payer must never be recovered as recipient keys"
    );
    assert_eq!(
        voucher.spendable_balance(None, Some(bob)),
        rust_decimal::Decimal::ZERO
    );
}

#[test]
fn same_transaction_id_with_distinct_guards_is_valid_conflict_evidence() {
    use human_money_core::services::{conflict_manager, crypto};
    let eph = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
    let eph_s = bs58::encode(eph.verifying_key().as_bytes()).into_string();
    let prev_hash = crypto::get_hash(b"fork");
    let ds_tag = crypto::get_ds_tag(&prev_hash, &eph_s).unwrap();
    let tx = Transaction {
        t_id: crypto::get_hash(b"same id"),
        prev_hash: prev_hash.clone(),
        sender_ephemeral_pub: Some(eph_s),
        privacy_guard: Some("guard A".into()),
        trap_data: Some(TrapData {
            ds_tag,
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut other = tx.clone();
    other.privacy_guard = Some("guard B".into());
    let mut proof = conflict_manager::create_proof_of_double_spend(
        "anonymous".into(),
        prev_hash,
        vec![tx.clone(), other],
        String::new(),
        &human_money_core::test_utils::ACTORS.alice.identity,
        false,
    )
    .unwrap();
    conflict_manager::verify_proof_structure(&proof)
        .expect("same id guard equivocation is a collision");
    proof.conflicting_transactions[1] = tx;
    assert!(
        conflict_manager::verify_proof_structure(&proof).is_err(),
        "an exact replay is not a conflict"
    );
}

#[test]
fn same_id_signed_metadata_equivocation_survives_proof_import() {
    use human_money_core::services::{conflict_manager, crypto, l2_gateway};
    use human_money_core::test_utils::{
        ACTORS, disclose_proof_receipt, setup_in_memory_wallet, sign_proof_fingerprints,
    };
    let owner = &ACTORS.bob.identity;
    let seed = [29; 32];
    let input = crypto::derive_owned_ephemeral_key(&owner.signing_key, &seed).unwrap();
    let eph = input.verifying_key().to_bytes();
    let tag = crypto::get_hash(b"metadata equivocation input");
    let id = crypto::get_hash(b"same metadata spend id");
    let (trap, _) = generate_sst_trap(&owner.signing_key, &tag, &eph, &id, "", &seed).unwrap();
    let tx = Transaction {
        t_id: id,
        prev_hash: tag.clone(),
        t_type: "gossip_soft_placeholder".into(),
        sender_ephemeral_pub: Some(bs58::encode(eph).into_string()),
        trap_data: Some(trap),
        ..Default::default()
    };
    for field in 0..3 {
        let mut txs = vec![tx.clone(), tx.clone()];
        let mut fps = sign_proof_fingerprints(&mut txs, &input);
        let other = &mut fps[1];
        match field {
            0 => other.encrypted_timestamp ^= 1,
            1 => other.created_at_ms += 1,
            _ => other.layer2_voucher_id = "different signed voucher binding".into(),
        }
        let digest = l2_gateway::calculate_l2_payload_hash_raw(
            &other.layer2_voucher_id,
            &other.ds_tag,
            &crypto::decode_bs58_fixed::<32>(&other.t_id, "t_id").unwrap(),
            &eph,
            &other.trap_r,
            &other.trap_s,
            other.encrypted_timestamp,
            other.created_at_ms,
            None,
            &other.privacy_guard_hash,
        );
        other.layer2_signature = bs58::encode(input.sign(&digest).to_bytes()).into_string();
        txs[1].layer2_signature = Some(other.layer2_signature.clone());
        let mut proof = conflict_manager::create_proof_of_double_spend(
            owner.user_id.clone(),
            tag.clone(),
            txs,
            "2099-01-01T00:00:00Z".into(),
            &ACTORS.alice.identity,
            false,
        )
        .unwrap();
        proof.fingerprints = fps;
        disclose_proof_receipt(&mut proof, owner, &seed, 0);
        let mut receiver = setup_in_memory_wallet(&ACTORS.charlie.identity);
        receiver
            .import_proof(proof)
            .expect("distinct authenticated metadata must survive proof import");
        assert_eq!(receiver.proof_store.proofs.len(), 1);
    }
}

#[test]
fn historical_junk_shard_must_not_evade_attribution_through_a_sockpuppet() {
    use human_money_core::models::profile::TransactionBundle;
    use human_money_core::services::{
        crypto, l2_gateway,
        voucher_validation::{StandardRegistry, ValidationPipeline},
    };
    use human_money_core::test_utils::{
        ACTORS, derive_recipient_holder_key, resign_transaction_ext, setup_voucher_with_one_tx,
    };
    let (standard, _, alice, bob, base, secrets) = setup_voucher_with_one_tx();
    let bob_input = derive_recipient_holder_key(bob, &secrets.recipient_seed);
    let (honest, _) = base
        .create_transaction(
            standard,
            &bob.user_id,
            &bob.signing_key,
            &bob_input,
            &alice.user_id,
            "40",
            Some(true),
        )
        .unwrap();
    let sock = &ACTORS.charlie.identity;
    let victim = &ACTORS.david.identity;
    let (mut poisoned, sock_secrets) = base
        .create_transaction(
            standard,
            &bob.user_id,
            &bob.signing_key,
            &bob_input,
            &sock.user_id,
            "40",
            Some(true),
        )
        .unwrap();
    let l2_id = l2_gateway::extract_layer2_voucher_id(&poisoned).unwrap();
    let tx = poisoned.transactions.last_mut().unwrap();
    let mut bytes = bs58::decode(&tx.trap_data.as_ref().unwrap().trap_s)
        .into_vec()
        .unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    tx.trap_data.as_mut().unwrap().trap_s = bs58::encode(bytes).into_string();
    *tx = resign_transaction_ext(tx.clone(), &bob.signing_key, &l2_id, Some(&bob_input));
    let poisoned_fp =
        human_money_core::services::conflict_manager::create_fingerprint_for_transaction(
            tx, &honest,
        )
        .unwrap();
    let sock_input = derive_recipient_holder_key(sock, &sock_secrets.recipient_seed);
    let forward = poisoned.create_transaction(
        standard,
        &sock.user_id,
        &sock.signing_key,
        &sock_input,
        &victim.user_id,
        "40",
        Some(true),
    );
    let forwarded = forward
        .expect("the honest forward transfer remains usable")
        .0;
    let bundle = TransactionBundle {
        sender_id: sock.user_id.clone(),
        recipient_id: victim.user_id.clone(),
        vouchers: vec![forwarded],
        ..Default::default()
    };
    let mut registry = StandardRegistry::new();
    registry.insert(standard.immutable.identity.uuid.clone(), standard.clone());
    let accepted =
        ValidationPipeline::validate_incoming_bundle(&bundle, victim, &registry, None, 0, false)
            .is_ok();
    let honest_fp =
        human_money_core::services::conflict_manager::create_fingerprint_for_transaction(
            honest.transactions.last().unwrap(),
            &honest,
        )
        .unwrap();
    let eph = bob_input.verifying_key().to_bytes();
    let recovered = extract_sst_identity(&honest_fp.ds_tag, &eph, &honest_fp, &poisoned_fp);
    assert!(
        accepted,
        "honest forwarding must preserve the recipient's normal acceptance path"
    );
    assert!(
        recovered.is_err(),
        "the manipulated shard must fail autonomous extraction"
    );
    {
        let mut wallet = human_money_core::test_utils::setup_in_memory_wallet(alice);
        let local_id =
            human_money_core::Wallet::calculate_local_instance_id(&honest, &alice.user_id).unwrap();
        wallet.add_voucher_instance(
            local_id,
            honest.clone(),
            human_money_core::VoucherStatus::Active,
        );
        wallet.scan_and_rebuild_fingerprints().unwrap();
        let foreign_seed = [37; 32];
        let foreign_key =
            crypto::derive_owned_ephemeral_key(&victim.signing_key, &foreign_seed).unwrap();
        let foreign_eph = foreign_key.verifying_key().to_bytes();
        let mut foreign_txs: Vec<Transaction> = [b"foreign A", b"foreign B"]
            .into_iter()
            .map(|id| {
                let id = crypto::get_hash(id);
                let (trap, _) = generate_sst_trap(
                    &victim.signing_key,
                    &honest_fp.ds_tag,
                    &foreign_eph,
                    &id,
                    "",
                    &foreign_seed,
                )
                .unwrap();
                Transaction {
                    t_id: id,
                    prev_hash: honest_fp.ds_tag.clone(),
                    t_type: "gossip_soft_placeholder".into(),
                    sender_ephemeral_pub: Some(bs58::encode(foreign_eph).into_string()),
                    trap_data: Some(trap),
                    ..Default::default()
                }
            })
            .collect();
        let mut forwarded =
            human_money_core::test_utils::sign_proof_fingerprints(&mut foreign_txs, &foreign_key);
        forwarded.push(poisoned_fp);
        let (wire, _) = human_money_core::services::bundle_processor::create_and_encrypt_bundle(
            victim,
            vec![],
            &alice.user_id,
            None,
            forwarded,
            vec![],
            None,
        )
        .unwrap();
        let standards = std::collections::HashMap::from([(
            standard.immutable.identity.uuid.clone(),
            standard.clone(),
        )]);
        wallet
            .process_encrypted_transaction_bundle(alice, &wire, None, &standards)
            .unwrap();
        let proof = wallet
            .proof_store
            .proofs
            .values()
            .find(|entry| {
                crypto::get_pubkey_from_user_id(&entry.proof.offender_id)
                    .is_ok_and(|pk| pk == bob.public_key)
            })
            .expect("the direct victim must disclose its valid receipt and attribute Bob")
            .proof
            .clone();
        assert_eq!(proof.victim_witnesses.len(), 1);
        assert!(
            proof
                .fingerprints
                .iter()
                .all(|fp| fp.sender_ephemeral_pub == bs58::encode(eph).into_string())
        );
        let mut mixed = proof.clone();
        mixed
            .fingerprints
            .extend(human_money_core::test_utils::sign_proof_fingerprints(
                &mut foreign_txs,
                &foreign_key,
            ));
        mixed.conflicting_transactions.extend(foreign_txs);
        mixed.fork_point_prev_hash = honest_fp.ds_tag.clone();
        for tx in &mut mixed.conflicting_transactions {
            tx.t_type = "gossip_soft_placeholder".into();
            tx.prev_hash = mixed.fork_point_prev_hash.clone();
        }
        mixed.proof_id = human_money_core::services::conflict_manager::derive_proof_id(
            &mixed.offender_id,
            &mixed.fork_point_prev_hash,
        )
        .unwrap();
        mixed.reporter_signature = bs58::encode(
            crypto::sign_ed25519(&alice.signing_key, mixed.proof_id.as_bytes()).to_bytes(),
        )
        .into_string();
        let mut mixed_receiver = human_money_core::test_utils::setup_in_memory_wallet(victim);
        let error = mixed_receiver.import_proof(mixed).unwrap_err();
        assert!(error.to_string().contains("share one ephemeral input key"));
        human_money_core::services::trap_manager::verify_victim_witness_disclosure(
            &proof.victim_witnesses[0],
            &proof.fingerprints,
        )
        .unwrap();
        let mut independent = human_money_core::test_utils::setup_in_memory_wallet(victim);
        let encoded = serde_json::to_vec(&proof).unwrap();
        let imported = serde_json::from_slice(&encoded).unwrap();
        independent
            .import_proof(imported)
            .expect("a third party must verify attribution despite the junk shard");
        let mut tampered = proof;
        tampered.victim_witnesses[0].sender_permanent_did = victim.user_id.clone();
        let mut clean = human_money_core::test_utils::setup_in_memory_wallet(victim);
        assert!(
            clean.import_proof(tampered).is_err(),
            "the disclosure must not frame another DID"
        );
        assert!(clean.proof_store.proofs.is_empty());
    }
}

#[test]
fn private_handover_witness_does_not_authorize_fabricated_double_spend_reports() {
    use human_money_core::services::{conflict_manager, crypto};
    use human_money_core::test_utils::{ACTORS, setup_in_memory_wallet};
    let owner = &ACTORS.bob.identity;
    let seed = [14; 32];
    let input = crypto::derive_owned_ephemeral_key(&owner.signing_key, &seed).unwrap();
    let eph = input.verifying_key().to_bytes();
    let previous = crypto::get_hash(b"previous");
    let tag = crypto::get_ds_tag(&previous, &bs58::encode(eph).into_string()).unwrap();
    let transactions = [b"a", b"b"]
        .into_iter()
        .map(|id| {
            let id = crypto::get_hash(id);
            let (trap, _) =
                generate_sst_trap(&owner.signing_key, &tag, &eph, &id, "", &seed).unwrap();
            Transaction {
                t_id: id,
                prev_hash: previous.clone(),
                sender_ephemeral_pub: Some(bs58::encode(eph).into_string()),
                trap_data: Some(trap),
                ..Default::default()
            }
        })
        .collect();
    let reporter = &ACTORS.alice.identity;
    let proof = conflict_manager::create_proof_of_double_spend(
        owner.user_id.clone(),
        previous,
        transactions,
        "2099-01-01T00:00:00Z".into(),
        reporter,
        false,
    )
    .unwrap();
    let mut wallet = setup_in_memory_wallet(&ACTORS.charlie.identity);
    assert!(
        wallet.import_proof(proof).is_err(),
        "trap witnesses alone do not prove that E signed two spends"
    );
    assert!(wallet.proof_store.proofs.is_empty());
}

#[test]
fn stealth_history_keeps_prior_senders_and_receipts_private() {
    use human_money_core::models::profile::TransactionBundle;
    use human_money_core::services::{
        crypto,
        voucher_validation::{StandardRegistry, ValidationPipeline},
    };
    use human_money_core::test_utils::{
        ACTORS, derive_holder_key, derive_recipient_holder_key, setup_voucher_with_one_tx,
    };
    let (standard, _, alice, bob, mut genesis, _) = setup_voucher_with_one_tx();
    genesis.transactions.truncate(1);
    let holder = derive_holder_key(&genesis, &alice.signing_key);
    let (first, first_secrets) = genesis
        .create_transaction(
            standard,
            &alice.user_id,
            &alice.signing_key,
            &holder,
            &bob.user_id,
            "40",
            Some(true),
        )
        .unwrap();
    let bob_input = derive_recipient_holder_key(bob, &first_secrets.recipient_seed);
    let charlie = &ACTORS.charlie.identity;
    let david = &ACTORS.david.identity;
    let (second, second_secrets) = first
        .create_transaction(
            standard,
            &bob.user_id,
            &bob.signing_key,
            &bob_input,
            &charlie.user_id,
            "40",
            Some(true),
        )
        .unwrap();
    let charlie_input = derive_recipient_holder_key(charlie, &second_secrets.recipient_seed);
    let (third, _) = second
        .create_transaction(
            standard,
            &charlie.user_id,
            &charlie.signing_key,
            &charlie_input,
            &david.user_id,
            "40",
            Some(true),
        )
        .unwrap();
    let wire = serde_json::to_string(&third).unwrap();
    for prior in [bob, charlie] {
        let root = crypto::create_user_id(&prior.public_key, None).unwrap();
        assert!(
            !wire.contains(&root),
            "prior sender identities must stay inside encrypted handovers"
        );
    }
    assert!(!wire.contains("victim_witnesses"));
    assert!(!wire.contains("input_key_seed"));
    let bundle = TransactionBundle {
        sender_id: charlie.user_id.clone(),
        recipient_id: david.user_id.clone(),
        vouchers: vec![third],
        ..Default::default()
    };
    let mut registry = StandardRegistry::new();
    registry.insert(standard.immutable.identity.uuid.clone(), standard.clone());
    ValidationPipeline::validate_incoming_bundle(&bundle, david, &registry, None, 0, false)
        .unwrap();
}

#[test]
fn all_output_types_have_the_same_unambiguous_owner_binding() {
    use human_money_core::services::crypto;
    use human_money_core::services::trap_manager::verify_input_owner;
    use human_money_core::test_utils::ACTORS;
    let owner = &ACTORS.bob.identity;
    let fake = &ACTORS.charlie.identity;
    let keys = [
        crypto::derive_owned_ephemeral_key(&owner.signing_key, &[41; 32]).unwrap(),
        crypto::derive_deterministic_change_key(&owner.signing_key, &owner.user_id, "previous")
            .unwrap(),
        crypto::derive_holder_ephemeral_key(&owner.signing_key, &[42; 16], Some("bob")).unwrap(),
    ];
    for key in keys {
        let seed = bs58::encode(key.input_seed().unwrap()).into_string();
        let eph = key.verifying_key().to_bytes();
        verify_input_owner(&owner.user_id, &seed, &eph).unwrap();
        assert!(verify_input_owner(&fake.user_id, &seed, &eph).is_err());
    }
}

#[test]
fn synthetic_signed_evidence_cannot_quarantine_an_unrelated_transaction_id() {
    use human_money_core::services::{conflict_manager, crypto};
    use human_money_core::test_utils::{
        ACTORS, disclose_proof_receipt, setup_in_memory_wallet, setup_voucher_with_one_tx,
        sign_proof_fingerprints,
    };
    let (_, _, _, recipient, unrelated, _) = setup_voucher_with_one_tx();
    let unrelated_id = unrelated.transactions.last().unwrap().t_id.clone();
    let offender = &ACTORS.charlie.identity;
    let seed = [47; 32];
    let input = crypto::derive_owned_ephemeral_key(&offender.signing_key, &seed).unwrap();
    let eph = input.verifying_key().to_bytes();
    let tag = crypto::get_hash(b"unrelated proof context");
    let ids = [
        crypto::get_hash(b"early spend"),
        crypto::get_hash(b"later spend"),
        unrelated_id,
    ];
    let mut txs: Vec<Transaction> = ids
        .into_iter()
        .enumerate()
        .map(|(index, id)| {
            let (trap, _) =
                generate_sst_trap(&offender.signing_key, &tag, &eph, &id, "", &seed).unwrap();
            Transaction {
                t_id: id,
                prev_hash: tag.clone(),
                t_type: "gossip_soft_placeholder".into(),
                t_time: format!("2026-01-0{}T00:00:00Z", index + 1),
                sender_ephemeral_pub: Some(bs58::encode(eph).into_string()),
                trap_data: Some(trap),
                ..Default::default()
            }
        })
        .collect();
    let fps = sign_proof_fingerprints(&mut txs, &input);
    let mut proof = conflict_manager::create_proof_of_double_spend(
        offender.user_id.clone(),
        tag,
        txs,
        "2099-01-01T00:00:00Z".into(),
        &ACTORS.alice.identity,
        false,
    )
    .unwrap();
    proof.fingerprints = fps;
    disclose_proof_receipt(&mut proof, offender, &seed, 0);
    let mut wallet = setup_in_memory_wallet(recipient);
    wallet.add_voucher_instance(
        "unrelated".into(),
        unrelated,
        human_money_core::VoucherStatus::Active,
    );
    wallet.import_proof(proof).unwrap();
    assert_eq!(
        wallet.voucher_store.vouchers["unrelated"].status,
        human_money_core::VoucherStatus::Active,
        "synthetic IDs and timestamps must not authorize quarantine of an unrelated input"
    );
}
