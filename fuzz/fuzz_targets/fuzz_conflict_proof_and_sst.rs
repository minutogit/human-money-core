#![no_main]

use human_money_core::models::conflict::{
    ProofOfDoubleSpend, TransactionFingerprint, VictimWitnessDisclosure,
};
use human_money_core::models::voucher::{TrapData, TrapWitness};
use human_money_core::services::conflict_manager::{
    verify_fingerprint_signature, verify_proof_structure, verify_reporter_signature,
};
use human_money_core::services::trap_manager::{
    fingerprints_conflict, verify_fingerprint_shards_against_identity, verify_input_owner,
    verify_sst_witness, verify_victim_witness_disclosure,
};
use human_money_core::test_utils::{setup_in_memory_wallet, ACTORS};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 1. Fuzz deserialization and verification of ProofOfDoubleSpend (including V4 victim witnesses)
    if let Ok(proof) = serde_json::from_slice::<ProofOfDoubleSpend>(data) {
        let _ = verify_proof_structure(&proof);
        let _ = verify_reporter_signature(&proof);

        for vw in &proof.victim_witnesses {
            let _ = verify_victim_witness_disclosure(vw, &proof.fingerprints);
        }

        // Invariant: importing into wallet must handle all invariants without panicking
        let mut wallet = setup_in_memory_wallet(&ACTORS.alice.identity);
        let _ = wallet.import_proof(proof);
    }

    // 2. Fuzz deserialization and verification of TransactionFingerprint (gossip ingress)
    if let Ok(fp) = serde_json::from_slice::<TransactionFingerprint>(data) {
        let _ = verify_fingerprint_signature(&fp);
    }

    // 3. Fuzz SST V4 VictimWitnessDisclosure directly
    if let Ok(disclosure) = serde_json::from_slice::<VictimWitnessDisclosure>(data) {
        let _ = verify_victim_witness_disclosure(&disclosure, &[]);

        let mut dummy_eph = [0u8; 32];
        if data.len() >= 32 {
            dummy_eph.copy_from_slice(&data[..32]);
        }
        let alice = &ACTORS.alice.identity;
        let bob = &ACTORS.bob.identity;
        let _ = verify_input_owner(
            &disclosure.sender_permanent_did,
            &disclosure.witness.input_seed,
            &dummy_eph,
        );
        let _ = verify_input_owner(&alice.user_id, &disclosure.witness.input_seed, &dummy_eph);
        let _ = verify_input_owner(&bob.user_id, &disclosure.witness.input_seed, &dummy_eph);

        let dummy_trap = TrapData {
            ds_tag: "fuzz_tag".into(),
            trap_r: disclosure.witness.r_sig.clone(),
            trap_s: disclosure.witness.s_sig.clone(),
        };
        let _ = verify_sst_witness(
            &disclosure.witness,
            &dummy_trap,
            &disclosure.sender_permanent_did,
            "fuzz_tag",
            &dummy_eph,
            "fuzz_tid",
            "fuzz_guard_hash",
        );
    }

    // 4. Fuzz pairs of TransactionFingerprints for conflict detection and SST identity attribution
    if let Ok((fp1, fp2)) =
        serde_json::from_slice::<(TransactionFingerprint, TransactionFingerprint)>(data)
    {
        let _ = fingerprints_conflict(&fp1, &fp2);
        let fps = [fp1.clone(), fp2.clone()];
        let dummy_point = curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
        let _ = verify_fingerprint_shards_against_identity(&fps, &dummy_point);

        let disclosure = VictimWitnessDisclosure {
            fingerprint_index: 0,
            sender_permanent_did: ACTORS.alice.identity.user_id.clone(),
            witness: TrapWitness {
                input_seed: "dummy_seed".into(),
                r_sig: fp1.trap_r.clone(),
                s_sig: fp1.trap_s.clone(),
                m_r: fp1.trap_r.clone(),
                m_s: fp1.trap_s.clone(),
                k_trap: fp1.trap_r.clone(),
                dleq_c: fp1.trap_s.clone(),
                dleq_s: fp1.trap_s.clone(),
            },
        };
        let _ = verify_victim_witness_disclosure(&disclosure, &[fp1, fp2]);
    }

    // 5. Direct TrapWitness deserialization
    if let Ok(witness) = serde_json::from_slice::<TrapWitness>(data) {
        let mut dummy_eph = [0u8; 32];
        if data.len() >= 32 {
            dummy_eph.copy_from_slice(&data[..32]);
        }
        let _ = verify_input_owner(&ACTORS.alice.identity.user_id, &witness.input_seed, &dummy_eph);
    }
});
