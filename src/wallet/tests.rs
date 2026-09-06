//! # src/wallet/tests.rs
//! Contains unit tests for the `Wallet` struct. This file is
//! deliberately separated from `mod.rs` to improve readability.
//!
//! ATTENTION: Most high-level integration tests have been moved to the
//! `tests/wallet_api/` directory. Only tests for internal or
//! path-dependent logic (pub(super)) remain here.

use bs58;
use crate::{
    test_utils::{
        ACTORS, setup_in_memory_wallet,
    },
};

/// Bundles internal logic tests (e.g. for private or pub(super) methods).
mod internal_logic {
    use super::*;

    /// **Test: rederive_secret_seed logic path (&& vs || mutant defense)**
    #[test]
    fn test_rederive_secret_seed_logic() {
        let identity = &ACTORS.alice;
        let wallet = setup_in_memory_wallet(identity);
        
        let mut dummy_voucher = crate::models::voucher::Voucher::default();
        dummy_voucher.voucher_nonce = bs58::encode(vec![0u8; 32]).into_string(); 
        
        let mut tx = crate::models::voucher::Transaction::default();
        tx.t_type = "transfer".to_string(); // Important: NOT "init"
        tx.sender_id = Some(identity.user_id.clone()); // Important: == identity.user_id
        tx.sender_remaining_amount = None; // So the split branch is ignored
        
        dummy_voucher.transactions.push(tx);
        
        // rederive_secret_seed is pub(super)
        let result = wallet.rederive_secret_seed(&dummy_voucher, identity);
        
        // Must fail since neither init nor split.
        assert!(result.is_err(), "rederive_secret_seed should fail for a non-init, non-split transfer if logic is &&");
        assert!(result.unwrap_err().to_string().contains("No valid ownership strategy found"));
    }

    /// **Test: resolve_conflict_offline (Earliest Wins - pub(super))**
    #[test]
    fn test_resolve_conflict_offline_earliest_wins() {
        use crate::models::conflict::TransactionFingerprint;
        use crate::models::voucher::{Transaction, Voucher};
        use crate::wallet::instance::{VoucherInstance, VoucherStatus};
        use crate::models::profile::VoucherStore;
        use crate::services::conflict_manager::encrypt_transaction_timestamp;
        
        let mut store = VoucherStore::default();
        
        let t_id_early = bs58::encode(b"early").into_string();
        let t_id_late = bs58::encode(b"latee").into_string();

        let tx_early = Transaction {
            t_id: t_id_early.clone(),
            prev_hash: bs58::encode(b"prev").into_string(),
            t_time: "2024-01-01T10:00:00.000000Z".to_string(),
            ..Default::default()
        };
        let enc_early = encrypt_transaction_timestamp(&tx_early).unwrap();
        
        let tx_late = Transaction {
            t_id: t_id_late.clone(),
            prev_hash: bs58::encode(b"prev").into_string(),
            t_time: "2024-01-01T11:00:00.000000Z".to_string(),
            ..Default::default()
        };
        let enc_late = encrypt_transaction_timestamp(&tx_late).unwrap();
        
        let voucher_early = Voucher { voucher_id: "v_early".to_string(), transactions: vec![tx_early.clone()], ..Default::default() };
        let voucher_late = Voucher { voucher_id: "v_late".to_string(), transactions: vec![tx_late.clone()], ..Default::default() };
        
        store.vouchers.insert("local_early".to_string(), VoucherInstance { voucher: voucher_early, status: VoucherStatus::Active, local_instance_id: "local_early".to_string() });
        store.vouchers.insert("local_late".to_string(), VoucherInstance { voucher: voucher_late, status: VoucherStatus::Active, local_instance_id: "local_late".to_string() });
        
        let fp_early = TransactionFingerprint {
            t_id: t_id_early,
            encrypted_timestamp: enc_early,
            ds_tag: "tag".to_string(),
            trap_r: "u".to_string(),
            trap_s: "b".to_string(),
            layer2_signature: "sig".to_string(),
            deletable_at: "2099-01-01T00:00:00Z".to_string(),
                    sender_ephemeral_pub: String::new(),
                layer2_voucher_id: String::new(),
                privacy_guard_hash: String::new(),
};
        let fp_late = TransactionFingerprint {
            t_id: t_id_late,
            encrypted_timestamp: enc_late,
            ds_tag: "tag".to_string(),
            trap_r: "u".to_string(),
            trap_s: "b".to_string(),
            layer2_signature: "sig".to_string(),
            deletable_at: "2099-01-01T00:00:00Z".to_string(),
                    sender_ephemeral_pub: String::new(),
                layer2_voucher_id: String::new(),
                privacy_guard_hash: String::new(),
};
        
        // resolve_conflict_offline is pub(crate), hence directly testable here.
        crate::wallet::conflicts::resolve_conflict_offline(&mut store, &[fp_early, fp_late]);
        
        assert!(matches!(store.vouchers["local_early"].status, VoucherStatus::Active), "early must win");
        assert!(matches!(store.vouchers["local_late"].status, VoucherStatus::Quarantined { .. }), "late must lose");
    }

    /// **AUDIT-01-F15 (WH3-01-105): the write phase of the offline race must
    /// never overwrite adjudicated voucher states.**
    ///
    /// Instances whose status was set by cryptographic evidence (an signed
    /// L2 verdict quarantine) or by endorsement escrow (`Endorsed`) must not
    /// be reactivated (or otherwise mutated) by a purely heuristic
    /// Earliest-Wins race that runs on every bundle receipt. Status
    /// transitions into `Active` from such states would let offenders
    /// circumvent adjudication and un-trust endorsed escrows.
    #[test]
    fn test_resolve_conflict_offline_must_not_overwrite_adjudicated_statuses() {
        use crate::models::conflict::TransactionFingerprint;
        use crate::models::voucher::{Transaction, Voucher};
        use crate::wallet::instance::{VoucherInstance, VoucherStatus};
        use crate::models::profile::VoucherStore;
        use crate::services::conflict_manager::encrypt_transaction_timestamp;

        fn make_tx(t_id_bytes: &[u8], hour: u32) -> Transaction {
            Transaction {
                t_id: bs58::encode(t_id_bytes).into_string(),
                prev_hash: bs58::encode(b"prev").into_string(),
                t_time: format!("2024-01-01T{:02}:00:00.000000Z", hour),
                ..Default::default()
            }
        }

        fn fingerprint_of(tx: &Transaction) -> TransactionFingerprint {
            TransactionFingerprint {
                t_id: tx.t_id.clone(),
                encrypted_timestamp: encrypt_transaction_timestamp(tx).unwrap(),
                ds_tag: "tag".to_string(),
                trap_r: "u".to_string(),
                trap_s: "b".to_string(),
                layer2_signature: String::new(),
                deletable_at: "2099-01-01T00:00:00Z".to_string(),
                sender_ephemeral_pub: String::new(),
                layer2_voucher_id: String::new(),
                privacy_guard_hash: String::new(),
            }
        }

        // --- Scenario 1: the race WINNER carries an Endorsed escrow state. --
        {
            let mut store = VoucherStore::default();
            let tx_early = make_tx(b"early", 10);
            let tx_late = make_tx(b"latee", 11);
            store.vouchers.insert(
                "local_endorsed".to_string(),
                VoucherInstance {
                    voucher: Voucher {
                        voucher_id: "v_e".to_string(),
                        transactions: vec![tx_early.clone()],
                        ..Default::default()
                    },
                    // Adjudicated escrow state (guarantor endorsement).
                    status: VoucherStatus::Endorsed { role: "guarantor".to_string() },
                    local_instance_id: "local_endorsed".to_string(),
                },
            );
            store.vouchers.insert(
                "local_active".to_string(),
                VoucherInstance {
                    voucher: Voucher {
                        voucher_id: "v_l".to_string(),
                        transactions: vec![tx_late.clone()],
                        ..Default::default()
                    },
                    status: VoucherStatus::Active,
                    local_instance_id: "local_active".to_string(),
                },
            );

            crate::wallet::conflicts::resolve_conflict_offline(
                &mut store,
                &[fingerprint_of(&tx_early), fingerprint_of(&tx_late)],
            );

            assert!(
                matches!(
                    store.vouchers["local_endorsed"].status,
                    VoucherStatus::Endorsed { .. }
                ),
                "AUDIT-01-F15: a heuristic offline race must NEVER reactivate \
                 an endorsed (adjudicated) instance to Active"
            );
            assert!(
                matches!(
                    store.vouchers["local_active"].status,
                    VoucherStatus::Quarantined { .. }
                ),
                "the honest Active loser of the race is still quarantined"
            );
        }

        // --- Scenario 2: the race WINNER is L2-verdict-quarantined. --------
        {
            let mut store = VoucherStore::default();
            let tx_early = make_tx(b"early", 10);
            let tx_late = make_tx(b"latee", 11);
            store.vouchers.insert(
                "local_verdict".to_string(),
                VoucherInstance {
                    voucher: Voucher {
                        voucher_id: "v_v".to_string(),
                        transactions: vec![tx_early.clone()],
                        ..Default::default()
                    },
                    // Set by a cryptographically signed L2 verdict — must
                    // take precedence over any later heuristic race.
                    status: VoucherStatus::Quarantined {
                        reason: "L2 verdict".to_string(),
                    },
                    local_instance_id: "local_verdict".to_string(),
                },
            );
            store.vouchers.insert(
                "local_active".to_string(),
                VoucherInstance {
                    voucher: Voucher {
                        voucher_id: "v_l".to_string(),
                        transactions: vec![tx_late.clone()],
                        ..Default::default()
                    },
                    status: VoucherStatus::Active,
                    local_instance_id: "local_active".to_string(),
                },
            );

            crate::wallet::conflicts::resolve_conflict_offline(
                &mut store,
                &[fingerprint_of(&tx_early), fingerprint_of(&tx_late)],
            );

            assert!(
                matches!(
                    &store.vouchers["local_verdict"].status,
                    VoucherStatus::Quarantined { reason } if reason == "L2 verdict"
                ),
                "AUDIT-01-F15: an L2-adjudicated quarantine must not be \
                 reactivated to Active by a heuristic offline race"
            );
        }
    }

    /// **AUDIT-01-F16 (WH3-01-106): attribution must be a deterministic
    /// function of the evidence set.**
    ///
    /// `check_for_double_spend` materializes bucket members from a
    /// `HashSet`, so the order of the conflict vector differs between runs.
    /// Since `verify_and_create_proof` extracts the identity from the first
    /// pair of that vector only, buckets with >= 3 members (two genuine
    /// forks + one structurally valid off-line shard) produce DIFFERENT
    /// offender identities depending on hash iteration order — breaking
    /// proof_id-keyed dedup/immunity, UI consistency and forensics.
    #[test]
    fn test_attribution_is_deterministic_for_three_member_buckets() {
        use crate::models::conflict::{KnownFingerprints, TransactionFingerprint};
        use crate::models::voucher::TrapData;
        use crate::services::conflict_manager;
        use crate::services::trap_manager;
        use rand::RngCore;

        fn random_b58_32() -> String {
            let mut b = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut b);
            bs58::encode(b).into_string()
        }

        let identity = &ACTORS.alice;
        let wallet = setup_in_memory_wallet(identity);

        // Genuine double spend bound to an attacker key (shards a, b) plus a
        // structurally VALID but off-line third shard (parseable point and
        // canonical scalar under the same ds_tag/ephemeral key).
        let offender_sk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let prev_hash_b58 = random_b58_32();
        let eph_b58 = random_b58_32();
        let ds_tag = {
            let prev = bs58::decode(&prev_hash_b58).into_vec().unwrap();
            let eph = bs58::decode(&eph_b58).into_vec().unwrap();
            crate::services::crypto::get_hash_from_slices(&[&prev, &eph])
        };
        let eph_bytes: [u8; 32] = bs58::decode(&eph_b58).into_vec().unwrap().try_into().unwrap();

        let t_a = random_b58_32();
        let t_b = random_b58_32();
        let (trap_a, _) = trap_manager::generate_sst_trap(&offender_sk, &ds_tag, &eph_bytes, &t_a).unwrap();
        let (trap_b, _) = trap_manager::generate_sst_trap(&offender_sk, &ds_tag, &eph_bytes, &t_b).unwrap();

        let mut junk_r = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut junk_r);
        let mut junk_s = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut junk_s);
        let t_c = random_b58_32();
        let junk_trap = TrapData {
            ds_tag: ds_tag.clone(),
            trap_r: bs58::encode(junk_r).into_string(),
            trap_s: bs58::encode(junk_s).into_string(),
        };

        let mk_fp = |t_id: String, trap: &TrapData| TransactionFingerprint {
            ds_tag: ds_tag.clone(),
            t_id,
            trap_r: trap.trap_r.clone(),
            trap_s: trap.trap_s.clone(),
            sender_ephemeral_pub: eph_b58.clone(),
            deletable_at: "2099-01-01T00:00:00Z".to_string(),
            ..Default::default()
        };
        let fps = [mk_fp(t_a, &trap_a), mk_fp(t_b, &trap_b), mk_fp(t_c, &junk_trap)];

        let mut known = KnownFingerprints::default();
        known
            .foreign_fingerprints
            .entry(ds_tag.clone())
            .or_default()
            .extend(fps.iter().cloned());

        // The deterministic true attribution for comparison.
        let expected_point =
            trap_manager::extract_sst_identity(&ds_tag, &eph_bytes, &fps[0], &fps[1]).unwrap();
        let pk_bytes = expected_point.compress().to_bytes();
        let expected_did = crate::services::crypto::create_user_id(
            &ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes).unwrap(),
            None,
        )
        .unwrap();

        // Repeated detection + attribution over fresh HashMap instances
        // (different SipHash seeds per call) must yield ONE stable outcome.
        let mut observed: Vec<String> = Vec::new();
        for _ in 0..40 {
            let result = conflict_manager::check_for_double_spend(
                &wallet.own_fingerprints,
                &known,
            );
            let bucket = result
                .verifiable_conflicts
                .get(&ds_tag)
                .expect("bucket must classify as verifiable conflict");
            let proof = wallet
                .verify_and_create_proof(&identity.identity, bucket, None)
                .expect("attribution must not error")
                .expect("soft proof must be created");
            observed.push(proof.offender_id);
        }
        observed.dedup();
        assert_eq!(
            observed.len(),
            1,
            "AUDIT-01-F16: offender attribution must be a deterministic \
             function of the evidence set, got variants: {observed:?}"
        );
        assert_eq!(
            observed[0], expected_did,
            "the deterministic outcome must be the genuine SST attribution"
        );
    }
}

