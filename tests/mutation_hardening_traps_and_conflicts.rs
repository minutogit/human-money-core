//! tests/mutation_hardening_traps_and_conflicts.rs
//!
//! Targeted mutation hardening regression tests for:
//! - `src/services/conflict_manager.rs` (`check_for_double_spend`, `derive_proof_id`)
//! - `src/services/trap_manager.rs` (`verify_input_owner`)
//!
//! Specifically closes coverage gaps on same-t_id equivocation detection,
//! individual signature-bound evidence fields, input authority validation,
//! and proof ID derivation determinism.

use ed25519_dalek::SigningKey;
use human_money_core::{
    models::conflict::{KnownFingerprints, OwnFingerprints, TransactionFingerprint},
    services::{
        conflict_manager::{check_for_double_spend, derive_proof_id},
        crypto::{create_user_id, derive_owned_ephemeral_key},
        trap_manager::verify_input_owner,
    },
    VoucherCoreError,
};

fn sample_base_fingerprint(ds_tag: &str, t_id: &str) -> TransactionFingerprint {
    TransactionFingerprint {
        ds_tag: ds_tag.to_string(),
        t_id: t_id.to_string(),
        encrypted_timestamp: 1_700_000_000_000_000_000,
        layer2_signature: "sig_dummy_base".to_string(),
        sender_ephemeral_pub: "eph_pub_dummy_base".to_string(),
        deletable_at: "2030-01-01T00:00:00Z".to_string(),
        trap_r: "trap_r_val_1".to_string(),
        trap_s: "trap_s_val_1".to_string(),
        layer2_voucher_id: "voucher_uuid_1".to_string(),
        privacy_guard_hash: "guard_commitment_hash_1".to_string(),
        created_at_ms: 1_700_000_000_000,
    }
}

// =============================================================================
// 1. EQUIVOCATION DETECTION TESTS (check_for_double_spend)
// =============================================================================

#[test]
fn test_identical_fingerprints_no_conflict() {
    let tag = "tag_identical";
    let fp1 = sample_base_fingerprint(tag, "tx_1");
    let fp2 = sample_base_fingerprint(tag, "tx_1");

    let own = OwnFingerprints::default();
    let mut known = KnownFingerprints::default();
    known.local_history.insert(tag.to_string(), vec![fp1]);
    known.foreign_fingerprints.insert(tag.to_string(), vec![fp2]);

    let res = check_for_double_spend(&own, &known);
    assert!(
        res.verifiable_conflicts.is_empty(),
        "Identical fingerprints must be deduplicated and not trigger a conflict"
    );
    assert!(
        res.unverifiable_warnings.is_empty(),
        "Identical fingerprints must not produce warnings"
    );
}

#[test]
fn test_retention_metadata_only_divergence_no_conflict() {
    let tag = "tag_retention";
    let fp1 = sample_base_fingerprint(tag, "tx_1");
    let mut fp2 = sample_base_fingerprint(tag, "tx_1");
    // Only deletable_at and layer2_signature differ (retention/relay metadata)
    fp2.deletable_at = "2035-01-01T00:00:00Z".to_string();
    fp2.layer2_signature = "sig_dummy_variant".to_string();

    let own = OwnFingerprints::default();
    let mut known = KnownFingerprints::default();
    known.local_history.insert(tag.to_string(), vec![fp1]);
    known.foreign_fingerprints.insert(tag.to_string(), vec![fp2]);

    let res = check_for_double_spend(&own, &known);
    assert!(
        res.verifiable_conflicts.is_empty(),
        "Metadata-only differences (deletable_at, signature replay) must not trigger equivocation conflict"
    );
}

#[test]
fn test_same_tid_equivocation_on_trap_r() {
    let tag = "tag_equiv_trap_r";
    let fp1 = sample_base_fingerprint(tag, "tx_same");
    let mut fp2 = sample_base_fingerprint(tag, "tx_same");
    fp2.trap_r = "trap_r_diverged_variant".to_string();

    let own = OwnFingerprints::default();
    let mut known = KnownFingerprints::default();
    known.local_history.insert(tag.to_string(), vec![fp1]);
    known.foreign_fingerprints.insert(tag.to_string(), vec![fp2]);

    let res = check_for_double_spend(&own, &known);
    assert!(
        res.verifiable_conflicts.contains_key(tag),
        "Same-t_id equivocation on trap_r must be detected as verifiable conflict"
    );
    assert_eq!(res.verifiable_conflicts.get(tag).unwrap().len(), 2);
}

#[test]
fn test_same_tid_equivocation_on_trap_s() {
    let tag = "tag_equiv_trap_s";
    let fp1 = sample_base_fingerprint(tag, "tx_same");
    let mut fp2 = sample_base_fingerprint(tag, "tx_same");
    fp2.trap_s = "trap_s_diverged_variant".to_string();

    let own = OwnFingerprints::default();
    let mut known = KnownFingerprints::default();
    known.local_history.insert(tag.to_string(), vec![fp1]);
    known.foreign_fingerprints.insert(tag.to_string(), vec![fp2]);

    let res = check_for_double_spend(&own, &known);
    assert!(
        res.verifiable_conflicts.contains_key(tag),
        "Same-t_id equivocation on trap_s must be detected as verifiable conflict"
    );
    assert_eq!(res.verifiable_conflicts.get(tag).unwrap().len(), 2);
}

#[test]
fn test_same_tid_equivocation_on_encrypted_timestamp() {
    let tag = "tag_equiv_enc_ts";
    let fp1 = sample_base_fingerprint(tag, "tx_same");
    let mut fp2 = sample_base_fingerprint(tag, "tx_same");
    fp2.encrypted_timestamp = 1_700_000_000_999_999_999;

    let own = OwnFingerprints::default();
    let mut known = KnownFingerprints::default();
    known.local_history.insert(tag.to_string(), vec![fp1]);
    known.foreign_fingerprints.insert(tag.to_string(), vec![fp2]);

    let res = check_for_double_spend(&own, &known);
    assert!(
        res.verifiable_conflicts.contains_key(tag),
        "Same-t_id equivocation on encrypted_timestamp must be detected as verifiable conflict"
    );
    assert_eq!(res.verifiable_conflicts.get(tag).unwrap().len(), 2);
}

#[test]
fn test_same_tid_equivocation_on_created_at_ms() {
    let tag = "tag_equiv_created_at";
    let fp1 = sample_base_fingerprint(tag, "tx_same");
    let mut fp2 = sample_base_fingerprint(tag, "tx_same");
    fp2.created_at_ms = 1_700_000_999_999;

    let own = OwnFingerprints::default();
    let mut known = KnownFingerprints::default();
    known.local_history.insert(tag.to_string(), vec![fp1]);
    known.foreign_fingerprints.insert(tag.to_string(), vec![fp2]);

    let res = check_for_double_spend(&own, &known);
    assert!(
        res.verifiable_conflicts.contains_key(tag),
        "Same-t_id equivocation on created_at_ms must be detected as verifiable conflict"
    );
    assert_eq!(res.verifiable_conflicts.get(tag).unwrap().len(), 2);
}

#[test]
fn test_same_tid_equivocation_on_layer2_voucher_id() {
    let tag = "tag_equiv_l2_voucher";
    let fp1 = sample_base_fingerprint(tag, "tx_same");
    let mut fp2 = sample_base_fingerprint(tag, "tx_same");
    fp2.layer2_voucher_id = "voucher_uuid_diverged".to_string();

    let own = OwnFingerprints::default();
    let mut known = KnownFingerprints::default();
    known.local_history.insert(tag.to_string(), vec![fp1]);
    known.foreign_fingerprints.insert(tag.to_string(), vec![fp2]);

    let res = check_for_double_spend(&own, &known);
    assert!(
        res.verifiable_conflicts.contains_key(tag),
        "Same-t_id equivocation on layer2_voucher_id must be detected as verifiable conflict"
    );
    assert_eq!(res.verifiable_conflicts.get(tag).unwrap().len(), 2);
}

#[test]
fn test_same_tid_equivocation_on_privacy_guard_hash() {
    let tag = "tag_equiv_privacy_guard";
    let fp1 = sample_base_fingerprint(tag, "tx_same");
    let mut fp2 = sample_base_fingerprint(tag, "tx_same");
    fp2.privacy_guard_hash = "guard_commitment_diverged".to_string();

    let own = OwnFingerprints::default();
    let mut known = KnownFingerprints::default();
    known.local_history.insert(tag.to_string(), vec![fp1]);
    known.foreign_fingerprints.insert(tag.to_string(), vec![fp2]);

    let res = check_for_double_spend(&own, &known);
    assert!(
        res.verifiable_conflicts.contains_key(tag),
        "Same-t_id equivocation on privacy_guard_hash must be detected as verifiable conflict"
    );
    assert_eq!(res.verifiable_conflicts.get(tag).unwrap().len(), 2);
}

#[test]
fn test_distinct_tid_double_spend() {
    let tag = "tag_distinct_tid";
    let fp1 = sample_base_fingerprint(tag, "tx_first");
    let fp2 = sample_base_fingerprint(tag, "tx_second");

    let own = OwnFingerprints::default();
    let mut known = KnownFingerprints::default();
    known.local_history.insert(tag.to_string(), vec![fp1]);
    known.foreign_fingerprints.insert(tag.to_string(), vec![fp2]);

    let res = check_for_double_spend(&own, &known);
    assert!(
        res.verifiable_conflicts.contains_key(tag),
        "Distinct t_id on same ds_tag must be detected as verifiable conflict"
    );
    assert_eq!(res.verifiable_conflicts.get(tag).unwrap().len(), 2);
}

#[test]
fn test_unverifiable_warning_when_only_in_own_history() {
    let tag = "tag_own_only";
    let fp1 = sample_base_fingerprint(tag, "tx_1");
    let fp2 = sample_base_fingerprint(tag, "tx_2");

    let mut own = OwnFingerprints::default();
    own.history.insert(tag.to_string(), vec![fp1, fp2]);
    let known = KnownFingerprints::default();

    let res = check_for_double_spend(&own, &known);
    assert!(
        res.verifiable_conflicts.is_empty(),
        "Conflict unknown to local_history or foreign_fingerprints cannot be verifiable"
    );
    assert!(
        res.unverifiable_warnings.contains_key(tag),
        "Conflict present only in own.history must be surfaced as unverifiable warning"
    );
}

// =============================================================================
// 2. PROOF ID CANONICALIZATION & DERIVATION TESTS (derive_proof_id)
// =============================================================================

#[test]
fn test_derive_proof_id_whitespace_insensitivity() {
    let raw_key = [42u8; 32];
    let did = format!("did:key:z{}", bs58::encode(raw_key).into_string());
    let prev_hash = bs58::encode([1u8; 32]).into_string();

    let clean_id = derive_proof_id(&did, &prev_hash).expect("clean derivation failed");
    let dirty_id = derive_proof_id(
        &format!("  \n\t {} \r\n ", did),
        &prev_hash,
    )
    .expect("dirty derivation failed");

    assert_eq!(
        clean_id, dirty_id,
        "derive_proof_id must be invariant to leading, trailing, and inter-whitespace characters"
    );
}

#[test]
fn test_derive_proof_id_user_id_prefix_with_did() {
    let raw_key = [77u8; 32];
    let base58_key = bs58::encode(raw_key).into_string();
    let full_user_id = format!("Alice@did:key:z{}", base58_key);
    let bare_did = format!("did:key:z{}", base58_key);
    let prev_hash = bs58::encode([2u8; 32]).into_string();

    let id_from_user = derive_proof_id(&full_user_id, &prev_hash).expect("user_id derivation failed");
    let id_from_bare = derive_proof_id(&bare_did, &prev_hash).expect("bare did derivation failed");

    assert_eq!(
        id_from_user, id_from_bare,
        "derive_proof_id with user profile prefix must resolve to same proof_id as bare did"
    );
}

#[test]
fn test_derive_proof_id_invalid_did_format() {
    let invalid_did = "did:key:z!!!NOT_VALID_BASE58###";
    let prev_hash = bs58::encode([3u8; 32]).into_string();

    let res = derive_proof_id(invalid_did, &prev_hash);
    assert!(
        matches!(res, Err(VoucherCoreError::ProofImport(_))),
        "Invalid Base58 in did:key format must return VoucherCoreError::ProofImport"
    );
}

#[test]
fn test_derive_proof_id_anonymous_fallback_deterministic() {
    let anon1 = "   anonymous_offender_id   ";
    let anon2 = "anonymous_offender_id";
    let prev_hash = bs58::encode([4u8; 32]).into_string();

    let res1 = derive_proof_id(anon1, &prev_hash).expect("anon1 failed");
    let res2 = derive_proof_id(anon2, &prev_hash).expect("anon2 failed");

    assert_eq!(
        res1, res2,
        "Anonymous fallback must also be whitespace-insensitive and deterministic"
    );
}

// =============================================================================
// 3. INPUT AUTHORITY VERIFICATION (verify_input_owner)
// =============================================================================

#[test]
fn test_verify_input_owner_accepts_valid_and_rejects_corrupted() {
    let secret = [55u8; 32];
    let seed = [99u8; 32];
    let sk = SigningKey::from_bytes(&secret);
    let input_key = derive_owned_ephemeral_key(&sk, &seed).expect("key derivation failed");
    let eph_pub = input_key.verifying_key().to_bytes();
    let did = create_user_id(&sk.verifying_key(), None).expect("did creation failed");
    let seed_b58 = bs58::encode(seed).into_string();

    // 1. Valid case
    let valid_res = verify_input_owner(&did, &seed_b58, &eph_pub);
    assert!(
        valid_res.is_ok(),
        "Valid input owner opening must succeed: {:?}",
        valid_res.err()
    );

    // 2. Corrupted eph_pub must be rejected with VoucherCoreError::Crypto
    let mut bad_eph_pub = eph_pub;
    bad_eph_pub[0] ^= 0xFF;
    let corrupted_eph_res = verify_input_owner(&did, &seed_b58, &bad_eph_pub);
    assert!(
        matches!(corrupted_eph_res, Err(VoucherCoreError::Crypto(_))),
        "Mismatched ephemeral point must be rejected with VoucherCoreError::Crypto, got {:?}",
        corrupted_eph_res
    );

    // 3. Mismatched seed must be rejected
    let bad_seed = bs58::encode([100u8; 32]).into_string();
    let bad_seed_res = verify_input_owner(&did, &bad_seed, &eph_pub);
    assert!(
        matches!(bad_seed_res, Err(VoucherCoreError::Crypto(_))),
        "Mismatched input seed must be rejected with VoucherCoreError::Crypto, got {:?}",
        bad_seed_res
    );

    // 4. Invalid DID must fail
    let invalid_did_res = verify_input_owner("did:key:invalid", &seed_b58, &eph_pub);
    assert!(
        invalid_did_res.is_err(),
        "Invalid DID format must return an error"
    );
}
