//! Integration tests for intelligent Layer-1 routing and gravitational coin selection.
//!
//! Covers:
//! - Bumerang priority (+10000 dominates corridor/eigen)
//! - Exact-Match-First / Subset-Sum before Greedy-Split
//! - Relative FEFO wealth protection (AgeRatio*1000)
//! - Bundle deduplication in RoutingMemoryStore
//! - Lazy decay with 365-day half-life

use chrono::{TimeZone, Utc};
use human_money_core::test_utils::{ACTORS, setup_in_memory_wallet};
use human_money_core::wallet::coin_selection::{SelectionReason, prepare_transfer, rank_vouchers};
use human_money_core::wallet::instance::{VoucherInstance, VoucherStatus};
use human_money_core::wallet::routing_memory::{RoutingMemoryStore, CORRIDOR_CAP};
use rust_decimal_macros::dec;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_voucher(
    voucher_id: &str,
    standard_uuid: &str,
    standard_name: &str,
    creator_id: &str,
    amount: &str,
    txs: Vec<(&str, &str, Option<&str>)>, // (t_id, sender_id, amount)
    creation_date: &str,
) -> human_money_core::Voucher {
    let mut v = human_money_core::Voucher::default();
    v.voucher_id = voucher_id.to_string();
    v.voucher_standard.uuid = standard_uuid.to_string();
    v.voucher_standard.name = standard_name.to_string();
    v.voucher_nonce = bs58::encode(voucher_id.as_bytes()).into_string();
    v.creation_date = creation_date.to_string();
    v.valid_until = "2099-12-31T23:59:59.000000Z".to_string();
    v.nominal_value.amount = amount.to_string();
    v.nominal_value.unit = "MIN".to_string();
    v.nominal_value.abbreviation = Some("MIN".to_string());
    v.creator_profile.id = Some(creator_id.to_string());
    // Build transactions
    for (t_id, sender_id, tx_amount) in txs {
        let mut tx = human_money_core::Transaction::default();
        tx.t_id = t_id.to_string();
        tx.t_type = "transfer".to_string();
        tx.t_time = creation_date.to_string();
        tx.prev_hash = human_money_core::crypto::get_hash(t_id);
        tx.sender_id = Some(sender_id.to_string());
        tx.sender_identity_signature = Some("dummy_sig".to_string());
        tx.recipient_id = "dummy".to_string();
        tx.amount = tx_amount.unwrap_or(amount).to_string();
        tx.receiver_ephemeral_pub_hash = Some("hash".to_string());
        v.transactions.push(tx);
    }
    // Ensure at least one tx
    if v.transactions.is_empty() {
        let mut tx = human_money_core::Transaction::default();
        tx.t_id = human_money_core::crypto::get_hash(voucher_id);
        tx.t_type = "init".to_string();
        tx.t_time = creation_date.to_string();
        tx.prev_hash = human_money_core::crypto::get_hash("prev");
        tx.sender_id = Some(creator_id.to_string());
        tx.sender_identity_signature = Some("dummy_sig".to_string());
        tx.recipient_id = creator_id.to_string();
        tx.amount = amount.to_string();
        v.transactions.push(tx);
    }
    v
}

fn insert_active(
    wallet: &mut human_money_core::Wallet,
    local_id: &str,
    voucher: human_money_core::Voucher,
) {
    wallet.voucher_store.vouchers.insert(
        local_id.to_string(),
        VoucherInstance {
            voucher,
            status: VoucherStatus::Active,
            local_instance_id: local_id.to_string(),
        },
    );
}

fn fixed_time(secs: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(secs, 0).unwrap()
}

// ---------------------------------------------------------------------------
// Bumerang-Priorität
// ---------------------------------------------------------------------------

#[test]
fn test_bumerang_priority_dominates() {
    human_money_core::set_signature_bypass(true);
    let alice = &ACTORS.alice.identity;
    let bob_id = ACTORS.bob.identity.user_id.clone();
    let charlie_id = ACTORS.charlie.identity.user_id.clone();

    let mut wallet = setup_in_memory_wallet(alice);
    let std_uuid = "11111111-1111-1111-1111-111111111111";

    // Voucher A: normal voucher from Charlie (not boomerang for Bob)
    let v_a = make_voucher(
        "vid-a",
        std_uuid,
        "Freetaler",
        &charlie_id,
        "50.00",
        vec![("t-a", &charlie_id, Some("50.00"))],
        "2024-01-01T00:00:00.000000Z",
    );
    insert_active(&mut wallet, "local-a", v_a);

    // Voucher B: boomerang – last tx sender is Bob (the recipient we will send to)
    let v_b = make_voucher(
        "vid-b",
        std_uuid,
        "Freetaler",
        &charlie_id,
        "50.00",
        vec![("t-b", &bob_id, Some("50.00"))],
        "2024-01-01T00:00:00.000000Z",
    );
    insert_active(&mut wallet, "local-b", v_b);

    // Even if we artificially boost corridor for A, bumerang should still win
    let mem = RoutingMemoryStore::new();
    // Give corridor weight to A's path? Both share same std_uuid + recipient, so corridor equal.
    // So boomerang (+10000) must dominate.
    let ranked = rank_vouchers(&wallet, dec!(10), Some(std_uuid), &bob_id, &mem);
    assert_eq!(ranked.len(), 2);
    // B (boomerang) must be first
    assert_eq!(ranked[0].local_instance_id, "local-b");
    assert!(ranked[0].breakdown.s_boomerang == 10_000);
    assert_eq!(ranked[1].breakdown.s_boomerang, 0);
    // Score difference >= 9000
    assert!(ranked[0].score - ranked[1].score >= 9_000);
}

#[test]
fn test_unsigned_sender_id_does_not_get_boomerang_priority() {
    human_money_core::set_signature_bypass(true);
    let alice = &ACTORS.alice.identity;
    let bob_id = ACTORS.bob.identity.user_id.clone();
    let charlie_id = ACTORS.charlie.identity.user_id.clone();

    let mut wallet = setup_in_memory_wallet(alice);
    let std_uuid = "11111111-1111-1111-1111-111111111111";

    // Voucher with unsigned sender_id = bob_id (unauthenticated / spoofed)
    let mut v_spoofed = make_voucher(
        "vid-spoofed",
        std_uuid,
        "Freetaler",
        &charlie_id,
        "50.00",
        vec![("t-spoof", &bob_id, Some("50.00"))],
        "2024-01-01T00:00:00.000000Z",
    );
    // Strip the sender_identity_signature
    v_spoofed.transactions[0].sender_identity_signature = None;
    insert_active(&mut wallet, "local-spoofed", v_spoofed);

    let mem = RoutingMemoryStore::new();
    let ranked = rank_vouchers(&wallet, dec!(10), Some(std_uuid), &bob_id, &mem);
    assert_eq!(ranked.len(), 1);
    // Must NOT receive boomerang score (+10000)
    assert_eq!(ranked[0].breakdown.s_boomerang, 0);
}

// ---------------------------------------------------------------------------
// Exact-Match / Split-Vermeidung (3-Stufen)
// ---------------------------------------------------------------------------

#[test]
fn test_exact_match_single_avoids_split() {
    human_money_core::set_signature_bypass(true);
    let alice = &ACTORS.alice.identity;
    let bob_id = ACTORS.bob.identity.user_id.clone();
    let mut wallet = setup_in_memory_wallet(alice);
    let std_uuid = "22222222-2222-2222-2222-222222222222";

    // Have 100 and 60 vouchers; target 60 should pick the exact 60, not split 100
    let v100 = make_voucher("vid-100", std_uuid, "Freetaler", &bob_id, "100.00", vec![("t-100", &bob_id, Some("100.00"))], "2024-01-01T00:00:00.000000Z");
    let v60 = make_voucher("vid-60", std_uuid, "Freetaler", &bob_id, "60.00", vec![("t-60", &bob_id, Some("60.00"))], "2024-01-01T00:00:00.000000Z");
    insert_active(&mut wallet, "local-100", v100);
    insert_active(&mut wallet, "local-60", v60);

    let mem = RoutingMemoryStore::new();
    let plan = prepare_transfer(&wallet, dec!(60), Some(std_uuid), &bob_id, &mem).unwrap();
    assert_eq!(plan.plan_reason, SelectionReason::ExactMatch);
    assert_eq!(plan.selected.len(), 1);
    assert_eq!(plan.selected[0].local_instance_id, "local-60");
    assert!(!plan.needs_split);
}

#[test]
fn test_subset_sum_preferred_over_greedy_split() {
    human_money_core::set_signature_bypass(true);
    let alice = &ACTORS.alice.identity;
    let bob_id = ACTORS.bob.identity.user_id.clone();
    let mut wallet = setup_in_memory_wallet(alice);
    let std_uuid = "33333333-3333-3333-3333-333333333333";

    // Target 60, have: 50, 30, 30, 100
    // Exact subset 30+30=60 should be preferred over greedy 50+30 (needs split) or single 100 split
    let v50 = make_voucher("vid-50", std_uuid, "Freetaler", &bob_id, "50.00", vec![("t-50", &bob_id, Some("50.00"))], "2024-01-01T00:00:00.000000Z");
    let v30a = make_voucher("vid-30a", std_uuid, "Freetaler", &bob_id, "30.00", vec![("t-30a", &bob_id, Some("30.00"))], "2024-01-01T00:00:00.000000Z");
    let v30b = make_voucher("vid-30b", std_uuid, "Freetaler", &bob_id, "30.00", vec![("t-30b", &bob_id, Some("30.00"))], "2024-01-01T00:00:00.000000Z");
    let v100 = make_voucher("vid-100b", std_uuid, "Freetaler", &bob_id, "100.00", vec![("t-100b", &bob_id, Some("100.00"))], "2024-01-01T00:00:00.000000Z");
    insert_active(&mut wallet, "local-50", v50);
    insert_active(&mut wallet, "local-30a", v30a);
    insert_active(&mut wallet, "local-30b", v30b);
    insert_active(&mut wallet, "local-100b", v100);

    let mem = RoutingMemoryStore::new();
    let plan = prepare_transfer(&wallet, dec!(60), Some(std_uuid), &bob_id, &mem).unwrap();
    // Should find exact subset 30+30, not greedy
    assert_eq!(plan.plan_reason, SelectionReason::SubsetExact);
    assert!(!plan.needs_split);
    assert_eq!(plan.total_selected, dec!(60));
    // Both selected should be the 30s (deterministic: check sums)
    let sum: rust_decimal::Decimal = plan.selected.iter().map(|r| r.amount).sum();
    assert_eq!(sum, dec!(60));
    // Should not include the 100 (would be split)
    assert!(!plan.selected.iter().any(|r| r.local_instance_id == "local-100b"));
}

#[test]
fn test_greedy_split_when_no_exact_available() {
    human_money_core::set_signature_bypass(true);
    let alice = &ACTORS.alice.identity;
    let bob_id = ACTORS.bob.identity.user_id.clone();
    let mut wallet = setup_in_memory_wallet(alice);
    let std_uuid = "44444444-4444-4444-4444-444444444444";

    // Target 60, have only 50 and 40 -> need split: greedy picks highest ranked first
    let v50 = make_voucher("vid-50c", std_uuid, "Freetaler", &bob_id, "50.00", vec![("t-50c", &bob_id, Some("50.00"))], "2024-01-01T00:00:00.000000Z");
    let v40 = make_voucher("vid-40", std_uuid, "Freetaler", &bob_id, "40.00", vec![("t-40", &bob_id, Some("40.00"))], "2024-01-01T00:00:00.000000Z");
    insert_active(&mut wallet, "local-50c", v50);
    insert_active(&mut wallet, "local-40", v40);

    let mem = RoutingMemoryStore::new();
    let plan = prepare_transfer(&wallet, dec!(60), Some(std_uuid), &bob_id, &mem).unwrap();
    assert_eq!(plan.plan_reason, SelectionReason::Greedy);
    assert!(plan.needs_split);
    // Total selected > target (50+40=90) and last will be split
    assert!(plan.total_selected > dec!(60));
    assert_eq!(plan.selected.len(), 2);
}

// ---------------------------------------------------------------------------
// Relativer FEFO Score
// ---------------------------------------------------------------------------

#[test]
fn test_relative_fefo_older_scores_higher() {
    human_money_core::set_signature_bypass(true);
    let alice = &ACTORS.alice.identity;
    let bob_id = ACTORS.bob.identity.user_id.clone();
    let mut wallet = setup_in_memory_wallet(alice);
    let std_uuid = "55555555-5555-5555-5555-555555555555";

    // Two vouchers identical except creation_date
    let v_old = make_voucher("vid-old", std_uuid, "Freetaler", &bob_id, "20.00", vec![("t-old", &bob_id, Some("20.00"))], "2020-01-01T00:00:00.000000Z");
    let v_young = make_voucher("vid-young", std_uuid, "Freetaler", &bob_id, "20.00", vec![("t-young", &bob_id, Some("20.00"))], "2024-01-01T00:00:00.000000Z");
    insert_active(&mut wallet, "local-old", v_old);
    insert_active(&mut wallet, "local-young", v_young);

    let mem = RoutingMemoryStore::new();
    let ranked = rank_vouchers(&wallet, dec!(10), Some(std_uuid), &bob_id, &mem);
    assert_eq!(ranked.len(), 2);
    let old_entry = ranked.iter().find(|r| r.local_instance_id == "local-old").unwrap();
    let young_entry = ranked.iter().find(|r| r.local_instance_id == "local-young").unwrap();
    // Older must have higher s_age
    assert!(old_entry.breakdown.s_age > young_entry.breakdown.s_age, "old {} vs young {}", old_entry.breakdown.s_age, young_entry.breakdown.s_age);
    // And higher total score when other factors equal
    assert!(old_entry.score > young_entry.score);
    // Youngest should be ~ ratio * 1000, oldest ~1000
    assert_eq!(old_entry.breakdown.s_age, 1000);
    // The ranking should put old first
    assert_eq!(ranked[0].local_instance_id, "local-old");
}

// ---------------------------------------------------------------------------
// Bundle-Deduplizierung
// ---------------------------------------------------------------------------

#[test]
fn test_bundle_deduplication_no_double_reinforcement() {
    let mut store = RoutingMemoryStore::new();
    let now = fixed_time(1_000_000);
    let std_uuid = "66666666-6666-6666-6666-666666666666";
    let recipient = "did:key:zBobo";

    let first = store.record_transfer(std_uuid, recipient, "bundle-xyz", now);
    assert!(first, "first record should reinforce");
    let w1 = store.get_weight_no_decay(std_uuid, recipient);

    let second = store.record_transfer(std_uuid, recipient, "bundle-xyz", now);
    assert!(!second, "duplicate bundle should be deduplicated");
    let w2 = store.get_weight_no_decay(std_uuid, recipient);
    assert_eq!(w1, w2, "weight must not increase on duplicate bundle");

    let third = store.record_transfer(std_uuid, recipient, "bundle-abc", now);
    assert!(third);
    let w3 = store.get_weight_no_decay(std_uuid, recipient);
    assert!(w3 > w2, "new bundle should increase weight");
}

// ---------------------------------------------------------------------------
// Lazy Decay (365 Tage Halbwertszeit)
// ---------------------------------------------------------------------------

#[test]
fn test_lazy_decay_half_life_365d() {
    let mut store = RoutingMemoryStore::new();
    let t0 = fixed_time(0);
    let std_uuid = "77777777-7777-7777-7777-777777777777";
    let recipient = "did:key:zDecay";

    // Reinforce to cap approx
    for i in 0..50 {
        store.record_transfer(std_uuid, recipient, &format!("b-{}", i), t0);
    }
    // Force weight to 1000 for deterministic test via direct insert
    // Instead read current weight and decay it
    let initial = store.get_weight_no_decay(std_uuid, recipient);
    assert!(initial > 0);

    // Simulate 365 days later: half-life => ~50%
    let t_half = fixed_time(365 * 86_400);
    let decayed = store.get_weight(std_uuid, recipient, t_half);
    let expected = (initial as f64 * 0.5).round() as i64;
    assert!((decayed as i64 - expected).abs() <= 2, "half-life decay: initial {} decayed {} expected {}", initial, decayed, expected);

    // Another 365 days => quarter
    let t_quarter = fixed_time(2 * 365 * 86_400);
    let decayed2 = store.get_weight(std_uuid, recipient, t_quarter);
    let expected2 = (decayed as f64 * 0.5).round() as i64;
    assert!((decayed2 as i64 - expected2).abs() <= 2, "second half-life: {} vs {}", decayed2, expected2);
}

#[test]
fn test_lazy_decay_no_time_no_decay() {
    let mut store = RoutingMemoryStore::new();
    let now = fixed_time(5_000_000);
    let std_uuid = "88888888-8888-8888-8888-888888888888";
    let recipient = "did:key:zNoDecay";
    store.record_transfer(std_uuid, recipient, "b1", now);
    let w1 = store.get_weight_no_decay(std_uuid, recipient);
    let w2 = store.get_weight(std_uuid, recipient, now);
    assert_eq!(w1, w2);
}

// ---------------------------------------------------------------------------
// Corridor Weight + Eigen Penalty + Chain Only For Own
// ---------------------------------------------------------------------------

#[test]
fn test_scoring_breakdown_components() {
    use human_money_core::wallet::coin_selection::score_voucher;
    // Eigen voucher with chain_len 5 should get S_chain bonus, non-eigen not
    let (score_eigen, bd_eigen) = score_voucher(dec!(10), dec!(10), false, true, 500, 0.5, 5, "uuid", "r");
    let (score_other, bd_other) = score_voucher(dec!(10), dec!(10), false, false, 500, 0.5, 5, "uuid", "r");
    assert!(bd_eigen.s_chain > 0, "eigen should have chain bonus");
    assert_eq!(bd_other.s_chain, 0, "non-eigen chain bonus must be 0");
    assert_eq!(bd_eigen.s_corridor, 500);
    assert_eq!(bd_other.s_corridor, 500);
    assert_eq!(bd_eigen.s_eigen, -2500);
    assert_eq!(bd_other.s_eigen, 0);
    // Eigen penalty should make eigen score lower despite chain bonus
    assert!(score_other > score_eigen - bd_eigen.s_chain, "eigen penalty dominates");
    let _ = (score_eigen, score_other);
}

#[test]
fn test_asymptotic_corridor_cap() {
    let mut store = RoutingMemoryStore::new();
    let now = fixed_time(0);
    let std_uuid = "99999999-9999-9999-9999-999999999999";
    let recipient = "did:key:zCap";
    for i in 0..200 {
        store.record_transfer(std_uuid, recipient, &format!("cap-b-{}", i), now);
    }
    let w = store.get_weight_no_decay(std_uuid, recipient);
    assert!(w <= CORRIDOR_CAP);
    assert_eq!(w, CORRIDOR_CAP, "after many reinforcements corridor must hit cap 1000");
}

#[test]
fn test_lru_cap_1000() {
    let mut store = RoutingMemoryStore::new();
    let now = fixed_time(0);
    for i in 0..1000 {
        store.record_transfer(&format!("uuid-{}", i), "did:key:zLRU", &format!("b-{}", i), now);
    }
    assert_eq!(store.len(), 1000);
    store.record_transfer("uuid-overflow", "did:key:zLRU", "b-overflow", now);
    assert_eq!(store.len(), 1000);
    assert!(store.get_weight_no_decay("uuid-overflow", "did:key:zLRU") > 0);
}

#[test]
fn test_deterministic_ranking_tie_break() {
    human_money_core::set_signature_bypass(true);
    let alice = &ACTORS.alice.identity;
    let bob_id = ACTORS.bob.identity.user_id.clone();
    let mut wallet = setup_in_memory_wallet(alice);
    let std_uuid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    // Two identical vouchers differing only in local_id
    let v1 = make_voucher("vid-1", std_uuid, "Freetaler", &bob_id, "10.00", vec![("t-1", &bob_id, Some("10.00"))], "2024-01-01T00:00:00.000000Z");
    let v2 = make_voucher("vid-2", std_uuid, "Freetaler", &bob_id, "10.00", vec![("t-2", &bob_id, Some("10.00"))], "2024-01-01T00:00:00.000000Z");
    insert_active(&mut wallet, "local-a", v1);
    insert_active(&mut wallet, "local-b", v2);
    let mem = RoutingMemoryStore::new();
    let r1 = rank_vouchers(&wallet, dec!(5), Some(std_uuid), &bob_id, &mem);
    let r2 = rank_vouchers(&wallet, dec!(5), Some(std_uuid), &bob_id, &mem);
    assert_eq!(r1[0].local_instance_id, r2[0].local_instance_id, "ranking must be deterministic");
    // Lexicographic tie break: local-a before local-b if scores equal
    assert_eq!(r1[0].local_instance_id, "local-a");
}

#[test]
fn test_wallet_rank_and_prepare_integration() {
    human_money_core::set_signature_bypass(true);
    let alice = &ACTORS.alice.identity;
    let bob_id = ACTORS.bob.identity.user_id.clone();
    let mut wallet = setup_in_memory_wallet(alice);
    let std_uuid = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    let v = make_voucher("vid-int", std_uuid, "Freetaler", &bob_id, "42.00", vec![("t-int", &bob_id, Some("42.00"))], "2024-01-01T00:00:00.000000Z");
    insert_active(&mut wallet, "local-int", v);

    // Use Wallet facade methods (queries.rs)
    let ranked = wallet.rank_vouchers("10.00", Some(std_uuid), &bob_id).unwrap();
    assert_eq!(ranked.len(), 1);

    let plan = wallet.prepare_transfer("42.00", Some(std_uuid), &bob_id).unwrap();
    assert_eq!(plan.plan_reason, SelectionReason::ExactMatch);
    assert_eq!(plan.selected[0].local_instance_id, "local-int");
}
