//! # src/wallet/coin_selection.rs
//!
//! Gravitational Coin Selection for Human Money vouchers.
//!
//! Implements deterministic scoring and a 3-stage selection strategy:
//! Stage 1: Exact-Match-First (single voucher exactly equals target)
//! Stage 2: Subset-Sum (combination of vouchers exactly equals target, no split)
//! Stage 3: Greedy-Split (ranked list, split last voucher if needed)
//!
//! Scoring components (deterministic, summed):
//! - **Boomerang +10000**: voucher previously came from the current recipient (return flow).
//! - **Eigen -2500**: voucher was self-issued (creator == wallet owner) — penalty to avoid
//!   circulating own debt first.
//! - **Korridor 0..1000**: weight from `RoutingMemoryStore` for (standard_uuid, recipient_id).
//! - **Relativer FEFO-Vermögensschutz AgeRatio*1000**: older vouchers score higher relative to
//!   the wallet's age span (protects young assets, spends old first). AgeRatio = age / max_age.
//! - **S_chain only for own**: chain-length bonus only for self-issued vouchers.
//! - **S_fit Exact Match +300 / Split -100**: exact amount match bonus, split penalty.

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

use crate::wallet::instance::VoucherStatus;
use crate::wallet::routing_memory::RoutingMemoryStore;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Reason for selecting a voucher (for forensic/UI explainability).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SelectionReason {
    /// Single voucher exactly matches the target amount.
    ExactMatch,
    /// Part of a subset that exactly matches the target (no split).
    SubsetExact,
    /// Selected via greedy ranking, may include a split on the last item.
    Greedy,
    /// Scored but not selected.
    NotSelected,
}

/// A voucher ranked by gravitational score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RankedVoucher {
    /// Local instance id of the voucher.
    pub local_instance_id: String,
    /// Deterministic total score (higher = preferred).
    pub score: i64,
    /// Breakdown for debugging / audit.
    pub breakdown: ScoreBreakdown,
    /// Reason (filled after selection).
    pub reason: SelectionReason,
    /// Current spendable amount of this voucher.
    pub amount: Decimal,
    /// Standard UUID of the voucher.
    pub standard_uuid: String,
}

/// Detailed score components.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScoreBreakdown {
    pub s_boomerang: i64,
    pub s_eigen: i64,
    pub s_corridor: i64,
    pub s_age: i64,
    pub s_chain: i64,
    pub s_fit: i64,
}

/// Result of `prepare_transfer`: ordered list of sources to use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferPlan {
    /// Ranked + selected vouchers in order of use.
    pub selected: Vec<RankedVoucher>,
    /// Total amount covered by `selected` (may exceed target if split not needed, or equal if exact).
    pub total_selected: Decimal,
    /// Target amount requested.
    pub target: Decimal,
    /// Whether the last voucher needs a split (true if total_selected > target).
    pub needs_split: bool,
    /// Overall plan reason.
    pub plan_reason: SelectionReason,
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

/// Compute deterministic score for a single voucher instance.
///
/// Parameters:
/// - `instance` – the voucher instance (must be Active)
/// - `standard_uuid` – the voucher's standard UUID (redundant but explicit)
/// - `amount` – spendable amount of the voucher
/// - `target` – the transfer target amount
/// - `recipient_id` – intended recipient (for boomerang + corridor)
/// - `owner_id` – wallet owner's user_id (for eigen check)
/// - `routing_memory` – corridor weights (0..1000)
/// - `is_boomerang` – true if voucher's source sender == recipient_id
/// - `is_eigen` – true if voucher creator == owner_id
/// - `age_ratio` – relative age 0.0..1.0 (1.0 = oldest in wallet for this asset class)
/// - `chain_len` – number of transactions beyond init (hop depth)
#[allow(clippy::too_many_arguments)] // Keep the established scoring API stable.
pub fn score_voucher(
    amount: Decimal,
    target: Decimal,
    is_boomerang: bool,
    is_eigen: bool,
    corridor_weight: u32,
    age_ratio: f64,
    chain_len: usize,
    standard_uuid: &str,
    _recipient_id: &str,
) -> (i64, ScoreBreakdown) {
    let _ = standard_uuid;
    let mut bd = ScoreBreakdown::default();

    // Boomerang +10000
    bd.s_boomerang = if is_boomerang { 10_000 } else { 0 };

    // Eigen -2500 (penalty for self-issued)
    bd.s_eigen = if is_eigen { -2500 } else { 0 };

    // Korridor 0..1000
    bd.s_corridor = corridor_weight.clamp(0, 1000) as i64;

    // Relativer FEFO: AgeRatio*1000 (older => higher)
    let age_clamped = age_ratio.clamp(0.0, 1.0);
    bd.s_age = (age_clamped * 1000.0).round() as i64;

    // S_chain only for own (eigen) vouchers: chain_len bonus
    // For non-eigen, chain score is 0.
    bd.s_chain = if is_eigen {
        // Small bonus per hop, capped at 500 to avoid dominating.
        (chain_len as i64 * 10).min(500)
    } else {
        0
    };

    // S_fit: Exact Match +300 / Split -100
    bd.s_fit = if amount == target {
        300
    } else if amount > target {
        // Would require split if used as single source -> penalty
        if is_boomerang {
            // Boomerang split is less penalized? Keep -100 anyway per spec.
            -100
        } else {
            -100
        }
    } else {
        // amount < target: no fit penalty/bonus unless part of subset
        0
    };

    let total = bd.s_boomerang + bd.s_eigen + bd.s_corridor + bd.s_age + bd.s_chain + bd.s_fit;
    (total, bd)
}

// ---------------------------------------------------------------------------
// Ranking
// ---------------------------------------------------------------------------

/// Rank all active vouchers for a given target and recipient.
///
/// Returns a vector sorted descending by score (deterministic tie-break by
/// local_instance_id lexicographically).
pub fn rank_vouchers(
    wallet: &crate::wallet::Wallet,
    target: Decimal,
    standard_uuid_filter: Option<&str>,
    recipient_id: &str,
    routing_memory: &RoutingMemoryStore,
) -> Vec<RankedVoucher> {
    rank_vouchers_internal(wallet, target, standard_uuid_filter, recipient_id, routing_memory, Utc::now())
}

fn rank_vouchers_internal(
    wallet: &crate::wallet::Wallet,
    target: Decimal,
    standard_uuid_filter: Option<&str>,
    recipient_id: &str,
    routing_memory: &RoutingMemoryStore,
    now: DateTime<Utc>,
) -> Vec<RankedVoucher> {
    // Collect ages for relative FEFO calculation.
    let mut ages: Vec<(String, f64)> = Vec::new();
    let mut max_age_secs: f64 = 1.0;

    // First pass: gather creation dates for this asset class.
    for (lid, inst) in &wallet.voucher_store.vouchers {
        if !matches!(inst.status, VoucherStatus::Active) {
            continue;
        }
        if let Some(filter) = standard_uuid_filter {
            if inst.voucher.voucher_standard.uuid != filter {
                continue;
            }
        }
        let creation_secs = DateTime::parse_from_rfc3339(&inst.voucher.creation_date)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or(now);
        let age_secs = (now - creation_secs).num_seconds().max(0) as f64;
        ages.push((lid.clone(), age_secs));
        if age_secs > max_age_secs {
            max_age_secs = age_secs;
        }
    }
    let age_map: HashMap<String, f64> = ages.into_iter().collect();

    let mut ranked: Vec<RankedVoucher> = Vec::new();

    for (lid, inst) in &wallet.voucher_store.vouchers {
        if !matches!(inst.status, VoucherStatus::Active) {
            continue;
        }
        if let Some(filter) = standard_uuid_filter {
            if inst.voucher.voucher_standard.uuid != filter {
                continue;
            }
        }
        // Spendable amount = last tx amount or sender_remaining_amount logic?
        // Simplified: use nominal_value.amount parsed, or last transaction amount.
        let amount_str = inst
            .voucher
            .transactions
            .last()
            .map(|tx| {
                // If we own the change branch, use sender_remaining_amount
                // Heuristic: if transaction has change and we are sender, use remaining.
                // For ranking we approximate with the amount field if not split known.
                // Try to infer from instance: if last tx sender == owner, use sender_remaining.
                // Otherwise use tx.amount.
                // Since we have no identity here, use tx.amount as spendable.
                // Caller can override via balance calculation, but for ranking consistency use tx.amount.
                // To be more accurate, we check if sender_remaining_amount exists and treat that as balance
                // when the voucher is a change output (conservative).
                // We prefer sender_remaining_amount when present and amount != sender_remaining_amount,
                // assuming the wallet holds the change side.
                // However we cannot know ownership without identity; we use a heuristic:
                // if change exists, rank by sender_remaining_amount (more accurate for change vouchers).
                if let Some(rem) = &tx.sender_remaining_amount {
                    // Determine if this voucher is the change side: check if tx.t_type == "split"
                    // If split, the holder of change holds remaining amount.
                    // We rank by remaining in that case (approx). Otherwise use amount.
                    if tx.t_type == "split" {
                        rem.clone()
                    } else {
                        tx.amount.clone()
                    }
                } else {
                    tx.amount.clone()
                }
            })
            .unwrap_or_else(|| inst.voucher.nominal_value.amount.clone());

        let amount = Decimal::from_str(&amount_str).unwrap_or(Decimal::ZERO);

        // Boomerang: check if voucher's source sender == recipient_id
        // Cryptographic verification:
        // - In public mode, only count sender_id if sender_identity_signature is present.
        // - In stealth/flexible mode (privacy_guard present), do not award boomerang score without decrypted payload.
        let is_boomerang = {
            let mut found_boomerang = false;
            for tx in inst.voucher.transactions.iter().rev() {
                if tx.privacy_guard.is_some() {
                    // Stealth / Flexible mode: without private keys to decrypt RecipientPayload,
                    // we cannot verify the sender. Do NOT award boomerang score from unverified data.
                    continue;
                } else if tx.sender_identity_signature.is_some() {
                    // Public mode with cryptographic signature
                    if let Some(ref sid) = tx.sender_id {
                        if sid == &wallet.profile.user_id {
                            // Sent by ourselves -> continue searching backwards
                            continue;
                        } else if sid == recipient_id {
                            found_boomerang = true;
                            break;
                        } else {
                            // Another authenticated sender -> not a boomerang
                            break;
                        }
                    }
                }
            }
            found_boomerang
        };

        // Eigen: creator == wallet owner? (SAI / prefix tolerant)
        let is_eigen = inst.voucher.is_to_creator(&wallet.profile.user_id);

        let corridor_weight = routing_memory.get_weight(&inst.voucher.voucher_standard.uuid, recipient_id, now);

        let age_secs = age_map.get(lid).copied().unwrap_or(0.0);
        let age_ratio = if max_age_secs > 0.0 { age_secs / max_age_secs } else { 0.0 };

        let chain_len = inst.voucher.transactions.len().saturating_sub(1);

        let (score, breakdown) = score_voucher(
            amount,
            target,
            is_boomerang,
            is_eigen,
            corridor_weight,
            age_ratio,
            chain_len,
            &inst.voucher.voucher_standard.uuid,
            recipient_id,
        );

        ranked.push(RankedVoucher {
            local_instance_id: lid.clone(),
            score,
            breakdown,
            reason: SelectionReason::NotSelected,
            amount,
            standard_uuid: inst.voucher.voucher_standard.uuid.clone(),
        });
    }

    // Deterministic sort: descending score, then lexicographic local_instance_id
    ranked.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.local_instance_id.cmp(&b.local_instance_id)));
    ranked
}

// ---------------------------------------------------------------------------
// 3-Stage Selection
// ---------------------------------------------------------------------------

/// Maximum allowed DP states in subset-sum search to prevent DoS / high memory usage.
pub const MAX_DP_STATES: usize = 2000;

/// Prepare a transfer plan for a given target amount.
///
/// Implements 3-stage logic:
/// 1. Exact-Match-First: if any single voucher == target, pick highest-ranked such.
/// 2. Subset-Sum: search subset of vouchers that sums to exactly target (bounded search).
/// 3. Greedy-Split: take ranked vouchers greedily until target reached, last one may be split.
pub fn prepare_transfer(
    wallet: &crate::wallet::Wallet,
    target: Decimal,
    standard_uuid_filter: Option<&str>,
    recipient_id: &str,
    routing_memory: &RoutingMemoryStore,
) -> Result<TransferPlan, crate::error::VoucherCoreError> {
    if target <= Decimal::ZERO {
        return Err(crate::error::VoucherCoreError::Wallet(
            crate::error::WalletError::InvalidAmount {
                reason: "Target amount must be positive".to_string(),
            },
        ));
    }

    let ranked = rank_vouchers(wallet, target, standard_uuid_filter, recipient_id, routing_memory);

    if ranked.is_empty() {
        return Err(crate::error::VoucherCoreError::Wallet(
            crate::error::WalletError::InvalidAmount {
                reason: "No active vouchers available for selection".to_string(),
            },
        ));
    }

    // Quick insufficient funds check (safe saturating summation)
    let total_available: Decimal = ranked
        .iter()
        .fold(Decimal::ZERO, |acc, r| acc.saturating_add(r.amount));
    if total_available < target {
        return Err(crate::error::VoucherCoreError::InsufficientFunds {
            available: total_available,
            needed: target,
        });
    }

    // Stage 1: Exact-Match-First (single voucher)
    if let Some(exact) = ranked.iter().find(|r| r.amount == target) {
        let mut selected = vec![exact.clone()];
        selected[0].reason = SelectionReason::ExactMatch;
        // Re-score breakdown already has +300 for exact? Ensure.
        return Ok(TransferPlan {
            total_selected: target,
            target,
            needs_split: false,
            plan_reason: SelectionReason::ExactMatch,
            selected,
        });
    }

    // Stage 2: Subset-Sum (exact combination without split)
    // Bounded exact subset search: use DP/backtracking limited to reasonable size.
    // We attempt to find subset summing to target, preferring fewer vouchers and higher total score.
    if let Some(subset) = find_exact_subset(&ranked, target) {
        let mut selected = subset;
        for r in &mut selected {
            r.reason = SelectionReason::SubsetExact;
        }
        return Ok(TransferPlan {
            total_selected: target,
            target,
            needs_split: false,
            plan_reason: SelectionReason::SubsetExact,
            selected,
        });
    }

    // Stage 3: Greedy-Split
    let mut selected = Vec::new();
    let mut acc = Decimal::ZERO;
    for mut rv in ranked.into_iter() {
        if acc >= target {
            break;
        }
        // If adding this voucher would exceed target, we still take it (will be split)
        // but we stop after.
        let remaining = target - acc;
        if rv.amount >= remaining {
            // This voucher will be split (or exactly cover remaining)
            rv.reason = SelectionReason::Greedy;
            acc = acc.saturating_add(rv.amount);
            selected.push(rv);
            break;
        } else {
            rv.reason = SelectionReason::Greedy;
            acc = acc.saturating_add(rv.amount);
            selected.push(rv);
        }
    }

    // If greedy didn't reach target (should not happen due to earlier check), error
    if acc < target {
        return Err(crate::error::VoucherCoreError::InsufficientFunds {
            available: total_available,
            needed: target,
        });
    }

    // total_selected is sum of selected voucher amounts (before split)
    let total_selected: Decimal = selected
        .iter()
        .fold(Decimal::ZERO, |acc, r| acc.saturating_add(r.amount));
    let needs_split = total_selected > target;

    Ok(TransferPlan {
        selected,
        total_selected,
        target,
        needs_split,
        plan_reason: SelectionReason::Greedy,
    })
}

/// Bounded exact subset search.
///
/// Uses DP with HashMap from sum -> best subset (by higher score sum and fewer items).
/// Limited to n <= 20 for exhaustive; for larger n, uses greedy windowed search.
/// Returns subset that sums exactly to target, preferring higher total score.
fn find_exact_subset(ranked: &[RankedVoucher], target: Decimal) -> Option<Vec<RankedVoucher>> {
    let n = ranked.len();
    if n == 0 {
        return None;
    }
    // For performance, limit exhaustive search to 20 vouchers (2^20 ~ 1M combos).
    // For larger sets, consider only top 20 ranked candidates for subset-sum.
    let candidates: Vec<RankedVoucher> = if n > 20 {
        ranked.iter().take(20).cloned().collect()
    } else {
        ranked.to_vec()
    };

    // DP: map sum -> (score_sum, subset_indices)
    // Use BTree-like deterministic iteration.
    let mut dp: HashMap<Decimal, (i64, Vec<usize>)> = HashMap::new();
    dp.insert(Decimal::ZERO, (0, Vec::new()));

    for (idx, rv) in candidates.iter().enumerate() {
        if dp.len() > MAX_DP_STATES {
            // Early fallback to None -> Greedy on state explosion
            return None;
        }

        let mut new_entries: Vec<(Decimal, (i64, Vec<usize>))> = Vec::new();
        for (sum, (score_sum, subset)) in dp.iter() {
            let new_sum = match sum.checked_add(rv.amount) {
                Some(s) => s,
                None => continue,
            };
            if new_sum > target {
                continue;
            }
            if dp.contains_key(&new_sum) && new_entries.iter().any(|(s, _)| s == &new_sum) {
                continue;
            }
            let new_score = *score_sum + rv.score;
            let mut new_subset = subset.clone();
            new_subset.push(idx);
            // Keep best score for this sum
            let should_insert = match dp.get(&new_sum) {
                Some((existing_score, existing_subset)) => {
                    new_score > *existing_score
                        || (new_score == *existing_score && new_subset.len() < existing_subset.len())
                }
                None => true,
            };
            if should_insert {
                // Also check new_entries for duplicate sum
                let existing_in_new = new_entries.iter().find(|(s, _)| s == &new_sum);
                let dominated = if let Some((_, (es, _))) = existing_in_new {
                    *es >= new_score
                } else {
                    false
                };
                if !dominated {
                    new_entries.push((new_sum, (new_score, new_subset)));
                }
            }
        }
        for (sum, val) in new_entries {
            dp.insert(sum, val);
        }

        if dp.len() > MAX_DP_STATES {
            return None;
        }

        // Early exit as soon as target is reached with optimal candidates
        if dp.contains_key(&target) {
            break;
        }
    }

    if let Some((_, indices)) = dp.get(&target) {
        if indices.is_empty() {
            return None;
        }
        let subset = indices.iter().map(|i| candidates[*i].clone()).collect();
        return Some(subset);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    #[test]
    fn test_score_boomerang_dominates() {
        let (score_b, _) = score_voucher(dec!(10), dec!(10), true, false, 0, 0.5, 0, "uuid", "did:key:zBob");
        let (score_no, _) = score_voucher(dec!(10), dec!(10), false, false, 0, 0.5, 0, "uuid", "did:key:zBob");
        assert!(score_b > score_no);
        assert!(score_b - score_no >= 9000);
    }

    #[test]
    fn test_score_eigen_penalty() {
        let (score_eigen, _) = score_voucher(dec!(10), dec!(10), false, true, 0, 0.5, 0, "uuid", "did:key:zBob");
        let (score_normal, _) = score_voucher(dec!(10), dec!(10), false, false, 0, 0.5, 0, "uuid", "did:key:zBob");
        assert!(score_normal > score_eigen);
        assert_eq!(score_normal - score_eigen, 2500);
    }

    #[test]
    fn test_score_corridor_range() {
        let (s0, _) = score_voucher(dec!(10), dec!(15), false, false, 0, 0.0, 0, "uuid", "r");
        let (s1000, _) = score_voucher(dec!(10), dec!(15), false, false, 1000, 0.0, 0, "uuid", "r");
        assert_eq!(s1000 - s0, 1000);
    }

    #[test]
    fn test_score_fit_exact_vs_split() {
        let (s_exact, _) = score_voucher(dec!(10), dec!(10), false, false, 0, 0.0, 0, "uuid", "r");
        let (s_split, _) = score_voucher(dec!(20), dec!(10), false, false, 0, 0.0, 0, "uuid", "r");
        assert!(s_exact > s_split);
        assert_eq!(s_exact - s_split, 400); // +300 vs -100
    }

    #[test]
    fn test_find_exact_subset_early_exit() {
        let ranked = vec![
            RankedVoucher {
                local_instance_id: "v1".to_string(),
                score: 100,
                breakdown: ScoreBreakdown::default(),
                reason: SelectionReason::NotSelected,
                amount: dec!(5),
                standard_uuid: "std".to_string(),
            },
            RankedVoucher {
                local_instance_id: "v2".to_string(),
                score: 90,
                breakdown: ScoreBreakdown::default(),
                reason: SelectionReason::NotSelected,
                amount: dec!(5),
                standard_uuid: "std".to_string(),
            },
            RankedVoucher {
                local_instance_id: "v3".to_string(),
                score: 50,
                breakdown: ScoreBreakdown::default(),
                reason: SelectionReason::NotSelected,
                amount: dec!(10),
                standard_uuid: "std".to_string(),
            },
        ];
        let subset = find_exact_subset(&ranked, dec!(10));
        assert!(subset.is_some());
        let s = subset.unwrap();
        let total: Decimal = s.iter().fold(Decimal::ZERO, |acc, v| acc.saturating_add(v.amount));
        assert_eq!(total, dec!(10));
    }

    #[test]
    fn test_find_exact_subset_dp_cap_fallback() {
        // If DP states explode beyond MAX_DP_STATES, find_exact_subset returns None safely
        let mut ranked = Vec::new();
        for i in 1..=20 {
            // Power of 2 amounts to generate up to 2^20 distinct sums if unconstrained
            ranked.push(RankedVoucher {
                local_instance_id: format!("v{}", i),
                score: 100 - i,
                breakdown: ScoreBreakdown::default(),
                reason: SelectionReason::NotSelected,
                amount: Decimal::from(1i64 << (i - 1)),
                standard_uuid: "std".to_string(),
            });
        }
        // Very large target that encompasses all combinations
        let result = find_exact_subset(&ranked, Decimal::from(10_000_000));
        // With 20 items and unique sums, states would exceed 2000, so it must return None cleanly
        assert!(result.is_none());
    }
}
