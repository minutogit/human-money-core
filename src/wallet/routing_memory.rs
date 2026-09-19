//! # src/wallet/routing_memory.rs
//!
//! Intelligent Layer-1 routing memory for the Human Money voucher system.
//!
//! The `RoutingMemoryStore` implements a corridor-based reinforcement memory
//! that learns which voucher asset classes flow to which recipients. It is used
//! by the gravitational coin selection to prefer corridor-proven vouchers.
//!
//! Properties:
//! - **Asymptotic reinforcement** up to cap 1000 (diminishing returns).
//! - **Bundle deduplication**: same `bundle_id` never reinforces twice per corridor.
//! - **Lazy decay** with 365 days half-life (exponential decay on read, no background task).
//! - **LRU cap** of 1000 corridor entries (least-recently-used eviction).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Maximum corridor weight (cap for asymptotic reinforcement).
pub const CORRIDOR_CAP: u32 = 1000;
/// Half-life for lazy decay in days.
pub const HALF_LIFE_DAYS: f64 = 365.0;
/// Maximum number of corridor entries (LRU cap).
pub const MAX_CORRIDORS: usize = 1000;
/// Maximum bundle IDs remembered per corridor (memory-bloat cap, AUDIT-00-WILDCARD-10).
pub const MAX_BUNDLE_IDS_PER_CORRIDOR: usize = 256;
/// Window after which a bundle_id dedup entry is considered expired (days).
pub const BUNDLE_DEDUP_WINDOW_DAYS: f64 = 90.0;

/// Unique corridor key: (standard_uuid, recipient_id).
/// Length-prefixed SHA3-256 hash for deterministic, delimiter-free HashMap indexing.
fn corridor_key(standard_uuid: &str, recipient_id: &str) -> String {
    crate::services::crypto::get_hash_from_slices(&[
        standard_uuid.as_bytes(),
        recipient_id.as_bytes(),
    ])
}

/// A single corridor entry storing reinforcement weight and deduplication state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CorridorEntry {
    /// Current corridor weight in 0..=1000.
    pub weight: u32,
    /// Set of already counted `bundle_id`s for deduplication.
    /// Kept with `#[serde(default)]` for seamless backward compatibility with
    /// existing wallet files. New code also maintains `seen_bundle_timestamps`.
    #[serde(default)]
    pub seen_bundle_ids: HashSet<String>,
    /// New: timestamped bundle deduplication map. Allows windowed expiry and
    /// LRU eviction per corridor. `#[serde(default)]` ensures old wallets
    /// (only `seen_bundle_ids`) deserialize cleanly.
    #[serde(default)]
    pub seen_bundle_timestamps: HashMap<String, DateTime<Utc>>,
    /// Last access / update timestamp (used for lazy decay and LRU).
    pub last_update: DateTime<Utc>,
}

impl CorridorEntry {
    /// Create a fresh entry with weight 0.
    pub fn new(now: DateTime<Utc>) -> Self {
        Self {
            weight: 0,
            seen_bundle_ids: HashSet::new(),
            seen_bundle_timestamps: HashMap::new(),
            last_update: now,
        }
    }

    /// Migrate legacy `seen_bundle_ids` into `seen_bundle_timestamps` if the
    /// latter is empty. Keeps `seen_bundle_ids` for backward-compatible writes.
    pub fn migrate_legacy(&mut self) {
        if self.seen_bundle_timestamps.is_empty() && !self.seen_bundle_ids.is_empty() {
            for id in self.seen_bundle_ids.iter() {
                self.seen_bundle_timestamps
                    .insert(id.clone(), self.last_update);
            }
        }
        // Ensure set and map stay in sync for legacy readers: populate set
        // from timestamps if set is empty but map has entries (new→old compat).
        if self.seen_bundle_ids.is_empty() && !self.seen_bundle_timestamps.is_empty() {
            for k in self.seen_bundle_timestamps.keys() {
                self.seen_bundle_ids.insert(k.clone());
            }
        }
    }

    /// Check whether a bundle_id is currently deduplicated (and not expired).
    pub fn contains_bundle(&self, bundle_id: &str, now: DateTime<Utc>) -> bool {
        if let Some(ts) = self.seen_bundle_timestamps.get(bundle_id) {
            let elapsed_secs = (now - *ts).num_seconds().max(0) as f64;
            let days = elapsed_secs / 86_400.0;
            days <= BUNDLE_DEDUP_WINDOW_DAYS
        } else {
            // Fallback to legacy set if timestamp map not populated
            self.seen_bundle_ids.contains(bundle_id)
        }
    }

    /// Returns true if the given bundle's dedup entry is expired at `now`.
    pub fn is_bundle_expired(&self, bundle_id: &str, now: DateTime<Utc>) -> bool {
        if let Some(ts) = self.seen_bundle_timestamps.get(bundle_id) {
            let elapsed_secs = (now - *ts).num_seconds().max(0) as f64;
            let days = elapsed_secs / 86_400.0;
            days > BUNDLE_DEDUP_WINDOW_DAYS
        } else {
            false
        }
    }

    /// Prune expired bundle IDs older than `BUNDLE_DEDUP_WINDOW_DAYS`.
    /// Returns number of entries removed.
    pub fn prune_expired_bundles(&mut self, now: DateTime<Utc>) -> usize {
        self.migrate_legacy();
        let mut to_remove = Vec::new();
        for (bid, ts) in &self.seen_bundle_timestamps {
            let elapsed_secs = (now - *ts).num_seconds().max(0) as f64;
            let days = elapsed_secs / 86_400.0;
            if days > BUNDLE_DEDUP_WINDOW_DAYS {
                to_remove.push(bid.clone());
            }
        }
        let n = to_remove.len();
        for bid in to_remove {
            self.seen_bundle_timestamps.remove(&bid);
            self.seen_bundle_ids.remove(&bid);
        }
        n
    }

    /// Enforce per-corridor bundle cap via LRU eviction of oldest timestamps.
    fn ensure_bundle_capacity(&mut self) {
        if self.seen_bundle_timestamps.len() <= MAX_BUNDLE_IDS_PER_CORRIDOR {
            return;
        }
        // Evict oldest entries first
        let mut entries: Vec<(String, DateTime<Utc>)> = self
            .seen_bundle_timestamps
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        entries.sort_by_key(|(_, ts)| *ts);
        let to_evict = entries.len() - MAX_BUNDLE_IDS_PER_CORRIDOR;
        for (bid, _) in entries.iter().take(to_evict) {
            self.seen_bundle_timestamps.remove(bid);
            self.seen_bundle_ids.remove(bid);
        }
    }

    /// Removes a bundle_id **only if it exists**. Returns true if removed.
    /// Conditional removal helper required by hardening spec.
    pub fn remove_bundle_id(&mut self, bundle_id: &str) -> bool {
        let existed = self.seen_bundle_timestamps.contains_key(bundle_id)
            || self.seen_bundle_ids.contains(bundle_id);
        if existed {
            self.seen_bundle_timestamps.remove(bundle_id);
            self.seen_bundle_ids.remove(bundle_id);
            true
        } else {
            false
        }
    }

    /// Removes a bundle_id **only if it is expired** (older than dedup window).
    /// Returns true if removed.
    pub fn remove_bundle_id_if_expired(&mut self, bundle_id: &str, now: DateTime<Utc>) -> bool {
        if self.is_bundle_expired(bundle_id, now) {
            self.remove_bundle_id(bundle_id)
        } else {
            false
        }
    }

    /// Calculate decayed weight without mutating.
    pub fn decayed_weight(&self, now: DateTime<Utc>) -> u32 {
        let elapsed_secs = (now - self.last_update).num_seconds().max(0) as f64;
        if elapsed_secs <= 0.0 || self.weight == 0 {
            return self.weight;
        }
        let days = elapsed_secs / 86_400.0;
        let factor = 0.5_f64.powf(days / HALF_LIFE_DAYS);
        let decayed = (self.weight as f64 * factor).round() as i64;
        decayed.clamp(0, CORRIDOR_CAP as i64) as u32
    }

    /// Apply lazy decay based on elapsed time since `last_update`.
    ///
    /// Decay formula: `weight' = weight * 0.5^(days / 365)`
    /// The `last_update` is advanced to `now` after decay.
    pub fn apply_lazy_decay(&mut self, now: DateTime<Utc>) {
        self.weight = self.decayed_weight(now);
        self.last_update = now;
    }

    /// Asymptotic reinforcement step.
    ///
    /// `weight' = weight + ceil((CAP - weight) / 10)`
    /// This guarantees strictly increasing weight until cap, with diminishing returns.
    /// For weight=0, first reinforcement yields ~100, approaching 1000 asymptotically.
    /// Returns true if weight actually increased.
    pub fn reinforce(&mut self) -> bool {
        if self.weight >= CORRIDOR_CAP {
            return false;
        }
        let remaining = CORRIDOR_CAP - self.weight;
        // At least 1, proportional to distance to cap.
        let delta = ((remaining as f64 / 10.0).ceil() as u32).max(1);
        let new_weight = (self.weight + delta).min(CORRIDOR_CAP);
        let changed = new_weight != self.weight;
        self.weight = new_weight;
        changed
    }

    /// Number of tracked bundle IDs (timestamp map size).
    pub fn bundle_count(&self) -> usize {
        self.seen_bundle_timestamps.len().max(self.seen_bundle_ids.len())
    }
}

/// In-memory corridor reinforcement store.
///
/// The store is serializable and cloneable so it can be persisted via `Wallet`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RoutingMemoryStore {
    /// Map from corridor_key -> entry.
    pub corridors: HashMap<String, CorridorEntry>,
}

impl Default for RoutingMemoryStore {
    fn default() -> Self {
        Self {
            corridors: HashMap::new(),
        }
    }
}

impl RoutingMemoryStore {
    /// Create a new empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Migrate legacy `seen_bundle_ids` into `seen_bundle_timestamps` for all
    /// corridors. Called on wallet load to ensure backward compatibility.
    pub fn migrate_legacy(&mut self) {
        for entry in self.corridors.values_mut() {
            entry.migrate_legacy();
        }
    }

    /// Prune expired bundle IDs across all corridors at `now`.
    /// Returns total number of pruned entries.
    pub fn prune_expired_bundles(&mut self, now: DateTime<Utc>) -> usize {
        let mut total = 0;
        for entry in self.corridors.values_mut() {
            total += entry.prune_expired_bundles(now);
        }
        total
    }

    /// Remove a bundle_id from a specific corridor **only if it exists**.
    /// Returns true if the bundle_id was present and removed.
    pub fn remove_bundle_id(
        &mut self,
        standard_uuid: &str,
        recipient_id: &str,
        bundle_id: &str,
    ) -> bool {
        let key = corridor_key(standard_uuid, recipient_id);
        if let Some(entry) = self.corridors.get_mut(&key) {
            entry.remove_bundle_id(bundle_id)
        } else {
            false
        }
    }

    /// Remove a bundle_id only if it is expired (conditional removal helper).
    pub fn remove_bundle_id_if_expired(
        &mut self,
        standard_uuid: &str,
        recipient_id: &str,
        bundle_id: &str,
        now: DateTime<Utc>,
    ) -> bool {
        let key = corridor_key(standard_uuid, recipient_id);
        if let Some(entry) = self.corridors.get_mut(&key) {
            if entry.is_bundle_expired(bundle_id, now) {
                entry.remove_bundle_id(bundle_id)
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Check if a corridor contains a bundle_id (window-aware).
    pub fn contains_bundle(
        &self,
        standard_uuid: &str,
        recipient_id: &str,
        bundle_id: &str,
        now: DateTime<Utc>,
    ) -> bool {
        let key = corridor_key(standard_uuid, recipient_id);
        self.corridors
            .get(&key)
            .map(|e| e.contains_bundle(bundle_id, now))
            .unwrap_or(false)
    }

    /// Returns the current weight for a corridor (calculating lazy decay purely on read).
    ///
    /// If the corridor does not exist, returns 0.
    pub fn get_weight(
        &self,
        standard_uuid: &str,
        recipient_id: &str,
        now: DateTime<Utc>,
    ) -> u32 {
        let key = corridor_key(standard_uuid, recipient_id);
        if let Some(entry) = self.corridors.get(&key) {
            entry.decayed_weight(now)
        } else {
            0
        }
    }

    /// Returns weight without mutating (no decay applied). Used for pure scoring without side effects.
    pub fn get_weight_no_decay(&self, standard_uuid: &str, recipient_id: &str) -> u32 {
        let key = corridor_key(standard_uuid, recipient_id);
        self.corridors.get(&key).map(|e| e.weight).unwrap_or(0)
    }

    /// Peek weight with decay applied.
    pub fn peek_weight_decayed(&self, standard_uuid: &str, recipient_id: &str) -> u32 {
        self.get_weight(standard_uuid, recipient_id, Utc::now())
    }

    /// Record a successful bundle transfer for a corridor.
    ///
    /// Performs lazy decay, bundle deduplication (same bundle_id never counts twice),
    /// asymptotic reinforcement, and LRU eviction if cap exceeded.
    ///
    /// Returns `true` if reinforcement actually occurred (not deduplicated).
    pub fn record_transfer(
        &mut self,
        standard_uuid: &str,
        recipient_id: &str,
        bundle_id: &str,
        now: DateTime<Utc>,
    ) -> bool {
        let key = corridor_key(standard_uuid, recipient_id);
        // Ensure entry exists; handle LRU eviction if inserting new
        if !self.corridors.contains_key(&key) {
            self.ensure_capacity(now);
            self.corridors.insert(key.clone(), CorridorEntry::new(now));
        }
        let entry = self.corridors.get_mut(&key).unwrap();
        entry.migrate_legacy();
        entry.prune_expired_bundles(now);
        entry.apply_lazy_decay(now);
        // Bundle deduplication via timestamp map (with fallback to legacy set)
        if entry.contains_bundle(bundle_id, now) {
            return false;
        }
        // Enforce per-corridor bundle cap before insert
        if entry.seen_bundle_timestamps.len() >= MAX_BUNDLE_IDS_PER_CORRIDOR {
            entry.ensure_bundle_capacity();
            // If still at cap (should not happen), evict one more oldest
            if entry.seen_bundle_timestamps.len() >= MAX_BUNDLE_IDS_PER_CORRIDOR {
                if let Some(oldest) = entry
                    .seen_bundle_timestamps
                    .iter()
                    .min_by_key(|(_, ts)| **ts)
                    .map(|(k, _)| k.clone())
                {
                    entry.seen_bundle_timestamps.remove(&oldest);
                    entry.seen_bundle_ids.remove(&oldest);
                }
            }
        }
        entry.seen_bundle_timestamps.insert(bundle_id.to_string(), now);
        entry.seen_bundle_ids.insert(bundle_id.to_string());
        entry.ensure_bundle_capacity();
        entry.reinforce();
        entry.last_update = now;
        true
    }

    /// Convenience: record with current time.
    pub fn record_transfer_now(&mut self, standard_uuid: &str, recipient_id: &str, bundle_id: &str) -> bool {
        self.record_transfer(standard_uuid, recipient_id, bundle_id, Utc::now())
    }

    /// Ensure capacity: if at cap and inserting new key would exceed, evict lowest weight entry.
    /// Evicts decayed weight == 0 first, then lowest decayed weight, breaking ties with oldest last_update.
    fn ensure_capacity(&mut self, now: DateTime<Utc>) {
        if self.corridors.len() < MAX_CORRIDORS {
            return;
        }
        // Evict entry with lowest decayed weight at `now`; tie-break with oldest last_update
        if let Some(evict_key) = self
            .corridors
            .iter()
            .min_by_key(|(_, e)| (e.decayed_weight(now), e.last_update))
            .map(|(k, _)| k.clone())
        {
            self.corridors.remove(&evict_key);
        }
    }

    /// Apply lazy decay to all entries (e.g., on wallet load). Uses `now`.
    /// Also migrates legacy dedup sets and prunes expired bundles.
    pub fn decay_all(&mut self, now: DateTime<Utc>) {
        self.migrate_legacy();
        self.prune_expired_bundles(now);
        for entry in self.corridors.values_mut() {
            entry.apply_lazy_decay(now);
        }
    }

    /// Returns number of corridors currently stored.
    pub fn len(&self) -> usize {
        self.corridors.len()
    }

    /// Returns true if empty.
    pub fn is_empty(&self) -> bool {
        self.corridors.is_empty()
    }

    /// Clear all corridors.
    pub fn clear(&mut self) {
        self.corridors.clear();
    }

    /// Insert or overwrite a corridor entry – test helper.
    #[cfg(test)]
    pub fn insert_for_test(&mut self, standard_uuid: &str, recipient_id: &str, entry: CorridorEntry) {
        let key = corridor_key(standard_uuid, recipient_id);
        self.corridors.insert(key, entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fixed_time(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).unwrap()
    }

    #[test]
    fn test_asymptotic_reinforcement_cap() {
        let mut entry = CorridorEntry::new(fixed_time(0));
        for _ in 0..100 {
            entry.reinforce();
        }
        assert_eq!(entry.weight, CORRIDOR_CAP);
        // Further reinforce stays at cap
        assert!(!entry.reinforce());
        assert_eq!(entry.weight, CORRIDOR_CAP);
    }

    #[test]
    fn test_diminishing_returns() {
        let mut entry = CorridorEntry::new(fixed_time(0));
        let mut deltas = Vec::new();
        let mut prev = 0;
        for _ in 0..5 {
            entry.reinforce();
            deltas.push(entry.weight - prev);
            prev = entry.weight;
        }
        // Deltas strictly decreasing (asymptotic)
        for w in deltas.windows(2) {
            assert!(w[0] >= w[1], "deltas should diminish: {:?}", deltas);
        }
    }

    #[test]
    fn test_bundle_deduplication() {
        let mut store = RoutingMemoryStore::new();
        let now = fixed_time(0);
        assert!(store.record_transfer("uuid-a", "did:key:zBob", "bundle-1", now));
        let w1 = store.get_weight_no_decay("uuid-a", "did:key:zBob");
        // Same bundle again -> no increase
        assert!(!store.record_transfer("uuid-a", "did:key:zBob", "bundle-1", now));
        let w2 = store.get_weight_no_decay("uuid-a", "did:key:zBob");
        assert_eq!(w1, w2);
        // Different bundle -> increase
        assert!(store.record_transfer("uuid-a", "did:key:zBob", "bundle-2", now));
        let w3 = store.get_weight_no_decay("uuid-a", "did:key:zBob");
        assert!(w3 > w2);
    }

    #[test]
    fn test_lazy_decay_half_life() {
        let mut entry = CorridorEntry {
            weight: 1000,
            seen_bundle_ids: HashSet::new(),
            seen_bundle_timestamps: HashMap::new(),
            last_update: fixed_time(0),
        };
        // After exactly 365 days, weight should be ~500
        let one_year_later = fixed_time(365 * 86_400);
        entry.apply_lazy_decay(one_year_later);
        assert!((entry.weight as i32 - 500).abs() <= 1, "weight after 1 half-life: {}", entry.weight);
        // After another 365 days -> ~250
        let two_years = fixed_time(2 * 365 * 86_400);
        entry.apply_lazy_decay(two_years);
        assert!((entry.weight as i32 - 250).abs() <= 1, "weight after 2 half-lives: {}", entry.weight);
    }

    #[test]
    fn test_lru_cap() {
        let mut store = RoutingMemoryStore::new();
        let base = fixed_time(0);
        for i in 0..MAX_CORRIDORS {
            let uuid = format!("uuid-{}", i);
            store.record_transfer(&uuid, "did:key:zBob", &format!("b-{}", i), base);
        }
        assert_eq!(store.len(), MAX_CORRIDORS);
        // Insert one more -> still at cap, LRU evicted
        store.record_transfer("uuid-overflow", "did:key:zBob", "b-overflow", base);
        assert_eq!(store.len(), MAX_CORRIDORS);
        // The overflow key must be present
        assert!(store.get_weight_no_decay("uuid-overflow", "did:key:zBob") > 0);
    }

    #[test]
    fn test_eviction_prefers_zero_weight_over_active_hot_corridors() {
        let mut store = RoutingMemoryStore::new();
        let t0 = fixed_time(0);
        let t1 = fixed_time(100);

        // Fill store with (MAX_CORRIDORS - 1) zero-weight corridors updated at t1
        for i in 0..(MAX_CORRIDORS - 1) {
            let key = format!("zero-weight-{}", i);
            store.insert_for_test(&key, "did:key:zBob", CorridorEntry {
                weight: 0,
                seen_bundle_ids: HashSet::new(),
                seen_bundle_timestamps: HashMap::new(),
                last_update: t1,
            });
        }

        // Add 1 hot corridor with high weight updated at earlier t0 (old timestamp)
        store.insert_for_test("hot-corridor", "did:key:zBob", CorridorEntry {
            weight: 900,
            seen_bundle_ids: HashSet::new(),
            seen_bundle_timestamps: HashMap::new(),
            last_update: t0,
        });

        assert_eq!(store.len(), MAX_CORRIDORS);

        // Now record transfer for a new corridor at t1.
        // Under pure LRU (last_update), hot-corridor at t0 would have been evicted!
        // Under weight-resilient eviction, a zero-weight corridor must be evicted instead.
        store.record_transfer("new-corridor", "did:key:zBob", "bundle-new", t1);

        assert_eq!(store.len(), MAX_CORRIDORS);
        assert!(
            store.corridors.contains_key(&corridor_key("hot-corridor", "did:key:zBob")),
            "Hot corridor should NOT be evicted by spam of zero-weight entries"
        );
        assert!(store.corridors.contains_key(&corridor_key("new-corridor", "did:key:zBob")));
    }

    #[test]
    fn test_migrate_legacy_seen_bundle_ids() {
        // Simulate old wallet JSON with only seen_bundle_ids
        let json = r#"{"weight":100,"seen_bundle_ids":["b1","b2"],"last_update":"2025-01-01T00:00:00Z"}"#;
        let mut entry: CorridorEntry = serde_json::from_str(json).unwrap();
        assert!(entry.seen_bundle_timestamps.is_empty());
        entry.migrate_legacy();
        assert_eq!(entry.seen_bundle_timestamps.len(), 2);
        assert!(entry.seen_bundle_timestamps.contains_key("b1"));
        assert!(entry.seen_bundle_timestamps.contains_key("b2"));
        // IDs still present for backward compat
        assert!(entry.seen_bundle_ids.contains("b1"));
    }

    #[test]
    fn test_prune_expired_bundles() {
        let mut entry = CorridorEntry::new(fixed_time(0));
        // Insert bundles at t0
        entry.seen_bundle_timestamps.insert("old".to_string(), fixed_time(0));
        entry.seen_bundle_ids.insert("old".to_string());
        entry.seen_bundle_timestamps.insert("fresh".to_string(), fixed_time(80 * 86_400));
        entry.seen_bundle_ids.insert("fresh".to_string());
        // Prune at 100 days: old (100d) > 90d window expires, fresh (20d) stays
        let now = fixed_time(100 * 86_400);
        let pruned = entry.prune_expired_bundles(now);
        assert_eq!(pruned, 1);
        assert!(!entry.seen_bundle_timestamps.contains_key("old"));
        assert!(entry.seen_bundle_timestamps.contains_key("fresh"));
    }

    #[test]
    fn test_remove_bundle_id_conditional() {
        let mut entry = CorridorEntry::new(fixed_time(0));
        entry.seen_bundle_timestamps.insert("b1".to_string(), fixed_time(0));
        entry.seen_bundle_ids.insert("b1".to_string());
        // Remove only if exists -> true
        assert!(entry.remove_bundle_id("b1"));
        assert!(!entry.seen_bundle_timestamps.contains_key("b1"));
        // Removing non-existent -> false
        assert!(!entry.remove_bundle_id("b1"));
        assert!(!entry.remove_bundle_id("ghost"));
    }

    #[test]
    fn test_bundle_cap_enforcement() {
        let mut entry = CorridorEntry::new(fixed_time(0));
        for i in 0..(MAX_BUNDLE_IDS_PER_CORRIDOR + 10) {
            entry.seen_bundle_timestamps.insert(format!("b{}", i), fixed_time(i as i64));
            entry.seen_bundle_ids.insert(format!("b{}", i));
        }
        assert!(entry.seen_bundle_timestamps.len() > MAX_BUNDLE_IDS_PER_CORRIDOR);
        entry.ensure_bundle_capacity();
        assert_eq!(entry.seen_bundle_timestamps.len(), MAX_BUNDLE_IDS_PER_CORRIDOR);
        // Oldest should be evicted
        assert!(!entry.seen_bundle_timestamps.contains_key("b0"));
    }
}
