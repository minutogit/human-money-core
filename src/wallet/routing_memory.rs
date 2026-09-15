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

/// Unique corridor key: (standard_uuid, recipient_id).
/// Serialized as `"<standard_uuid>::<recipient_id>"` for HashMap storage.
fn corridor_key(standard_uuid: &str, recipient_id: &str) -> String {
    format!("{}::{}", standard_uuid, recipient_id)
}

/// A single corridor entry storing reinforcement weight and deduplication state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CorridorEntry {
    /// Current corridor weight in 0..=1000.
    pub weight: u32,
    /// Set of already counted `bundle_id`s for deduplication.
    #[serde(default)]
    pub seen_bundle_ids: HashSet<String>,
    /// Last access / update timestamp (used for lazy decay and LRU).
    pub last_update: DateTime<Utc>,
}

impl CorridorEntry {
    /// Create a fresh entry with weight 0.
    pub fn new(now: DateTime<Utc>) -> Self {
        Self {
            weight: 0,
            seen_bundle_ids: HashSet::new(),
            last_update: now,
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
        entry.apply_lazy_decay(now);
        // Bundle deduplication
        if !entry.seen_bundle_ids.insert(bundle_id.to_string()) {
            // Already seen -> no reinforcement
            return false;
        }
        entry.reinforce();
        entry.last_update = now;
        true
    }

    /// Convenience: record with current time.
    pub fn record_transfer_now(&mut self, standard_uuid: &str, recipient_id: &str, bundle_id: &str) -> bool {
        self.record_transfer(standard_uuid, recipient_id, bundle_id, Utc::now())
    }

    /// Ensure LRU capacity: if at cap and inserting new key would exceed, evict oldest.
    fn ensure_capacity(&mut self, _now: DateTime<Utc>) {
        if self.corridors.len() < MAX_CORRIDORS {
            return;
        }
        // Find LRU entry (smallest last_update)
        if let Some(lru_key) = self
            .corridors
            .iter()
            .min_by_key(|(_, e)| e.last_update)
            .map(|(k, _)| k.clone())
        {
            self.corridors.remove(&lru_key);
        }
    }

    /// Apply lazy decay to all entries (e.g., on wallet load). Uses `now`.
    pub fn decay_all(&mut self, now: DateTime<Utc>) {
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
}
