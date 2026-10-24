//! # `src/services/latency_router.rs`
//!
//! Stateless latency-based peer routing utilities.
//!
//! Provides pure functions for:
//! - 3-ping median computation (`compute_median_latency`)
//! - Exponential moving average smoothing (`update_ema_latency`)
//! - Latency-aware sorting and jittered selection among the top-3 fastest peers
//!
//! All functions are `wasm32`-compatible (no I/O, no network, no OS calls).

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Latency snapshot for a single peer used during routing decisions.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PeerLatencyInfo {
    /// URL of the peer / bootstrap node.
    pub url: String,
    /// Median latency in milliseconds (computed via [`compute_median_latency`]).
    pub median_latency_ms: u64,
    /// Whether the peer is currently considered offline / unreachable.
    pub is_offline: bool,
}

// ---------------------------------------------------------------------------
// Core pure functions
// ---------------------------------------------------------------------------

/// Computes the median of a mutable slice of latency samples.
///
/// The slice is sorted in-place to avoid an extra allocation. Returns `None`
/// for an empty slice. For even-length inputs the upper-middle element
/// (`len / 2`) is returned, which for the canonical 3-ping case is the
/// exact middle value.
///
/// # Example
/// ```
/// use human_money_core::services::latency_router::compute_median_latency;
/// let mut v = vec![30, 10, 20];
/// assert_eq!(compute_median_latency(&mut v), Some(20));
/// ```
pub fn compute_median_latency(samples: &mut [u64]) -> Option<u64> {
    if samples.is_empty() {
        return None;
    }
    samples.sort_unstable();
    let mid = samples.len() / 2;
    Some(samples[mid])
}

/// Updates an exponentially weighted moving average (EMA) with smoothing
/// factors `alpha = 0.3` for the new sample and `1 - alpha = 0.7` for history.
///
/// Formula: `ema_new = 0.7 * old_ema + 0.3 * new_sample`
/// Result is rounded to the nearest integer (`u64`).
///
/// # Example
/// ```
/// use human_money_core::services::latency_router::update_ema_latency;
/// assert_eq!(update_ema_latency(100, 200), 130);
/// ```
pub fn update_ema_latency(old_ema: u64, new_sample: u64) -> u64 {
    let ema = 0.7 * old_ema as f64 + 0.3 * new_sample as f64;
    ema.round() as u64
}

// ---------------------------------------------------------------------------
// Sorting & selection
// ---------------------------------------------------------------------------

/// Sorts peers in-place by routing priority:
///
/// 1. Online peers (`is_offline == false`) first.
/// 2. Among online peers, ascending `median_latency_ms`.
/// 3. Offline peers at the end, also sorted by latency (stable fallback).
pub fn sort_peers_by_latency(peers: &mut [PeerLatencyInfo]) {
    peers.sort_by(|a, b| match (a.is_offline, b.is_offline) {
        (false, true) => std::cmp::Ordering::Less,
        (true, false) => std::cmp::Ordering::Greater,
        _ => a.median_latency_ms.cmp(&b.median_latency_ms),
    });
}

/// Returns the best (lowest-latency) online peer, if any.
///
/// Assumes `peers` is already sorted via [`sort_peers_by_latency`] or
/// performs an equivalent linear scan.
pub fn select_best_peer(peers: &[PeerLatencyInfo]) -> Option<&PeerLatencyInfo> {
    peers.iter().find(|p| !p.is_offline)
}

/// Selects a peer among the top-3 fastest online peers using a deterministic
/// jitter seed (e.g. derived from RNG or request id).
///
/// - Collects the first up to 3 online peers after sorting by latency.
/// - Picks `top[jitter_seed % top.len()]` to spread load while keeping tail
///   latency bounded (jitter-selection).
/// - Returns `None` if no online peer exists.
///
/// If `peers` is unsorted, it is not mutated; the function works on a
/// sorted view internally.
pub fn select_peer_from_top3(
    peers: &[PeerLatencyInfo],
    jitter_seed: u64,
) -> Option<&PeerLatencyInfo> {
    // Collect online peers sorted by latency without mutating caller slice
    let mut online: Vec<&PeerLatencyInfo> = peers.iter().filter(|p| !p.is_offline).collect();
    if online.is_empty() {
        return None;
    }
    online.sort_by_key(|p| p.median_latency_ms);
    let top_n = online.len().min(3);
    let idx = (jitter_seed as usize) % top_n;
    Some(online[idx])
}

/// Convenience wrapper that sorts `peers` in place and then performs
/// jittered selection among the top-3 online entries.
///
/// Returns `None` if every peer is offline.
pub fn sort_and_select_top3_jittered(
    peers: &mut [PeerLatencyInfo],
    jitter_seed: u64,
) -> Option<PeerLatencyInfo> {
    sort_peers_by_latency(peers);
    let online_top: Vec<&PeerLatencyInfo> = peers.iter().filter(|p| !p.is_offline).take(3).collect();
    if online_top.is_empty() {
        return None;
    }
    let idx = (jitter_seed as usize) % online_top.len();
    Some(online_top[idx].clone())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- median ----

    #[test]
    fn test_compute_median_latency_empty() {
        let mut v: Vec<u64> = vec![];
        assert_eq!(compute_median_latency(&mut v), None);
    }

    #[test]
    fn test_compute_median_latency_single() {
        let mut v = vec![42];
        assert_eq!(compute_median_latency(&mut v), Some(42));
    }

    #[test]
    fn test_compute_median_latency_three_pings_odd() {
        let mut v = vec![30, 10, 20];
        assert_eq!(compute_median_latency(&mut v), Some(20));
        // already sorted
        let mut v2 = vec![5, 50, 100];
        assert_eq!(compute_median_latency(&mut v2), Some(50));
    }

    #[test]
    fn test_compute_median_latency_unsorted_three() {
        let mut v = vec![100, 1, 50];
        // sorted => [1,50,100] median 50
        assert_eq!(compute_median_latency(&mut v), Some(50));
    }

    #[test]
    fn test_compute_median_latency_duplicates() {
        let mut v = vec![10, 10, 10];
        assert_eq!(compute_median_latency(&mut v), Some(10));
        let mut v2 = vec![5, 5, 100];
        assert_eq!(compute_median_latency(&mut v2), Some(5));
    }

    #[test]
    fn test_compute_median_latency_even_length_upper_middle() {
        // spec does not strictly define even case; we use upper-middle (len/2)
        let mut v = vec![10, 20, 30, 40];
        // sorted [10,20,30,40] -> index 2 -> 30
        assert_eq!(compute_median_latency(&mut v), Some(30));
        let mut v2 = vec![1, 2];
        assert_eq!(compute_median_latency(&mut v2), Some(2));
    }

    #[test]
    fn test_compute_median_latency_five_elements() {
        let mut v = vec![9, 1, 8, 2, 7];
        // sorted [1,2,7,8,9] median index 2 => 7
        assert_eq!(compute_median_latency(&mut v), Some(7));
    }

    // ---- EMA ----

    #[test]
    fn test_update_ema_latency_basic() {
        // 0.7*100 + 0.3*200 = 70 + 60 = 130
        assert_eq!(update_ema_latency(100, 200), 130);
    }

    #[test]
    fn test_update_ema_latency_no_change() {
        assert_eq!(update_ema_latency(50, 50), 50);
    }

    #[test]
    fn test_update_ema_latency_rounding() {
        // 0.7*10 + 0.3*11 = 7 + 3.3 = 10.3 -> 10
        assert_eq!(update_ema_latency(10, 11), 10);
        // 0.7*10 + 0.3*12 = 7 + 3.6 = 10.6 -> 11
        assert_eq!(update_ema_latency(10, 12), 11);
        // 0.7*0 + 0.3*1 = 0.3 -> 0
        assert_eq!(update_ema_latency(0, 1), 0);
        // 0.7*0 + 0.3*2 = 0.6 -> 1
        assert_eq!(update_ema_latency(0, 2), 1);
    }

    #[test]
    fn test_update_ema_latency_zero() {
        assert_eq!(update_ema_latency(0, 0), 0);
        assert_eq!(update_ema_latency(0, 100), 30);
        assert_eq!(update_ema_latency(100, 0), 70);
    }

    #[test]
    fn test_update_ema_latency_large_values() {
        // 0.7*1000 + 0.3*2000 = 700+600=1300
        assert_eq!(update_ema_latency(1000, 2000), 1300);
        // near u64::MAX not tested to avoid overflow, but within normal latency range
    }

    // ---- sorting & jitter selection ----

    #[test]
    fn test_sort_peers_by_latency_online_first() {
        let mut peers = vec![
            PeerLatencyInfo { url: "c".into(), median_latency_ms: 30, is_offline: false },
            PeerLatencyInfo { url: "a".into(), median_latency_ms: 10, is_offline: true },
            PeerLatencyInfo { url: "b".into(), median_latency_ms: 20, is_offline: false },
            PeerLatencyInfo { url: "d".into(), median_latency_ms: 5, is_offline: true },
        ];
        sort_peers_by_latency(&mut peers);
        // online sorted first: b(20), c(30), then offline sorted: d(5), a(10)
        assert_eq!(peers[0].url, "b");
        assert_eq!(peers[1].url, "c");
        assert_eq!(peers[2].url, "d");
        assert_eq!(peers[3].url, "a");
    }

    #[test]
    fn test_select_best_peer() {
        let peers = vec![
            PeerLatencyInfo { url: "slow".into(), median_latency_ms: 100, is_offline: false },
            PeerLatencyInfo { url: "fast".into(), median_latency_ms: 10, is_offline: false },
        ];
        let mut sorted = peers.clone();
        sort_peers_by_latency(&mut sorted);
        assert_eq!(select_best_peer(&sorted).unwrap().url, "fast");
    }

    #[test]
    fn test_select_best_peer_all_offline() {
        let peers = vec![
            PeerLatencyInfo { url: "a".into(), median_latency_ms: 10, is_offline: true },
        ];
        assert!(select_best_peer(&peers).is_none());
    }

    #[test]
    fn test_select_peer_from_top3_jitter() {
        let peers = vec![
            PeerLatencyInfo { url: "p1".into(), median_latency_ms: 10, is_offline: false },
            PeerLatencyInfo { url: "p2".into(), median_latency_ms: 20, is_offline: false },
            PeerLatencyInfo { url: "p3".into(), median_latency_ms: 30, is_offline: false },
            PeerLatencyInfo { url: "p4".into(), median_latency_ms: 40, is_offline: false },
        ];
        // top3 are p1,p2,p3. seed 0 -> p1, seed1->p2, seed2->p3, seed3->p1 again
        assert_eq!(select_peer_from_top3(&peers, 0).unwrap().url, "p1");
        assert_eq!(select_peer_from_top3(&peers, 1).unwrap().url, "p2");
        assert_eq!(select_peer_from_top3(&peers, 2).unwrap().url, "p3");
        assert_eq!(select_peer_from_top3(&peers, 3).unwrap().url, "p1");
        // p4 should never be selected via top3
        for seed in 0..10 {
            assert_ne!(select_peer_from_top3(&peers, seed).unwrap().url, "p4");
        }
    }

    #[test]
    fn test_select_peer_from_top3_fewer_than_three() {
        let peers = vec![
            PeerLatencyInfo { url: "only".into(), median_latency_ms: 10, is_offline: false },
        ];
        assert_eq!(select_peer_from_top3(&peers, 0).unwrap().url, "only");
        assert_eq!(select_peer_from_top3(&peers, 99).unwrap().url, "only");

        let peers2 = vec![
            PeerLatencyInfo { url: "a".into(), median_latency_ms: 10, is_offline: false },
            PeerLatencyInfo { url: "b".into(), median_latency_ms: 20, is_offline: false },
        ];
        assert_eq!(select_peer_from_top3(&peers2, 0).unwrap().url, "a");
        assert_eq!(select_peer_from_top3(&peers2, 1).unwrap().url, "b");
        assert_eq!(select_peer_from_top3(&peers2, 2).unwrap().url, "a");
    }

    #[test]
    fn test_select_peer_from_top3_ignores_offline() {
        let peers = vec![
            PeerLatencyInfo { url: "offline_fast".into(), median_latency_ms: 1, is_offline: true },
            PeerLatencyInfo { url: "online_slow".into(), median_latency_ms: 100, is_offline: false },
            PeerLatencyInfo { url: "online_fast".into(), median_latency_ms: 10, is_offline: false },
        ];
        // top online are online_fast, online_slow ; offline should not be considered
        assert_eq!(select_peer_from_top3(&peers, 0).unwrap().url, "online_fast");
        assert_eq!(select_peer_from_top3(&peers, 1).unwrap().url, "online_slow");
    }

    #[test]
    fn test_sort_and_select_top3_jittered_mutating() {
        let mut peers = vec![
            PeerLatencyInfo { url: "p3".into(), median_latency_ms: 30, is_offline: false },
            PeerLatencyInfo { url: "p1".into(), median_latency_ms: 10, is_offline: false },
            PeerLatencyInfo { url: "p2".into(), median_latency_ms: 20, is_offline: false },
        ];
        let selected = sort_and_select_top3_jittered(&mut peers, 1).unwrap();
        assert_eq!(selected.url, "p2");
        // after call peers should be sorted
        assert_eq!(peers[0].url, "p1");
        assert_eq!(peers[1].url, "p2");
        assert_eq!(peers[2].url, "p3");
    }

    #[test]
    fn test_select_peer_from_top3_all_offline_none() {
        let peers = vec![
            PeerLatencyInfo { url: "a".into(), median_latency_ms: 10, is_offline: true },
            PeerLatencyInfo { url: "b".into(), median_latency_ms: 20, is_offline: true },
        ];
        assert!(select_peer_from_top3(&peers, 0).is_none());
        let mut peers_mut = peers.clone();
        assert!(sort_and_select_top3_jittered(&mut peers_mut, 0).is_none());
    }
}
