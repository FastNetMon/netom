//! Per-peer BMP-style statistics for native BGP ingresses.
//!
//! Tracks the counters needed to synthesize BMP Statistics Reports
//! (RFC 7854 §4.8) for peers terminated directly by `bgp_tcp_in`. The
//! registry is shared as `Arc<BgpPeerStatsRegistry>` between the
//! per-connection task that updates counters and the periodic emitter
//! that snapshots them and publishes `Update::PeerStats`.
//!
//! Two kinds of value live here and they are maintained in different
//! places. Message counters (rejected prefixes, notifications) belong to
//! the receive path and are updated by `router_handler` as PDUs arrive.
//! The Adj-RIB-In *gauges* cannot be, because BGP's implicit withdraw
//! makes an arriving NLRI ambiguous — a new prefix and a replacement look
//! identical on the wire — so they are maintained by `Rib::insert_prefix`,
//! which can compare against what the store already holds for the peer.
//!
//! Counters Netom doesn't compute (loop checks, RFC 7606
//! treat-as-withdraw, Loc-RIB totals) are kept as fields so the
//! emitted Stats Report has a stable RFC 7854 §4.8 TLV set; their
//! values are simply zero. See `stats_builder` for serialization.
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use crate::ingress::IngressId;

/// AFI/SAFI key used for the per-AFI/SAFI Adj-RIB-In and Loc-RIB
/// counters (RFC 7854 §4.8 stat types 9 and 10). AFI is u16, SAFI is
/// u8, both in IANA-assigned wire values.
pub type AfiSafiKey = (u16, u8);

/// Per-peer counters mapped 1:1 to RFC 7854 §4.8 stat TLVs.
///
/// Counters are atomic so the BGP-receive path can update them without
/// taking a lock. Gauges that are per-AFI/SAFI live behind a `RwLock`
/// because the set of active families is rarely larger than 2-4.
#[derive(Debug, Default)]
pub struct BgpPeerStats {
    pub prefixes_rejected: AtomicU64,
    pub dup_prefix_advertisements: AtomicU64,
    pub dup_withdraws: AtomicU64,
    pub invalid_cluster_list_loops: AtomicU64,
    pub invalid_as_path_loops: AtomicU64,
    pub invalid_originator_id: AtomicU64,
    pub invalid_as_confed_loops: AtomicU64,
    pub adj_rib_in_routes: AtomicU64,
    pub loc_rib_routes: AtomicU64,
    pub adj_rib_in_per_afi_safi: RwLock<HashMap<AfiSafiKey, u64>>,
    pub loc_rib_per_afi_safi: RwLock<HashMap<AfiSafiKey, u64>>,
    pub updates_treat_as_withdraw: AtomicU64,
    pub prefixes_treat_as_withdraw: AtomicU64,
    pub dup_updates: AtomicU64,
}

impl BgpPeerStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc_prefixes_rejected(&self, n: u64) {
        self.prefixes_rejected.fetch_add(n, Ordering::Relaxed);
    }

    /// Count an announcement that did not change the Adj-RIB-In size: an
    /// implicit withdraw (re-advertisement of a prefix this peer already
    /// has in the RIB, with or without changed attributes). RFC 7854 §4.8
    /// stat type 1.
    ///
    /// This is the counterpart of [`Self::add_adj_rib_in`]: every accepted
    /// announcement lands in exactly one of the two, so
    /// `adj_rib_in_routes + dup_prefix_advertisements` is the total NLRI
    /// count while `adj_rib_in_routes` alone stays a true gauge.
    pub fn inc_dup_prefix_advertisements(&self, n: u64) {
        self.dup_prefix_advertisements
            .fetch_add(n, Ordering::Relaxed);
    }

    /// Record `n` prefixes newly present in the Adj-RIB-In for `afi_safi`.
    ///
    /// This is a *gauge*, not a counter: the caller must only report
    /// prefixes that were not already active for this peer, or the value
    /// diverges from the RIB. See `Rib::insert_prefix`, which derives the
    /// transition from the store.
    pub fn add_adj_rib_in(&self, afi_safi: AfiSafiKey, n: u64) {
        if n == 0 {
            return;
        }
        // Aggregate and per-family are mutated under the one write lock so
        // the two can never disagree; the aggregate stays atomic purely so
        // `snapshot` can read it without taking the lock.
        let mut map = self.adj_rib_in_per_afi_safi.write().unwrap();
        *map.entry(afi_safi).or_insert(0) += n;
        let agg = self.adj_rib_in_routes.load(Ordering::Relaxed);
        self.adj_rib_in_routes
            .store(agg.saturating_add(n), Ordering::Relaxed);
    }

    /// Record `n` prefixes leaving the Adj-RIB-In for `afi_safi`. Saturates
    /// at zero so a burst of withdraws for unseen prefixes can't underflow.
    pub fn sub_adj_rib_in(&self, afi_safi: AfiSafiKey, n: u64) {
        if n == 0 {
            return;
        }
        let mut map = self.adj_rib_in_per_afi_safi.write().unwrap();
        let cur = map.entry(afi_safi).or_insert(0);
        let dec = (*cur).min(n);
        *cur = cur.saturating_sub(dec);
        // Mirror the same saturation for the aggregate.
        let agg = self.adj_rib_in_routes.load(Ordering::Relaxed);
        let new_agg = agg.saturating_sub(dec);
        self.adj_rib_in_routes.store(new_agg, Ordering::Relaxed);
    }

    /// Reset the per-AFI/SAFI Adj-RIB-In gauge to zero, e.g. on
    /// session reset or peer down. Aggregate is recomputed accordingly.
    pub fn reset_adj_rib_in(&self) {
        let mut map = self.adj_rib_in_per_afi_safi.write().unwrap();
        map.clear();
        self.adj_rib_in_routes.store(0, Ordering::Relaxed);
    }

    /// Zero one family's Adj-RIB-In gauge, for a withdrawal scoped to a
    /// single AFI/SAFI. Other families keep their counts.
    pub fn reset_adj_rib_in_afi_safi(&self, afi_safi: AfiSafiKey) {
        let mut map = self.adj_rib_in_per_afi_safi.write().unwrap();
        let dropped = map.remove(&afi_safi).unwrap_or(0);
        let agg = self.adj_rib_in_routes.load(Ordering::Relaxed);
        self.adj_rib_in_routes
            .store(agg.saturating_sub(dropped), Ordering::Relaxed);
    }
}

/// Snapshot of [`BgpPeerStats`] suitable for serialization without
/// holding the underlying locks.
#[derive(Clone, Debug, Default)]
pub struct BgpPeerStatsSnapshot {
    pub prefixes_rejected: u64,
    pub dup_prefix_advertisements: u64,
    pub dup_withdraws: u64,
    pub invalid_cluster_list_loops: u64,
    pub invalid_as_path_loops: u64,
    pub invalid_originator_id: u64,
    pub invalid_as_confed_loops: u64,
    pub adj_rib_in_routes: u64,
    pub loc_rib_routes: u64,
    pub adj_rib_in_per_afi_safi: Vec<(AfiSafiKey, u64)>,
    pub loc_rib_per_afi_safi: Vec<(AfiSafiKey, u64)>,
    pub updates_treat_as_withdraw: u64,
    pub prefixes_treat_as_withdraw: u64,
    pub dup_updates: u64,
}

impl BgpPeerStats {
    pub fn snapshot(&self) -> BgpPeerStatsSnapshot {
        BgpPeerStatsSnapshot {
            prefixes_rejected: self.prefixes_rejected.load(Ordering::Relaxed),
            dup_prefix_advertisements: self
                .dup_prefix_advertisements
                .load(Ordering::Relaxed),
            dup_withdraws: self.dup_withdraws.load(Ordering::Relaxed),
            invalid_cluster_list_loops: self
                .invalid_cluster_list_loops
                .load(Ordering::Relaxed),
            invalid_as_path_loops: self
                .invalid_as_path_loops
                .load(Ordering::Relaxed),
            invalid_originator_id: self
                .invalid_originator_id
                .load(Ordering::Relaxed),
            invalid_as_confed_loops: self
                .invalid_as_confed_loops
                .load(Ordering::Relaxed),
            adj_rib_in_routes: self.adj_rib_in_routes.load(Ordering::Relaxed),
            loc_rib_routes: self.loc_rib_routes.load(Ordering::Relaxed),
            adj_rib_in_per_afi_safi: self
                .adj_rib_in_per_afi_safi
                .read()
                .unwrap()
                .iter()
                .map(|(k, v)| (*k, *v))
                .collect(),
            loc_rib_per_afi_safi: self
                .loc_rib_per_afi_safi
                .read()
                .unwrap()
                .iter()
                .map(|(k, v)| (*k, *v))
                .collect(),
            updates_treat_as_withdraw: self
                .updates_treat_as_withdraw
                .load(Ordering::Relaxed),
            prefixes_treat_as_withdraw: self
                .prefixes_treat_as_withdraw
                .load(Ordering::Relaxed),
            dup_updates: self.dup_updates.load(Ordering::Relaxed),
        }
    }
}

/// Registry of per-peer stats keyed by [`IngressId`]. Cheaply cloneable
/// (it's just an `Arc<RwLock<HashMap<...>>>` internally) so it can be
/// passed to per-connection tasks and the emission timer alike.
#[derive(Debug, Default)]
pub struct BgpPeerStatsRegistry {
    inner: RwLock<HashMap<IngressId, Entry>>,
    /// Mirrors `inner.len()` so the RIB's insert path — which consults the
    /// registry once per stored prefix — can skip the lock entirely in
    /// deployments with no native BGP peers (a BMP-only collector, the
    /// stock config). Only ever written under the write lock.
    len: AtomicUsize,
}

/// A registry slot. `Alias` entries are the ADD-PATH path-children of a
/// session: they share the parent session's counters, so a peer that
/// negotiated ADD-PATH still reports one Adj-RIB-In gauge rather than one
/// per path id. `snapshot_all` skips them so the periodic Stats Report
/// emitter does not publish the same peer once per path id.
#[derive(Clone, Debug)]
enum Entry {
    Session(Arc<BgpPeerStats>),
    Alias(Arc<BgpPeerStats>),
}

impl Entry {
    fn stats(&self) -> &Arc<BgpPeerStats> {
        match self {
            Entry::Session(s) | Entry::Alias(s) => s,
        }
    }
}

impl BgpPeerStatsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get-or-create the stats entry for `id`. The same `Arc` is
    /// returned on subsequent calls so the per-connection task can
    /// keep a clone for cheap counter updates.
    pub fn get_or_create(&self, id: IngressId) -> Arc<BgpPeerStats> {
        if let Some(s) = self.inner.read().unwrap().get(&id) {
            return s.stats().clone();
        }
        let mut w = self.inner.write().unwrap();
        let entry = w
            .entry(id)
            .or_insert_with(|| Entry::Session(Arc::new(BgpPeerStats::new())))
            .stats()
            .clone();
        self.len.store(w.len(), Ordering::Relaxed);
        entry
    }

    pub fn get(&self, id: IngressId) -> Option<Arc<BgpPeerStats>> {
        self.inner
            .read()
            .unwrap()
            .get(&id)
            .map(|e| e.stats().clone())
    }

    /// True when no native BGP session has stats. Lets hot paths bail out
    /// before touching the lock.
    pub fn is_empty(&self) -> bool {
        self.len.load(Ordering::Relaxed) == 0
    }

    /// Point `child` at `parent`'s counters, for an ADD-PATH path-child
    /// ingress id. Routes stored under the child mui then land on the
    /// session's gauge. No-op (returning false) if `parent` has no entry.
    pub fn alias(&self, child: IngressId, parent: IngressId) -> bool {
        let mut w = self.inner.write().unwrap();
        let Some(stats) = w.get(&parent).map(|e| e.stats().clone()) else {
            return false;
        };
        w.insert(child, Entry::Alias(stats));
        self.len.store(w.len(), Ordering::Relaxed);
        true
    }

    pub fn remove(&self, id: IngressId) {
        let mut w = self.inner.write().unwrap();
        w.remove(&id);
        self.len.store(w.len(), Ordering::Relaxed);
    }

    /// Snapshot every (id, snapshot) pair currently in the registry.
    /// Used by the periodic emitter to walk all peers without holding
    /// the lock for the full emit duration. ADD-PATH aliases are skipped;
    /// their routes are already folded into the parent session's entry.
    pub fn snapshot_all(&self) -> Vec<(IngressId, BgpPeerStatsSnapshot)> {
        self.inner
            .read()
            .unwrap()
            .iter()
            .filter_map(|(id, e)| match e {
                Entry::Session(s) => Some((*id, s.snapshot())),
                Entry::Alias(_) => None,
            })
            .collect()
    }
}

static REGISTRY: std::sync::LazyLock<Arc<BgpPeerStatsRegistry>> =
    std::sync::LazyLock::new(|| Arc::new(BgpPeerStatsRegistry::new()));

/// The process-wide peer-stats registry.
///
/// Global for two reasons: the HTTP API has to read these counters without
/// reaching inside a unit, and a per-runner registry would be rebuilt on a
/// live reconfiguration, silently resetting every peer's counters on SIGHUP.
/// Keys are [`IngressId`]s, which are process-wide unique, so one map stays
/// correct with several `bgp-tcp-in` units configured. Entries are removed
/// on session teardown, so the map does not grow without bound.
pub fn registry() -> Arc<BgpPeerStatsRegistry> {
    REGISTRY.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_then_sub_adj_rib_in() {
        let s = BgpPeerStats::new();
        s.add_adj_rib_in((1, 1), 10);
        s.add_adj_rib_in((2, 1), 5);
        assert_eq!(s.adj_rib_in_routes.load(Ordering::Relaxed), 15);

        s.sub_adj_rib_in((1, 1), 3);
        let snap = s.snapshot();
        assert_eq!(snap.adj_rib_in_routes, 12);
        let by_key: HashMap<_, _> =
            snap.adj_rib_in_per_afi_safi.iter().cloned().collect();
        assert_eq!(by_key[&(1u16, 1u8)], 7);
        assert_eq!(by_key[&(2u16, 1u8)], 5);
    }

    #[test]
    fn sub_saturates_at_zero() {
        let s = BgpPeerStats::new();
        s.add_adj_rib_in((1, 1), 2);
        s.sub_adj_rib_in((1, 1), 99);
        assert_eq!(s.adj_rib_in_routes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn registry_get_or_create_is_idempotent() {
        let reg = BgpPeerStatsRegistry::new();
        let a = reg.get_or_create(42);
        let b = reg.get_or_create(42);
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn alias_shares_the_parents_counters() {
        let reg = BgpPeerStatsRegistry::new();
        let parent = reg.get_or_create(42);
        assert!(reg.alias(43, 42));

        // An ADD-PATH child's routes are stored under the child mui but
        // belong to the parent session's one Adj-RIB-In.
        reg.get(43).unwrap().add_adj_rib_in((1, 1), 3);
        assert_eq!(parent.snapshot().adj_rib_in_routes, 3);

        // ...and the emitter must not publish the peer twice.
        let ids: Vec<_> =
            reg.snapshot_all().into_iter().map(|(id, _)| id).collect();
        assert_eq!(ids, vec![42]);
    }

    #[test]
    fn alias_without_a_parent_is_refused() {
        let reg = BgpPeerStatsRegistry::new();
        assert!(!reg.alias(43, 42));
        assert!(reg.get(43).is_none());
    }

    #[test]
    fn is_empty_tracks_membership() {
        let reg = BgpPeerStatsRegistry::new();
        assert!(reg.is_empty());
        reg.get_or_create(42);
        reg.alias(43, 42);
        assert!(!reg.is_empty());
        reg.remove(43);
        assert!(!reg.is_empty());
        reg.remove(42);
        assert!(reg.is_empty());
    }

    #[test]
    fn reset_one_family_leaves_the_others() {
        let s = BgpPeerStats::new();
        s.add_adj_rib_in((1, 1), 10);
        s.add_adj_rib_in((2, 1), 5);
        s.reset_adj_rib_in_afi_safi((1, 1));
        let snap = s.snapshot();
        assert_eq!(snap.adj_rib_in_routes, 5);
        assert_eq!(snap.adj_rib_in_per_afi_safi, vec![((2, 1), 5)]);
    }

    #[test]
    fn reset_clears_per_afi_safi() {
        let s = BgpPeerStats::new();
        s.add_adj_rib_in((1, 1), 10);
        s.add_adj_rib_in((2, 1), 5);
        s.reset_adj_rib_in();
        let snap = s.snapshot();
        assert_eq!(snap.adj_rib_in_routes, 0);
        assert!(snap.adj_rib_in_per_afi_safi.is_empty());
    }
}
