use std::{
    collections::{hash_set, HashMap, HashSet},
    fmt,
    hash::{BuildHasher, Hasher},
    net::IpAddr,
    ops::Deref,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};

use chrono::{Duration, Utc};
use inetnum::{addr::Prefix, asn::Asn};
use log::{debug, error, info, trace, warn};
use rotonda_store::{
    epoch,
    errors::{FatalResult, PrefixStoreError},
    match_options::{MatchOptions, QueryResult},
    prefix_record::{Meta, PrefixRecord, Record, RecordSet, RouteStatus},
    rib::{config::MemoryOnlyConfig, StarCastRib},
    stats::UpsertReport,
};
use routecore::bgp::{
    aspath::HopPath,
    nlri::afisafi::{AfiSafiNlri, IsPrefix, Nlri},
    path_attributes::PaMap,
    path_selection::{OrdRoute, Rfc4271, TiebreakerInfo},
    types::{AfiSafiType, Otc},
};
use serde::{
    ser::{SerializeSeq, SerializeStruct},
    Serialize, Serializer,
};

use crate::{
    ingress::{self, register::IdAndInfo, IngressId, IngressInfo},
    payload::{
        PathAttributeInterner, RotondaPaMap, RotondaPaMapWithQueryFilter,
        RotondaRoute, RouterId,
    },
    representation::{GenOutput, Json},
    roto_runtime::{types::RotoPackage, Ctx},
};

use super::flowspec::{
    FlowSpecQueryRow, FlowSpecRuleCounts, FlowSpecRuleSet, FlowSpecStore,
    FlowSpecValidity,
};
use super::{http_ng::Include, QueryFilter};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum FlowSpecOriginator {
    BgpId([u8; 4]),
    Ingress(IngressId),
}

type Store = StarCastRib<RotondaPaMap, MemoryOnlyConfig>;

// ---------------------------------------------------------------------------
// Streaming full-RIB dump tuning + concurrency control
// ---------------------------------------------------------------------------

/// Number of prefix *keys* whose records are fetched into one owned batch
/// before that batch is emitted to the consumer.
///
/// A full-RIB dump enumerates keys up front (guard-free) and then, per chunk
/// of this many keys, materialises the chunk's records under short-lived
/// per-prefix guards and emits them with NO epoch guard held. This bounds the
/// transient memory of a dump's in-flight batch to roughly
/// `DUMP_KEY_CHUNK * records_per_prefix * record_size` (kilobytes-to-low-MB),
/// independent of total table size or path count.
const DUMP_KEY_CHUNK: usize = 512;

/// Wall-clock backstop for a single full-RIB dump.
///
/// The streaming design already prevents a slow dump from leaking memory (no
/// epoch guard is ever held across the network-paced emission), so this only
/// guards against a pathologically long-running dump indefinitely occupying a
/// blocking thread, a dump slot and a key buffer. It is deliberately set well
/// above any legitimate full-table dump time — 300M records at even 50k
/// records/s is ~100 min — so it never truncates a real dump; on reaching it
/// the walk stops and logs, returning the partial count.
const DUMP_MAX_DURATION: std::time::Duration =
    std::time::Duration::from_secs(3 * 60 * 60);

/// Maximum number of concurrent full-RIB dumps across ALL output paths
/// (bmp-out table dumps + HTTP `?format=jsonl` dumps combined).
///
/// Each in-flight dump holds a blocking thread and an owned key buffer
/// (~table-size × `Prefix`); this caps the aggregate so a burst of dump
/// requests — notably on the unauthenticated HTTP endpoint — cannot pile up
/// unboundedly. See [`DumpGuard`].
const MAX_CONCURRENT_DUMPS: usize = 8;

static ACTIVE_DUMPS: AtomicUsize = AtomicUsize::new(0);

/// RAII counter for in-flight full-RIB dumps, enforcing [`MAX_CONCURRENT_DUMPS`].
///
/// Trusted callers that must not be rejected (a connecting BMP collector)
/// use [`DumpGuard::enter`], which always succeeds but still counts toward the
/// global total so untrusted callers back off. Untrusted callers (the HTTP
/// endpoint) use [`DumpGuard::try_enter`], which returns `None` once the cap
/// is reached so the request can be refused with `503` instead of adding load.
#[must_use = "the dump slot is released when the DumpGuard is dropped"]
pub struct DumpGuard(());

impl DumpGuard {
    /// Enter a dump unconditionally (for trusted callers). Always succeeds;
    /// still increments the shared in-flight count.
    pub fn enter() -> DumpGuard {
        ACTIVE_DUMPS.fetch_add(1, Ordering::AcqRel);
        DumpGuard(())
    }

    /// Try to enter a dump subject to the global cap (for untrusted callers).
    /// Returns `None` when [`MAX_CONCURRENT_DUMPS`] is already in flight.
    pub fn try_enter() -> Option<DumpGuard> {
        let mut cur = ACTIVE_DUMPS.load(Ordering::Relaxed);
        loop {
            if cur >= MAX_CONCURRENT_DUMPS {
                return None;
            }
            match ACTIVE_DUMPS.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(DumpGuard(())),
                Err(actual) => cur = actual,
            }
        }
    }

    /// Current number of in-flight dumps (diagnostics only).
    pub fn active() -> usize {
        ACTIVE_DUMPS.load(Ordering::Relaxed)
    }
}

impl Drop for DumpGuard {
    fn drop(&mut self) {
        ACTIVE_DUMPS.fetch_sub(1, Ordering::AcqRel);
    }
}

type RotoHttpFilter = roto::TypedFunc<
    Ctx,
    fn(
        roto::Val<crate::roto_runtime::RcRotondaPaMap>,
    ) -> roto::Verdict<(), ()>,
>;

#[derive(Clone)]
pub struct Rib {
    unicast: Arc<Option<Store>>,
    multicast: Arc<Option<Store>>,
    /// FlowSpec rules (SAFI 133, v4+v6 in the one dual-family store), keyed
    /// on `RotondaRoute::index_prefix()` — the destination-prefix component,
    /// or the family default route for rules without a usable one. The
    /// record value per `(prefix, mui)` is a whole [`FlowSpecRuleSet`] blob.
    flowspec: Arc<Option<FlowSpecStore>>,
    flowspec_rule_counts: Arc<FlowSpecRuleCounts>,
    pub(crate) ingress_register: Arc<ingress::Register>,
    roto_package: Option<Arc<RotoPackage>>,
    roto_context: Arc<Mutex<Ctx>>,
    path_attribute_interner: Arc<PathAttributeInterner>,
    // Serialises every writer to the per-store `withdrawn_muis_bmin`
    // roaring bitmap: `withdraw_for_ingress` (mark_mui_as_withdrawn) and
    // `remove_for_ingresses` (`remove_mui` marks the MUI active).
    // rotonda-store 0.5.0's
    // `TreeBitMap::update_withdrawn_muis_bmin` has a CAS retry loop that
    // never reloads its `expected` value, so any concurrent writer that
    // loses a CAS race livelocks indefinitely. Holding this mutex around
    // every call guarantees there's only ever one in flight.
    withdraw_lock: Arc<Mutex<()>>,
    // Serialises the read-modify-write of FlowSpecRuleSet blobs: the store
    // overwrites whole records per (prefix, mui), so two concurrent
    // upserts of different rules under the same key would lose one rule
    // without this. Deliberately NOT withdraw_lock — that one is held
    // across whole-store compaction walks and would stall flowspec ingest
    // during peer-down cascades. Lock order is always
    // flowspec_lock -> withdraw_lock (via mark_ingress_active inside
    // insert_flowspec); no path acquires them in reverse.
    flowspec_lock: Arc<Mutex<()>>,
}

#[derive(Copy, Clone, Debug)]
struct Multicast(bool);

impl Rib {
    pub fn new(
        ingress_register: Arc<ingress::Register>,
        roto_package: Option<Arc<RotoPackage>>,
        roto_context: Arc<Mutex<Ctx>>,
    ) -> Result<Self, PrefixStoreError> {
        let flowspec_rule_counts =
            super::flowspec::flowspec_metrics().register_rule_counts();
        Ok(Rib {
            unicast: Arc::new(Some(Store::try_default()?)),
            multicast: Arc::new(Some(Store::try_default()?)),
            flowspec: Arc::new(Some(FlowSpecStore::try_default()?)),
            flowspec_rule_counts,
            ingress_register,
            roto_package,
            roto_context,
            path_attribute_interner: Arc::new(
                PathAttributeInterner::default(),
            ),
            withdraw_lock: Arc::new(Mutex::new(())),
            flowspec_lock: Arc::new(Mutex::new(())),
        })
    }

    pub fn store(&self) -> Result<&Store, PrefixStoreError> {
        if let Some(rib) = self.unicast.as_ref() {
            Ok(rib)
        } else {
            Err(PrefixStoreError::StoreNotReadyError)
        }
    }

    /// Emit a consolidated snapshot of the main memory consumers to the log,
    /// for leak hunting. Cheap: store counters are atomic loads, the interner
    /// scan and register tally lock briefly. Intended to be called on a slow
    /// timer (every few minutes), not on any hot path.
    ///
    /// What to watch:
    /// * `routes/variants` climbing while `prefixes` is flat (a rising
    ///   variants-per-prefix ratio) ⇒ dead per-mui route slots not being
    ///   physically reclaimed — the RIB leak.
    /// * `ingress connected` climbing past the count of genuinely live peers ⇒
    ///   stuck-`Connected` half-open exporters that GC can never reclaim.
    /// * `bmp-out buffered` large/growing ⇒ a slow consumer's dump backlog.
    /// * `RSS` is the bottom line — cross-check it against the sum of the above
    ///   to see whether the leak is accounted for here or somewhere unmeasured.
    pub fn report_memory(&self, status_split: bool) {
        use crate::mem_stats::{
            bmp_out_snapshot, fmt_bytes, fmt_count, read_rss_bytes,
        };

        let rss = read_rss_bytes()
            .map(fmt_bytes)
            .unwrap_or_else(|| "n/a".to_string());
        let bmp = bmp_out_snapshot();
        info!(
            "memstat: RSS={rss} | bmp-out clients={} buffered={} ({} entries)",
            bmp.clients,
            fmt_bytes(bmp.buffered_bytes),
            fmt_count(bmp.buffered_entries),
        );

        for (label, store) in [
            ("unicast", self.unicast.as_ref()),
            ("multicast", self.multicast.as_ref()),
        ] {
            let Some(store) = store else {
                continue;
            };
            let prefixes = store.prefixes_count().in_memory();
            let v4 = store.prefixes_v4_count().in_memory();
            let v6 = store.prefixes_v6_count().in_memory();
            let routes = store.routes_count().in_memory();
            let nodes = store.nodes_count();
            let per_prefix = if prefixes > 0 {
                routes as f64 / prefixes as f64
            } else {
                0.0
            };
            info!(
                "memstat: {label} prefixes={} (v4 {} / v6 {}) \
                 routes/variants={} ({per_prefix:.1}/prefix) nodes={}",
                fmt_count(prefixes),
                fmt_count(v4),
                fmt_count(v6),
                fmt_count(routes),
                fmt_count(nodes),
            );
        }

        if let Some(store) = self.flowspec.as_ref() {
            let prefixes = store.prefixes_count().in_memory();
            let records = store.routes_count().in_memory();
            info!(
                "memstat: flowspec keys={} (v4 {} / v6 {}) rule-sets={}",
                fmt_count(prefixes),
                fmt_count(store.prefixes_v4_count().in_memory()),
                fmt_count(store.prefixes_v6_count().in_memory()),
                fmt_count(records),
            );
        }

        let (buckets, weak_slots, live_blobs) =
            self.path_attribute_interner.stats();
        info!(
            "memstat: pa-interner buckets={} weak_slots={} live_blobs={}",
            fmt_count(buckets),
            fmt_count(weak_slots),
            fmt_count(live_blobs),
        );

        let reg = self.ingress_register.memory_summary();
        info!(
            "memstat: ingress total={} connected={} disconnected={} \
             non_network={} unset={} (BgpViaBmp {}, BgpPath {})",
            reg.total,
            reg.connected,
            reg.disconnected,
            reg.non_network,
            reg.state_unset,
            reg.bgp_via_bmp,
            reg.bgp_path,
        );

        // Optional Active/Withdrawn split of the per-(prefix, mui) route
        // slots. `routes/variants` counts every physically-resident slot
        // regardless of status, so a runaway count with flat prefixes is
        // either (a) Withdrawn slots retained under still-live peers — a
        // mark-withdrawn graveyard that only whole-mui removal reclaims — or
        // (b) slots under muis that have left the ingress register entirely
        // and so are invisible to the Disconnected-only GC. The withdrawn %
        // distinguishes status; `store-muis` vs the `ingress total` line
        // above distinguishes (a) (roughly equal) from (b) (store-muis far
        // larger).
        //
        // This walks every record in the store (cost ~ a full RIB dump, and
        // it pins epoch garbage for the whole walk), so it only runs when the
        // rib unit's `memstat_status_split` config flag is on (hot-reloadable;
        // off by default). Leave it off for normal operation.
        if status_split {
            if let Some(store) = self.flowspec.as_ref() {
                let guard = &epoch::pin();
                let mut rules = 0usize;
                let mut rule_bytes = 0usize;
                let mut per_mui: HashMap<u32, usize> = HashMap::new();
                for pr in store.prefixes_iter(guard).flatten() {
                    for r in pr.meta.iter() {
                        let n = r.meta.rule_count();
                        rules += n;
                        rule_bytes += r.meta.byte_size();
                        *per_mui.entry(r.multi_uniq_id).or_insert(0) += n;
                    }
                }
                info!(
                    "memstat: flowspec rules={} blob-bytes={} store-muis={}",
                    fmt_count(rules),
                    fmt_bytes(rule_bytes),
                    fmt_count(per_mui.len()),
                );
            }
            for (label, store) in [
                ("unicast", self.unicast.as_ref()),
                ("multicast", self.multicast.as_ref()),
            ] {
                let Some(store) = store else {
                    continue;
                };
                let guard = &epoch::pin();
                let mut active = 0usize;
                let mut withdrawn = 0usize;
                // Per-mui total slot count (active + withdrawn), so a runaway
                // count can be attributed to the fattest sessions. The key
                // (mui == ingress_id) cross-references the /ingresses API to a
                // concrete (router, peer, pre/post) — use it to target which
                // sessions to stop monitoring or filter.
                let mut per_mui: HashMap<u32, usize> = HashMap::new();
                for pr in store.prefixes_iter(guard).flatten() {
                    for r in pr.meta.iter() {
                        *per_mui.entry(r.multi_uniq_id).or_insert(0) += 1;
                        if r.status == RouteStatus::Withdrawn {
                            withdrawn += 1;
                        } else {
                            active += 1;
                        }
                    }
                }
                let total = active + withdrawn;
                let pct = if total > 0 {
                    withdrawn as f64 * 100.0 / total as f64
                } else {
                    0.0
                };
                info!(
                    "memstat: {label} route-status active={} withdrawn={} \
                     ({pct:.1}% withdrawn) store-muis={}",
                    fmt_count(active),
                    fmt_count(withdrawn),
                    fmt_count(per_mui.len()),
                );

                // Per-mui route-count histogram: the top sessions by slot count
                // plus how many muis sit above coarse thresholds. Lets a leak
                // ("a mui past its peer's real table") be told apart from scale
                // ("many fat full-table sessions"), and ranks filtering targets.
                if !per_mui.is_empty() {
                    let mut counts: Vec<(u32, usize)> =
                        per_mui.into_iter().collect();
                    counts.sort_unstable_by(|a, b| b.1.cmp(&a.1));
                    let over_1m =
                        counts.iter().filter(|(_, c)| *c > 1_000_000).count();
                    let over_100k =
                        counts.iter().filter(|(_, c)| *c > 100_000).count();
                    let max = counts.first().map(|(_, c)| *c).unwrap_or(0);
                    let top: String = counts
                        .iter()
                        .take(10)
                        .map(|(mui, c)| format!("{mui}={}", fmt_count(*c)))
                        .collect::<Vec<_>>()
                        .join(" ");
                    info!(
                        "memstat: {label} per-mui max={} muis>1M={} \
                         muis>100k={} top10[mui=routes]: {top}",
                        fmt_count(max),
                        over_1m,
                        over_100k,
                    );
                }
            }
        }
    }

    pub fn insert(
        &self,
        val: &RotondaRoute,
        route_status: RouteStatus,
        ltime: u64,
        ingress_id: IngressId,
        retain_withdrawn_attributes: bool,
        deduplicate_path_attributes: bool,
    ) -> Result<UpsertReport, String> {
        let res = match val {
            RotondaRoute::Ipv4Unicast(n, ..) => self.insert_prefix(
                &n.prefix(),
                Multicast(false),
                val,
                route_status,
                ltime,
                ingress_id,
                retain_withdrawn_attributes,
                deduplicate_path_attributes,
            ),
            RotondaRoute::Ipv6Unicast(n, ..) => self.insert_prefix(
                &n.prefix(),
                Multicast(false),
                val,
                route_status,
                ltime,
                ingress_id,
                retain_withdrawn_attributes,
                deduplicate_path_attributes,
            ),
            RotondaRoute::Ipv4Multicast(n, ..) => self.insert_prefix(
                &n.prefix(),
                Multicast(true),
                val,
                route_status,
                ltime,
                ingress_id,
                retain_withdrawn_attributes,
                deduplicate_path_attributes,
            ),
            RotondaRoute::Ipv6Multicast(n, ..) => self.insert_prefix(
                &n.prefix(),
                Multicast(true),
                val,
                route_status,
                ltime,
                ingress_id,
                retain_withdrawn_attributes,
                deduplicate_path_attributes,
            ),
            RotondaRoute::Ipv4FlowSpec(n, pamap) => self.insert_flowspec(
                n.nlri().raw().as_ref(),
                pamap,
                val.index_prefix(),
                route_status,
                ltime,
                ingress_id,
            ),
            RotondaRoute::Ipv6FlowSpec(n, pamap) => self.insert_flowspec(
                n.nlri().raw().as_ref(),
                pamap,
                val.index_prefix(),
                route_status,
                ltime,
                ingress_id,
            ),
        };
        res.map_err(|e| e.to_string())
    }

    /// Upsert or withdraw one FlowSpec rule in the flowspec store.
    ///
    /// The store overwrites the whole record per `(prefix, mui)`, so this
    /// is a read-modify-write of the [`FlowSpecRuleSet`] blob, serialised
    /// by `flowspec_lock` (see the field comment). Identity within the set
    /// is the full raw NLRI: announcements replace-by-NLRI, withdrawals
    /// remove-by-NLRI, and a set that empties is written back as a
    /// `Withdrawn` record so the store's per-mui GC reclaims it.
    fn insert_flowspec(
        &self,
        nlri_raw: &[u8],
        pamap: &RotondaPaMap,
        key: Prefix,
        route_status: RouteStatus,
        ltime: u64,
        ingress_id: IngressId,
    ) -> Result<UpsertReport, PrefixStoreError> {
        let store = (*self.flowspec)
            .as_ref()
            .ok_or(PrefixStoreError::StoreNotReadyError)?;
        let mui = ingress_id;

        let no_op = UpsertReport {
            cas_count: 0,
            prefix_new: false,
            mui_new: false,
            mui_count: 0,
        };

        let _guard = self
            .flowspec_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _count_mutation = self.flowspec_rule_counts.begin_mutation();

        // A withdrawn MUI may still own the previous session's records when
        // withdrawn attributes are retained. Clearing the family-wide bit
        // would make those records active again, so empty only this FlowSpec
        // family before accepting its first new announcement. Do not use the
        // whole-ingress removal path here: a family-scoped withdrawal must
        // not erase unrelated unicast, multicast, or opposite-family routes.
        if route_status == RouteStatus::Active
            && if key.is_v4() {
                store.mui_is_withdrawn_v4(mui)
            } else {
                store.mui_is_withdrawn_v6(mui)
            }
        {
            // Lock order: flowspec_lock (held) -> withdraw_lock (inside).
            self.reset_flowspec_family(store, mui, key.is_v4())?;
            self.ingress_register.update_info(
                mui,
                ingress::IngressInfo::new()
                    .with_state(ingress::register::IngressState::Connected),
            );
        }

        let mut ruleset = store
            .get_records_for_prefix(&key, Some(mui), true)
            .map_err(|_| PrefixStoreError::StoreNotReadyError)?
            .and_then(|records| {
                records
                    .into_iter()
                    .find(|r| r.multi_uniq_id == mui)
                    .map(|r| r.meta)
            })
            .unwrap_or_default();

        let metrics = super::flowspec::flowspec_metrics();
        let is_v4 = key.is_v4();

        if route_status == RouteStatus::Withdrawn {
            metrics.note_update(is_v4, true);
            if !ruleset.remove(nlri_raw) {
                // Unknown rule (or peer) — nothing to withdraw.
                return Ok(no_op);
            }
            let (status, ltime) = if ruleset.is_empty() {
                (RouteStatus::Withdrawn, ltime)
            } else {
                (RouteStatus::Active, ltime)
            };
            let pubrec = Record::new(mui, ltime, status, ruleset);
            let report = store.insert(&key, pubrec, None);
            if report.is_ok() {
                self.flowspec_rule_counts.add(is_v4, -1);
            }
            return report;
        }
        metrics.note_update(is_v4, false);

        let flow_originator = self.flowspec_identity(pamap, mui).0;
        let validity = self.validate_flowspec(
            nlri_raw,
            flow_originator,
            is_v4,
        );
        let replaced = ruleset.upsert(nlri_raw, pamap, validity);
        let pubrec = Record::new(mui, ltime, route_status, ruleset);
        let report = store.insert(&key, pubrec, None);
        if report.is_ok() && !replaced {
            self.flowspec_rule_counts.add(is_v4, 1);
        }
        report
    }

    /// Remove retained rules for one FlowSpec family and make that family's
    /// withdrawn-MUI bitmap active again. The caller holds `flowspec_lock`.
    fn reset_flowspec_family(
        &self,
        store: &FlowSpecStore,
        mui: IngressId,
        is_v4: bool,
    ) -> Result<(), PrefixStoreError> {
        let _guard = self
            .withdraw_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let keys: Vec<Prefix> = if is_v4 {
            store.prefixes_keys_iter_v4().collect()
        } else {
            store.prefixes_keys_iter_v6().collect()
        };

        for key in keys {
            let owns_key = store
                .get_records_for_prefix(&key, Some(mui), true)
                .map_err(|_| PrefixStoreError::StoreNotReadyError)?
                .is_some_and(|records| {
                    records.iter().any(|record| record.multi_uniq_id == mui)
                });
            if owns_key {
                store.insert(
                    &key,
                    Record::new(
                        mui,
                        0,
                        RouteStatus::Withdrawn,
                        FlowSpecRuleSet::default(),
                    ),
                    None,
                )?;
            }
        }

        if is_v4 {
            store.mark_mui_as_active_v4(mui)
        } else {
            store.mark_mui_as_active_v6(mui)
        }
    }

    /// RFC 8955 §6 validation of one FlowSpec rule. The result stored at
    /// insert time is a snapshot; `query_flowspec` refreshes it against the
    /// current unicast RIB before exposing it. Never rejects: a monitor wants
    /// to SEE invalid rules.
    ///
    /// * no usable destination prefix (absent component, or RFC 8956
    ///   offset != 0) -> `Unvalidatable`;
    /// * (a) the best-match unicast route for the destination prefix must
    ///   have the same BGP originator;
    /// * (b) no more-specific unicast route may have a different neighboring
    ///   AS in its AS_PATH (only checked when both ASNs are known).
    fn validate_flowspec(
        &self,
        nlri_raw: &[u8],
        flow_originator: FlowSpecOriginator,
        is_v4: bool,
    ) -> FlowSpecValidity {
        let Some(nlri) = super::flowspec::parse_raw_nlri(nlri_raw, is_v4)
        else {
            return FlowSpecValidity::Unvalidatable;
        };
        let Some(dst) = nlri.dst_prefix() else {
            return FlowSpecValidity::Unvalidatable;
        };
        let Some(store) = (*self.unicast).as_ref() else {
            return FlowSpecValidity::NotValidated;
        };

        let guard = &epoch::pin();
        let match_options = MatchOptions {
            match_type: rotonda_store::match_options::MatchType::LongestMatch,
            include_withdrawn: false,
            include_less_specifics: false,
            include_more_specifics: true,
            mui: None,
            include_history:
                rotonda_store::match_options::IncludeHistory::None,
        };
        let Ok(res) = store.match_prefix(&dst, &match_options, guard) else {
            return FlowSpecValidity::NotValidated;
        };

        // (a) Compare BGP originators, using ORIGINATOR_ID when present and
        // the advertising peer's BGP Identifier otherwise. Falling back to
        // the ingress id preserves validation for inputs (notably MRT) that
        // carry neither. This also handles route-reflector feeds where the
        // same originator legitimately arrives through different sessions.
        let best_match = res.records.iter().find_map(|r| {
            if r.status == RouteStatus::Withdrawn {
                return None;
            }
            let (originator, neighbor) =
                self.flowspec_identity(&r.meta, r.multi_uniq_id);
            (originator == flow_originator).then_some((r, neighbor))
        });
        let Some(best_match) = best_match.filter(|_| res.prefix.is_some())
        else {
            return FlowSpecValidity::Invalid;
        };

        // (b) Compare the neighboring AS encoded in AS_PATH. The session's
        // remote ASN is only a fallback for empty/missing paths, which is
        // important for iBGP and route-reflector collectors: every session
        // there has the same remote ASN while the routes can originate in
        // different neighboring ASes.
        if let (Some(best_neighbor), Some(more_specifics)) =
            (best_match.1, res.more_specifics.as_ref())
        {
            for pr in more_specifics.iter() {
                for r in pr.meta.iter() {
                    if r.status == RouteStatus::Withdrawn {
                        continue;
                    }
                    let other_asn =
                        self.flowspec_identity(&r.meta, r.multi_uniq_id).1;
                    if matches!(other_asn, Some(asn) if asn != best_neighbor)
                    {
                        return FlowSpecValidity::Invalid;
                    }
                }
            }
        }

        FlowSpecValidity::Valid
    }

    /// Extract only the two attributes needed by RFC 8955 validation.
    /// Scanning the shared raw attribute bytes avoids allocating a full
    /// `OwnedPathAttributes`/`PaMap` on every validation.
    fn flowspec_validation_attrs(
        &self,
        pamap: &RotondaPaMap,
    ) -> (Option<[u8; 4]>, Option<Asn>) {
        let raw = pamap.as_ref();
        if raw.len() < 2 {
            return (None, None);
        }
        let asn_len = if raw[1] == 1 { 4 } else { 2 };
        let attrs = &raw[2..];
        let mut originator = None;
        let mut neighbor = None;
        let mut pos = 0usize;

        while pos < attrs.len() {
            if attrs.len() - pos < 3 {
                break;
            }
            let flags = attrs[pos];
            let type_code = attrs[pos + 1];
            let (header_len, value_len) = if flags & 0x10 != 0 {
                if attrs.len() - pos < 4 {
                    break;
                }
                (
                    4,
                    u16::from_be_bytes([attrs[pos + 2], attrs[pos + 3]])
                        as usize,
                )
            } else {
                (3, attrs[pos + 2] as usize)
            };
            let Some(end) = pos
                .checked_add(header_len)
                .and_then(|start| start.checked_add(value_len))
                .filter(|end| *end <= attrs.len())
            else {
                break;
            };
            let value = &attrs[pos + header_len..end];

            if type_code == 9 && value.len() == 4 {
                originator = Some(value.try_into().expect("length checked"));
            } else if type_code == 2
                && neighbor.is_none()
                && value.len() >= 2 + asn_len
                && value[0] == 2
                && value[1] != 0
            {
                neighbor = Some(if asn_len == 4 {
                    Asn::from_u32(u32::from_be_bytes(
                        value[2..6].try_into().expect("length checked"),
                    ))
                } else {
                    Asn::from_u32(u16::from_be_bytes(
                        value[2..4].try_into().expect("length checked"),
                    ) as u32)
                });
            }
            pos = end;
        }
        (originator, neighbor)
    }

    fn flowspec_identity(
        &self,
        pamap: &RotondaPaMap,
        ingress_id: IngressId,
    ) -> (FlowSpecOriginator, Option<Asn>) {
        // ADD-PATH path-child muis are display-only entries without a
        // bgp_id of their own; resolve to the parent session so every
        // path of one peer yields the same identity.
        let session_id = self.ingress_register.session_for(ingress_id);
        let (attr_id, path_neighbor) =
            self.flowspec_validation_attrs(pamap);
        let (peer_id, remote_asn) = self
            .ingress_register
            .bgp_id_and_remote_asn(session_id);
        let originator = attr_id
            .or(peer_id)
            .map(FlowSpecOriginator::BgpId)
            .unwrap_or(FlowSpecOriginator::Ingress(session_id));
        (originator, path_neighbor.or(remote_asn))
    }

    /// Recount the stored-rule gauges by walking the (small) flowspec
    /// store. Called after operations that drop rules without going through
    /// `insert_flowspec` (whole-mui removal, compaction) so the gauges
    /// cannot drift.
    fn recount_flowspec_rules(&self) {
        let Some(store) = (*self.flowspec).as_ref() else {
            return;
        };
        loop {
            let Some(generation) =
                self.flowspec_rule_counts.recount_generation()
            else {
                std::thread::yield_now();
                continue;
            };
            let mut v4 = 0u64;
            let mut v6 = 0u64;
            for key in store.prefixes_keys_iter() {
                if let Ok(Some(records)) =
                    store.get_records_for_prefix(&key, None, false)
                {
                    let rules: u64 = records
                        .iter()
                        .filter(|r| r.status != RouteStatus::Withdrawn)
                        .map(|r| r.meta.rule_count() as u64)
                        .sum();
                    if key.is_v4() {
                        v4 += rules;
                    } else {
                        v6 += rules;
                    }
                }
            }
            if !self
                .flowspec_rule_counts
                .generation_is_quiescent(generation)
            {
                continue;
            }
            self.flowspec_rule_counts.set(v4, v6);
            if self
                .flowspec_rule_counts
                .generation_is_quiescent(generation)
            {
                return;
            }
        }
    }

    fn insert_prefix(
        &self,
        prefix: &Prefix,
        multicast: Multicast,
        val: &RotondaRoute,
        route_status: RouteStatus,
        ltime: u64,
        ingress_id: IngressId,
        retain_withdrawn_attributes: bool,
        deduplicate_path_attributes: bool,
    ) -> Result<UpsertReport, PrefixStoreError> {
        // Check whether our self.rib is Some(..) or bail out.
        let arc_store = match multicast.0 {
            true => self.multicast.clone(),
            false => self.unicast.clone(),
        };

        let store = (*arc_store)
            .as_ref()
            .ok_or(PrefixStoreError::StoreNotReadyError)?;

        let mui = ingress_id;

        if route_status == RouteStatus::Withdrawn {
            if !retain_withdrawn_attributes {
                if !store.contains(prefix, Some(mui)) {
                    return Ok(UpsertReport {
                        cas_count: 0,
                        prefix_new: false,
                        mui_new: false,
                        mui_count: 0,
                    });
                }

                let pubrec = Record::new(
                    mui,
                    ltime,
                    RouteStatus::Withdrawn,
                    RotondaPaMap::empty_path_attributes(),
                );

                return store.insert(prefix, pubrec, None);
            }

            // instead of creating an empty PrefixRoute for this Prefix and
            // putting that in the store, we use the new
            // mark_mui_as_withdrawn_for_prefix . This way, we preserve the
            // last seen attributes/nexthop for this {prefix,mui} combination,
            // while setting the status to Withdrawn.
            store.mark_mui_as_withdrawn_for_prefix(prefix, mui, 0)?;

            // FIXME this is just to satisfy the function signature, but is
            // quite useless as-is.
            return Ok(UpsertReport {
                cas_count: 0,
                prefix_new: false,
                mui_new: false,
                mui_count: 0,
            });
        }

        // A reused MUI may still own retained records from its previous
        // session.  Merely clearing the global withdrawn bit would resurrect
        // all of them, including prefixes not announced in the new session.
        // Remove the old session on the first active announcement instead.
        if route_status == RouteStatus::Active
            && (store.mui_is_withdrawn_v4(mui)
                || store.mui_is_withdrawn_v6(mui))
        {
            self.remove_for_ingresses(&[mui]);
            self.ingress_register.update_info(
                mui,
                ingress::IngressInfo::new()
                    .with_state(ingress::register::IngressState::Connected),
            );
        }

        let pubrec = Record::new(
            mui,
            ltime,
            route_status,
            if deduplicate_path_attributes {
                val.rotonda_pamap()
                    .dedup_with(&self.path_attribute_interner)
            } else {
                val.rotonda_pamap().clone()
            },
        );

        store.insert(
            prefix, pubrec, None, // Option<TBI>
        )
    }

    pub fn withdraw_for_ingress(
        &self,
        ingress_id: IngressId,
        specific_afisafi: Option<AfiSafiType>,
        retain_withdrawn_attributes: bool,
    ) {
        self.withdraw_for_ingresses(
            &[(ingress_id, specific_afisafi)],
            retain_withdrawn_attributes,
        );
    }

    /// Batched withdraw. The compaction phase walks every prefix in the
    /// store; doing it per-ingress in a cascade is O(N_ingress × N_prefix)
    /// (≈62% of CPU in production under peer-down cascades). Batching
    /// collapses it to a single walk that fans the results out to every
    /// ingress in the call.
    pub fn withdraw_for_ingresses(
        &self,
        ids: &[(IngressId, Option<AfiSafiType>)],
        retain_withdrawn_attributes: bool,
    ) {
        if ids.is_empty() {
            return;
        }

        // See the `withdraw_lock` field comment for why this is held across
        // the whole body: rotonda-store 0.5.0's CAS retry loop livelocks
        // under concurrent writers. Holding it across the whole batch is
        // strictly shorter than the pre-batch loop, which re-acquired per
        // ingress.
        let _guard = self
            .withdraw_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let count_mutation = self.flowspec_rule_counts.begin_mutation();

        if !retain_withdrawn_attributes {
            self.compact_withdrawn_attributes_for_ingresses(ids);
        }

        for (ingress_id, specific_afisafi) in ids {
            debug!("withdraw_for_ingress for {ingress_id}");
            match specific_afisafi {
                None => {
                    // Set all address families to withdrawn.
                    // `mark_mui_as_withdrawn` already covers both v4 and v6
                    // in the unicast store in a single tree walk.

                    debug!(
                        "mark_mui_as_withdrawn on unicast for {ingress_id}"
                    );
                    if let Err(e) = (*self.unicast)
                        .as_ref()
                        .unwrap()
                        .mark_mui_as_withdrawn(*ingress_id)
                    {
                        error!(
                            "failed to mark MUI as withdrawn in unicast rib: {}",
                            e
                        )
                    }

                    if let Err(e) = (*self.multicast)
                        .as_ref()
                        .unwrap()
                        .mark_mui_as_withdrawn(*ingress_id)
                    {
                        error!("failed to mark MUI as withdrawn in multicast rib: {}", e)
                    }

                    if let Err(e) = (*self.flowspec)
                        .as_ref()
                        .unwrap()
                        .mark_mui_as_withdrawn(*ingress_id)
                    {
                        error!("failed to mark MUI as withdrawn in flowspec rib: {}", e)
                    }
                }
                Some(AfiSafiType::Ipv4Unicast) => {
                    if let Err(e) = (*self.unicast)
                        .as_ref()
                        .unwrap()
                        .mark_mui_as_withdrawn_v4(*ingress_id)
                    {
                        error!(
                            "failed to mark MUI as withdrawn for v4: {}",
                            e
                        )
                    }
                }
                Some(AfiSafiType::Ipv6Unicast) => {
                    if let Err(e) = (*self.unicast)
                        .as_ref()
                        .unwrap()
                        .mark_mui_as_withdrawn_v6(*ingress_id)
                    {
                        error!(
                            "failed to mark MUI as withdrawn for v6: {}",
                            e
                        )
                    }
                }
                Some(AfiSafiType::Ipv4Multicast) => {
                    if let Err(e) = (*self.multicast)
                        .as_ref()
                        .unwrap()
                        .mark_mui_as_withdrawn_v4(*ingress_id)
                    {
                        error!(
                            "failed to mark MUI as withdrawn for v4: {}",
                            e
                        )
                    }
                }
                Some(AfiSafiType::Ipv6Multicast) => {
                    if let Err(e) = (*self.multicast)
                        .as_ref()
                        .unwrap()
                        .mark_mui_as_withdrawn_v6(*ingress_id)
                    {
                        error!(
                            "failed to mark MUI as withdrawn for v6: {}",
                            e
                        )
                    }
                }
                Some(AfiSafiType::Ipv4FlowSpec) => {
                    if let Err(e) = (*self.flowspec)
                        .as_ref()
                        .unwrap()
                        .mark_mui_as_withdrawn_v4(*ingress_id)
                    {
                        error!(
                            "failed to mark MUI as withdrawn for v4 flowspec: {}",
                            e
                        )
                    }
                }
                Some(AfiSafiType::Ipv6FlowSpec) => {
                    if let Err(e) = (*self.flowspec)
                        .as_ref()
                        .unwrap()
                        .mark_mui_as_withdrawn_v6(*ingress_id)
                    {
                        error!(
                            "failed to mark MUI as withdrawn for v6 flowspec: {}",
                            e
                        )
                    }
                }

                afisafi => {
                    // Reachable for families we never store (they are
                    // dropped at the TryFrom chokepoint), so log instead
                    // of taking the process down.
                    error!("no support to withdraw {:?} yet", afisafi)
                }
            }
        }

        drop(count_mutation);
        drop(_guard);
        // Whole-mui status flips change which flowspec rules are visible
        // without going through insert_flowspec.
        self.recount_flowspec_rules();
    }

    /// Physically remove every record for these ingress ids from the RIB,
    /// reclaiming their memory — as opposed to `withdraw_for_ingresses`, which
    /// only marks them withdrawn (a status bit) and keeps the records around.
    ///
    /// This is used both for ids that are gone for good and to discard a
    /// retained previous session before reusing an id. Synthesized BMP peers
    /// that mint a fresh ingress id every session must take this path so
    /// mark-withdraw does not leak one record slot per announced prefix.
    pub fn remove_for_ingresses(&self, ids: &[IngressId]) {
        if ids.is_empty() {
            return;
        }

        // `remove_mui` clears the per-store `withdrawn_muis_bmin` bitmap (via
        // mark_mui_as_active), the same CAS that livelocks under concurrent
        // writers, so it must hold `withdraw_lock` just like the mark path.
        // See the `withdraw_lock` field comment.
        let _guard = self
            .withdraw_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let count_mutation = self.flowspec_rule_counts.begin_mutation();

        for &id in ids {
            if let Some(store) = (*self.unicast).as_ref() {
                match store.remove_mui(id) {
                    Ok((records, emptied)) => debug!(
                        "removed MUI {id} from unicast rib: \
                         {records} records, {emptied} prefixes emptied"
                    ),
                    Err(e) => error!(
                        "failed to remove MUI {id} from unicast rib: {e}"
                    ),
                }
            }
            if let Some(store) = (*self.multicast).as_ref() {
                match store.remove_mui(id) {
                    Ok((records, emptied)) => debug!(
                        "removed MUI {id} from multicast rib: \
                         {records} records, {emptied} prefixes emptied"
                    ),
                    Err(e) => error!(
                        "failed to remove MUI {id} from multicast rib: {e}"
                    ),
                }
            }
            if let Some(store) = (*self.flowspec).as_ref() {
                match store.remove_mui(id) {
                    Ok((records, emptied)) => debug!(
                        "removed MUI {id} from flowspec rib: \
                         {records} records, {emptied} prefixes emptied"
                    ),
                    Err(e) => error!(
                        "failed to remove MUI {id} from flowspec rib: {e}"
                    ),
                }
            }
        }
        drop(count_mutation);
        drop(_guard);
        self.recount_flowspec_rules();
    }

    pub fn compact_withdrawn_attributes_for_ingress(
        &self,
        ingress_id: IngressId,
        specific_afisafi: Option<AfiSafiType>,
    ) {
        self.compact_withdrawn_attributes_for_ingresses(&[(
            ingress_id,
            specific_afisafi,
        )]);
    }

    /// Bucket the ingress ids by their afisafi scope, then issue at most one
    /// store walk per (store × afisafi-bucket). A peer-down cascade with
    /// N synthesized peers used to do N full-store walks; this collapses to
    /// one.
    fn compact_withdrawn_attributes_for_ingresses(
        &self,
        ids: &[(IngressId, Option<AfiSafiType>)],
    ) {
        let mut all_afis: HashSet<IngressId> = HashSet::new();
        let mut v4u_uc: HashSet<IngressId> = HashSet::new();
        let mut v6u_uc: HashSet<IngressId> = HashSet::new();
        let mut v4u_mc: HashSet<IngressId> = HashSet::new();
        let mut v6u_mc: HashSet<IngressId> = HashSet::new();
        let mut v4_fs: HashSet<IngressId> = HashSet::new();
        let mut v6_fs: HashSet<IngressId> = HashSet::new();

        for (id, specific_afisafi) in ids {
            match specific_afisafi {
                None => {
                    all_afis.insert(*id);
                }
                Some(AfiSafiType::Ipv4Unicast) => {
                    v4u_uc.insert(*id);
                }
                Some(AfiSafiType::Ipv6Unicast) => {
                    v6u_uc.insert(*id);
                }
                Some(AfiSafiType::Ipv4Multicast) => {
                    v4u_mc.insert(*id);
                }
                Some(AfiSafiType::Ipv6Multicast) => {
                    v6u_mc.insert(*id);
                }
                Some(AfiSafiType::Ipv4FlowSpec) => {
                    v4_fs.insert(*id);
                }
                Some(AfiSafiType::Ipv6FlowSpec) => {
                    v6_fs.insert(*id);
                }
                afisafi => {
                    warn!(
                        "no support to compact withdrawn attributes for {:?} yet",
                        afisafi
                    );
                }
            }
        }

        if !all_afis.is_empty() {
            self.compact_withdrawn_attributes_in_store_batch(
                self.unicast.as_ref().as_ref(),
                &all_afis,
                None,
            );
            self.compact_withdrawn_attributes_in_store_batch(
                self.multicast.as_ref().as_ref(),
                &all_afis,
                None,
            );
            self.compact_flowspec_for_ingresses(&all_afis, None);
        }
        if !v4_fs.is_empty() {
            self.compact_flowspec_for_ingresses(&v4_fs, Some(true));
        }
        if !v6_fs.is_empty() {
            self.compact_flowspec_for_ingresses(&v6_fs, Some(false));
        }
        if !v4u_uc.is_empty() {
            self.compact_withdrawn_attributes_in_store_batch(
                self.unicast.as_ref().as_ref(),
                &v4u_uc,
                Some(AfiSafiType::Ipv4Unicast),
            );
        }
        if !v6u_uc.is_empty() {
            self.compact_withdrawn_attributes_in_store_batch(
                self.unicast.as_ref().as_ref(),
                &v6u_uc,
                Some(AfiSafiType::Ipv6Unicast),
            );
        }
        if !v4u_mc.is_empty() {
            self.compact_withdrawn_attributes_in_store_batch(
                self.multicast.as_ref().as_ref(),
                &v4u_mc,
                Some(AfiSafiType::Ipv4Multicast),
            );
        }
        if !v6u_mc.is_empty() {
            self.compact_withdrawn_attributes_in_store_batch(
                self.multicast.as_ref().as_ref(),
                &v6u_mc,
                Some(AfiSafiType::Ipv6Multicast),
            );
        }
    }

    /// FlowSpec analogue of withdrawn-attribute compaction: rewrite every
    /// record these muis hold in the flowspec store to an empty rule-set
    /// blob, freeing the rule bytes while the (small) record slot stays
    /// until whole-mui removal. `family`: `Some(true)` = v4 keys only,
    /// `Some(false)` = v6 only, `None` = both.
    ///
    /// Runs under `withdraw_lock` (caller) but deliberately NOT under
    /// `flowspec_lock` — taking it here would invert the
    /// flowspec_lock -> withdraw_lock order used by `insert_flowspec`. The
    /// resulting race (an in-flight insert for a mui that is being torn
    /// down) is last-writer-wins on a record that is about to be marked
    /// withdrawn mui-wide, same exposure as the unicast compaction.
    fn compact_flowspec_for_ingresses(
        &self,
        ingress_ids: &HashSet<IngressId>,
        family: Option<bool>,
    ) {
        let Some(store) = (*self.flowspec).as_ref() else {
            return;
        };
        if ingress_ids.is_empty() {
            return;
        }

        let mut pending: Vec<(Prefix, IngressId)> = Vec::new();
        {
            let guard = &epoch::pin();
            for pr in store.prefixes_iter(guard).flatten() {
                if let Some(want_v4) = family {
                    if pr.prefix.is_v4() != want_v4 {
                        continue;
                    }
                }
                for r in pr.meta.iter() {
                    if ingress_ids.contains(&r.multi_uniq_id) {
                        pending.push((pr.prefix, r.multi_uniq_id));
                    }
                }
            }
        }

        for (prefix, mui) in pending {
            let pubrec = Record::new(
                mui,
                0,
                RouteStatus::Withdrawn,
                FlowSpecRuleSet::default(),
            );
            if let Err(err) = store.insert(&prefix, pubrec, None) {
                warn!(
                    "failed to compact flowspec rules for {prefix} and \
                     ingress {mui}: {err}"
                );
            }
        }
    }

    fn compact_withdrawn_attributes_in_store_batch(
        &self,
        store: Option<&Store>,
        ingress_ids: &HashSet<IngressId>,
        specific_afisafi: Option<AfiSafiType>,
    ) {
        let Some(store) = store else {
            return;
        };
        if ingress_ids.is_empty() {
            return;
        }

        let guard = &epoch::pin();

        // The two phases (iter + insert) both borrow `store` immutably and
        // rotonda-store's epoch-based concurrency permits inserts while a
        // walk is in flight, so the flush inside `drain_compaction_iter`
        // interleaves with the iterator rather than waiting for the walk
        // to complete. That keeps peak memory bounded regardless of how
        // many ingresses or prefixes the cascade touches.
        match specific_afisafi {
            Some(AfiSafiType::Ipv4Unicast | AfiSafiType::Ipv4Multicast) => {
                Self::drain_compaction_iter(
                    store,
                    ingress_ids,
                    store.prefixes_iter_v4(guard).flatten(),
                );
            }
            Some(AfiSafiType::Ipv6Unicast | AfiSafiType::Ipv6Multicast) => {
                Self::drain_compaction_iter(
                    store,
                    ingress_ids,
                    store.prefixes_iter_v6(guard).flatten(),
                );
            }
            _ => {
                Self::drain_compaction_iter(
                    store,
                    ingress_ids,
                    store.prefixes_iter(guard).flatten(),
                );
            }
        };
    }

    /// Walk `iter`, accumulating per-ingress prefix lists, and flush them
    /// to `store` as insert-Withdrawn records every FLUSH_AT pending
    /// entries. The cap on `pending` is what bounds peak memory: at
    /// ~24 bytes per `Prefix`, FLUSH_AT = 64K caps in-flight state at
    /// ~1.5 MB regardless of cascade size.
    fn drain_compaction_iter<I>(
        store: &Store,
        ingress_ids: &HashSet<IngressId>,
        iter: I,
    ) where
        I: Iterator<Item = PrefixRecord<RotondaPaMap>>,
    {
        const FLUSH_AT: usize = 64 * 1024;

        let mut pending: HashMap<IngressId, Vec<Prefix>> =
            HashMap::with_capacity(ingress_ids.len());
        let mut pending_count: usize = 0;

        for prefix_record in iter {
            pending_count += Self::group_prefix_by_ingress(
                &prefix_record,
                ingress_ids,
                &mut pending,
            );
            if pending_count >= FLUSH_AT {
                Self::flush_compaction(store, &mut pending);
                pending_count = 0;
            }
        }
        Self::flush_compaction(store, &mut pending);
    }

    fn flush_compaction(
        store: &Store,
        pending: &mut HashMap<IngressId, Vec<Prefix>>,
    ) {
        for (ingress_id, prefixes) in pending.drain() {
            for prefix in prefixes {
                let pubrec = Record::new(
                    ingress_id,
                    0,
                    RouteStatus::Withdrawn,
                    RotondaPaMap::empty_path_attributes(),
                );
                if let Err(err) = store.insert(&prefix, pubrec, None) {
                    warn!(
                        "failed to compact withdrawn attributes for {prefix} and ingress {ingress_id}: {err}"
                    );
                }
            }
        }
    }

    /// For one prefix's records, record this prefix once under every ingress
    /// in `ingress_ids` that holds at least one record on it. Returns the
    /// number of (ingress, prefix) entries appended to `out`.
    fn group_prefix_by_ingress(
        prefix_record: &PrefixRecord<RotondaPaMap>,
        ingress_ids: &HashSet<IngressId>,
        out: &mut HashMap<IngressId, Vec<Prefix>>,
    ) -> usize {
        // Dedupe within this prefix: ADDPATH can produce several records
        // per (prefix, ingress). 8 slots is plenty for the realistic case
        // (a single peer-down cascade rarely overlaps deeply on one prefix);
        // overflow falls back to harmless duplicate inserts.
        let mut matched: [IngressId; 8] = [0; 8];
        let mut matched_n: usize = 0;
        let mut added: usize = 0;
        for record in prefix_record.meta.iter() {
            let mui = record.multi_uniq_id;
            if !ingress_ids.contains(&mui) {
                continue;
            }
            if matched[..matched_n].contains(&mui) {
                continue;
            }
            if matched_n < matched.len() {
                matched[matched_n] = mui;
                matched_n += 1;
            }
            out.entry(mui).or_default().push(prefix_record.prefix);
            added += 1;
        }
        added
    }

    /// Layer C garbage-collection sweep. Reclaims idle register entries that
    /// have stayed `Disconnected` across at least one full sweep interval —
    /// i.e. were torn down and did not reconnect:
    ///
    /// * BMP-monitored peers (`IngressType::BgpViaBmp`): their mark-withdrawn
    ///   RIB records are physically reclaimed (`remove_for_ingresses`).
    ///   Without this, the peers that Layer D keeps as Disconnected (for mui
    ///   reuse) would hold their records forever if they never came back.
    ///   Deferred while any ADD-PATH path-child still references the peer as
    ///   `parent_ingress` — reclaiming the parent first would leave children
    ///   whose claim identity dangles; children go first, the session follows
    ///   one sweep later.
    ///
    /// * ADD-PATH path-children (`IngressType::BgpPath`, of both BMP-monitored
    ///   and direct BGP sessions): they hold RIB records under their own mui,
    ///   so they take the same record-reclaiming path as `BgpViaBmp` peers.
    ///   This also reaps children whose path id simply stopped being announced
    ///   across a session flap (the rebind claim leaves them Disconnected).
    ///
    /// * BMP routers (`IngressType::Bmp`, the parent entries) that have **no
    ///   children left in the register**. These hold no RIB records of their
    ///   own (routes live under their `BgpViaBmp` children), so only the
    ///   register entry is removed. A router parent is kept while any child
    ///   (`parent_ingress == this id`) still exists so a reconnecting peer can
    ///   rebind to it; once the last child is gone the parent has no reuse
    ///   value left. Without this path, every torn-down router leaks a
    ///   permanent `Disconnected` entry — including every TCP connection that
    ///   drops before sending Initiation (port scan, TLS probe, half-open RST,
    ///   each minting a childless provisional entry) and every
    ///   NAT/IP-renumber/sysName change — because the sweep otherwise only
    ///   reaped `BgpViaBmp`.
    ///
    /// Uses a two-sweep set rather than per-entry timestamps: `prev` is the
    /// set seen Disconnected on the previous sweep; any still Disconnected now
    /// have been idle for >= one interval and are reclaimed. Returns the set
    /// to pass to the next sweep.
    pub fn gc_disconnected_bmp_peers(
        &self,
        prev: HashSet<IngressId>,
    ) -> HashSet<IngressId> {
        let info = self.ingress_register.cloned_info();

        // Every parent_ingress referenced by some entry. A router (parent)
        // entry is only reclaimable once nothing still references it as a
        // parent — otherwise a leftover child could still rebind to it.
        let parents_in_use: HashSet<IngressId> =
            info.values().filter_map(|i| i.parent_ingress).collect();

        // All Disconnected ids we track across sweeps for idle-interval
        // detection (this set becomes the next `prev`). Split into the two
        // reclaim paths: `peers` (BgpViaBmp, carry RIB records) and
        // `childless_routers` (Bmp parents with no remaining children). A Bmp
        // parent that still has children is added to `disconnected` only — it
        // stays a candidate next sweep but is not yet eligible to reclaim.
        let mut disconnected: HashSet<IngressId> = HashSet::new();
        let mut peers: HashSet<IngressId> = HashSet::new();
        let mut childless_routers: HashSet<IngressId> = HashSet::new();
        for (id, i) in &info {
            if i.state
                != Some(ingress::register::IngressState::Disconnected)
            {
                continue;
            }
            match i.ingress_type {
                Some(ingress::IngressType::BgpViaBmp) => {
                    disconnected.insert(*id);
                    // Defer while ADD-PATH path-children still reference
                    // this session as parent: they are reclaimed this
                    // sweep, the session becomes eligible on the next one.
                    if !parents_in_use.contains(id) {
                        peers.insert(*id);
                    }
                }
                Some(ingress::IngressType::BgpPath) => {
                    // Path-children carry RIB records under their own mui,
                    // so they flow through the record-reclaiming path.
                    disconnected.insert(*id);
                    peers.insert(*id);
                }
                Some(ingress::IngressType::Bmp) => {
                    disconnected.insert(*id);
                    if !parents_in_use.contains(id) {
                        childless_routers.insert(*id);
                    }
                }
                _ => {}
            }
        }

        // Reclaim BgpViaBmp peers that were already Disconnected last sweep.
        let peers_to_reclaim: Vec<IngressId> =
            peers.intersection(&prev).copied().collect();
        if !peers_to_reclaim.is_empty() {
            // Atomically remove each still-Disconnected id from the register
            // FIRST, and only physically reclaim the store records
            // (remove_mui) for ids that were actually removed. A peer that
            // reconnected and rebound its id in the window since the
            // cloned_info() snapshot is now Connected: remove_if_disconnected
            // returns None for it, so we neither delete its live registration
            // nor wipe its freshly inserted routes. Removing from the register
            // before remove_mui also means any concurrent reuse can no longer
            // match this id (it mints a fresh one instead), so remove_mui only
            // ever clears the old, genuinely-departed session's records.
            let reclaimed: Vec<IngressId> = peers_to_reclaim
                .iter()
                .copied()
                .filter(|id| {
                    self.ingress_register
                        .remove_if_disconnected(*id)
                        .is_some()
                })
                .collect();
            if !reclaimed.is_empty() {
                self.remove_for_ingresses(&reclaimed);
                info!(
                    "rib GC: reclaimed {} peer/path ingress(es) idle \
                     (Disconnected) for >= one GC interval",
                    reclaimed.len()
                );
            }
        }

        // Reclaim childless BMP router (parent) entries that were already
        // Disconnected last sweep. Same atomic guard as the peer path: a
        // router that reconnected since the snapshot is now Connected, so
        // remove_if_disconnected skips it (the reconnect rebinds via
        // find_existing_bmp_router_and_claim, which flips it to Connected).
        // No remove_for_ingresses — parents own no RIB records.
        let routers_to_reclaim: Vec<IngressId> =
            childless_routers.intersection(&prev).copied().collect();
        if !routers_to_reclaim.is_empty() {
            let reclaimed = routers_to_reclaim
                .iter()
                .filter(|id| {
                    self.ingress_register
                        .remove_if_disconnected(**id)
                        .is_some()
                })
                .count();
            if reclaimed > 0 {
                info!(
                    "rib GC: reclaimed {reclaimed} idle BMP router(s) \
                     (Disconnected, no children) for >= one GC interval"
                );
            }
        }

        // Reclaimed ids are now gone from the register, so they won't appear
        // in the next sweep's snapshot; returning the full current set is fine.
        disconnected
    }

    pub fn match_prefix(
        &self,
        prefix: &Prefix,
        match_options: &MatchOptions,
    ) -> Result<QueryResult<RotondaPaMap>, String> {
        let guard = &epoch::pin();
        let store = (*self.unicast)
            .as_ref()
            .ok_or(PrefixStoreError::StoreNotReadyError.to_string())?;
        let unicast_res = store
            .match_prefix(prefix, match_options, guard)
            .map_err(|err| err.to_string())?;
        if unicast_res.records.is_empty()
            && unicast_res.less_specifics.is_none()
            && unicast_res.more_specifics.is_none()
        {
            debug!("no result in unicast store, trying multicast");
            let multicast_store = (*self.multicast)
                .as_ref()
                .ok_or(PrefixStoreError::StoreNotReadyError.to_string())?;
            let multicast_res = multicast_store
                .match_prefix(prefix, match_options, guard)
                .map_err(|err| err.to_string())?;
            if !(multicast_res.records.is_empty()
                && multicast_res.less_specifics.is_none()
                && multicast_res.more_specifics.is_none())
            {
                return Ok(multicast_res);
            }
        }
        Ok(unicast_res)
    }

    /// Iterate all prefix records in the unicast RIB.
    /// Each PrefixRecord contains the prefix and all non-withdrawn route
    /// records (from all peers). Withdrawn entries are filtered out at the
    /// iterator level so callers don't need to skip them, and PrefixRecords
    /// whose entire meta vec is withdrawn are dropped entirely — keeps the
    /// returned Vec smaller for large RIBs (relevant on initial BMP dump).
    pub fn iter_all_prefix_records(
        &self,
    ) -> Result<Vec<PrefixRecord<RotondaPaMap>>, String> {
        let guard = &epoch::pin();
        let store = (*self.unicast)
            .as_ref()
            .ok_or(PrefixStoreError::StoreNotReadyError.to_string())?;

        let res: Vec<PrefixRecord<RotondaPaMap>> = store
            .prefixes_iter(guard)
            .flatten()
            .filter_map(|mut pr| {
                pr.meta.retain(|r| r.status != RouteStatus::Withdrawn);
                if pr.meta.is_empty() {
                    None
                } else {
                    Some(pr)
                }
            })
            .collect();

        debug!("rib::iter_all_prefix_records: {} prefix records", res.len());
        Ok(res)
    }

    /// Stream prefix records to a caller-supplied closure instead of
    /// collecting into a `Vec`. The closure returns `true` to continue
    /// iteration or `false` to stop early (e.g. on consumer disconnect).
    ///
    /// Use this for large dumps: collecting 100M+ route records into a
    /// single `Vec` is many GB even without copying the Arc-backed PaMap
    /// bytes, and that allocation has to coexist with the rest of the
    /// process (downstream sender, in-flight live updates, etc).
    /// Streaming bounds the working set to whatever the consumer can
    /// drain plus one `PrefixRecord` in flight.
    ///
    /// Withdrawn meta entries are filtered out before the closure is
    /// called, and prefixes whose entire meta vec is withdrawn are
    /// skipped — matching `iter_all_prefix_records` semantics. A record is
    /// emitted iff it is `Active` or `InActive` and its mui is not globally
    /// withdrawn (identical to the previous
    /// `prefixes_iter` + `retain(!Withdrawn)` filtering).
    ///
    /// ## Memory model — no epoch guard is held across `f`
    ///
    /// A naive `prefixes_iter(&guard)` walk borrows a single `epoch::pin()`
    /// guard for its entire lifetime and reads every record value inline, so
    /// when `f` blocks on a slow consumer the guard stays pinned and
    /// concurrent BGP/BMP churn garbage cannot be reclaimed — peak RSS then
    /// tracks `churn_rate × walk_wall_time` (unbounded for a trickling
    /// client). To avoid that, this method:
    ///
    /// 1. enumerates just the prefix *keys* up front via the guard-free
    ///    `prefixes_keys_iter` (bounded by table size, not path count); then
    /// 2. for each [`DUMP_KEY_CHUNK`]-sized chunk of keys, fetches that
    ///    chunk's records into an owned batch — each `get_records_for_prefix`
    ///    pins its OWN short-lived guard — and emits the batch to `f` with
    ///    **no** guard held at all.
    ///
    /// Because no guard is ever live across a (potentially blocking) call into
    /// `f`, a slow or stalled consumer can no longer pin churn garbage.
    ///
    /// As the walk is no longer a point-in-time snapshot, a prefix withdrawn
    /// between key enumeration and record fetch is simply skipped, and updates
    /// landing mid-walk may or may not appear — acceptable for a dump, and no
    /// weaker than the previous "essentially unordered" iterator under
    /// concurrent mutation.
    ///
    /// A [`DUMP_MAX_DURATION`] wall-clock backstop stops a pathologically long
    /// dump early (logged; partial count returned).
    pub fn stream_prefix_records<F>(
        &self,
        mut f: F,
    ) -> Result<usize, String>
    where
        F: FnMut(PrefixRecord<RotondaPaMap>) -> bool,
    {
        let store = (*self.unicast)
            .as_ref()
            .ok_or(PrefixStoreError::StoreNotReadyError.to_string())?;

        // Phase A: enumerate keys only (no epoch guard, no record reads).
        let keys: Vec<Prefix> = store.prefixes_keys_iter().collect();

        // Phase B: fetch + emit in bounded chunks, never holding a guard
        // across `f`.
        let deadline = Instant::now() + DUMP_MAX_DURATION;
        let mut count = 0usize;
        let mut deadline_hit = false;
        'outer: for chunk in keys.chunks(DUMP_KEY_CHUNK) {
            let mut batch: Vec<PrefixRecord<RotondaPaMap>> =
                Vec::with_capacity(chunk.len());
            for &prefix in chunk {
                // include_withdrawn=true mirrors the legacy get_value(true);
                // the retain below then drops Withdrawn (incl. globally
                // withdrawn muis), keeping Active + InActive exactly as before.
                if let Ok(Some(mut meta)) =
                    store.get_records_for_prefix(&prefix, None, true)
                {
                    meta.retain(|r| r.status != RouteStatus::Withdrawn);
                    if !meta.is_empty() {
                        batch.push(PrefixRecord::new(prefix, meta));
                    }
                }
                // Ok(None)/Err: prefix withdrawn or unreadable since Phase A —
                // skip (best-effort dump snapshot).
            }

            // Emit with NO guard held: f may block on slow network I/O.
            for pr in batch {
                count += 1;
                if !f(pr) {
                    break 'outer;
                }
            }

            if Instant::now() >= deadline {
                deadline_hit = true;
                break;
            }
        }

        if deadline_hit {
            warn!(
                "rib::stream_prefix_records: dump deadline ({}s) reached \
                 after {count} records; emitting partial RIB",
                DUMP_MAX_DURATION.as_secs()
            );
        }
        debug!("rib::stream_prefix_records: {count} prefix records");
        Ok(count)
    }

    /// FlowSpec twin of [`stream_prefix_records`](Self::stream_prefix_records):
    /// stream the flowspec store's records (whole rule-sets per
    /// `(key-prefix, mui)`) to `f`, guard-free and chunked, Withdrawn
    /// filtered. Same deadline budget; volumes are tiny compared to the
    /// unicast table so this walk adds negligible dump time.
    pub fn stream_flowspec_records<F>(
        &self,
        mut f: F,
    ) -> Result<usize, String>
    where
        F: FnMut(PrefixRecord<FlowSpecRuleSet>) -> bool,
    {
        let store = (*self.flowspec)
            .as_ref()
            .ok_or(PrefixStoreError::StoreNotReadyError.to_string())?;

        let keys: Vec<Prefix> = store.prefixes_keys_iter().collect();

        let deadline = Instant::now() + DUMP_MAX_DURATION;
        let mut count = 0usize;
        'outer: for chunk in keys.chunks(DUMP_KEY_CHUNK) {
            let mut batch: Vec<PrefixRecord<FlowSpecRuleSet>> =
                Vec::with_capacity(chunk.len());
            for &prefix in chunk {
                if let Ok(Some(mut meta)) =
                    store.get_records_for_prefix(&prefix, None, true)
                {
                    meta.retain(|r| {
                        r.status != RouteStatus::Withdrawn
                            && !r.meta.is_empty()
                    });
                    if !meta.is_empty() {
                        batch.push(PrefixRecord::new(prefix, meta));
                    }
                }
            }

            for pr in batch {
                count += 1;
                if !f(pr) {
                    break 'outer;
                }
            }

            if Instant::now() >= deadline {
                warn!(
                    "rib::stream_flowspec_records: dump deadline reached \
                     after {count} records; emitting partial table"
                );
                break;
            }
        }
        debug!("rib::stream_flowspec_records: {count} records");
        Ok(count)
    }

    /// Decoded flowspec rows for the HTTP API. `prefix == None` lists the
    /// whole table of the given family; `Some(prefix)` returns the rules
    /// keyed at that prefix, plus less- and/or more-specific keys when
    /// requested (a rule keyed at the family default route — no usable
    /// dst-prefix — is a less-specific of everything).
    pub fn query_flowspec(
        &self,
        family_v4: bool,
        prefix: Option<Prefix>,
        include_less_specifics: bool,
        include_more_specifics: bool,
        ingress_id: Option<IngressId>,
        limits: Option<(usize, usize)>,
    ) -> Result<Vec<FlowSpecQueryRow>, String> {
        let store = (*self.flowspec)
            .as_ref()
            .ok_or(PrefixStoreError::StoreNotReadyError.to_string())?;

        let mut rows: Vec<FlowSpecQueryRow> = Vec::new();
        let mut raw_bytes = 0usize;
        let mut push_records =
            |rows: &mut Vec<FlowSpecQueryRow>,
             key: Prefix,
             records: Vec<Record<FlowSpecRuleSet>>|
             -> Result<(), String> {
                for r in records {
                    if r.status == RouteStatus::Withdrawn {
                        continue;
                    }
                    if let Some(want) = ingress_id {
                        if r.multi_uniq_id != want {
                            continue;
                        }
                    }
                    for rule in r.meta.iter() {
                        if let Some((max_rows, max_raw_bytes)) = limits {
                            let rule_bytes = rule
                                .nlri
                                .len()
                                .saturating_add(rule.pamap.as_ref().len());
                            if rows.len() >= max_rows
                                || raw_bytes.saturating_add(rule_bytes)
                                    > max_raw_bytes
                            {
                                return Err(format!(
                                    "FlowSpec query exceeds the response limit \
                                     ({max_rows} rules or {max_raw_bytes} raw bytes)"
                                ));
                            }
                            raw_bytes += rule_bytes;
                        }
                        rows.push(FlowSpecQueryRow {
                            key_prefix: key,
                            ingress_id: r.multi_uniq_id,
                            rule: rule.clone(),
                        });
                    }
                }
                Ok(())
            };

        match prefix {
            None => {
                let keys: Vec<Prefix> = if family_v4 {
                    store.prefixes_keys_iter_v4().collect()
                } else {
                    store.prefixes_keys_iter_v6().collect()
                };
                for key in keys {
                    if let Ok(Some(records)) =
                        store.get_records_for_prefix(&key, None, false)
                    {
                        push_records(&mut rows, key, records)?;
                    }
                }
            }
            Some(prefix) => {
                let guard = &epoch::pin();
                let match_options = MatchOptions {
                    match_type: rotonda_store::match_options::MatchType::ExactMatch,
                    include_withdrawn: false,
                    include_less_specifics,
                    include_more_specifics,
                    mui: ingress_id,
                    include_history:
                        rotonda_store::match_options::IncludeHistory::None,
                };
                let res = store
                    .match_prefix(&prefix, &match_options, guard)
                    .map_err(|e| e.to_string())?;
                if let Some(key) = res.prefix {
                    push_records(&mut rows, key, res.records)?;
                }
                for set in [res.less_specifics, res.more_specifics]
                    .into_iter()
                    .flatten()
                {
                    for pr in set.iter() {
                        push_records(
                            &mut rows,
                            pr.prefix,
                            pr.meta.clone(),
                        )?;
                    }
                }
            }
        }

        // Validation depends on destination prefix and BGP originator, not on
        // the rule's remaining traffic-match components. Refresh only the
        // rows being returned and share the result among rules with the same
        // (key, originator). This keeps all revalidation off the unicast
        // ingest hot path and bounds work to one lookup per distinct pair in
        // the query.
        let mut validity_cache: HashMap<
            (Prefix, FlowSpecOriginator),
            FlowSpecValidity,
        > = HashMap::new();
        for row in &mut rows {
            let flow_originator =
                self.flowspec_identity(&row.rule.pamap, row.ingress_id).0;
            let cache_key = (row.key_prefix, flow_originator);
            let validity = *validity_cache.entry(cache_key).or_insert_with(|| {
                self.validate_flowspec(
                    &row.rule.nlri,
                    flow_originator,
                    family_v4,
                )
            });
            row.rule.validity = validity;
        }
        Ok(rows)
    }

    pub fn match_ingress_id(
        &self,
        ingress_id: IngressId,
        //match_options: &MatchOptions,
    ) -> Result<Vec<PrefixRecord<RotondaPaMap>>, String> {
        let guard = &epoch::pin();
        let store = (*self.unicast)
            .as_ref()
            .ok_or(PrefixStoreError::StoreNotReadyError.to_string())?;

        let include_withdrawals = false;

        let mut res = store
            .iter_records_for_mui_v4(ingress_id, include_withdrawals, guard)
            .collect::<FatalResult<Vec<_>>>()
            .map_err(|e| e.to_string())?;
        res.append(
            &mut store
                .iter_records_for_mui_v6(
                    ingress_id,
                    include_withdrawals,
                    guard,
                )
                .collect::<FatalResult<Vec<_>>>()
                .map_err(|e| e.to_string())?,
        );

        //tmp: while the per mui methods do not work yet, we can use
        //.prefixes_iter() to test the output.
        //let res = store.prefixes_iter().collect::<Vec<_>>();
        debug!(
            "rib::match_ingress_id for {ingress_id}: {} results",
            res.len()
        );
        Ok(res)
    }

    //
    // new methods returning results to be used by both HTTP API and CLI, i.e. types that will need
    // impls for ToJson and ToCli so they can be impl OutputFormat
    //
    // For now, all these new methods are prefixed search_
    //

    /// Query the Store for routes based on Nlri/prefix
    pub fn search_routes(
        &self,
        afisafi: AfiSafiType,
        //nlri: Nlri<&[u8]>,
        nlri: Prefix, // change to Nlri or equivalent after routecore refactor
        filter: QueryFilter,
        //) -> Result<QueryResult<RotondaPaMap>, String> {
    ) -> Result<SearchResult, String> {
        let guard = &epoch::pin();

        let store = match afisafi {
            AfiSafiType::Ipv4Unicast | AfiSafiType::Ipv6Unicast => (*self
                .unicast)
                .as_ref()
                .ok_or(PrefixStoreError::StoreNotReadyError.to_string())?,
            AfiSafiType::Ipv4Multicast | AfiSafiType::Ipv6Multicast => {
                (*self.multicast)
                    .as_ref()
                    .ok_or(PrefixStoreError::StoreNotReadyError.to_string())?
            }
            u => {
                return Err(format!("address family {u} unsupported"));
            }
        };

        let match_options = &MatchOptions {
            match_type: rotonda_store::match_options::MatchType::ExactMatch,
            include_withdrawn: false,
            include_less_specifics: filter
                .include
                .contains(&Include::LessSpecifics),
            include_more_specifics: filter
                .include
                .contains(&Include::MoreSpecifics),
            mui: filter.ingress_id,
            include_history:
                rotonda_store::match_options::IncludeHistory::None,
        };

        debug!("match_options.mui: {:?}", match_options.mui);

        let t0 = std::time::Instant::now();
        let mut res = store
            .match_prefix(&nlri, match_options, guard)
            .map(|res| {
                SearchResult::new(
                    res,
                    self.ingress_register.clone(),
                    filter.clone(),
                )
            })
            .map_err(|err| err.to_string());

        // filter on:
        // X origin asn
        // X peer rib type
        // X ingress_id -> done via Store.match_prefix already
        // X otc
        //
        // - community
        // - large community
        // - peer distinguisher

        debug!(
            "store lookup took {:?}",
            std::time::Instant::now().duration_since(t0)
        );

        // Find the roto function from the compiled Roto Package.
        // We do this here, once, to reduce acquiring locks and such over and over.
        // If the query contains a filter name for which no roto function exists, this simply
        // filters as if no filter was passed:

        //let maybe_roto_function: Option<RotoHttpFilter> = filter.roto_function.as_ref().and_then(|name| {
        //    self.roto_package.as_ref().and_then(|package| {
        //        let mut package = package.lock().unwrap();
        //        package.get_function(name.as_str()).ok()
        //    })
        //});

        // Alternatively, we could return an error:
        let maybe_roto_function: Option<RotoHttpFilter> = match filter
            .roto_function
            .as_ref()
        {
            Some(name) => {
                debug!("looking up {name} in compiled roto package");
                if let Some(f) =
                    self.roto_package.as_ref().and_then(|package| {
                        let mut package = package.lock().unwrap();
                        package.get_function(name.as_str()).ok()
                    })
                {
                    Some(f)
                } else {
                    error!("query for undefined roto filter");
                    return Err(format!("no roto function '{name}' defined"));
                }
            }
            None => None,
        };

        let t0 = std::time::Instant::now();

        let _ = res.as_mut().map(|sr| {
            self.apply_filter(
                &mut sr.query_result.records,
                &filter,
                maybe_roto_function.clone(),
                &sr.ingress_info,
            );
            if let Some(rs) = sr.query_result.more_specifics.as_mut() {
                rs.v4.retain_mut(|pr| {
                    self.apply_filter(
                        &mut pr.meta,
                        &filter,
                        maybe_roto_function.clone(),
                        &sr.ingress_info,
                    );
                    !pr.meta.is_empty()
                });
                rs.v6.retain_mut(|pr| {
                    self.apply_filter(
                        &mut pr.meta,
                        &filter,
                        maybe_roto_function.clone(),
                        &sr.ingress_info,
                    );
                    !pr.meta.is_empty()
                });
            }
            if let Some(rs) = sr.query_result.less_specifics.as_mut() {
                rs.v4.retain_mut(|pr| {
                    self.apply_filter(
                        &mut pr.meta,
                        &filter,
                        maybe_roto_function.clone(),
                        &sr.ingress_info,
                    );
                    !pr.meta.is_empty()
                });
                rs.v6.retain_mut(|pr| {
                    self.apply_filter(
                        &mut pr.meta,
                        &filter,
                        maybe_roto_function.clone(),
                        &sr.ingress_info,
                    );
                    !pr.meta.is_empty()
                });
            }
        });

        debug!(
            "filtering took {:?}",
            std::time::Instant::now().duration_since(t0)
        );

        res
    }

    // XXX:
    // if the results from the store are already filtered on a MUI/ingress_id, we do not need to
    // query the ingress register over and over to fetch info like peer_rib_type
    // In such case, we could optimize:
    //  - fetch the required info once, pass it into apply_filter
    //  - in apply_filter, check for such info and branch: if let Some(passed_info), etc

    fn apply_filter(
        &self,
        records: &mut Vec<Record<RotondaPaMap>>,
        filter: &QueryFilter,
        roto_filter: Option<RotoHttpFilter>,
        ingress_info: &HashMap<IngressId, IngressInfo>,
    ) {
        if let Some(ingress_id) = filter.ingress_id {
            records.retain(|r| r.multi_uniq_id == ingress_id);
        }

        if let Some(rib_type) = filter.rib_type {
            records.retain(|r| {
                ingress_info
                    .get(&r.multi_uniq_id)
                    .map(|ii| ii.peer_rib_type == Some(rib_type))
                    .unwrap_or(true)
            });
        }

        if let Some(peer_asn) = filter.peer_asn {
            records.retain(|r| {
                ingress_info
                    .get(&r.multi_uniq_id)
                    .map(|ii| ii.remote_asn == Some(peer_asn))
                    .unwrap_or(true)
            });
        }

        if let Some(peer_addr) = filter.peer_addr {
            records.retain(|r| {
                ingress_info
                    .get(&r.multi_uniq_id)
                    .map(|ii| ii.remote_addr == Some(peer_addr))
                    .unwrap_or(true)
            });
        }

        if let Some(f) = roto_filter {
            let mut ctx = self.roto_context.lock().unwrap();
            records.retain_mut(|r| {
                let rc_r: crate::roto_runtime::RcRotondaPaMap =
                    std::mem::take(&mut r.meta).into();
                match f.call(&mut ctx, roto::Val(rc_r.clone())) {
                    roto::Verdict::Accept(_) => {
                        r.meta = std::rc::Rc::into_inner(rc_r).unwrap();
                        true
                    }
                    roto::Verdict::Reject(_) => {
                        //debug!("in Reject for {}", roto_function);
                        false
                    }
                }
            });
        }

        if filter.origin_asn.is_some()
            || filter.otc.is_some()
            || filter.community.is_some()
            || filter.large_community.is_some()
            || filter.rov_status.is_some()
        {
            records.retain(|r| {
                if let Some(rov_status) = filter.rov_status {
                    if r.meta.rpki_info().rov_status() != rov_status {
                        return false
                    }
                }
                let path_attributes = r.meta.path_attributes();
                if let Some(otc) = filter.otc {
                    if Some(otc) != path_attributes.get::<Otc>().map(|otc| otc.0) {
                        return false
                    }
                }
                if let Some(large_community) = filter.large_community {
                    if let Some(list) = path_attributes.get::<routecore::bgp::path_attributes::LargeCommunitiesList>() {
                        if !list.communities().contains(&large_community) {
                            return false
                        }
                    } else {
                        return false
                    }
                }
                if let Some(community) = filter.community {
                    if let Some(list) = path_attributes.get::<routecore::bgp::message::update_builder::StandardCommunitiesList>() {
                        if !list.communities().contains(&community) {
                            return false
                        }
                    } else {
                        return false
                    }
                }
                if let Some(origin_asn) = filter.origin_asn {
                    if Some(origin_asn) != path_attributes.get::<HopPath>().and_then(|hp|
                        hp.origin().and_then(|hop| hop.clone().try_into().ok())
                    ) {
                        return false;
                    }
                }
                true
            });

            // TODO:
            // - communities
            // - large communities
            // - route distinguisher
        }
    }

    pub fn search_and_output_routes<T>(
        &self,
        mut target: T,
        afisafi: AfiSafiType,
        //nlri: Nlri<&[u8]>,
        nlri: Prefix, // change to Nlri or equivalent after routecore refactor
        filter: QueryFilter,
    ) -> Result<(), String>
    where
        SearchResult: GenOutput<T>,
    {
        match self.search_routes(afisafi, nlri, filter) {
            Ok(search_results) => {
                let _ = search_results.write(&mut target);
            }
            Err(e) => {
                error!("error in search_and_output_routes: {e}");
                return Err(format!("store error: {e}"));
            }
        }

        Ok(())
    }

    pub fn check_filter_and_store(
        &self,
        afisafi: AfiSafiType,
        filter: &QueryFilter,
    ) -> Result<(), String> {
        match afisafi {
            AfiSafiType::Ipv4Unicast | AfiSafiType::Ipv6Unicast => {
                if self.unicast.as_ref().is_none() {
                    return Err("Store not ready".to_string());
                }
            }
            AfiSafiType::Ipv4Multicast | AfiSafiType::Ipv6Multicast => {
                if self.multicast.as_ref().is_none() {
                    return Err("Store not ready".to_string());
                }
            }
            u => {
                return Err(format!("address family {u} unsupported"));
            }
        }

        if let Some(name) = filter.roto_function.as_ref() {
            let exists =
                self.roto_package.as_ref().map_or(false, |package| {
                    let mut package = package.lock().unwrap();
                    let res: Result<RotoHttpFilter, _> =
                        package.get_function(name.as_str());
                    res.is_ok()
                });
            if !exists {
                return Err(format!("no roto function '{name}' defined"));
            }
        }

        Ok(())
    }

    pub fn write_jsonl_stream<W: std::io::Write>(
        &self,
        afisafi: AfiSafiType,
        query_prefix: Prefix,
        filter: QueryFilter,
        target: &mut W,
    ) -> Result<(), crate::representation::OutputError> {
        // Full-RIB dumps hold an epoch guard across the whole walk, which
        // pins concurrent withdraw/insert garbage in the store until the
        // walk completes. Log entry+exit so heavy dumps are attributable
        // when RSS spikes correlate with HTTP activity.
        let dump_start = std::time::Instant::now();
        let ingress_filter = filter.ingress_id;
        let has_roto = filter.roto_function.is_some();
        info!(
            "rib dump start: afisafi={afisafi} query_prefix={query_prefix} \
             ingress_filter={ingress_filter:?} has_roto={has_roto}"
        );
        let mut prefixes_scanned: u64 = 0;
        let mut prefixes_emitted: u64 = 0;
        let mut records_emitted: u64 = 0;

        let res = self.write_jsonl_stream_inner(
            afisafi,
            query_prefix,
            filter,
            target,
            &mut prefixes_scanned,
            &mut prefixes_emitted,
            &mut records_emitted,
        );

        let elapsed = dump_start.elapsed();
        let outcome = match &res {
            Ok(_) => "ok",
            Err(_) => "err",
        };
        // Warn on dumps that hold the epoch guard long enough to matter
        // for reclamation latency; info otherwise.
        let log_msg = format!(
            "rib dump end: afisafi={afisafi} outcome={outcome} \
             elapsed_ms={} prefixes_scanned={prefixes_scanned} \
             prefixes_emitted={prefixes_emitted} records_emitted={records_emitted}",
            elapsed.as_millis()
        );
        if elapsed >= std::time::Duration::from_secs(2) {
            warn!("{log_msg}");
        } else {
            info!("{log_msg}");
        }
        res
    }

    fn write_jsonl_stream_inner<W: std::io::Write>(
        &self,
        afisafi: AfiSafiType,
        query_prefix: Prefix,
        filter: QueryFilter,
        target: &mut W,
        prefixes_scanned: &mut u64,
        prefixes_emitted: &mut u64,
        records_emitted: &mut u64,
    ) -> Result<(), crate::representation::OutputError> {
        let store = match afisafi {
            AfiSafiType::Ipv4Unicast | AfiSafiType::Ipv6Unicast => {
                (*self.unicast).as_ref().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Store not ready",
                    )
                })?
            }
            AfiSafiType::Ipv4Multicast | AfiSafiType::Ipv6Multicast => {
                (*self.multicast).as_ref().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Store not ready",
                    )
                })?
            }
            u => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("address family {u} unsupported"),
                )
                .into());
            }
        };

        let ingress_info = self.ingress_register.cloned_info();

        let maybe_roto_function: Option<RotoHttpFilter> =
            match filter.roto_function.as_ref() {
                Some(name) => {
                    if let Some(f) =
                        self.roto_package.as_ref().and_then(|package| {
                            let mut package = package.lock().unwrap();
                            package.get_function(name.as_str()).ok()
                        })
                    {
                        Some(f)
                    } else {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("no roto function '{name}' defined"),
                        )
                        .into());
                    }
                }
                None => None,
            };

        // Determine if we iterate over IPv4 or IPv6, then enumerate that
        // family's prefix *keys* only (guard-free) — so no epoch guard is held
        // across the network-paced serialization below. The HTTP jsonl client
        // may drain at a trickle (or stall), and the previous
        // `prefixes_iter_v4/_v6(&guard)` walk pinned one guard for the whole
        // emission, making concurrent churn garbage unreclaimable. See
        // `stream_prefix_records` for the full rationale.
        let is_v4 = query_prefix.is_v4();
        let keys: Vec<Prefix> = if is_v4 {
            store.prefixes_keys_iter_v4().collect()
        } else {
            store.prefixes_keys_iter_v6().collect()
        };

        let deadline = Instant::now() + DUMP_MAX_DURATION;

        for chunk in keys.chunks(DUMP_KEY_CHUNK) {
            // Materialise this chunk's records under short-lived per-prefix
            // guards (get_records_for_prefix pins its own guard). Fetch with
            // include_withdrawn=true to match the legacy get_value(true) input;
            // the emit loop applies the same retain(!Withdrawn) as before.
            let mut batch: Vec<PrefixRecord<RotondaPaMap>> =
                Vec::with_capacity(chunk.len());
            for &prefix in chunk {
                match store.get_records_for_prefix(&prefix, None, true) {
                    Ok(Some(meta)) => {
                        batch.push(PrefixRecord::new(prefix, meta))
                    }
                    // Empty-default to preserve the legacy scanned-count for a
                    // prefix that has no live records.
                    Ok(None) => {
                        batch.push(PrefixRecord::new(prefix, Vec::new()))
                    }
                    Err(_) => {}
                }
            }

            // Emit the batch with NO epoch guard held: serde_json::to_writer
            // and target.write_all may block on a slow HTTP client.
            for mut pr in batch {
                *prefixes_scanned += 1;

                // 1. Filter out withdrawn records
                pr.meta.retain(|r| r.status != RouteStatus::Withdrawn);
                if pr.meta.is_empty() {
                    continue;
                }

                // 2. Apply standard filters in place
                self.apply_filter(
                    &mut pr.meta,
                    &filter,
                    maybe_roto_function.clone(),
                    &ingress_info,
                );
                if pr.meta.is_empty() {
                    continue;
                }

                *prefixes_emitted += 1;

                // Determine if the prefix is the query prefix itself
                let section = if pr.prefix == query_prefix {
                    "data"
                } else {
                    "moreSpecifics"
                };

                for record in &pr.meta {
                    *records_emitted += 1;
                    let ingress = ingress_info
                        .get(&record.multi_uniq_id)
                        .map(|info| (record.multi_uniq_id, info).into());
                    let source = RouteSource::resolve(
                        record.multi_uniq_id,
                        ingress_info.get(&record.multi_uniq_id),
                    );
                    let status = RouteStatusWrapper(record.status);

                    if filter.fields_path_attributes.is_some() {
                        let line = JsonlLineFiltered {
                            prefix: pr.prefix,
                            section,
                            status,
                            ingress,
                            source,
                            pamap: RotondaPaMapWithQueryFilter(
                                &record.meta,
                                &filter,
                            ),
                        };
                        serde_json::to_writer(&mut *target, &line)?;
                    } else {
                        let line = JsonlLine {
                            prefix: pr.prefix,
                            section,
                            status,
                            ingress,
                            source,
                            pamap: &record.meta,
                        };
                        serde_json::to_writer(&mut *target, &line)?;
                    }
                    target.write_all(b"\n")?;
                }
            }

            if Instant::now() >= deadline {
                warn!(
                    "rib dump: deadline ({}s) reached after {} prefixes; \
                     emitting partial RIB",
                    DUMP_MAX_DURATION.as_secs(),
                    *prefixes_emitted
                );
                break;
            }
        }

        Ok(())
    }

    /// Query the store based on `IngressId`/MUI
    pub fn search_routes_for_ingress(
        _afisafi: AfiSafiType,
        _nlri: Nlri<&[u8]>,
        _ingress_id: IngressId,
        _match_options: MatchOptions,
    ) -> Result<SearchResult, String> {
        todo!()
    }

    /// Query the store based on Origin AS in the AS_PATH
    pub fn search_routes_for_origin_as(
        _afisafi: AfiSafiType,
        _origin_as: Asn,
        _match_options: MatchOptions,
    ) -> Result<SearchResult, String> {
        todo!()
    }
}

/// Wrapper around `QueryResult` from rotonda-store
///
/// This wrapper is used to impl the necessary traits on, to enable consistent representation
/// between CLI, HTTP API, etc.
pub struct SearchResult {
    pub(crate) query_result: QueryResult<RotondaPaMap>,
    pub(crate) ingress_info: HashMap<IngressId, IngressInfo>,
    query_filter: QueryFilter,
}

/// Stable public identity for the source of a route.
///
/// ADD-PATH records use a child ingress as their store MUI. API consumers,
/// however, need the owning session and the path ID scoped to that session;
/// the child ID is retained as an explicit implementation/debug identifier.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RouteSource {
    pub ingress_id: IngressId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal_path_ingress_id: Option<IngressId>,
}

impl RouteSource {
    pub(crate) fn resolve(
        record_ingress_id: IngressId,
        info: Option<&IngressInfo>,
    ) -> Self {
        if matches!(
            info.and_then(|info| info.ingress_type.as_ref()),
            Some(ingress::IngressType::BgpPath)
        ) {
            Self {
                ingress_id: info
                    .and_then(|info| info.parent_ingress)
                    .unwrap_or(record_ingress_id),
                path_id: info.and_then(|info| info.path_id),
                internal_path_ingress_id: Some(record_ingress_id),
            }
        } else {
            Self {
                ingress_id: record_ingress_id,
                path_id: None,
                internal_path_ingress_id: None,
            }
        }
    }
}

crate::genoutput_json!(SearchResult);

impl SearchResult {
    fn new(
        query_result: QueryResult<RotondaPaMap>,
        ingress_register: Arc<ingress::Register>,
        query_filter: QueryFilter,
    ) -> Self {
        Self {
            query_result,
            ingress_info: ingress_register.cloned_info(),
            query_filter,
        }
    }

    pub(crate) fn ingress_info(
        &self,
        ingress_id: IngressId,
    ) -> Option<&IngressInfo> {
        self.ingress_info.get(&ingress_id)
    }

    pub fn query_filter(&self) -> &QueryFilter {
        &self.query_filter
    }

    fn id_and_info(&self, ingress_id: IngressId) -> Option<IdAndInfo<'_>> {
        self.ingress_info
            .get(&ingress_id)
            .map(|info| (ingress_id, info).into())
    }

    fn route_source(&self, ingress_id: IngressId) -> RouteSource {
        RouteSource::resolve(ingress_id, self.ingress_info.get(&ingress_id))
    }

    /// Write one JSON object per line (NDJSON / JSONL).
    ///
    /// Each line is a flat record uniquely identified by (prefix, ingressId).
    /// A `section` field marks whether the line came from the matched prefix
    /// itself or from the more-/less-specifics include sets, so no data is
    /// lost relative to the nested JSON shape.
    pub fn write_jsonl<W: std::io::Write>(
        &self,
        target: &mut W,
    ) -> Result<(), crate::representation::OutputError> {
        if let Some(prefix) = self.query_result.prefix {
            for record in &self.query_result.records {
                self.write_jsonl_line(target, prefix, record, "data")?;
            }
        }
        if let Some(set) = self.query_result.more_specifics.as_ref() {
            self.write_jsonl_recordset(target, set, "moreSpecifics")?;
        }
        if let Some(set) = self.query_result.less_specifics.as_ref() {
            self.write_jsonl_recordset(target, set, "lessSpecifics")?;
        }
        Ok(())
    }

    fn write_jsonl_recordset<W: std::io::Write>(
        &self,
        target: &mut W,
        set: &RecordSet<RotondaPaMap>,
        section: &'static str,
    ) -> Result<(), crate::representation::OutputError> {
        for pr in set.v4.iter().chain(set.v6.iter()) {
            for record in &pr.meta {
                self.write_jsonl_line(target, pr.prefix, record, section)?;
            }
        }
        Ok(())
    }

    fn write_jsonl_line<W: std::io::Write>(
        &self,
        target: &mut W,
        prefix: Prefix,
        record: &Record<RotondaPaMap>,
        section: &'static str,
    ) -> Result<(), crate::representation::OutputError> {
        let query_filter = &self.query_filter;
        let ingress = self.id_and_info(record.multi_uniq_id);
        let status = RouteStatusWrapper(record.status);
        if query_filter.fields_path_attributes.is_some() {
            let line = JsonlLineFiltered {
                prefix,
                section,
                status,
                ingress,
                source: self.route_source(record.multi_uniq_id),
                pamap: RotondaPaMapWithQueryFilter(
                    &record.meta,
                    query_filter,
                ),
            };
            serde_json::to_writer(&mut *target, &line)?;
        } else {
            let line = JsonlLine {
                prefix,
                section,
                status,
                ingress,
                source: self.route_source(record.multi_uniq_id),
                pamap: &record.meta,
            };
            serde_json::to_writer(&mut *target, &line)?;
        }
        target.write_all(b"\n")?;
        Ok(())
    }
}

#[derive(Serialize)]
struct JsonlLine<'a, 'b> {
    prefix: Prefix,
    section: &'static str,
    status: RouteStatusWrapper,
    #[serde(skip_serializing_if = "Option::is_none")]
    ingress: Option<IdAndInfo<'b>>,
    source: RouteSource,
    #[serde(flatten)]
    pamap: &'a RotondaPaMap,
}

#[derive(Serialize)]
struct JsonlLineFiltered<'a, 'b, 'c> {
    prefix: Prefix,
    section: &'static str,
    status: RouteStatusWrapper,
    #[serde(skip_serializing_if = "Option::is_none")]
    ingress: Option<IdAndInfo<'b>>,
    source: RouteSource,
    #[serde(flatten)]
    pamap: RotondaPaMapWithQueryFilter<'a, 'c>,
}

impl Serialize for SearchResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // TODO:
        // - ingress data (include in Arc<Register> in SearchResults wrapper?
        // X rpki rov status
        // X route status
        // - path attributes
        //      X first go based on existing Serialize impl
        //      - have a good look on what we did vs what we now think is best
        //      - especially communities:
        //          - old style was 241M vs ~90M for the 25M raw BMP input data
        //          - can we provide multiple 'styles' of output (via some query param), e.g.
        //              - the old, very verbose one,
        //              - one with Martin Pels' draft applied
        //
        //
        //
        // - includes:
        //  X more specifics
        //  X less specifics
        //  - lpm?
        //
        //  XXX: old format returned "data": [] (i.e. an array) so the matching prefix/nlri was
        //  repeated $n times.
        //  is that correct? shouldn't it be:
        //      "data": {
        //          "nlri": $some_nlri,
        //          "routes": [ ... ]
        //      },
        //      "included": ...
        //
        // the good thing about that repetition though is, that when including routes for more/less
        // specifics in the "included" section, we can follow the exact same structure?
        //
        //  XXX json:api states "included" is an _array_ where we returned a object before
        //  perhaps go with
        //
        //      "included": [
        //          {
        //              "include_type": "moreSpecifics",
        //                  "data": {
        //                      "nlri": $some_nlri,
        //                      "routes": [ { .. }, .. ]
        //                  }
        //          },
        //          {
        //              "include_type": "lessSpecifics",
        //                  "data": {
        //                      "nlri": $some_nlri,
        //                      "routes": [ { .. }, .. ]
        //                  }
        //          }
        //      ]
        //
        //
        //
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct IncludedData<'a, 'b> {
            #[serde(skip_serializing_if = "Option::is_none")]
            more_specifics: Option<RecordSetWrapper<'a, 'b>>,
            #[serde(skip_serializing_if = "Option::is_none")]
            less_specifics: Option<RecordSetWrapper<'a, 'b>>,
        }

        let mut root = serializer.serialize_struct("nlri", 3)?;
        // TODO meta:
        // - routes pre filtering
        // - routes post filtering (== returned items)
        // - time to get from store
        // - time to serialize to json? (is that possible? or should meta then be at the end of the
        //   response perhaps?)
        root.serialize_field("meta", &None::<String>)?;
        root.serialize_field(
            "data",
            &Data {
                nlri: self.query_result.prefix,
                routes: RecordsWrapper(&self.query_result.records, self),
            },
        )?;

        root.serialize_field(
            "included",
            &IncludedData {
                more_specifics: self
                    .query_result
                    .more_specifics
                    .as_ref()
                    .map(|s| RecordSetWrapper(s, self)),
                less_specifics: self
                    .query_result
                    .less_specifics
                    .as_ref()
                    .map(|s| RecordSetWrapper(s, self)),
            },
        )?;
        root.end()
    }
}

#[derive(Serialize)]
struct Data<'a, 'b> {
    nlri: Option<Prefix>,
    routes: RecordsWrapper<'a, 'b>,
}

struct RecordsWrapper<'a, 'b>(
    &'a Vec<Record<RotondaPaMap>>,
    &'b SearchResult,
);
struct RecordWrapper<'a, 'b>(&'a Record<RotondaPaMap>, &'b SearchResult);
struct RecordSetWrapper<'a, 'b>(
    &'a RecordSet<RotondaPaMap>,
    &'b SearchResult,
);
struct PrefixRecordWrapper<'a, 'b>(
    &'a PrefixRecord<RotondaPaMap>,
    &'b SearchResult,
);
struct RouteStatusWrapper(RouteStatus);

impl Serialize for RecordsWrapper<'_, '_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for e in self.0.iter() {
            seq.serialize_element(&RecordWrapper(e, self.1))?;
        }
        seq.end()
    }
}

impl Serialize for RecordWrapper<'_, '_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // The RPKI information is stored in the value (so, RotondaPaMap) in the store.
        // The RotondaPaMap serializes to { rpki: {}, pathAttributes: [] },
        // so with serde(flatten) the wrapped store::Record serializes to
        // { status: foo, rpki: bla, pathAttributes: buzz, etc .. }
        // on 'one level'.
        //
        #[derive(Serialize)]
        struct Helper<'a, 'b> {
            status: RouteStatusWrapper,
            ingress: Option<IdAndInfo<'b>>,
            source: RouteSource,
            #[serde(flatten)]
            pamap: &'a RotondaPaMap,
            //pamap: RotondaPaMapWithQueryFilter<'a, 'b>,//(&RotondaPaMap, &self.2),
        }

        #[derive(Serialize)]
        struct HelperWithQueryFilter<'a, 'b, 'c> {
            status: RouteStatusWrapper,
            ingress: Option<IdAndInfo<'b>>,
            source: RouteSource,
            #[serde(flatten)]
            pamap: RotondaPaMapWithQueryFilter<'a, 'c>, //(&RotondaPaMap, &self.2),
        }

        // Possible optimisation: lift this wrapping (and thus branching up) into RecordsWrapper or
        // even SearchResult.
        // Have variants for:
        // - NoPathAttributes, i.e. &fields[pathAttributes]=
        // - FilteredPathAttrbutes, i.e. is_some() && !is_empty()
        // - Default case, not specified, so we only filter out typecodes 14 and 15 (MP
        // REACH/UNREACH) while those are stored. After the refactoring of routecore et al and we
        // are sure 14/15 do not end up in the store, that .filter can be removed completely.
        let query_filter = &self.1.query_filter;
        if query_filter.fields_path_attributes.is_some() {
            HelperWithQueryFilter {
                ingress: self.1.id_and_info(self.0.multi_uniq_id),
                source: self.1.route_source(self.0.multi_uniq_id),
                status: RouteStatusWrapper(self.0.status),
                pamap: RotondaPaMapWithQueryFilter(
                    &self.0.meta,
                    query_filter,
                ),
            }
            .serialize(serializer)
        } else {
            Helper {
                ingress: self.1.id_and_info(self.0.multi_uniq_id),
                source: self.1.route_source(self.0.multi_uniq_id),
                status: RouteStatusWrapper(self.0.status),
                pamap: &self.0.meta,
            }
            .serialize(serializer)
        }
    }
}

impl Serialize for RecordSetWrapper<'_, '_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_seq(Some(self.0.len()))?;
        for e in &self.0.v4 {
            s.serialize_element(&PrefixRecordWrapper(e, self.1))?;
        }
        for e in &self.0.v6 {
            s.serialize_element(&PrefixRecordWrapper(e, self.1))?;
        }
        s.end()
    }
}

impl Serialize for PrefixRecordWrapper<'_, '_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Data {
            nlri: Some(self.0.prefix),
            routes: RecordsWrapper(&self.0.meta, self.1),
        }
        .serialize(serializer)
    }
}

impl Serialize for RouteStatusWrapper {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0 {
            RouteStatus::Active => serializer.serialize_str("active"),
            RouteStatus::InActive => serializer.serialize_str("inactive"),
            RouteStatus::Withdrawn => serializer.serialize_str("withdrawn"),
        }
    }
}

#[derive(Debug)]
pub enum StoreInsertionEffect {
    RoutesWithdrawn(usize),
    #[allow(dead_code)]
    RoutesRemoved(usize),
    RouteAdded,
    RouteUpdated,
}

// --- Tests ----------------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{
        alloc::System, net::IpAddr, ops::Deref, str::FromStr, sync::Arc,
    };

    use inetnum::{addr::Prefix, asn::Asn};
    //use roto::types::{
    //    builtin::{BuiltinTypeValue, NlriStatus, PrefixRoute, RotondaId},
    //    lazyrecord_types::BgpUpdateMessage,
    //    typevalue::TypeValue,
    //};
    use routecore::bgp::{message::SessionConfig, types::AfiSafiType};

    use crate::{
        bgp::encode::{mk_bgp_update, Announcements, Prefixes},
        common::memory::TrackingAllocator,
    };

    use super::*;

    // LH: these do not make much sense anymore with the new prefix store
    // doing all the updating/merging of entries. Adapting does not seem to be
    // worth it, perhaps we redo some of these from scratch?
    /*
    #[test]
    fn empty_by_default() {
        let rib_value = RibValue::default();
        assert!(rib_value.is_empty());
    }

    #[test]
    fn into_new() {
        let rib_value: RibValue =
            PreHashedTypeValue::new(123u8.into(), 18).into();
        assert_eq!(rib_value.len(), 1);
        assert_eq!(
            rib_value.iter().next(),
            Some(&Arc::new(PreHashedTypeValue::new(123u8.into(), 18)))
        );
    }

    #[test]
    fn merging_in_separate_values_yields_two_entries() {
        let settings = StoreEvictionPolicy::UpdateStatusOnWithdraw.into();
        let rib_value = RibValue::default();
        let value_one = PreHashedTypeValue::new(1u8.into(), 1);
        let value_two = PreHashedTypeValue::new(2u8.into(), 2);

        let (rib_value, _user_data) = rib_value
            .clone_merge_update(&value_one.into(), Some(&settings))
            .unwrap();
        assert_eq!(rib_value.len(), 1);

        let (rib_value, _user_data) = rib_value
            .clone_merge_update(&value_two.into(), Some(&settings))
            .unwrap();
        assert_eq!(rib_value.len(), 2);
    }

    #[test]
    fn merging_in_the_same_precomputed_hashcode_yields_one_entry() {
        let settings = StoreEvictionPolicy::UpdateStatusOnWithdraw.into();
        let rib_value = RibValue::default();
        let value_one = PreHashedTypeValue::new(1u8.into(), 1);
        let value_two = PreHashedTypeValue::new(2u8.into(), 1);

        let (rib_value, _user_data) = rib_value
            .clone_merge_update(&value_one.into(), Some(&settings))
            .unwrap();
        assert_eq!(rib_value.len(), 1);

        let (rib_value, _user_data) = rib_value
            .clone_merge_update(&value_two.into(), Some(&settings))
            .unwrap();
        assert_eq!(rib_value.len(), 1);
    }

    #[test]
    fn merging_in_a_withdrawal_updates_matching_entries() {
        // Given route announcements and withdrawals from a couple of peers to a single prefix
        let prefix = Prefix::new("127.0.0.1".parse().unwrap(), 32).unwrap();

        let peer_one = PeerId::new(
            Some(IpAddr::from_str("192.168.0.1").unwrap()),
            Some(Asn::from_u32(123)),
        );
        let peer_two = PeerId::new(
            Some(IpAddr::from_str("192.168.0.2").unwrap()),
            Some(Asn::from_u32(456)),
        );

        let peer_one_announcement_one =
            mk_route_announcement(prefix, "123,456,789", peer_one);
        let peer_one_announcement_two =
            mk_route_announcement(prefix, "123,789", peer_one);
        let peer_two_announcement_one =
            mk_route_announcement(prefix, "456,789", peer_two);
        let peer_one_withdrawal = mk_route_withdrawal(prefix, peer_one);

        let peer_one_announcement_one =
            PreHashedTypeValue::new(peer_one_announcement_one.into(), 1);
        let peer_one_announcement_two =
            PreHashedTypeValue::new(peer_one_announcement_two.into(), 2);
        let peer_two_announcement_one =
            PreHashedTypeValue::new(peer_two_announcement_one.into(), 3);
        let peer_one_withdrawal =
            PreHashedTypeValue::new(peer_one_withdrawal.into(), 4);

        // When merged into a RibValue
        let settings = StoreEvictionPolicy::UpdateStatusOnWithdraw.into();
        let rib_value = RibValue::default();

        // Unique announcements accumulate in the RibValue
        let (rib_value, _user_data) = rib_value
            .clone_merge_update(
                &peer_one_announcement_one.into(),
                Some(&settings),
            )
            .unwrap();
        assert_eq!(rib_value.len(), 1);

        let (rib_value, _user_data) = rib_value
            .clone_merge_update(
                &peer_one_announcement_two.into(),
                Some(&settings),
            )
            .unwrap();
        assert_eq!(rib_value.len(), 2);

        let (rib_value, _user_data) = rib_value
            .clone_merge_update(
                &peer_two_announcement_one.into(),
                Some(&settings),
            )
            .unwrap();
        assert_eq!(rib_value.len(), 3);

        // And a withdrawal by one peer of the prefix which the RibValue represents leaves the RibValue size unchanged
        let (rib_value, _user_data) = rib_value
            .clone_merge_update(
                &peer_one_withdrawal.clone().into(),
                Some(&settings),
            )
            .unwrap();
        assert_eq!(rib_value.len(), 3);

        // And routes from the first peer which were withdrawn are marked as such
        let mut iter = rib_value.iter();
        let first = iter.next();
        assert!(first.is_some());
        let first_ty: &TypeValue = first.unwrap().deref();
        assert!(matches!(
            first_ty,
            TypeValue::Builtin(BuiltinTypeValue::Route(_))
        ));
        if let TypeValue::Builtin(BuiltinTypeValue::Route(route)) = first_ty {
            assert_eq!(route.peer_ip(), Some(peer_one.ip.unwrap()));
            assert_eq!(route.peer_asn(), Some(peer_one.asn.unwrap()));
            assert_eq!(route.status(), NlriStatus::Withdrawn);
        }

        let next = iter.next();
        assert!(next.is_some());
        let next_ty: &TypeValue = next.unwrap().deref();
        assert!(matches!(
            next_ty,
            TypeValue::Builtin(BuiltinTypeValue::Route(_))
        ));
        if let TypeValue::Builtin(BuiltinTypeValue::Route(route)) = next_ty {
            assert_eq!(route.peer_ip(), Some(peer_one.ip.unwrap()));
            assert_eq!(route.peer_asn(), Some(peer_one.asn.unwrap()));
            assert_eq!(route.status(), NlriStatus::Withdrawn);
        }

        // But the route from the second peer remains untouched
        let next = iter.next();
        assert!(next.is_some());
        let next_ty: &TypeValue = next.unwrap().deref();
        assert!(matches!(
            next_ty,
            TypeValue::Builtin(BuiltinTypeValue::Route(_))
        ));
        if let TypeValue::Builtin(BuiltinTypeValue::Route(route)) = next_ty {
            assert_eq!(route.peer_ip(), Some(peer_two.ip.unwrap()));
            assert_eq!(route.peer_asn(), Some(peer_two.asn.unwrap()));
            assert_eq!(route.status(), NlriStatus::InConvergence);
        }

        // And a withdrawal by one peer of the prefix which the RibValue represents, when using the removal eviction
        // policy, causes the two routes from that peer to be removed leaving only one in the RibValue.
        let settings = StoreEvictionPolicy::RemoveOnWithdraw.into();
        let (rib_value, _user_data) = rib_value
            .clone_merge_update(&peer_one_withdrawal.into(), Some(&settings))
            .unwrap();
        assert_eq!(rib_value.len(), 1);
    }

    #[test]
    fn test_route_comparison_using_default_hash_key_values() {
        let rib = HashedRib::default();
        let prefix = Prefix::new("127.0.0.1".parse().unwrap(), 32).unwrap();
        let peer_one = IpAddr::from_str("192.168.0.1").unwrap();
        let peer_two = IpAddr::from_str("192.168.0.2").unwrap();
        let announcement_one_from_peer_one =
            mk_route_announcement(prefix, "123,456", peer_one);
        let announcement_two_from_peer_one =
            mk_route_announcement(prefix, "789,456", peer_one);
        let announcement_one_from_peer_two =
            mk_route_announcement(prefix, "123,456", peer_two);
        let announcement_two_from_peer_two =
            mk_route_announcement(prefix, "789,456", peer_two);

        let hash_code_route_one_peer_one = rib.precompute_hash_code(
            &announcement_one_from_peer_one.clone().into(),
        );
        let hash_code_route_one_peer_one_again =
            rib.precompute_hash_code(&announcement_one_from_peer_one.into());
        let hash_code_route_one_peer_two =
            rib.precompute_hash_code(&announcement_one_from_peer_two.into());
        let hash_code_route_two_peer_one =
            rib.precompute_hash_code(&announcement_two_from_peer_one.into());
        let hash_code_route_two_peer_two =
            rib.precompute_hash_code(&announcement_two_from_peer_two.into());

        // Hashing sanity checks
        assert_ne!(hash_code_route_one_peer_one, 0);
        assert_eq!(
            hash_code_route_one_peer_one,
            hash_code_route_one_peer_one_again
        );

        assert_ne!(
            hash_code_route_one_peer_one, hash_code_route_one_peer_two,
            "Routes that differ only by peer IP should be considered different"
        );
        assert_ne!(
            hash_code_route_two_peer_one, hash_code_route_two_peer_two,
            "Routes that differ only by peer IP should be considered different"
        );
        assert_ne!(
            hash_code_route_one_peer_one, hash_code_route_two_peer_one,
            "Routes that differ only by AS path should be considered different"
        );
        assert_ne!(
            hash_code_route_one_peer_two, hash_code_route_two_peer_two,
            "Routes that differ only by AS path should be considered different"
        );

        // Sanity checks
        assert_eq!(
            hash_code_route_one_peer_one,
            hash_code_route_one_peer_one
        );
        assert_eq!(
            hash_code_route_one_peer_two,
            hash_code_route_one_peer_two
        );
        assert_eq!(
            hash_code_route_two_peer_one,
            hash_code_route_two_peer_one
        );
        assert_eq!(
            hash_code_route_two_peer_two,
            hash_code_route_two_peer_two
        );
    }

    #[test]
    fn test_merge_update_user_data_in_out() {
        const NUM_TEST_ITEMS: usize = 18;

        type TestMap<T> = hashbrown::HashSet<
            T,
            DefaultHashBuilder,
            TrackingAllocator<System>,
        >;

        #[derive(Debug)]
        struct MergeUpdateSettings {
            pub allocator: TrackingAllocator<System>,
            pub num_items_to_insert: usize,
        }

        impl MergeUpdateSettings {
            fn new(
                allocator: TrackingAllocator<System>,
                num_items_to_insert: usize,
            ) -> Self {
                Self {
                    allocator,
                    num_items_to_insert,
                }
            }
        }

        #[derive(Default)]
        struct TestMetaData(TestMap<usize>);

        // Create some settings
        let allocator = TrackingAllocator::default();
        let settings = MergeUpdateSettings::new(allocator, NUM_TEST_ITEMS);

        // Verify that it hasn't allocated anything yet
        assert_eq!(0, settings.allocator.stats().bytes_allocated);

        // Cause the allocator to be used by the merge update
        let meta = TestMetaData::default();
        let update_meta = TestMetaData::default();
        let (updated_meta, _user_data_out) = meta
            .clone_merge_update(&update_meta, Some(&settings))
            .unwrap();

        // Verify that the allocator was used
        assert!(settings.allocator.stats().bytes_allocated > 0);
        assert_eq!(NUM_TEST_ITEMS, updated_meta.0.len());

        // Drop the updated meta and check that no bytes are currently allocated
        drop(updated_meta);
        assert_eq!(0, settings.allocator.stats().bytes_allocated);
    }
    */

    // LH: which then obsoletes these as well

    /*
        fn mk_route_announcement<T: Into<PeerId>>(
            prefix: Prefix,
            as_path: &str,
            peer_id: T,
        ) -> PrefixRoute {
            let delta_id = (RotondaId(0), 0);
            let announcements = Announcements::from_str(&format!(
                "e [{as_path}] 10.0.0.1 BLACKHOLE,123:44 {}",
                prefix
            ))
            .unwrap();
            let bgp_update_bytes =
                mk_bgp_update(&Prefixes::default(), &announcements, &[]);

            // When it is processed by this unit
            let roto_update_msg =
                BgpUpdateMessage::new(bgp_update_bytes, SessionConfig::modern())
                .unwrap();
            let afi_safi = if prefix.is_v4() { AfiSafiType::Ipv4Unicast } else { AfiSafiType::Ipv6Unicast };
            // let bgp_update_msg =
            //     Arc::new(BgpUpdateMessage::new(delta_id, roto_update_msg));
            let mut route = PrefixRoute::new(
                delta_id,
                prefix,
                roto_update_msg,
                afi_safi,
                None,
                NlriStatus::InConvergence,
            );

            let peer_id = peer_id.into();

            if let Some(ip) = peer_id.ip {
                route = route.with_peer_ip(ip);
            }

            if let Some(asn) = peer_id.asn {
                route = route.with_peer_asn(asn);
            }

            route
        }

        fn mk_route_withdrawal(
            prefix: Prefix,
            peer_id: PeerId,
        ) -> MutableBasicRoute {
            let delta_id = (RotondaId(0), 0);
            let bgp_update_bytes = mk_bgp_update(
                &Prefixes::new(vec![prefix]),
                &Announcements::None,
                &[],
            );

            // When it is processed by this unit
            let roto_update_msg =
                BgpUpdateMessage::new(bgp_update_bytes, SessionConfig::modern()).unwrap();
            let afi_safi = if prefix.is_v4() { AfiSafiType::Ipv4Unicast } else { AfiSafiType::Ipv6Unicast };

            let mut route = BasicRoute::new(
                delta_id,
                prefix,
                roto_update_msg,
                afi_safi,
                None,
                NlriStatus::Withdrawn,
            );

            if let Some(ip) = peer_id.ip {
                route = route.with_peer_ip(ip);
            }

            if let Some(asn) = peer_id.asn {
                route = route.with_peer_asn(asn);
            }

            route
        }
    */

    // ------------ FlowSpec store ------------------------------------------

    fn test_rib() -> Rib {
        Rib::new(
            Default::default(),
            None,
            Arc::new(Mutex::new(Ctx::empty())),
        )
        .unwrap()
    }

    /// Wrap raw v4 flowspec component bytes into a RotondaRoute.
    fn mk_flowspec_v4(raw_components: &[u8]) -> RotondaRoute {
        mk_flowspec_v4_with_pamap(
            raw_components,
            RotondaPaMap::empty_path_attributes(),
        )
    }

    fn mk_flowspec_v4_with_pamap(
        raw_components: &[u8],
        pamap: RotondaPaMap,
    ) -> RotondaRoute {
        let mut wire = Vec::with_capacity(raw_components.len() + 1);
        wire.push(u8::try_from(raw_components.len()).unwrap());
        wire.extend_from_slice(raw_components);
        let bytes = bytes::Bytes::from(wire);
        let mut parser = octseq::Parser::from_ref(&bytes);
        let nlri = routecore::bgp::nlri::flowspec::FlowSpecNlri::parse(
            &mut parser,
            routecore::bgp::types::Afi::Ipv4,
        )
        .unwrap();
        RotondaRoute::Ipv4FlowSpec(nlri.into(), pamap)
    }

    fn validation_pamap(originator: [u8; 4], neighbor_asn: u32) -> RotondaPaMap {
        RotondaPaMap::from(vec![
            0x80, 9, 4, originator[0], originator[1], originator[2],
            originator[3], // ORIGINATOR_ID
            0x40, 2, 6, 2, 1, // AS_PATH, one AS_SEQUENCE entry
            (neighbor_asn >> 24) as u8,
            (neighbor_asn >> 16) as u8,
            (neighbor_asn >> 8) as u8,
            neighbor_asn as u8,
        ])
    }

    // {dst 10.0.1.0/24, proto =17}
    const FS_DST_PROTO: &[u8] =
        &[0x01, 0x18, 10, 0, 1, 0x03, 0x81, 0x11];
    // {dst 10.0.1.0/24, dport =53}
    const FS_DST_DPORT: &[u8] =
        &[0x01, 0x18, 10, 0, 1, 0x05, 0x81, 0x35];
    // {proto =17, sport =53} — no destination prefix component
    const FS_NO_DST: &[u8] = &[0x03, 0x81, 0x11, 0x06, 0x81, 0x35];

    fn flowspec_rows(rib: &Rib) -> Vec<FlowSpecQueryRow> {
        rib.query_flowspec(true, None, false, false, None, None)
            .unwrap()
    }

    #[test]
    fn route_source_exposes_addpath_session_path_and_internal_child() {
        let session = 7u32;
        let child = 11u32;
        let child_info = IngressInfo::new()
            .with_ingress_type(ingress::IngressType::BgpPath)
            .with_parent_ingress(session)
            .with_path_id(42u32);

        let source = RouteSource::resolve(child, Some(&child_info));
        let json = serde_json::to_value(source).unwrap();
        assert_eq!(json["ingressId"], session);
        assert_eq!(json["pathId"], 42);
        assert_eq!(json["internalPathIngressId"], child);

        let plain = serde_json::to_value(RouteSource::resolve(session, None))
            .unwrap();
        assert_eq!(plain["ingressId"], session);
        assert!(plain.get("pathId").is_none());
        assert!(plain.get("internalPathIngressId").is_none());
    }

    /// Guard test for the design's central storage assumption: a rule with
    /// no destination-prefix component is keyed at the family default route
    /// (0.0.0.0/0), shows up in walks/queries there, and is reclaimed by
    /// whole-mui removal like any other record.
    #[test]
    fn flowspec_no_dst_rule_keyed_at_default_route() {
        let rib = test_rib();
        let mui: IngressId = 42;
        let route = mk_flowspec_v4(FS_NO_DST);
        assert_eq!(
            route.index_prefix(),
            Prefix::new_v4(0.into(), 0).unwrap()
        );

        rib.insert(&route, RouteStatus::Active, 1, mui, false, false)
            .unwrap();

        let rows = flowspec_rows(&rib);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].key_prefix,
            Prefix::new_v4(0.into(), 0).unwrap()
        );
        assert_eq!(rows[0].ingress_id, mui);
        assert_eq!(rows[0].rule.nlri, FS_NO_DST);

        let mut streamed = 0;
        rib.stream_flowspec_records(|_pr| {
            streamed += 1;
            true
        })
        .unwrap();
        assert_eq!(streamed, 1);

        // Physical whole-mui reclaim covers the default-route record.
        rib.remove_for_ingresses(&[mui]);
        assert!(flowspec_rows(&rib).is_empty());
        let mut streamed = 0;
        rib.stream_flowspec_records(|_pr| {
            streamed += 1;
            true
        })
        .unwrap();
        assert_eq!(streamed, 0);
    }

    #[test]
    fn flowspec_rules_share_dst_key_and_withdraw_independently() {
        let rib = test_rib();
        let mui: IngressId = 7;
        let key = Prefix::from_str("10.0.1.0/24").unwrap();
        let rule_a = mk_flowspec_v4(FS_DST_PROTO);
        let rule_b = mk_flowspec_v4(FS_DST_DPORT);
        assert_eq!(rule_a.index_prefix(), key);

        rib.insert(&rule_a, RouteStatus::Active, 1, mui, false, false)
            .unwrap();
        rib.insert(&rule_b, RouteStatus::Active, 2, mui, false, false)
            .unwrap();

        let rows = flowspec_rows(&rib);
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.key_prefix == key));

        // Re-announcing an existing rule replaces, not duplicates.
        rib.insert(&rule_a, RouteStatus::Active, 3, mui, false, false)
            .unwrap();
        assert_eq!(flowspec_rows(&rib).len(), 2);

        // Withdrawing one rule leaves the other.
        rib.insert(&rule_a, RouteStatus::Withdrawn, 4, mui, false, false)
            .unwrap();
        let rows = flowspec_rows(&rib);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].rule.nlri, FS_DST_DPORT);

        // Withdrawing an unknown rule is a no-op.
        rib.insert(&rule_a, RouteStatus::Withdrawn, 5, mui, false, false)
            .unwrap();
        assert_eq!(flowspec_rows(&rib).len(), 1);

        // Withdrawing the last rule empties the record; nothing remains
        // visible in queries or the dump walk.
        rib.insert(&rule_b, RouteStatus::Withdrawn, 6, mui, false, false)
            .unwrap();
        assert!(flowspec_rows(&rib).is_empty());
        let mut streamed = 0;
        rib.stream_flowspec_records(|_pr| {
            streamed += 1;
            true
        })
        .unwrap();
        assert_eq!(streamed, 0);
    }

    #[test]
    fn flowspec_two_peers_and_prefix_query() {
        let rib = test_rib();
        let key = Prefix::from_str("10.0.1.0/24").unwrap();
        let rule = mk_flowspec_v4(FS_DST_PROTO);
        rib.insert(&rule, RouteStatus::Active, 1, 1, false, false)
            .unwrap();
        rib.insert(&rule, RouteStatus::Active, 1, 2, false, false)
            .unwrap();
        // no-dst rule from peer 1 sits at 0/0
        let nodst = mk_flowspec_v4(FS_NO_DST);
        rib.insert(&nodst, RouteStatus::Active, 1, 1, false, false)
            .unwrap();

        assert_eq!(flowspec_rows(&rib).len(), 3);

        // Exact-match query on the dst prefix
        let rows = rib
            .query_flowspec(true, Some(key), false, false, None, None)
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows.iter().map(|r| r.ingress_id).collect::<HashSet<_>>(),
            HashSet::from([1, 2])
        );

        // ... filtered by peer
        let rows = rib
            .query_flowspec(true, Some(key), false, false, Some(2), None)
            .unwrap();
        assert_eq!(rows.len(), 1);

        // Less-specifics of the dst prefix include the 0/0 no-dst rule.
        let rows = rib
            .query_flowspec(true, Some(key), true, false, None, None)
            .unwrap();
        assert_eq!(rows.len(), 3);

        assert!(rib
            .query_flowspec(
                true,
                None,
                false,
                false,
                None,
                Some((2, usize::MAX)),
            )
            .is_err());
        assert!(rib
            .query_flowspec(
                true,
                None,
                false,
                false,
                None,
                Some((usize::MAX, 1)),
            )
            .is_err());
    }

    #[test]
    fn flowspec_validation_states() {
        let rib = test_rib();
        let reg = rib.ingress_register.clone();
        let peer_a = reg.register();
        let peer_b = reg.register();
        reg.update_info(
            peer_a,
            IngressInfo::new().with_remote_asn(Asn::from_u32(65001)),
        );
        reg.update_info(
            peer_b,
            IngressInfo::new().with_remote_asn(Asn::from_u32(65002)),
        );

        let rule = mk_flowspec_v4(FS_DST_PROTO); // dst 10.0.1.0/24

        // A FlowSpec rule can arrive before its covering unicast route during
        // a dump. It is initially invalid, then becomes valid on the next
        // query without requiring a FlowSpec re-announcement.
        rib.insert(&rule, RouteStatus::Active, 1, peer_a, false, false)
            .unwrap();
        assert_eq!(
            flowspec_rows(&rib)[0].rule.validity,
            FlowSpecValidity::Invalid
        );

        // Best-match unicast route for the rules' dst prefix, from peer A.
        let uni = RotondaRoute::Ipv4Unicast(
            Prefix::from_str("10.0.0.0/16").unwrap().try_into().unwrap(),
            RotondaPaMap::empty_path_attributes(),
        );
        rib.insert(&uni, RouteStatus::Active, 2, peer_a, false, false)
            .unwrap();

        // (a) satisfied: same peer as the best-match unicast route.
        let rows = flowspec_rows(&rib);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].rule.validity, FlowSpecValidity::Valid);

        // (a) violated: rule from a peer that does not hold the best-match
        // unicast route.
        rib.insert(&rule, RouteStatus::Active, 3, peer_b, false, false)
            .unwrap();
        let rows = flowspec_rows(&rib);
        let b_row = rows
            .iter()
            .find(|r| r.ingress_id == peer_b)
            .expect("rule from peer B stored");
        assert_eq!(b_row.rule.validity, FlowSpecValidity::Invalid);
        // ... but it IS stored: invalid rules are the interesting signal.

        // No destination prefix component: unvalidatable, keyed at 0/0.
        let nodst = mk_flowspec_v4(FS_NO_DST);
        rib.insert(&nodst, RouteStatus::Active, 4, peer_a, false, false)
            .unwrap();
        let rows = flowspec_rows(&rib);
        let nodst_row = rows
            .iter()
            .find(|r| r.key_prefix.len() == 0)
            .expect("no-dst rule stored");
        assert_eq!(
            nodst_row.rule.validity,
            FlowSpecValidity::Unvalidatable
        );

        // (b) violated: a more-specific unicast route from a different
        // neighboring AS invalidates the existing rule on the next query.
        let more_specific = RotondaRoute::Ipv4Unicast(
            Prefix::from_str("10.0.1.128/25")
                .unwrap()
                .try_into()
                .unwrap(),
            RotondaPaMap::empty_path_attributes(),
        );
        rib.insert(
            &more_specific,
            RouteStatus::Active,
            5,
            peer_b,
            false,
            false,
        )
        .unwrap();
        let rows = flowspec_rows(&rib);
        let a_row = rows
            .iter()
            .find(|r| r.ingress_id == peer_a && r.key_prefix.len() == 24)
            .expect("rule from peer A stored");
        assert_eq!(a_row.rule.validity, FlowSpecValidity::Invalid);
    }

    #[test]
    fn flowspec_validation_uses_route_origin_and_as_path() {
        let rib = test_rib();
        let reg = rib.ingress_register.clone();
        let flow_peer = reg.register();
        let route_peer = reg.register();
        let more_specific_peer = reg.register();
        for (peer, bgp_id) in [
            (flow_peer, [192, 0, 2, 1]),
            (route_peer, [192, 0, 2, 2]),
            (more_specific_peer, [192, 0, 2, 3]),
        ] {
            reg.update_info(
                peer,
                IngressInfo::new()
                    .with_bgp_id(bgp_id)
                    .with_remote_asn(Asn::from_u32(65000)),
            );
        }

        let originator = [198, 51, 100, 9];
        let rule = mk_flowspec_v4_with_pamap(
            FS_DST_PROTO,
            validation_pamap(originator, 65001),
        );
        let covering = RotondaRoute::Ipv4Unicast(
            Prefix::from_str("10.0.0.0/16").unwrap().try_into().unwrap(),
            validation_pamap(originator, 65001),
        );
        rib.insert(&rule, RouteStatus::Active, 1, flow_peer, false, false)
            .unwrap();
        rib.insert(
            &covering,
            RouteStatus::Active,
            2,
            route_peer,
            false,
            false,
        )
        .unwrap();

        // Different collector sessions are valid when ORIGINATOR_ID agrees.
        assert_eq!(
            flowspec_rows(&rib)[0].rule.validity,
            FlowSpecValidity::Valid
        );

        let more_specific = RotondaRoute::Ipv4Unicast(
            Prefix::from_str("10.0.1.128/25")
                .unwrap()
                .try_into()
                .unwrap(),
            validation_pamap([203, 0, 113, 7], 65002),
        );
        rib.insert(
            &more_specific,
            RouteStatus::Active,
            3,
            more_specific_peer,
            false,
            false,
        )
        .unwrap();

        // All three sessions have remote_asn=65000; only AS_PATH exposes the
        // different neighboring AS that invalidates the rule.
        assert_eq!(
            flowspec_rows(&rib)[0].rule.validity,
            FlowSpecValidity::Invalid
        );
    }

    #[test]
    fn flowspec_mark_withdrawn_and_reactivate() {
        let rib = test_rib();
        let mui: IngressId = 9;
        let rule = mk_flowspec_v4(FS_DST_PROTO);
        let unicast_prefix = Prefix::from_str("10.0.0.0/16").unwrap();
        let unicast = RotondaRoute::Ipv4Unicast(
            unicast_prefix.try_into().unwrap(),
            RotondaPaMap::empty_path_attributes(),
        );
        rib.insert(&unicast, RouteStatus::Active, 1, mui, false, false)
            .unwrap();
        rib.insert(&rule, RouteStatus::Active, 1, mui, false, false)
            .unwrap();
        assert_eq!(flowspec_rows(&rib).len(), 1);

        // Peer-down: mark the whole mui withdrawn for the flowspec family.
        rib.withdraw_for_ingress(
            mui,
            Some(AfiSafiType::Ipv4FlowSpec),
            true,
        );
        assert!(flowspec_rows(&rib).is_empty());

        // Re-announcement reactivates the mui (withdrawn-mui bitmap
        // cleared on the insert path) and the rule is visible again.
        rib.insert(&rule, RouteStatus::Active, 2, mui, false, false)
            .unwrap();
        assert_eq!(flowspec_rows(&rib).len(), 1);
        let unicast_records = rib
            .store()
            .unwrap()
            .get_records_for_prefix(&unicast_prefix, Some(mui), false)
            .unwrap()
            .unwrap();
        assert!(unicast_records.iter().any(|record| {
            record.multi_uniq_id == mui
                && record.status == RouteStatus::Active
        }));

        // Family-agnostic peer-down (None) also covers flowspec.
        rib.withdraw_for_ingress(mui, None, true);
        assert!(flowspec_rows(&rib).is_empty());
    }

    #[test]
    fn flowspec_reconnect_does_not_resurrect_unannounced_rules() {
        let rib = test_rib();
        let mui: IngressId = 10;
        let rule_a = mk_flowspec_v4(FS_DST_PROTO);
        let rule_b = mk_flowspec_v4(FS_DST_DPORT);

        rib.insert(&rule_a, RouteStatus::Active, 1, mui, true, false)
            .unwrap();
        rib.insert(&rule_b, RouteStatus::Active, 2, mui, true, false)
            .unwrap();
        assert_eq!(flowspec_rows(&rib).len(), 2);

        rib.withdraw_for_ingress(mui, None, true);
        assert!(flowspec_rows(&rib).is_empty());

        // The new session announces only A. B belongs to the old session
        // and must remain gone when the MUI is made active again.
        rib.insert(&rule_a, RouteStatus::Active, 3, mui, true, false)
            .unwrap();
        let rows = flowspec_rows(&rib);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].rule.nlri, FS_DST_PROTO);
    }

    #[test]
    fn flowspec_rule_counts_survive_concurrent_recounts() {
        let rib = Arc::new(test_rib());
        let mui: IngressId = 91;
        let writer_rib = rib.clone();
        let writer = std::thread::spawn(move || {
            let rule = mk_flowspec_v4(FS_DST_PROTO);
            for ltime in 1..=250 {
                writer_rib
                    .insert(
                        &rule,
                        RouteStatus::Active,
                        ltime * 2,
                        mui,
                        false,
                        false,
                    )
                    .unwrap();
                writer_rib
                    .insert(
                        &rule,
                        RouteStatus::Withdrawn,
                        ltime * 2 + 1,
                        mui,
                        false,
                        false,
                    )
                    .unwrap();
            }
        });

        let lifecycle_rib = rib.clone();
        let lifecycle = std::thread::spawn(move || {
            for _ in 0..100 {
                lifecycle_rib.withdraw_for_ingress(
                    mui,
                    Some(AfiSafiType::Ipv4FlowSpec),
                    true,
                );
            }
        });
        writer.join().unwrap();
        lifecycle.join().unwrap();

        let rule = mk_flowspec_v4(FS_DST_PROTO);
        rib.insert(&rule, RouteStatus::Active, 1000, mui, false, false)
            .unwrap();
        rib.recount_flowspec_rules();
        assert_eq!(flowspec_rows(&rib).len(), 1);
        assert_eq!(rib.flowspec_rule_counts.snapshot(), (1, 0));
    }
}
