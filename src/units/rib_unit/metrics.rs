use std::{
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering::SeqCst},
        Arc, OnceLock, Weak,
    },
    time::{Duration, Instant},
};

use arc_swap::{ArcSwap, ArcSwapAny};
use dashmap::DashMap;

use crate::{
    comms::{Gate, GateMetrics},
    ingress::IngressId,
    metrics::{
        self, util::append_per_router_metric, Metric, MetricType, MetricUnit,
    },
    payload::RouterId,
};

use super::{rib::Rib, statistics::RibMergeUpdateStatistics};

#[derive(Debug, Default)]
pub struct RibUnitMetrics {
    gate: Arc<GateMetrics>,
    /// The RIB, for the gauges that are read from the store at scrape time
    /// rather than accumulated: how many prefixes and records it holds is
    /// something the store already knows exactly, and a counter maintained
    /// alongside it can only drift -- as `num_routes_announced` did, all the
    /// way past zero and around.
    ///
    /// Weak so that metrics never keep a replaced RIB alive across a
    /// reconfigure; unset in tests that build no RIB, where both gauges read
    /// zero.
    rib: OnceLock<Weak<ArcSwap<Rib>>>,
    pub num_insert_retries: AtomicUsize,
    pub num_insert_hard_failures: AtomicUsize,
    pub num_routes_announced: AtomicUsize,
    pub num_modified_route_announcements: AtomicUsize,
    pub num_routes_withdrawn: AtomicUsize,
    pub num_route_withdrawals_without_announcement: AtomicUsize,
    pub last_insert_duration_micros: AtomicU64,
    pub last_update_duration_micros: AtomicU64,
    //routers: Arc<FrimMap<Arc<RouterId>, Arc<RouterMetrics>>>,
    // A concurrent hash map (O(1) lookup) rather than FrimMap: this is hit
    // once (twice for withdrawals) per prefix on the RIB update hot path, so
    // FrimMap's arc-swap load + linear scan dominated CPU under load.
    routers: Arc<DashMap<IngressId, Arc<RouterMetrics>>>,
    pub rib_merge_update_stats: Arc<RibMergeUpdateStatistics>,
}

impl RibUnitMetrics {
    /// Point the store-sourced gauges at the RIB. Called once, after both
    /// exist.
    pub fn set_rib(&self, rib: &Arc<ArcSwap<Rib>>) {
        let _ = self.rib.set(Arc::downgrade(rib));
    }

    /// Prefixes and records currently in the store, across every family.
    /// `None` when there is no RIB to ask.
    fn store_totals(&self) -> Option<(usize, usize)> {
        let rib = self.rib.get()?.upgrade()?;
        let counts = rib.load().store_counts();
        Some(counts.iter().fold((0, 0), |(prefixes, routes), c| {
            (prefixes + c.prefixes, routes + c.routes)
        }))
    }

    pub fn router_metrics(
        &self,
        //router_id: Arc<RouterId>,
        ingress_id: IngressId,
    ) -> Arc<RouterMetrics> {
        self.routers
            .entry(ingress_id)
            .or_insert_with(Default::default)
            .value()
            .clone()
    }
}

#[derive(Debug)]
pub struct RouterMetrics {
    pub last_e2e_delay_millis: Arc<AtomicU64>,
    pub last_e2e_delay_at: Arc<ArcSwap<Instant>>,
}

impl Default for RouterMetrics {
    fn default() -> Self {
        Self {
            last_e2e_delay_millis: Arc::new(Default::default()),
            last_e2e_delay_at: Arc::new(ArcSwapAny::new(Arc::new(
                Instant::now(),
            ))),
        }
    }
}

impl RibUnitMetrics {
    const NUM_UNIQUE_PREFIXES_METRIC: Metric = Metric::new(
        "rib_unit_num_unique_prefixes",
        "the number of unique prefixes currently in the rib",
        MetricType::Gauge,
        MetricUnit::Total,
    );
    const NUM_ITEMS_METRIC: Metric = Metric::new(
        "rib_unit_num_items",
        "the total number of records -- one per prefix and ingress -- stored (withdrawn or not) in the rib",
        MetricType::Gauge,
        MetricUnit::Total,
    );
    const NUM_INSERT_RETRIES_METRIC: Metric = Metric::new(
        "rib_unit_num_insert_retries",
        "the number of times prefix insertions had to be retried due to contention",
        MetricType::Counter,
        MetricUnit::Total,
    );
    const NUM_INSERT_HARD_FAILURES_METRIC: Metric = Metric::new(
        "rib_unit_num_insert_hard_failures",
        "the number of prefix insertions that were given up after exhausting all retries",
        MetricType::Counter,
        MetricUnit::Total,
    );
    const NUM_ROUTES_ANNOUNCED_METRIC: Metric = Metric::new(
        "rib_unit_num_routes_announced",
        "announcements that brought a new prefix into the rib (see rib_unit_num_items for what it currently holds)",
        MetricType::Counter,
        MetricUnit::Total,
    );
    const NUM_MODIFIED_ROUTE_ANNOUNCEMENTS_METRIC: Metric = Metric::new(
        "rib_unit_num_modified_route_announcements",
        "announcements for a prefix the rib already held: another peer's path, or a re-announcement of one it had",
        MetricType::Counter,
        MetricUnit::Total,
    );
    const NUM_ROUTES_WITHDRAWN_METRIC: Metric = Metric::new(
        "rib_unit_num_routes_withdrawn",
        "withdrawals applied to a route the rib held (see rib_unit_num_items for what it currently holds)",
        MetricType::Counter,
        MetricUnit::Total,
    );
    const NUM_WITHDRAWN_ROUTES_WITHOUT_ANNOUNCEMENTS_METRIC: Metric = Metric::new(
        "rib_unit_num_route_withdrawals_without_announcements",
        "the number of route withdrawals processed without a corresponding announcement",
        MetricType::Counter,
        MetricUnit::Total,
    );
    const LAST_INSERT_DURATION_METRIC: Metric = Metric::new(
        "rib_unit_insert_duration",
        "the time taken to insert the last prefix inserted into the RIB unit store",
        MetricType::Gauge,
        MetricUnit::Microsecond,
    );
    const LAST_UPDATE_DURATION_METRIC: Metric = Metric::new(
        "rib_unit_update_duration",
        "the time taken to update the last prefix modified in the RIB unit store",
        MetricType::Gauge,
        MetricUnit::Microsecond,
    );
    const LAST_END_TO_END_DELAY_PER_ROUTER_METRIC: Metric = Metric::new(
        "rib_unit_e2e_duration",
        "the time taken from initial receipt to completed insertion for a prefix into the RIB unit store",
        MetricType::Gauge,
        MetricUnit::Millisecond,
    );
}

impl RibUnitMetrics {
    pub fn new(
        gate: &Arc<Gate>,
        rib_merge_update_stats: Arc<RibMergeUpdateStatistics>,
    ) -> Self {
        RibUnitMetrics {
            gate: gate.metrics(),
            rib_merge_update_stats,
            ..Default::default()
        }
    }
}

impl metrics::Source for RibUnitMetrics {
    fn append(&self, unit_name: &str, target: &mut metrics::Target) {
        self.gate.append(unit_name, target);

        let (prefixes, routes) = self.store_totals().unwrap_or((0, 0));
        target.append_simple(
            &Self::NUM_UNIQUE_PREFIXES_METRIC,
            Some(unit_name),
            prefixes,
        );
        target.append_simple(
            &Self::NUM_ITEMS_METRIC,
            Some(unit_name),
            routes,
        );
        target.append_simple(
            &Self::NUM_INSERT_RETRIES_METRIC,
            Some(unit_name),
            self.num_insert_retries.load(SeqCst),
        );
        target.append_simple(
            &Self::NUM_INSERT_HARD_FAILURES_METRIC,
            Some(unit_name),
            self.num_insert_hard_failures.load(SeqCst),
        );
        target.append_simple(
            &Self::NUM_ROUTES_ANNOUNCED_METRIC,
            Some(unit_name),
            self.num_routes_announced.load(SeqCst),
        );
        target.append_simple(
            &Self::NUM_MODIFIED_ROUTE_ANNOUNCEMENTS_METRIC,
            Some(unit_name),
            self.num_modified_route_announcements.load(SeqCst),
        );
        target.append_simple(
            &Self::NUM_ROUTES_WITHDRAWN_METRIC,
            Some(unit_name),
            self.num_routes_withdrawn.load(SeqCst),
        );
        target.append_simple(
            &Self::NUM_WITHDRAWN_ROUTES_WITHOUT_ANNOUNCEMENTS_METRIC,
            Some(unit_name),
            self.num_route_withdrawals_without_announcement.load(SeqCst),
        );
        target.append_simple(
            &Self::LAST_INSERT_DURATION_METRIC,
            Some(unit_name),
            self.last_insert_duration_micros.load(SeqCst),
        );
        target.append_simple(
            &Self::LAST_UPDATE_DURATION_METRIC,
            Some(unit_name),
            self.last_update_duration_micros.load(SeqCst),
        );

        let max_age = Duration::from_secs(60);
        self.routers.retain(|_, metrics| {
            metrics.last_e2e_delay_at.load().elapsed() <= max_age
        });

        for entry in self.routers.iter() {
            append_per_router_metric(
                unit_name,
                target,
                // TODO this should come from the ingress::Register and
                // preferably be a nice name or ip address
                format!("{}", entry.key()),
                Self::LAST_END_TO_END_DELAY_PER_ROUTER_METRIC,
                entry.value().last_e2e_delay_millis.load(SeqCst),
            );
        }

        self.rib_merge_update_stats.append(unit_name, target);
    }
}
