use core::fmt;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    net::IpAddr,
    path::PathBuf,
    rc::Rc,
    sync::{Arc, LazyLock, Mutex},
    time::{Duration, Instant},
};

use chrono::serde::ts_microseconds;
use chrono::Utc;
use inetnum::{addr::Prefix, asn::Asn};
use log::{debug, warn};
use routecore::bgp::{
    message::UpdateMessage, nlri::afisafi::Nlri, types::AfiSafiType,
};
use serde::{Deserialize, Serialize};

use crate::{
    ingress::IngressId,
    manager,
    metrics,
    payload::{RotondaPaMap, RotondaRoute},
};

use super::MutLogEntry;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct FilterName(String);

impl Default for FilterName {
    fn default() -> Self {
        FilterName("".into())
    }
}

// XXX LH: not a fan of calling load_filter_name from here, quite a surprising
// side effect of deserializing a config parameter.
impl<'de> Deserialize<'de> for FilterName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // This has to be a String, even though we pass a &str to
        // ShortString::from(), because of the way that newer versions of the
        // toml crate work.
        //
        // See: https://github.com/toml-rs/toml/issues/597
        let s: String = Deserialize::deserialize(deserializer)?;
        let filter_name = FilterName(s);
        Ok(manager::load_filter_name(filter_name))
    }
}

impl From<String> for FilterName {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl fmt::Display for FilterName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Default)]
pub struct RotoScripts {
    scripts: HashMap<FilterName, PathBuf>,
}

impl RotoScripts {
    pub fn new(scripts: HashMap<FilterName, PathBuf>) -> Self {
        Self { scripts }
    }

    pub fn get(&self, name: &FilterName) -> Option<&PathBuf> {
        self.scripts.get(name)
    }

    pub fn get_filter_names(&self) -> HashSet<FilterName> {
        self.scripts.keys().cloned().collect::<HashSet<_>>()
    }

    pub fn get_script_origins(&self) -> HashSet<PathBuf> {
        self.scripts.values().cloned().collect::<HashSet<_>>()
    }
}

pub type RotoPackage = std::sync::Mutex<roto::Package>;

#[derive(Default)]
pub struct OutputStream<M> {
    msgs: Vec<M>,
    entry: MutLogEntry,
}

pub type RotoOutputStream = OutputStream<Output>;

impl<M> OutputStream<M> {
    pub fn new() -> Self {
        Self::with_vec(vec![])
    }

    pub fn with_vec(v: Vec<M>) -> Self {
        Self {
            msgs: v,
            entry: Rc::new(RefCell::new(LogEntry::new())),
        }
    }

    /// Create a new `OutputStream` wrapped in an `Rc<RefCell<>>`
    pub fn new_rced() -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self::new()))
    }

    pub fn push(&mut self, msg: M) {
        self.msgs.push(msg);
    }

    pub fn drain(&mut self) -> std::vec::Drain<'_, M> {
        self.msgs.drain(..)
    }

    pub fn is_empty(&self) -> bool {
        self.msgs.is_empty()
    }

    pub fn entry(&mut self) -> MutLogEntry {
        self.entry.clone()
    }

    pub fn take_entry(&mut self) -> MutLogEntry {
        std::mem::take(&mut self.entry)
    }

    pub fn print(&self, msg: impl AsRef<str>) {
        eprintln!("{}", msg.as_ref());
    }
}

impl<M> IntoIterator for OutputStream<M> {
    type Item = M;

    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.msgs.into_iter()
    }
}

#[derive(Clone, Debug)]
pub enum Output {
    /// Community observed in Path Attributes.
    Community(u32),

    /// ASN observed in the AS_PATH Path Attribute.
    Asn(Asn),

    /// ASN observed as right-most AS in the AS_PATH.
    Origin(Asn),

    // TODO stick the PeerIp in here from roto, if we can, otherwise get it
    // from elsewhere in Rotonda
    /// A BMP PeerDownNotification was observed.
    PeerDown,
    /// Prefix observed in the BGP or BMP message.
    Prefix(Prefix),

    /// Variant to support user-defined log entries.
    Custom((u32, u32)),

    /// Extensive, composable log entry, see [`LogEntry`].
    Entry(LogEntry),
}

#[derive(Copy, Clone, Debug)]
pub struct InsertionInfo {
    pub prefix_new: bool,
    pub new_peer: bool,
    //is_new_best: bool,
    //replaced_route: RotondaRoute,
}

//------------ PeerRibType ---------------------------------------------------

#[derive(
    Debug,
    Copy,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Default,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub enum PeerRibType {
    InPre,
    InPost,
    Loc,
    OutPre,
    #[default]
    OutPost, // This is the default for BGP messages
}

// XXX LH: perhaps we can/should get rid of PeerRibType here if we extend the
// one in routecore?
impl From<(bool, routecore::bmp::message::RibType)> for PeerRibType {
    fn from(
        (is_post_policy, rib_type): (bool, routecore::bmp::message::RibType),
    ) -> Self {
        match rib_type {
            routecore::bmp::message::RibType::AdjRibIn => {
                if is_post_policy {
                    PeerRibType::InPost
                } else {
                    PeerRibType::InPre
                }
            }
            routecore::bmp::message::RibType::AdjRibOut => {
                if is_post_policy {
                    PeerRibType::OutPost
                } else {
                    PeerRibType::OutPre
                }
            }
            routecore::bmp::message::RibType::LocRib => PeerRibType::Loc,
        }
    }
}

impl fmt::Display for PeerRibType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerRibType::InPre => write!(f, "adj-RIB-in-pre"),
            PeerRibType::InPost => write!(f, "adj-RIB-in-post"),
            PeerRibType::Loc => write!(f, "RIB-loc"),
            PeerRibType::OutPre => write!(f, "adj-RIB-out-pre"),
            PeerRibType::OutPost => write!(f, "adj-RIB-out-post"),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, serde::Serialize)]
#[serde(untagged)]
pub enum OutputStreamMessageRecord {
    Route(Option<RotondaRoute>),
    Peerdown(IpAddr, Asn),
    Custom(CustomLogEntry),
    Entry(LogEntry),
}

impl OutputStreamMessageRecord {
    pub fn into_timestamped(
        self,
        timestamp: chrono::DateTime<Utc>,
    ) -> TimestampedOSMR {
        TimestampedOSMR {
            timestamp: timestamp.timestamp(),
            record: self,
        }
    }
}

#[derive(Debug, serde::Serialize)]
pub struct TimestampedOSMR {
    timestamp: i64,
    record: OutputStreamMessageRecord,
}

impl From<OutputStreamMessageRecord> for TimestampedOSMR {
    fn from(value: OutputStreamMessageRecord) -> Self {
        Self {
            timestamp: Utc::now().timestamp(),
            record: value,
        }
    }
}

impl From<OutputStreamMessage> for TimestampedOSMR {
    fn from(value: OutputStreamMessage) -> Self {
        let value = value.record;
        value.into()
    }
}

#[derive(Debug, PartialEq, Eq, Clone, serde::Serialize)]
pub struct CustomLogEntry {
    id: u32,
    value: u32,
}

impl From<(u32, u32)> for CustomLogEntry {
    fn from(t: (u32, u32)) -> Self {
        Self {
            id: t.0,
            value: t.1,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct LogEntry {
    #[serde(with = "ts_microseconds")]
    pub timestamp: chrono::DateTime<Utc>,
    pub origin_as: Option<Asn>,
    pub peer_as: Option<Asn>,
    pub as_path_hops: Option<usize>,
    pub conventional_reach: usize,
    pub conventional_unreach: usize,
    pub mp_reach: Option<usize>,
    pub mp_reach_afisafi: Option<AfiSafiType>,
    pub mp_unreach: Option<usize>,
    pub mp_unreach_afisafi: Option<AfiSafiType>,
    pub custom: Option<String>,
}

use serde_with;

#[serde_with::skip_serializing_none]
#[derive(serde::Serialize)]
pub struct MinimalLogEntry {
    #[serde(with = "ts_microseconds")]
    pub timestamp: chrono::DateTime<Utc>,
    pub origin_as: Option<Asn>,
    pub peer_as: Option<Asn>,
    pub as_path_hops: Option<usize>,
    pub conventional_reach: usize,
    pub conventional_unreach: usize,
    pub mp_reach: Option<usize>,
    pub mp_reach_afisafi: Option<AfiSafiType>,
    pub mp_unreach: Option<usize>,
    pub mp_unreach_afisafi: Option<AfiSafiType>,
}

impl From<LogEntry> for MinimalLogEntry {
    fn from(value: LogEntry) -> Self {
        Self {
            timestamp: value.timestamp,
            origin_as: value.origin_as,
            peer_as: value.peer_as,
            as_path_hops: value.as_path_hops,
            conventional_reach: value.conventional_reach,
            conventional_unreach: value.conventional_unreach,
            mp_reach: value.mp_reach,
            mp_reach_afisafi: value.mp_reach_afisafi,
            mp_unreach: value.mp_unreach,
            mp_unreach_afisafi: value.mp_unreach_afisafi,
        }
    }
}

impl LogEntry {
    pub fn new() -> Self {
        Self {
            //timestamp: Utc::now(),
            ..Default::default()
        }
    }
    pub fn into_minimal(self) -> MinimalLogEntry {
        self.into()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OutputStreamMessage {
    name: String,
    topic: String,
    record: OutputStreamMessageRecord,
    ingress_id: Option<IngressId>,
}

const MQTT_NAME: &str = "mqtt";
impl OutputStreamMessage {
    pub fn prefix(
        record: Option<RotondaRoute>,
        ingress_id: Option<IngressId>,
    ) -> Self {
        Self {
            name: MQTT_NAME.into(),
            topic: "prefix".into(),
            record: OutputStreamMessageRecord::Route(record),
            ingress_id,
        }
    }

    pub fn community(
        record: Option<RotondaRoute>,
        ingress_id: Option<IngressId>,
    ) -> Self {
        Self {
            name: MQTT_NAME.into(),
            topic: "community".into(),
            record: OutputStreamMessageRecord::Route(record),
            ingress_id,
        }
    }

    pub fn asn(
        record: Option<RotondaRoute>,
        ingress_id: Option<IngressId>,
    ) -> Self {
        Self {
            name: MQTT_NAME.into(),
            topic: "asn".into(),
            record: OutputStreamMessageRecord::Route(record),
            ingress_id,
        }
    }

    pub fn origin(
        record: Option<RotondaRoute>,
        ingress_id: Option<IngressId>,
    ) -> Self {
        Self {
            name: MQTT_NAME.into(),
            topic: "origin".into(),
            record: OutputStreamMessageRecord::Route(record),
            ingress_id,
        }
    }

    pub fn peer_down(
        name: String,
        topic: String,
        peer_ip: IpAddr,
        peer_asn: Asn,
        ingress_id: Option<IngressId>,
    ) -> Self {
        Self {
            name,
            topic,
            record: OutputStreamMessageRecord::Peerdown(peer_ip, peer_asn),
            ingress_id,
        }
    }
    pub fn custom(
        id: u32,
        value: u32,
        ingress_id: Option<IngressId>,
    ) -> Self {
        Self {
            name: MQTT_NAME.into(),
            topic: "custom".into(),
            record: OutputStreamMessageRecord::Custom((id, value).into()),
            ingress_id,
        }
    }

    pub fn entry(entry: LogEntry, ingress_id: Option<IngressId>) -> Self {
        Self {
            name: MQTT_NAME.into(),
            topic: "log_entry".into(),
            record: OutputStreamMessageRecord::Entry(entry),
            ingress_id,
        }
    }

    pub fn get_name(&self) -> String {
        self.name.clone()
    }

    pub fn get_topic(&self) -> &String {
        &self.topic
    }

    pub fn get_record(&self) -> &OutputStreamMessageRecord {
        &self.record
    }

    pub fn into_record(self) -> OutputStreamMessageRecord {
        self.record
    }

    pub fn get_ingress_id(&self) -> Option<IngressId> {
        self.ingress_id
    }
}

//--- Unsupported AFI/SAFI drop accounting -----------------------------------

/// How often to emit a rolled-up summary of NLRI dropped because their AFI/SAFI
/// has no [`RotondaRoute`] representation.
const UNSUPPORTED_AFISAFI_SUMMARY_INTERVAL: Duration = Duration::from_secs(60);

/// Process-global accounting for NLRI dropped because their AFI/SAFI has no
/// [`RotondaRoute`] representation (FlowSpec, MPLS-VPN, EVPN, RouteTarget, ...).
/// Such NLRI are parsed fine by routecore but dropped before any RIB in the
/// [`RotondaRoute`] `TryFrom` chokepoint. This serves two purposes:
///
///  * **logging** — warn once per family on first sight, then fold the volume
///    into a periodic `warn!` summary, so the drops are visible at default log
///    levels without one line per prefix;
///  * **metrics** — a monotonic per-AFI/SAFI Prometheus counter, exposed by the
///    [`metrics::Source`] impl and registered globally in `Manager::new`.
///
/// Reachable from the shared explode path (bmp-in, bgp-in, mrt-in) via
/// [`note_unsupported_afisafi`]; the live handle is obtained with
/// [`unsupported_afisafi_metrics`].
#[derive(Debug, Default)]
pub struct UnsupportedAfiSafiMetrics {
    inner: Mutex<UnsupportedAfiSafiInner>,
}

/// Tallies are kept in `Vec`s rather than `HashMap`s: the set of distinct
/// AFI/SAFI types is tiny, so linear scans beat hashing, and this only runs on
/// the (rare) drop path and on metrics scrapes.
#[derive(Debug, Default)]
struct UnsupportedAfiSafiInner {
    /// AFI/SAFI types already called out individually; persists for process
    /// life so each family warns exactly once on first sight.
    seen: Vec<AfiSafiType>,
    /// Per-type drop tally for the next periodic log summary (drained on emit).
    window_counts: Vec<(AfiSafiType, u64)>,
    /// Monotonic per-type drop totals exposed via Prometheus (never drained).
    totals: Vec<(AfiSafiType, u64)>,
    /// Start of the current log-summary window (anchored on the first drop
    /// after a summary); `None` until the next drop re-anchors it.
    window_start: Option<Instant>,
}

/// Increment the per-AFI/SAFI counter in a small assoc-`Vec`, inserting on
/// first sight.
fn bump(counts: &mut Vec<(AfiSafiType, u64)>, afi_safi: AfiSafiType) {
    match counts.iter_mut().find(|(t, _)| *t == afi_safi) {
        Some((_, n)) => *n += 1,
        None => counts.push((afi_safi, 1)),
    }
}

impl UnsupportedAfiSafiMetrics {
    /// Record one dropped NLRI: bump the monotonic Prometheus total and drive
    /// the throttled `warn!` logging (see the type docs for the scheme). `now`
    /// is taken by the caller so this stays deterministic in tests.
    fn note(&self, afi_safi: AfiSafiType, now: Instant) {
        let (first_sight, summary) = {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());

            // Monotonic Prometheus total (never drained).
            bump(&mut inner.totals, afi_safi);

            // First time this exact AFI/SAFI is ever dropped: call it out
            // immediately rather than waiting for the next summary.
            let first_sight = !inner.seen.contains(&afi_safi);
            if first_sight {
                inner.seen.push(afi_safi);
            }

            // Windowed tally driving the periodic log summary.
            bump(&mut inner.window_counts, afi_safi);
            let window_start = *inner.window_start.get_or_insert(now);
            let elapsed = now.saturating_duration_since(window_start);
            let summary = if elapsed >= UNSUPPORTED_AFISAFI_SUMMARY_INTERVAL {
                let total: u64 =
                    inner.window_counts.iter().map(|(_, n)| n).sum();
                let mut breakdown = std::mem::take(&mut inner.window_counts);
                inner.window_start = None;
                breakdown.sort_by(|a, b| b.1.cmp(&a.1));
                Some((total, elapsed, breakdown))
            } else {
                None
            };
            (first_sight, summary)
        };
        // Lock released; format and log outside the critical section.

        if first_sight {
            warn!(
                "Dropping route(s) with unsupported AFI/SAFI {afi_safi}: no \
                 RotondaRoute representation, not stored in any RIB. Further \
                 drops are summarized at most once per {}s and counted in \
                 rotonda_unsupported_afisafi_dropped_total.",
                UNSUPPORTED_AFISAFI_SUMMARY_INTERVAL.as_secs(),
            );
        }

        if let Some((total, elapsed, breakdown)) = summary {
            let detail = breakdown
                .iter()
                .map(|(t, n)| format!("{t}={n}"))
                .collect::<Vec<_>>()
                .join(", ");
            warn!(
                "Dropped {total} route(s) with unsupported AFI/SAFI over the \
                 last {}s (no RotondaRoute representation, not stored in any \
                 RIB): {detail}",
                elapsed.as_secs(),
            );
        }
    }
}

impl metrics::Source for UnsupportedAfiSafiMetrics {
    fn append(&self, _unit_name: &str, target: &mut metrics::Target) {
        const DROPPED_METRIC: metrics::Metric = metrics::Metric::new(
            "unsupported_afisafi_dropped",
            "routes dropped because their AFI/SAFI has no internal \
             representation and cannot be stored in any RIB",
            metrics::MetricType::Counter,
            metrics::MetricUnit::Total,
        );

        // Snapshot under the lock, render outside it.
        let totals: Vec<(AfiSafiType, u64)> = {
            let inner = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            inner.totals.clone()
        };

        if totals.is_empty() {
            return;
        }

        // One HELP/TYPE block, one labelled row per AFI/SAFI family, e.g.
        // rotonda_unsupported_afisafi_dropped_total{afi_safi="Ipv4FlowSpec"}.
        target.append(&DROPPED_METRIC, None, |records| {
            for (afi_safi, count) in &totals {
                let afi_safi = afi_safi.to_string();
                records
                    .label_value(&[("afi_safi", afi_safi.as_str())], *count);
            }
        });
    }
}

static UNSUPPORTED_AFISAFI: LazyLock<Arc<UnsupportedAfiSafiMetrics>> =
    LazyLock::new(|| Arc::new(UnsupportedAfiSafiMetrics::default()));

/// Returns the process-global unsupported-AFI/SAFI accounting handle so the
/// manager can register it as a [`metrics::Source`]. The `LazyLock` keeps a
/// strong reference for the life of the process, so the `Weak` held by the
/// metrics collection never dangles.
pub fn unsupported_afisafi_metrics() -> Arc<UnsupportedAfiSafiMetrics> {
    UNSUPPORTED_AFISAFI.clone()
}

/// Record one NLRI dropped because its AFI/SAFI has no [`RotondaRoute`]
/// representation. Called from the shared `TryFrom` drop path; bumps the
/// Prometheus counter and drives the throttled `warn!` logging.
fn note_unsupported_afisafi(afi_safi: AfiSafiType) {
    UNSUPPORTED_AFISAFI.note(afi_safi, Instant::now());
}

impl<O> TryFrom<(Nlri<O>, RotondaPaMap)> for RotondaRoute {
    type Error = ();
    fn try_from(value: (Nlri<O>, RotondaPaMap)) -> Result<Self, Self::Error> {
        let res = match value.0 {
            Nlri::Ipv4Unicast(n) => RotondaRoute::Ipv4Unicast(n, value.1),
            Nlri::Ipv4Multicast(n) => RotondaRoute::Ipv4Multicast(n, value.1),
            Nlri::Ipv6Unicast(n) => RotondaRoute::Ipv6Unicast(n, value.1),
            Nlri::Ipv6Multicast(n) => RotondaRoute::Ipv6Multicast(n, value.1),

            Nlri::Ipv4UnicastAddpath(..)
            | Nlri::Ipv4MulticastAddpath(..)
            | Nlri::Ipv4MplsUnicast(..)
            | Nlri::Ipv4MplsUnicastAddpath(..)
            | Nlri::Ipv4MplsVpnUnicast(..)
            | Nlri::Ipv4MplsVpnUnicastAddpath(..)
            | Nlri::Ipv4RouteTarget(..)
            | Nlri::Ipv4RouteTargetAddpath(..)
            | Nlri::Ipv4FlowSpec(..)
            | Nlri::Ipv4FlowSpecAddpath(..)
            | Nlri::Ipv6UnicastAddpath(..)
            | Nlri::Ipv6MulticastAddpath(..)
            | Nlri::Ipv6MplsUnicast(..)
            | Nlri::Ipv6MplsUnicastAddpath(..)
            | Nlri::Ipv6MplsVpnUnicast(..)
            | Nlri::Ipv6MplsVpnUnicastAddpath(..)
            | Nlri::Ipv6FlowSpec(..)
            | Nlri::Ipv6FlowSpecAddpath(..)
            | Nlri::L2VpnVpls(..)
            | Nlri::L2VpnVplsAddpath(..)
            | Nlri::L2VpnEvpn(..)
            | Nlri::L2VpnEvpnAddpath(..) => {
                note_unsupported_afisafi(value.0.afi_safi());
                debug!(
                    "AFI/SAFI {} not yet supported in RotondaRoute",
                    value.0
                );
                return Err(());
            }
        };

        Ok(res)
    }
}

pub(crate) fn explode_announcements(
    bgp_update: &UpdateMessage<impl routecore::Octets>,
) -> Result<Vec<RotondaRoute>, routecore::bgp::ParseError> {
    let mut res = vec![];

    let pas = bgp_update.path_attributes()?;
    let pamap = RotondaPaMap::new(pas.into());

    for a in bgp_update.announcements()? {
        let a = a?;
        if let Ok(r) = (a, pamap.clone()).try_into() {
            res.push(r);
        } else {
            debug!("unsupported AFI/SAFI in explode_announcements");
        }
    }
    Ok(res)
}

pub(crate) fn explode_withdrawals(
    bgp_update: &UpdateMessage<impl routecore::Octets>,
) -> Result<Vec<RotondaRoute>, routecore::bgp::ParseError> {
    let mut res = vec![];

    let pamap = RotondaPaMap::new(
        routecore::bgp::path_attributes::OwnedPathAttributes::new(
            bgp_update.pdu_parse_info(),
            vec![],
        ),
    );

    for w in bgp_update.withdrawals()? {
        let w = w?;
        if let Ok(r) = (w, pamap.clone()).try_into() {
            res.push(r);
        } else {
            debug!("unsupported AFI/SAFI in explode_withdrawals");
        }
    }
    Ok(res)
}

//------------ Temporary types -----------------------------------------------

// PeerId was part of the old roto, but used throughout the BMP state machine.
// This should go (elsewhere), eventually.

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct PeerId {
    pub addr: IpAddr,
    pub asn: Asn,
}

impl PeerId {
    pub fn new(addr: IpAddr, asn: Asn) -> Self {
        Self { addr, asn }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_afisafi_counter_increments_and_renders() {
        let m = UnsupportedAfiSafiMetrics::default();
        let now = Instant::now();
        // Two FlowSpec drops and one MPLS-VPN drop.
        m.note(AfiSafiType::Ipv4FlowSpec, now);
        m.note(AfiSafiType::Ipv4FlowSpec, now);
        m.note(AfiSafiType::Ipv6MplsVpnUnicast, now);

        let mut target =
            metrics::Target::new(metrics::OutputFormat::Prometheus);
        metrics::Source::append(&m, "unsupported_afisafi", &mut target);
        let out = target.into_string();

        assert!(
            out.contains(
                "rotonda_unsupported_afisafi_dropped_total\
                 {afi_safi=\"Ipv4FlowSpec\"} 2"
            ),
            "missing FlowSpec total in:\n{out}"
        );
        assert!(
            out.contains(
                "rotonda_unsupported_afisafi_dropped_total\
                 {afi_safi=\"Ipv6MplsVpnUnicast\"} 1"
            ),
            "missing MPLS-VPN total in:\n{out}"
        );
    }

    #[test]
    fn unsupported_afisafi_metric_absent_until_first_drop() {
        let m = UnsupportedAfiSafiMetrics::default();
        let mut target =
            metrics::Target::new(metrics::OutputFormat::Prometheus);
        metrics::Source::append(&m, "unsupported_afisafi", &mut target);
        assert!(!target.into_string().contains("unsupported_afisafi"));
    }
}
