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
    message::UpdateMessage,
    nlri::afisafi::{AfiSafiNlri, Nlri, NlriType},
    nlri::common::PathId,
    types::AfiSafiType,
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
    // from elsewhere in Netom
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

//--- Unsupported NLRI drop accounting ---------------------------------------

/// How often to emit a rolled-up summary of NLRI dropped because their type has
/// no [`RotondaRoute`] representation.
const UNSUPPORTED_NLRI_SUMMARY_INTERVAL: Duration = Duration::from_secs(60);

/// Process-global accounting for NLRI dropped because their [`NlriType`] has no
/// [`RotondaRoute`] representation: genuinely unsupported families (MPLS-VPN,
/// EVPN, RouteTarget, ...). ADD-PATH NLRI of the stored families
/// (unicast/multicast/flowspec) are *not* counted here — [`convert_nlri`]
/// strips their path id into a per-path child ingress and stores them. Such
/// NLRI parse fine in routecore but are dropped before any RIB in the
/// [`convert_nlri`] chokepoint.
///
/// Keyed on [`NlriType`] rather than `AfiSafiType` so the ADD-PATH variants
/// of the remaining unsupported families stay distinct: `AfiSafiType` would
/// collapse e.g. `Ipv4MplsUnicastAddpath` down to `Ipv4MplsUnicast` and hide
/// which encoding actually arrived.
///
/// This serves two purposes:
///
///  * **logging** — warn once per NLRI type on first sight, then fold the volume
///    into a periodic `warn!` summary, so the drops are visible at default log
///    levels without one line per prefix;
///  * **metrics** — a monotonic per-NLRI-type Prometheus counter, exposed by the
///    [`metrics::Source`] impl and registered globally in `Manager::new`.
///
/// Reachable from the shared explode path (bmp-in, bgp-in, mrt-in) via
/// [`note_unsupported_nlri`]; the live handle is obtained with
/// [`unsupported_nlri_metrics`].
#[derive(Debug, Default)]
pub struct UnsupportedNlriMetrics {
    inner: Mutex<UnsupportedNlriInner>,
}

/// Tallies are kept in `Vec`s rather than `HashMap`s: the set of distinct NLRI
/// types is tiny, so linear scans beat hashing, and this only runs on the
/// (rare) drop path and on metrics scrapes.
#[derive(Debug, Default)]
struct UnsupportedNlriInner {
    /// NLRI types already called out individually; persists for process life so
    /// each type warns exactly once on first sight.
    seen: Vec<NlriType>,
    /// Per-type drop tally for the next periodic log summary (drained on emit).
    window_counts: Vec<(NlriType, u64)>,
    /// Monotonic per-type drop totals exposed via Prometheus (never drained).
    totals: Vec<(NlriType, u64)>,
    /// Start of the current log-summary window (anchored on the first drop
    /// after a summary); `None` until the next drop re-anchors it.
    window_start: Option<Instant>,
}

/// Increment the per-NLRI-type counter in a small assoc-`Vec`, inserting on
/// first sight.
fn bump(counts: &mut Vec<(NlriType, u64)>, nlri_type: NlriType) {
    match counts.iter_mut().find(|(t, _)| *t == nlri_type) {
        Some((_, n)) => *n += 1,
        None => counts.push((nlri_type, 1)),
    }
}

impl UnsupportedNlriMetrics {
    /// Record one dropped NLRI: bump the monotonic Prometheus total and drive
    /// the throttled `warn!` logging (see the type docs for the scheme). `now`
    /// is taken by the caller so this stays deterministic in tests.
    fn note(&self, nlri_type: NlriType, now: Instant) {
        let (first_sight, summary) = {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());

            // Monotonic Prometheus total (never drained).
            bump(&mut inner.totals, nlri_type);

            // First time this exact NLRI type is ever dropped: call it out
            // immediately rather than waiting for the next summary.
            let first_sight = !inner.seen.contains(&nlri_type);
            if first_sight {
                inner.seen.push(nlri_type);
            }

            // Windowed tally driving the periodic log summary.
            bump(&mut inner.window_counts, nlri_type);
            let window_start = *inner.window_start.get_or_insert(now);
            let elapsed = now.saturating_duration_since(window_start);
            let summary = if elapsed >= UNSUPPORTED_NLRI_SUMMARY_INTERVAL {
                let total: u64 =
                    inner.window_counts.iter().map(|(_, n)| n).sum();
                let mut breakdown = std::mem::take(&mut inner.window_counts);
                inner.window_start = None;
                // Highest-volume NLRI type first.
                breakdown.sort_by_key(|&(_, n)| std::cmp::Reverse(n));
                Some((total, elapsed, breakdown))
            } else {
                None
            };
            (first_sight, summary)
        };
        // Lock released; format and log outside the critical section.

        if first_sight {
            warn!(
                "Dropping route(s) with unsupported NLRI type {nlri_type:?}: \
                 no RotondaRoute representation, not stored in any RIB. \
                 Further drops are summarized at most once per {}s and counted \
                 in netom_unsupported_nlri_dropped_total.",
                UNSUPPORTED_NLRI_SUMMARY_INTERVAL.as_secs(),
            );
        }

        if let Some((total, elapsed, breakdown)) = summary {
            let detail = breakdown
                .iter()
                .map(|(t, n)| format!("{t:?}={n}"))
                .collect::<Vec<_>>()
                .join(", ");
            warn!(
                "Dropped {total} route(s) with unsupported NLRI type over the \
                 last {}s (no RotondaRoute representation, not stored in any \
                 RIB): {detail}",
                elapsed.as_secs(),
            );
        }
    }
}

impl metrics::Source for UnsupportedNlriMetrics {
    fn append(&self, _unit_name: &str, target: &mut metrics::Target) {
        const DROPPED_METRIC: metrics::Metric = metrics::Metric::new(
            "unsupported_nlri_dropped",
            "routes dropped because their NLRI type (AFI/SAFI, or its ADD-PATH \
             encoding) has no internal representation and cannot be stored in \
             any RIB",
            metrics::MetricType::Counter,
            metrics::MetricUnit::Total,
        );

        // Snapshot under the lock, render outside it.
        let totals: Vec<(NlriType, u64)> = {
            let inner = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            inner.totals.clone()
        };

        if totals.is_empty() {
            return;
        }

        // One HELP/TYPE block, one labelled row per NLRI type, e.g.
        // netom_unsupported_nlri_dropped_total{nlri_type="Ipv4FlowSpecAddpath"}.
        target.append(&DROPPED_METRIC, None, |records| {
            for (nlri_type, count) in &totals {
                let nlri_type = format!("{nlri_type:?}");
                records.label_value(
                    &[("nlri_type", nlri_type.as_str())],
                    *count,
                );
            }
        });
    }
}

static UNSUPPORTED_NLRI: LazyLock<Arc<UnsupportedNlriMetrics>> =
    LazyLock::new(|| Arc::new(UnsupportedNlriMetrics::default()));

/// Returns the process-global unsupported-NLRI accounting handle so the manager
/// can register it as a [`metrics::Source`]. The `LazyLock` keeps a strong
/// reference for the life of the process, so the `Weak` held by the metrics
/// collection never dangles.
pub fn unsupported_nlri_metrics() -> Arc<UnsupportedNlriMetrics> {
    UNSUPPORTED_NLRI.clone()
}

/// Record one NLRI dropped because its [`NlriType`] has no [`RotondaRoute`]
/// representation. Called from the shared [`convert_nlri`] drop path; bumps
/// the Prometheus counter and drives the throttled `warn!` logging.
fn note_unsupported_nlri(nlri_type: NlriType) {
    UNSUPPORTED_NLRI.note(nlri_type, Instant::now());
}

/// Convert one parsed NLRI plus its path attributes into the stored
/// [`RotondaRoute`] form.
///
/// ADD-PATH (RFC 7911) unicast/multicast/flowspec variants convert to the
/// same plain variants — the store key has no path-id representation — and
/// the stripped [`PathId`] is returned alongside so the caller can resolve a
/// per-(session, path_id) child ingress to store the route under. Plain
/// variants return `None`. NLRI types with no `RotondaRoute` representation
/// (MPLS/VPN/EVPN/VPLS/RouteTarget) are counted and dropped as before.
pub(crate) fn convert_nlri<O: AsRef<[u8]>>(
    nlri: Nlri<O>,
    pamap: RotondaPaMap,
) -> Result<(RotondaRoute, Option<PathId>), ()> {
    use routecore::bgp::nlri::afisafi::Addpath;

    let res = match nlri {
        Nlri::Ipv4Unicast(n) => (RotondaRoute::Ipv4Unicast(n, pamap), None),
        Nlri::Ipv4Multicast(n) => {
            (RotondaRoute::Ipv4Multicast(n, pamap), None)
        }
        Nlri::Ipv6Unicast(n) => (RotondaRoute::Ipv6Unicast(n, pamap), None),
        Nlri::Ipv6Multicast(n) => {
            (RotondaRoute::Ipv6Multicast(n, pamap), None)
        }
        Nlri::Ipv4UnicastAddpath(n) => {
            let pid = n.path_id();
            (RotondaRoute::Ipv4Unicast(n.into(), pamap), Some(pid))
        }
        Nlri::Ipv4MulticastAddpath(n) => {
            let pid = n.path_id();
            (RotondaRoute::Ipv4Multicast(n.into(), pamap), Some(pid))
        }
        Nlri::Ipv6UnicastAddpath(n) => {
            let pid = n.path_id();
            (RotondaRoute::Ipv6Unicast(n.into(), pamap), Some(pid))
        }
        Nlri::Ipv6MulticastAddpath(n) => {
            let pid = n.path_id();
            (RotondaRoute::Ipv6Multicast(n.into(), pamap), Some(pid))
        }
        // Copy the flowspec NLRI out of the (possibly borrowed) octets
        // into owned Bytes; identity is the raw NLRI bytes. The ADD-PATH
        // variants strip their path id like unicast/multicast above.
        Nlri::Ipv4FlowSpec(n) => (
            RotondaRoute::Ipv4FlowSpec(
                n.nlri().to_owned_octets::<bytes::Bytes>().into(),
                pamap,
            ),
            None,
        ),
        Nlri::Ipv6FlowSpec(n) => (
            RotondaRoute::Ipv6FlowSpec(
                n.nlri().to_owned_octets::<bytes::Bytes>().into(),
                pamap,
            ),
            None,
        ),
        Nlri::Ipv4FlowSpecAddpath(n) => {
            let pid = n.path_id();
            (
                RotondaRoute::Ipv4FlowSpec(
                    n.nlri().to_owned_octets::<bytes::Bytes>().into(),
                    pamap,
                ),
                Some(pid),
            )
        }
        Nlri::Ipv6FlowSpecAddpath(n) => {
            let pid = n.path_id();
            (
                RotondaRoute::Ipv6FlowSpec(
                    n.nlri().to_owned_octets::<bytes::Bytes>().into(),
                    pamap,
                ),
                Some(pid),
            )
        }

        Nlri::Ipv4MplsUnicast(..)
        | Nlri::Ipv4MplsUnicastAddpath(..)
        | Nlri::Ipv4MplsVpnUnicast(..)
        | Nlri::Ipv4MplsVpnUnicastAddpath(..)
        | Nlri::Ipv4RouteTarget(..)
        | Nlri::Ipv4RouteTargetAddpath(..)
        | Nlri::Ipv6MplsUnicast(..)
        | Nlri::Ipv6MplsUnicastAddpath(..)
        | Nlri::Ipv6MplsVpnUnicast(..)
        | Nlri::Ipv6MplsVpnUnicastAddpath(..)
        | Nlri::L2VpnVpls(..)
        | Nlri::L2VpnVplsAddpath(..)
        | Nlri::L2VpnEvpn(..)
        | Nlri::L2VpnEvpnAddpath(..) => {
            note_unsupported_nlri(nlri.nlri_type());
            debug!(
                "NLRI type {:?} not yet supported in RotondaRoute: {}",
                nlri.nlri_type(),
                nlri
            );
            return Err(());
        }
    };

    Ok(res)
}

/// Explode a BGP UPDATE's announcements into storable routes.
///
/// Each entry carries the RFC 7911 path id when the NLRI was an ADD-PATH
/// variant (`None` otherwise) so the caller can resolve the per-path child
/// ingress to store the route under.
pub(crate) fn explode_announcements(
    bgp_update: &UpdateMessage<impl routecore::Octets>,
) -> Result<Vec<(RotondaRoute, Option<PathId>)>, routecore::bgp::ParseError>
{
    let mut res = vec![];

    let pas = bgp_update.path_attributes()?;
    let pamap = RotondaPaMap::new(pas.into());

    for a in bgp_update.announcements()? {
        let a = a?;
        if let Ok(r) = convert_nlri(a, pamap.clone()) {
            res.push(r);
        } else {
            debug!("unsupported AFI/SAFI in explode_announcements");
        }
    }
    Ok(res)
}

/// Explode a BGP UPDATE's withdrawals into storable routes; see
/// [`explode_announcements`] for the path-id component.
pub(crate) fn explode_withdrawals(
    bgp_update: &UpdateMessage<impl routecore::Octets>,
) -> Result<Vec<(RotondaRoute, Option<PathId>)>, routecore::bgp::ParseError>
{
    let mut res = vec![];

    let pamap = RotondaPaMap::new(
        routecore::bgp::path_attributes::OwnedPathAttributes::new(
            bgp_update.pdu_parse_info(),
            vec![],
        ),
    );

    for w in bgp_update.withdrawals()? {
        let w = w?;
        if let Ok(r) = convert_nlri(w, pamap.clone()) {
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
    fn unsupported_nlri_counter_increments_and_renders() {
        let m = UnsupportedNlriMetrics::default();
        let now = Instant::now();
        // Two ADD-PATH MPLS drops (unsupported — AfiSafiType would collapse
        // these to plain Ipv4MplsUnicast) and one plain MPLS drop.
        m.note(NlriType::Ipv4MplsUnicastAddpath, now);
        m.note(NlriType::Ipv4MplsUnicastAddpath, now);
        m.note(NlriType::Ipv6MplsUnicast, now);

        let mut target =
            metrics::Target::new(metrics::OutputFormat::Prometheus);
        metrics::Source::append(&m, "unsupported_nlri", &mut target);
        let out = target.into_string();

        assert!(
            out.contains(
                "netom_unsupported_nlri_dropped_total\
                 {nlri_type=\"Ipv4MplsUnicastAddpath\"} 2"
            ),
            "missing MPLS ADD-PATH total in:\n{out}"
        );
        assert!(
            out.contains(
                "netom_unsupported_nlri_dropped_total\
                 {nlri_type=\"Ipv6MplsUnicast\"} 1"
            ),
            "missing MPLS total in:\n{out}"
        );
    }

    #[test]
    fn explode_surfaces_addpath_path_ids() {
        use std::str::FromStr;

        use routecore::bgp::message::update_builder::UpdateBuilder;
        use routecore::bgp::message::SessionConfig;
        use routecore::bgp::nlri::afisafi::{Ipv4UnicastNlri, IsPrefix};

        let prefix =
            inetnum::addr::Prefix::from_str("10.0.0.0/24").unwrap();

        // Two paths for one prefix, and an ADD-PATH withdrawal, built with
        // routecore's own encoder.
        let mut builder = UpdateBuilder::new_vec();
        builder
            .add_announcement(
                Ipv4UnicastNlri::try_from(prefix)
                    .unwrap()
                    .into_addpath(PathId(1)),
            )
            .unwrap();
        builder
            .add_announcement(
                Ipv4UnicastNlri::try_from(prefix)
                    .unwrap()
                    .into_addpath(PathId(2)),
            )
            .unwrap();
        // Parsing with ADD-PATH enabled for the family must surface the
        // stripped path ids next to plain-variant RotondaRoutes.
        let mut sc = SessionConfig::modern();
        sc.add_addpath_rxtx(AfiSafiType::Ipv4Unicast);
        let upd = builder.into_message(&sc).unwrap();

        let announced = explode_announcements(&upd).unwrap();
        assert_eq!(announced.len(), 2);
        let mut pids = vec![];
        for (rr, pid) in &announced {
            match rr {
                RotondaRoute::Ipv4Unicast(n, _) => {
                    assert_eq!(n.prefix(), prefix)
                }
                other => panic!("unexpected RotondaRoute {other:?}"),
            }
            pids.push(pid.expect("path id must be surfaced"));
        }
        pids.sort_unstable();
        assert_eq!(pids, [PathId(1), PathId(2)]);

        // Withdrawals carry the path id the same way.
        let mut builder = UpdateBuilder::new_vec();
        builder
            .append_withdrawals(vec![Ipv4UnicastNlri::try_from(prefix)
                .unwrap()
                .into_addpath(PathId(7))])
            .unwrap();
        let upd = builder.into_message(&sc).unwrap();

        let withdrawn = explode_withdrawals(&upd).unwrap();
        assert_eq!(withdrawn.len(), 1);
        assert_eq!(withdrawn[0].1, Some(PathId(7)));

        // A plain (non-ADD-PATH) message keeps yielding None.
        let mut builder = UpdateBuilder::new_vec();
        builder
            .add_announcement(Ipv4UnicastNlri::try_from(prefix).unwrap())
            .unwrap();
        let upd = builder.into_message(&SessionConfig::modern()).unwrap();
        let announced = explode_announcements(&upd).unwrap();
        assert_eq!(announced.len(), 1);
        assert_eq!(announced[0].1, None);
    }

    #[test]
    fn unsupported_nlri_metric_absent_until_first_drop() {
        let m = UnsupportedNlriMetrics::default();
        let mut target =
            metrics::Target::new(metrics::OutputFormat::Prometheus);
        metrics::Source::append(&m, "unsupported_nlri", &mut target);
        assert!(!target.into_string().contains("unsupported_nlri"));
    }
}
