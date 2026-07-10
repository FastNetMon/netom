//! FlowSpec rule storage.
//!
//! FlowSpec routes (RFC 8955/8956, SAFI 133) are keyed in a dedicated
//! `StarCastRib` on their destination-prefix component — or the family
//! default route when no usable destination prefix exists (absent component,
//! or an RFC 8956 pattern offset != 0). Several distinct rules can share one
//! destination prefix from one peer, and the store overwrites whole records
//! per `(prefix, mui)`, so the record value is a [`FlowSpecRuleSet`]: an
//! ordered list of rules encoded into one `Meta` byte blob, where each
//! rule's identity is its full raw NLRI bytes.
//!
//! Blob layout (all integers big-endian):
//!
//! ```text
//! blob  := ver:u8 (=1) , entry*
//! entry := flags:u8 , nlri_len:u16 , pa_len:u32 , nlri_bytes , pamap_raw
//! flags := bits 0-1: FlowSpecValidity; bits 2-7 reserved (0)
//! ```
//!
//! `nlri_bytes` is `FlowSpecNlri::raw()` (no length header; max 4095 bytes
//! per RFC 8955 §4.1, so `u16` is safe). `pamap_raw` is the full
//! `RotondaPaMap` backing bytes (rpki byte, pdu-parse-info byte, raw path
//! attribute blob), so a decoded entry needs nothing outside the blob.

use rotonda_store::prefix_record::Meta;
use rotonda_store::rib::config::MemoryOnlyConfig;
use rotonda_store::rib::StarCastRib;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, Weak};

use crate::metrics;
use crate::payload::RotondaPaMap;

pub type FlowSpecStore = StarCastRib<FlowSpecRuleSet, MemoryOnlyConfig>;

/// RFC 8955 §6 validation state of a stored FlowSpec rule.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FlowSpecValidity {
    /// Not (yet) validated.
    NotValidated = 0,
    /// Passed the RFC 8955 §6 originator/more-specifics checks.
    Valid = 1,
    /// Failed validation — the interesting signal for a monitor; stored,
    /// never rejected.
    Invalid = 2,
    /// Cannot be validated: no destination-prefix component, or an
    /// RFC 8956 pattern offset anchors the prefix mid-address.
    Unvalidatable = 3,
}

impl FlowSpecValidity {
    fn from_flags(flags: u8) -> Self {
        match flags & 0x03 {
            1 => FlowSpecValidity::Valid,
            2 => FlowSpecValidity::Invalid,
            3 => FlowSpecValidity::Unvalidatable,
            _ => FlowSpecValidity::NotValidated,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            FlowSpecValidity::NotValidated => "not-validated",
            FlowSpecValidity::Valid => "valid",
            FlowSpecValidity::Invalid => "invalid",
            FlowSpecValidity::Unvalidatable => "unvalidatable",
        }
    }
}

impl fmt::Display for FlowSpecValidity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One decoded rule out of a [`FlowSpecRuleSet`].
#[derive(Clone, Debug)]
pub struct FlowSpecRule {
    pub validity: FlowSpecValidity,
    /// Raw FlowSpec NLRI bytes (the rule identity).
    pub nlri: Vec<u8>,
    pub pamap: RotondaPaMap,
}

/// One `(store key, peer, rule)` row of a flowspec query, for the HTTP API.
#[derive(Clone, Debug)]
pub struct FlowSpecQueryRow {
    pub key_prefix: inetnum::addr::Prefix,
    pub ingress_id: crate::ingress::IngressId,
    pub rule: FlowSpecRule,
}

const BLOB_VERSION: u8 = 1;
const ENTRY_HEADER: usize = 1 + 2 + 4; // flags + nlri_len + pa_len

/// All FlowSpec rules of one `(dst-prefix, mui)`, as one store `Meta` blob.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FlowSpecRuleSet {
    raw: Vec<u8>,
}

impl FlowSpecRuleSet {
    /// Iterate the decoded rules. Tolerant: decoding stops silently at the
    /// first malformed entry (a truncated blob yields the entries before
    /// the truncation).
    pub fn iter(&self) -> FlowSpecRuleIter<'_> {
        let body = match self.raw.first() {
            Some(&BLOB_VERSION) => &self.raw[1..],
            _ => &[],
        };
        FlowSpecRuleIter { body, pos: 0 }
    }

    /// Add `nlri` with `pamap`, replacing any existing entry with the same
    /// NLRI. Returns `true` when an entry was replaced.
    pub fn upsert(
        &mut self,
        nlri: &[u8],
        pamap: &RotondaPaMap,
        validity: FlowSpecValidity,
    ) -> bool {
        let replaced = self.remove(nlri);
        if self.raw.is_empty() {
            self.raw.push(BLOB_VERSION);
        }
        let pa = pamap.raw_arc();
        self.raw.push(validity as u8);
        self.raw
            .extend_from_slice(&(nlri.len() as u16).to_be_bytes());
        self.raw
            .extend_from_slice(&(pa.len() as u32).to_be_bytes());
        self.raw.extend_from_slice(nlri);
        self.raw.extend_from_slice(&pa);
        replaced
    }

    /// Remove the entry whose NLRI equals `nlri`. Returns `true` when an
    /// entry was removed.
    pub fn remove(&mut self, nlri: &[u8]) -> bool {
        if self.raw.first() != Some(&BLOB_VERSION) {
            return false;
        }
        let mut pos = 0usize;
        let body_start = 1;
        let body = &self.raw[body_start..];
        while body.len() - pos >= ENTRY_HEADER {
            let nlri_len = u16::from_be_bytes([body[pos + 1], body[pos + 2]])
                as usize;
            let pa_len = u32::from_be_bytes([
                body[pos + 3],
                body[pos + 4],
                body[pos + 5],
                body[pos + 6],
            ]) as usize;
            let entry_len = ENTRY_HEADER + nlri_len + pa_len;
            if body.len() - pos < entry_len {
                break; // malformed tail
            }
            let nlri_start = pos + ENTRY_HEADER;
            if &body[nlri_start..nlri_start + nlri_len] == nlri {
                let abs = body_start + pos;
                self.raw.drain(abs..abs + entry_len);
                if self.raw.len() == 1 {
                    self.raw.clear();
                }
                return true;
            }
            pos += entry_len;
        }
        false
    }

    pub fn rule_count(&self) -> usize {
        self.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.raw.len() <= 1
    }

    /// Approximate heap size of the encoded blob, for memstat.
    pub fn byte_size(&self) -> usize {
        self.raw.len()
    }
}

pub struct FlowSpecRuleIter<'a> {
    body: &'a [u8],
    pos: usize,
}

impl Iterator for FlowSpecRuleIter<'_> {
    type Item = FlowSpecRule;

    fn next(&mut self) -> Option<FlowSpecRule> {
        let body = self.body;
        let pos = self.pos;
        if body.len().saturating_sub(pos) < ENTRY_HEADER {
            return None;
        }
        let flags = body[pos];
        let nlri_len =
            u16::from_be_bytes([body[pos + 1], body[pos + 2]]) as usize;
        let pa_len = u32::from_be_bytes([
            body[pos + 3],
            body[pos + 4],
            body[pos + 5],
            body[pos + 6],
        ]) as usize;
        let entry_len = ENTRY_HEADER + nlri_len + pa_len;
        if body.len() - pos < entry_len {
            return None; // malformed tail: stop
        }
        let nlri_start = pos + ENTRY_HEADER;
        let pa_start = nlri_start + nlri_len;
        let rule = FlowSpecRule {
            validity: FlowSpecValidity::from_flags(flags),
            nlri: body[nlri_start..pa_start].to_vec(),
            pamap: RotondaPaMap::from_raw(
                body[pa_start..pa_start + pa_len].to_vec(),
            ),
        };
        self.pos = pos + entry_len;
        Some(rule)
    }
}

impl AsRef<[u8]> for FlowSpecRuleSet {
    fn as_ref(&self) -> &[u8] {
        self.raw.as_ref()
    }
}

impl From<Vec<u8>> for FlowSpecRuleSet {
    fn from(value: Vec<u8>) -> Self {
        Self { raw: value }
    }
}

impl fmt::Display for FlowSpecRuleSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FlowSpecRuleSet({} rules)", self.rule_count())
    }
}

impl Meta for FlowSpecRuleSet {
    type Orderable<'a> = ();
    type TBI = ();

    fn as_orderable(&self, _tbi: Self::TBI) -> Self::Orderable<'_> {}
}

/// Re-frame raw flowspec NLRI bytes (the stored identity, without the
/// length header) with their RFC 8955 §4.1 length header and parse them —
/// for Display, ordering and validation purposes. `None` on malformed or
/// oversized bytes.
pub fn parse_raw_nlri(
    raw: &[u8],
    v4: bool,
) -> Option<routecore::bgp::nlri::flowspec::FlowSpecNlri<bytes::Bytes>> {
    use routecore::bgp::types::Afi;

    let len = raw.len();
    let mut wire = Vec::with_capacity(len + 2);
    if len >= 240 {
        wire.extend_from_slice(
            &(0xf000u16 | u16::try_from(len).ok().filter(|l| *l <= 4095)?)
                .to_be_bytes(),
        );
    } else {
        wire.push(len as u8);
    }
    wire.extend_from_slice(raw);
    let bytes = bytes::Bytes::from(wire);
    let mut parser = octseq::Parser::from_ref(&bytes);
    routecore::bgp::nlri::flowspec::FlowSpecNlri::parse(
        &mut parser,
        if v4 { Afi::Ipv4 } else { Afi::Ipv6 },
    )
    .ok()
}

/// Human-readable FlowSpec traffic actions (RFC 8955 §7 / RFC 8956 §5)
/// found in a rule's extended communities.
pub fn decode_actions(pamap: &RotondaPaMap) -> Vec<String> {
    use routecore::bgp::path_attributes::{
        ExtendedCommunitiesList, Ipv6ExtendedCommunitiesList,
    };

    let mut actions = Vec::new();
    let attrs = pamap.path_attributes();
    if let Some(list) = attrs.get::<ExtendedCommunitiesList>() {
        for ec in list.communities() {
            if let Some(action) = ec.flowspec() {
                actions.push(action.to_string());
            }
        }
    }
    if let Some(list) = attrs.get::<Ipv6ExtendedCommunitiesList>() {
        for ec in list.communities() {
            if let Some(action) = ec.flowspec() {
                actions.push(action.to_string());
            }
        }
    }
    actions
}

//------------ Metrics -------------------------------------------------------

/// Process-global FlowSpec accounting, modeled on `UnsupportedNlriMetrics`:
/// held alive by a `LazyLock`, registered once in the manager.
#[derive(Debug, Default)]
pub struct FlowSpecRuleCounts {
    v4: AtomicU64,
    v6: AtomicU64,
    /// Optimistic recount coordination. Writers never wait: lifecycle
    /// recounts retry when either value changes while they scan the store.
    active_writers: AtomicU64,
    generation: AtomicU64,
}

impl FlowSpecRuleCounts {
    pub fn begin_mutation(&self) -> FlowSpecRuleCountMutation<'_> {
        self.active_writers.fetch_add(1, Ordering::AcqRel);
        FlowSpecRuleCountMutation { counts: self }
    }

    pub fn add(&self, is_v4: bool, delta: i64) {
        let gauge = if is_v4 { &self.v4 } else { &self.v6 };
        if delta >= 0 {
            gauge.fetch_add(delta as u64, Ordering::Relaxed);
        } else {
            let amount = delta.unsigned_abs();
            let _ = gauge.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |current| Some(current.saturating_sub(amount)),
            );
        }
    }

    pub fn set(&self, v4: u64, v6: u64) {
        self.v4.store(v4, Ordering::Relaxed);
        self.v6.store(v6, Ordering::Relaxed);
    }

    pub fn recount_generation(&self) -> Option<u64> {
        if self.active_writers.load(Ordering::Acquire) != 0 {
            return None;
        }
        let generation = self.generation.load(Ordering::Acquire);
        (self.active_writers.load(Ordering::Acquire) == 0)
            .then_some(generation)
    }

    pub fn generation_is_quiescent(&self, generation: u64) -> bool {
        self.active_writers.load(Ordering::Acquire) == 0
            && self.generation.load(Ordering::Acquire) == generation
    }

    #[cfg(test)]
    pub fn snapshot(&self) -> (u64, u64) {
        (
            self.v4.load(Ordering::Relaxed),
            self.v6.load(Ordering::Relaxed),
        )
    }
}

pub struct FlowSpecRuleCountMutation<'a> {
    counts: &'a FlowSpecRuleCounts,
}

impl Drop for FlowSpecRuleCountMutation<'_> {
    fn drop(&mut self) {
        self.counts.generation.fetch_add(1, Ordering::Release);
        self.counts.active_writers.fetch_sub(1, Ordering::Release);
    }
}

#[derive(Debug, Default)]
pub struct FlowSpecMetrics {
    pub v4_announced: AtomicU64,
    pub v4_withdrawn: AtomicU64,
    pub v6_announced: AtomicU64,
    pub v6_withdrawn: AtomicU64,
    /// Per-RIB stored-rule contributions. The hot path updates only its local
    /// atomics; collection sums live RIBs and prunes dropped ones.
    rule_counts: Mutex<Vec<Weak<FlowSpecRuleCounts>>>,
}

impl FlowSpecMetrics {
    pub fn note_update(&self, is_v4: bool, withdrawn: bool) {
        let counter = match (is_v4, withdrawn) {
            (true, false) => &self.v4_announced,
            (true, true) => &self.v4_withdrawn,
            (false, false) => &self.v6_announced,
            (false, true) => &self.v6_withdrawn,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn register_rule_counts(&self) -> Arc<FlowSpecRuleCounts> {
        let counts = Arc::new(FlowSpecRuleCounts::default());
        self.rule_counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(Arc::downgrade(&counts));
        counts
    }

    fn rules(&self) -> (u64, u64) {
        let mut counts = self
            .rule_counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut v4 = 0u64;
        let mut v6 = 0u64;
        counts.retain(|weak| {
            let Some(count) = weak.upgrade() else {
                return false;
            };
            v4 = v4.saturating_add(count.v4.load(Ordering::Relaxed));
            v6 = v6.saturating_add(count.v6.load(Ordering::Relaxed));
            true
        });
        (v4, v6)
    }
}

impl metrics::Source for FlowSpecMetrics {
    fn append(&self, _unit_name: &str, target: &mut metrics::Target) {
        const UPDATES_METRIC: metrics::Metric = metrics::Metric::new(
            "flowspec_updates",
            "FlowSpec rule announcements and withdrawals ingested into \
             the flowspec store",
            metrics::MetricType::Counter,
            metrics::MetricUnit::Total,
        );
        const RULES_METRIC: metrics::Metric = metrics::Metric::new(
            "flowspec_rules_stored",
            "FlowSpec rules currently stored, per address family",
            metrics::MetricType::Gauge,
            metrics::MetricUnit::Total,
        );

        target.append(&UPDATES_METRIC, None, |records| {
            for (labels, value) in [
                (
                    [("afi", "ipv4"), ("op", "announce")],
                    self.v4_announced.load(Ordering::Relaxed),
                ),
                (
                    [("afi", "ipv4"), ("op", "withdraw")],
                    self.v4_withdrawn.load(Ordering::Relaxed),
                ),
                (
                    [("afi", "ipv6"), ("op", "announce")],
                    self.v6_announced.load(Ordering::Relaxed),
                ),
                (
                    [("afi", "ipv6"), ("op", "withdraw")],
                    self.v6_withdrawn.load(Ordering::Relaxed),
                ),
            ] {
                records.label_value(&labels, value);
            }
        });

        target.append(&RULES_METRIC, None, |records| {
            let (v4, v6) = self.rules();
            records.label_value(
                &[("afi", "ipv4")],
                v4,
            );
            records.label_value(
                &[("afi", "ipv6")],
                v6,
            );
        });
    }
}

static FLOWSPEC_METRICS: LazyLock<Arc<FlowSpecMetrics>> =
    LazyLock::new(|| Arc::new(FlowSpecMetrics::default()));

/// The process-global FlowSpec metrics handle; the `LazyLock` keeps the
/// strong reference alive so the manager's `Weak` never dangles.
pub fn flowspec_metrics() -> Arc<FlowSpecMetrics> {
    FLOWSPEC_METRICS.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pamap(fill: u8) -> RotondaPaMap {
        // rpki byte, ppi byte, then a fake attribute blob
        RotondaPaMap::from_raw(vec![0, 0, fill, fill, fill])
    }

    #[test]
    fn upsert_iter_remove_round_trip() {
        let mut rs = FlowSpecRuleSet::default();
        assert!(rs.is_empty());
        assert_eq!(rs.rule_count(), 0);

        let nlri_a = [0x01u8, 0x18, 10, 0, 1, 0x03, 0x81, 0x11];
        let nlri_b = [0x01u8, 0x18, 10, 0, 1, 0x05, 0x81, 0x35];

        assert!(!rs.upsert(&nlri_a, &pamap(0xaa), FlowSpecValidity::Valid));
        assert!(!rs.upsert(&nlri_b, &pamap(0xbb), FlowSpecValidity::Invalid));
        assert_eq!(rs.rule_count(), 2);

        let rules: Vec<_> = rs.iter().collect();
        assert_eq!(rules[0].nlri, nlri_a);
        assert_eq!(rules[0].validity, FlowSpecValidity::Valid);
        assert_eq!(rules[1].nlri, nlri_b);
        assert_eq!(rules[1].validity, FlowSpecValidity::Invalid);
        assert_eq!(rules[0].pamap.raw_arc()[2], 0xaa);

        // replace-by-NLRI
        assert!(rs.upsert(&nlri_a, &pamap(0xcc), FlowSpecValidity::Valid));
        assert_eq!(rs.rule_count(), 2);
        let rules: Vec<_> = rs.iter().collect();
        // replaced entry re-appends at the tail
        assert_eq!(rules[1].nlri, nlri_a);
        assert_eq!(rules[1].pamap.raw_arc()[2], 0xcc);

        assert!(rs.remove(&nlri_b));
        assert!(!rs.remove(&nlri_b));
        assert_eq!(rs.rule_count(), 1);
        assert!(rs.remove(&nlri_a));
        assert!(rs.is_empty());
        assert_eq!(rs.as_ref().len(), 0);
    }

    #[test]
    fn store_meta_round_trip() {
        let mut rs = FlowSpecRuleSet::default();
        let nlri = [0x03u8, 0x81, 0x11];
        rs.upsert(&nlri, &pamap(0x42), FlowSpecValidity::Unvalidatable);
        // Simulate the store's AsRef<[u8]> -> From<Vec<u8>> round trip.
        let restored = FlowSpecRuleSet::from(rs.as_ref().to_vec());
        assert_eq!(restored, rs);
        let rules: Vec<_> = restored.iter().collect();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].nlri, nlri);
        assert_eq!(rules[0].validity, FlowSpecValidity::Unvalidatable);
    }

    #[test]
    fn hostile_bytes_do_not_panic() {
        // wrong version byte
        let rs = FlowSpecRuleSet::from(vec![9, 1, 2, 3]);
        assert_eq!(rs.rule_count(), 0);
        // truncated entry header
        let rs = FlowSpecRuleSet::from(vec![1, 0, 0]);
        assert_eq!(rs.rule_count(), 0);
        // entry longer than blob
        let rs = FlowSpecRuleSet::from(vec![1, 0, 0, 5, 0, 0, 0, 5, 1, 2]);
        assert_eq!(rs.rule_count(), 0);
        // valid entry followed by garbage tail
        let mut rs = FlowSpecRuleSet::default();
        rs.upsert(&[0x03, 0x81, 0x11], &pamap(1), FlowSpecValidity::Valid);
        let mut bytes = rs.as_ref().to_vec();
        bytes.extend_from_slice(&[0xff, 0xff]);
        let rs = FlowSpecRuleSet::from(bytes);
        assert_eq!(rs.rule_count(), 1);
        // remove on hostile bytes
        let mut rs = FlowSpecRuleSet::from(vec![9, 1, 2, 3]);
        assert!(!rs.remove(&[1, 2]));
    }

    #[test]
    fn metrics_sum_live_rib_rule_counts() {
        let metrics = FlowSpecMetrics::default();
        let first = metrics.register_rule_counts();
        let second = metrics.register_rule_counts();
        first.set(2, 3);
        second.set(5, 7);
        assert_eq!(metrics.rules(), (7, 10));

        drop(first);
        assert_eq!(metrics.rules(), (5, 7));
    }

    #[test]
    fn rule_counts_saturate_and_track_mutations() {
        let counts = FlowSpecRuleCounts::default();
        counts.add(true, -1);
        assert_eq!(counts.v4.load(Ordering::Relaxed), 0);

        let generation = counts.recount_generation().unwrap();
        {
            let _mutation = counts.begin_mutation();
            assert!(counts.recount_generation().is_none());
            counts.add(true, 1);
        }
        assert!(!counts.generation_is_quiescent(generation));
        assert_eq!(counts.v4.load(Ordering::Relaxed), 1);
    }
}
