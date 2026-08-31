//! BGP best path selection (RFC 4271 section 9.1) over the RIB's records.
//!
//! # Why this is not done in the store
//!
//! `rotonda-store` has a path-selection hook — `Meta::as_orderable`, driven by
//! `RecordMap::best_backup` — but it cannot express the RFC's decision process.
//! `best_backup` takes **one** [`TiebreakerInfo`] and applies it to every record
//! of a prefix, while `TiebreakerInfo` carries `peer_addr`, `bgp_identifier` and
//! the EBGP/IBGP `source`, all of which differ per record. Steps d, f and g of
//! RFC 4271 section 9.1.2.2 are therefore not computable that way.
//!
//! So selection happens here, at query time, where the ingress register supplies
//! per-record peer identity. See `docs/best-path-selection.md`.
//!
//! # What is delegated
//!
//! The ordering itself is `routecore::bgp::path_selection`: [`OrdRoute`] wraps a
//! `(TiebreakerInfo, &PaMap)` pair whose `Ord` *is* the decision process, with
//! [`Rfc4271`] or [`SkipMed`] selecting whether step c (MULTI_EXIT_DISC) counts.
//! This module only assembles candidates, resolves their tiebreakers, and
//! explains the outcome; it never re-implements the ranking.
//!
//! [`decisive_step`] does mirror routecore's comparison step by step, but purely
//! to name the step that separated two routes. A test asserts it agrees with
//! `OrdRoute`'s `Ord` on every pair it is given, so the explanation can never
//! drift from the ranking it explains.

use std::{cmp::Ordering, collections::HashMap, fmt, net::IpAddr, str::FromStr};

use inetnum::{addr::Prefix, asn::Asn};
use rotonda_store::prefix_record::{Record, RouteStatus};
use routecore::bgp::{
    aspath::{Hop, HopPath},
    path_attributes::{
        BgpIdentifier, ClusterIds, PaMap, PathAttribute, WireformatPathAttribute,
    },
    path_selection::{
        DecisionError, DegreeOfPreference, OrdRoute,
        RouteSource as OrdRouteSource, TiebreakerInfo,
    },
    types::{LocalPref, MultiExitDisc, Origin, OriginatorId},
};
use serde::{Serialize, Serializer};

use crate::{
    ingress::{IngressId, IngressInfo},
    payload::{RotondaPaMap, RotondaPaMapWithQueryFilter},
    units::rib_unit::{rib::RouteSource, QueryFilter},
};

//------------ Query options -------------------------------------------------

/// Which `OrdStrat` the decision process runs with.
///
/// `SkipMed` drops step c entirely, matching deployments that do not compare
/// MULTI_EXIT_DISC at all. There is no "always-compare-MED" strategy: routecore
/// offers only these two.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Strategy {
    #[default]
    Rfc4271,
    SkipMed,
}

impl Strategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Strategy::Rfc4271 => "rfc4271",
            Strategy::SkipMed => "skipMed",
        }
    }
}

impl Serialize for Strategy {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl FromStr for Strategy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "rfc4271" => Ok(Strategy::Rfc4271),
            "skipMed" | "skipmed" => Ok(Strategy::SkipMed),
            other => Err(format!(
                "unknown strategy '{other}', expected rfc4271 or skipMed"
            )),
        }
    }
}

/// How many ranked alternatives to report below the best path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Alternatives {
    #[default]
    All,
    AtMost(usize),
}

impl FromStr for Alternatives {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "all" {
            return Ok(Alternatives::All);
        }
        s.parse::<usize>().map(Alternatives::AtMost).map_err(|_| {
            format!("alternatives must be a number or 'all', got '{s}'")
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BestPathOptions {
    pub strategy: Strategy,
    pub alternatives: Alternatives,
}

//------------ Decision steps ------------------------------------------------

/// The step of the decision process at which two routes stopped being equal.
///
/// Phase 1 plus RFC 4271 section 9.1.2.2 steps a-g, with the two RFC 4456
/// additions: `BgpIdentifier` covers step f including the ORIGINATOR_ID
/// substitution, and `ClusterListLength` is the rule inserted between f and g.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionStep {
    /// Phase 1 degree of preference (LOCAL_PREF for IBGP routes).
    DegreeOfPreference,
    /// Step a: fewest AS numbers in AS_PATH.
    AsPathLength,
    /// Step b: lowest ORIGIN.
    Origin,
    /// Step c: lowest MULTI_EXIT_DISC, within one neighbour AS.
    Med,
    /// Step d: EBGP preferred over IBGP.
    PeerType,
    /// Step e: lowest interior cost. Never constructed: routecore's
    /// `OrdStrat::step_e` defaults to `Equal` and neither strategy overrides
    /// it, and netom has no IGP view to override it with. Named so the enum
    /// is the RFC's list rather than a subset of it, and so that filling the
    /// gap later does not change the API's vocabulary.
    #[allow(dead_code)]
    InteriorCost,
    /// Step f: lowest BGP Identifier, or ORIGINATOR_ID when present.
    BgpIdentifier,
    /// RFC 4456: shortest CLUSTER_LIST, between steps f and g.
    ClusterListLength,
    /// Step g: lowest peer address.
    PeerAddress,
    /// Every step compared equal. Two records for one prefix from one peer
    /// with identical attributes, which the RFC's algorithm does not expect.
    Tie,
}

impl DecisionStep {
    pub fn as_str(self) -> &'static str {
        match self {
            DecisionStep::DegreeOfPreference => "degreeOfPreference",
            DecisionStep::AsPathLength => "asPathLength",
            DecisionStep::Origin => "origin",
            DecisionStep::Med => "med",
            DecisionStep::PeerType => "peerType",
            DecisionStep::InteriorCost => "interiorCost",
            DecisionStep::BgpIdentifier => "bgpIdentifier",
            DecisionStep::ClusterListLength => "clusterListLength",
            DecisionStep::PeerAddress => "peerAddress",
            DecisionStep::Tie => "tie",
        }
    }
}

impl Serialize for DecisionStep {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl fmt::Display for DecisionStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

//------------ Ineligibility -------------------------------------------------

/// Why a stored record was not a candidate for selection.
///
/// The first two are netom's own: without a register entry, or without a peer
/// address, steps d/f/g have no inputs, and ranking the route anyway would mean
/// inventing an identity for it. The rest are routecore's `DecisionError`,
/// which is RFC 4271 section 9.1.2's requirement that a candidate carry the
/// mandatory attributes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IneligibleReason {
    /// The record's mui has no entry in the ingress register.
    UnknownIngress,
    /// The session is known but has no remote address recorded.
    UnknownPeerAddress,
    /// The path attribute blob would not parse.
    MalformedPathAttributes,
    /// Mandatory ORIGIN missing.
    MissingOrigin,
    /// Mandatory AS_PATH missing.
    MissingAsPath,
    /// An EBGP route whose AS_PATH has no neighbour ASN.
    EbgpWithoutNeighbour,
    /// The AS_PATH contains the local AS (RFC 4271 section 9.1.2).
    AsPathLoop,
}

impl IneligibleReason {
    pub fn as_str(self) -> &'static str {
        match self {
            IneligibleReason::UnknownIngress => "unknownIngress",
            IneligibleReason::UnknownPeerAddress => "unknownPeerAddress",
            IneligibleReason::MalformedPathAttributes => {
                "malformedPathAttributes"
            }
            IneligibleReason::MissingOrigin => "missingOrigin",
            IneligibleReason::MissingAsPath => "missingAsPath",
            IneligibleReason::EbgpWithoutNeighbour => "ebgpWithoutNeighbour",
            IneligibleReason::AsPathLoop => "asPathLoop",
        }
    }
}

impl Serialize for IneligibleReason {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

/// A tiebreaker input that had to be guessed because the register did not
/// carry it. Reported per candidate so a ranking is never silently based on
/// invented data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Assumed {
    /// No local ASN on the session, so EBGP vs IBGP (step d) could not be
    /// determined; the route was treated as EBGP.
    RouteSource,
    /// No BGP Identifier for the peer, so step f used 255.255.255.255 — an
    /// unknown identifier loses a tie rather than winning it.
    BgpIdentifier,
}

impl Assumed {
    fn as_str(self) -> &'static str {
        match self {
            Assumed::RouteSource => "routeSource",
            Assumed::BgpIdentifier => "bgpIdentifier",
        }
    }
}

impl Serialize for Assumed {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

/// The BGP Identifier used when the peer's is unknown.
///
/// Step f prefers the *lower* identifier, so the maximum value means an
/// unknown identity can never win the tie-break by default.
const UNKNOWN_BGP_ID: [u8; 4] = [0xff; 4];

/// Stands in for a session's local ASN when it was never recorded. AS 0 is
/// reserved by RFC 7607 and never appears as a real neighbour.
fn unknown_asn() -> Asn {
    Asn::from_u32(0)
}

//------------ Candidates ----------------------------------------------------

/// One record, with the decision-process inputs resolved.
///
/// `pa_map` is owned because [`OrdRoute`] borrows it; the candidate list must
/// outlive the `OrdRoute`s built from it.
pub(crate) struct Candidate {
    pub(crate) mui: IngressId,
    pub(crate) status: RouteStatus,
    pub(crate) pamap: RotondaPaMap,
    pub(crate) pa_map: PaMap,
    pub(crate) route_source: OrdRouteSource,
    pub(crate) local_asn: Asn,
    pub(crate) bgp_identifier: [u8; 4],
    pub(crate) peer_addr: IpAddr,
    pub(crate) assumed: Vec<Assumed>,
}

impl Candidate {
    fn tiebreakers(&self) -> TiebreakerInfo {
        TiebreakerInfo::new(
            self.route_source,
            // Left as None so routecore applies the RFC's own rule: LOCAL_PREF
            // counts for IBGP routes only. netom has no policy hook that would
            // set a degree of preference explicitly.
            None,
            self.local_asn,
            BgpIdentifier::from(self.bgp_identifier),
            self.peer_addr,
        )
    }

    /// Phase 1 degree of preference, resolved the way routecore's `Ord` does.
    fn degree_of_preference(&self) -> DegreeOfPreference {
        if self.route_source == OrdRouteSource::Ibgp {
            self.pa_map
                .get::<LocalPref>()
                .map(Into::into)
                .unwrap_or(DegreeOfPreference(0))
        } else {
            DegreeOfPreference(0)
        }
    }

    /// The neighbour AS used for MED comparability (step c), falling back to
    /// the local ASN exactly as routecore does when the leftmost AS_PATH hop
    /// is not a bare ASN (an AS_CONFED_SEQUENCE, say).
    fn neighbor_asn(&self) -> Asn {
        self.pa_map
            .get::<HopPath>()
            .and_then(|asp| asp.neighbor_path_selection())
            .unwrap_or(self.local_asn)
    }

    /// Step f's identifier: ORIGINATOR_ID when the route carries one (RFC
    /// 4456), otherwise the advertising peer's BGP Identifier.
    fn effective_bgp_id(&self) -> [u8; 4] {
        self.pa_map
            .get::<OriginatorId>()
            .map(|id| id.0.octets())
            .unwrap_or(self.bgp_identifier)
    }

    fn cluster_list_len(&self) -> usize {
        self.pa_map.get::<ClusterIds>().map(|l| l.len()).unwrap_or(0)
    }
}

/// A record that never entered the comparison.
pub(crate) struct Excluded {
    pub(crate) mui: IngressId,
    pub(crate) status: RouteStatus,
    pub(crate) pamap: RotondaPaMap,
    pub(crate) reason: IneligibleReason,
}

/// Turn one stored record into a candidate, or explain why it cannot be one.
///
/// `session_info` is the record's *session*, already resolved through
/// [`RouteSource`] so an ADD-PATH path-child inherits its parent's peer
/// identity — the child ingress carries only a parent id and a path id.
fn classify(
    record: &Record<RotondaPaMap>,
    session_info: Option<&IngressInfo>,
) -> Result<Candidate, Excluded> {
    let exclude = |reason| Excluded {
        mui: record.multi_uniq_id,
        status: record.status,
        pamap: record.meta.clone(),
        reason,
    };

    let Some(info) = session_info else {
        return Err(exclude(IneligibleReason::UnknownIngress));
    };
    let Some(peer_addr) = info.remote_addr else {
        return Err(exclude(IneligibleReason::UnknownPeerAddress));
    };

    let pa_map = match build_pa_map(&record.meta) {
        Some(pa_map) => pa_map,
        None => {
            return Err(exclude(IneligibleReason::MalformedPathAttributes))
        }
    };

    let mut assumed = Vec::new();

    // EBGP vs IBGP needs both ends of the session. `local_asn` is recorded at
    // session establishment (native BGP) or from the Peer Up's sent OPEN
    // (BMP); MRT replay has no local end at all, and neither did any session
    // registered by an older netom.
    let route_source = match (info.local_asn, info.remote_asn) {
        (Some(local), Some(remote)) if local == remote => OrdRouteSource::Ibgp,
        (Some(_), Some(_)) => OrdRouteSource::Ebgp,
        _ => {
            assumed.push(Assumed::RouteSource);
            OrdRouteSource::Ebgp
        }
    };

    // Step c falls back to the local ASN when a route's AS_PATH does not begin
    // with a bare ASN — an AS_SET or AS_CONFED_SEQUENCE — which is RFC 4271
    // step c's "it is the local AS" clause. When the local ASN is unknown the
    // fallback has to be the *same* value for every candidate, or two routes
    // that the RFC says share a neighbour AS would compare as if they did not,
    // and their MEDs would silently stop being weighed. AS 0 is reserved
    // (RFC 7607) and so can never collide with a real neighbour.
    let local_asn = info.local_asn.unwrap_or_else(unknown_asn);

    let bgp_identifier = match info.bgp_id {
        Some(id) => id,
        None => {
            assumed.push(Assumed::BgpIdentifier);
            UNKNOWN_BGP_ID
        }
    };

    let candidate = Candidate {
        mui: record.multi_uniq_id,
        status: record.status,
        pamap: record.meta.clone(),
        pa_map,
        route_source,
        local_asn,
        bgp_identifier,
        peer_addr,
        assumed,
    };

    // RFC 4271 section 9.1.2: a route whose AS_PATH contains the local AS is
    // excluded from Phase 2. Only checkable when the local ASN was recorded —
    // an MRT-replayed peer has no local end, so there is nothing to compare
    // against and the route is left in.
    //
    // "Local" is the local end of *that session*: for a BMP-monitored peer it
    // is the monitored router's ASN, which is what this reproduces the view
    // of. Excluded routes are reported in `ineligible`, so an operator can
    // still see a loop netom rejected rather than wondering where it went.
    //
    // Checked *before* routecore's eligibility, which would otherwise claim a
    // looped path that begins with an AS_SET or AS_CONFED_SEQUENCE as
    // `EbgpWithoutNeighbour`. Both exclude the route; the loop is the more
    // specific and more actionable answer.
    if let (Some(local), Some(path)) =
        (info.local_asn, candidate.pa_map.get::<HopPath>())
    {
        if as_path_contains(&path, local) {
            return Err(exclude(IneligibleReason::AsPathLoop));
        }
    }

    if let Err(reason) = check_eligible(&candidate) {
        return Err(exclude(reason));
    }

    Ok(candidate)
}

/// Whether `asn` appears anywhere in the AS_PATH.
///
/// RFC 4271 section 9.1.2 excludes a route from Phase 2 when its AS_PATH
/// contains the local AS, and says the check scans the *full* path — so
/// AS_SET, AS_CONFED_SEQUENCE and AS_CONFED_SET members count, not just the
/// bare hops of an AS_SEQUENCE.
fn as_path_contains(path: &HopPath, asn: Asn) -> bool {
    path.iter().any(|hop| match hop {
        Hop::Asn(hop_asn) => *hop_asn == asn,
        Hop::Segment(segment) => segment.asns().any(|a| a == asn),
    })
}

/// Build a [`PaMap`] from a stored attribute blob.
///
/// Mirrors `PaMap::from_update_pdu`: every wire-format attribute is parsed and
/// owned into the map. Returns `None` if any attribute fails to parse, which
/// makes the whole record ineligible — a route whose attributes cannot be read
/// cannot be ranked on them.
fn build_pa_map(pamap: &RotondaPaMap) -> Option<PaMap> {
    let mut out = PaMap::empty();
    for pa in pamap.path_attributes_ref() {
        let pa: WireformatPathAttribute<'_, _> = pa.ok()?;
        let owned: PathAttribute = pa.to_owned().ok()?;
        out.attributes_mut().insert(owned.type_code(), owned);
    }
    Some(out)
}

/// Map routecore's `DecisionError` onto our reason enum.
///
/// `DecisionError` exposes no discriminant, so its `Display` string is the
/// only thing to match on. Each arm is one of the three conditions
/// `OrdRoute::eligible` checks.
fn ineligible_reason(err: DecisionError) -> IneligibleReason {
    let msg = err.to_string();
    if msg.contains("ORIGIN") {
        IneligibleReason::MissingOrigin
    } else if msg.contains("missing mandatory AS_PATH") {
        IneligibleReason::MissingAsPath
    } else {
        IneligibleReason::EbgpWithoutNeighbour
    }
}

/// Whether routecore would accept this candidate into the decision process.
///
/// Eligibility is strategy-independent: it checks ORIGIN and AS_PATH, neither
/// of which step c touches. Running it up front means a route missing a
/// mandatory attribute is reported as ineligible rather than panicking step a
/// ("can not compare routes lacking AS_PATH") during the sort.
fn check_eligible(candidate: &Candidate) -> Result<(), IneligibleReason> {
    OrdRoute::rfc4271(&candidate.pa_map, candidate.tiebreakers())
        .map(|_| ())
        .map_err(ineligible_reason)
}

/// Order two candidates with routecore's `Ord` — the authoritative ranking.
///
/// The strategy has to be chosen when the wrappers are *built*, because it is
/// a type parameter that drives `Ord`. `OrdRoute::from_strat` only re-tags the
/// `PhantomData`, so converting a `SkipMed` wrapper into an `Rfc4271` one
/// silently reinstates the MED comparison; the two arms below are therefore
/// not interchangeable.
fn compare(
    a: &Candidate,
    b: &Candidate,
    strategy: Strategy,
) -> Result<Ordering, IneligibleReason> {
    match strategy {
        Strategy::Rfc4271 => {
            let x = OrdRoute::rfc4271(&a.pa_map, a.tiebreakers())
                .map_err(ineligible_reason)?;
            let y = OrdRoute::rfc4271(&b.pa_map, b.tiebreakers())
                .map_err(ineligible_reason)?;
            Ok(x.cmp(&y))
        }
        Strategy::SkipMed => {
            let x = OrdRoute::skip_med(&a.pa_map, a.tiebreakers())
                .map_err(ineligible_reason)?;
            let y = OrdRoute::skip_med(&b.pa_map, b.tiebreakers())
                .map_err(ineligible_reason)?;
            Ok(x.cmp(&y))
        }
    }
}

//------------ Comparison ----------------------------------------------------

/// Compare two candidates and name the step that separated them.
///
/// This mirrors the `Ord` impl of [`OrdRoute`] step for step. It exists only to
/// *explain* an outcome — [`select`] ranks with routecore's `Ord`, never with
/// this. `best_path_explanation_matches_routecore_ordering` in the tests
/// asserts the two agree, so the explanation cannot drift from the ranking.
pub(crate) fn decisive_step(
    a: &Candidate,
    b: &Candidate,
    strategy: Strategy,
) -> (Ordering, DecisionStep) {
    // Phase 1: higher degree of preference wins, so the comparison is
    // reversed relative to the tie-breakers below.
    let ord = b.degree_of_preference().cmp(&a.degree_of_preference());
    if ord != Ordering::Equal {
        return (ord, DecisionStep::DegreeOfPreference);
    }

    // Step a: fewest AS numbers, an AS_SET counting as one. Both sides are
    // known to carry an AS_PATH: `classify` rejected any route without one.
    let ord = match (a.pa_map.get::<HopPath>(), b.pa_map.get::<HopPath>()) {
        (Some(x), Some(y)) => {
            x.hop_count_path_selection().cmp(&y.hop_count_path_selection())
        }
        _ => Ordering::Equal,
    };
    if ord != Ordering::Equal {
        return (ord, DecisionStep::AsPathLength);
    }

    // Step b: lowest ORIGIN.
    let ord = match (a.pa_map.get::<Origin>(), b.pa_map.get::<Origin>()) {
        (Some(x), Some(y)) => x.cmp(&y),
        _ => Ordering::Equal,
    };
    if ord != Ordering::Equal {
        return (ord, DecisionStep::Origin);
    }

    // Step c: lowest MED, comparable only within one neighbour AS. A missing
    // MED is the lowest possible value (0), per RFC 4271.
    if strategy == Strategy::Rfc4271 && a.neighbor_asn() == b.neighbor_asn() {
        let a_med = a.pa_map.get::<MultiExitDisc>().unwrap_or(MultiExitDisc(0));
        let b_med = b.pa_map.get::<MultiExitDisc>().unwrap_or(MultiExitDisc(0));
        let ord = a_med.cmp(&b_med);
        if ord != Ordering::Equal {
            return (ord, DecisionStep::Med);
        }
    }

    // Step d: EBGP over IBGP.
    let ord = a.route_source.cmp(&b.route_source);
    if ord != Ordering::Equal {
        return (ord, DecisionStep::PeerType);
    }

    // Step e (interior cost) is a no-op in routecore's strategies and has no
    // inputs here either, so it never decides.

    // Step f: lowest BGP Identifier, ORIGINATOR_ID substituted when present.
    let ord = a.effective_bgp_id().cmp(&b.effective_bgp_id());
    if ord != Ordering::Equal {
        return (ord, DecisionStep::BgpIdentifier);
    }

    // RFC 4456, between f and g: shortest CLUSTER_LIST.
    let ord = a.cluster_list_len().cmp(&b.cluster_list_len());
    if ord != Ordering::Equal {
        return (ord, DecisionStep::ClusterListLength);
    }

    // Step g: lowest peer address.
    let ord = a.peer_addr.cmp(&b.peer_addr);
    if ord != Ordering::Equal {
        return (ord, DecisionStep::PeerAddress);
    }

    (Ordering::Equal, DecisionStep::Tie)
}

//------------ Result --------------------------------------------------------

/// A ranked route, with the step that placed it there.
pub(crate) struct Ranked {
    pub(crate) rank: usize,
    /// For the best path, the step that separated it from the runner-up. For
    /// an alternative, the step at which it lost to the best path. `None` when
    /// there is nothing to compare against (a single candidate).
    pub(crate) step: Option<DecisionStep>,
    pub(crate) candidate: Candidate,
}

pub struct BestPathResult {
    pub(crate) prefix: Option<Prefix>,
    /// Set only for the longest-prefix-match form, echoing what was asked for.
    pub(crate) query_addr: Option<IpAddr>,
    pub(crate) exact_match: bool,
    pub(crate) strategy: Strategy,
    pub(crate) best: Option<Ranked>,
    pub(crate) alternatives: Vec<Ranked>,
    pub(crate) excluded: Vec<Excluded>,
    pub(crate) total: usize,
    pub(crate) ingress_info: HashMap<IngressId, IngressInfo>,
    pub(crate) query_filter: QueryFilter,
}

/// Run the decision process over one prefix's records.
pub(crate) fn select(
    records: &[Record<RotondaPaMap>],
    ingress_info: &HashMap<IngressId, IngressInfo>,
    options: BestPathOptions,
) -> (Option<Ranked>, Vec<Ranked>, Vec<Excluded>) {
    let mut candidates = Vec::new();
    let mut excluded = Vec::new();

    for record in records {
        // Resolve through the session: an ADD-PATH child holds no peer
        // identity of its own, only a parent id and a path id.
        let source = RouteSource::resolve(
            record.multi_uniq_id,
            ingress_info.get(&record.multi_uniq_id),
        );
        let session_info = ingress_info.get(&source.ingress_id);

        match classify(record, session_info) {
            Ok(candidate) => candidates.push(candidate),
            Err(ex) => excluded.push(ex),
        }
    }

    if candidates.is_empty() {
        return (None, Vec::new(), excluded);
    }

    // Rank with routecore's `Ord`. The index is carried alongside so the
    // winner can be mapped back to its candidate, and breaks the residual tie
    // between records the decision process considers identical, making the
    // order stable rather than dependent on sort internals.
    let mut order: Vec<usize> = (0..candidates.len()).collect();
    order.sort_by(|&x, &y| {
        // Both passed `check_eligible` in `classify`, so `compare` cannot
        // fail here; falling back to the index keeps the sort total if it
        // somehow did.
        compare(&candidates[x], &candidates[y], options.strategy)
            .unwrap_or(Ordering::Equal)
            .then(x.cmp(&y))
    });

    // Move the candidates out in ranked order without cloning: take them by
    // swapping in placeholders is awkward for a non-Default type, so build a
    // map from the original index instead.
    let mut by_index: Vec<Option<Candidate>> =
        candidates.into_iter().map(Some).collect();

    let best_idx = order[0];
    let best_candidate = by_index[best_idx].take().expect("best taken once");

    // The best path's own step is what separated it from the runner-up.
    let decided_by = order.get(1).map(|&second| {
        decisive_step(
            &best_candidate,
            by_index[second].as_ref().expect("runner-up present"),
            options.strategy,
        )
        .1
    });

    let mut alternatives = Vec::new();
    let wanted = match options.alternatives {
        Alternatives::All => usize::MAX,
        Alternatives::AtMost(n) => n,
    };

    for (rank, &idx) in order.iter().enumerate().skip(1) {
        if alternatives.len() >= wanted {
            break;
        }
        let candidate = by_index[idx].take().expect("alternative taken once");
        // Each alternative is explained against the best path, not against
        // its neighbour in the ranking: "why is this not the best" is the
        // question an operator is asking.
        let (_, step) =
            decisive_step(&best_candidate, &candidate, options.strategy);
        alternatives.push(Ranked {
            rank: rank + 1,
            step: Some(step),
            candidate,
        });
    }

    let best = Ranked {
        rank: 1,
        step: decided_by,
        candidate: best_candidate,
    };

    (Some(best), alternatives, excluded)
}

//------------ Serialization -------------------------------------------------

/// One route row, in the same shape `/routes` emits, plus the ranking fields.
struct RowWrapper<'a> {
    result: &'a BestPathResult,
    rank: Option<usize>,
    step_key: &'static str,
    step: Option<DecisionStep>,
    reason: Option<IneligibleReason>,
    assumed: &'a [Assumed],
    mui: IngressId,
    status: RouteStatus,
    pamap: &'a RotondaPaMap,
}

impl Serialize for RowWrapper<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(None)?;
        if let Some(rank) = self.rank {
            map.serialize_entry("rank", &rank)?;
        }
        if let Some(step) = self.step {
            map.serialize_entry(self.step_key, &step)?;
        }
        if let Some(reason) = self.reason {
            map.serialize_entry("reason", &reason)?;
        }
        if !self.assumed.is_empty() {
            map.serialize_entry("assumed", self.assumed)?;
        }
        map.serialize_entry("status", &status_str(self.status))?;
        if let Some(info) = self.result.ingress_info.get(&self.mui) {
            map.serialize_entry(
                "ingress",
                &crate::ingress::register::IdAndInfo::from((self.mui, info)),
            )?;
        }
        map.serialize_entry(
            "source",
            &RouteSource::resolve(
                self.mui,
                self.result.ingress_info.get(&self.mui),
            ),
        )?;

        // The path attributes and rpki status flatten into this same object,
        // exactly as they do on `/routes`, so a row here is a superset of a
        // row there and existing renderers keep working.
        let filter = &self.result.query_filter;
        let value = if filter.fields_path_attributes.is_some() {
            serde_json::to_value(RotondaPaMapWithQueryFilter(self.pamap, filter))
        } else {
            serde_json::to_value(self.pamap)
        }
        .map_err(serde::ser::Error::custom)?;

        if let serde_json::Value::Object(fields) = value {
            for (k, v) in fields {
                map.serialize_entry(&k, &v)?;
            }
        }
        map.end()
    }
}

fn status_str(status: RouteStatus) -> &'static str {
    match status {
        RouteStatus::Active => "active",
        RouteStatus::InActive => "inactive",
        RouteStatus::Withdrawn => "withdrawn",
    }
}

impl BestPathResult {
    fn row<'a>(&'a self, ranked: &'a Ranked, step_key: &'static str) -> RowWrapper<'a> {
        RowWrapper {
            result: self,
            rank: Some(ranked.rank),
            step_key,
            step: ranked.step,
            reason: None,
            assumed: &ranked.candidate.assumed,
            mui: ranked.candidate.mui,
            status: ranked.candidate.status,
            pamap: &ranked.candidate.pamap,
        }
    }

    /// The winning route's store mui, for callers that only need the identity.
    pub fn best_mui(&self) -> Option<IngressId> {
        self.best.as_ref().map(|b| b.candidate.mui)
    }
}

impl Serialize for BestPathResult {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;

        let mut data = serializer.serialize_map(None)?;
        data.serialize_entry("nlri", &self.prefix)?;
        if let Some(addr) = self.query_addr {
            data.serialize_entry("queryAddress", &addr)?;
            data.serialize_entry(
                "matchType",
                if self.exact_match {
                    "exactMatch"
                } else {
                    "longestMatch"
                },
            )?;
        }
        data.serialize_entry("strategy", &self.strategy)?;

        let eligible =
            self.best.iter().count() + self.alternatives.len();
        data.serialize_entry(
            "counts",
            &Counts {
                total: self.total,
                // `alternatives` may be capped by the query, so eligible is
                // derived from the total rather than from what is rendered.
                eligible: self.total - self.excluded.len(),
                ineligible: self.excluded.len(),
                reported: eligible,
            },
        )?;

        match &self.best {
            Some(best) => {
                data.serialize_entry("best", &self.row(best, "decidedBy"))?
            }
            None => data.serialize_entry("best", &None::<()>)?,
        }

        let alternatives: Vec<_> = self
            .alternatives
            .iter()
            .map(|a| self.row(a, "lostAt"))
            .collect();
        data.serialize_entry("alternatives", &alternatives)?;

        let excluded: Vec<_> = self
            .excluded
            .iter()
            .map(|e| RowWrapper {
                result: self,
                rank: None,
                step_key: "lostAt",
                step: None,
                reason: Some(e.reason),
                assumed: &[],
                mui: e.mui,
                status: e.status,
                pamap: &e.pamap,
            })
            .collect();
        data.serialize_entry("ineligible", &excluded)?;

        data.end()
    }
}

#[derive(Serialize)]
struct Counts {
    total: usize,
    eligible: usize,
    ineligible: usize,
    /// How many eligible routes this response actually lists, which is lower
    /// than `eligible` when `alternatives=<n>` capped it.
    reported: usize,
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::IngressType;

    //--- Wire-format path attribute builders --------------------------------
    //
    // The decision process reads attributes out of the stored blob, so the
    // tests have to produce a real one rather than a mock: `RotondaPaMap`'s
    // raw layout is [rpki, ppi, attributes...], with ppi == 1 for
    // `PduParseInfo::modern()` (four-octet ASNs).

    fn pamap(parts: &[Vec<u8>]) -> RotondaPaMap {
        let mut raw = vec![0u8, 1u8];
        for part in parts {
            raw.extend_from_slice(part);
        }
        RotondaPaMap::from_raw(raw)
    }

    /// ORIGIN (type 1): 0 = IGP, 1 = EGP, 2 = INCOMPLETE.
    fn origin(value: u8) -> Vec<u8> {
        vec![0x40, 1, 1, value]
    }

    /// AS_PATH (type 2) as a single AS_SEQUENCE of four-octet ASNs.
    fn as_path(asns: &[u32]) -> Vec<u8> {
        as_path_segments(&[(SEQ, asns)])
    }

    // AS_PATH segment types (RFC 4271 section 4.3, RFC 5065 section 3).
    const SET: u8 = 1;
    const SEQ: u8 = 2;
    const CONFED_SEQ: u8 = 3;

    /// AS_PATH built from explicit segments, for the AS_SET and confederation
    /// cases where the segment type is the point.
    fn as_path_segments(segments: &[(u8, &[u32])]) -> Vec<u8> {
        let mut value = Vec::new();
        for (stype, asns) in segments {
            value.push(*stype);
            value.push(asns.len() as u8);
            for asn in *asns {
                value.extend_from_slice(&asn.to_be_bytes());
            }
        }
        let mut out = vec![0x40, 2, value.len() as u8];
        out.extend_from_slice(&value);
        out
    }

    fn med(value: u32) -> Vec<u8> {
        let mut out = vec![0x80, 4, 4];
        out.extend_from_slice(&value.to_be_bytes());
        out
    }

    fn local_pref(value: u32) -> Vec<u8> {
        let mut out = vec![0x40, 5, 4];
        out.extend_from_slice(&value.to_be_bytes());
        out
    }

    fn originator_id(id: [u8; 4]) -> Vec<u8> {
        let mut out = vec![0x80, 9, 4];
        out.extend_from_slice(&id);
        out
    }

    fn cluster_list(ids: &[[u8; 4]]) -> Vec<u8> {
        let mut out = vec![0x80, 10, (ids.len() * 4) as u8];
        for id in ids {
            out.extend_from_slice(id);
        }
        out
    }

    /// A plain, always-eligible route: IGP origin and a one-hop AS_PATH.
    fn plain(asns: &[u32]) -> RotondaPaMap {
        pamap(&[origin(0), as_path(asns)])
    }

    fn record(mui: IngressId, meta: RotondaPaMap) -> Record<RotondaPaMap> {
        Record::new(mui, 0, RouteStatus::Active, meta)
    }

    /// An EBGP session: local and remote ASN differ.
    fn ebgp(remote: u32, addr: &str, bgp_id: [u8; 4]) -> IngressInfo {
        IngressInfo::new()
            .with_ingress_type(IngressType::Bgp)
            .with_local_asn(Asn::from_u32(65000))
            .with_remote_asn(Asn::from_u32(remote))
            .with_remote_addr(addr.parse::<IpAddr>().unwrap())
            .with_bgp_id(bgp_id)
    }

    /// An IBGP session: local and remote ASN are the same.
    fn ibgp(addr: &str, bgp_id: [u8; 4]) -> IngressInfo {
        IngressInfo::new()
            .with_ingress_type(IngressType::Bgp)
            .with_local_asn(Asn::from_u32(65000))
            .with_remote_asn(Asn::from_u32(65000))
            .with_remote_addr(addr.parse::<IpAddr>().unwrap())
            .with_bgp_id(bgp_id)
    }

    fn registry(
        entries: Vec<(IngressId, IngressInfo)>,
    ) -> HashMap<IngressId, IngressInfo> {
        entries.into_iter().collect()
    }

    struct Outcome {
        best: Option<Ranked>,
        alternatives: Vec<Ranked>,
        excluded: Vec<Excluded>,
    }

    impl Outcome {
        fn best_mui(&self) -> IngressId {
            self.best.as_ref().expect("a best path").candidate.mui
        }

        fn decided_by(&self) -> Option<DecisionStep> {
            self.best.as_ref().expect("a best path").step
        }

        /// The ranking, best first.
        fn order(&self) -> Vec<IngressId> {
            self.best
                .iter()
                .map(|r| r.candidate.mui)
                .chain(self.alternatives.iter().map(|r| r.candidate.mui))
                .collect()
        }
    }

    fn run(
        records: &[Record<RotondaPaMap>],
        info: &HashMap<IngressId, IngressInfo>,
        strategy: Strategy,
    ) -> Outcome {
        let (best, alternatives, excluded) = select(
            records,
            info,
            BestPathOptions {
                strategy,
                alternatives: Alternatives::All,
            },
        );
        Outcome {
            best,
            alternatives,
            excluded,
        }
    }

    fn rfc4271(
        records: &[Record<RotondaPaMap>],
        info: &HashMap<IngressId, IngressInfo>,
    ) -> Outcome {
        run(records, info, Strategy::Rfc4271)
    }

    //--- The tie-breakers, in RFC order -------------------------------------

    /// Phase 1: LOCAL_PREF outranks everything below it, but only on IBGP
    /// routes — RFC 4271's degree of preference is computed from local policy
    /// for EBGP, and netom has no policy hook that sets one.
    #[test]
    fn local_pref_decides_between_ibgp_routes() {
        // mui 2 has the longer AS_PATH but the higher LOCAL_PREF, which is
        // evaluated first and therefore wins.
        let records = [
            record(1, pamap(&[origin(0), as_path(&[65001]), local_pref(100)])),
            record(
                2,
                pamap(&[origin(0), as_path(&[65001, 65002]), local_pref(200)]),
            ),
        ];
        let info = registry(vec![
            (1, ibgp("10.0.0.1", [10, 0, 0, 1])),
            (2, ibgp("10.0.0.2", [10, 0, 0, 2])),
        ]);

        let out = rfc4271(&records, &info);
        assert_eq!(out.best_mui(), 2);
        assert_eq!(out.decided_by(), Some(DecisionStep::DegreeOfPreference));
    }

    /// The same LOCAL_PREF on EBGP routes is ignored, so the shorter AS_PATH
    /// decides instead. This is the RFC's rule and it surprises people, so it
    /// is pinned explicitly.
    #[test]
    fn local_pref_is_ignored_on_ebgp_routes() {
        let records = [
            record(1, pamap(&[origin(0), as_path(&[65001]), local_pref(100)])),
            record(
                2,
                pamap(&[origin(0), as_path(&[65001, 65002]), local_pref(200)]),
            ),
        ];
        let info = registry(vec![
            (1, ebgp(65001, "10.0.0.1", [10, 0, 0, 1])),
            (2, ebgp(65001, "10.0.0.2", [10, 0, 0, 2])),
        ]);

        let out = rfc4271(&records, &info);
        assert_eq!(out.best_mui(), 1);
        assert_eq!(out.decided_by(), Some(DecisionStep::AsPathLength));
    }

    /// Step a.
    #[test]
    fn shortest_as_path_wins() {
        let records = [
            record(1, plain(&[65001, 65002, 65003])),
            record(2, plain(&[65001])),
            record(3, plain(&[65001, 65002])),
        ];
        let info = registry(vec![
            (1, ebgp(65001, "10.0.0.1", [10, 0, 0, 1])),
            (2, ebgp(65001, "10.0.0.2", [10, 0, 0, 2])),
            (3, ebgp(65001, "10.0.0.3", [10, 0, 0, 3])),
        ]);

        let out = rfc4271(&records, &info);
        assert_eq!(out.order(), vec![2, 3, 1]);
        assert_eq!(out.decided_by(), Some(DecisionStep::AsPathLength));
        // Every alternative is explained against the best path.
        assert!(out
            .alternatives
            .iter()
            .all(|a| a.step == Some(DecisionStep::AsPathLength)));
    }

    /// Step b: lowest ORIGIN, IGP(0) < EGP(1) < INCOMPLETE(2).
    #[test]
    fn lower_origin_breaks_an_as_path_tie() {
        let records = [
            record(1, pamap(&[origin(2), as_path(&[65001])])),
            record(2, pamap(&[origin(0), as_path(&[65001])])),
        ];
        let info = registry(vec![
            (1, ebgp(65001, "10.0.0.1", [10, 0, 0, 1])),
            (2, ebgp(65001, "10.0.0.2", [10, 0, 0, 2])),
        ]);

        let out = rfc4271(&records, &info);
        assert_eq!(out.best_mui(), 2);
        assert_eq!(out.decided_by(), Some(DecisionStep::Origin));
    }

    /// Step c: MED is only comparable within one neighbouring AS.
    #[test]
    fn med_decides_within_one_neighbour_as() {
        let records = [
            record(1, pamap(&[origin(0), as_path(&[65001]), med(200)])),
            record(2, pamap(&[origin(0), as_path(&[65001]), med(50)])),
        ];
        let info = registry(vec![
            (1, ebgp(65001, "10.0.0.1", [10, 0, 0, 1])),
            (2, ebgp(65001, "10.0.0.2", [10, 0, 0, 2])),
        ]);

        let out = rfc4271(&records, &info);
        assert_eq!(out.best_mui(), 2);
        assert_eq!(out.decided_by(), Some(DecisionStep::Med));
    }

    /// The same MEDs across *different* neighbour ASes must not be compared;
    /// the decision falls through to the peer address instead.
    #[test]
    fn med_is_not_compared_across_neighbour_ases() {
        let records = [
            record(1, pamap(&[origin(0), as_path(&[65001]), med(200)])),
            record(2, pamap(&[origin(0), as_path(&[65002]), med(50)])),
        ];
        let info = registry(vec![
            (1, ebgp(65001, "10.0.0.1", [10, 0, 0, 1])),
            (2, ebgp(65002, "10.0.0.2", [10, 0, 0, 2])),
        ]);

        let out = rfc4271(&records, &info);
        assert_ne!(out.decided_by(), Some(DecisionStep::Med));
        // Identical but for the MED and the neighbour AS, so step f (the
        // lower BGP Identifier) is what is left to decide it.
        assert_eq!(out.best_mui(), 1);
        assert_eq!(out.decided_by(), Some(DecisionStep::BgpIdentifier));
    }

    /// `strategy=skipMed` drops step c, so the route the RFC strategy rejects
    /// on its MED wins on the next criterion instead.
    #[test]
    fn skip_med_strategy_ignores_the_med() {
        let records = [
            record(1, pamap(&[origin(0), as_path(&[65001]), med(200)])),
            record(2, pamap(&[origin(0), as_path(&[65001]), med(50)])),
        ];
        let info = registry(vec![
            (1, ebgp(65001, "10.0.0.1", [10, 0, 0, 1])),
            (2, ebgp(65001, "10.0.0.2", [10, 0, 0, 2])),
        ]);

        assert_eq!(rfc4271(&records, &info).best_mui(), 2);

        let out = run(&records, &info, Strategy::SkipMed);
        assert_eq!(out.best_mui(), 1, "lower BGP id wins once MED is skipped");
        assert_eq!(out.decided_by(), Some(DecisionStep::BgpIdentifier));
    }

    /// Step d.
    #[test]
    fn ebgp_beats_ibgp() {
        let records =
            [record(1, plain(&[65001])), record(2, plain(&[65001]))];
        // The IBGP peer has the lower BGP Identifier and the lower address,
        // so only step d can put the EBGP route first.
        let info = registry(vec![
            (1, ibgp("10.0.0.1", [10, 0, 0, 1])),
            (2, ebgp(65001, "10.0.0.2", [10, 0, 0, 2])),
        ]);

        let out = rfc4271(&records, &info);
        assert_eq!(out.best_mui(), 2);
        assert_eq!(out.decided_by(), Some(DecisionStep::PeerType));
    }

    /// Step f with the RFC 4456 substitution: a reflected route is judged on
    /// the ORIGINATOR_ID of the speaker that first advertised it, not on the
    /// reflector's identifier.
    #[test]
    fn originator_id_substitutes_for_the_bgp_identifier() {
        let records = [
            record(1, plain(&[65001])),
            record(
                2,
                pamap(&[
                    origin(0),
                    as_path(&[65001]),
                    originator_id([10, 0, 0, 0]),
                ]),
            ),
        ];
        // Peer 1 has the lower BGP Identifier, but peer 2's route carries an
        // ORIGINATOR_ID lower than either, so it wins.
        let info = registry(vec![
            (1, ibgp("10.0.0.1", [10, 0, 0, 1])),
            (2, ibgp("10.0.0.2", [10, 0, 0, 2])),
        ]);

        let out = rfc4271(&records, &info);
        assert_eq!(out.best_mui(), 2);
        assert_eq!(out.decided_by(), Some(DecisionStep::BgpIdentifier));
    }

    /// RFC 4456's rule between steps f and g.
    #[test]
    fn shorter_cluster_list_wins() {
        let shared = originator_id([10, 0, 0, 9]);
        let records = [
            record(
                1,
                pamap(&[
                    origin(0),
                    as_path(&[65001]),
                    shared.clone(),
                    cluster_list(&[[1, 1, 1, 1], [2, 2, 2, 2]]),
                ]),
            ),
            record(
                2,
                pamap(&[
                    origin(0),
                    as_path(&[65001]),
                    shared,
                    cluster_list(&[[1, 1, 1, 1]]),
                ]),
            ),
        ];
        // Equal through step f thanks to the shared ORIGINATOR_ID.
        let info = registry(vec![
            (1, ibgp("10.0.0.1", [10, 0, 0, 1])),
            (2, ibgp("10.0.0.2", [10, 0, 0, 2])),
        ]);

        let out = rfc4271(&records, &info);
        assert_eq!(out.best_mui(), 2);
        assert_eq!(out.decided_by(), Some(DecisionStep::ClusterListLength));
    }

    /// Step g, the last resort.
    #[test]
    fn lowest_peer_address_decides_when_all_else_is_equal() {
        let records =
            [record(1, plain(&[65001])), record(2, plain(&[65001]))];
        // Identical BGP Identifiers (parallel sessions), so only the peer
        // address is left.
        let info = registry(vec![
            (1, ebgp(65001, "10.0.0.9", [10, 0, 0, 1])),
            (2, ebgp(65001, "10.0.0.2", [10, 0, 0, 1])),
        ]);

        let out = rfc4271(&records, &info);
        assert_eq!(out.best_mui(), 2);
        assert_eq!(out.decided_by(), Some(DecisionStep::PeerAddress));
    }

    //--- Eligibility --------------------------------------------------------

    #[test]
    fn a_route_without_origin_is_ineligible() {
        let records = [
            record(1, pamap(&[as_path(&[65001])])),
            record(2, plain(&[65001, 65002])),
        ];
        let info = registry(vec![
            (1, ebgp(65001, "10.0.0.1", [10, 0, 0, 1])),
            (2, ebgp(65001, "10.0.0.2", [10, 0, 0, 2])),
        ]);

        let out = rfc4271(&records, &info);
        assert_eq!(out.best_mui(), 2, "the only eligible route wins");
        assert_eq!(out.excluded.len(), 1);
        assert_eq!(out.excluded[0].mui, 1);
        assert_eq!(out.excluded[0].reason, IneligibleReason::MissingOrigin);
    }

    #[test]
    fn a_route_without_as_path_is_ineligible() {
        let records =
            [record(1, pamap(&[origin(0)])), record(2, plain(&[65001]))];
        let info = registry(vec![
            (1, ebgp(65001, "10.0.0.1", [10, 0, 0, 1])),
            (2, ebgp(65001, "10.0.0.2", [10, 0, 0, 2])),
        ]);

        let out = rfc4271(&records, &info);
        assert_eq!(out.best_mui(), 2);
        assert_eq!(out.excluded[0].reason, IneligibleReason::MissingAsPath);
    }

    /// An EBGP route must name a neighbour in its AS_PATH.
    #[test]
    fn an_ebgp_route_with_an_empty_as_path_is_ineligible() {
        let records =
            [record(1, pamap(&[origin(0), as_path(&[])])), record(2, plain(&[65001]))];
        let info = registry(vec![
            (1, ebgp(65001, "10.0.0.1", [10, 0, 0, 1])),
            (2, ebgp(65001, "10.0.0.2", [10, 0, 0, 2])),
        ]);

        let out = rfc4271(&records, &info);
        assert_eq!(out.best_mui(), 2);
        assert_eq!(
            out.excluded[0].reason,
            IneligibleReason::EbgpWithoutNeighbour
        );
    }

    /// A record whose mui is not in the register cannot be ranked: steps d, f
    /// and g have no inputs. It is reported rather than silently dropped.
    #[test]
    fn a_route_with_no_ingress_entry_is_ineligible() {
        let records =
            [record(1, plain(&[65001])), record(99, plain(&[65001]))];
        let info = registry(vec![(1, ebgp(65001, "10.0.0.1", [10, 0, 0, 1]))]);

        let out = rfc4271(&records, &info);
        assert_eq!(out.best_mui(), 1);
        assert_eq!(out.excluded.len(), 1);
        assert_eq!(out.excluded[0].mui, 99);
        assert_eq!(out.excluded[0].reason, IneligibleReason::UnknownIngress);
    }

    #[test]
    fn a_session_with_no_peer_address_is_ineligible() {
        let records =
            [record(1, plain(&[65001])), record(2, plain(&[65001]))];
        let info = registry(vec![
            (1, ebgp(65001, "10.0.0.1", [10, 0, 0, 1])),
            (
                2,
                IngressInfo::new()
                    .with_ingress_type(IngressType::Bgp)
                    .with_local_asn(Asn::from_u32(65000))
                    .with_remote_asn(Asn::from_u32(65001)),
            ),
        ]);

        let out = rfc4271(&records, &info);
        assert_eq!(out.best_mui(), 1);
        assert_eq!(
            out.excluded[0].reason,
            IneligibleReason::UnknownPeerAddress
        );
    }

    //--- Assumptions --------------------------------------------------------

    /// A session with no recorded local ASN cannot be classified EBGP or
    /// IBGP. It is still ranked (as EBGP), but says so.
    #[test]
    fn a_session_without_a_local_asn_reports_the_assumption() {
        let records = [record(1, plain(&[65001]))];
        let info = registry(vec![(
            1,
            IngressInfo::new()
                .with_ingress_type(IngressType::Mrt)
                .with_remote_asn(Asn::from_u32(65001))
                .with_remote_addr("10.0.0.1".parse::<IpAddr>().unwrap())
                .with_bgp_id([10, 0, 0, 1]),
        )]);

        let out = rfc4271(&records, &info);
        let best = out.best.as_ref().unwrap();
        assert_eq!(best.candidate.route_source, OrdRouteSource::Ebgp);
        assert!(best.candidate.assumed.contains(&Assumed::RouteSource));
    }

    /// An unknown BGP Identifier must lose step f rather than win it: the
    /// placeholder is the maximum value, and the assumption is reported.
    #[test]
    fn an_unknown_bgp_id_never_wins_step_f() {
        let records =
            [record(1, plain(&[65001])), record(2, plain(&[65001]))];
        let info = registry(vec![
            (
                1,
                IngressInfo::new()
                    .with_ingress_type(IngressType::Bgp)
                    .with_local_asn(Asn::from_u32(65000))
                    .with_remote_asn(Asn::from_u32(65001))
                    .with_remote_addr("10.0.0.1".parse::<IpAddr>().unwrap()),
            ),
            (2, ebgp(65001, "10.0.0.2", [200, 200, 200, 200])),
        ]);

        let out = rfc4271(&records, &info);
        assert_eq!(
            out.best_mui(),
            2,
            "the peer with a known identifier must win step f"
        );
        assert_eq!(out.decided_by(), Some(DecisionStep::BgpIdentifier));
        let loser = &out.alternatives[0].candidate;
        assert!(loser.assumed.contains(&Assumed::BgpIdentifier));
    }

    //--- ADD-PATH -----------------------------------------------------------

    /// Two paths from one ADD-PATH peer are stored under separate child muis
    /// and must compete as separate candidates, each inheriting the parent
    /// session's peer identity.
    #[test]
    fn addpath_children_compete_as_separate_candidates() {
        let records = [
            record(11, plain(&[65001, 65002])),
            record(12, plain(&[65001])),
        ];
        let session = ebgp(65001, "10.0.0.1", [10, 0, 0, 1]);
        let child = |path_id: u32| {
            IngressInfo::new()
                .with_ingress_type(IngressType::BgpPath)
                .with_parent_ingress(3u32)
                .with_path_id(path_id)
        };
        let info = registry(vec![
            (3, session),
            (11, child(1)),
            (12, child(2)),
        ]);

        let out = rfc4271(&records, &info);
        assert_eq!(out.order(), vec![12, 11]);
        assert_eq!(out.decided_by(), Some(DecisionStep::AsPathLength));
        assert!(
            out.excluded.is_empty(),
            "children must inherit the session's peer identity, not be \
             dropped for lacking one"
        );
    }

    //--- Reporting ----------------------------------------------------------

    /// `alternatives=<n>` caps what is listed, not what was considered.
    #[test]
    fn the_alternatives_cap_limits_reporting_only() {
        let records = [
            record(1, plain(&[65001, 65002, 65003])),
            record(2, plain(&[65001])),
            record(3, plain(&[65001, 65002])),
        ];
        let info = registry(vec![
            (1, ebgp(65001, "10.0.0.1", [10, 0, 0, 1])),
            (2, ebgp(65001, "10.0.0.2", [10, 0, 0, 2])),
            (3, ebgp(65001, "10.0.0.3", [10, 0, 0, 3])),
        ]);

        let (best, alternatives, excluded) = select(
            &records,
            &info,
            BestPathOptions {
                strategy: Strategy::Rfc4271,
                alternatives: Alternatives::AtMost(1),
            },
        );
        assert_eq!(best.unwrap().candidate.mui, 2);
        assert_eq!(alternatives.len(), 1);
        assert_eq!(alternatives[0].candidate.mui, 3, "the runner-up, not any");
        assert!(excluded.is_empty());
    }

    #[test]
    fn no_eligible_routes_yields_no_best_path() {
        let records = [record(1, plain(&[65001]))];
        let out = rfc4271(&records, &registry(vec![]));
        assert!(out.best.is_none());
        assert!(out.alternatives.is_empty());
        assert_eq!(out.excluded.len(), 1);
    }

    /// A single candidate has nothing to be compared against, so there is no
    /// deciding step to report.
    #[test]
    fn a_lone_candidate_has_no_deciding_step() {
        let records = [record(1, plain(&[65001]))];
        let info = registry(vec![(1, ebgp(65001, "10.0.0.1", [10, 0, 0, 1]))]);

        let out = rfc4271(&records, &info);
        assert_eq!(out.best_mui(), 1);
        assert_eq!(out.decided_by(), None);
    }

    //--- RFC edge cases -----------------------------------------------------

    /// RFC 4271 §9.1.2: "If the AS_PATH attribute of a BGP route contains an
    /// AS loop, the BGP route should be excluded from the Phase 2 decision
    /// function."
    #[test]
    fn a_route_whose_as_path_contains_the_local_as_is_excluded() {
        let records = [
            record(1, plain(&[65001, 65000, 65002])),
            record(2, plain(&[65001, 65002, 65003, 65004])),
        ];
        let info = registry(vec![
            (1, ebgp(65001, "10.0.0.1", [10, 0, 0, 1])),
            (2, ebgp(65001, "10.0.0.2", [10, 0, 0, 2])),
        ]);

        let out = rfc4271(&records, &info);
        assert_eq!(
            out.best_mui(),
            2,
            "the longer path wins because the shorter one loops"
        );
        assert_eq!(out.excluded.len(), 1);
        assert_eq!(out.excluded[0].mui, 1);
        assert_eq!(out.excluded[0].reason, IneligibleReason::AsPathLoop);
    }

    /// The RFC says the check scans the *full* AS path, so a local AS hidden
    /// inside an AS_SET is still a loop.
    #[test]
    fn an_as_path_loop_inside_an_as_set_is_found() {
        let records = [record(
            1,
            pamap(&[
                origin(0),
                as_path_segments(&[(SEQ, &[65001]), (SET, &[65009, 65000])]),
            ]),
        )];
        let info = registry(vec![(1, ebgp(65001, "10.0.0.1", [10, 0, 0, 1]))]);

        let out = rfc4271(&records, &info);
        assert!(out.best.is_none());
        assert_eq!(out.excluded[0].reason, IneligibleReason::AsPathLoop);
    }

    /// Confederation members appear in AS_CONFED_SEQUENCE, which is part of
    /// the path being scanned: a route that already traversed this member AS
    /// is a loop like any other.
    #[test]
    fn an_as_path_loop_inside_a_confed_sequence_is_found() {
        let records = [record(
            1,
            pamap(&[
                origin(0),
                as_path_segments(&[
                    (CONFED_SEQ, &[65000]),
                    (SEQ, &[65001]),
                ]),
            ]),
        )];
        let info = registry(vec![(1, ebgp(65001, "10.0.0.1", [10, 0, 0, 1]))]);

        let out = rfc4271(&records, &info);
        assert_eq!(out.excluded[0].reason, IneligibleReason::AsPathLoop);
    }

    /// Without a local ASN there is nothing to compare against, so the check
    /// is skipped rather than guessed at. MRT-replayed peers have no local
    /// end at all.
    #[test]
    fn loop_detection_is_skipped_when_the_local_asn_is_unknown() {
        let records = [record(1, plain(&[65001, 65000, 65002]))];
        let info = registry(vec![(
            1,
            IngressInfo::new()
                .with_ingress_type(IngressType::Mrt)
                .with_remote_asn(Asn::from_u32(65001))
                .with_remote_addr("10.0.0.1".parse::<IpAddr>().unwrap())
                .with_bgp_id([10, 0, 0, 1]),
        )]);

        let out = rfc4271(&records, &info);
        assert_eq!(out.best_mui(), 1, "cannot detect a loop without a local AS");
        assert!(out.excluded.is_empty());
    }

    /// Step a: "an AS_SET counts as 1, no matter how many ASes are in the
    /// set". The set here holds three ASNs but must weigh the same as one hop,
    /// so the two-hop sequence loses.
    #[test]
    fn an_as_set_counts_as_a_single_hop() {
        let records = [
            record(
                1,
                pamap(&[
                    origin(0),
                    as_path_segments(&[(SET, &[65001, 65002, 65003])]),
                ]),
            ),
            record(2, plain(&[65004, 65005])),
        ];
        let info = registry(vec![
            (1, ibgp("10.0.0.1", [10, 0, 0, 1])),
            (2, ibgp("10.0.0.2", [10, 0, 0, 2])),
        ]);

        let out = rfc4271(&records, &info);
        assert_eq!(out.best_mui(), 1);
        assert_eq!(out.decided_by(), Some(DecisionStep::AsPathLength));
    }

    /// RFC 5065 §5.3: AS_CONFED segments are not counted in the AS_PATH
    /// length used by step a. The confederation route below has four ASNs in
    /// its path but only one that counts, so it beats a two-hop sequence.
    #[test]
    fn confed_segments_do_not_count_towards_as_path_length() {
        let records = [
            record(
                1,
                pamap(&[
                    origin(0),
                    as_path_segments(&[
                        (CONFED_SEQ, &[65101, 65102, 65103]),
                        (SEQ, &[65001]),
                    ]),
                ]),
            ),
            record(2, plain(&[65004, 65005])),
        ];
        let info = registry(vec![
            (1, ibgp("10.0.0.1", [10, 0, 0, 1])),
            (2, ibgp("10.0.0.2", [10, 0, 0, 2])),
        ]);

        let out = rfc4271(&records, &info);
        assert_eq!(out.best_mui(), 1);
        assert_eq!(out.decided_by(), Some(DecisionStep::AsPathLength));
    }

    /// Step c's neighbour AS is "the local AS" when the AS_PATH does not begin
    /// with a plain ASN — an aggregate whose path starts with an AS_SET. Both
    /// routes then share a neighbour AS, so their MEDs *are* comparable.
    #[test]
    fn med_is_comparable_when_both_paths_start_with_an_as_set() {
        let set_path = as_path_segments(&[(SET, &[65001, 65002])]);
        let records = [
            record(
                1,
                pamap(&[origin(0), set_path.clone(), med(200)]),
            ),
            record(2, pamap(&[origin(0), set_path, med(50)])),
        ];
        // IBGP: an EBGP route whose path names no neighbour is ineligible, so
        // this clause is only reachable for internal routes.
        let info = registry(vec![
            (1, ibgp("10.0.0.1", [10, 0, 0, 1])),
            (2, ibgp("10.0.0.2", [10, 0, 0, 2])),
        ]);

        let out = rfc4271(&records, &info);
        assert_eq!(out.best_mui(), 2);
        assert_eq!(out.decided_by(), Some(DecisionStep::Med));
    }

    /// Phase 1 runs before every tie-breaker, so an internal route with a
    /// LOCAL_PREF outranks an external one — netom applies no import policy,
    /// which means EBGP routes have a degree of preference of 0 rather than a
    /// vendor-style default of 100. Step d never gets to run.
    #[test]
    fn an_ibgp_local_pref_outranks_an_ebgp_route() {
        let records = [
            record(1, pamap(&[origin(0), as_path(&[65001]), local_pref(100)])),
            record(2, plain(&[65001])),
        ];
        let info = registry(vec![
            (1, ibgp("10.0.0.1", [10, 0, 0, 1])),
            (2, ebgp(65001, "10.0.0.2", [10, 0, 0, 2])),
        ]);

        let out = rfc4271(&records, &info);
        assert_eq!(out.best_mui(), 1, "LOCAL_PREF is weighed before step d");
        assert_eq!(out.decided_by(), Some(DecisionStep::DegreeOfPreference));
    }

    /// An IBGP route with no LOCAL_PREF has a degree of preference of 0, not
    /// the 100 most vendors default to, so it loses to any internal route that
    /// carries one.
    #[test]
    fn a_missing_local_pref_on_an_ibgp_route_counts_as_zero() {
        let records = [
            record(1, plain(&[65001])),
            record(2, pamap(&[origin(0), as_path(&[65001]), local_pref(1)])),
        ];
        let info = registry(vec![
            (1, ibgp("10.0.0.1", [10, 0, 0, 1])),
            (2, ibgp("10.0.0.2", [10, 0, 0, 2])),
        ]);

        let out = rfc4271(&records, &info);
        assert_eq!(out.best_mui(), 2);
        assert_eq!(out.decided_by(), Some(DecisionStep::DegreeOfPreference));
    }

    /// Step g compares peer addresses, which may be of different families —
    /// a v6 session can carry v4 NLRI. The RFC says nothing about ordering
    /// across families; `IpAddr` sorts every v4 address before every v6 one.
    /// Pinned because it is arbitrary but must stay deterministic.
    #[test]
    fn step_g_sorts_ipv4_peers_before_ipv6_peers() {
        let records =
            [record(1, plain(&[65001])), record(2, plain(&[65001]))];
        // Identical but for the peer address family.
        let info = registry(vec![
            (1, ebgp(65001, "2001:db8::1", [10, 0, 0, 1])),
            (2, ebgp(65001, "10.0.0.2", [10, 0, 0, 1])),
        ]);

        let out = rfc4271(&records, &info);
        assert_eq!(out.best_mui(), 2);
        assert_eq!(out.decided_by(), Some(DecisionStep::PeerAddress));
    }

    /// A missing MULTI_EXIT_DISC is the *lowest* value, per RFC 4271 step c —
    /// not the highest, which is a widespread vendor option
    /// ("med-missing-as-worst") and not what the RFC says.
    #[test]
    fn a_missing_med_is_the_lowest_med() {
        let records = [
            record(1, pamap(&[origin(0), as_path(&[65001]), med(1)])),
            record(2, plain(&[65001])),
        ];
        let info = registry(vec![
            (1, ebgp(65001, "10.0.0.1", [10, 0, 0, 1])),
            (2, ebgp(65001, "10.0.0.2", [10, 0, 0, 2])),
        ]);

        let out = rfc4271(&records, &info);
        assert_eq!(out.best_mui(), 2, "no MED beats MED 1");
        assert_eq!(out.decided_by(), Some(DecisionStep::Med));
    }

    /// A confederation-external peer's routes begin with an
    /// AS_CONFED_SEQUENCE, which names no neighbour ASN, so routecore's
    /// eligibility check rejects them as `ebgpWithoutNeighbour`. RFC 5065
    /// deployments therefore do not get best-path selection for
    /// confederation-external routes today.
    ///
    /// Pinned as a known limitation rather than asserted as correct: if
    /// routecore learns to read a neighbour out of an AS_CONFED_SEQUENCE this
    /// test should be the one that fails and gets updated.
    #[test]
    fn confed_external_routes_are_currently_ineligible() {
        let records = [record(
            1,
            pamap(&[
                origin(0),
                as_path_segments(&[(CONFED_SEQ, &[65101]), (SEQ, &[65001])]),
            ]),
        )];
        // A confederation member AS, distinct from ours, so the session reads
        // as EBGP.
        let info = registry(vec![(1, ebgp(65101, "10.0.0.1", [10, 0, 0, 1]))]);

        let out = rfc4271(&records, &info);
        assert!(out.best.is_none());
        assert_eq!(
            out.excluded[0].reason,
            IneligibleReason::EbgpWithoutNeighbour
        );
    }

    //--- The explanation must not drift from the ranking --------------------

    /// [`decisive_step`] mirrors routecore's `Ord` so it can name the step
    /// that decided a comparison. If the two ever disagree the API would
    /// report a reason that did not produce the ranking, so every pair from a
    /// deliberately varied corpus is checked against `OrdRoute::cmp`.
    #[test]
    fn the_explanation_agrees_with_routecore_ordering() {
        let metas = [
            plain(&[65001]),
            plain(&[65001, 65002]),
            pamap(&[origin(1), as_path(&[65001])]),
            pamap(&[origin(2), as_path(&[65001])]),
            pamap(&[origin(0), as_path(&[65001]), med(10)]),
            pamap(&[origin(0), as_path(&[65001]), med(500)]),
            pamap(&[origin(0), as_path(&[65002]), med(10)]),
            pamap(&[origin(0), as_path(&[65001]), local_pref(50)]),
            pamap(&[origin(0), as_path(&[65001]), local_pref(400)]),
            pamap(&[origin(0), as_path(&[65001]), originator_id([1, 2, 3, 4])]),
            pamap(&[
                origin(0),
                as_path(&[65001]),
                cluster_list(&[[9, 9, 9, 9], [8, 8, 8, 8]]),
            ]),
        ];

        // Vary the per-peer inputs too: steps d, f and g come from the
        // session, not from the attributes.
        let sessions = [
            ebgp(65001, "10.0.0.1", [10, 0, 0, 1]),
            ebgp(65002, "10.0.0.2", [10, 0, 0, 2]),
            ibgp("10.0.0.3", [10, 0, 0, 3]),
            ibgp("10.0.0.4", [1, 1, 1, 1]),
        ];

        let mut candidates = Vec::new();
        for meta in &metas {
            for session in &sessions {
                let rec = record(1, meta.clone());
                if let Ok(candidate) =
                    classify(&rec, Some(session))
                {
                    candidates.push(candidate);
                }
            }
        }
        assert!(candidates.len() > 20, "corpus should be substantial");

        for strategy in [Strategy::Rfc4271, Strategy::SkipMed] {
            for a in &candidates {
                for b in &candidates {
                    let (explained, step) = decisive_step(a, b, strategy);
                    let authoritative = compare(a, b, strategy)
                        .expect("corpus is all eligible");
                    assert_eq!(
                        explained, authoritative,
                        "explanation disagreed with routecore at step {step}"
                    );
                    if explained == Ordering::Equal {
                        assert_eq!(step, DecisionStep::Tie);
                    } else {
                        assert_ne!(step, DecisionStep::Tie);
                    }
                }
            }
        }
    }
}
