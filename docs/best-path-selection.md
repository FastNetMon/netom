# BGP best path selection

What the RFCs require of the decision process, what `routecore` implements of
it, and how netom runs it: at query time, over the `/best-path` endpoints, not
in the store.

The RFC text itself is kept verbatim alongside this file rather than
paraphrased here:

| File | Covers |
| --- | --- |
| `rfc4271_section9.1_decision_process.txt` | The normative decision process: Phase 1/2/3, and the step a–g tie-breakers |
| `rfc4456_section9_route_selection.txt` | Route reflection: ORIGINATOR_ID in step f, CLUSTER_LIST length between f and g |
| `rfc4451_section3_med.txt` | MED comparability, the missing-MED value, MED under RR and confederations |
| `rfc5065_section5_confederations.txt` | AS_CONFED segments excluded from AS_PATH length; MED/LOCAL_PREF across member ASes |
| `rfc5004_section3_avoid_oscillation.txt` | Optional: keep the incumbent external best path when tied at step f |
| `rfc7911_section5_addpath.txt` | ADD-PATH — paths keyed by (prefix, Path Identifier) |

## Where selection happens: at query time

netom runs the decision process when a `/best-path` query asks for it, over the
records the store returns, using the ingress register for each record's peer
identity. It is not run on ingest, nothing is precomputed, and no "best" flag is
stored: `RouteStatus::Active` still means "this peer advertises it".

The code is `src/units/rib_unit/best_path.rs`, reached through
`Rib::best_path` (`src/units/rib_unit/rib.rs`) and the handlers in
`src/units/rib_unit/http_ng.rs`. See `docs/rib-query-api.md` for the endpoints
and `docs/cli.md` for `show ip bgp <prefix> best`.

### Why not in the store

`rotonda-store` has a path-selection hook — `Meta::as_orderable`, driven by
`RecordMap::best_backup` and enabled by passing `Some(tbi)` to `store.insert` —
and it cannot express the RFC's decision process. `best_backup` takes **one**
`TiebreakerInfo` and applies it to every record of a prefix, but
`TiebreakerInfo` carries `peer_addr`, `bgp_identifier` and the EBGP/IBGP
`source`, all of which differ per record. Steps d, f and g of RFC 4271
§9.1.2.2 are therefore not computable that way.

So `RotondaPaMap::as_orderable` (`src/payload.rs`) stays unimplemented — its
body is an `unreachable!()` carrying that explanation — and every
`store.insert` call site continues to pass `None`. If the store's hook ever
grows a per-record tiebreaker, moving selection into it becomes worth
revisiting; until then, a store-level "best" would be wrong rather than fast.

The cost of query-time selection is bounded: one prefix's records, parsed into
`PaMap`s and sorted. That is why there is no whole-table best-path endpoint —
it would be a full store walk with a sort per prefix.

### What the API adds beyond the winner

The endpoint reports the ranked alternatives and, for each, the step at which
it lost to the best path, plus the routes that never entered the comparison and
why. Two netom-specific exclusions sit alongside routecore's: a record whose
mui has no register entry (`unknownIngress`) and a session with no recorded
remote address (`unknownPeerAddress`) have no inputs for steps d, f and g, so
they are reported as excluded rather than ranked on invented identity.

Where a value is missing but not disqualifying, the candidate says so in an
`assumed` array rather than ranking silently:

- **no `local_asn`** on the session — EBGP vs IBGP is unknown, so the route is
  treated as EBGP. Sessions now record it (native BGP from the unit's `my_asn`,
  BMP from the Peer Up's sent OPEN), but MRT replay has no local end at all.
- **no `bgp_id`** for the peer — step f uses `255.255.255.255`, so an unknown
  identifier loses a tie rather than winning it. This is the common case for
  natively terminated sessions: routecore's `NegotiatedConfig` holds
  `remote_bgp_id` but exposes no accessor for it, so netom cannot read the
  peer's identifier off its own sessions. BMP-monitored peers have it from the
  per-peer header.

## What routecore provides

`routecore::bgp::path_selection` is a complete implementation waiting to be
called. The entry points:

| Item | Purpose |
| --- | --- |
| `OrdRoute<'a, OS>` | A `(TiebreakerInfo, &PaMap)` pair whose `Ord` *is* the decision process. Ordering is "most preferred first": `a < b` means a is preferred, so the minimum of a collection is the best path. |
| `OrdRoute::rfc4271(...)` / `try_new(...)` | Construct one; both run the eligibility check below and return `Result<_, DecisionError>`. |
| `Rfc4271` / `SkipMed` | `OrdStrat` strategies. `SkipMed` makes step c a no-op, for `bgp always-compare-med`-style deployments. `into_strat` / `from_strat` convert between them. |
| `TiebreakerInfo::new(source, degree_of_preference, local_asn, bgp_identifier, peer_addr)` | The per-route context the path attributes cannot supply. This is what netom would have to construct per ingress. |
| `preferred(a, b)`, `best(iter)`, `best_backup(iter)`, `best_backup_generic(iter)` | Selection over anything `Ord`, so `(OrdRoute, mui)` tuples work and hand back the local id with the winner. |

### Step-by-step mapping

The `Ord` impl follows RFC 4271 §9.1.2.2 in order, with the RFC 4456 additions
folded in:

| Step | Rule | routecore |
| --- | --- | --- |
| Phase 1 | Degree of preference; higher wins | `TiebreakerInfo.degree_of_preference` if set, else LOCAL_PREF **only when the route is IBGP**, else 0 |
| a | Shortest AS_PATH; AS_SET counts as 1 | `HopPath::hop_count_path_selection()` — counts `Hop::Asn` and AS_SET as 1 each, and skips AS_CONFED segments, giving RFC 5065 §5.3 behaviour for free |
| b | Lowest ORIGIN | `Origin` compare; equal if either is absent |
| c | Lowest MED, same neighbour AS only | `OrdStrat::step_c`. Neighbour AS from `neighbor_path_selection()` (first hop, only if it is a bare ASN — a leading AS_CONFED_SEQUENCE yields `None`), falling back to `local_asn`. A missing MED is treated as 0, per the RFC |
| d | Prefer EBGP over IBGP | `RouteSource` ordering — `Ebgp` is declared before `Ibgp`, so it sorts first |
| e | Lowest interior (IGP) cost | **Not implemented.** `OrdStrat::step_e` has a default body returning `Equal`, and neither strategy overrides it |
| f | Lowest BGP Identifier, or ORIGINATOR_ID if present (RFC 4456) | Implemented, ORIGINATOR_ID substitution included |
| f2 | Shorter CLUSTER_LIST (RFC 4456, between f and g) | Implemented; absent CLUSTER_LIST counts as length 0 |
| g | Lowest peer address | `TiebreakerInfo.peer_addr` |

### Eligibility, and what it does not check

`OrdRoute::eligible()` runs at construction and rejects a route when ORIGIN is
missing, AS_PATH is missing, or the route is EBGP with no neighbour ASN in its
AS_PATH.

netom maps those three onto `missingOrigin`, `missingAsPath` and
`ebgpWithoutNeighbour` in the `ineligible` array, and adds `unknownIngress`,
`unknownPeerAddress`, `malformedPathAttributes` and `asPathLoop` of its own.

`asPathLoop` is the other half of §9.1.2's candidate rule, which routecore
declares but never applies: a route whose AS_PATH contains the local AS is
excluded from Phase 2. netom can run it now that sessions record their local
ASN — for a BMP-monitored peer that is the monitored router's ASN, so the check
reproduces that router's view. The full path is scanned, so an AS inside an
AS_SET or an AS_CONFED segment counts, and the check runs *before* routecore's
eligibility so a looped path beginning with a set or confed segment is reported
as a loop rather than as a missing neighbour. MRT replay records no local ASN,
so the check is skipped there rather than guessed at. What eligibility
does **not** cover is under [Known gaps](#known-gaps).

Running it is not optional: step a calls
`panic!("can not compare routes lacking AS_PATH")` when either side has no
AS_PATH. Anything building an `OrdRoute` must go through `rfc4271()` or
`try_new()` and handle the `DecisionError`, never assemble one another way.

## Known gaps

Inherited from routecore, and unchanged by this:

- **Step e (interior/IGP cost) never decides.** `OrdStrat::step_e` defaults to
  `Equal` and neither strategy overrides it. netom has no IGP view to override
  it with. `DecisionStep::InteriorCost` exists in the API's vocabulary but is
  never returned.
- **NEXT_HOP resolvability (§9.1.2.1) is not checked.** A candidate with an
  unreachable next hop is still ranked. netom has no FIB or IGP view, so there
  is nothing to resolve against.
- **Confederation-external routes are not selectable.** Their AS_PATH begins
  with an AS_CONFED_SEQUENCE, so `neighbor_path_selection()` returns `None` and
  routecore's eligibility rejects them as "expected non-empty AS_PATH". Fixing
  it means teaching routecore to look past a leading confed segment. AS_CONFED
  handling is correct elsewhere: excluded from the step a length per RFC 5065
  §5.3, and scanned for loops.
- **AS4_PATH (RFC 6793) is not merged into AS_PATH** for the step a count.
- **Vendor-style import defaults are absent**, which changes outcomes rather
  than just omitting a feature: an EBGP route's degree of preference is 0
  because §9.1.1 leaves it to local policy and netom has none, so any IBGP
  route with a LOCAL_PREF above 0 wins Phase 1 outright. A missing LOCAL_PREF
  on an IBGP route is 0, not 100.
- **RFC 5004 is not implemented** — there is no "prefer the incumbent external
  path" rule, so a best path can flap between two externals tied at step f.
  See `rfc5004_section3_avoid_oscillation.txt`.
- **No multipath.** Paths tied after step e are equal-cost and could be used
  together; the ranking runs the remaining tie-breakers instead and returns a
  single winner.
- **Vendor extras are absent**: Cisco-style `weight`, and the "oldest route
  wins" rule several vendors insert between steps e and f. Neither is in RFC
  4271.

## Keeping the explanation honest

`decisive_step` in `best_path.rs` mirrors routecore's `Ord` step by step so the
API can name *why* a route won or lost. That is a second implementation of the
same comparison, and a second implementation can drift.

It is not used for ranking — `compare` builds real `OrdRoute`s and uses their
`Ord` — and `the_explanation_agrees_with_routecore_ordering` checks the two
against each other over every pair of a deliberately varied candidate corpus,
under both strategies. That test has already earned its place once: it caught
that `OrdRoute::from_strat` only re-tags the strategy's `PhantomData`, so
converting a `SkipMed` wrapper into an `Rfc4271` one silently reinstated the
MED comparison the caller had asked to skip.
