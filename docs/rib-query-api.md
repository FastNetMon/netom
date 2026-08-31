# The RIB query API

`/api/v1/ribs/*` — looking up routes in netom's RIB over HTTP: the endpoints,
the query parameters they accept, the shape of what comes back, and the limits
that apply to whole-table dumps.

Two neighbouring documents cover the parts deliberately left out here:
`docs/addpath-flowspec-api.md` for how ADD-PATH sessions and FlowSpec rules are
modelled (path-child ingresses, rule validity, what `?ingressId=` means for a
peer that has several paths), and `docs/cli.md` for `netom-cli`, which is a
renderer on top of these same endpoints.

The API is unauthenticated and unencrypted. Everything below is a GET; nothing
in this API changes state.

## Endpoints

| Endpoint | Returns |
| --- | --- |
| `GET /api/v1/ribs/ipv4unicast/routes/{addr}/{len}` | every route for one prefix |
| `GET /api/v1/ribs/ipv6unicast/routes/{addr}/{len}` | |
| `GET /api/v1/ribs/ipv4unicast/routes` | the whole table (see [Whole-table dumps](#whole-table-dumps)) |
| `GET /api/v1/ribs/ipv6unicast/routes` | |
| `GET /api/v1/ribs/ipv4flowspec/routes/{addr}/{len}` | FlowSpec rules keyed on one prefix |
| `GET /api/v1/ribs/ipv6flowspec/routes/{addr}/{len}` | |
| `GET /api/v1/ribs/ipv4flowspec/routes` | every FlowSpec rule |
| `GET /api/v1/ribs/ipv6flowspec/routes` | |
| `GET /api/v1/ribs/ipv4unicast/best-path/{addr}/{len}` | the best path for one prefix (see [Best path](#best-path)) |
| `GET /api/v1/ribs/ipv6unicast/best-path/{addr}/{len}` | |
| `GET /api/v1/ribs/ipv4unicast/best-path/{addr}` | the best path for the prefix covering one address |
| `GET /api/v1/ribs/ipv6unicast/best-path/{addr}` | |

The prefix is split over two path segments — `10.0.0.0/24` is
`/routes/10.0.0.0/24`, and `2001:db8::/32` is `/routes/2001:db8::/32`.

A bare `/routes` is a `0.0.0.0/0` (or `::/0`) query with `moreSpecifics`
added, which is why it returns the table rather than the default route.

Any other AFI/SAFI (`/api/v1/ribs/{afisafi}/routes`) currently answers 500 with
`TODO`; multicast is stored but not yet queryable this way.

## Query parameters

### Selecting routes

| Parameter | Value | Notes |
| --- | --- | --- |
| `ingressId` | ingress id, e.g. `5` | Not `filter[...]`-style. Exact store mui — for an ADD-PATH peer this is one *path*, not the peer; see `docs/addpath-flowspec-api.md`. |
| `filter[ingressType]` | `bgp`, `bmp`, `bgpViaBmp`, `mrt`, `rtr`, `bgpPath` | Where the route was learned. Matched on the *session*, so an ADD-PATH peer's paths count as their session's type; `bmp` means "anything learned through BMP", since a monitored router's own ingress holds no routes. |
| `filter[peerAddress]` | IP address | The peer's remote address, from the ingress register. |
| `filter[peerAsn]` | `AS65000` or `65000` | |
| `filter[ribType]` | `inPre`, `inPost`, `loc`, `outPre`, `outPost` | BMP peer RIB type + policy. Sessions netom terminates itself are always `inPost`, so this does not separate BGP from BMP — use `filter[ingressType]`. |
| `filter[originAsn]` | `AS65000` or `65000` | Last ASN of the AS_PATH. |
| `filter[otc]` | `AS65000` or `65000` | RFC 9234 Only-To-Customer attribute. |
| `filter[community]` | `65000:100`, `0x1a2b3c4d`, or a well-known name such as `NO_EXPORT` | Standard community. |
| `filter[largeCommunity]` | `65000:1:2` (`AS65000:1:2` also parses) | |
| `filter[rovStatus]` | `notChecked`, `notFound`, `valid`, `invalid` | RPKI route origin validation state. |
| `function[roto]` | name of a function in the loaded Roto package | Called per record; `Accept` keeps the route. An undefined name is a 400, not an empty result. |

Filters combine with AND. `ingressId` is pushed into the store lookup; the
rest are applied to the records the lookup returns.

Note that `filter[peerAddress]` and `filter[peerAsn]` *keep* a record whose
ingress is not in the register, while `filter[ingressType]` drops it — a
record with no known ingress has no type, and keeping it would leak routes of
one origin into an answer about another.

### Shaping the response

| Parameter | Value | Notes |
| --- | --- | --- |
| `include` | `moreSpecifics`, `lessSpecifics`, or both comma-separated | Adds the covering / covered prefixes to an `included` section. Implied for a bare `/routes`. |
| `format` | `json` (default) or `jsonl` | `jsonl` streams one object per line as `application/x-ndjson`. |
| `fields[pathAttributes]` | comma-separated BGP path attribute type codes, e.g. `1,2,5` | Emit only these attributes. |

## Response shapes

### JSON (default)

```json
{
  "meta": null,
  "data": {
    "nlri": "10.0.0.0/24",
    "routes": [
      {
        "status": "active",
        "ingress": {"id": 4, "ingress_type": "bgpPath", "parent_ingress": 3, "path_id": 1},
        "source": {"ingressId": 3, "pathId": 1, "internalPathIngressId": 4},
        "rpki": {"rov": "notChecked"},
        "pathAttributes": [{"origin": "Igp"}, {"asPath": ["AS65001"]}]
      }
    ]
  },
  "included": {}
}
```

`ingress` is the register entry for the record's store mui, with its fields in
`snake_case`. `source` is the resolved identity in `camelCase`: `ingressId` is
the **session**, and `pathId` / `internalPathIngressId` appear only for
ADD-PATH records. Group by `source.ingressId` to collapse a peer's paths back
into one peer; `ingress.id` is the child for those rows, not the session.

`included` gains a `moreSpecifics` and/or `lessSpecifics` key when `include`
asked for them, each an array of `{"nlri": …, "routes": [ … ]}` objects with
the same route shape as `data`.

### JSONL (`format=jsonl`)

One flat object per line, each uniquely identified by `(prefix, ingress.id)`:

```json
{"prefix":"10.0.0.0/24","section":"data","status":"active","ingress":{…},"source":{…},"rpki":{…},"pathAttributes":[…]}
```

`section` is `data`, `moreSpecifics`, or `lessSpecifics` — the same split the
JSON response expresses structurally, flattened so no information is lost when
the response is a stream of independent lines.

### FlowSpec

```json
{"data": [
  {
    "keyPrefix": "10.0.0.0/24",
    "ingressId": 4,
    "source": {"ingressId": 3, "pathId": 1, "internalPathIngressId": 4},
    "validity": "valid",
    "nlri": "dst 10.0.0.0/24, proto =17",
    "nlriHex": "01180a0000038111",
    "actions": [],
    "attributes": {"rpki": {…}, "pathAttributes": [ … ]}
  }
]}
```

`keyPrefix` is the rule's destination-prefix component, or the family default
route for a rule without a usable one; `nlriHex` is the raw rule bytes, which
are the rule's identity. Rules are ordered per RFC 8955 §5.1, and `validity` is
the RFC 8955 §6 state, recomputed against the current unicast RIB on every
query.

## Best path

`/best-path` runs the RFC 4271 §9.1 decision process over the routes for one
prefix and returns the winner, the ranked alternatives, and the step at which
each of them lost. `docs/best-path-selection.md` covers what is and is not
implemented, and keeps the RFC text alongside it.

Two forms:

* `/best-path/{addr}/{len}` — an exact prefix, the counterpart of
  `/routes/{addr}/{len}`.
* `/best-path/{addr}` — a longest-prefix match: "which route would forward this
  address". The answer's `nlri` is the prefix that matched, which is normally
  not the address that was asked for, so the response echoes `queryAddress` and
  a `matchType`.

Selection happens at query time; nothing is precomputed and no "best" flag is
stored. There is no whole-table form — that would be a full store walk with a
sort per prefix. Use `/routes` and rank client-side if you need it.

### Parameters

Every parameter under [Selecting routes](#selecting-routes) works here and
narrows the *candidate set*, so `?filter[ingressType]=bgp` asks "what would the
best path be if only BGP-learned routes existed". `fields[pathAttributes]`
works as elsewhere. Two are specific to this endpoint:

| Parameter | Value | Notes |
| --- | --- | --- |
| `strategy` | `rfc4271` (default) or `skipMed` | `skipMed` drops step c, for deployments that do not compare MULTI_EXIT_DISC. These are the only two routecore offers; there is no always-compare-MED. |
| `alternatives` | a count, or `all` (default) | Caps how many ranked alternatives are listed. It does not change what was considered — `counts` still reports the whole candidate set. |

`include` and `format=jsonl` are rejected with 400 naming the parameter: the
first has no meaning for a decision about one prefix, and the second has
nothing to stream.

### Response

```json
{
  "meta": null,
  "data": {
    "nlri": "10.0.0.0/24",
    "queryAddress": "10.0.0.7",
    "matchType": "longestMatch",
    "strategy": "rfc4271",
    "counts": {"total": 4, "eligible": 3, "ineligible": 1, "reported": 3, "equalCost": 1},
    "best": {
      "rank": 1,
      "equalCost": true,
      "decidedBy": "asPathLength",
      "status": "active",
      "ingress": {"id": 3, "ingress_type": "bgp"},
      "source": {"ingressId": 3},
      "rpki": {"rov": "notChecked"},
      "pathAttributes": [{"origin": "Igp"}, {"asPath": ["AS65001"]}]
    },
    "alternatives": [{"rank": 2, "lostAt": "med", "...": "same shape"}],
    "ineligible": [{"reason": "missingAsPath", "...": "same shape, no rank"}]
  }
}
```

A route row is exactly a `/routes` row — `status`, `ingress`, `source`, `rpki`,
`pathAttributes`, with the same ADD-PATH semantics — plus the ranking fields,
so anything that renders `/routes` renders these.

`queryAddress` and `matchType` appear only on the address form. `best` is
`null` when no route was eligible; check `ineligible` to tell that apart from
"no such prefix".

`counts.eligible` is the whole candidate set, `counts.reported` is how many of
them this response lists — they differ when `alternatives=<n>` capped it.

### Equal-cost paths

`equalCost` on a row means it is tied with the best path through step e — that
is, on every criterion the RFC treats as a real preference. Steps f and g (the
BGP Identifier and the peer address) exist only to force a single winner out of
routes already found equally good, so an equal-cost route is one a router doing
multipath would install alongside the winner.

`counts.equalCost` is how many of the listed routes, the best path included,
are in that set. **`1` means the winner won on merit; more means it was picked
by a tie-breaker** and the choice is arbitrary in everything but its
determinism. netom does not do multipath itself — this reports what a router
would have to decide.

### The deciding step

`decidedBy` on the best path is the step that separated it from the runner-up
(absent when there is no runner-up). `lostAt` on an alternative is the step at
which it lost **to the best path**, not to the row above it.

| Value | RFC 4271 §9.1.2.2 |
| --- | --- |
| `degreeOfPreference` | Phase 1 — LOCAL_PREF, on IBGP routes only |
| `asPathLength` | step a |
| `origin` | step b |
| `med` | step c |
| `peerType` | step d — EBGP over IBGP |
| `interiorCost` | step e — never returned; netom has no IGP view |
| `bgpIdentifier` | step f, with RFC 4456's ORIGINATOR_ID substitution |
| `clusterListLength` | RFC 4456, between f and g |
| `peerAddress` | step g |
| `tie` | every step compared equal |

### Routes that did not compete

`ineligible` lists what never entered the comparison, each with a `reason`:

| Reason | Meaning |
| --- | --- |
| `missingOrigin` | Mandatory ORIGIN absent |
| `missingAsPath` | Mandatory AS_PATH absent |
| `ebgpWithoutNeighbour` | An EBGP route whose AS_PATH names no neighbour AS |
| `asPathLoop` | The AS_PATH contains the session's local AS (RFC 4271 §9.1.2) |
| `malformedPathAttributes` | The stored attribute blob would not parse |
| `unknownIngress` | The record's mui has no ingress register entry |
| `unknownPeerAddress` | The session has no remote address recorded |

`unknownIngress` and `unknownPeerAddress` are netom's own: without a peer
identity, steps d, f and g have no inputs, and ranking the route anyway would
mean inventing one.

`asPathLoop` is RFC 4271 §9.1.2's rule that a route whose AS_PATH contains the
local AS is excluded from Phase 2. The whole path is scanned, so an AS inside
an AS_SET or an AS_CONFED segment counts. It can only be applied when the
session recorded a local ASN, which MRT replay never does — those routes are
left in, unchecked.

### Behaviour worth knowing about

Several of these follow the RFC but differ from what a router would do, because
netom applies no import policy:

* **EBGP routes have a degree of preference of 0.** RFC 4271 §9.1.1 computes it
  from local policy for external routes, and netom has none — so LOCAL_PREF on
  an EBGP route is ignored, and any *internal* route with a LOCAL_PREF above 0
  outranks every external one at Phase 1, before step d is reached. Vendors
  avoid this by applying a default LOCAL_PREF of 100 on import.
* **A missing LOCAL_PREF on an IBGP route is 0**, not the 100 vendors default
  to.
* **A missing MULTI_EXIT_DISC is the lowest MED**, per step c. The widespread
  "MED missing as worst" behaviour is a vendor option, not the RFC.
* **Confederations follow RFC 5065 §5.3.** AS_CONFED segments are excluded
  from the step a length (rule 3); the neighbour AS for step c is the leftmost
  AS of the first AS_SEQUENCE past them (rule 2), or the local AS for a path
  entirely internal to the confederation (rule 1); and a confederation peer
  counts as *internal* at step d, so its LOCAL_PREF is weighed (rule 4).
  Membership is inferred from the presence of AS_CONFED segments, since RFC
  5065 §4.1 requires them to be stripped before a route leaves a
  confederation — netom has no confederation identifier in its configuration.
* **Step g across address families.** A v6 session can carry v4 NLRI, so peer
  addresses of both families can meet at step g. The RFC says nothing about
  ordering between them; every IPv4 address sorts before every IPv6 one. It is
  arbitrary, but stable.
* **AS4_PATH is read for loop detection but not merged.** RFC 6793 §4.2.3's
  reconstruction preserves the AS count, so step a is unaffected either way,
  and loop detection reads both attributes as the RFC requires. What is not
  reconstructed is step c's neighbour AS, which stays the one in the AS_PATH as
  received; a row carrying AS4_PATH says so via `assumed`.

### Assumptions

A candidate carries an `assumed` array when a tiebreaker input was missing but
not disqualifying:

* `routeSource` — the session has no recorded local ASN, so EBGP vs IBGP (step
  d) is unknown and the route was treated as EBGP. MRT-replayed peers have no
  local end at all.
* `bgpIdentifier` — the peer's BGP Identifier is unknown, so step f used
  `255.255.255.255`; an unknown identifier loses a tie rather than winning it.
  Both natively terminated and BMP-monitored peers record one, so in practice
  this appears only for MRT replay and for sessions registered by an older
  netom.
* `as4Path` — the route carries AS4_PATH (RFC 6793), so it crossed a speaker
  without four-octet ASN support and its AS_PATH holds AS_TRANS placeholders.
  Step a is unaffected, since the RFC's reconstruction preserves the AS count,
  and loop detection reads both attributes — but step c's neighbour AS comes
  from the AS_PATH as received.

## Whole-table dumps

A bare `/routes` (or an explicit `/0` plus `moreSpecifics`) covers the entire
table, and is treated differently from a bounded lookup:

* **`format=jsonl` is required.** Without it the request is refused with 400.
  The JSON path builds the whole response in memory before serialising it,
  which spikes RSS on a production-sized table; the jsonl path streams within a
  bounded buffer.
* **Concurrency is capped.** At most 8 full-RIB dumps may be in flight across
  all output paths — HTTP dumps and `bmp-tcp-out` table dumps share the count.
  Over that, the request gets 503 rather than being queued.
* **A dump has a 3 hour wall-clock backstop.** On expiry the response ends
  cleanly with a partial table and a warning in the log, rather than running
  forever.
* **A stalled client is dropped.** If the client stops draining for 60s the
  dump is aborted.

`?ingressId=` narrows a dump's *output* but not its cost: the walk still visits
every prefix, because the store has no per-mui prefix index. See the RIB query
API section of `TODO.md`.

## Errors

Errors come back as `{"data": null, "error": "<message>"}` with:

| Status | When |
| --- | --- |
| 400 | Unparseable prefix or parameter value, an undefined `function[roto]`, a full dump without `format=jsonl`, an unsupported FlowSpec parameter, a FlowSpec response over the limits, or `include`/`format=jsonl`/an unknown `strategy` on `/best-path` |
| 500 | Store not ready, or an unimplemented AFI/SAFI |
| 503 | Dump concurrency cap reached |

The FlowSpec endpoints accept only `ingressId`, `filter[ingressType]` and
`include`; every other filter, `fields[pathAttributes]`, `function[roto]` and
`format=jsonl` are rejected with 400 naming the offending parameters, rather
than being silently ignored. A FlowSpec response is also capped at 10,000 rules
and 16 MiB of raw NLRI; over that the query is refused and must be narrowed by
prefix or `ingressId`. Note that `filter[ingressType]` is applied after the
store walk, so it does not help a response fit under those caps.

## Related endpoints

* `GET /api/v1/ingresses` — the peers and sessions the ids above refer to.
  Accepts `filter[type]`, `filter[state]`, `filter[ribType]`,
  `filter[peerAddress]`, `filter[peerAsn]` and `format`.
* `GET /api/v1/ingresses/{id}` — one ingress.
* `GET /api/v1/bgp/neighbors[/{peer}]` — session state and per-peer counters,
  merging natively terminated and BMP-monitored peers.
