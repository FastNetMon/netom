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
| 400 | Unparseable prefix or parameter value, an undefined `function[roto]`, a full dump without `format=jsonl`, an unsupported FlowSpec parameter, or a FlowSpec response over the limits |
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
