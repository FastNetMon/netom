# ADD-PATH and FlowSpec in the HTTP API

How ADD-PATH (RFC 7911) sessions, FlowSpec rules (RFC 8955/8956), and
FlowSpec-over-ADD-PATH appear in Netom's HTTP API. All example responses in
this document are captured from a live instance fed a BMP session that
negotiated ADD-PATH for IPv4 unicast + IPv4 flowspec and announced one
prefix and two flowspec rules under two path ids.

For the query API itself — every endpoint, the full filter list, response
shapes and dump limits — see `docs/rib-query-api.md`. This document covers
only what ADD-PATH and FlowSpec add on top.

## Data model: sessions and path-child ingresses

Every route in the RIB is stored under an *ingress id* (the store's `mui`).
For a plain session that id is the session itself. When a session negotiates
ADD-PATH for a family, each distinct `(session, path_id)` pair gets its own
child ingress of type `bgpPath`:

* the child's `parent_ingress` points at the session (a `bgpViaBmp` or
  `bgp` entry) and its `path_id` holds the RFC 7911 path identifier;
* routes of *every* ADD-PATH family — unicast, multicast, and flowspec —
  from that path are stored under the child's id, so several paths for one
  NLRI from one peer coexist in the RIB;
* children connect, disconnect, and garbage-collect together with their
  session, and are reused across session flaps (same `(session, path_id)`
  identity);
* children are display/storage entities only: `bmp-tcp-out` resolves them
  back to the parent session for the downstream per-peer header and
  re-attaches the path id when encoding NLRI.

## `/api/v1/ingresses`

The session entry advertises the negotiated ADD-PATH families
(`addpath_families`, decoded from capability 69); each path shows up as a
`bgpPath` child:

```json
{
  "data": [
    {
      "id": 3,
      "ingress_type": "bgpViaBmp",
      "parent_ingress": 2,
      "state": "Connected",
      "remote_addr": "10.99.0.1",
      "remote_asn": 65001,
      "bgp_id": [10, 99, 0, 1],
      "local_addr": "10.99.0.254",
      "rib_type": "AdjRibIn",
      "peer_rib_type": "inPre",
      "local_capabilities": ["MultiProtocol", "MultiProtocol", "AddPath", "FourOctetAsn"],
      "remote_capabilities": ["MultiProtocol", "MultiProtocol", "AddPath", "FourOctetAsn"],
      "addpath_families": ["Ipv4Unicast/SendReceive", "Ipv4FlowSpec/SendReceive"]
    },
    {
      "id": 4,
      "ingress_type": "bgpPath",
      "parent_ingress": 3,
      "state": "Connected",
      "remote_addr": "10.99.0.1",
      "remote_asn": 65001,
      "bgp_id": [10, 99, 0, 1],
      "path_id": 1
    },
    {
      "id": 5,
      "ingress_type": "bgpPath",
      "parent_ingress": 3,
      "state": "Connected",
      "remote_addr": "10.99.0.1",
      "remote_asn": 65001,
      "bgp_id": [10, 99, 0, 1],
      "path_id": 2
    }
  ]
}
```

(The `bmp` router entry, id 2 here, is omitted for brevity. `path_id` and
`addpath_families` are only present where they apply — absent fields are
skipped, not null.)

To enumerate the paths of a session: filter the list on
`ingress_type == "bgpPath" && parent_ingress == <session id>`.

## Unicast routes with ADD-PATH

`GET /api/v1/ribs/ipv4unicast/routes/10.0.0.0/24` (same shape for
`ipv6unicast`). Each stored path is one entry in `routes`, and its
`ingress` object tells you which path it is — a `bgpPath` ingress with
`path_id`, rather than the session itself:

```json
{
  "meta": null,
  "data": {
    "nlri": "10.0.0.0/24",
    "routes": [
      {
        "status": "active",
        "ingress": {
          "id": 4,
          "ingress_type": "bgpPath",
          "parent_ingress": 3,
          "state": "Connected",
          "remote_addr": "10.99.0.1",
          "remote_asn": 65001,
          "bgp_id": [10, 99, 0, 1],
          "path_id": 1
        },
        "rpki": { "rov": "notChecked" },
        "pathAttributes": [
          { "origin": "Igp" },
          { "asPath": ["AS65001"] },
          { "conventionalNextHop": "192.0.2.1" }
        ]
      },
      {
        "status": "active",
        "ingress": {
          "id": 5,
          "ingress_type": "bgpPath",
          "parent_ingress": 3,
          "state": "Connected",
          "remote_addr": "10.99.0.1",
          "remote_asn": 65001,
          "bgp_id": [10, 99, 0, 1],
          "path_id": 2
        },
        "rpki": { "rov": "notChecked" },
        "pathAttributes": [
          { "origin": "Igp" },
          { "asPath": ["AS65001"] },
          { "conventionalNextHop": "192.0.2.2" }
        ]
      }
    ]
  },
  "included": {}
}
```

A route from a non-ADD-PATH session looks the same except that `ingress` is
the session entry itself (`bgpViaBmp`/`bgp`, no `path_id`).

Every route also carries a `source` object, elided from the capture above,
which states the same identity without a second lookup:

```json
"source": { "ingressId": 3, "pathId": 1, "internalPathIngressId": 4 }
```

`ingressId` is the owning **session**, `pathId` the RFC 7911 identifier, and
`internalPathIngressId` the child mui — the last two present only for
ADD-PATH records. So `source.pathId != null` selects the ADD-PATH routes out
of any result, and grouping on `source.ingressId` collapses a peer's paths
back into one peer. `ingress.id` is the child for those rows, not the
session.

## FlowSpec rules

`GET /api/v1/ribs/ipv4flowspec/routes` (or `ipv6flowspec`; add
`/{prefix}/{len}` to query one destination prefix). Rules are keyed on
their destination-prefix component (`keyPrefix`; the family default route
`0.0.0.0/0` / `::/0` when a rule has no usable one) and carry a decoded
`nlri` string, the raw rule bytes (`nlriHex`, the rule's identity), decoded
traffic `actions`, and the RFC 8955 §6 `validity`.

### FlowSpec over ADD-PATH

For a rule received on an ADD-PATH session, `ingressId` is the `bgpPath`
child; the rule's `source` object (elided from the capture below, same shape
as for unicast) resolves it to the owning session and path id. Two rules
from paths 1 and 2 of the session above:

```json
{
  "data": [
    {
      "keyPrefix": "10.0.0.0/24",
      "ingressId": 4,
      "validity": "valid",
      "nlri": "dst 10.0.0.0/24, proto =17",
      "nlriHex": "01180a0000038111",
      "actions": [],
      "attributes": {
        "rpki": { "rov": "notChecked" },
        "pathAttributes": [
          { "origin": "Igp" },
          { "asPath": ["AS65001"] },
          { "mpReachNlri": { "nextHop": "empty" } }
        ]
      }
    },
    {
      "keyPrefix": "10.0.0.0/24",
      "ingressId": 5,
      "validity": "valid",
      "nlri": "dst 10.0.0.0/24, dport =53",
      "nlriHex": "01180a0000058135",
      "actions": [],
      "attributes": {
        "rpki": { "rov": "notChecked" },
        "pathAttributes": [
          { "origin": "Igp" },
          { "asPath": ["AS65001"] },
          { "mpReachNlri": { "nextHop": "empty" } }
        ]
      }
    }
  ]
}
```

A rule from a non-ADD-PATH session carries the session's own id in
`ingressId`.

### Validity

`validity` is the RFC 8955 §6 state, refreshed against the current unicast
RIB on every query: `valid`, `invalid`, `unvalidatable` (no usable
destination prefix), or `not-validated`. Validation compares BGP originator
identities and treats a session and all of its `bgpPath` children as one
peer — in the example above the rules under child muis 4/5 validate against
the covering `10.0.0.0/24` unicast routes of the same session.

## Filtering by ingress

`?ingressId=<id>` and `filter[ingressType]=<type>` are documented in
`docs/rib-query-api.md`; what follows is only what they mean for a peer with
ADD-PATH.

`?ingressId=` selects one exact store mui, and an ADD-PATH peer's routes live
under its children. So **filtering by a child id gives you one path**, while
filtering by the *session* id returns only what the session stored directly
— its non-ADD-PATH families — and does not aggregate the children. To get
everything one peer contributed this way, collect the session id plus its
`bgpPath` children from `/api/v1/ingresses` and query per id.

`filter[ingressType]=` is the opposite: it resolves a child through
`parent_ingress` and judges it by its session, so `bgp` returns every path of
an ADD-PATH BGP peer rather than dropping them all. `bgpPath` selects the
path-children themselves, across every session type.

Neither filter changes the identity in the response: a row returned under
`filter[ingressType]=bgp` still reports `ingress.ingress_type: "bgpPath"`,
with the session in `source.ingressId`.

## On the wire (bmp-out)

Downstream BMP consumers never see the child ingresses. `bmp-tcp-out`
emits one downstream peer per session; its synthesized Peer Up advertises
capability 69 in both OPENs for the negotiated families it re-encodes with
path ids (v4/v6 unicast and flowspec — multicast is folded into the unicast
NLRI space), and every re-encoded NLRI from a `bgpPath`-stored route
carries its 4-byte path id: prepended to the prefix in the classic
NLRI/withdrawn fields for unicast, and preceding the RFC 8955 length header
inside MP_REACH/MP_UNREACH for flowspec. With `fastpath` enabled the
original UPDATE bytes are forwarded verbatim instead, path ids included.
See `docs/bmp-tcp-out.md` and `scripts/e2e-addpath-bmp.sh` for the
end-to-end behavior.
