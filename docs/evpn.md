# EVPN monitoring

EVPN monitoring is **disabled by default**. Enable it explicitly in the
TOML global settings, above all `[units.*]` and `[targets.*]` tables:

```toml
enable_evpn = true
```

Restart Netom after changing this flag; a reload that changes it is rejected.
This keeps negotiated BGP capabilities and retained routing state consistent.
When disabled, Netom omits EVPN from BGP MP and ADD-PATH capabilities, drops
EVPN announcements and withdrawals from BGP/BMP route conversion through the
unsupported-NLRI accounting path, and returns HTTP 503 with an enablement
message for EVPN queries. Other families continue to work. Verbatim BMP
forwarding is independent of monitoring and can still carry EVPN updates.

EVPN retains a separate collection of routes and attributes, and queries incur
additional copying, allocation, and serialization costs. These costs grow with
routes, paths, tenants, and concurrent queries. Requiring an explicit opt-in
keeps deployments that only monitor other families from accidentally taking
on this state and query load. Enabling EVPN is not a memory or query-cost limit;
size the deployment for its routing state and workload.

With the flag enabled, Netom collects L2VPN EVPN (AFI 25, SAFI 70) from BGP and BMP, including
ADD-PATH sessions. Configure `L2VpnEvpn` in a BGP peer's `protocols` list;
BMP peers use the capabilities in their exported Peer Up messages.

EVPN routes live in a separate RIB. Overlapping tenant prefixes do not collide
with each other or with the global unicast table. Identity includes the route
type, wire-format route distinguisher (RD), route-specific key, and ingress
(including the ADD-PATH child). Type 2 identity excludes ESI and labels;
type 5 identity excludes ESI, gateway, and label. Changes to forwarding fields
replace the same route, and withdrawals match even when labels differ.
Peer Down, family-scoped withdrawals, and ingress cleanup include EVPN.

## Symmetric IRB

Inspect type 2 MAC/IP advertisements and type 5 IP prefix advertisements
together to monitor the MAC-VRF and IP-VRF views of a tenant. The decoder
exposes the RD, Ethernet tag, ESI, MAC, IPv4/IPv6 host or prefix, gateway,
and label fields. Both type 2 labels are preserved for deployments that
advertise a MAC-VRF label and an IP-VRF label.

The API also decodes route targets, the EVPN Router's MAC extended community,
and the MP_REACH next hop. Use a route target to select the routes associated
with a tenant across multiple advertising RDs. An RD distinguishes routes;
it is not a tenant membership or import-policy identifier. Route targets are
reported as advertised; Netom does not simulate VRF import policy or recursive
forwarding resolution.

Label fields are returned as **raw 24-bit integers**. For VXLAN these are
VNIs. For MPLS, decode the label-stack entry according to the encapsulation;
do not interpret the raw field as an MPLS label number. The API does not
infer which VNI is an L2 VNI or L3 VNI from its value alone.

## Query API

`GET /api/v1/ribs/l2vpnevpn/routes` returns `{"data": [...]}`. Each row has:

- `route`: `nlri`, retained `attributes`, `ingress_id`, `ltime`, and `active`;
- `overlay`: `route_targets`, `router_mac`, and `next_hop`;
- `source_ingress_id` and `path_id`: original session and optional ADD-PATH ID.

The `nlri.raw` byte array includes the route type and length header, allowing
inspection of fields not decoded by the API. Types 1, 3, and 4 are retained,
with RD and applicable tag/ESI fields decoded. Unknown route types with an RD
are preserved as opaque records and matched by their complete NLRI.

All filters below are optional and combine with AND:

| Parameter | Meaning |
| --- | --- |
| `rd` | Exact RD, e.g. `65000:100` or `192.0.2.1:100` |
| `route_target` | Exact advertised RT, e.g. `65000:100` |
| `route_type` | Numeric EVPN type, e.g. `2` or `5` |
| `vni` | Match either raw label field (for VXLAN monitoring) |
| `prefix` | Exact type 2 host or type 5 prefix |
| `ingress_id` | Exact stored ingress ID, including ADD-PATH child IDs |
| `include_withdrawn` | `true` includes retained withdrawn records; default `false` |

Unknown parameters are rejected. Withdrawn records are available only when
the RIB is configured to retain withdrawn attributes. A withdrawal preserves
the last announced attributes and forwarding fields.

```sh
curl -G http://127.0.0.1:8080/api/v1/ribs/l2vpnevpn/routes \
  --data-urlencode 'route_target=65000:100' \
  --data-urlencode 'route_type=5'

curl -G http://127.0.0.1:8080/api/v1/ribs/l2vpnevpn/routes \
  --data-urlencode 'rd=192.0.2.1:100' \
  --data-urlencode 'prefix=10.0.0.0/24'
```

The endpoint produces buffered JSON and takes a snapshot of the EVPN table;
large tables require memory proportional to the stored records and response.
It shares the concurrent query limit with other RIB queries.

## Pipeline support and limits

BMP output includes EVPN in live rebuilt updates and initial RIB dumps,
retaining next hops, communities, and ADD-PATH IDs. Synthetic Peer Up messages
and End-of-RIB markers include EVPN when advertised by the source peer.
BGP4MP MRT updates use the same decoder; TABLE_DUMP_V2 EVPN import is not
implemented. Use [`netom-cli show evpn`](cli.md#evpn-routes) for interactive
inspection.
The ClickHouse route schema does not expose EVPN.

Roto route filters can use `is_evpn()` and `evpn_rd()`. `fmt_prefix()` returns
the type 2 host or type 5 prefix; EVPN routes without an IP prefix return
`0.0.0.0/0`, so guard IP-only policies with `is_evpn()`.

Wire formats follow [RFC 7432](https://www.rfc-editor.org/rfc/rfc7432),
[RFC 9135](https://www.rfc-editor.org/rfc/rfc9135), and
[RFC 9136](https://www.rfc-editor.org/rfc/rfc9136).
