# BMP TCP Out Unit

The `bmp-tcp-out` unit restreams BMP (BGP Monitoring Protocol, RFC 7854) data to
downstream consumers. It accepts TCP connections from BMP collectors and sends
them a full initial table dump followed by real-time updates.

## Configuration

```toml
[units.bmp-out]
type = "bmp-tcp-out"
listen = "0.0.0.0:11020"
sources = ["rib"]
rib_unit = "rib"
sys_name = "netom-bmp-out"
sys_descr = "Netom BMP restreamer"
max_client_buffer = 100000
forward_router_info = true
acl = ["0.0.0.0/0", "::/0"]

# Optional TLS
tls = false
tls_cert = "/path/to/cert.pem"
tls_key = "/path/to/key.pem"
```

### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `listen` | yes | — | Address and port to listen on for BMP client connections. |
| `sources` | yes | — | Upstream gate(s) to receive live updates from (typically a RIB unit). |
| `rib_unit` | no | `"rib"` | Name of the RIB unit used for the initial table dump. |
| `sys_name` | no | `"netom-bmp-out"` | Value sent in the BMP Initiation Message sysName TLV. |
| `sys_descr` | no | `"Netom BMP restreamer"` | Value sent in the BMP Initiation Message sysDescr TLV. |
| `max_client_buffer` | no | `100000` | Maximum number of updates buffered per client during the initial dump phase. If exceeded, the client is disconnected. See [Buffer Overflow](#buffer-overflow) below. |
| `acl` | yes | — | List of allowed client IP addresses or CIDR prefixes. Use `["0.0.0.0/0", "::/0"]` to allow all. |
| `forward_router_info` | no | `true` | Include upstream router identity (sysName/sysDescr) as a JSON Admin Label TLV (type 4, RFC 9736) in Peer Up messages. |
| `fastpath` | no | `true` | Restream live Route Monitoring messages verbatim instead of rebuilding them from parsed routes, for peers whose raw copies arrive from a `bmp-tcp-in` unit with `forward_raw_updates` on (the default). See [Fastpath](#fastpath) below. |
| `tls` | no | `false` | Enable TLS encryption for client connections. |
| `tls_cert` | no | — | Path to PEM certificate file. If omitted with `tls = true`, a self-signed certificate is generated. |
| `tls_key` | no | — | Path to PEM private key file. Required if `tls_cert` is set. |

## How It Works

### Connection Lifecycle

When a BMP consumer connects:

1. **ACL check** — the client IP is checked against the `acl` list. Rejected connections are closed immediately.
2. **Initiation Message** — a BMP Initiation Message (type 4) is sent with `sys_name` and `sys_descr`.
3. **Initial table dump** — for each active BGP peer known to Netom:
   - A BMP Peer Up Notification is sent (with synthetic BGP OPEN messages).
   - All routes for that peer are read from the RIB and sent as BMP Route Monitoring messages.
   - End-of-RIB markers are sent per address family (IPv4 Unicast, IPv6 Unicast).
4. **Buffered updates drained** — any live updates that arrived during the dump are replayed.
5. **Live phase** — the client receives real-time updates as they arrive from upstream.

### Update Types

| Upstream event | BMP message sent |
|---|---|
| Route announcement/withdrawal | Route Monitoring (type 0) wrapping a BGP UPDATE |
| BGP session down | Peer Down Notification (type 2) |
| BGP session reappears | Peer Up Notification (type 3) |

### Buffer Overflow

During the initial dump phase, live updates are buffered in memory so they can
be replayed after the dump completes. If the RIB is large and the update rate is
high, the buffer can fill up before the dump finishes.

When the buffer exceeds `max_client_buffer`, the client is **disconnected**. The
`netom_bmp_tcp_out_buffer_overflows_total` metric tracks how often this happens.

**Tuning considerations:**

- If `netom_bmp_tcp_out_buffer_overflows_total` is increasing and the system
  has sufficient RAM available, increasing `max_client_buffer` (e.g., to 200000
  or 500000) can resolve the issue by giving the initial dump more time to
  complete before the buffer fills up.
- Each buffered update consumes approximately 750-900 bytes of memory. Use this
  table to estimate peak memory usage per client:

  | `max_client_buffer` | Approx. RAM per client |
  |---------------------|------------------------|
  | 100,000 (default)   | ~75-90 MB              |
  | 200,000             | ~150-180 MB            |
  | 500,000             | ~375-450 MB            |

- If buffer overflows persist even with a larger buffer, the root cause is
  usually that the dump is too slow relative to the update rate. Consider
  whether the consuming application can keep up with the data rate.

### Admin Label TLV (Upstream Router Identity)

When `forward_router_info = true` (the default), each Peer Up Notification
includes an **Admin Label TLV** (type 4, as defined in RFC 9736). The value is
a JSON object carrying the upstream BMP router's `sysName` and `sysDescr` that
were received via the BMP Initiation Message on the `bmp-tcp-in` side.

This allows downstream BMP consumers to identify which upstream router each
peer belongs to, even when netom multiplexes multiple routers into a single
BMP session.

Fields whose value is a placeholder (`"no-sysname"` / `"no-sysdesc"`) or empty
are omitted from the JSON. If both fields are absent, the TLV is not included.

Set `forward_router_info = false` to disable the TLV entirely.

#### Wire Format Specification for Downstream Implementors

The TLV appears **after** the two BGP OPEN messages inside the BMP Peer Up
Notification (message type 3), as permitted by RFC 9736 Section 4.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Type = 4              |            Length              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Value (UTF-8 JSON)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Type** (2 bytes, big-endian): `0x0004` — Admin Label (RFC 9736 Section 4.4).
- **Length** (2 bytes, big-endian): byte length of the Value field.
- **Value**: UTF-8 encoded JSON object.

#### JSON Schema

```json
{
  "sysName":  "<string>",
  "sysDescr": "<string>"
}
```

Both keys are optional. At least one will be present when the TLV is included.
Values are JSON-escaped (e.g. `\"`, `\\`, `\n`). Downstream parsers should
tolerate unknown keys for forward compatibility.

#### Parsing Algorithm

To extract the Admin Label from a Peer Up Notification:

1. Parse the BMP Common Header (6 bytes) — verify message type = 3.
2. Skip the Per-Peer Header (42 bytes).
3. Skip Local Address (16 bytes), Local Port (2 bytes), Remote Port (2 bytes).
4. Parse the Sent OPEN message: read its BGP length field (bytes 16–17 of
   the BGP message, big-endian) and skip that many bytes total.
5. Parse the Received OPEN message the same way.
6. Any remaining bytes are TLVs. For each TLV:
   - Read Type (2 bytes) and Length (2 bytes), both big-endian.
   - If Type = 4, the next Length bytes are the Admin Label JSON.
   - Otherwise skip Length bytes (unknown TLV — ignore).

#### Examples

Full Peer Up with Admin Label (both fields):
```
Type: 0x0004  Length: 0x002E
Value: {"sysName":"edge-rtr01","sysDescr":"Cisco IOS XR 7.9.1"}
```

Only sysName present:
```
Type: 0x0004  Length: 0x001A
Value: {"sysName":"edge-rtr01"}
```

No Admin Label TLV is present when:
- `forward_router_info = false` in config, or
- The upstream BMP router did not send sysName/sysDescr in its Initiation
  Message, or sent only placeholder values.

## Fastpath

Without fastpath, every restreamed Route Monitoring message is *rebuilt*:
the upstream message is parsed into per-route payloads at ingest, stored in
the RIB, and re-encoded into a fresh BGP UPDATE here. With fastpath the
live path instead forwards the **original BGP UPDATE bytes verbatim**,
re-synthesizing only the BMP common and per-peer headers.

Fastpath is **on by default** on both ends:

```toml
[units.bmp-in]
type = "bmp-tcp-in"
forward_raw_updates = true   # default; emit verbatim copies before the parsed routes

[units.bmp-out]
type = "bmp-tcp-out"
fastpath = true              # default; consume them, skip the rebuild path per covered peer
```

Coverage is **adaptive per peer**, so any flag combination is loss-free: a
peer is served from raw copies only while its raw copies are actually
arriving. `bmp-tcp-in` emits the raw copy *before* the parsed payloads of
the same message and does so for every parsed message of an eligible
session, so the switchover point can neither duplicate a message nor drop
one. Coverage marks are cleared on Peer Down / session teardown, because
ingress ids can be re-bound to reconnecting sessions with different
settings.

What fastpath changes:

- **Fidelity** — path attributes, exotic/unknown attributes and the exact
  NLRI encoding reach the consumer byte-for-byte; the per-peer header
  timestamp is the original export time; the A-flag (legacy 2-byte AS
  encoding) reflects the encoding the message actually parsed with. The
  peer identity fields and the fan-in `peer_distinguisher` still come from
  the Peer Up this unit synthesized, so the (peer, pd, rib_type) keying
  stays consistent.
- **Live EoR passthrough** — upstream End-of-RIB markers received after
  the initial dump phase are forwarded verbatim (the rebuild path never
  restreamed live EoRs at all). Messages carrying only NLRI types the RIB
  cannot store are likewise forwarded instead of vanishing.
- **Cost** — the per-route re-encode and pa-blob re-aggregation are
  skipped on the live path.

What it does *not* change:

- **The initial table dump** stays on the rebuild path — raw bytes are not
  stored in the RIB.
- **Non-BMP sources** (BGP, MRT) have no raw copies; their routes keep
  being rebuilt.
- **ADD-PATH sessions** participate fully. Each `(session, path_id)` is
  stored under its own path-child ingress (`IngressType::BgpPath`); on emit
  the child resolves back to its parent session's per-peer header, the
  synthesized Peer Up advertises the ADD-PATH capability (code 69,
  SendReceive, in both OPENs) for the session's negotiated v4/v6 unicast
  families, and the rebuild path re-attaches the 4-byte path id to the
  NLRI — in the initial dump and live. With `fastpath` enabled their live
  UPDATEs are forwarded verbatim like any other BMP session (the raw copy
  carries the session id; the duplicate-suppression check resolves the
  parsed payloads' child ids back to the session). (Multicast ADD-PATH
  routes are emitted with path ids inside the unicast NLRI space — the
  encoder's pre-existing family collapse; FlowSpec-ADD-PATH routes are
  dropped at ingest.)

Caveat: fastpath is a **pre-filter mirror**. Routes dropped or rewritten by
roto filters in upstream units are restreamed in their original form. Set
`fastpath = false` on this unit if downstream consumers must observe
filtered data. In pipelines with no bmp-tcp-out unit at all, set
`forward_raw_updates = false` on bmp-tcp-in to save one gate update per
Route Monitoring message.

## Prometheus Metrics

All metrics are exported under the configured unit name (e.g., `component="bmp-out"`).

| Metric | Type | Description |
|--------|------|-------------|
| `netom_bmp_tcp_out_listener_bound_count_total` | counter | Number of times the TCP listen port was bound. |
| `netom_bmp_tcp_out_clients_connected_total` | counter | Total BMP client connections accepted. |
| `netom_bmp_tcp_out_clients_disconnected_total` | counter | Total BMP client connections lost. |
| `netom_bmp_tcp_out_messages_sent_total` | counter | Total BMP messages sent to all clients. |
| `netom_bmp_tcp_out_bytes_sent_total` | counter | Total bytes sent to all clients. |
| `netom_bmp_tcp_out_active_dumps_total` | gauge | Number of clients currently receiving an initial table dump. |
| `netom_bmp_tcp_out_buffer_overflows_total` | counter | Number of clients disconnected due to buffer overflow during dump. |
| `netom_bmp_tcp_out_acl_rejected_total` | counter | Number of connections rejected by ACL. |
| `netom_bmp_tcp_out_tls_handshake_failures_total` | counter | Number of TLS handshake failures. |

## Example Configuration

Minimal setup receiving from a BMP input and restreaming:

```toml
[units.bmp-in]
type = "bmp-tcp-in"
listen = "0.0.0.0:11019"

[units.rib]
type = "rib"
sources = ["bmp-in"]

[units.bmp-out]
type = "bmp-tcp-out"
listen = "0.0.0.0:11020"
sources = ["rib"]
rib_unit = "rib"
acl = ["0.0.0.0/0", "::/0"]

[targets.null]
type = "null-out"
sources = ["rib"]
```

With TLS and restricted access:

```toml
[units.bmp-out]
type = "bmp-tcp-out"
listen = "0.0.0.0:11020"
sources = ["rib"]
rib_unit = "rib"
sys_name = "my-collector"
sys_descr = "Production BMP restreamer"
max_client_buffer = 200000
acl = ["10.0.0.0/8", "2001:db8::/32"]
tls = true
tls_cert = "/etc/netom/cert.pem"
tls_key = "/etc/netom/key.pem"
```
