# BMP input: listening or connecting

A `bmp-tcp-in` unit can accept router connections or actively connect to a BMP
exporter. Use exactly one of `listen` and `connect`. Each active unit maintains
one session; use multiple units for multiple exporters.

```toml
[units.feed-a]
type = "bmp-tcp-in"
connect = "exporter.example.net:11019"
forward_raw_updates = false

[units.feed-b]
type = "bmp-tcp-in"
connect = "[2001:db8::1]:11020"
tls = { ca_file = "/etc/netom/exporter-ca.pem", server_name = "exporter.example.net" }
forward_raw_updates = false

[units.rib]
type = "rib"
sources = ["feed-a", "feed-b"]
retain_withdrawn_attributes = false

[targets.null]
type = "null-out"
sources = ["rib"]
```

The existing `listen = "0.0.0.0:11019"` configuration remains supported.
`connect` accepts a DNS name, IPv4 address, or bracketed IPv6 address and a port.
The BMP collector only receives messages, regardless of which side opens TCP.

## TLS

Omit `tls` for plain TCP. `tls = {}` verifies the certificate and endpoint name
using bundled public CA roots. `ca_file` selects a PEM CA bundle instead;
`server_name` overrides certificate name verification and DNS SNI. A file is
read on each connection attempt, so replacing its contents takes effect at the
next reconnect.

For encryption-only compatibility with self-signed exporters, explicitly use
`tls = { insecure = true }`. This skips certificate trust/name checks and matches
bgpviewd's `bmps_endpoints` mode. It cannot be combined with `ca_file`.

## Reconnects and reloads

DNS resolution, TCP connection and TLS handshake share a 15-second deadline.
Failures and short-lived sessions retry after 1, 2, 4, … seconds, capped at 300.
A session lasting five minutes resets that backoff. TCP keepalive uses 60 seconds
idle and 15 seconds between probes; the operating system supplies the probe count.

Changing the endpoint or TLS settings on reload cancels the old attempt/session,
runs the usual peer invalidation and ingress cleanup, then starts the new one.
An unchanged endpoint/TLS configuration keeps its session. Shutdown cancels
connect, handshake, idle reads and retry delays. Downstream backpressure can
still delay cleanup; the daemon's shutdown/drain rules apply.

The existing filtering and tracing settings apply to active input as well.
`ignore_post_policy_routes`, `forward_raw_updates`, and `reconciliation` changes apply to the next
connection. Listening address changes preserve existing accepted connections.

## Automatic reconciliation and stale-peer retention

Reconciliation is enabled for every BMP input, for both `listen` and `connect`.
No opt-in is needed. The former experimental `recover_unnumbered_peers` heuristic
has been replaced: Netom does not infer that a shared BGP identifier authorizes
it to delete another peer.

An exporter can omit Peer Down or send it with an address that no longer matches
Peer Up. [Issue #11](https://github.com/FastNetMon/netom/issues/11) describes FRR
reporting `::` after losing an unnumbered peer's old link-local address. The
collector otherwise retains that peer as connected, including all of its routes.
GC cannot reclaim state that still appears live.

Netom repairs the observation by closing **that speaker's BMP transport** and
rebuilding from a fresh snapshot on reconnection. It uses normal disconnect
processing to withdraw every peer, policy view and ADD-PATH child owned by the
connection. Their disconnected register entries and records are reclaimed by
normal RIB GC if they are not rebound. Other speakers' state is not withdrawn.

This follows [RFC 7854 §3.2](https://www.rfc-editor.org/rfc/rfc7854.html#section-3.2):
a collector restarts monitoring by dropping the TCP connection. Under
[§3.3](https://www.rfc-editor.org/rfc/rfc7854.html#section-3.3), reconnection starts
with Initiation, Peer Up for each established monitored peer, and its current
Adj-RIB-In. [§5](https://www.rfc-editor.org/rfc/rfc7854.html#section-5) describes
that snapshot and per-peer End-of-RIB markers. BMP does not provide a collector
request to refresh one peer, or a global marker proving all peers have been
listed.

Refresh triggers and default bounds:

| Condition | Behavior |
| --- | --- |
| Accepted Peer Down cannot match a logical peer (ignoring policy flags) | Schedule reconciliation, no earlier than 60 seconds after connection start. Repeated anomalies do not postpone it. |
| A new link-local address has the same ASN, BGP identifier, peer type and distinguisher as an existing link-local peer | After the startup window, reconcile the whole speaker; do not guess which session is obsolete. |
| Peer Ups arrive within the first 300 seconds | Accept parallel identities as part of startup/replay. Possible-replacement detection is suppressed; unmatched Peer Down and capacity protection still apply. |
| No detectable anomaly, including a completely silent connection | Renew every 6 hours, plus independently selected 0–10% jitter. This bounds the age of an unreconciled observation. |
| The connection reaches 65,536 FSM peer states, including policy views | Close immediately, even within the minimum session lifetime. This is a per-connection peer-state limit, **not a total process-memory or route-count limit**. |

The first anomaly after the minimum lifetime can close the connection immediately.
Anomalies early in a new connection are coalesced until that minimum. Replay
collisions within the startup window do not cause a new reset, so legitimate
parallel sessions in an ordinary fresh snapshot survive. A timer also interrupts
an idle transport or a partial BMP frame; a cancelled partial read is discarded
with its transport and is never resumed.

The defaults can be tuned without disabling reconciliation:

```toml
[units.bmp-in]
type = "bmp-tcp-in"
listen = "0.0.0.0:11019"
reconciliation = { interval_secs = 21600, min_session_secs = 60, replay_grace_secs = 300, max_peer_states = 65536 }
```

Validation requires `0 < min_session_secs <= replay_grace_secs < interval_secs
<= 604800` and `max_peer_states > 0`. The maximum interval is seven days before
jitter. Changes take effect on the next BMP connection. Unmatched messages
rejected by a Roto filter do not trigger anomaly reconciliation; periodic and
capacity guards remain active.

### Operational caveat

This recovery has a cost: it withdraws the speaker's routes from Netom and its
downstream consumers until replay restores them. It does **not** reset the
router's BGP sessions, but it causes a monitoring gap and a full-table replay,
which consumes exporter CPU, bandwidth, and collector work. Consumers may see
withdrawal/reannouncement events. This is not an atomic or gap-free snapshot
replacement, and downstream backpressure can delay withdrawal/GC processing.

For passive inputs, the exporter must reconnect. For active inputs, Netom's
normal retry/backoff reconnects. Replay depends on the exporter supplying a
current snapshot; an incremental-only exporter cannot restore missing routes,
and an exporter that replays obsolete peers cannot be corrected by reconciliation.
No timeout can distinguish an idle live peer from a dead peer whose Peer Down
was never sent, so Netom never deletes a peer merely for having no updates.
A missed disappearance during startup may remain visible until periodic renewal.

The startup window is a conservative time allowance, not proof that replay has
finished. Size it for exporters with slow or very large initial dumps; parallel
Peer Ups arriving after it can cause an additional refresh. A legitimate feed
above the peer-state limit will repeatedly hit that limit until capacity is
raised or the feed is split. The hard limit overrides cooldown; the active
connector/exporter's reconnect backoff must still be respected. Neither the
peer limit nor periodic renewal promises a fixed byte limit for all collector
memory. Physical reclamation also waits for the normal RIB GC sweeps.

Each refresh logs its reason and speaker address. `scripts/bmp-peer-churn.py`
exercises current-state replay, disappearance, parallel peers, partial frames,
and capacity protection; see [TESTING.md](../TESTING.md).

## History and initial data

TCP and TLS use the same BMP parser, peer identities, ADD-PATH handling and
withdrawal logic as passive input. If the exporter sends a synthetic initial
full dump (including Netom's `bmp-tcp-out`), these announcements populate the RIB
and appear as observations in ClickHouse. No separate dump request is sent.
An exporter offering only subsequent updates cannot supply earlier routes.

Point a `clickhouse-out` target at the input unit names to record received
observations before RIB mutation. See [ClickHouse export](clickhouse.md).
Exporter-generated snapshots and EOR completeness tracking remain later work.

## Integration tests

The ClickHouse test driver can act as a BMP exporter:

```sh
python3 scripts/e2e-clickhouse.py --serve --bmp 127.0.0.1:11119
python3 scripts/e2e-clickhouse.py --serve --bmp 127.0.0.1:11120 \
  --tls-cert /tmp/bmp-test.crt --tls-key /tmp/bmp-test.key
```

Configure active inputs for these ports and include both in the history target's
sources. The driver checks identical observations, IPv4/IPv6, ADD-PATH IDs, raw
attributes, derived columns, and peer invalidations in ClickHouse. Its router
names isolate each test from live feeds. It accepts one connection and exits.
