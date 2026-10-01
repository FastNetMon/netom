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
`ignore_post_policy_routes` and `forward_raw_updates` changes apply to the next
connection. Listening address changes preserve existing accepted connections.

## History and initial data

TCP and TLS use the same BMP parser, peer identities, ADD-PATH handling and
withdrawal logic as passive input. If the exporter sends a synthetic initial
full dump (including Netom's `bmp-tcp-out`), these announcements populate the RIB
and appear as observations in ClickHouse. No separate dump request is sent.
An exporter offering only subsequent updates cannot supply earlier routes.

Point a `clickhouse-out` target at the input unit names to record received
observations before RIB mutation. See [ClickHouse export](clickhouse.md).
Exporter-generated snapshots and EOR completeness tracking remain later work.

## Why a peer's session went down

When one of a monitored router's own BGP sessions goes down, the router sends
a Peer Down Notification (RFC 7854 §4.9). netom records the reason on that
peer and keeps it after the session comes back up, so you can still see why
it last dropped:

* `GET /api/v1/bgp/neighbors` gives the peer's row a `lastError` with a
  one-line summary and a `lastDownTime`.
* `GET /api/v1/ingresses` gives each view of the peer (pre-policy,
  post-policy) a structured `last_down`.

| Reason | `reason` | Carries |
|---|---|---|
| 1 | `localNotification` | the NOTIFICATION the router sent, e.g. `Cease(MaximumPrefixesReached)` |
| 2 | `localFsm` | the FSM event code that made the router close the session |
| 3 | `remoteNotification` | the NOTIFICATION the peer sent, e.g. `Cease(AdministrativeShutdown)` |
| 4 | `remoteNoData` | nothing: the peer closed the session without a NOTIFICATION |
| 5 | `peerDeconfigured` | nothing: the peer was removed from the router's configuration |
| 6 | `localTlv` | (RFC 9069) the router closed the session; TLV data follows |

For a Cease Administrative Shutdown or Administrative Reset NOTIFICATION, the
shutdown communication (RFC 8203, RFC 9003) is decoded too, so a summary reads
like `remote NOTIFICATION: Cease(AdministrativeShutdown) "maintenance"`. The
time is the Peer Down's per-peer header timestamp, or the time netom received
it when the router sends 0.

Two limits:

* A router only reports sessions that reached Established. It sends Peer
  Down only for a peer it sent Peer Up for, so a session that never comes up,
  for example an OPEN rejected for a bad peer AS, never appears here. Look on
  the router itself for those.
* The record lives on the peer's ingress. If a peer stays down until the rib's
  garbage collection reaps it, its record goes with it.

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
