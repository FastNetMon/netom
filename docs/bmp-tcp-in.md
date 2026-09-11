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
