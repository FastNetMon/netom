# Netom

**Collect, inspect, and restream BGP routing data.**

Netom is an open-source routing data engine maintained by FastNetMon. It collects
routes from BGP peers, BMP (BGP Monitoring Protocol) feeds, and MRT routing dump
files, then keeps them in an in-memory routing table (RIB) for queries and export.
Use it for routing visibility, troubleshooting, and feeding downstream monitoring
systems such as FastNetMon.

**[Quickstart](docs/quickstart.md)** · [Full documentation](https://fastnetmon.github.io/netom/) · [Releases](https://github.com/FastNetMon/netom/releases) · [Report an issue](https://github.com/FastNetMon/netom/issues)

## What can it do?

- **Collect routes:** accept or initiate BGP and BMP connections, or import MRT files.
- **Inspect routing data:** query routes, peers, AS paths, and communities through
  the router-style CLI or HTTP/JSON API, including ADD-PATH and FlowSpec data.
- **Filter and process:** connect pipeline components and apply programmable Roto filters.
- **Restream BMP:** send downstream consumers an initial routing table followed
  by live updates, with TLS, access controls, and slow-consumer protection.
- **Monitor the collector:** expose Prometheus metrics and operational logs.
- **Export observations:** send Roto-generated messages to files or MQTT, or try
  the experimental ClickHouse output for IPv4/IPv6 unicast history.

## What are its limits?

- **It does not forward traffic or advertise routes over BGP.** Netom collects
  routing information; it is not a replacement for a router or route reflector.
- **The live routing table is not persistent.** After a restart, routes must be
  learned or imported again. ClickHouse history does not restore the live RIB.
- **ClickHouse output is experimental.** Sustained high-rate throughput has not
  been qualified, and it does not provide complete historical routing state.
- **The CLI is read-only.** Configure Netom through its TOML configuration file.
- **Interfaces are still evolving.** Configuration, APIs, and Roto syntax may
  change between 0.x versions.

## Get started

- [Run your first BMP collector](docs/quickstart.md).
- [Run Netom as a Linux service](docs/quickstart.md#run-an-installed-package-as-a-service).
- [Build packages and containers](docs/releases.md#local-builds).

## Go further

| I want to… | Guide |
| --- | --- |
| Configure sources, filters, and outputs | [Configuration](docs/configuration.md) · [Example config](etc/netom.conf) |
| Inspect peers and routes | [CLI](docs/cli.md) · [HTTP API](docs/rib-query-api.md) |
| Connect to a remote feed | [BMP input](docs/bmp-tcp-in.md) · [Active BGP](docs/bgp-active-mode.md) |
| Feed another monitoring system | [BMP restreaming](docs/bmp-tcp-out.md) |
| Store route observations | [ClickHouse](docs/clickhouse.md) |
| Install packages or build containers | [Packages and builds](docs/releases.md) |

## Contributing and license

Found a bug or have an idea? [Open an issue](https://github.com/FastNetMon/netom/issues).
For patches, see [Contributing](CONTRIBUTING.md) and [Testing](TESTING.md).
Report vulnerabilities using the [security policy](SECURITY.md).

Netom is a FastNetMon-maintained fork of [NLnet Labs Rotonda](https://github.com/NLnetLabs/rotonda/),
not an official NLnet Labs release. It is licensed under the
[Mozilla Public License 2.0](LICENSE); see [NOTICE.md](NOTICE.md) for attribution.
