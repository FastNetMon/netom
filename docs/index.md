# Netom documentation

Netom is a programmable BGP and BMP engine maintained by FastNetMon. Connect
routing data sources, keep routes in an in-memory RIB, inspect them through
the CLI or HTTP API, and stream updates to other systems.

Start with the [quickstart](quickstart.md) to run a BMP collector, then use
the [configuration guide](configuration.md) to connect the components you need.
The [CLI guide](cli.md) covers day-to-day inspection; the
[RIB query API](rib-query-api.md) covers automation and route exports.

This manual follows the `main` branch. Netom is under active development;
configuration and API details can change between 0.x versions. See
[releases](releases.md) for package platforms and the publishing process.

```{toctree}
:caption: Getting started
:maxdepth: 1

quickstart
configuration
cli
```

```{toctree}
:caption: Routing pipelines
:maxdepth: 1

bmp-tcp-in
bgp-active-mode
bmp-tcp-out
clickhouse
```

```{toctree}
:caption: Routes and APIs
:maxdepth: 1

rib-query-api
addpath-flowspec-api
best-path-selection
```

```{toctree}
:caption: Project
:maxdepth: 1

releases
documentation
```

Netom is a fork of Rotonda. It is maintained independently and is not an
official NLnet Labs release. See the repository's
[attribution and licensing notes](https://github.com/FastNetMon/netom/blob/main/NOTICE.md).
Report problems in the [Netom issue tracker](https://github.com/FastNetMon/netom/issues).
