# Configuration

Netom reads a TOML file supplied with `netom --config PATH`. Start with the
[quickstart configuration](quickstart.md#create-a-configuration), or download
the repository's [annotated example](../etc/netom.conf).

## Build a pipeline

A configuration describes named **units** and **targets**. Units receive,
process, store, or forward routing data. Targets consume the output of a
pipeline. Each component has a `type`; downstream components name their
upstream units in `sources`.

For example, the quickstart connects `bmp-in` to `rib`, then connects the
RIB to a `null-out` target. The RIB stores routes for queries, while the null
target consumes the pipeline's output. Names such as `bmp-in` and `rib` are
configuration choices; use matching names when connecting components.

| Component | Configuration and behavior |
| --- | --- |
| BMP input | [Listen for exporters or connect to remote feeds](bmp-tcp-in.md) |
| BGP input | [Initiate BGP sessions](bgp-active-mode.md) |
| RIB | [Route queries](rib-query-api.md) and [best path selection](best-path-selection.md) |
| BMP output | [Send a RIB dump followed by live updates](bmp-tcp-out.md) |
| ClickHouse output | [Store observation history](clickhouse.md) |

## Configure logging and HTTP

Global settings belong above the first component table:

```toml
log_level = "info"
log_target = "stderr"
http_listen = ["127.0.0.1:8080"]
```

The HTTP listener serves operational APIs and Prometheus metrics. The
[CLI](cli.md) uses the same listener. Keep it on loopback or restrict access
to a trusted management network; see [API access considerations](cli.md#security).

Component-specific settings belong under that component's table, such as
`[units.bmp-in]`. TOML table scope continues until another table begins, so
placing a global setting at the end of the file would put it inside the
last component instead.

## Example files

The [annotated configuration](../etc/netom.conf) is maintained with the
source code and includes additional pipeline examples. The ClickHouse guide
also provides an [example configuration](clickhouse/example.conf) and
[database schema](clickhouse/schema.sql). Review addresses, ports, and file
paths before using an example in your deployment.
