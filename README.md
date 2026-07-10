# Netom

The composable, programmable BGP Engine

Netom is a FastNetMon Inc maintained fork of NLnet Labs Rotonda, renamed to
avoid confusion with the upstream project. It is not an official NLnet Labs
release. The original upstream project is available at
<https://github.com/NLnetLabs/rotonda/>. See [NOTICE.md](NOTICE.md) for fork
attribution and licensing notes.

## Why Netom?

Netom is focused on production deployments that collect, process, and
redistribute large volumes of BGP and BMP routing data. Compared with the
Rotonda version from which it was forked, Netom adds:

- BMP restreaming with an initial RIB dump followed by live updates;
- bounded buffers, streaming full-RIB exports, and slow-consumer protection;
- stronger BMP peer lifecycle, reconnect, withdrawal, and memory handling;
- TLS and access controls for BMP consumers;
- TCP MD5 authentication for BGP sessions;
- additional operational metrics, memory diagnostics, packaging, and
  large-scale MRT ingestion testing.

These changes make Netom particularly suitable for FastNetMon and other
high-volume routing-monitoring pipelines. Rotonda continues to evolve
independently, so users should choose between the projects based on the
features and compatibility requirements of their deployment.

The current version of Netom allows you to open BGP and BMP sessions and
collect incoming routes from many peers into a in-memory database, modeled as
a Routing Information Base (RIB). It also supports importing routes from MRT
files into this database. Conditions for accepting incoming routes and sending
messages to log files or a MQTT stream can be created using filters with the
`Roto` programming language. The RIB can be queried through an HTTP/JSON
API.

Future versions of Netom will support an on-disk database, using external
datasets in filters, reading routes from Kafka streams, and more.

Read the fork documentation and release notes in this repository to install and
use this FastNetMon-maintained build of Netom.

> `Netom` is under active development and features are added regularly.
> The APIs, the configuration and the `Roto` syntax may change between
> 0.x versions.
>
> For more information on upstream NLnet Labs Rotonda, see
> <https://github.com/NLnetLabs/rotonda/>.

For issues with this fork, use the FastNetMon repository and support channels.
Upstream NLnet Labs community resources may not apply to this fork.

## GOALS

#### Modularity
   Netom applications are built by combining units into a pipeline through
   which BGP data will flow. You can filter, and store the BGP data along
   the way, and create signals based on it to send to other applications. We
   aim for units to be hot-swappable, i.e. they can be added and removed in a
   *running* Netom application.

   Netom offers units to create BGP and BMP sessions, Routing Information
   Bases (RIBs), and more.

#### Flexibility
   The behaviour of the units can be modeled by using a small, fun programming
   language called `Roto`, developed by NLnet Labs to combine flexibility and
   ease-of-use. Right now, `Roto` is used to define filters that run in the hot
   path of the Netom pipeline. Netom aims to integrate filter definition,
   configuration syntax, and query syntax into `Roto` scripts in one place.
   Modifying, versioning and provisioning of your `Roto` scripts should be as
   straightforward as possible.

#### Tailored Performance
   Netom aims to offer units that perform the same task, but with different
   performance characteristics, so that you can optimize for your needs, be it
   a high-volume, low latency installation or a small installation in a
   constraint environment.

#### Observability
   All Netom units will have their own finely-grained logging capabilities,
   and some have built-in queryable JSON API interfaces to give information
   about their current state and content through Netom’s built-in HTTPS
   server. Signals can be sent to other applications. Moreover, Netom aims
   to offer true observability by allowing the user to trace BMP/BGP packets
   start-to-end through the whole pipeline.

##### Storage Persistence
   By default a Netom application stores all the data that you want to
   collect in memory. It should be possible to configure parts to persist
   to another storage location, such as files or a database. Whether you put
   RIBs to files or in a database, you can should still be able to query it
   transparently with `Roto`.

#### External Data Sources
   `Roto` filter units should be able to make decisions based on real-time
   external data sources. Similarly filter units should be ahlt to make
   decisions based on data present in multiple RIBs. External data sources
   can be, among others, files, databases or even a RIB backed by an RTR
   connection.

#### Robustness & Scalability
   Multiple Netom instances should be able to synchronize or shard data via
   a binary protocol, that we dubbed `rotoro`.

#### Security & Safety
   Netom applications will be able to use data provided by the RPKI through
   connections with tools like Routinator and Krill. Besides that, Netom
   supports BGPsec out of the box. Again, no patching or recompiling required.

#### Open Source License

Netom is licensed under the [Mozilla Public License 2.0](LICENSE). This fork
preserves upstream NLnet Labs attribution and adds FastNetMon Inc attribution
for fork-specific modifications.

## Memory allocator (jemalloc) tuning

This build uses jemalloc (`tikv-jemallocator`) as the global allocator instead
of the system allocator, because glibc malloc retains freed pages on its free
lists under the fragmented, small-allocation pattern the RIB store produces, so
RSS plateaus at the high-water mark after a large bmp-out dump instead of
falling back. jemalloc is tuned at runtime through the `_RJEM_MALLOC_CONF`
environment variable (note the `_RJEM_` prefix — the plain `MALLOC_CONF`
variable is silently ignored by this build).

### Make RSS actually return after a dump

```
_RJEM_MALLOC_CONF="background_thread:true,dirty_decay_ms:5000,muzzy_decay_ms:5000"
```

- `background_thread:true` — a background thread purges decayed pages even when
  an arena goes idle (critical: after a dump, if the feed quiets, idle arenas
  still get reclaimed). This is enabled because the build includes the
  `background_threads_runtime_support` feature.
- decay 5s — freed pages go back to the OS (via `MADV_DONTNEED`, which does drop
  RSS) within ~5s. Drop to `muzzy_decay_ms:0` for immediate return if you want
  it aggressive.
- Optional: `narenas:8` — jemalloc defaults to a high arena count (96 on a
  typical box here); fewer arenas means less per-arena retained slack and a
  lower baseline footprint, at a small concurrency cost. Worth trying.

### Leak hunting (heap profiling)

Profiling is compiled into this build, so it can be enabled at runtime:

```
_RJEM_MALLOC_CONF="prof:true,prof_active:true,lg_prof_sample:19,lg_prof_interval:31,prof_prefix:/tmp/jeprof"
```

- Samples roughly every 512 KiB (low overhead) and auto-dumps a heap profile
  every 2 GiB allocated to `/tmp/jeprof.*.heap`.
- Analyze with:
  ```
  jeprof --show_bytes --text ./target/release/netom /tmp/jeprof.*.heap
  ```
  `jeprof` ships with `libjemalloc-dev`. The release profile is built with
  `debug = 1`, so call sites are symbolized — the profile shows exactly which
  call sites hold the bytes.
