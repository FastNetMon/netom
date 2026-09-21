# Draft: direct ClickHouse history exporter

Status: proposal; implementation has not started.
Date: 2026-09-11.
Keep this file untracked. Do not include it in implementation commits.

## Objective

Add an optional `clickhouse-out` target that records Netom's observed BGP route
events and peer lifecycle events in ClickHouse. Support prefix timelines, path
and next-hop changes, announcement/withdrawal rates, and peer troubleshooting.

ClickHouse stores history; Netom's RIB continues to serve current routing state.
Exact reconstruction of state at a past time requires a known starting snapshot,
complete lifecycle information, and a history interval without collection gaps.

## Agreed scope and proposed defaults (2026-09-11)

- Capture **observations**, including repeated identical announcements, at the
  selected input/filter boundary. Do not suppress them using RIB state equality.
- Configurable retention, default **24 hours**; no hard export-latency requirement.
  Favor efficient batches over subsecond visibility.
- Use compact peer/session/family invalidation events in v1 (recommendation based
  on GoBMP's implementation below); retain observed prefix withdrawals normally.
- Ship a unified physical table plus ordinary route/peer views in v1. Defer split
  layout to v2 unless a concrete consumer requires separate retention.
- Use a minimum compatibility baseline of ClickHouse **25.8 LTS**, subject to
  integration tests, and also test current production LTS releases. Do not require
  the newest server line. No automated migrations; supply operator-applied SQL.
- Store raw attributes plus parse context authoritatively, with derived query
  columns. Use LZ4-compressed, immutable RowBinary segments as insert units.
- Snapshots, EOR coverage, and exact historical RIB reconstruction are deferred.
  Basic peer lifecycle and loss markers remain part of v1.

The numeric resource defaults below are proposed engineering choices, not measured
exporter capacity or guarantees. They remain configurable.

### Attachment point, retention, startup, and configuration decisions

**gcore attachment:** connect `clickhouse-out` to `bmp-in`, as a sibling of `rib`.
The live configuration inspected on 2026-09-11 has no active `roto_script` and has
`ignore_post_policy_routes = true`. This captures accepted, decoded input
observations before RIB filters, mutations, validation/enrichment, or attribute
retention decisions. RIB-derived output is an alternative explicitly named mode,
not a second simultaneous source (which would duplicate observations).

This is not an unfiltered BMP wire archive. In
`src/units/bmp_tcp_in/router_handler.rs`, BMP Roto rejection precedes decoded gate
emission. Input policy filtering, parsing failures, and currently suppressed
unknown-ADD-PATH withdrawals are also outside the emitted stream. Capturing those
requires new source plumbing. Record the capture boundary and config fingerprint
in control events, and count these exclusions where the source exposes counters.
The RIB's `filter_payload` forwards accepted mutated routes and omits rejected
ones; choosing `rib` would therefore have different historical semantics.

**Retention:** 24 hours is the gcore capacity-driven starting default, not evidence
that a day covers every troubleshooting investigation. Keep it configurable beyond
24 hours; longer investigations need longer retention or a later archive facility.
Document that incidents noticed after expiry cannot be reconstructed from this
store. There is no hard export-latency requirement.

**Startup markers:** emit `history_start` for a new target run and an unclean-stop
marker when applicable. Then enumerate currently known relevant router/parent-peer
ingresses incrementally, emitting `identity_observed` records, followed by
`identity_inventory_end` with counts and coverage status. Do not synthesize
`peer_up` at exporter startup or enumerate ADD-PATH children as independent peers.
Use lazy first-sight identity records for concurrent arrivals; an inventory is not
an atomic peer-state snapshot or proof of route completeness. A start marker
identifies a collection boundary, not the exact time a previously lost event
occurred. Add a lightweight hourly coverage heartbeat (also before new events
after an idle interval) so startup metadata does not disappear from a rolling
24-hour query window. No prefix scan, route snapshot, or EOR requirement in v1.

**Collector identity:** per-target `collector_id`, e.g. `netomics-gcore`; use a
generated persistent UUID if omitted, never a changing hostname as the only key.
Persist an independent stream UUID in the spool to disambiguate multiple targets.
Generate a new producer epoch for each target run; event IDs include stream UUID,
epoch, and sequence. Replay old segments under their original IDs. Reload does
not rotate the epoch. Session generation must survive cache eviction and distinguish
reappearance of the same ingress; add minimal lifecycle generation plumbing if
the register cannot currently provide this. No new global config setting in v1.

| Configuration change | Reconfigure behavior |
| --- | --- |
| Batch row/byte/time thresholds, timeouts, retry backoff, bounded concurrency | Hot reload; apply only to newly opened segments/requests |
| Queue/cache limits, spool budget/reserve, full policy, fsync interval | Hot reload with validation; never evict accepted data or exceed a shrunken budget |
| Credentials/TLS and endpoint | Hot reload between attempts only for the same logical destination/deduplication domain; pin existing attempts |
| Source/capture mode, collector ID, stream identity, spool path, row schema/codec, table/database | Restart or explicit drain-and-reinitialize; pending segments retain their original contract |
| Retention/partition/order settings | Operator-applied DDL; no automatic migration or silent hot reload |

For endpoint changes, a different hostname is not proof of the same destination.
Validate schema and an operator-configured destination identity; non-replicated
servers have independent dedup logs. Changing to another database/server's storage
requires an explicit cutover, not a silent replay redirect. Reject incompatible
reloads atomically and retain the working config.

## High-end sizing: netomics-gcore

### Evidence collected read-only on 2026-09-11

The existing [memory investigation](MEMLEAK_TRACKING.md) describes an August feed
of 112 BMP routers and about 8,580 monitored peers. Do not assume those counts are
unchanged. The latest live `memstat:` cycle now reports:

- About **369.30 million active route variants**, plus 31.06 million withdrawn
  records: 400.36 million stored variants across 1.94 million unique prefixes.
- 9,303 `BgpViaBmp` registry entries; this is not a measured connected-peer count.
- 32 logical CPUs, approximately 49.2 GiB Netom RSS, and only **244 GiB available**
  on the existing root filesystem. No ClickHouse capacity benchmark was run.
- Service start: 2026-08-26 19:12:25 UTC, with no restart for this measurement.

Sampled `http://[::1]:8080/metrics` every five seconds for one minute, from
**04:18:51.882 to 04:19:51.881 UTC**. Summed these global RIB counters:

| Counter suffix (under `netom_rib_unit_`) | First value | Last value |
| --- | ---: | ---: |
| `num_routes_announced_total` | 1,997,061 | 1,997,061 |
| `num_modified_route_announcements_total` | 20,356,596,607 | 20,356,921,380 |
| `num_routes_withdrawn_total` | 551,744,972 | 551,783,836 |
| `num_route_withdrawals_without_announcements_total` | 370,403,446 | 370,409,898 |

The delta is **370,089 events in 60 seconds**, approximately **6,168/s**. The
largest five-second delta was **53,762**, approximately **10,752/s**. The initial
sum, 21.281 billion events over 15.379 days of uptime, gives a coarse lifetime
average of **16,015/s**, including startup loading and reconnects.

These are RIB-work proxies, not exact exporter observation counts. Source filters,
unsupported families, and bulk invalidation accounting can change the relationship.
Do not derive event rate from growth in current RIB size, unique prefix counts,
interned attributes, or BMP message count: one BMP UPDATE can carry many NLRIs.
The minute sample does not establish historical peak or percentile rates. A
dedicated counter at the future export boundary and longer measurement are needed.

### Planning envelope, not a measured upper bound

Use **50,000 route events/s sustained** as an initial busy-load benchmark and
**250,000–1,000,000/s** as a reconnect/burst benchmark range. Include a
**1.25-million/s replay stress test**. Derivation: replaying the current 369.3
million active variants once gives the following average rate during replay:

| Assumed full-feed replay duration | Average announcements/s |
| --- | ---: |
| 30 minutes | 205,167 |
| 10 minutes | 615,500 |
| 5 minutes | 1,231,000 |

Actual dumps may be staggered or slower, and repeated resets or additional policy
views can exceed this model. Compact invalidations avoid an additional synthetic
withdrawal row per active variant, but do not eliminate the reannouncements.
Every initial/reconnect announcement remains an observation even though explicit
snapshot generation and EOR coverage are deferred.

Measure both the ability to append bursts to the spool and the sink's sustained
drain rate. If arrivals are R and drain rate is D, backlog grows at R-D when
positive. Recovery requires D above ongoing arrival rate. Memory buffering alone
cannot absorb a full-feed replay. This is a workload target, not a claim that the
current machine, Netom, or a single ClickHouse server already supports that rate.

### Daily storage and outage buffer arithmetic

For a first model, **assume** 500 bytes/event before spool/transport compression and
100–300 bytes/event on disk in ClickHouse after column compression. These sizes
have not been measured; long paths and large community sets can exceed them.
Spool and column-store compression are different; do not assume identical ratios.

| Sustained average | Rows / 24 h | ClickHouse data at 100–300 B/row |
| --- | ---: | ---: |
| 5,000/s | 432 million | 43–130 GB |
| 16,000/s | 1.382 billion | 138–415 GB |
| 50,000/s | 4.320 billion | 432–1,296 GB |
| 100,000/s | 8.640 billion | 864–2,592 GB |

GB above is decimal and excludes replication, additional physical views/indexes,
merge workspace, TTL deletion lag, and filesystem reserves. Provision headroom;
the root volume's currently available 244 GiB is not enough to establish a safe
24-hour high-end deployment. Plan separate storage for ClickHouse and a budgeted
spool volume, then replace these assumptions with measured bytes/row.

Without compression, at 500 B/event, a **128-GiB spool** absorbs approximately:

- 4.8 hours at 16,000/s while ClickHouse is unavailable.
- 92 minutes at 50,000/s, or 46 minutes at 100,000/s.
- 4.6 minutes at 1,000,000/s.

The 32-GiB default covers one quarter of those durations. One complete 369.3M-row
replay occupies about **185 GB / 172 GiB** at 500 B/event if none can drain, so a
128-GiB spool cannot hold that whole replay during an outage. At a million rows/s,
the uncompressed encoded write rate is approximately **500 MB/s**; spool reads,
fsyncs, encoding, compression, and network add work. Doubling actual row size
doubles required bandwidth/storage and halves outage coverage. Benchmark disk
throughput as well as database rows/s before selecting a deployment profile.

LZ4 spool compression is part of v1. A measured compression ratio C divides disk
write/read bandwidth and multiplies outage coverage by approximately C, excluding
framing and metadata. For example, **if C=3**, 500 MB/s becomes roughly 167 MB/s
of writes plus reads while draining, and the 128-GiB full-outage burst buffer lasts
about 13.7 minutes instead of 4.6. This is sensitivity arithmetic, not a measured
BGP ratio or a promise that ordinary NVMe meets the target. RowBinary places
repeated attributes among other fields; its compression differs from columnar
ClickHouse storage. Re-measure row sizes after adding authoritative raw attributes
and compact identity keys. The 64-MiB queue holds only about **134 ms** at the
uncompressed 500-MB/s envelope, so compression and spool I/O must run off the input
hot path in bounded work chunks; the queue is not the burst reservoir.

Next measurement: gather per-export-boundary deltas at 1–5-second resolution over
at least a day and an operationally occurring reconnect (do not trigger a live
restart for measurement), and benchmark representative captured event batches.

## Reference implementations

- [GoBMP message types](https://github.com/sbezverk/gobmp/blob/master/pkg/message/types.go)
  define parsed JSON records, including `add`/`del`, router and peer identities,
  prefix, timestamp, nested attributes, ADD-PATH ID, and RIB/policy flags.
- [GoBMP serialization](https://github.com/sbezverk/gobmp/blob/master/pkg/message/route-monitor.go)
  and [Kafka publisher](https://github.com/sbezverk/gobmp/blob/master/pkg/kafka/kafka-publisher.go)
  show JSON route records sent to family-specific topics. Raw BMP binary output
  is a separate mode. Do not infer the Kafka schema from a console wrapper.
- [nxthdr BMP SQL](https://github.com/nxthdr/infrastructure/blob/main/clickhouse-tables/bmp/bmp.sql)
  provides a complete Kafka-engine table, materialized view, and persistent
  MergeTree table with BGP attributes, timestamps, daily partitions, and a
  seven-day TTL. Its input is Risotto's Cap'n Proto format, not GoBMP JSON.
  Adapt the design rather than copying its ingestion schema or retention policy.
- [Risotto](https://github.com/nxthdr/risotto) documents reconnect deduplication,
  synthetic withdrawals, and the distinction between observed events and curated
  state changes. It is a useful lifecycle reference, not a drop-in Netom exporter.
- [ClickHouse Kafka ingestion](https://clickhouse.com/docs/integrations/connectors/data-ingestion/kafka/kafka-table-engine)
  documents Kafka consumption through a materialized view into persistent tables.
  JSONEachRow can decode GoBMP JSON into typed columns. Kafka-engine ingestion has
  at-least-once semantics, so duplicates still need consideration.
- [Official Rust client](https://github.com/ClickHouse/clickhouse-rs) supports typed
  binary rows over HTTP, compression, and batch inserts.
- [ClickHouse insert guidance](https://clickhouse.com/docs/concepts/best-practices/selecting-an-insert-strategy)
  recommends batching, ideally 10,000–100,000 rows when workload permits. A timer
  must flush smaller batches during quiet periods.

No complete GoBMP-specific ClickHouse deployment was verified during the initial
research. The verified BMP database example uses Risotto.

## Proposed architecture

```text
BMP/BGP input -> decoded Netom updates -> normal processing / RIB
                          |
                          v
                   clickhouse-out target
                          |
                 compact keys + shared attributes
                          |
              encode once -> LZ4 RowBinary segments
                          |
               batch writer / retry / acknowledgement
                          |
                     ClickHouse
```

Use the existing target and link infrastructure. Subscribe to decoded events at
the configured pipeline point; do not poll HTTP RIB snapshots to discover changes.
Document whether that point captures all observed updates or filtered updates.
Review link buffering and upstream filtering/deduplication before claiming that
every observed event reaches the exporter.

Use a pinned official `clickhouse` Rust client where its formatted streaming API
supports the required payload path; otherwise use a narrow HTTP transport adapter.
Encode the documented RowBinary contract once into compressed spool segments;
do not deserialize and reserialize events for retries. Validate column types/order
at startup. Keep logical event construction separate from its durable encoding.

Kafka remains an alternative for multiple consumers, independent replay, or a
shared durable log. It is not required for direct ClickHouse ingestion.

## Initial scope

- IPv4 and IPv6 unicast announcements and withdrawals, including ADD-PATH.
- Peer/session lifecycle events and address-family-scoped invalidation.
- Router/peer identity and available VRF/distinguisher and RIB-view metadata.
- UTC receive timestamps, source timestamps when available, and event ordering.
- Batched inserts, bounded resources, outage recovery, and exporter metrics.
- Explicit handling and metrics for unsupported route families; never silently
  claim a complete history when configured inputs contain unsupported events.

FlowSpec and other route families can follow with family-specific NLRI encoding.
Do not force every NLRI into an IP-prefix schema. Historical query APIs, a UI,
Kafka export, and a materialized current-state table are separate follow-up work.

## Event model and tables

Treat the following as a logical schema. Final SQL types, ordering keys, and
partitioning must be validated against expected volume and query patterns.

### `route_events`

Append one row per observed route announcement or withdrawal:

| Group | Proposed fields |
| --- | --- |
| Event identity | schema version, collector ID, collector epoch, event sequence |
| Timing | receive time in UTC, optional BMP source time, optional insert time |
| Source | compact router/peer-session keys and identity reference; full identity in peer/control rows |
| Routing context | AFI/SAFI and compact identity reference for distinguisher/VRF/RIB-view metadata |
| Route identity | prefix/address and length, ADD-PATH presence and unsigned path ID |
| Operation | announcement or withdrawal; observed or synthetic provenance |
| Authoritative attributes | binary path-attribute blob, parse/ASN-width context, encoding version; RPKI metadata separately |
| Derived attributes | next hop, origin, flattened AS-path array, MED, local preference, communities |

Preserve distinctions that affect correctness: missing attributes versus explicit
zero, ADD-PATH disabled versus path ID zero, AS sequence versus AS set, and absent
source timestamps versus valid timestamps. A flattened ASN array alone cannot
represent every AS_PATH: preserve the raw attribute blob authoritatively and
label flattened columns as query conveniences. Unsupported/failed derivations
must be distinguishable from genuinely absent attributes.

`RotondaPaMap::raw_arc()` cheaply shares `Arc<[u8]>`, but its first two bytes are
**Netom's RPKI and parse-context bytes**, not BGP attribute bytes. Store `raw[2..]`
as a binary-safe ClickHouse `String`, with separate versioned parse context
(including 2/4-octet ASN interpretation) and optional RPKI metadata. Do not base64
encode or require UTF-8. Use borrowing attribute accessors for derived columns.
Sharing exists before RIB interning too; do not assume a `bmp-in` attachment has
already passed through the RIB's global attribute interner.

These bytes represent the attributes retained at the selected pipeline boundary,
not the complete original UPDATE. `explode_announcements` shares the parsed
UPDATE's attribute blob across its routes; `explode_withdrawals` deliberately uses
an empty attribute map. Audit MP_REACH/MP_UNREACH preservation and repeated-NLRI
overhead before sizing raw columns; raw packet archival is separate. Future
unknown attribute types can be retained without new columns,
but new NLRI families still require decoder support and a generic versioned
`nlri_raw`/AFI/SAFI representation (reserve that column now). Derived columns or
family-specific query features may still need later schema changes.

Do not use the process-local `IngressId` as the durable route identity. Export
owned identity metadata before ingress entries can be retired. Stable event IDs
identify observations, not route contents: repeated identical announcements can
be legitimate history and must not be deduplicated by route hash.

Start with an append-only MergeTree history table. Add withdrawals as rows, not
DELETE mutations. Do not use a route-keyed ReplacingMergeTree as the only history
table because replacement would discard older events. Retry deduplication is a
separate concern from route-state replacement.

Use the physical design below: route/control class, AFI/SAFI, and prefix lead
the sort order, with receive time before peer identity for cross-peer prefix
timelines. This is a query ordering, not a uniqueness constraint. Hourly partitions
prune broad time ranges; a compact peer projection supplies a second access path.
Ordinary views alone do not create another index or physical sort order.

For the expected retention of up to a day, start with hourly partitions and a
row TTL based on **receive time + configured retention**, not date truncation or
insert time. A delayed replay must not restart an event's retention period.
Set **`ttl_only_drop_parts = 1`** in setup SQL. Parts are deleted once every row
has expired, avoiding row-level TTL rewrites. This adds up to a part's time span
(within an hour for hourly partitions), plus background scheduling lag, before
physical removal. It does not atomically drop the entire hourly partition.
ClickHouse TTL deletion is asynchronous; queries must apply the receive-time
cutoff when an exact visible 24-hour window is wanted. Reserve disk for expiry
lag and merges. See [ClickHouse TTL documentation](https://clickhouse.com/docs/concepts/features/operations/delete/ttl).
Expose retention in setup-SQL generation; changes to existing table TTLs are
operator-applied SQL, consistent with deferring automatic migrations.
Use an explicit per-row `expires_at` for the identity-anchor exception described
below; ordinary route rows still use receive time + configured retention.
Do not silently expire pending spool records; replay with original receive time
and expose when export lag exceeds the useful history window.

### Default physical schema: compact storage and selective searches

Design for named query patterns, not arbitrary full-text searches across opaque
attribute blobs. Ordinary prefix/time and peer/time queries must demonstrate
partition/index pruning before the schema is accepted. ClickHouse's primary index
is sparse: a selective lookup reads candidate granules, not necessarily one row.
It does not enforce unique keys. See [primary-key guidance](https://clickhouse.com/docs/concepts/best-practices/choosing-a-primary-key).

#### Column representation and codecs

| Data | Initial physical representation |
| --- | --- |
| Event class and extensible kind code | `UInt8` class and `UInt16` kind, documented versioned mapping; no repeated descriptive strings |
| AFI / SAFI / prefix length | `UInt16` / `UInt8` / `UInt8` |
| Prefix and next-hop addresses | Packed `IPv6` (IPv4-mapped convention), with AFI/presence flags; no CIDR/address strings in hot rows |
| Router/peer/session/stream/segment keys | Fixed-width UUID/128-bit keys with defined namespaces/generation; never unchecked truncation of a hash |
| Receive/source timestamps | `DateTime64(6, 'UTC')` initially; source presence flag; preserve source precision explicitly if it exceeds microseconds |
| Sequence | `UInt64`, scoped by stream/epoch |
| ASN, MED, local preference, path ID | `UInt32`; presence bits distinguish absent values and valid zero |
| Standard / large communities | `Array(UInt32)` / `Array(Tuple(UInt32, UInt32, UInt32))` |
| Extended communities | Packed eight-byte values, not formatted strings |
| Raw attributes / generic NLRI | Binary-safe `String CODEC(ZSTD(1))`, never JSON/base64/hex storage |
| Descriptive names, capabilities | Identity/control records only, not copied into each route |

Start with `ZSTD(1)` for database columns and compare against LZ4 on real batches;
spool/transport compression remains LZ4 for ingestion speed. Try `Delta, ZSTD(1)`
for receive/source times and sequences only where actual sort order gives small
deltas. Do not assume globally monotonic timestamps after prefix sorting.
These choices follow [ClickHouse compression guidance](https://clickhouse.com/docs/guides/clickhouse/data-modelling/compression/compression-in-clickhouse).

Use `LowCardinality(String)` only for genuinely small categorical vocabularies
where a string is useful. Do not apply it blindly to raw attributes, UUIDs, or
prefixes: millions of distinct values can make dictionary encoding worse. The
[LowCardinality documentation](https://clickhouse.com/docs/reference/data-types/lowcardinality)
explicitly notes that high diversity can negate its benefit. The in-memory RIB's
interner savings do not establish the database's per-part compression ratio.

Keep absent values distinguishable via a small presence bitmask where convenient;
do not replace unknown values with meaningful defaults. Store raw blobs as cold
columns: timeline/list queries select only compact columns, and fetch raw bytes
after a user selects particular events. No default `SELECT *`.

#### Primary order and peer access path

Proposed SQL fragment (column names are the draft contract, not the final schema):

```sql
ENGINE = MergeTree
PARTITION BY toStartOfHour(received_at)
PRIMARY KEY (event_class, afi, safi, prefix_addr, prefix_len, received_at)
ORDER BY (event_class, afi, safi, prefix_addr, prefix_len, received_at,
          peer_session_key, stream_id, epoch, event_seq)
TTL expires_at DELETE
SETTINGS index_granularity = 8192,
         ttl_only_drop_parts = 1,
         non_replicated_deduplication_window = 10000
```

The dedup window above is only a starting setup value and must be sized according
to the retry contract; it does not provide 24 hours of deduplication automatically.
The shorter explicit primary key avoids indexing long unique event-ID suffixes.
Keep time predicates index-friendly; provide explicit partition-hour predicates
where the minimum-version optimizer does not infer them. Route views supply the
route class; control rows use their own class rather than pretending to be /0.

Add one compact secondary projection for peer/time and identity resolution:

```sql
PROJECTION by_peer
(
    SELECT peer_session_key, event_class, received_at,
           afi, safi, prefix_addr, prefix_len, event_kind, origin_as,
           _part_offset
    ORDER BY (peer_session_key, event_class, received_at)
)
```

`_part_offset` allows retrieving other fields from the base table without storing
a second copy of raw attributes. Selected compact columns can satisfy common
peer timelines directly. This trades some disk/write cost for another index;
measure that cost rather than treating projections as free. Verify automatic
selection on both 25.8 and the staging server, and test joins/ordinary-view query
shapes too. [ClickHouse projection documentation](https://clickhouse.com/docs/concepts/features/projections/projections)
describes both offset-only and mixed projections. Feature existence alone does
not guarantee identical optimizer behavior across supported versions.

Resolve router/peer names to compact peer-session keys from control metadata first,
then push those keys into route queries. The leading control class bounds metadata
enumeration; the peer projection serves specific identity/session lookups. Do not
join every route to every identity before applying prefix/time/peer filters.
Large router-wide fanout must be tested; add a router projection only if a measured
workload requires it, instead of copying every possible index into the default.

#### Query patterns and limits

| Query | Planned pruning/access |
| --- | --- |
| Exact prefix, all peers, time range | Hour partitions + route class/AFI/SAFI/prefix primary key |
| Prefix and particular peer(s) | Prefix primary key, with peer filtering; evaluate peer projection for narrow peer sets |
| Peer changes over a time range | Compact peer/time projection |
| Router changes | Resolve to scoped peer keys, then peer projection; benchmark large fanout |
| Identity details for selected events | Scoped control rows and peer projection; retain segment/identity reference constraints |
| Routes covering an address | Enumerate at most 33 IPv4 or 129 IPv6 ancestor prefix keys; query exact `(prefix_addr, prefix_len)` candidates with AFI/time filters |
| Origin-AS / AS-path member / community | Time/scope bounds plus benchmarked optional scalar/array Bloom skipping index or a later posting/aggregate structure |
| Per-minute charts across the entire feed | Later aggregate projection/table, rather than repeatedly reading billions of raw observations |

Exact prefix and address containment are different queries. Avoid converting the
stored IP column to strings or running a per-row CIDR parser for address lookups.
Ancestor enumeration does not solve arbitrary supernet/subnet searches; those
require explicit ranges or their own measured access strategy.

Bloom indexes only help when a value is absent from many granules; common ASNs or
communities may saturate them. They are optional benchmark candidates, not a
promise of index-only membership search. Arbitrary raw-attribute substring queries
and unbounded day-wide exports can still scan large amounts of data. `LIMIT` alone
does not make an unindexed filter cheap. Use stable keyset pagination for result
lists; no growing OFFSET scans, routine FINAL, or OPTIMIZE FINAL per query.

#### Deduplication: preserve events, reduce repeated payload cost

Keep three separate mechanisms:

1. **Delivery deduplication:** immutable insert tokens suppress retry copies within
   configured windows. Every legitimate observation keeps its own event ID.
2. **Metadata normalization:** compact keys and segment identity records avoid
   repeating full router/peer identity on every route.
3. **Attribute storage:** v1 baseline keeps authoritative raw bytes inline with
   ZSTD compression. Repetition is exploited within compressed column blocks;
   this is not a global store-once dictionary or cross-part dedup guarantee.

Benchmark inline raw bytes against an attribute dictionary before finalizing the
schema, using real event batches with repeated and high-cardinality attributes.
A normalized alternative stores a content-addressed attribute row once per scoped
generation and references it from events, while retaining hot derived columns.
Its identity must include encoding/ASN-width context and exact bytes, with an
explicit collision policy; a plain 64-bit hash is not authoritative identity.

That alternative adds reference bytes, dictionary indexes, join work, and durable
delivery/retention dependencies. A cache hit alone cannot prove the dictionary row
is still retained. Attribute rows must outlive all references, including replay
and snapshots, and event visibility must handle partial insertion. A MergeTree
ORDER BY hash does not enforce uniqueness, and an eventually replacing dictionary
cannot be joined naively without risking duplicate output rows. A bounded
segment-local attribute dictionary is another candidate if global lifecycle cost
is too high; it still needs efficient attribute-key lookup.

Choose normalization only if **total** bytes per event (all tables/projections,
indexes, and retained dictionary generations) and query/write behavior improve
materially over inline compression. Do not discard observations or lose rare
attribute types to meet a disk target. The schema decision remains a milestone-1
benchmark gate, not an untested promise of a particular compression ratio.

#### Staging acceptance evidence

Benchmark realistic distributions at 1M, 10M, and at least 100M event rows where
the staging disk budget permits; reserve at least 20% filesystem headroom and
avoid filling the host to obtain a test result. Include skewed/default prefixes,
many peers, repeated/unique attribute sets, mixed IPv4/IPv6, and expired data.

For each supported query shape, record `EXPLAIN indexes=1`/projection selection,
selected parts/granules, `read_rows`, `read_bytes`, warm/cold latency, and result
correctness. An exact selective prefix query must not select every granule in its
time window. Peer lookup must show its projection/access benefit. Report broad
queries honestly rather than hiding scans behind cached timings.

Report base-column compressed bytes, projection/index bytes, disk total, inserts/s,
rows/s, CPU, active parts, merge load, and TTL lag. Compare index granularity 8192
with smaller values only if selective-query read amplification warrants the larger
index. No default schema is accepted solely because a tiny synthetic test is fast.

### `peer_events`

Record peer up/down, collector/router connection loss, family-scoped invalidation,
and resynchronization or gap markers where the input provides enough information.
Include source identity, epoch, sequence, timestamps, scope, and reason.

A session-wide withdrawal is not a normal prefix withdrawal. Use compact
lifecycle events for v1; document how queries invalidate routes using their
session/family scope. Never imply that a later snapshot can recover intermediate
events missed during an outage. Synthetic lifecycle events caused by collector
disconnects must be distinguished from observed router peer-down notifications.

[GoBMP's peer handler](https://github.com/sbezverk/gobmp/blob/master/pkg/message/peer.go)
constructs one `PeerStateChange` with `action: "down"` for a BMP Peer Down, then
publishes it to `gobmp.parsed.peer`. This handler does not enumerate prefixes or
publish a synthetic route withdrawal for each one. Individual route withdrawals
are separate route records with `action: "del"`. Downstream consumers must apply
peer invalidation if deriving state. This is distinct from Risotto's optional
curation, which generates synthetic per-prefix withdrawals. This source check
does not assert that GoBMP synthesizes peer downs for every collector disconnect.

For netomics-gcore, invalidating hundreds of millions of paths by expanding them
would manufacture a large extra write burst. Compact invalidation also fits the
chosen observation semantics. Expansion can be a later derived processing step.

### Physical layout: unified in v1

Use one `events` MergeTree table with `event_kind` and typed fields, plus ordinary
SQL views named `route_events` and `peer_events`. Views add no second stored copy.
Allow database/table name configuration and operator-managed DDL matching a fixed
contract. Arbitrary column remapping and exporter-managed split destinations are
deferred to v2. This supersedes the earlier plan to ship both layouts immediately.

Users may add their own materialized views, but that adds write/storage cost and
requires separate retry/partial-success validation. The built-in views remain
ordinary views. Unified storage avoids exporter-level fan-out, but does not imply
atomicity across server blocks or partitions. Event sequence, not insert visibility
order, defines stream order. Pending spool segments pin the physical contract.

### Bounded identity cache and retention-safe references

Model the target's lookup accelerators on
`src/units/bmp_tcp_out/client_state.rs`, without retaining a full `IngressInfo` per
route. Resolve ADD-PATH children to `(parent, path_id)` and cache compact immutable
identities, invalidating on down/reappearance/identity change. Start with 65,536
entries and an additional 16-MiB cache budget, both configurable. Cache eviction
must never change a peer/session key or forget a lifecycle generation.

Add a compact register accessor to avoid copying strings/capability vectors on
ordinary misses. Copy full identity only for metadata records; preserve available
inline teardown metadata before retirement. On an unresolved identity, record an
explicit unknown-identity condition instead of inventing a peer identity.

Emit metadata on first sight, identity change, and reappearance. These alone are
insufficient with a rolling TTL: a long-lived peer's only identity row could expire
while newer route events still reference it. For v1, make each immutable segment
self-describing: include one `identity_observed` row per referenced compact
identity/version in that segment. This is segment-local bounded deduplication,
not a second unbounded global map. Route references include segment/identity keys.

Identity rows are metadata observations, never synthetic BGP announcements. Their
expiry anchor must be at least the maximum receive time of referring rows in the
segment (while their actual observation time is preserved separately). A common
`expires_at` column can express this, with route expiry still based on receive time.
An identity query must not drop these rows with a route-only receive-time predicate.
For the one-hour segment contract, set identity expiry to **end of that receive
hour + retention** and encode each identity before its first referencing route.
This conservative bound avoids patching bytes at seal, and persists identity
alongside any recoverable open-segment rows. Do not leave the only full identity
in RAM until seal. It adds at most one hour to metadata retention before scheduling
lag. Bound the segment-local identity set by count/bytes as well; seal early if
its budget is reached. Cache/segment metadata budgets must account for any retained
full strings and capability vectors, not just compact keys.

Segment-per-hour boundaries ensure the metadata and routes have compatible
partition/TTL behavior. Server block processing can still expose routes before
their identity rows are visible; queries report pending/unresolved references rather than silently
discarding those routes. Test partial insertion and retry. Consider a separate
long-lived identity dimension only in a later design if segment metadata overhead
is material. Measure metadata row amplification under high peer diversity.

## Netom integration details to verify

- `src/targets/mod.rs`: register and configure the new target; follow existing
  target lifecycle, reconfiguration, shutdown, and metrics conventions.
- `src/payload.rs`: `Single`/`Bulk` contain decoded route events.
  `Withdraw`/`WithdrawBulk` represent session or family teardown and require
  separate handling. Audit explicit peer-up plumbing; EOR coverage is deferred.
- `Payload.received` is `std::time::Instant`, which cannot serve as a persistent
  UTC timestamp. Capture wall-clock receive time at input; retain the monotonic
  timestamp for latency measurement. Preserve BMP source time when available.
- `RouteMonitoringRaw` is emitted in addition to parsed updates. Do not count
  both as route history. A future raw archive would be a distinct stream.
- ADD-PATH child ingresses must resolve to their parent peer and actual path ID.
- Capture metadata before queuing; delayed registry lookups may race with ingress
  retirement. Account for inline metadata on bulk teardown events.

### Compressed segment = immutable insert unit

Encode the fixed RowBinary column order once, in bounded chunks, into an open
segment with a manifest/header containing stream/epoch/segment ID, schema hash,
destination identity, partition hour, row counts, checksum, and pinned insert
settings. The payload is LZ4-compressed RowBinary; local framing/manifest bytes
must never be included as database rows. Seal on configured row/byte/time limits
or partition-hour change, fsync it, then publish it to the insert worker. Only
sealed segments are sent. Recover complete checksummed frames/rows from a damaged
open tail and seal them before first delivery; never rewrite an already-sent body.

Prefer **one complete segment per INSERT in v1**. Use globally unique segment ID
as `insert_deduplication_token`. If ranges become necessary, persist immutable
row/frame-aligned ranges before sending and use distinct `segment_id:range_id`
tokens. Reusing one segment token for different ranges risks suppressing valid
rows. Do not repartition, append to, or change encoding/settings of an attempted
insert on retry. Network chunk boundaries need not be row boundaries when the
whole stream is replayed; corruption recovery and independent ranges do.

Use ClickHouse-compatible compressed framing to stream the stored payload bytes
directly when possible. Generic LZ4 frame format and ClickHouse's HTTP compressed
block format are not interchangeable. The inspected Rust client's
[`InsertFormatted`](https://github.com/ClickHouse/clickhouse-rs/blob/main/src/insert_formatted.rs)
has raw/formatted send methods, but its precompressed wrapper has private fields
and does not expose an obvious constructor for arbitrary persisted compressed
bytes. Verify the pinned released API: a narrow HTTP adapter may be needed for
direct reuse of the on-disk frames. Streaming decompression without row reencoding
is a valid fallback; do not promise zero-copy or zero recompression without proof.

Recovery must distinguish a corrupted unattempted tail from a corrupted sealed
segment. Never silently skip bytes inside an attempted segment and retry its token
with different contents. Quarantine/report corruption and preserve the original
delivery state. Persist acknowledgements before deleting a segment.

#### Deduplication contract

- Explicitly enable insert deduplication. For non-replicated MergeTree, setup SQL
  must set **`non_replicated_deduplication_window > 0`**; its default of zero disables
  deduplication. A token alone is insufficient. Size the window from inserted
  **blocks**, retry delay, concurrent writers, and safety margin, not row retention.
- ReplicatedMergeTree also needs suitable count/time windows. Tokens are scoped
  to the table/deduplication domain and are not permanent uniqueness constraints.
  Beyond the window, duplicates remain possible; stable event IDs expose them.
- Keep parsing and block-formation settings identical on every attempt. A large
  INSERT can contain multiple blocks; `max_insert_block_size` alone is not proof
  that the insert produces one block. Byte thresholds, partitioning, and server
  version matter. The gcore profile requires real multi-block/partial-success
  tests, including timeout after some blocks, then replay of exactly the same
  segment. Pin `max_insert_threads = 1` initially where supported to avoid a new
  version's changed default affecting the delivery path.
- If tested multi-block behavior is inadequate, choose smaller immutable segments
  compatible with verified server block settings; do not split an already
  attempted segment under its original token. Resolve this in an early prototype,
  before committing to a performance guarantee.

See [ClickHouse retry deduplication](https://clickhouse.com/docs/concepts/features/operations/insert/deduplicating-inserts-on-retries)
and the [25.8 MergeTree settings source](https://github.com/ClickHouse/ClickHouse/blob/v25.8.1.5101-lts/src/Storages/MergeTree/MergeTreeSettings.cpp).
Exactly-once history is not claimed: immutable segments simplify retries but do
not eliminate finite-window, crash-checkpoint, or multi-block failure cases.

#### Batch size and part pressure

Keep the generic profile at 100k rows / 32 MiB / 5 seconds. For gcore, start at
**1,000,000 rows OR 256 MiB uncompressed RowBinary OR 5 seconds**, first threshold
wins, with two in-flight inserts. At the provisional 500 B/row, 256 MiB holds
about 537k rows, so a million events/s needs roughly two inserts/s rather than one.
If the measured part/merge load calls for about one insert/s, evaluate a 512-MiB
cap, subject to server memory and deduplication tests. Additional identity rows
count toward every limit. Stream segments; never allocate a full 256/512-MiB
batch per worker in RAM merely because that is the segment limit.

Ten 100k-row inserts/s can create problematic merge pressure; it is not a universal
hard failure threshold. Parts depend on blocks and partitions, so one INSERT is
not guaranteed to create exactly one part. Prefer larger tested inserts before
raising concurrency. Track active parts per partition, part creation rate, merge
backlog, delayed/rejected inserts, and **TOO_MANY_PARTS**. On overload, back off and
retain segments rather than raising the parts limit or splitting retries into
many smaller inserts. Pin a segment to one receive-hour partition to limit fan-out.

## Delivery and resource guarantees

Define guarantees at the durable spool boundary. BMP itself cannot acknowledge
individual updates end to end, and a collector crash can lose events received
before they reach durable storage. Document the chosen fsync policy and this
window rather than promising unconditional lossless capture.

For durably spooled events, target at-least-once delivery with identifiable
duplicates. Persist event IDs and original timestamps across retries/restarts.
Define the ClickHouse deduplication mechanism and its retention window explicitly;
an event-ID column by itself does not enforce uniqueness.

- Bound queued bytes, batch bytes/rows, in-flight requests, and spool disk usage.
- Flush by row/byte threshold or elapsed time using the defaults below, then tune
  under realistic bursts and quiet streams.
- Acknowledge spool records only after the configured ClickHouse insert succeeds.
  Retain immutable batches when relying on block-based retry deduplication.
- Retry transient failures with bounded exponential backoff. Surface schema/type
  errors distinctly; do not discard malformed or rejected events silently.
- Define disk-full behavior explicitly: backpressure or recorded data loss.
  Neither unbounded buffering nor indefinite invisible drops is acceptable.
- Specify shutdown timeout, restart recovery, spool version compatibility, and
  recovery from a truncated final record. Keep unacknowledged records on disk.
- Use synchronous server inserts with client-side batching in v1. Server-side
  asynchronous inserts are deferred because they complicate block/dedup semantics.
- Define supported destination topology and acknowledgement semantics for local,
  replicated, or distributed tables before claiming durability guarantees.

Expose queue/spool bytes, oldest pending event age, inserted/retried/failed rows,
unsupported/dropped events, batch size, insert latency, and last successful insert.

### Proposed operational defaults

| Setting | Default | Reason / high-volume adjustment |
| --- | --- | --- |
| Spool | Enabled, checksummed LZ4-compressed RowBinary segments | Encode once, immutable insert/retry unit; bounded streaming buffers |
| Disk sync | Group commit every 500 ms | Matches Vector's documented disk-buffer interval; offer sync-per-batch mode |
| Spool size | 32 GiB per target, hard cap including metadata | Start with 128 GiB on a dedicated volume for the gcore profile; size by outage duration |
| Free-space reserve | Greater of 5 GiB or 5% of the spool filesystem | Stop accepting spool writes at this threshold, before ENOSPC |
| Full spool / queue | `block` | Backpressure instead of intentionally dropping observations; configurable `drop_newest` |
| Segment size | Same row/byte/time limits as an insert | No separate fixed 128-MiB segment limit; seal at receive-hour boundaries |
| In-memory queue | 64 MiB of owned records | Charge allocation/encoding costs; do not cap only event count |
| Batch flush | 100,000 rows OR 32 MiB encoded OR 5 seconds | First threshold wins; no hard latency requirement |
| gcore batch flush | 1,000,000 rows OR 256 MiB uncompressed encoded OR 5 seconds | Test 512 MiB if needed to approach one insert/s; verify multi-block retries |
| In-flight batches | 2, configurable | Prefer bigger verified batches over more parts; increase only after measuring merge capacity |
| Spool/transport compression | LZ4 with compatible framing where possible | Benchmark ratio and CPU; stream stored frames without row reencoding |
| Identity cache | 65,536 entries AND 16 MiB | First limit wins; session identity must remain stable across eviction |
| Connection / insert timeout | 5 seconds / 30 seconds | Retry ambiguous insert outcomes using unchanged IDs/batches |
| Retry backoff | 1 second to 30 seconds, with jitter | Transient retries continue while data remains spooled |
| Shutdown timeout | 30 seconds | Prioritize flushing accepted memory records to disk and syncing; retain pending network work |

The 500-ms interval is a sync scheduling target, not a hard maximum loss window:
queued events and slow storage can extend it. Track sync lag and durably committed
sequence, fsync segment/directory metadata when needed, and retire acknowledged
segments only with a crash-safe checkpoint protocol. A stricter fsync mode changes
the local durability boundary; it does not provide end-to-end BMP acknowledgements.

`block` follows the [Vector ClickHouse sink](https://vector.dev/docs/reference/configuration/sinks/clickhouse/)
default, and group syncing follows its [buffering model](https://vector.dev/docs/architecture/buffering-model/).
Other numeric defaults here are our initial choices. Backpressure may propagate
to Netom's RIB/BMP processing through shared links and eventually cause router
disconnects; it cannot guarantee complete observations during prolonged overload.
Users prioritizing live collection can select `drop_newest`, with counters, logs,
and bounded gap tracking. Reserve space for loss/control markers and persist a
summary when possible; expose loss immediately through metrics even if disk writes
are unavailable. Never discard already-spooled history to admit new events by default.

Queue and batch byte budgets must include retained allocation costs. The queue cap
is not a total RSS cap: account separately for encoding, compression, in-flight
requests, and runtime overhead. No rate target is valid until memory/disk/CPU have
been measured with representative attributes.

### ClickHouse version, topology, and schema setup

Propose **25.8 LTS as the minimum compatibility line**, using a maintained/pinned
patch selected by the operator, rather than requiring the newest server. This
minimum is a test target until implementation passes integration tests; feature
presence alone does not establish compatibility. The necessary
`non_replicated_deduplication_window` and `ttl_only_drop_parts` settings exist in
the [25.8 source](https://github.com/ClickHouse/ClickHouse/blob/v25.8.1.5101-lts/src/Storages/MergeTree/MergeTreeSettings.cpp).
Also test current 26.3/26.8 LTS deployments. Older versions may work but are not
claimed supported without testing. Exporter compatibility and upstream patch
maintenance are separate policies.

Do not use newer JSON/Variant features for the baseline contract. Pin the client
release independently, verify its formatted byte-stream API, and pin server
block-formation settings per segment. New settings documented on current server
pages must not be assumed available on the minimum version. Do not upgrade a
server or rewrite pending segment contracts automatically.

V1 baseline: one HTTP(S) endpoint writing a local MergeTree table. Also test
direct inserts to ReplicatedMergeTree, with explicit acknowledgement settings.
User-managed Distributed tables and Cloud endpoints may be configurable, but
their forwarding/replication durability must be validated before claiming equal
support; v1 does not manage cluster topology or client-side sharding.

Ship setup SQL for unified storage/views and configurable retention, with a read-only
startup schema compatibility check. Fail clearly on incompatible tables. No
automatic CREATE/ALTER/migration on exporter startup. Operators apply the initial
DDL and any subsequent changes; an explicit SQL-generation command/template may
help them do so. Retain schema version markers for diagnostics and spool decoding,
without implementing a migration framework.

## Staging test environment (installed 2026-09-11)

`netomics-staging` is available for implementation tests. Inspected Ubuntu 24.04,
64 logical CPUs, 251 GiB RAM (about 183 GiB available), and about 685 GiB available
disk before installation. Existing Netom systemd service was inactive; no Netom
service/configuration change was made as part of ClickHouse installation.

- Installed official signed Debian packages `clickhouse-server`,
  `clickhouse-client`, and `clickhouse-common-static`, all **26.8.2.7**.
- Enabled and started `clickhouse-server.service`.
- HTTP endpoint: **http://127.0.0.1:8123** on staging; native port 9000.
  All ClickHouse listeners were verified bound to IPv4 loopback.
- Systemd limits: eight-CPU quota, 20-GiB memory high watermark, 24-GiB hard cap,
  no cgroup swap. Server memory budget 16 GiB; default query budget 8 GiB and
  `max_threads = 8`. These limits keep room for existing staging services and
  must be revisited explicitly for high-end throughput benchmarks.
- Data: `/var/lib/clickhouse`; package source:
  `/etc/apt/sources.list.d/clickhouse.list`.
- Local overrides: `/etc/clickhouse-server/config.d/90-netom-staging.xml`,
  `/etc/clickhouse-server/users.d/90-netom-staging.xml`, and
  `/etc/systemd/system/clickhouse-server.service.d/netom-staging.conf`.
- Test database: `netom_test`. Table `exporter_smoke_20260911` has a one-day row
  TTL, `ttl_only_drop_parts=1`, and `non_replicated_deduplication_window=10000`.
  The smoke table is not the proposed exporter schema; table metadata remains
  after its rows expire.

Verified service health, HTTP ping, native version query, and HTTP RowBinary
round-trip including NUL/non-UTF-8 attribute bytes. Inserting 10,000 rows twice
with one token left 10,000 rows; inserting the same body with a new token produced
20,000 rows, retaining legitimate repeated observations. Counts, numeric checksum,
and binary values matched. This is a basic deduplication smoke test, not proof of
multi-block partial-success recovery, compression throughput, or 25.8 compatibility.
Those remain milestone tests. The exporter itself is not implemented or connected.

Local access example:

```sh
ssh -F /home/nuclear/.ssh/config netomics-staging 'clickhouse-client --query "SELECT version()"'
```

## Implementation stages

1. **Contract and feasibility prototype:** validate the bmp-in capture boundary,
   raw attributes/parse context, compact identity/session generations, RowBinary
   streaming transport, and single/multi-block token behavior on minimum/current
   LTS versions. Finalize unified SQL/views and the pinned segment contract.
2. **Event construction:** implement compact caches, retention-safe identity rows,
   timestamps, ADD-PATH, lifecycle/inventory/coverage markers, and collector IDs.
3. **Segment encoder/spool:** encode once into bounded LZ4 chunks, seal/fsync
   immutable insert segments, recover open tails, and enforce disk/queue policy.
4. **Streaming writer and retries:** replay stored bytes, checkpoint acknowledgements,
   handle overload/part pressure, validate Reconfigure rules, and instrument metrics.
5. **Integration and operational validation:** exercise router bursts, outages,
   restarts, shutdown, and historical queries against a real ClickHouse instance.
6. **Documentation and release:** provide example configuration, schema setup,
   retention guidance, query examples, supported semantics, and known limitations.

If implementation is requested, keep fixes/features in small explained commits.
Keep this planning file untracked throughout.

## Required validation

- Announcement, replacement, withdrawal, and repeated identical observations.
- IPv4/IPv6 identity separation; ADD-PATH siblings and path ID zero.
- Same prefix on different routers, peers, VRFs, and RIB views.
- Peer down, family-only reset, reconnect, and metadata retirement races.
- Correct source/receive timestamps and deterministic ordering within a stream.
- No double export of raw BMP and parsed route events.
- Database unavailable, timeout after a successful insert, partial multi-block
  success, token-window expiry, spool restart, truncated spool tail, and full disk.
- Whole-segment/range token uniqueness; first attempt versus identical replay;
  non-replicated dedup disabled/enabled; identical legitimate observations retained.
- RowBinary binary-string round trip, legacy/modern ASN widths, AS_SET/confederation
  paths, unknown attributes, empty withdrawal attributes, and raw/derived consistency.
- LZ4 frame recovery and stream reuse, sealed-segment corruption, and no retry-time
  reencoding or unbounded full-segment allocations.
- Cache eviction/peer reappearance and route identity joins across TTL boundaries;
  segment metadata expiry must never precede referencing route expiry.
- Startup inventory during churn, periodic coverage markers, incompatible reloads,
  and endpoint changes across different deduplication domains.
- TOO_MANY_PARTS/backoff, realistic merge pressure, hourly part expiration, and
  prefix-first versus peer-only query performance on the minimum server version.
- Flush on quiet streams and shutdown; memory remains bounded under sustained
  bursts and database outages.
- Real-server tests for SQL/row compatibility, retry behavior, and TTL semantics.
- Query examples for a prefix timeline and per-peer announcement/withdrawal rates;
  lifecycle-aware state reconstruction only once snapshot/gap semantics are tested.

## Later milestone: synthetic full dump before live history

Support an optional initial RIB dump without changing the meaning of ordinary
observation events. Keep it disabled in v1. Proposed future configuration (not
implemented syntax):

```toml
initial_dump = "rib"             # default: "none"
snapshot_rib = "rib"
```

The exporter can reference a RIB for initialization separately from its live
source, as bmp-out already does. It must validate that the snapshot and live
stream describe the same routing state before presenting them as a single
reconstructable history.

### Reuse the dump mechanics, preserve history semantics

`bmp_tcp_out::perform_initial_dump` registers its consumer before the walk,
streams the RIB through bounded channels, emits peer/EOR information, drains
updates buffered during the walk, and switches to live delivery atomically.
Reuse the streaming walker and peer/ADD-PATH resolution concepts, not BMP wire
encoding or a giant in-memory dump buffer. The RIB walk is over mutable state;
the dump procedure does not by itself prove an atomic point-in-time snapshot.

Reserve extensible event kinds and optional `snapshot_id`/watermark metadata in
the v1 contract so this milestone does not require reinterpreting observations:

- `snapshot_begin`: scope, snapshot UUID, source/RIB/filter revision, and start
  boundary; distinguishes a requested baseline from `history_start` metadata.
- `snapshot_route`: synthetic active route row, with raw attributes and compact
  identity references. Never count it as an observed announcement.
- `snapshot_end`: complete manifest, row count, and catch-up boundary after all
  required snapshot/delta segments are acknowledged and the gap checks pass.
- `snapshot_abort`: interrupted, overflowed, source changed, or incomplete dump.

Use an extensible string/numeric event kind rather than a closed SQL Enum that
would require ALTER for every new control event. Allocate a fresh snapshot ID for
each attempt. Carry collection/scan time on synthetic rows, not a fabricated
original announcement timestamp. Keep snapshot ordering separate from live event
sequence; delayed upload does not make a baseline row newer than a live update.

### Consistent handover

1. Register live capture first and journal observations durably. Establish a
   start watermark S0 with a barrier proving the selected RIB has applied the
   corresponding live stream through S0. A target-local timestamp is not a RIB
   application barrier; this needs explicit source/RIB sequencing plumbing.
2. Stream active RIB records into compressed snapshot segments. Include identities
   and all supported path variants; continue journaling live changes in separate
   segments. Bound both streams by the shared disk budget, and prioritize live
   capture over progress of a synthetic scan.
3. After the walk, establish an applied boundary S1 and replay the contiguous
   live range `(S0, S1]` on top of the baseline, including scoped peer invalidation.
   A row seen mid-walk may already include some of those updates: replay is a
   state-convergence step, not permission to duplicate observations in the event
   log. Each live observation is stored once apart from identifiable delivery
   retries. Queries must apply baseline first, then ordered deltas.
4. Publish completion only when the scan, covered deltas, and identity records
   are durably delivered with no known gaps. Continue from S1 without a gap or
   duplicate subscription. Completion manifests identify all required segments;
   a visible end marker alone is not a cross-part/replica transaction guarantee.

The moving-walk-plus-replay approach must be validated for iterator behavior,
peer generation changes, route removal/reappearance, and GC. If those properties
cannot establish convergence at S1, label the result a non-atomic baseline or
introduce a versioned/snapshot-capable RIB view. Do not pause the global RIB for
a multi-minute full-table copy.

Failure during scan or spool exhaustion leaves an incomplete snapshot, never a
valid baseline. Continue ordinary history where possible, emit an abort marker,
and retry a new snapshot explicitly. Do not redump on each ClickHouse reconnect:
resume pending immutable segments instead. On process restart, replay already
sealed segments; an interrupted mutable RIB walk normally needs a new snapshot ID.

### Capture boundary and readiness

For a dump from `rib`, the straightforward coherent mode is live events from that
same RIB output. A `bmp-in` observation stream plus a filtered/mutated RIB dump
must not silently become one state history. Either use an unmodified mirror RIB
with matching source scope and a sequencing barrier, or export the dump with
explicit `rib` provenance as a separate baseline dataset. The current gcore
configuration has no Roto script, but that alone does not prove equivalence for
every parser, lifecycle, and RIB behavior; validate it before enabling bootstrap.

If the collector/RIB is still loading, the dump contains only currently known
state. Advertise that coverage explicitly. Waiting for peer/family EOR or other
readiness evidence belongs to this milestone; exporter startup alone is not proof
that the upstream full feed is complete.

### Cost and retention

At gcore's measured scale, a full baseline adds roughly **369 million route rows**
plus identities. At the provisional 500 B/row, that is about 185 GB before spool
compression, independently of concurrent live history. A 128-GiB spool cannot
hold an undrained uncompressed dump of that size; stream it and budget backlog
explicitly. At a total sink capacity of 250k rows/s with 16k/s ongoing arrivals,
the idealized baseline drain alone takes about 26 minutes, before scan/CPU limits.

A one-time initial dump only seeds reconstruction while the baseline remains
available. To reconstruct state throughout a rolling history window later, retain
a completed baseline from at or before the window start plus all following deltas.
The normal 24-hour event TTL is insufficient for long-lived unchanged routes.
Periodic snapshots and separately managed baseline retention (possibly a dedicated
snapshot table in v2) are therefore needed for that stronger feature. Expire
aborted attempts independently; preserve a prior valid baseline until its
replacement is complete. Do not extend v1's history claim implicitly.

## Remaining implementation validation

- Measure actual serialized/compressed bytes per event and replay throughput.
- Verify observation coverage at the chosen source/filter boundary and quantify
  historic peaks with sustained metrics; short samples are not peak measurements.
- Finalize raw/derived column contracts and test unified storage/views and retry paths.
- Verify backpressure behavior through shared Netom links and disk-full recovery.
- Confirm the selected ClickHouse version/topology's acknowledgement guarantees.

Snapshots, EOR coverage, and exact historical state reconstruction are explicitly
later milestones, not unresolved v1 scope decisions.
Split physical destinations are also deferred to v2; ordinary views are sufficient
for v1 route/peer query separation.

## Implementation checkpoint — 2026-09-11

Initial exporter implemented in reviewable main-branch commits; operational
contract is now in docs/clickhouse.md, schema in docs/clickhouse/schema.sql,
and measured results in docs/clickhouse/validation-2026-09-11.md. This draft
remains untracked. Netomics-staging runs the dpkg-installed fnm15 service and
ClickHouse 26.8.2.7 on localhost. Active BMP-over-TLS input is configured for the
same 30 hosts as bgpviewd; both the RIB and ClickHouse receive these feeds.

Completed: RowBinary/raw attributes plus derived fields; prefix/peer indexing;
LZ4 compressed immutable spool, ownership and destination binding; bounded queue;
compact identities and lifecycle events; retry/checksum/recovery; basic metrics;
manual schema checks. Tests cover ClickHouse 25.8.33.6 and 26.8.2.7, one million
synthetic routes, database outage/restart replay, and systemd SIGTERM/SIGKILL.
Staging testing also found and fixed the daemon's missing SIGTERM handler.

Initial implementation deliberately uses one in-flight insert, restart-only
configuration, first-sight peer identity (no full startup ingress enumeration),
and uncompressed HTTP RowBinary streamed from the compressed spool. It retains
wire AS membership arrays instead of claiming normalized AS4/AS_SET paths.
Drop-newest, exact BMP router timestamps, additional families, replicated/split
layouts, snapshots/EOR, hot reload and sustained gcore qualification remain later
increments. Do not treat the synthetic compression/latency figures as a production
capacity guarantee. See the validation note for the remaining fault-injection
and long-run tests.


## Private deployment record (removed from public docs)

# Active BMP staging validation — 2026-09-11

Netom 0.6.0-fnm15 was built for Ubuntu 24.04, copied to netomics-staging,
verified against SHA256
`550ed8c3833b8fd73de29bab25f061adcb3db12f09b956674e2f7c1d0e7f53d9`, and installed
with dpkg. The packaged `/usr/bin/netom` runs under systemd. bgpviewd was not
restarted or reconfigured.

## Verification

- Library suite: 342 passed, 30 ignored. Includes Gate clone reload regression,
  TCP reconnects, cancellation during partial frames and TLS handshake, unchanged
  reloads, retry interruption, TLS certificate trust/name checks and deadlines.
- Active TCP and active TLS synthetic exporters each produced exactly 1,006
  route observations: 1,005 announcements, one withdrawal, one IPv6 observation,
  two distinct peer generations and 1,006 unique event IDs. Raw attributes,
  ADD-PATH IDs, derived attributes and compact invalidations passed verification.
- Both live RIB and ClickHouse targets subscribe to the 30 TLS endpoints from
  staging's `/etc/bgpviewd.toml`. The localhost passive input remains available
  for test feeds. TLS encryption-only mode matches bgpviewd's configuration.
- At approximately 06:47 UTC, the live RIB held 30,243,482 records across
  1,391,276 prefixes. ClickHouse contained 31,832,921 route observations received
  since the live start at 06:38:19 UTC, with zero announcement attribute-parse
  failures. Counts are observations/records, not an assertion of dump completeness.
- ClickHouse reported zero exporter errors, unsupported routes, missing identities
  and stopped observations. Its queue was empty and the on-disk spool was 32 KiB.
  Including earlier test data, the events table had 10 active parts occupying
  about 699 MiB. RIB insertion failures were zero.
- Netom's memory cgroup used about 5.4 GiB with zero service restarts. Staging
  limits Netom to 16 CPU equivalents, MemoryHigh=64G, MemoryMax=96G and no swap;
  bgpviewd retains its existing service and workload.

History retention is 24 hours, with batches capped at one million rows or
256 MiB, a 32 GiB spool budget and the existing disk reserve. ClickHouse 26.8.2.7
listens on localhost. The configuration backup is
`/etc/netom/netom.conf.before-active-bmp`. A five-line operator note is in
`/home/nuclearcat/README_netom_clickhouse.md`.

## Connection coverage

At the measurement above, Netom had 27 established exporter connections and
bgpviewd had 29, from 30 configured hosts. The final configured host was unavailable
to both. Two additional Netom sessions timed out during connect/TLS and continued
to retry automatically. An independent OpenSSL-based probe succeeded against
one and timed out during TLS against the other. A separate 22-second Netom
process also connected successfully to the first host using the same TLS
configuration, demonstrating that its certificate/handshake is compatible.
This is partial live coverage;
full source parity and initial-dump completeness are not claimed.

This is a functional staging run, not a sustained gcore throughput qualification.
Netom preserves wire attributes; bgpviewd's `remove_left_asn` presentation rule
is not automatically reproduced.


## Private deployment record (removed from public docs)

# Initial staging validation — 2026-09-11

Netom 0.6.0-fnm14 was built for Ubuntu 24.04 using `./build.sh 24.04`, installed
on netomics-staging with dpkg, and enabled with the packaged systemd service.
The service runs as `netom`, stores its spool under `/var/lib/netom/clickhouse`,
and uses [staging.conf](staging.conf). BMP (11019), Netom HTTP (8080), and
ClickHouse HTTP (8123) listen on localhost. No production feed was connected.
Existing unrelated staging services were left in place.

## Results

- Library/daemon regression suite passed, with pre-existing ignored tests retained.
- Real RowBinary round-trip and same-token retry tests passed on staging
  ClickHouse **26.8.2.7** and an isolated **25.8.33.6** container.
  Tests verify unique event IDs, raw binary attributes, mapped IPv4 and ADD-PATH.
- End-to-end BMP tests passed for IPv4/IPv6, repeated identical announcements,
  path withdrawals, peer reconnect generations, raw/derived fields and compact
  invalidations. The largest run delivered **1,000,006 route observations** with
  exactly that many unique event IDs.
- With ClickHouse stopped, **100,006 route observations** survived a Netom restart
  and replayed without missing or duplicate event IDs.
- Restart testing exposed an existing daemon defect: SIGTERM was not handled.
  Before the fix, a dpkg/systemd restart lost a memory-only tail observation.
  After adding graceful SIGTERM handling, **10,006 route observations** survived
  a ClickHouse outage, graceful Netom restart, then SIGKILL/automatic restart.
  Journal evidence shows units and targets stopping and exit code 0 on SIGTERM.
- Unit tests cover partial-tail recovery, corrupted sealed segments, exclusive
  spool ownership, missing/mismatched manifests, bounded queue shutdown,
  full-spool backpressure, cache eviction/reconnect identities and mixed-family
  next-hop derivation. An executor test checks that shutdown waits for target
  completion without blocking other asynchronous work.

## Index and storage evidence

At approximately 1.1 million stored rows:

- An exact IPv4 prefix/time query selected **3 / 143** primary-index granules.
- A peer/time query used `by_peer`, selecting **3 / 138** projection granules.
- A storage sample reported 1,111,086 rows, 16,092,540 total bytes on disk,
  6,884,304 compressed base-column bytes and 258,906,260 uncompressed base-column
  bytes. Total disk includes projection/metadata overhead.
- Twenty successful exporter INSERTs observed in the query log had a maximum
  duration of **202 ms** in that sample. This is not a sustained throughput test.
- During the 100k outage test, compressed pending segments occupied about 834 KiB.

These fixtures deliberately repeat a small attribute set, use few peers, and have
ordered synthetic prefixes. Their compression ratios and query pruning do not
predict diverse production traffic. No gcore peak-rate or day-long retention
capacity claim is made. Network replay was tested locally on staging; the Rust
integration test also exercised an SSH tunnel.

## Remaining qualification

Sustained gcore-scale throughput, diverse attribute/peer distributions, long merge
pressure, real filesystem exhaustion, lost-ACK fault injection and retry-window
expiry remain to be tested. The current batch cap is below the fixed two-million
row insert block setting; arbitrary multi-block partial-success retries are not
qualified. Replicated/Distributed topologies remain unsupported. Snapshots, EOR,
split tables, hot reload and parallel draining are later increments.
