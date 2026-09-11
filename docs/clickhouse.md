# ClickHouse observation history (initial implementation)

`clickhouse-out` writes live IPv4/IPv6 unicast observations directly to a local
ClickHouse MergeTree table. No Kafka is needed. This first implementation is for
evaluation; sustained high-rate throughput has **not** been qualified.

## Setup

ClickHouse 25.8 or newer is required by the schema's compact projection. The
integration tests cover ClickHouse 25.8 and 26.8. Replicated/Distributed tables and schema
migrations are not supported in this release. Apply [schema.sql](clickhouse/schema.sql)
manually, with the destination database selected. The exporter checks required
column types, engine and retry deduplication settings before inserting. It never
creates or alters tables. Do not change the table schema while it is running.

```sh
clickhouse-client --query 'CREATE DATABASE netom'
clickhouse-client --database netom --multiquery < docs/clickhouse/schema.sql
```

```toml
[targets.history]
type = "clickhouse-out"
sources = ["bmp-in"]
endpoint = "http://127.0.0.1:8123"
database = "netom"
table = "events"
collector_id = "collector-a"
spool_dir = "/var/lib/netom/clickhouse"
retention_hours = 24
# username = "default"
# password_file = "/etc/netom/clickhouse.password"
```

Netom handles systemd's SIGTERM, quiesces producers (up to five seconds before
closing target admission to release backpressure), and waits for targets to drain.
The package's systemd service runs as `netom`; `StateDirectory=netom` supplies
the writable `/var/lib/netom` directory. Each target needs its own spool directory.
Keep its manifest and pending files together. The manifest binds a persistent
stream ID to the endpoint, database, table, collector ID and encoding version.
Changing that binding requires a separate spool; drain the old one using its
original configuration. Credentials are not stored in the manifest. All config
changes currently require a restart; Reconfigure logs a warning and retains the
active configuration.

## Capture and identity

Attach to `bmp-in` to observe its parsed output before RIB filtering/mutation;
attach to `rib` to observe that RIB's output instead. These are different capture
boundaries. Input Roto rejects, ignored post-policy updates and unknown ADD-PATH
withdrawals already dropped by the parser are absent. Raw BMP copies are ignored
to avoid exporting each route twice. FlowSpec and multicast are counted as
unsupported. This is an observation log, without a startup RIB snapshot, EOR
coverage guarantee or reconstruction of complete historical state.

`received_at` maps the source's monotonic receive timestamp to UTC using a process
anchor. It is millisecond precision and is **not** the router's BMP timestamp.
Routes retained in an upstream queue can therefore have an older receive time.
`stream_id`, `epoch`, `event_seq` identify an exported event. Epoch changes on each
target start; sequence orders rows within that epoch, not across source threads.
IDs and sequence values survive spool replay. Repeated identical announcements
remain separate observations.

`peer_key` combines stream, epoch, session ingress and connection generation.
ADD-PATH route rows carry a nullable `path_id` and resolve to their parent peer.
A bounded cache (65,536 entries / approximately 16 MiB) shares identity JSON;
connection generations live in the ingress register and survive cache eviction.
Each segment repeats needed identities before their references, and repeats them
for each receive-time hour. Routes carry compact keys; identity JSON contains the
peer, its router when available, and collector metadata. Missing metadata is
explicit and counted. There is no startup enumeration of inactive peers yet.

| event_kind | Meaning |
|---|---|
| 1 | Announcement |
| 2 | Route withdrawal |
| 3 | Identity observed/refreshed |
| 4 | Ingress invalidation (compact; path_id restricts scope when present) |
| 5 | Family invalidation (afi/safi restrict scope) |
| 6 | Ingress reappeared |
| 7 | History starts here; no baseline |
| 8 | Clean exporter shutdown |
| 9 | Source end-of-stream |

Control/identity rows have `event_class=0`; route rows have `event_class=1`.
Invalidation is not expanded into millions of synthetic route withdrawals.
Consumers must interpret the scope/parent metadata. A missing clean end marker
means coverage may have a gap; it is not a precise count of lost observations.

## Attributes, disk use and queries

`raw_attrs` is the authoritative binary String. Netom's RPKI and ASN-width prefix
bytes are stored separately, not included in the wire attributes. Withdrawals
normally have empty attributes. `as_path` and `as4_path` expose wire AS membership,
including sets/confederations; they do not merge RFC 6793 paths or identify origin
AS. Preserve raw attributes when segment semantics matter. Standard communities
are UInt32; extended/large communities retain 8/12-byte network-order values.
Unknown attributes remain in raw_attrs. Failed derivation leaves empty/null query
fields and `attrs_parse_ok=0`. IPv4 addresses use IPv4-mapped IPv6 representation.

Raw and array columns use ZSTD(1). Repetition is compressed without dropping
observations or relying on eventually consistent attribute dictionary joins.
Dictionary normalization remains a benchmark candidate. The prefix-first sparse
primary index supports exact prefix/time queries; the `by_peer` projection stores
compact query fields and row offsets, avoiding a second copy of raw attributes.
Hourly partitions prune time windows. Expiry rounds up to the receive-hour end
plus retention_hours; whole-part TTL drops can occur later during background
maintenance. This is a retention target, not an exact deletion deadline or a
ClickHouse disk quota. Budget ClickHouse storage independently from the spool.

```sql
SELECT received_at, event_kind, hex(peer_key), path_id, as_path
FROM route_events
WHERE afi = 1 AND safi = 1
  AND prefix_addr = toIPv6('::ffff:192.0.2.0') AND prefix_len = 24
  AND received_at >= now() - INTERVAL 1 HOUR
ORDER BY received_at LIMIT 100;

SELECT received_at, prefix_addr, prefix_len, event_kind
FROM events
WHERE peer_key = unhex('00112233445566778899AABBCCDDEEFF')
  AND event_class = 1 AND received_at >= now() - INTERVAL 1 HOUR
ORDER BY received_at LIMIT 100;
```

Use `EXPLAIN indexes=1` and `system.query_log.read_rows/read_bytes` to verify
pruning with representative data. Arbitrary AS/community membership, substring,
and covering-prefix queries are not automatically indexed by this key. Avoid
`SELECT *`, `FINAL`, unbounded time ranges and deep OFFSET for interactive search.
Views are ordinary views; they do not duplicate stored data or give independent
retention. Split tables, optional membership indexes and snapshots are later work.

## Buffering and failure behavior

| Setting | Default | Notes |
|---|---:|---|
| queue_bytes | 67108864 | Conservative byte accounting; shared blobs count fully |
| spool_bytes | 34359738368 | Pending spool budget, with bounded frame headroom |
| reserve_bytes | 5368709120 | Also reserve at least 5% of filesystem capacity |
| batch_rows | 100000 | Includes identities/control; up to one row over threshold |
| batch_bytes | 33554432 | Uncompressed encoding threshold; one event may exceed it |
| flush_seconds | 5 | Seal partial batch after this age |
| retention_hours | 24 | Range 1–8760 |
| request_timeout_seconds | 60 | Includes response processing |
| shutdown_seconds | 30 | Time allowed to drain memory to disk |

For high-volume qualification, start with batch_rows=1000000,
batch_bytes=268435456 and a dedicated 128 GiB spool. Current drain concurrency is
one. Increase batch size before adding inserts; watch active parts and merges.
Small synthetic tests do not establish sustained capacity.

Spool frames contain row-aligned RowBinary bytes compressed with LZ4, checksums
and bounds. Disk synchronization runs at roughly 500 ms and at segment seal.
Only sealed files are sent, using the segment UUID as insert_deduplication_token.
Replay validates the file, then streams decompressed bytes without re-encoding.
HTTP currently sends uncompressed RowBinary; the local LZ4 wrapper is not the
ClickHouse native compressed wire format. Replay uses bounded frame buffers.

On restart, complete frames in unattempted `.open` files are recovered; incomplete
tails are truncated. Corruption of complete frames or sealed files stops replay
and leaves the file for investigation. Never edit a `.ready` file and retry it
under the same token. Files are removed only after successful synchronous insert
acknowledgement. ClickHouse outages, TOO_MANY_PARTS and schema errors retain the
batch and retry with exponential backoff up to 30 seconds.

The setup SQL enables non_replicated_deduplication_window=10000. Insert block
settings are fixed and batches are capped below the configured two-million-row
block limit. Tokens have finite retention: replay outside the server's
deduplication window can duplicate rows. This is not exactly-once delivery.
The table is append-only MergeTree, not ReplacingMergeTree; queries needing to
collapse delivery duplicates can use the event ID explicitly.

The default full-buffer behavior blocks input. Backpressure can delay other
targets sharing that source. If the spool fills, it seals written data for drain
and waits. It does not discard oldest segments. Shutdown closes admission and
tries to persist queued data; an unavailable/full disk beyond the deadline or
process/power failure can lose memory-only data since the last sync. Other I/O
errors stop the writer visibly; pending durable segments remain replayable.
There is no drop_newest mode in this first release.

Metrics under `/metrics` include clickhouse_accepted, clickhouse_inserted,
clickhouse_errors, clickhouse_unsupported, clickhouse_missing_identity,
clickhouse_stopped, clickhouse_spool_bytes, clickhouse_queue_bytes and
clickhouse_healthy (with Netom's usual metric naming/labels). Alert on errors,
queue/spool growth, unsupported routes and target termination; a healthy HTTP
endpoint alone does not establish complete history coverage.

## Tests

```sh
cargo test --lib targets::clickhouse
NETOM_CLICKHOUSE_TEST_ENDPOINT=http://127.0.0.1:8123 \
  cargo test --lib targets::clickhouse::transport -- --ignored
```

The latter creates a uniquely named table in an existing `netom_test` database,
tests binary fields and same-token retries, then drops only that test table on
success. Failure leaves its table available for inspection.

The installed-service driver is `python3 scripts/e2e-clickhouse.py --routes 1000`.
It requires the [example configuration](clickhouse/example.conf) and
`netom_test.events`. It supports
`--feed-only` (prints a run token) and `--verify TOKEN` for outage/restart tests.
