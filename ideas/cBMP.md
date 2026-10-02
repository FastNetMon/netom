# cBMP: a canonical, compressed BMP corpus

Proposal, based on the current Netom source. No implementation or compression
measurements are implied.

The idea is to normalize the **structure of BMP observations across all incoming
streams**, then use measured frequency and co-occurrence to arrange their encoded
representation for similarity. Compress the result with zstd using a shared,
versioned dictionary. Sorting BGP path attributes is one small part of this:
repeated peer headers, message shapes, UPDATE packaging, next hops, NLRI and
control-message structures also offer opportunities.

The central hypothesis is that **compression can replace application-level
deduplication for storage and output**. Serialize every observation, including
repeated headers and bodies, in a consistent representation; let zstd encode the
repetition. The initial design needs no peer/body content tables, content-addressed
object store, reference counting or deduplication lookup on the write path.
Normalization exposes redundancy, statistical ordering brings similar bytes
within reach of the compressor, and the shared dictionary supplies learned
patterns across independently compressed chunks.

The proposed output is a versioned corpus/container format, provisionally cBMP,
with a decoder that can reconstruct BMP streams. It is not a new encoding to send
directly to an ordinary BMP TCP collector. BMP's existing message boundaries and
per-peer headers remain the interoperability contract
([RFC 7854](https://www.rfc-editor.org/rfc/rfc7854.html)).

## What is already in place

| Area | Current implementation | Implication for cBMP |
| --- | --- | --- |
| Input framing | [`bmp_tcp_in/io.rs`](../src/units/bmp_tcp_in/io.rs), `bmp_read` and `BmpStream::next`, read length-bounded messages into `Bytes` and validate them with routecore. Tracing can modify the version byte before validation. | A natural capture boundary exists, but exact capture must precede mutation and parser rejection. |
| Input processing | [`router_handler.rs`](../src/units/bmp_tcp_in/router_handler.rs), `process_msg`, applies post-policy suppression, filters and the BMP state machine. | Capture before this path to include every received observation, independently of routing policy. |
| Raw UPDATE forwarding | [`payload.rs`](../src/payload.rs), `Update::RouteMonitoringRaw`, carries the per-peer header and BGP UPDATE. [`machine.rs`](../src/units/bmp_tcp_in/state_machine/machine.rs) constructs it after successful parsing and can correct the ASN-width A flag. The handler emits it before parsed route payloads when `forward_raw_updates` is enabled. | Useful parsing/forwarding precedent, but not a complete or byte-exact BMP archive: common headers and other message types are absent, and the header can change. |
| Statistics forwarding | `Update::PeerStats` carries the statistics count and TLVs; BMP output rebuilds headers. | Some non-route bodies already survive forwarding, but original envelopes still need capture. |
| Attribute representation | `RotondaPaMap` holds an `Arc<[u8]>` containing RPKI and parse metadata followed by raw path attributes. `PathAttributeInterner` uses sharded hash buckets, weak references and byte equality to share identical buffers. | Existing memory deduplication is byte-based, not semantic normalization, durable object storage or a zstd dictionary. Keep internal metadata separate from canonical wire attributes. |
| BMP reconstruction | [`bmp_builder.rs`](../src/units/bmp_tcp_out/bmp_builder.rs) builds control messages, synthetic OPENs, EORs and Route Monitoring. `DumpAggregator` groups by peer, family, ADD-PATH presence and attribute-blob hash, checks equality, and flushes under byte/message limits. | Reuse protocol encoding knowledge and bounded aggregation patterns. Hash-map iteration and fullest-group eviction are not a canonical statistical ordering. |
| Output fastpath | [`bmp-tcp-out`](../docs/bmp-tcp-out.md) preserves live BGP UPDATE bytes while synthesizing BMP identity headers; initial dumps rebuild from the RIB. | Neither path is a corpus of original messages. A RIB snapshot cannot recover event history or original message packaging. |
| History storage | [`clickhouse/event.rs`](../src/targets/clickhouse/event.rs) records route observations, sequence/epoch identities, raw attributes and derived columns. [`spool.rs`](../src/targets/clickhouse/spool.rs) writes immutable, checksummed, row-aligned LZ4 frames. [ClickHouse documentation](../docs/clickhouse.md) describes ZSTD(1) columns and uncompressed RowBinary HTTP output. | Reuse lifecycle and durability ideas, but this is route history rather than full BMP capture. Database column compression is not a shared BMP dictionary. |

[`Cargo.toml`](../Cargo.toml) has LZ4 and other compression dependencies, but no
direct zstd dependency. There is currently no cBMP codec, statistical layout
profile, shared zstd dictionary lifecycle, or full-message corpus target.

## Fidelity and canonical identity

Start with a lossless observation corpus: retain every framed message, including
duplicates, source identity, connection epoch, per-connection sequence number,
receive time and original BMP timestamp. Preserve original message boundaries.
Compression must not collapse observations from different routers or times.
Do not equate equal route bodies with equal policy views or peer sessions.

Define three separate artifacts:

1. **Canonical content:** a deterministic structural representation under a
   named normalization version. Identical supported structures produce identical
   bytes irrespective of incidental attribute ordering.
2. **Observation envelope and reconstruction data:** source/session identity,
   timing, boundaries, ordering and any original encodings needed to reverse a
   transformation. These preserve differences that canonical content factors out.
3. **Physical layout:** a statistics-driven arrangement of content and envelopes
   within a bounded segment, followed by zstd compression. Its profile can change
   without changing canonical content identity.

This distinction resolves a tension: a globally adaptive frequency ordering is
not a timeless canonical form. Freeze the normalization rules and layout profile
by version; use stable content bytes for identity and the profile for placement.
If a future format makes statistical order part of canonical serialization, its
identity must also include that profile version.

For an initial lossless implementation, use reversible transforms and opaque
fallbacks. Exact reconstruction requires original ordering/encoding residuals
where normalization changes bytes; account for their cost. A later explicitly
semantic export could omit those residuals and emit normalized BMP, but must not
claim byte-for-byte recovery. Preserve unknown attributes, TLVs, unsupported
families, duplicate fields and malformed-but-framed bodies as opaque bytes when
their transformation is not demonstrably safe. Invalid lengths and truncated TCP
messages require capture-error records; they are not valid complete BMP messages.

## Normalize structures, not just attribute lists

Represent messages using a common envelope and typed bodies. Serialize repeated
per-peer fields consistently for each observation and let compression exploit
their repetition. Keep volatile timestamps and sequence numbers in separate lanes;
delta-encode only with explicit bases and reversible signed deltas. Clock changes
and zero timestamps must remain representable.

For Route Monitoring, split the nested UPDATE into withdrawals, shared path
attributes, family/next-hop context, announcements and explicit EOR form. Separate
NLRI from MP_REACH/MP_UNREACH containers so otherwise identical attributes are
not made different by the list of prefixes carried in the UPDATE. Retain the
mapping back to each original message and original container layout.

Normalize known field encodings conservatively. A canonical attribute ordering
and reversible ordering of supported community collections are candidates.
Keep AS sequence order, AS segment kinds, ASN width, AS4 information, next-hop
structure, ADD-PATH IDs and AFI/SAFI distinctions. Do not infer that every list
is a set, remove duplicate fields, or merge withdrawals and announcements.
Unknown or ambiguous encodings take the opaque path. Original OPEN capabilities
and session context must accompany data that depends on them for decoding.

Use common skeletons for Peer Up/Down, Initiation/Termination, Statistics and
Route Mirroring, with variable fields/TLV bodies factored out only where safe.
The first codec can leave these bodies opaque while capturing all of them.
Synthetic OPENs from the current restreamer are not substitutes for captured
OPENs. Likewise, decoder output must not inherit the builder's documented
multicast-to-unicast family collapse.

This also makes packaging differences compressible: one UPDATE carrying 100
prefixes and 100 UPDATEs carrying one prefix each expose the same canonical
attribute bytes to the compressor. Their envelopes and boundary records remain
different. Feed repeated bytes directly to the encoder without building a durable
attribute-reference table or allocating an extra copy for every occurrence.

## Statistics-driven ordering

Collect bounded samples across all configured BMP inputs. Measure message/body
shape frequencies, attribute combinations, repeated values, shared byte prefixes,
field cardinality and co-occurrence. Balance sampling across exporters, time,
initial dumps and live updates so one large feed does not define the whole model.
These are corpus statistics, distinct from incoming BMP Statistics Reports.

Use those measurements to generate a frozen layout profile:

- Cluster messages/content by structural shape, family and next-hop form, then
  by common attribute structure and values. Compare candidate keys using actual
  compressed bytes; frequency alone does not establish useful adjacency.
- Place common stable fields together and separate high-cardinality envelope
  fields from reusable bodies. Compare record-oriented and field-lane layouts.
- Order structural groups using measured frequency and similarity. Resolve ties
  with canonical bytes; retain every occurrence without assigning content IDs.
- Consider prefix locality inside a compatible group, with an inverse permutation
  wherever the original order matters. Never sort AS sequences for compression.

For example, alternating observations `router-A/body-X`, `router-B/body-Y`,
`router-C/body-X` can place the two serialized body-X occurrences together while
retaining all three observations and their replay positions. Zstd can encode the
second occurrence as a match when it is within its matching window, or use
dictionary matches for patterns present there. The application writes both
occurrences and maintains no body-X deduplication entry.

Only reorder physical storage within bounded segments. Preserve logical order
using `(source, connection epoch, sequence)` and positional correspondence between
envelope and body lanes, with an inverse permutation where needed.
There is no inherent global causal order across independent TCP connections;
record a collector merge ordinal if reproducing the collector's interleaving is
required. Replay restores order before emitting Peer Up, routes, EOR, Peer Down
and termination. A compressed segment should include the identity/session context
needed to interpret it; starting a new BMP session halfway through history may
still require earlier state or a separate snapshot.

Profiles should update at segment boundaries, not after every observation.
Deterministic tie-breaking and recorded profile parameters allow reproducible
normalization/layout for a fixed input and segmentation policy. Do not promise
identical compressed bytes across zstd versions or settings.

## One shared zstd dictionary across incoming streams

Train on the **normalized serialized representation**, after choosing its layout,
using representative samples pooled across inputs. Share the resulting immutable
dictionary generation among compression workers. Each worker keeps its own
compression context; a shared dictionary does not imply a single mutable
compression stream or a global lock.

Zstd dictionaries require the corresponding dictionary during decompression and
are particularly useful for small inputs
([zstd documentation](https://github.com/facebook/zstd/blob/dev/programs/zstd.1.md)).
They do not provide unbounded cross-frame history or global deduplication of every
previous message. Choose chunk layout and compression-window settings together:
repetitions outside the available history only benefit from the shared dictionary
when it contains useful matching patterns. The goal is good total compression
without maintaining an application-level index of everything seen before.

Keep manual content deduplication out of the initial implementation. It can be an
optional benchmark comparison if compression leaves substantial repeated content
uncompressed; introduce it only if measured gains justify the extra tables,
references and lifecycle management. The existing RIB `PathAttributeInterner`
addresses a separate problem: sharing live, uncompressed in-memory route state.
Compressing the corpus does not automatically replace that interner, and this
proposal does not require changing it.

Use independent zstd frames for bounded chunks inside immutable segments. Flush
on a configurable byte or latency threshold. Compare pooled multi-source chunks
with per-source chunks using the same dictionary: pooling may improve locality,
but adds buffering and couples latency. Large chunks may reduce the incremental
benefit of a dictionary, so measure rather than assume it.

Each segment manifest should identify the format/normalization version, layout
profile digest, dictionary digest and zstd dictionary ID, codec parameters,
source/epoch sequence ranges, frame sizes and checksums. Store dictionary and
profile artifacts durably before publishing dependent segments; retain them while
any segment references them. A zstd dictionary ID alone is not a content-integrity
check. Exports must bundle the artifacts or specify a durable resolution contract.
Missing/wrong dictionaries and corrupt frames must produce explicit errors.

Bootstrap with dictionary-free zstd until enough samples exist. Train replacement
generations off the ingestion path and adopt only at segment boundaries after
held-out evaluation. Keep old generations readable; do not rewrite the entire
corpus on rotation. Training controls and sampling memory must be bounded.

## High-level implementation changes

1. **Introduce a full BMP capture envelope.** Extend the framing boundary in
   `bmp_tcp_in/io.rs` to retain original bytes before tracing mutation and protocol
   parsing. Deliver complete framed messages, connection lifecycle and capture
   errors to an optional capture channel before filtering/state-machine changes.
   Assign persistent source identity, fresh connection epochs and sequences here;
   transient/rebound `IngressId` values alone are insufficient. Reuse cheap `Bytes`
   clones. Capture must work regardless of `forward_raw_updates`.
2. **Add a shared collector target.** A proposed `cbmp-out` target subscribes to
   capture from multiple BMP input units. Prefer a dedicated capture subscription
   over adding full raw traffic to every existing route consumer. Wire its config
   and lifecycle through `src/targets/mod.rs` and the manager. Keep the capture
   envelope/codec independent of the RIB and ClickHouse event model.
3. **Implement a versioned codec library.** Suggested modules cover capture
   records, conservative normalization, inverse reconstruction, layout profiles,
   dictionary artifacts and segment framing. Begin with opaque lossless bodies,
   then support Route Monitoring structure. Reuse routecore parsing with recorded
   session context and extract suitable builder helpers; do not route exact replay
   through synthetic-header output routines.
   Serialize normalized occurrences directly into bounded compression buffers;
   do not add a persistent content-deduplication layer.
4. **Add bounded processing and persistence.** Run normalization, sorting,
   training and compression away from async socket tasks. Bound queued bytes,
   worker memory, sorting windows and disk backlog. Adapt the ClickHouse spool's
   checksum/recovery patterns, not its RowBinary schema or LZ4 format. Publish
   segments atomically after required durability steps and recover partial writes.
   Define queue-full behavior explicitly: backpressure for lossless operation, or
   an explicitly configured loss mode with durable gap records and counters.
5. **Provide decoding and output tools.** First implement offline inspect, verify
   and decode commands for the corpus. Emit reconstructed per-source BMP streams
   in logical order. Later add framed corpus transport with dictionary/profile
   delivery and resumable segment identities; keep it separate from standard BMP
   TCP output. Reuse the same immutable segment bytes for storage and transfer.
6. **Expose operational evidence.** Report input/canonical/compressed bytes,
   dictionary and index overhead, opaque fallback rate, queue size, segment age,
   compression/decompression CPU, dictionary generation, gaps and replay failures.

## Validation and rollout

Build an offline prototype before coupling the codec to live ingestion. Evaluate
the following on the same captured corpus, segment boundaries and zstd settings:

| Variant | Question answered |
| --- | --- |
| Raw BMP + zstd, no dictionary | What does ordinary chunk compression already achieve? |
| Raw BMP + shared dictionary | What does dictionary training alone contribute? |
| Attribute-order normalization + zstd | How much does the narrow approach buy? |
| Structural normalization, original event order + zstd | What does factoring message structure contribute? |
| Structural normalization + statistical layout + zstd | What does physical ordering contribute? |
| Full design + shared dictionary | Does the shared model improve the normalized corpus further? |
| Optional explicit deduplication + compression | Is there enough additional benefit to justify application-level tables and references? |

Train on an earlier interval and test on later intervals and held-out exporters.
Include initial dumps, churn, withdrawals, IPv4/IPv6, multiple policy views,
ADD-PATH, unknown attributes, unsupported families and control messages. Compare
total retained bytes including envelopes, inverse permutations, residuals, indexes,
profiles and amortized dictionaries. Measure ingest/decode throughput, peak memory,
latency, random segment reads and recovery time. Do not use the existing synthetic
ClickHouse compression results as a prediction for this format.

Correctness gates include byte-exact capture/decode round trips, deterministic and
idempotent canonicalization for supported structures, opaque fallback round trips,
preservation of event multiplicity and per-stream order, and dictionary rotation,
restart, truncation and checksum failures. Verify that reconstruction cannot
confuse peer epochs or ADD-PATH parsing context. Property/fuzz tests belong at the
parser/codec boundary once implementation begins.

Roll out in stages: offline baseline and codec; optional live lossless capture;
conservative structural normalization; statistical layout and shared dictionary;
then corpus transport and optional semantic BMP export. Advance the more complex
transforms only when their measured savings cover metadata, CPU and latency costs.
