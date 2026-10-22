# Batched RIB reclamation and BMP replay safety

## Incident and change

On 2026-10-22, netomics-gcore had one Netom thread consuming a CPU continuously.
Perf attributed the work to `gc_disconnected_bmp_peers -> remove_for_ingresses ->
remove_mui`. The store traversed the table separately for each retired ID, while
Netom held the withdrawal mutex across the entire batch. The instance reported
1.94 million prefixes and 413 million stored route variants. Some ingestion
continued, but many BMP sockets had multi-megabyte receive queues.

The replacement scans prefix keys once for a batch of permanently retired IDs.
It deletes matching records under each prefix's mutation lock without cloning
path attributes. Netom releases its withdrawal lock after each prefix, drops
all epoch guards before scheduling pauses, and pauses for 1 ms every 512 prefixes.
This is cooperative pacing, not a hard real-time latency guarantee. A single
expensive prefix operation or an unrelated session reset can still take longer.

Reusable-session reset remains synchronous and distinct from permanent
retirement. It must finish before that session's fresh routes are accepted.
The store fixes concurrent existence-bit/counter changes and serializes bitmap
writes internally. Reannouncements no longer increment the total record gauge.

## Ownership and ordering invariants

- A retirement writer fence drains admitted RIB writes before unlinking an
  eligible registration. Later writes to that ID are rejected. Numerical
  retired-ID tombstones carry no metadata or route references. IDs never wrap
  and get reused within the same process.
- Reconnect claims retain their existing atomic registry checks. A claimed live
  session is excluded from GC. Whole-session resets preserve existing ordering;
  family-specific reset behavior is unchanged.
- Pending cleanup tickets remain owned by the RIB until every store succeeds.
  Retired routes are marked withdrawn in batches before physical removal. A
  failed pass keeps its ticket and can restart idempotently. Progress is not
  persisted across process restart because the RIB itself is memory-only.
- Per-prefix insert/delete locks cover record mutation, existence bits and
  counters. Empty-to-nonempty reinsertion restores both sets of store counters.
  Physical removal rejects persistent stores rather than silently leaving a
  disk copy that might reappear.
- BMP dump-buffer entries own immutable snapshots of their original ingress,
  parent peer and router metadata. Shared snapshots use weak cache entries;
  they do not own the RIB, client, input handler or mutable registry.
- Replay looks up metadata only in its owned snapshot, never in the current
  registration. Session generation changes invalidate cached output headers;
  an older generation cannot reopen a peer after a newer one was emitted.
  The per-client output mutex orders cache transitions and message enqueueing.
- A Peer Down uses the header previously emitted to that consumer when available.
  Missing identity causes a reconnect, never an unspecified/default header.
  Child-to-parent/path mapping and raw-forwarding coverage are invalidated at
  their corresponding lifecycle boundaries.
- On writer disconnect the client is removed and its dump buffer is discarded
  immediately. Failed/expired dump walks do not emit successful End-of-RIB
  completion. Existing bounded queues, write timeouts and nonblocking live
  sends remain in effect.

## Costs and limits

Prefix-key snapshots use O(prefix count) memory, not O(route variants); they are
not a strict constant-memory cursor. Deletion target sets use O(retired IDs).
The numerical retired-ID bitmap grows with lifetime churn, but does not pin
session metadata or route attributes. A future change to recycle IDs would
require a different lifetime scheme, not just removing the overflow check.

Mutation stripes add an uncontended lock to insertions. Reclamation yields
reduce its throughput in exchange for responsiveness. Reconnect reset and
withdrawn-attribute compaction can still hold the withdrawal lock for a scan;
this patch does not make those operations asynchronous.

Replay metadata is conservatively charged to each queued event, even when
several events share one allocation. Consumers may reach the configured byte
cap sooner and reconnect. Output generation history and snapshot lookup caches
are bounded; a consumer exceeding generation-history capacity requests a fresh
dump rather than forgetting the ordering fence. Already active dump peers can
exceed the nominal history cap; new identities trigger a reconnect at the cap.

Missing metadata before an event reaches the restreamer's buffering boundary
still requires a consumer reconnect. This patch does not provide a durable
archive of all upstream events. It protects owned queued snapshots and rejects
unsafe identity reconstruction.

## Monitoring

The `/metrics` endpoint exports:

- `netom_rib_gc_pending_ids_total`: outstanding retirement tickets (gauge).
- `netom_rib_gc_prefixes_scanned_total`: cumulative scanned prefixes.
- `netom_rib_gc_records_removed_total`: cumulative physically removed records.
- `netom_rib_gc_completed_batches_total`: successful passes.
- `netom_rib_gc_failed_batches_total`: failed passes kept for retry.

Progress is logged approximately every five seconds during a long pass.
Check that the backlog drains while ingestion counters continue advancing;
watch reconnect frequency, BMP receive queues, RSS and process CPU as well.
A lower CPU number alone is not evidence of correct reclamation.

## Validation and deployment

Regression coverage includes batch/default-route removal across both families,
concurrent insertion/deletion, bitmap writers, duplicate announcements, a
retirement admission barrier, owned route snapshots, deferred and partially
failed cleanup, replay after registry deletion and same-ID reconnect, rejection
of old generations, and missing Peer Down identity.

Manual performance case in netom-store:

```sh
cargo test --release --test remove_mui batch_reclamation_workload -- --ignored --nocapture
```

For 2,048 prefixes and 128 IDs, repeated single-ID calls took approximately
112 ms versus 6.7 ms for one batch on the development machine. This is a small
algorithm comparison, not a production-table latency or memory guarantee.

Before production rollout, replay representative traffic on an isolated
instance and compare route sets, BMP identities, update latency and memory.
The library commit must be pushed before publishing a Netom commit that pins
it. Deploy by restarting Netom with the new binary; its existing in-process
collector cannot be replaced or safely killed independently. A restart needs
an upstream replay and downstream redump. Roll back the binary and restart if
route/peer identity, progress or latency checks regress. No production service
was changed during development.

### Development verification (2026-10-22)

- `cargo test --locked --offline --lib`: 364 passed, 31 existing ignored,
  zero failures, using the pinned store revision.
- Full `netom-store` unit/integration/doc suite: passed; the manual benchmark
  remains ignored by default.
- `scripts/e2e-addpath-bmp.sh`: passed for raw and rebuilt output, unicast and
  FlowSpec path IDs, reconnect dumps, and exactly-once Peer Down.
- `CHURN=5000 scripts/addpath-churn.sh`: passed; retired child entries and route
  records returned to zero with the live parent/session retained.
- `python3 scripts/bmp-peer-churn.py --binary target/debug/netom --cycles 20`:
  all eight scenarios passed, including silent and partial-frame recovery.
- Changed Rust files pass rustfmt; both repositories pass `git diff --check`.

No production-scale canary or deployment has been performed. The initial
sandboxed suite was unable to bind test sockets; the results above are from
rerunning with loopback access.
