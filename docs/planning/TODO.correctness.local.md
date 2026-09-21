# Correctness review fixes (local, untracked)

Review baseline: 2ca2d4c. Existing library suite: 308 passed, 29 ignored.
Eight reproductions are preserved in /tmp/netom-correctness-review/reproduction-tests.patch.

Fix sequentially, adding regression coverage and recording validation below.

- [x] 1. P1 Native BGP teardown leaks withdrawn RIB records after removing their ingress registrations. Preserve reclaimable ownership through GC or explicitly remove records.
- [x] 2. P1 ADD-PATH cache hits return disconnected/deleted child IDs; reannouncements can be garbage-collected or orphaned. Coordinate reactivation, insertion, retirement and cache lookup.
- [x] 3. P1 Idle child retirement ignores active FlowSpec rules. Include both FlowSpec families in the liveness scan.
- [x] 4. P1 First unicast/multicast announcement after withdrawal removes other families, including FlowSpec already reannounced after reconnect. Reset only the affected family.
- [x] 5. P2 Child GC and input-cache pruning leave global peer-stat aliases behind. Reclaim aliases with their child without resetting the parent peer's live gauge.
- [x] 6. P2 BMP output emit-target caches retain departed peers/children indefinitely. Bound caches and reclaim obsolete mappings, including the fastpath session cache.

## Validation and decisions

No fixes committed or staged automatically. Keep this file untracked.

1. Implemented disconnected native-BGP retention through GC and atomic reconnect claim. Regression `gc_reclaims_native_bgp_records_and_spares_reconnect` passes (both attribute-retention modes and reconnect protection).

2. Cached child IDs now atomically reactivate or are replaced. Idle retirement compares activity generations across both sweeps and under the registry lock. Fifteen path-child tests and the between-sweeps/GC regression pass.

3. Idle scans now include IPv4 and IPv6 FlowSpec and abort on store-read errors. Regression confirms live rules survive and withdrawn rules are reclaimed.

4. Unicast/multicast reset is scoped to its AFI/SAFI and clears stale records before reactivation. Regression covers four families, stale-prefix suppression, and FlowSpec arriving before unicast after reconnect (both retention modes).

5. GC now removes stats entries for reclaimed ingresses. Aggregate resets apply only to session entries, so retiring an alias preserves sibling counts. Alias-reclamation/live-sibling regression passes.

6. Emit-target caches are bounded to 65,536 mappings and clear a session’s mappings on Peer Down. Fastpath session memo uses the same cap. If metadata expired before buffered replay, the client reconnects for a new dump rather than sending an invalid header. Both cache regressions pass.

Follow-up validation: teardown now ignores already-reclaimed cached children instead of recreating incomplete registrations; a BMP wire-message regression covers reactivation, replacement and teardown.

## Final validation

- `cargo test --offline --all-features --release --quiet`: PASS — 318 library tests, 107 CLI tests; 30 pre-existing ignored tests across library/main.
- `cargo build --offline --release --bin netom`: PASS (existing unused `set_rib` warning).
- `scripts/e2e-addpath-bmp.sh`: PASS — fastpath and rebuilt live unicast/FlowSpec, withdrawals, reconnect dump, exactly one Peer Down.
- `scripts/addpath-churn.sh`: PASS — 2,000 churn paths reclaimed; settled at 0 children and 0 route records (including the withdrawn baseline path).
- `git diff --check`: PASS.
- No tracked TODO modified; no staging, commits or deployment.

Operational changes: disconnected native BGP records remain eligible for reclamation after the GC grace interval. Reusing a cached ADD-PATH ID takes a register write lock to validate and record activity. BMP identity caches cap retained mappings at 65,536; a replay whose required metadata has expired requests a fresh dump instead of emitting an invalid peer header. Large-production-table throughput has not been benchmarked.

Logs: /tmp/netom-fix-full-tests.log, /tmp/netom-fix-addpath-e2e.log, /tmp/netom-fix-churn.log.

## Publication

At the user's request, committed and pushed directly to origin/main:

- a878dd6 — Reclaim disconnected BGP session records.
- 86478f3 — Safely reactivate retired ADD-PATH children.
- ee2b33c — Preserve active FlowSpec children during GC.
- 9c5fe9a — Limit reconnect resets to the affected family.
- c87e179 — Reclaim retired peer-stat aliases.
- b1b3e66 — Bound BMP output ingress identity caches.

Each intermediate commit compiled and passed its targeted regressions before publication. Push confirmed main at b1b3e6615bec33c21ed9fb207534f26efdb2bcbc. This TODO remains untracked and was not pushed.


## Active BMP follow-up (2026-09-11)

- [x] Fix Gate clone registration across reconfiguration. Old asynchronous
  attachment targeted the replaced command channel, closing new handlers after
  reloads; synchronous weak registry attachment/removal also avoids blocking
  the runtime during clone drop. Commit 34c6062; full suite with active BMP:
  342 passed, 30 ignored.
- [x] Add active TCP/TLS BMP input with interruptible retries and cleanup before
  redial. Commit a880cf4; staged fnm15 and verified both transports through
  ClickHouse (1,006 route observations each).

This file and CLICKHOUSE_PLAN.md remain untracked.
