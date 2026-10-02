# Netom engineering principles

Netom monitors large BGP/BMP routing tables and many sessions. Correctness
includes protocol semantics, lifecycle and metrics, bounded resource use, and
predictable ingestion under concurrent queries. Evaluate changes at realistic
route/path/ingress counts and at 10x scale, beyond small test fixtures.

## Keep common objects compact

- Measure `size_of` before/after changes to core route, payload, queue, and
  message types, including enclosing types, alignment, and padding. Justify
  increases and report their aggregate cost in the PR.
- A large enum variant enlarges every instance. Keep uncommon large data behind
  appropriate indirection; account for allocations, reference counts, and copies.
- On 64-bit targets, the boxed EVPN layout preserves `RotondaRoute` at 64 bytes
  and `Payload` at 96 bytes. Inline EVPN raised them to 240/272 bytes:
  +176 bytes per object, or roughly 176 MB per million objects.
- Queue/buffer accounting must include owned heap allocations and capacities,
  not just stack size. Preserve lightweight layout and accounting regression tests.

## Filter before copying; preserve snapshot consistency

- Never deep-clone the entire RIB to satisfy a filtered query or solve ownership.
  Apply cheap family, active/withdrawn, and identity filters before copying;
  exclude withdrawn records unless requested.
- Prefer references or filtered shared immutable snapshots. Captured records/IDs
  must remain valid through consumption; use copy-on-write where needed to keep
  snapshots coherent across updates, withdrawals, and removal.
- Snapshot predicates under a writer mutex must be inexpensive. Decode, sort,
  transform, serialize, and perform network I/O after releasing the lock.
- Account for snapshot lifetime, retained old versions, and concurrent readers.
  Add indexes for frequent expensive queries only with a justified memory cost.

## Bound work and contention

- Analyze cost using actual cardinalities: routes, paths, ingresses, updates,
  peers, and concurrent queries. Include allocations, copies, and lock duration.
- Avoid linear membership searches inside table scans. For batch ingress cleanup,
  build a membership set outside the lock: expected O(I + R), rather than O(I × R).
  Empty batches return immediately without locking or scanning.
- Keep hot lock sections short; avoid full-table deep copies, expensive decoding,
  serialization, and unnecessary allocations while holding them. Preserve an
  explicit consistency model when moving work outside locks.

## Guard the complete query operation

- Bound concurrent expensive RIB queries. Hold the resource permit through
  extraction, transformation, allocation, and serialization, including work in
  `spawn_blocking`; releasing it before JSON encoding defeats the limit.
- Move synchronous CPU-heavy work off Tokio workers. `spawn_blocking` alone
  does not bound concurrency or peak memory.
- Serialize typed responses directly. Avoid `json!`/JSON value trees that create
  another large representation solely for encoding.
- Assess peak memory across retained state, snapshots, response rows, encoded
  bodies, and concurrent requests; final response size alone is insufficient.

## Preserve identity, lifecycle, and metric semantics

- Route identity must include the correct NLRI, ingress/session provenance, and
  ADD-PATH identity. Equal NLRIs can have independent paths; withdrawing one must
  leave the others active.
- Derive metrics from prior existence/state and the event, not just resulting
  `active`. A known-route withdrawal must not become an unannounced withdrawal;
  a different ingress/path is not a matching prior record.
- Define retained-withdrawn behavior explicitly, including repeated withdrawals,
  re-announcements, and “new” counters. Test both retention modes.
- Every insertion needs cleanup for withdrawal, family withdrawal, peer/session
  teardown, and ingress removal. Marking withdrawn is not physical removal;
  expired sessions must not leak one retained slot per prefix/path.
- Test known/unknown withdrawals, updates and re-announcements, independent
  ADD-PATH withdrawals, family/peer cleanup, and snapshot stability during mutation.

## Make optional family support consistent

- EVPN requires explicit runtime opt-in (`enable_evpn`, default false). Gate
  negotiation (including ADD-PATH), ingestion, and APIs consistently; account
  for disabled-family drops without retaining their routing state.
- Configuration affecting negotiated sessions and retained state must not change
  on reload without a safe transition. EVPN enablement currently requires restart.
  Tests should inject settings rather than race on process-global configuration.
- Keep EVPN semantics distinct: RD is not tenant identity; route-target selection
  is not VRF import-policy simulation; a numeric label/VNI does not establish
  L2 versus L3 role. Preserve Type 2/Type 5 data needed for symmetric IRB analysis.

## Validate the cost as well as the behavior

For significant RIB/API changes, report relevant before/after measurements:
bytes per object and owned heap, allocations/copies, query latency, lock hold
time, ingestion throughput, and peak serialization memory. Show how costs grow
with table size and concurrency. Follow the whole operation so a later stage
does not recreate costs eliminated earlier.
