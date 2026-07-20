# Netom Major TODOs

This document tracks the major remaining engineering work in Netom. It is
ordered by expected impact, with correctness and production safety ahead of
feature completeness and cleanup.

## 1. Peer lifecycle and RIB correctness

- [ ] Make RIB garbage collection atomic with BMP peer reconnect and ingress-ID
      reuse. A peer must be rechecked as disconnected immediately before its
      routes and register entry are removed.
- [ ] Make disconnected ingress-ID lookup and transition to connected a single
      atomic claim operation, so two concurrent sessions cannot reuse the same
      ID.
- [ ] Prevent an old BGP or BMP session's teardown from deleting register,
      metrics, or router state belonging to a replacement session.
- [ ] Audit peer flap and reconnect behavior with concurrent route insertion,
      withdrawal, and garbage collection.
- [ ] Add deterministic concurrency tests for reconnect-versus-GC and
      old-session-versus-new-session teardown races.

## 2. Complete RTR and RPKI integration

- [ ] Implement `RtrTarget::apply` in `src/units/rtr/client.rs` and verify full
      and delta cache-update behavior.
- [ ] Implement `RotondaPaMap::as_orderable` in `src/payload.rs`.
- [ ] Implement the RPKI route metadata `as_orderable` path in
      `src/units/rib_unit/rpki.rs`.
- [ ] Remove avoidable full-cache cloning from RTR delta processing.
- [ ] Add end-to-end tests covering RTR reset, delta, reconnect, and ROV status
      changes.

## 3. Finish the RIB query API

- [ ] Implement generic non-unicast route queries. The registered
      `/ribs/{afisafi}/routes` handler currently returns HTTP 500 with `TODO`.
- [ ] Implement `Rib::search_routes_for_ingress`.
- [ ] Implement `Rib::search_routes_for_origin_as`.
- [ ] Define supported filters and representations consistently for unicast,
      multicast, FlowSpec, and future AFI/SAFI families.
- [ ] Return a clear client error for unsupported queries instead of an
      internal-server error.
- [ ] Add pagination or bounded streaming for queries that can cover the whole
      RIB.

## 4. Bound memory and output backpressure

- [ ] Ensure every full-RIB HTTP and WebUI path streams or enforces a strict
      result limit instead of materializing the entire RIB and serialized
      response in memory.
- [ ] Keep BMP-out live delivery nonblocking and test slow or stalled clients
      under sustained route churn.
- [ ] Verify BMP-out dump-to-live ordering and snapshot/buffer consistency under
      concurrent announcements and withdrawals.
- [ ] Bound the MQTT publish queue and define an explicit overflow policy.
- [ ] Add load tests for multiple simultaneous BMP-out dumps and slow clients.

## 5. Harden configuration and runtime error handling

- [ ] Ensure invalid link names produce a location-aware configuration error
      without panicking, including during SIGHUP reload.
- [ ] Ensure missing or unreadable Roto scripts return an error and preserve the
      previously active script during reload.
- [ ] Validate MQTT QoS as `0..=2` during configuration loading.
- [ ] Reject or clamp link queue sizes of zero before constructing an MPSC
      channel.
- [ ] Replace reachable `unwrap`, `expect`, `todo!`, and `unimplemented!` calls
      on operator-controlled or network-controlled paths with explicit errors.

## 6. Correct and complete observability

- [ ] Audit RIB insert, withdrawal, item, and latency metrics for incorrect
      classification, underflow, and reversed duration calculations.
- [ ] Ensure BMP-out per-client message and byte counters update the shared
      exported metrics.
- [ ] Ensure active-dump and BMP-state gauges are decremented or transitioned on
      every early-return and termination path.
- [ ] Add BGP-in per-peer session and route statistics.
- [ ] Implement plain-format handling in `MetricsTarget::append_raw`, or remove
      the unsupported format.
- [ ] Add tests asserting exported metric values after announce, withdraw,
      reconnect, dump failure, and termination scenarios.

## 7. Complete BGP output and AFI/SAFI support

- [ ] Decide whether a BGP-in unit should also be usable as an output target. It
      currently logs that this is unsupported and drops direct updates.
- [ ] If supported, finish encoding and delivery for IPv4/IPv6 unicast,
      Add-Path, multicast, and relevant FlowSpec families. (Ingest-side
      ADD-PATH is done — see section 8; this item is the TX/output
      direction, where the `PrefixRouteWs::*Addpath` arms in
      `src/units/bgp_tcp_in/unit.rs` still end in `todo!()` inside
      dead code.)
- [ ] Replace partial AFI/SAFI matches that end in `todo!()` with supported
      implementations or explicit rejection during configuration.
- [ ] Add interoperability tests against a real BGP speaker for announcements,
      withdrawals, Add-Path, and reconnect behavior.

## 8. ADD-PATH (RFC 7911) follow-ups

Core support landed 2026-07-19 (commits `7cd89bb..4d9ddd3`): routes from
ADD-PATH sessions (BMP-monitored and direct BGP) are stored under
per-`(session, path_id)` child ingresses (`IngressType::BgpPath`, shown as
`bgpPath` with `pathId`/`parentIngress` in `/api/v1/ingresses`), tear down
and garbage-collect together with their session, and are restreamed by
`bmp-tcp-out` with full path fidelity — synthesized Peer Up advertises
cap 69 in both OPENs for the negotiated v4/v6 unicast families, re-encoded
NLRI carry the path id, and the raw fastpath forwards ADD-PATH UPDATEs
verbatim (duplicate suppression maps child payloads back to the session).
End-to-end coverage: `scripts/e2e-addpath-bmp.sh` (fastpath and rebuild
consumers). Remaining work:

- [x] FlowSpec ADD-PATH (done 2026-07-19): `convert_nlri` stores the two
      FlowSpec ADD-PATH variants under per-path child muis, the bmp-out
      FlowSpec encoder threads path ids through MP_REACH/MP_UNREACH and the
      dump aggregator, and the synthesized Peer Up advertises cap 69 for
      negotiated flowspec families. Along the way: RFC 8955 §6 validation
      now resolves child muis to their session (child entries carried no
      bgp_id, so rules under child muis were falsely Invalid), closing a
      pre-existing hole for unicast ADD-PATH too. Covered by unit tests and
      a flowspec leg in `scripts/e2e-addpath-bmp.sh`.
- [x] MRT ADD-PATH (done 2026-07-20): updated to routecore's RFC 8050
      support for TABLE_DUMP_V2 subtypes 8–12 and BGP4MP subtypes 8–11.
      `mrt-file-in` now admits those RIB records, retains path identifiers
      from both snapshots and UPDATEs, and stores each `(peer, path_id)`
      under a stable `BgpPath` child ingress so paths for one NLRI coexist
      and bmp-out can reattach the identifier. Observed families are saved
      on the MRT peer for synthesized cap-69 advertisement. The mrtgen
      corpus regression covers both TABLE_DUMP_V2 and BGP4MP ADD-PATH.
- [ ] exabgp e2e variant for BGP-in ADD-PATH (`add-path send/receive`
      toward `bgp-tcp-in`, two paths for one prefix, asserted via bmp-out) —
      the crafted-bytes harness covers the BMP pipeline only; Step 4's
      teardown paths for direct BGP have no live-stack coverage yet.
- [ ] `addpath_families` on a session ingress is only refreshed at
      PeerUp / SessionNegotiated. If the alternate-config retry
      (`generate_alternate_config`) ever starts toggling ADD-PATH per
      family (see the commented-out `inverse_addpaths` idea in
      `src/common/routecore_extra.rs`), the stored families and the
      advertised cap-69 value must be refreshed alongside.
- [ ] Multicast family collapse: bmp-out folds multicast NLRI into the
      unicast NLRI space (pre-existing quirk, now inherited by ADD-PATH —
      multicast paths are emitted with path ids inside the unicast family).
      A proper MP_REACH SAFI-2 encoder would remove the collapse; document
      or fix.
- [x] Flaky `ingests_mrtgen_*` tests (fixed 2026-07-19): the temp-file name
      was derived from (pid, corpus length, extension), so the TableDumpV2
      and BGP4MP tests over the same corpus collided on one path in the
      shared test process and raced create/read/delete. A process-global
      sequence number in the name makes every call's file distinct; six
      consecutive full-suite runs pass where ~1 in 2–3 failed before.

## 9. Operational completeness

- [ ] Drop privileges after acquiring required resources.
- [ ] Support systemd socket activation where appropriate.
- [ ] Add PID-file handling if still required by supported deployment modes.
- [ ] Complete graceful MQTT shutdown, including a defined policy for in-flight
      messages.
- [ ] Write standalone configuration-format documentation and keep example
      configurations synchronized with behavior changes.

## Validation notes

The untracked `BUGS.md`, `BMP_TODO.md`, and related review documents contain
useful findings, but they are not an authoritative current backlog. Some items
described there have already been fixed in the source. Before implementing a
review finding, reproduce it against the current revision and add a regression
test where practical.
