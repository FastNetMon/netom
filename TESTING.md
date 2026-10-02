# Testing

The tests of Netom live in a few places:

 - unit tests in the source code
 - doctests in the source code
 - end-to-end tests in a separate, private repo called REEDS


Running these tests is done with a single command:
```
cargo test --all-features --release
```


## End-to-end testing (REEDS)

The end-to-end tests for Netom are maintained in a separate repository that
is private. Keeping it private enables us to store real-world network data,
which is used as input in the test suites.

While this makes the end-to-end tests invisible, we do encourage contributors
to think about what types of input data would be required to test their
contributions in an end-to-end fashion. For example, when a PR adds certain new
fields to the response of an API endpoint, we should create a test where the
input (e.g. pcap or binary BMP) contains PDUs that result in API responses
featuring the newly added output.

Ideally, a PR is accompanied with a pcap or likewise (perhaps transferred to
use in private) for us to create an end-to-end test from. This might not always
be trivial: in that case, please reach out to discuss how we can proceed to get
proper testing in place.


## End-to-end FlowSpec testing

FlowSpec (RFC 8955/8956) is covered end-to-end on both ingest paths, with the
decoded rules verified through the HTTP API
(`/api/v1/ribs/ipv{4,6}flowspec/routes`):

 - `cargo test --lib ingests_mrtgen_flowspec_rules` — in-process test: a
   [mrtgen](https://github.com/FastNetMon/mrtgen)-generated BGP4MP file with
   diverse rules goes through the mrt-file-in unit into the flowspec store.
   Runs as part of the normal test suite and CI.
 - `scripts/e2e-flowspec-mrt.sh` — the same corpus against a real netom
   binary: the mrtgen CLI (pinned to the Cargo.toml revision) writes the MRT
   file, an mrt-file-in unit ingests it, assertions run over the HTTP API.
 - `scripts/e2e-flowspec-exabgp.sh` — live BGP session: exabgp announces 8
   diverse FlowSpec rules (plus one unicast route for RFC 8955 §6 validation)
   to a bgp-tcp-in unit that negotiates the FlowSpec families.
 - `scripts/e2e-addpath-bmp.sh` — ADD-PATH (RFC 7911) through the full BMP
   pipeline: a crafted BMP session negotiates ADD-PATH (cap 69 in both
   OPENs), announces one prefix under two path ids, withdraws one, and goes
   down. Asserts on the bmp-out side that the synthesized Peer Up advertises
   cap 69 in both OPENs, both paths restream live with their path ids, the
   withdrawal carries its path id, a reconnect dump replays only the active
   path, `/api/v1/ingresses` shows the two `bgpPath` children, and Peer Down
   fires exactly once (driver: `scripts/e2e-addpath-bmp.py`). Runs two
   downstream consumers: one on a fastpath unit (verbatim raw forwarding —
   catches duplicate delivery if the raw-coverage check fails to map
   path-children to their session) and one on a rebuild unit
   (`fastpath = false`, bmp-out re-encodes the path ids itself).
 - `scripts/e2e-cli.sh` — `netom-cli` against a live daemon: a real BGP
   session is driven in by `scripts/e2e-cli-speaker.py` while a second peer
   is configured but unreachable. Asserts that the established peer is
   reported with its prefix count, that the peer which never came up appears
   as `Active` rather than being missing, that `show running-config` redacts
   a configured `md5_key`, and that abbreviation, output filters, `--json`
   (including NDJSON whole-table dumps), broken-pipe handling, batch stdin,
   endpoint discovery via `-c`, and the exit codes all behave. Set
   `NETOM_CLI_BIN` alongside `NETOM_BIN` to skip the build.

Both scripts build netom themselves (set `NETOM_BIN` to skip that), install
their tools (mrtgen, exabgp) into a scratch directory when missing, and clean
up after themselves. The corpus in each covers every component type — dst/src
prefix, protocol, ports, TCP flags, packet length, ICMP type/code, DSCP,
fragment, IPv6 flow label — rules without a destination prefix (keyed at the
family default route), all decodable traffic actions, and the RFC 8955 §6
validity states.

The `e2e-flowspec` GitHub workflow runs both scripts on demand
(workflow_dispatch).

## BMP reconciliation simulations

`python3 scripts/bmp-peer-churn.py` builds and runs isolated real daemons, then
acts as a BMP exporter over loopback TCP. No FRR, containers, external data, or
third-party Python packages are required. It exercises the automatic recovery
for [issue #11](https://github.com/FastNetMon/netom/issues/11).

```sh
python3 scripts/bmp-peer-churn.py --binary target/debug/netom
python3 scripts/bmp-peer-churn.py --binary target/debug/netom --cycles 20
```

The exporter keeps an independent list of actually established peers. After a
collector-initiated disconnect, it reconnects and replays only those peers and
their routes, including End-of-RIB. Retired identities are not replayed.

Seven scenarios run by default; select one with `--scenario NAME`:

- `matching`: correctly addressed Peer Down, ordinary cleanup control.
- `mismatched`: Peer Down with `::`, then a new link-local peer address.
- `missing`: a new peer address with no preceding Peer Down.
- `parallel`: legitimate parallel peers coexist in startup; adding another
  later causes one reconciliation, and all three survive the new snapshot
  beyond its startup window without another anomaly reset.
- `silent`: a peer vanishes without any further BMP message; periodic renewal
  removes it after the authoritative empty replay.
- `partial`: the same disappearance with a stalled, incomplete BMP frame.
- `limit`: startup churn reaches the peer-state cap; reconnect restores the
  sole actually established peer.

The script shortens reconciliation timings in the test configuration and GC
intervals in the test daemon's environment. It verifies current peer addresses,
retained peer entries and route records after GC, then checks complete cleanup
when the exporter closes. The table is constant-size during churn. A timeout,
missing metric, failed replay, unexpected parallel-session reset, or retained
state makes the script exit 1; success exits 0. These are object-count checks,
not RSS thresholds: allocator caching can retain pages after objects are freed.

Rust regressions are part of the normal suite:

```sh
cargo test --lib units::bmp_tcp_in
```

They cover deadline coalescing, startup replay, periodic jitter, capacity,
configuration validation, peer identity scopes, policy/ADD-PATH teardown,
idle/partial transport cancellation, and active-connector redial. Live network
tests require permission to bind loopback sockets.

See [automatic reconciliation](docs/bmp-tcp-in.md#automatic-reconciliation-and-stale-peer-retention)
for the RFC 7854 references, defaults, and monitoring-gap/replay caveat.

Validation on 2026-10-02 (implementation `0ec9bd6`, regressions `a816a12`):

- `cargo test --lib --offline`: 354 passed, 31 ignored, no failures.
- `cargo build --bin netom --offline`: passed (existing unused `set_rib` warning).
- `python3 scripts/bmp-peer-churn.py --binary target/debug/netom --cycles 20`:
  all seven scenarios passed. Each churn scenario ended with one peer and one
  record after GC; the parallel replay retained all three peers/records; silent
  and partial-frame recovery reclaimed all obsolete peers/records; capacity
  recovery restored the one current peer. Every final disconnect cleaned up.
- Changed Rust files passed rustfmt checks; the Python driver passed syntax
  compilation; `git diff --check` passed.
