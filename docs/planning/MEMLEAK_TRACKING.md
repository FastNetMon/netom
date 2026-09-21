# netom memory investigation — gcore.fastnetmon.com

Local-only tracking notes. Not part of the repository; see `TODO.md` for the
items that are.

**Status 2026-08-27 21:06 (26h after deploy):** the path-attribute interner
leak is found, fixed, deployed and **verified in steady state**. At the same
record count the process holds **46.1 GiB where it held 70.9 GiB** — 24.8 GiB
less for the same data — and growth has fallen from 2.3 GiB/day on a flat
table (~5.4 GiB/day sustained, §6c) to **0.98 GiB/day and decelerating**, all
of it attributable to data (§6b). That 0.98 is still an upper bound: it
contains a one-off reload tail and the unfixed ADD-PATH child accumulation at
~235k entries/day (open item 2).

---

## 1. The box

| | |
| --- | --- |
| host | `gcore.fastnetmon.com` (`netomics-gcore`), Ubuntu 24.04, 125 GB RAM |
| netom | `bmp-tcp-in` on `[::]:11019`, `rib`, `bmp-tcp-out` on `[::1]:61234`, API on `[::1]:8080` |
| feed | 112 BMP routers, ~8,580 monitored peers, ~348M records over ~1.55M prefixes (~225 records/prefix) |
| neighbour | `bgpviewd` (~22-34 GB) consumes netom's bmp-out; it reconnects on its own with backoff |
| config | `retain_withdrawn_attributes = false`, `deduplicate_path_attributes = true`, `ignore_post_policy_routes = true` |

No Prometheus/VictoriaMetrics on this host — the metric history used below is
netom's own `memstat:` log lines, every 5 minutes, read out of the journal.

## 2. What was observed (fnm10, PID 1051142, up since 2026-08-21)

RSS climbing steadily while the table was **not** growing:

| window (2026-08-26) | RSS | records (active) | interner buckets | live blobs |
| --- | --- | --- | --- | --- |
| 06:51–06:57 | 69.76 GiB | 341.29M | 147.45M | 51.53M |
| 18:31–18:37 | 70.89 GiB | 347.87M | 153.40M | 51.81M |

* RSS: **+1.13 GiB in 11.7h ≈ 2.3 GiB/day** (this window turned out to be a
  quiet one; the sustained rate across three full runs was ~5.4 GiB/day — §6c)
* interner buckets over 18.3h: 140.20M → 153.40M, **+13.2M**
* live blobs over the same 18.3h: 51.38M → 51.81M, **flat**
* dead slots: **101.6M, 66% of the table**

Everything else was small or stable: withdrawn tombstones 2.0% of records,
ingress register 1,351,778 entries (~0.6 GB), bmp-out buffers empty.

### Cost per bucket, measured rather than assumed

In the 06:57→15:17 window the record count was nearly flat (+0.28M ≈ 42 MB)
while buckets grew +4.51M and RSS grew +848 MB → **~180 bytes of RSS per
interner bucket** (hashbrown entry + a separate heap allocation for the
one-element `Vec`). That puts the dead slots at **~18 GB**, and 13M/day at
~2.3 GB/day — i.e. the interner accounted for essentially all of the growth.

## 3. Root cause

`PathAttributeInterner::intern` (`src/payload.rs`) prunes dead `Weak`s **only
in the bucket it is already touching**:

```rust
let entries = shard.entry(hash).or_default();   // this bucket only
...
None => { entries.swap_remove(idx); }           // prune, but only here
```

* a blob whose hash never recurs keeps its dead `Weak` for the life of the
  process — nothing revisits that bucket;
* the `HashMap` entry outlives even the `Weak`: `entry(hash).or_default()`
  creates buckets and nothing removes an emptied one;
* `HashMap` capacity never shrinks.

So cleanup is O(buckets you touch) while the garbage is O(buckets you stop
touching), and on a BGP collector those sets barely overlap — AS paths churn
and mostly never repeat. 344M withdrawals/re-announcements in five days.

Introduced in `2d84bf2` (2026-05-06, *rib: Deduplicate path attributes*). The
instrumentation that made it findable came three weeks later in `20df863`
(2026-05-31, *Add mem stats*), whose own comment predicted the failure mode:
*"A steadily growing gap between `weak_slots` and `live_blobs` would point at
dead `Weak`s piling up"*.

## 4. The fix — `7ad7c6e`, shipped in 0.6.0-fnm13

* `PathAttributeInterner::sweep_shard(index)` — drops dead `Weak`s, removes
  the buckets they emptied, and shrinks the shard's table.
* `pa-interner-sweep` task in the rib unit — one shard per 30s tick on the
  blocking pool, so a lock hold covers 1/64 of the table and a full pass takes
  ~32 minutes. Logs per pass, not per shard.
* Shrink threshold is **2x** capacity-to-length, not the 4x the store uses on
  record maps: clearing two thirds of a shard leaves capacity at ~3x length,
  which 4x never catches. Measured on a 3M-bucket interner with two thirds
  dead — 4x reclaimed **0 MB**, 2x reclaimed **66 MB**.

Most of what a sweep frees is small per-bucket allocations that glibc keeps in
its arenas, so RSS falls by less than the sweep drops. That is not the point:
in the same measurement, **2M further dead interns after a sweep cost 10 MB
where they would otherwise have cost ~340 MB**. Growth becomes a plateau.

## 5. Deployment

* 2026-08-26 19:11 UTC — `dpkg -i netom_0.6.0~fnm13-1_amd64.deb` (fnm10 → fnm13, 29 commits).
* 19:12:25 — service restarted **by the postinst** (`_dh_action=restart`), not by hand.
* Config validated beforehand by running the packaged binary against a copy of
  `/etc/netom/netom.conf` locally with the listen ports retargeted; there is no
  `--check` flag.
* Rollback: `/root/netom-fnm10.bak` (the old `/usr/bin/netom`). dpkg metadata
  would read fnm13 until a proper reinstall. No fnm10 `.deb` exists on the box.
* `bgpviewd` dropped its BMP state at the restart and reconnected on its own
  (`session lasted 47550s, reconnecting in 1s (backoff)` → `connected`).

## 6. Verification — 2026-08-27, ~11h of steady state

| | fnm10 (26th 18:36) | fnm13 (27th 06:02) |
| --- | --- | --- |
| RSS | 70.89 GiB | **45.50 GiB** |
| records (active) | 347.87M | 345.95M |
| interner weak slots | 153.40M | 52.44M |
| live blobs | 51.81M | 51.53M |
| **dead slots** | **101.6M (66%)** | **0.91M (1.7%)** |
| withdrawn tombstones | 7.09M (2.0%) | 1.85M (0.5%) |
| swap | 3.3 GB | 0 |

Sweep passes reclaim **1.4–1.8M slots each** (~2.8M/hour) and the dead gap
holds flat across passes instead of widening. The interner leak is closed.

### Still growing, ~2.5 GiB/day (22:02 → 06:02)

| | Δ/8h | Δ/day |
| --- | --- | --- |
| RSS | +0.82 GiB | +2.5 GiB |
| interner buckets | +0.5M | +1.5M (was 13M) |
| records | +1.95M | +5.9M |
| v6 prefixes | 316.1k → 368.2k | +156k |
| tree nodes | 721.3k → 1.15M (+60%) | +1.3M |
| **ADD-PATH children** | **+56.9k** | **+170k** |

Most of this is the table still converging after the restart: v6 prefixes
+16% and tree nodes +60% overnight, against 1.55M prefixes now vs 1.66M before
the restart. The exception is the last row — see item 2 below.

## 6b. 26h steady state — 2026-08-27 21:06

The reload has converged and the growth rate has dropped with it.

| window | RSS | rate |
| --- | --- | --- |
| fnm10, flat table | 69.76 → 70.89 GiB / 11.7h | **2.3 GiB/day** |
| fnm13, reload tail (22:02–06:02) | 44.68 → 45.50 GiB / 8h | 2.5 GiB/day |
| fnm13, steady state (06:02–20:02) | 45.50 → 46.07 GiB / 14h | **0.98 GiB/day** |

Per-2h increments over that last window: +0.17, +0.06, +0.06, +0.05, +0.08,
+0.10, +0.05 GiB — decelerating, not linear.

Interner at 20:02: buckets 53.33M, live 52.43M, **gap 0.90M (1.7%)** — the
same gap as 14h earlier (0.91M). Buckets grew +0.89M and live blobs +0.90M:
what is growing is genuine attribute diversity, not dead slots. The sweep is
holding the line exactly as intended.

The ~0.57 GiB of growth over those 14h is accounted for by real data:

| | Δ/14h | ~bytes |
| --- | --- | --- |
| records (348.26M active) | +2.3M | ~253 MB |
| interner live blobs | +0.90M | ~160 MB |
| ADD-PATH children | +137k | ~64 MB |
| | | **~480 MB of the observed 570 MB** |

**Verdict: the leak is fixed.** Growth is now attributable to data and
decelerating, at 46.07 GiB against 70.89 GiB for the same ~348M records.

### What the 0.98 GiB/day still contains

This is not yet the floor. Two things inflate it, and both are expected to
come out:

1. **The reload tail.** The process is one day old and the v6 half is still
   converging: v6 prefixes 316.1k → 368.2k overnight (+16%) and tree nodes
   721.3k → 1.15M (+60%), against 1.55M prefixes now vs 1.66M before the
   restart. This is a one-off cost of the restart, not a rate. It should
   disappear over the next day or two -- watch `unicast prefixes` v6 and
   `nodes` flatten.
2. **ADD-PATH child accumulation, unfixed.** 934,088 → 1,071,211 register
   entries in 14h, **~235k/day**, ~110 MB/day for the entries alone plus the
   records each child owns. Unlike the reload tail this does not stop: one
   permanent ingress per `(session, path_id)`, path ids that never repeat,
   and reaping only on session teardown. It passes the pre-upgrade 1.34M
   about a day from now and keeps going. See open item 2 -- it needs the
   `mui_new` store fix first.

So the honest reading of 0.98 GiB/day is: an upper bound on the steady-state
rate, with a one-off component that will fall away and an unbounded component
that will not until item 2 is fixed. Re-measure once v6 has flattened; if the
rate settles near the ~110 MB/day the child growth alone implies, the memory
behaviour is as good as this design gets without item 1 or 2.

The one term that keeps climbing on its own is ADD-PATH children:
934,088 → 1,071,211 in 14h, **~235k/day**, which passes the pre-upgrade 1.34M
in about a day. See open item 2.

## 6c. The old build's real rate — three previous runs

The 2.3 GiB/day in §2 was one quiet 11.7h window. The journal goes back to
2026-07-31 and holds three complete runs of the leaking build, all with the
same signature: climb until someone restarts it.

| PID | ran | start → end | peak |
| --- | --- | --- | --- |
| 923789 | Jul 31 → Aug 14 (13.6d) | 6.50 → 88.30 GiB | 88.30 |
| 1001435 | Aug 14 → Aug 21 (7.8d) | 6.76 → 89.27 GiB | 89.27 |
| 1051142 | Aug 21 → Aug 26 (4.9d) | 7.10 → 70.94 GiB | **76.38** (26th 06:16) |
| 1079786 (fnm13) | Aug 26 → | 7.37 → 46.10 GiB (1.1d) | 47.33 |

PID 1001435 sampled at 21:06 each day: 51.73, 55.56, 63.37, 67.80, 72.97,
77.91, 83.57, 89.27 → daily deltas +3.83, +7.81, +4.43, +5.17, +4.94, +5.66,
+5.70, i.e. **~5.4 GiB/day sustained**.

So the comparison is:

| | rate |
| --- | --- |
| old build, sustained | **~5.4 GiB/day** |
| old build, quiet window on a flat table | 2.3 GiB/day |
| fnm13, first full day | +1.6 GiB |
| fnm13, last 14h | **0.98 GiB/day** |

**3.4-5.5x slower.** Note also that 1051142's 70.9 GiB was not its peak: it
touched 76.38 GiB that morning and fell back before the measurements in §2
were taken. The ~88-89 GiB ceiling that forced a restart every 5-14 days is
now roughly six weeks out at the current rate, and further once item 2 lands.

## 6d. ADD-PATH child accumulation — located and reproduced (2026-09-01)

### Where it is

* **Minted:** `get_or_create_path_child` — `units/bgp_tcp_in/router_handler.rs:940`
  and `units/bmp_tcp_in/state_machine/machine.rs:2060`. First sight of a
  `(session, path_id)` registers a child with `state = Connected` and caches
  it in a per-peer `path_children: HashMap<PathId, IngressId>`
  (`router_handler.rs:130`, `machine.rs:207`).
* **Reclaimed:** only via `Rib::gc_disconnected_bmp_peers`
  (`units/rib_unit/rib.rs:1736`), which skips anything whose state is not
  `Disconnected`. Children are set `Disconnected` only when their *session*
  goes down — peer-down folds `peer.path_children.values()` into the
  withdrawal set (`machine.rs:764`, `machine.rs:1811`) and the session
  teardown clears the map (`router_handler.rs:536`).
* **Therefore:** withdrawing a path does not retire its child. On a session
  that stays up for weeks, every path id ever used keeps its register entry,
  its `path_children` map slot, and (see below) a store record — forever.

### Reproduced locally

`scripts/addpath-churn.sh` drives one prefix under fresh path ids, announce
then withdraw, against a local netom. 2000 pairs on 0.6.0-fnm13:

```
before:   entries=3     children=1     prefixes=1 records=1
after:    entries=2003  children=2001  prefixes=1 records=2001
growth:   +2000 children for 2000 withdrawn paths (100% of churn)
```

**100% of the churn is retained** while the RIB holds one prefix throughout.

The record count is the part that was not previously quantified: each
retired path also leaves a **withdrawn record under its own mui** —
2001 records for one prefix. So a dead path costs a register entry (~467 B),
a `path_children` slot, *and* a store record, not just the register entry.
That matches gcore's 8.12M withdrawn records (2.1%) against 1.4M children.

The script is the regression test for the fix; it exits non-zero today by
design. `TOLERANCE` (default 0.05) sets how much growth still counts as
bounded.

## 7. Where the 45.5 GiB sits

| | estimate | basis |
| --- | --- | --- |
| store records | ~38 GB | 348M records at ~110 B |
| interner (buckets + live blobs) | ~5-9 GB | 52.5M buckets at ~180 B |
| tree nodes + prefixes | ~1 GB | 1.15M nodes, 1.55M prefixes |
| ingress register | ~0.44 GB | 934k entries at ~467 B |
| withdrawn tombstones | negligible | 1.86M, 0.5% |

**225 records per prefix** is what sets the total: ~8,580 peers each holding a
large slice of the table. That is data, not overhead.

## 8. Open items, by size

1. **Per-record footprint (~38 GB).** The only lever that moves the total.
   Shaving 20 B/record is ~7 GB. Store-side (`netom-store`).
2. **ADD-PATH child reaping (~0.44 GB, +170k entries/day, unbounded).** One
   permanent ingress per `(session, path_id)`; the routers here allocate path
   ids monotonically and never reuse them (top peer: 110,914 children spanning
   path ids 270,561,816..417,327,431 — density 0.001), and children are only
   reclaimed when their session goes down. At 170k/day this passes the old
   1.34M in ~2.5 days. Blocked on the `mui_new` store bug (`TODO.md` §3a):
   netom cannot currently tell when a child's last record leaves the RIB.
3. **Interner bucket layout.** `Vec<Weak<[u8]>>` costs a separate allocation
   per bucket for what is almost always a single entry (buckets ≈ weak slots,
   so collisions are rare). `SmallVec<[Weak<[u8]>; 1]>` removes ~52M
   allocations — ~1.7 GB plus less fragmentation.

## 9. Next checks

* **Does RSS flatten once v6 converges?** Watch `unicast prefixes` v6 and
  `nodes`. If RSS is still +2.5 GiB/day after those flatten, item 2 is next.
* **Does the interner gap stay bounded under a full day of churn?**
  `weak_slots - live_blobs` should oscillate around one sweep pass's worth
  (~1.5M), never trend.
* **Child count trajectory.** If `BgpPath` passes ~1.34M and keeps climbing,
  item 2 has become the dominant growth term.

### Commands

```sh
# full memstat cycle
ssh netomics-gcore 'sudo journalctl -u netom --no-pager -o cat -n 200 | grep "^memstat:" | tail -11'

# interner drift, every ~2h
ssh netomics-gcore 'sudo journalctl -u netom --since "-24h" --no-pager -o short-iso \
  | grep "memstat: pa-interner" | awk "NR%24==1"'

# sweep reclaim per pass
ssh netomics-gcore 'sudo journalctl -u netom --since "-24h" --no-pager -o cat \
  | grep "pa-interner sweep"'

# live counters
ssh netomics-gcore 'curl -s "http://[::1]:8080/metrics" \
  | grep -E "^netom_(ingress_register|rib_unit_num_(items|unique_prefixes))"'

# ingress register shape (streams 240MB+, counts on the box)
ssh netomics-gcore 'curl -s "http://[::1]:8080/api/v1/ingresses" \
  | grep -o "\"ingress_type\":\"[a-zA-Z]*\"" | sort | uniq -c'
```
