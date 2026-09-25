# netom-cli

`netom-cli` inspects a running netom daemon with router-style commands over
its HTTP API. It is read-only: every command is a GET, and nothing it can do
changes the daemon's state or configuration.

```
$ netom-cli show ip bgp summary

Neighbor        V     AS Src  UpdRcvd NotifRcvd   Up/Down State/PfxRcd
10.1.0.1        4  65001 bgp    13980         1  02:14:33       84,211
10.1.0.3        4  65003 bgp        0         0     never       Active
192.0.2.7       4  65100 bmp        -         -  01:02:11            -

Total neighbors 3 (bgp 2, bmp 1)
```

## Running it

Three ways, plus a prompt:

```sh
netom-cli show ip bgp summary          # one-shot
netom-cli -e 'show version' -e 'show status'   # repeatable
printf 'show version\nshow status\n' | netom-cli   # batch
netom-cli                              # interactive: netom> prompt
```

Keywords abbreviate to any unambiguous prefix, so `sh ip b sum` is
`show ip bgp summary`. A trailing `?` lists what may follow — always as a
list, even when only one keyword matches — and ends with `<cr>` when the
line is already a command you can run. In interactive mode TAB completes
instead, and `?` works at any point in the line without disturbing it.

```
netom> show ip bgp ?
  summary      Summary of BGP neighbor status
  neighbors    Detailed neighbor information
  flowspec     FlowSpec rules
  <A.B.C.D/M>  Network in the BGP routing table
  source       Only routes learned over one kind of ingress
  ingress      Only routes stored under one ingress id
  origin-as    Only routes originated by one AS
  community    Only routes carrying one community
  <cr>
```

`help` prints the whole command tree at once, which is the place to start
if you do not yet know what to press `?` after:

```
netom> help
Commands:

  show ip bgp                               BGP information
  show ip bgp summary                       Summary of BGP neighbor status
  ...
  show running-config                       Current operating configuration
  show filters                              Roto filter script and entrypoints
  help                                      List every command
  exit                                      Exit the CLI
```

## Finding the daemon

In order: `--url`, `$NETOM_URL`, `-c <config>`, `./netom.conf`,
`/etc/netom/netom.conf`, then `http://127.0.0.1:8080`.

netom ships `http_listen = ["[::]:8080"]`, which is a wildcard and not
something you can connect to. `netom-cli` rewrites wildcards to loopback
(`::` → `::1` then `127.0.0.1`; `0.0.0.0` → `127.0.0.1`), so discovery never
sends a query off-box on its own initiative. When a connection fails it says
which addresses it tried and where they came from:

```
% Unable to connect to netom at [::1]:8080, 127.0.0.1:8080: Connection refused
%   (from /etc/netom/netom.conf: http_listen)
```

## Scripting

`--json` emits the daemon's response bytes unchanged, so scripts see the API
contract rather than a rendering of it:

```sh
netom-cli --json show ip bgp summary | jq '.data[] | select(.state != "Established")'
```

Whole-table route dumps are newline-delimited JSON — one object per line,
not a JSON array — which is what the API emits and what `jq -c` and `wc -l`
want:

```sh
netom-cli --json show ip bgp | wc -l
```

Exit codes: `0` success, `1` the command did not parse, `2` the daemon was
unreachable or the response was truncated, `3` the daemon returned an error.

Output filters take Cisco's form and match case-insensitive substrings
(not regular expressions):

```sh
netom-cli show ip bgp summary '| exclude Established'
netom-cli show ingresses '| count'
```

## What the numbers mean

netom is a *collector*, not a router, so some familiar columns cannot
honestly be filled in. Rather than print plausible zeros, `netom-cli` names
the counters for what they are and leaves the rest blank.

**`UpdRcvd` / `NotifRcvd`, not `MsgRcvd` / `MsgSent`.** netom counts the
UPDATE and NOTIFICATION messages it receives. It never originates UPDATEs,
and KEEPALIVEs are handled inside the BGP state machine without ever
surfacing, so a total-message counter would be a guess and a sent-message
counter would always read zero.

**`State/PfxRcd` shows `-` for BMP-observed peers.** For a session netom
terminates itself the prefix count is maintained as routes enter and leave
the RIB. For a session observed through a BMP feed, getting the same number
would mean scanning the whole RIB once per peer — far too expensive for a
command people run repeatedly. A dash means "not counted", not "zero".

**`PfxRcd` is the current table size, not a running total.** It counts the
prefixes the peer currently has in the RIB, so re-advertisements do not
inflate it: a peer that keeps re-announcing the same prefix with a new AS
path is performing BGP's implicit withdraw, and the count stays put. If you
want the churn instead, it is the `dupPrefixAdvertisements` counter on
`/bgp/neighbors` and in the peer's BMP Statistics Report.

**The hold time is the configured one.** `show ip bgp neighbors` reports the
hold time netom was configured with. The negotiated value —
`min(peer's, ours)` — is computed inside the BGP library and kept private.

**`Src` distinguishes the two kinds of peer.** `bgp` is a session this netom
terminates; `bmp` is one it observes through a monitored router. Narrow to
one with `show ip bgp summary bgp` or `... bmp`.

## Narrowing a route query

`show ip bgp` dumps the whole table. Each of these narrows it, and works the
same under `show ipv6 bgp`:

```
netom> show ip bgp source bmp                 routes learned through BMP
netom> show ip bgp source bgp                 sessions netom terminates itself
netom> show ip bgp source mrt                 peers replayed from MRT files
netom> show ip bgp neighbors 10.1.0.1 routes  what one neighbor sent
netom> show ip bgp ingress 5                  one exact ingress id
netom> show ip bgp origin-as 65001            originated by one AS
netom> show ip bgp community 65000:100        carrying one community
```

Two of these need a word about ADD-PATH, where each `(peer, path_id)` gets
its own ingress id. `ingress 5` is one exact id, so for such a peer it is one
*path*, not the peer — while `source` and `neighbors … routes` resolve those
children back to their session, and so return every path the peer sent. The
ids come from `show ingresses`.

`source bmp` covers every peer under a monitored router, not the router's
own ingress, which holds no routes of its own.

Only one filter applies per command — the grammar is a path, not a set of
flags — so stack `| include` on top when you need a second condition:

```sh
netom-cli show ip bgp source bmp '| include 10.0.'
```

FlowSpec takes `source` and `ingress` (`show ip bgp flowspec source bmp`) but
not the others; the API implements only those two for FlowSpec, so the rest
are not typeable there rather than failing at the daemon.

A filter narrows the output, not the work: the daemon still walks the whole
table to answer, so a narrowed dump is no faster than a full one.

## Route detail

The route table shows one line per path: network, next hop, the peer it came
from, and the AS path. Add `detail` for every attribute of each path:

```
netom> show ipv6 bgp 2001:db8::/32 detail
BGP routing table entry for 2001:db8::/32, 1 path(s)

  Peer: 192.0.2.7 (AS65100)
  Learned via: ingress 3, bgpViaBmp, pre-policy
  Status: active
  RPKI: rov notChecked
  Origin: IGP
  AS path: 65100 65010
  MED: 50
  Local preference: 200
  Communities: 65000:100 NO_EXPORT
  Large communities: 65001:1:2
  Next hop: 2001:db8::1
  Link-local next hop: fe80::1
```

It works on every route query:

```
netom> show ip bgp detail                          the whole table
netom> show ip bgp detail 10.0.0.0/24              one prefix
netom> show ip bgp 10.0.0.0/24 detail              the same
netom> show ip bgp detail source bmp               with one filter
netom> show ip bgp neighbors 10.1.0.1 routes detail
```

`Learned via` names the session's ingress id (as `show ingresses` lists it,
even for an ADD-PATH path), its kind, and for BMP whether the copy is
pre- or post-policy. An attribute the CLI has no name for is printed as
`name: value` rather than dropped. `--json` returns the same data unchanged.

## Best path

Which of the routes for a prefix wins the RFC 4271 decision process, and why
the others lost:

```
netom> show ip bgp 10.0.0.0/24 best     the decision for one prefix
netom> show ip bgp best 10.0.0.7        the route that would forward an address
```

The second is a longest-prefix match, so the prefix in the answer is normally
not the address that was typed — the header says which one answered:

```
netom> show ip bgp best 10.0.1.7
BGP routing table entry for 10.0.1.0/24 (best path for 10.0.1.7)
    Network              Next Hop             Path        Peer   Decided by
>   10.0.1.0/24          192.0.2.9            65001       3      asPathLength
    10.0.1.0/24          192.0.2.1            65001 65002 2      asPathLength
```

`>` marks the winner, as it does on a router. `Decided by` is the step of the
decision process that put each row where it is: on the winner, the step that
separated it from the runner-up; on the others, the step at which they lost to
the winner. `Peer` is the owning session, so an ADD-PATH peer's paths are
attributed to the peer rather than to the internal path-child id.

`=` marks a path tied with the winner through step e — equally good on every
criterion the RFC treats as a preference, and separated only by the BGP
Identifier or the peer address. Those are tie-breakers, not preferences, so a
line below the table says when the winner was picked by one rather than earned
it:

```
netom> show ip bgp 10.0.0.0/24 best
BGP routing table entry for 10.0.0.0/24
    Network              Next Hop             Path    Peer   Decided by
>   10.0.0.0/24          192.0.2.2            65001   2      bgpIdentifier
=   10.0.0.0/24          192.0.2.1            65001   1      bgpIdentifier
  2 paths are equal-cost (=); the winner was picked by bgpIdentifier, not
  preferred over them
```

Routes that could not be weighed at all are listed separately with the reason,
rather than silently omitted:

```
  excluded from the decision process:
    peer 9 - missingAsPath
```

A `note:` line appears when a tiebreaker had to be assumed — an MRT-replayed
peer has neither a local ASN nor a BGP Identifier, so step d and step f fall
back. `docs/rib-query-api.md` lists every step, reason and assumption.

`source`, `ingress`, `origin-as` and `community` work here too, narrowing the
*candidates*: `show ip bgp 10.0.0.0/24 best source bgp` asks what the best path
would be if only BGP-learned routes existed. `neighbors <ip> routes` is not
among them — narrowing to a single peer leaves nothing to decide.

## Peers that are down

A peer that has never established has no session and no routes, so before
this existed it appeared nowhere at all — the one case where you most want a
row. Configured peers are now always listed, with the RFC 4271 state saying
why:

```
netom> show ip bgp summary
Neighbor        V     AS Src  UpdRcvd NotifRcvd   Up/Down State/PfxRcd
10.1.0.3        4  65003 bgp        0         0     never       Active

netom> show ip bgp neighbors 10.1.0.3
BGP neighbor is 10.1.0.3, remote AS 65003
  Description: PeerC
  BGP state = Active
  Learned via: direct BGP session
  Configured: yes (active mode; we initiate the connection)
  Last error: Connection refused (os error 111)
```

`Active` means netom is retrying the transport connection; `Idle` means it
is waiting for a peer that has not connected. Only exactly-configured peers
can be listed this way — a peer matched by a prefix has no single address to
show until it connects.

## Paging

There is no built-in pager, and piping a whole-table dump into one is a bad
idea: the daemon aborts a dump whose reader stops draining, so a pager
sitting on the first screen will truncate it. When that happens `netom-cli`
says so and exits non-zero rather than presenting a partial table as a whole
one:

```
% Output truncated: the daemon closed the connection before the dump was
  complete. It aborts dumps whose reader stalls, so avoid paging this
  command.
```

`| include` and friends are streamed line by line and are safe on any size
of output.

## Security

netom's HTTP API is unauthenticated and unencrypted. Pointing `--url` at a
non-loopback host sends queries, and receives configuration and routing
data, in the clear.

`show running-config` redacts secrets — BGP TCP-MD5 keys and MQTT passwords
— but still exposes topology: peer addresses, ASNs and listen ports. Treat
access to the API port as equivalent to read access to the config.

## See also

* `netom-cli(1)` for the full option and command reference.
* [The RIB query API](rib-query-api.md) for the HTTP endpoints, filters and JSON shapes
  behind these commands.
* [ADD-PATH and FlowSpec](addpath-flowspec-api.md) for what these add on top.
