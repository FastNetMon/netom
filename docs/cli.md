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
`show ip bgp summary`. A trailing `?` lists what may follow; in interactive
mode TAB completes.

```
netom> show ip bgp ?
  summary       Summary of BGP neighbor status
  neighbors     Detailed neighbor information
  flowspec      FlowSpec rules
  <A.B.C.D/M>   Network in the BGP routing table
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
terminates itself the prefix count is maintained as routes arrive. For a
session observed through a BMP feed, getting the same number would mean
scanning the whole RIB once per peer — far too expensive for a command
people run repeatedly. A dash means "not counted", not "zero".

**The hold time is the configured one.** `show ip bgp neighbors` reports the
hold time netom was configured with. The negotiated value —
`min(peer's, ours)` — is computed inside the BGP library and kept private.

**`Src` distinguishes the two kinds of peer.** `bgp` is a session this netom
terminates; `bmp` is one it observes through a monitored router. Narrow to
one with `show ip bgp summary bgp` or `... bmp`.

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
* `docs/addpath-flowspec-api.md` for the JSON shapes behind these commands.
