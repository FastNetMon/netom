# Offline BMP capture decoder

`netom-bmpdump` decodes BMP, BGP, and EVPN messages from PCAP and PCAPNG
captures. Use it to inspect traffic sent to or from a Netom BMP collector.
It does not require a running Netom daemon, Python, TShark, libpcap, or root
privileges.

## Installation

The tool is shipped alongside `netom` and `netom-cli` in the Netom DEB/RPM
packages and runtime images. To build just the decoder from source:

```sh
cargo build --locked --release -p netom-bmpdump
./target/release/netom-bmpdump --version
```

It is a separate workspace package and does not link to the daemon library.
It inherits the Netom release version and minimum Rust version. Its source
uses Rust edition 2024, which the project's Rust 1.88 minimum supports.

To install only this executable with Cargo:

```sh
cargo install --path tools/bmpdump --locked
```

## Reading a capture

```sh
# First 20 BMP messages.
netom-bmpdump -r capture.pcapng -c 20

# Every EVPN route with readable attributes.
netom-bmpdump -r capture.pcapng --evpn -v

# EVPN IP-prefix routes.
netom-bmpdump -r capture.pcapng --route-type 5 -v

# Filter exporter, monitored BGP peer, or message type.
netom-bmpdump -r capture.pcapng --router 192.0.2.10
netom-bmpdump -r capture.pcapng --peer 192.0.2.20 --type route-monitoring

# Newline-delimited JSON or aggregate counts.
netom-bmpdump -r capture.pcapng --json > messages.jsonl
netom-bmpdump -r capture.pcapng --summary
netom-bmpdump -r capture.pcapng --summary --json

# Custom BMP ports; repeat -p to select more than one.
netom-bmpdump -r capture.pcap -p 5000 -p 5001

# Read a capture from stdin.
cat capture.pcapng | netom-bmpdump -r -
```

Default BMP ports are **11019 and 1790**. Specifying `-p` replaces these
defaults. Addresses are always numeric; `-n` is accepted for familiarity.

Each output record is one BMP message, not one TCP packet. The decoder
reassembles split messages and separates coalesced messages. `-c` counts
messages after filtering. Filters select complete messages, including any
other routes in the same matching message.

Frame references include a message ordinal: `Frame 20.3` (or `#20.3` in
compact output) means the third BMP message completed in capture frame 20.
The ordinal starts at one in each frame and is assigned before filtering,
so references remain consistent across filters. JSON exposes the components
as `frame` and `frame_message`.

Times are UTC. Verbose output labels the full date and time as `Capture time`;
compact output shows the time of day. The frame number and capture timestamp
identify the packet that completed reassembly; the BMP peer timestamp remains
available separately in JSON. Untimestamped PCAPNG Simple Packet Blocks display
`unknown-time`.

## Readable output and colors

`-v` prints aligned message blocks, individual communities, and a block for
each announcement or withdrawal. `-vv` also prints the full decoded JSON.

ANSI colors are automatic on recognized color terminals: cyan headings and
labels, green announcements, red withdrawals/errors, and yellow warnings.
Pipes, redirects, `TERM=dumb`, an unset `TERM`, and `NO_COLOR` disable
automatic coloring.

```sh
netom-bmpdump -r capture.pcapng -v --color never
netom-bmpdump -r capture.pcapng -v --color always | less -R
```

`--color always` overrides detection and `NO_COLOR`. JSON on stdout is always
plain. Diagnostics go to stderr.

## Supported decoding

- PCAP in either byte order, with microsecond or nanosecond timestamps.
- PCAPNG sections and interfaces, Enhanced/Simple/obsolete Packet Blocks,
  decimal/binary timestamp resolution, and timestamp offsets.
- Ethernet and VLANs, Linux cooked v1/v2, raw IP, BSD loopback, IPv4/IPv6 TCP,
  and IPv6 extension headers.
- TCP reassembly, out-of-order segments after the initial sequence is
  established, retransmissions, overlaps, and sequence wraparound.
- BMP v3 Initiation, Peer Up/Down, Route Monitoring, Statistics,
  Termination, and Route Mirroring; Loc-RIB and pre/post-policy metadata.
- BGP OPEN capabilities, UPDATE, NOTIFICATION, KEEPALIVE, ROUTE-REFRESH,
  IPv4/IPv6 unicast/multicast NLRI, MP_REACH/MP_UNREACH, and End-of-RIB.
- Common attributes including AS_PATH/AS4_PATH, next hop, MED, local
  preference, communities, extended/large communities, and PMSI tunnels.
- EVPN route types 1–5, including RD, ESI, MAC/IP, prefix, next hop, label,
  and explicitly signaled overlay VNI fields.
- ADD-PATH inferred from Peer Up capabilities. `--add-path` forces it for
  all supported families when negotiation is missing; use it only when
  those families are known to use ADD-PATH.

Unknown message types, attributes, capabilities, route types, and address
families retain raw hexadecimal data in JSON.

## Errors and limits

Exit codes are **0** for clean completion, **2** for read/decode errors or
diagnostics, and **130** for interruption. A capture may produce useful
output and still return 2. `-c` intentionally stops early without diagnosing
the unread capture tail.

Malformed nested OPENs are retained with errors, and decoding continues at
the next BMP boundary. Other malformed bodies appear as raw error records.
An invalid established-stream BMP header or an exceeded buffer limit stops
decoding.

IP fragment reassembly, encrypted transport, IPv6 jumbograms, and extended
BGP OPEN optional-parameter encoding are not implemented. Checksums are
not validated. Missing TCP bytes are reported; gaps are not filled with
invented data. Midstream capture recovery searches for a plausible BMP v3
boundary and reports discarded bytes.

Consumed retransmissions are ignored. Overlapping data follows the bytes
first delivered by the reassembler, which may differ from an endpoint's
overlap policy. Conflicting queued retransmissions with the same starting
sequence fail. Interfaces are tracked separately and can contain duplicate
observations of one connection.

Limits are 64 MiB per capture block, 4 MiB per BMP message, 8 MiB buffered per
TCP direction, 64 MiB buffered globally, 256 tracked TCP directions, and
4096 peer capability records per direction.

EVPN withdrawals can omit encapsulation communities. Without an explicit
overlay indication, output retains `label_raw` and its MPLS interpretation,
and does not assume a VNI.

For decoder tests, see
[Testing](https://github.com/FastNetMon/netom/blob/main/TESTING.md#offline-bmp-decoder).
