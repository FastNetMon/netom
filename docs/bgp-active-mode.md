# BGP Active Mode

By default the `bgp-tcp-in` unit is passive: it binds a listener and waits for
peers to connect to it. Some peers will not do that — they expect to be
connected to, or their operator refuses to configure netom as a passive
neighbour. Active mode makes netom initiate the TCP connection instead.

Only the socket is affected. Above it, nothing changes: for an exactly
configured peer, netom's FSM already sends the OPEN as soon as the connection
is up (RFC 4271 section 8.2.2, `Active` + `TcpConnectionConfirmed` with
DelayOpen disabled), so the same session machinery runs in either direction.

## Configuration

Set `connect = true` on a peer:

```toml
[units.bgp-in.peers."10.1.0.3"]
name = "PeerC"
remote_asn = 64513
connect = true
```

| Key | Default | Meaning |
| --- | --- | --- |
| `connect` | `false` | Actively connect to this peer. |
| `remote_port` | `179` | Port to connect to. |
| `source_addr` | unset | Local address to bind the connection to, e.g. a loopback the peer expects to see. Must be of the same address family as the peer. |
| `connect_retry_secs` | `30` | Interval between connection attempts. Each wait is jittered by up to a quarter of this value. |

`md5_key` works in active mode too. The key is installed on the socket before
`connect()`, because the SYN itself already carries the TCP MD5 option
(RFC 2385). This is Linux-only, as it is for inbound connections.

## Behaviour

- **The peer must be keyed on an exact IP address.** A peer keyed on a prefix
  has no single address to dial; `connect = true` on such an entry is ignored
  with a warning.
- **The listener stays active for these peers.** Active mode adds a way in, it
  does not remove one — whichever side connects first wins.
- **One connection at a time.** netom does not dial a peer that already has a
  live session, whether that session was set up by us or by the peer.
- **Retry.** After a failed attempt, or after a session ends, netom waits
  `connect_retry_secs` (plus jitter) and tries again. A connection attempt that
  gets no response is abandoned after 10 seconds rather than waiting out the
  kernel's SYN retry budget.
- **Reconfiguration.** Adding, removing, or changing an active peer takes
  effect within a few seconds without restarting the unit. Changed connect
  parameters apply to the next connection attempt; they do not tear down an
  established session.

If both ends dial each other at the same moment, both connections can reach
OPEN. The existing collision resolution in the session handler — keyed on the
negotiated peer address and ASN — then tears one of them down, and the jittered
retry keeps the two ends from repeating the race in lockstep.

## Metrics

| Metric | Meaning |
| --- | --- |
| `bgp_tcp_in_connection_initiated_count` | Connections we established to a peer. |
| `bgp_tcp_in_connect_error_count` | Failed connection attempts. |

The existing `bgp_tcp_in_connection_accepted_count` still counts only inbound
connections, so the two directions can be told apart.
