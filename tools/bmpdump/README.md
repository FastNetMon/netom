# netom-bmpdump

Standalone offline BMP/BGP/EVPN decoder, distributed as an additional Netom
tool. It does not link to the Netom daemon or require a running collector.

From the repository root:

```sh
cargo build --locked --release -p netom-bmpdump
./target/release/netom-bmpdump -r capture.pcapng --evpn -v
cargo test --locked -p netom-bmpdump
```

See [the user guide](../../docs/bmpdump.md) for formats, filters, JSON,
terminal colors, and decoding limits.
