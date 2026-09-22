# Quickstart

This example runs a BMP collector with an in-memory RIB and an HTTP interface
on localhost. You will need a router or exporter that sends BMP data to it.

## Install Netom

The [release workflow](releases.md) builds DEB and RPM packages for amd64 and
arm64, plus versioned container images. Published assets appear on the
[GitHub releases page](https://github.com/FastNetMon/netom/releases). If no
release is available yet, build from source:

```sh
git clone https://github.com/FastNetMon/netom.git
cd netom
cargo build --locked --release --bin netom --bin netom-cli
```

Use the Rust toolchain pinned in
[`pkg/targets.toml`](https://github.com/FastNetMon/netom/blob/main/pkg/targets.toml).
For distribution dependencies and container-based package builds,
see [local builds](releases.md#local-builds). The commands below use binaries
on `PATH`; after a source build, use `./target/release/netom` and
`./target/release/netom-cli` instead.

## Create a configuration

Save the following as `netom.conf`:

```toml
log_level = "info"
log_target = "stderr"
http_listen = ["127.0.0.1:8080"]

[units.bmp-in]
type = "bmp-tcp-in"
listen = "0.0.0.0:11019"

[units.rib]
type = "rib"
sources = ["bmp-in"]

[targets.null]
type = "null-out"
sources = ["rib"]
```

BMP listens on TCP port 11019. Restrict access to the routers and exporters
that should connect. The HTTP API is unauthenticated and unencrypted, so this
example binds it to loopback. See [CLI security](cli.md#security) before
making it accessible from another host.

## Start and inspect the collector

```sh
netom --config netom.conf
```

Configure your BMP exporter to connect to the collector's address on port
11019. In another terminal, inspect the running instance:

```sh
netom-cli --url http://127.0.0.1:8080 show ip bgp summary
curl http://127.0.0.1:8080/metrics
```

An empty routing table is expected until an exporter connects and sends
routes. The RIB is held in memory; restarting Netom requires routes to be
learned again. Press Ctrl-C to stop this foreground instance.

## Run an installed package as a service

DEB and RPM packages include a systemd unit and an example configuration.
Create `/etc/netom/netom.conf` from the configuration above, or copy
`/etc/netom/netom.conf.example` and review its listeners before starting.
Once the configuration is in place:

```sh
sudo systemctl enable --now netom
sudo journalctl -u netom -f
```

The service runs as the `netom` account. Ensure any files referenced by the
configuration are readable by that account.

## Next steps

- [Connect pipeline components](configuration.md).
- [Pull BMP feeds with active TCP or TLS connections](bmp-tcp-in.md).
- [Inspect and filter routes with the CLI](cli.md).
- [Query and export routes through HTTP](rib-query-api.md).
- [Restream BMP to downstream consumers](bmp-tcp-out.md).
