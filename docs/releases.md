# Releases

Netom releases DEB and RPM packages plus a multi-architecture container at
`ghcr.io/fastnetmon/netom:<version>`. All outputs contain `netom` and `netom-cli`.

| Format | Supported distributions | Architectures | Build baseline |
| --- | --- | --- | --- |
| DEB | Ubuntu 22.04, 24.04, 26.04; Debian 13 | amd64, arm64 | Ubuntu 22.04 |
| RPM | AlmaLinux 8, 9, 10 | x86_64, aarch64 | AlmaLinux 8 |
| Docker | Debian 13 slim runtime | linux/amd64, linux/arm64 | Installs the tested DEB |

Ubuntu coverage includes LTS releases in standard support. AlmaLinux coverage
includes supported major releases, including security maintenance: 8 through
2029, 9 through 2032, and 10 through 2035. See the
[AlmaLinux lifecycle](https://wiki.almalinux.org/release-notes/).

## Build once, test across distributions

`pkg/targets.toml` is the platform inventory and pins the release Rust and
cargo-deb versions. `pkg/release-metadata.py` generates the workflow matrices.
There are four native Rust builds: two package families, each on amd64 and
arm64 GitHub runners. There is no emulation or cross compiler.

ARM64 builds configure jemalloc and ELF segment alignment for 64 KiB pages so
the release is not tied to a runner's 4 KiB kernel. Containers share the runner's
kernel; the matrix does not independently exercise 16/64 KiB ARM kernels.

Builds use the oldest supported distribution in each family and `Cargo.lock`.
The resulting package is then installed, reinstalled, and removed in every
supported distribution on its native architecture. Tests check binary versions,
architecture, required files, account creation, and preservation of configuration
edits and the account ID during reinstall. Systemd lifecycle code is packaged,
but service management under a running systemd is not covered by container tests.

Each family produces one package per architecture, shared across its supported
releases. This avoids recompiling the same application for each distribution.
The compatibility assumption is checked by the full installation matrix; a new
runtime dependency that breaks an older target must be resolved before publishing.

Docker images install those same DEBs and add CA certificates and Tini. They run
as the `netom` account. Native tests verify both binaries, the non-root user,
and successful HTTP startup with the default configuration. The exact tested
images are saved as artifacts and later pushed without rebuilding.

Builds use FastNetMon Git forks, crates.io, official distribution repositories,
Rust tooling, and GitHub/Docker Actions. CI and release preparation run
`pkg/check-build-sources.py` to reject upstream build endpoints/actions and Git
sources outside FastNetMon. There is no dependency on NLnet Labs infrastructure
or Ploutos. Copyright and author attribution remain intact.

## Workflows

- **Build release artifacts** (`pkg-build.yml`): manual or reusable, builds and
  tests all packages and Docker images without publishing. Manual inputs can
  select a package family or omit images. RPM-only builds omit Docker images.
- **Build DEB packages** (`pkg-deb.yml`): a small compatibility entry point for
  DEB-only builds, including both architectures and all four distributions.
- **Release packages and containers** (`pkg-release.yml`): pushing `v<version>`
  validates the tag against `Cargo.toml`, then runs the full build/test workflow.
  Only after every test succeeds do jobs receive publishing permissions.
- **Build and Upload DEBs to S3** (`pkg-s3.yml`): manual, uses the DEB-only workflow
  and uploads both architectures into every APT suite in `pkg/targets.toml`.

The release workflow publishes a single versioned GHCR manifest referencing
both tested image digests. It also creates a draft GitHub release with all four
packages, the container manifest, SHA-256 checksums, and generated release notes.
Review and publish the draft in GitHub. A rerun can update an existing draft,
but refuses to replace the assets or versioned image of a published release.
There is no automatic `latest` alias: versions such as `0.6.0` are explicit.
Temporary `build-<run>-<attempt>-<architecture>` tags retain the individual images.

GHCR uses the repository's `GITHUB_TOKEN` with `packages: write`; no separate
registry credential is required. On first publication, check the package's
visibility and repository access in GitHub Packages. GitHub package visibility
is managed separately from repository visibility.

S3 publishing retains the existing private object visibility and secrets:
`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, `DEB_S3_BUCKET`, and
optional `S3_ENDPOINT`. Index updates are serialized. Both APT architectures
share identical package files across suites; distribution-specific copies are
unnecessary. Repository/package signing and an RPM repository are not configured;
RPMs are downloadable GitHub release assets.

## Local builds

Run these commands from the repository root on the architecture being built:

```sh
python3 pkg/check-build-sources.py
python3 pkg/release-metadata.py

# Match NETOM_VERSION to Cargo.toml. The Dockerfile defaults match targets.toml.
docker build -f pkg/Dockerfile --target artifacts \
  --build-arg DISTRO_IMAGE=ubuntu:22.04 --build-arg PACKAGE_FORMAT=deb \
  --build-arg NETOM_VERSION=0.6.0 --output type=local,dest=dist .

docker build -f pkg/Dockerfile --target artifacts \
  --build-arg DISTRO_IMAGE=almalinux:8 --build-arg PACKAGE_FORMAT=rpm \
  --build-arg NETOM_VERSION=0.6.0 --output type=local,dest=dist-rpm .

# dist/ must contain only the DEB for the current native architecture.
docker build --build-arg VERSION=0.6.0 -t netom:local .
bash pkg/test-scripts/smoke-image.sh netom:local 0.6.0
```

Use `--output type=local` with BuildKit to export packages without copying files
from a running builder container. BuildKit caches are scoped by package family
and architecture in GitHub Actions. When changing the Rust/tool versions, update
`pkg/targets.toml` and the Dockerfile defaults together.

To run the published image with your own configuration:

```sh
docker run --rm -p 8080:8080 -p 11019:11019 \
  -v "$PWD/netom.conf:/etc/netom/netom.conf:ro" \
  ghcr.io/fastnetmon/netom:0.6.0
```

The packaged example configuration is installed as `netom.conf.example` in host
packages. Copy and edit it as `/etc/netom/netom.conf` before enabling the systemd
service. Container images provide it as the default `netom.conf`; ports and
listeners can be changed by mounting your own configuration.
