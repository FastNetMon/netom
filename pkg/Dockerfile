# syntax=docker/dockerfile:1
ARG DISTRO_IMAGE=ubuntu:22.04
FROM ${DISTRO_IMAGE} AS toolchain
ARG PACKAGE_FORMAT=deb
RUN if [ "$PACKAGE_FORMAT" = deb ]; then \
      apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential ca-certificates curl git libssl-dev pkg-config \
      && rm -rf /var/lib/apt/lists/*; \
    elif [ "$PACKAGE_FORMAT" = rpm ]; then \
      dnf install -y gcc gcc-c++ make ca-certificates curl git openssl-devel pkgconf-pkg-config rpm-build \
      && dnf clean all; \
    else exit 1; fi
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo PATH=/usr/local/cargo/bin:${PATH}
ARG RUST_VERSION=1.97.1
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain "$RUST_VERSION" --no-modify-path
ARG CARGO_DEB_VERSION=3.7.0
RUN if [ "$PACKAGE_FORMAT" = deb ]; then cargo install cargo-deb --locked --version "$CARGO_DEB_VERSION"; fi

FROM toolchain AS build
ARG TARGETARCH
ARG NETOM_VERSION
WORKDIR /build
COPY . .
# Scope compiled objects to the ABI baseline and architecture. Git and registry
# caches only contain source; they can be shared across both package families.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=netom-${PACKAGE_FORMAT}-${TARGETARCH},target=/build/target,sharing=locked \
    bash pkg/build-package.sh "$PACKAGE_FORMAT" "$NETOM_VERSION"

FROM scratch AS artifacts
COPY --from=build /out/ /
