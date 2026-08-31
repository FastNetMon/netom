#!/usr/bin/env bash

set -euo pipefail

readonly DISTRO_VERSION="${1:-24.04}"

case "${DISTRO_VERSION}" in
    22.04)
        DEB_VARIANT="ubuntu-jammy"
        ;;
    24.04|26.04)
        DEB_VARIANT=""
        ;;
    *)
        echo "Unsupported Ubuntu version: ${DISTRO_VERSION}" >&2
        echo "Supported versions: 22.04, 24.04 (default), 26.04" >&2
        exit 2
        ;;
esac

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT
VERSION="$(
    awk '
        $0 == "[workspace.package]" { in_workspace_package = 1; next }
        in_workspace_package && /^\[/ { exit }
        in_workspace_package && /^version[[:space:]]*=/ {
            gsub(/^[^"]*"|".*$/, "")
            print
            exit
        }
    ' "${REPO_ROOT}/Cargo.toml"
)"
readonly VERSION

if [[ -z "${VERSION}" ]]; then
    echo "Could not determine workspace package version from Cargo.toml" >&2
    exit 1
fi

DOCKER=(docker)
if ! docker info >/dev/null 2>&1; then
    DOCKER=(sudo docker)
fi

readonly IMAGE_TAG="netom-deb-build:ubuntu-${DISTRO_VERSION//./-}"
readonly BASE_TAG="netom-build-base:ubuntu-${DISTRO_VERSION//./-}"
readonly RUST_VERSION="${RUST_VERSION:-stable}"

# The toolchain image is expensive (toolchain download + cargo-deb build) and
# never changes between releases, so build it only when it is missing. Set
# REBUILD_BASE=1 to pick up a new Rust or cargo-deb version.
if [[ "${REBUILD_BASE:-0}" == "1" ]] \
    || ! "${DOCKER[@]}" image inspect "${BASE_TAG}" >/dev/null 2>&1; then
    echo "Building toolchain image ${BASE_TAG} (one-off, several minutes)"
    "${DOCKER[@]}" build \
        --platform linux/amd64 \
        --build-arg "DISTRO_VERSION=${DISTRO_VERSION}" \
        --build-arg "RUST_VERSION=${RUST_VERSION}" \
        --file "${REPO_ROOT}/pkg/Dockerfile.base" \
        --tag "${BASE_TAG}" \
        "${REPO_ROOT}/pkg"
else
    echo "Reusing toolchain image ${BASE_TAG}"
fi

echo "Building netom ${VERSION} for Ubuntu ${DISTRO_VERSION} (linux/amd64)"
"${DOCKER[@]}" build \
    --platform linux/amd64 \
    --build-arg "BASE_IMAGE=${BASE_TAG}" \
    --build-arg "NETOM_VERSION=${VERSION}" \
    --build-arg "DEB_VARIANT=${DEB_VARIANT}" \
    --file "${REPO_ROOT}/pkg/Dockerfile.deb" \
    --tag "${IMAGE_TAG}" \
    "${REPO_ROOT}"

container_id="$("${DOCKER[@]}" create "${IMAGE_TAG}")"
cleanup() {
    "${DOCKER[@]}" rm --force "${container_id}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

mkdir -p "${REPO_ROOT}/target/debian"
"${DOCKER[@]}" cp "${container_id}:/out/." "${REPO_ROOT}/target/debian/"

echo "Package written to:"
find "${REPO_ROOT}/target/debian" -maxdepth 1 -type f -name 'netom_*.deb' -print
