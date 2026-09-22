#!/usr/bin/env bash
set -euo pipefail
image=${1:?Image required}
version=${2:?Version required}
test "$(docker run --rm "$image" --version)" = "netom $version"
test "$(docker run --rm --entrypoint netom-cli "$image" --version)" = "netom-cli $version"
test "$(docker run --rm --entrypoint id "$image" -u)" -ne 0
container=$(docker run --detach --publish 127.0.0.1::8080 "$image")
trap 'docker logs "$container"; docker rm --force "$container" >/dev/null' EXIT
address=$(docker port "$container" 8080/tcp)
curl --fail --silent --show-error --retry 20 --retry-connrefused \
    --retry-delay 1 --max-time 3 "http://$address/metrics" > /dev/null
