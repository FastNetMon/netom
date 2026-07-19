#!/usr/bin/env bash
# End-to-end ADD-PATH (RFC 7911) test via BMP.
#
# Feeds a real netom process (bmp-tcp-in -> rib -> bmp-tcp-out) a crafted
# BMP session whose PeerUp negotiates ADD-PATH (capability 69, IPv4 unicast,
# SendReceive in both OPENs), announces one prefix twice with distinct path
# ids, withdraws one path, and tears the peer down. Asserts on the bmp-out
# side that:
#
#   * the synthesized downstream Peer Up advertises cap 69 in BOTH OPENs,
#   * both paths are restreamed live with their 4-byte path ids in the NLRI,
#   * a path-specific withdrawal carries its path id,
#   * a reconnecting consumer's initial dump replays only the still-active
#     path (with its path id),
#   * the /ingresses HTTP API shows the two bgpPath children with pathId and
#     parentIngress,
#   * PeerDown is emitted exactly once (for the session, not per child).
#
# Requirements: cargo, python3. Set NETOM_BIN to skip the build.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d /tmp/netom-e2e-addpath-bmp.XXXXXX)"
HTTP_ADDR="127.0.0.1:8819"
BMP_IN_ADDR="127.0.0.1:31019"
BMP_OUT_ADDR="127.0.0.1:31020"
BMP_OUT_REBUILD_ADDR="127.0.0.1:31022"
NETOM_PID=""

cleanup() {
    [[ -n "$NETOM_PID" ]] && kill "$NETOM_PID" 2>/dev/null || true
    if [[ -f "$WORKDIR/netom.log" && "${1:-}" != "ok" ]]; then
        echo "--- netom log ---"
        tail -50 "$WORKDIR/netom.log"
    fi
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

# --- build netom --------------------------------------------------------------

if [[ -z "${NETOM_BIN:-}" ]]; then
    echo "Building netom..."
    cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml"
    NETOM_BIN="$REPO_ROOT/target/release/netom"
fi

# --- netom config -------------------------------------------------------------

cat > "$WORKDIR/netom.conf" <<EOF
http_listen = ["$HTTP_ADDR"]

[units.bmp-in]
type = "bmp-tcp-in"
listen = "$BMP_IN_ADDR"

[units.rib]
type = "rib"
sources = ["bmp-in"]

[targets.null]
type = "null-out"
sources = ["rib"]

# fastpath defaults to true: live ADD-PATH UPDATEs are forwarded verbatim
# and the duplicate-suppression must map path-child payloads back to the
# session (a bug there shows up as every route delivered twice).
[units.bmp-out]
type = "bmp-tcp-out"
listen = "$BMP_OUT_ADDR"
sources = ["rib"]
rib_unit = "rib"
tls = false
acl = ["127.0.0.0/8"]
sys_name = "e2e-addpath"
sys_descr = "addpath e2e restreamer (fastpath)"

# Same feed with fastpath off: exercises the live rebuild path (path ids
# re-attached by the encoder rather than forwarded verbatim).
[units.bmp-out-rebuild]
type = "bmp-tcp-out"
listen = "$BMP_OUT_REBUILD_ADDR"
sources = ["rib"]
rib_unit = "rib"
tls = false
fastpath = false
acl = ["127.0.0.0/8"]
sys_name = "e2e-addpath-rebuild"
sys_descr = "addpath e2e restreamer (rebuild)"

[targets.bmp-out-consume]
type = "null-out"
source = "bmp-out"

[targets.bmp-out-rebuild-consume]
type = "null-out"
source = "bmp-out-rebuild"
EOF

echo "Starting netom..."
"$NETOM_BIN" -c "$WORKDIR/netom.conf" > "$WORKDIR/netom.log" 2>&1 &
NETOM_PID=$!

# --- drive and assert ----------------------------------------------------------

HTTP_ADDR="$HTTP_ADDR" BMP_IN_ADDR="$BMP_IN_ADDR" BMP_OUT_ADDR="$BMP_OUT_ADDR" \
BMP_OUT_REBUILD_ADDR="$BMP_OUT_REBUILD_ADDR" \
python3 "$REPO_ROOT/scripts/e2e-addpath-bmp.py"

echo "e2e-addpath-bmp: OK"
cleanup ok
trap - EXIT
