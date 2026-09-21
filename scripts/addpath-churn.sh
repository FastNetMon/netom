#!/usr/bin/env bash
# Reproduce (and, after a fix, regression-test) ADD-PATH path-child
# accumulation: a peer that never reuses a path id grows the ingress
# register forever while its RIB stays one prefix.
#
# Run by hand; not part of the CI matrix, since it is currently expected to
# fail — it reproduces an open bug (docs/planning/MEMLEAK_TRACKING.md open item 2).
#
#   scripts/addpath-churn.sh                 # 2000 path ids
#   CHURN=50000 scripts/addpath-churn.sh     # longer, slower
#
# Requirements: cargo, python3. Set NETOM_BIN to skip the build.
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d /tmp/netom-addpath-churn.XXXXXX)"
export BMP_IN_ADDR="${BMP_IN_ADDR:-127.0.0.1:11021}"
export HTTP_ADDR="${HTTP_ADDR:-127.0.0.1:8831}"
export CHURN="${CHURN:-2000}"
NETOM_PID=""

cleanup() {
    [[ -n "$NETOM_PID" ]] && kill "$NETOM_PID" 2>/dev/null || true
    if [[ -f "$WORKDIR/netom.log" && "${1:-}" != "ok" ]]; then
        echo "--- netom log (tail) ---"
        tail -30 "$WORKDIR/netom.log"
    fi
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

if [[ -z "${NETOM_BIN:-}" ]]; then
    echo "Building netom..."
    cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml"
    NETOM_BIN="$REPO_ROOT/target/release/netom"
fi

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
EOF

# Shorten the GC/reap cycle so a reap completes inside the test rather than
# in half an hour. Production uses the constants in units/rib_unit/unit.rs.
export NETOM_RIB_GC_INTERVAL_SECS="${NETOM_RIB_GC_INTERVAL_SECS:-2}"
export NETOM_RIB_REAP_EVERY_TICKS="${NETOM_RIB_REAP_EVERY_TICKS:-1}"

"$NETOM_BIN" --config "$WORKDIR/netom.conf" > "$WORKDIR/netom.log" 2>&1 &
NETOM_PID=$!

for _ in $(seq 1 100); do
    if curl -fsS -o /dev/null "http://$HTTP_ADDR/metrics" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$NETOM_PID" 2>/dev/null; then
        echo "FAIL: netom exited during startup" >&2
        exit 1
    fi
    sleep 0.2
done

set +e
python3 "$REPO_ROOT/scripts/addpath-churn.py"
rc=$?
set -e

# The register state is worth seeing whichever way the run went.
echo "--- /api/v1/ingresses by type ---"
curl -fsS "http://$HTTP_ADDR/api/v1/ingresses" 2>/dev/null \
    | grep -o '"ingress_type":"[a-zA-Z]*"' | sort | uniq -c || true

if [[ $rc -eq 0 ]]; then
    trap 'cleanup ok' EXIT
    echo "addpath-churn: OK"
else
    echo "addpath-churn: FAIL (rc=$rc)"
fi
exit $rc
