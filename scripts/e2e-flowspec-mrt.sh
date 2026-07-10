#!/usr/bin/env bash
# End-to-end FlowSpec test via MRT ingest.
#
# Generates a BGP4MP MRT file with mrtgen (pinned to the same revision as
# Cargo.toml) containing diverse FlowSpec rules (RFC 8955/8956), feeds it to
# a real netom process through an mrt-file-in unit, and verifies the decoded
# rules through the HTTP API (/ribs/ipv{4,6}flowspec/routes).
#
# Requirements: cargo, curl, python3. Set NETOM_BIN to skip the build.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d /tmp/netom-e2e-flowspec-mrt.XXXXXX)"
HTTP_ADDR="127.0.0.1:8809"
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

# --- build netom and mrtgen -------------------------------------------------

if [[ -z "${NETOM_BIN:-}" ]]; then
    echo "Building netom..."
    cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml"
    NETOM_BIN="$REPO_ROOT/target/release/netom"
fi

MRTGEN_REV="$(sed -n 's/^mrtgen.*rev = "\([0-9a-f]*\)".*/\1/p' "$REPO_ROOT/Cargo.toml")"
if [[ -z "$MRTGEN_REV" ]]; then
    echo "Could not find the pinned mrtgen revision in Cargo.toml" >&2
    exit 1
fi
echo "Installing mrtgen @ $MRTGEN_REV..."
cargo install --git https://github.com/FastNetMon/mrtgen.git \
    --rev "$MRTGEN_REV" --root "$WORKDIR/tools" mrtgen

# --- generate the MRT corpus -------------------------------------------------
# Diverse FlowSpec rules: every component type, both address families, rules
# with and without a destination prefix, every decodable traffic action. The
# unicast route comes first so the 192.0.2.0/24 rule validates against it
# (RFC 8955 section 6, same peer).

cat > "$WORKDIR/routes.json" <<'EOF'
[
    { "prefix": "192.0.2.0/24", "nexthop": "198.51.100.1", "as_path": [64500] },
    { "flowspec": { "dst_prefix": "192.0.2.0/24", "protocol": [6],
                    "dst_port": [80, 443] },
      "actions": { "rate_limit_bytes": 0 } },
    { "flowspec": { "dst_prefix": "198.51.100.0/24", "protocol": [6],
                    "tcp_flags": [{"flags": ["syn"], "match": true}],
                    "packet_length": [{"range": [512, 1500]}] },
      "actions": { "redirect": "65100:999", "sample": true } },
    { "flowspec": { "dst_prefix": "198.51.100.0/24", "protocol": [1],
                    "icmp_type": [8], "icmp_code": [0], "dscp": [46],
                    "fragment": [{"flags": ["is-fragment"]}] },
      "actions": { "traffic_marking": 22, "terminal_action": true } },
    { "flowspec": { "src_prefix": "203.0.113.0/24", "protocol": [17],
                    "src_port": [{"range": [1024, 65535]}] },
      "actions": { "redirect": "198.51.100.9:100" } },
    { "flowspec": { "dst_prefix": "2001:db8:1::/48", "protocol": [6],
                    "dst_port": [443] },
      "actions": { "rate_limit_bytes": 1000000.0 } },
    { "flowspec": { "src_prefix": "2001:db8:2::/48",
                    "flow_label": [{"gt": 0}] },
      "actions": { "rate_limit_bytes": 0 } }
]
EOF

"$WORKDIR/tools/bin/mrtgen" -r "$WORKDIR/routes.json" \
    --routes-format bgp4mp -o "$WORKDIR/flowspec.mrt"

# --- run netom over the file --------------------------------------------------

cat > "$WORKDIR/netom.conf" <<EOF
log_level = "info"
log_target = "stderr"
http_listen = ["$HTTP_ADDR"]

[units.mrt-in]
type = "mrt-file-in"
filename = ["$WORKDIR/flowspec.mrt"]

[units.rib]
type = "rib"
sources = ["mrt-in"]

[targets.null]
type = "null-out"
sources = ["rib"]
EOF

"$NETOM_BIN" -c "$WORKDIR/netom.conf" > "$WORKDIR/netom.log" 2>&1 &
NETOM_PID=$!

echo "Waiting for netom to ingest the MRT file..."
for i in $(seq 1 60); do
    COUNT="$(curl -sf "http://$HTTP_ADDR/api/v1/ribs/ipv4flowspec/routes" \
        | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["data"]))' \
        2>/dev/null || echo 0)"
    [[ "$COUNT" == "4" ]] && break
    if ! kill -0 "$NETOM_PID" 2>/dev/null; then
        echo "netom exited early" >&2
        exit 1
    fi
    sleep 0.5
done

# --- verify -------------------------------------------------------------------

curl -sf "http://$HTTP_ADDR/api/v1/ribs/ipv4flowspec/routes" > "$WORKDIR/v4.json"
curl -sf "http://$HTTP_ADDR/api/v1/ribs/ipv6flowspec/routes" > "$WORKDIR/v6.json"
curl -sf "http://$HTTP_ADDR/metrics" | grep -i flowspec || true

python3 - "$WORKDIR/v4.json" "$WORKDIR/v6.json" <<'EOF'
import json, sys
from collections import Counter

v4 = json.load(open(sys.argv[1]))["data"]
v6 = json.load(open(sys.argv[2]))["data"]
print(json.dumps(v4 + v6, indent=2))

def check(name, cond):
    if not cond:
        raise SystemExit(f"FAIL: {name}")
    print(f"ok: {name}")

check("4 IPv4 rules stored", len(v4) == 4)
check("2 IPv6 rules stored", len(v6) == 2)

keys4 = Counter(r["keyPrefix"] for r in v4)
keys6 = Counter(r["keyPrefix"] for r in v6)
check("v4 keying (dst prefixes + default route)",
      keys4 == {"192.0.2.0/24": 1, "198.51.100.0/24": 2, "0.0.0.0/0": 1})
check("v6 keying (dst prefix + default route)",
      keys6 == {"2001:db8:1::/48": 1, "::/0": 1})

for r in v4 + v6:
    check(f"NLRI decodes at {r['keyPrefix']}: {r['nlri']}",
          r["nlri"] != "<malformed>")
    check(f"actions decoded at {r['keyPrefix']}: {r['actions']}",
          len(r["actions"]) >= 1)

validity = {r["keyPrefix"]: r["validity"] for r in v4 + v6}
check("rule covered by unicast route from same peer is valid",
      validity["192.0.2.0/24"] == "valid")
check("uncovered dst rules are invalid",
      validity["198.51.100.0/24"] == "invalid"
      and validity["2001:db8:1::/48"] == "invalid")
check("dst-less rules are unvalidatable",
      validity["0.0.0.0/0"] == "unvalidatable"
      and validity["::/0"] == "unvalidatable")

print("PASS: flowspec MRT ingest end-to-end")
EOF

trap 'cleanup ok' EXIT
