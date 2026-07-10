#!/usr/bin/env bash
# End-to-end FlowSpec test over a live BGP session.
#
# Starts netom with a bgp-tcp-in unit that negotiates the FlowSpec families,
# has exabgp announce diverse FlowSpec rules (RFC 8955/8956) plus one unicast
# route, and verifies the decoded rules through the HTTP API
# (/ribs/ipv{4,6}flowspec/routes).
#
# Requirements: cargo, curl, python3, exabgp 4.2 (installed into a scratch
# venv automatically when not on PATH). Set NETOM_BIN to skip the build.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d /tmp/netom-e2e-flowspec-exabgp.XXXXXX)"
HTTP_ADDR="127.0.0.1:8810"
BGP_ADDR="127.0.0.1:11179"
NETOM_PID=""
EXABGP_PID=""

cleanup() {
    [[ -n "$EXABGP_PID" ]] && kill "$EXABGP_PID" 2>/dev/null || true
    [[ -n "$NETOM_PID" ]] && kill "$NETOM_PID" 2>/dev/null || true
    if [[ "${1:-}" != "ok" ]]; then
        for log in netom.log exabgp.log; do
            if [[ -f "$WORKDIR/$log" ]]; then
                echo "--- $log ---"
                tail -50 "$WORKDIR/$log"
            fi
        done
    fi
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

# --- prerequisites ------------------------------------------------------------

if [[ -z "${NETOM_BIN:-}" ]]; then
    echo "Building netom..."
    cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml"
    NETOM_BIN="$REPO_ROOT/target/release/netom"
fi

EXABGP="$(command -v exabgp || true)"
if [[ -z "$EXABGP" ]]; then
    echo "Installing exabgp into a scratch venv..."
    python3 -m venv "$WORKDIR/venv"
    "$WORKDIR/venv/bin/pip" -q install 'exabgp==4.2.*'
    EXABGP="$WORKDIR/venv/bin/exabgp"
fi
"$EXABGP" --version

# --- netom: BGP listener with FlowSpec families -------------------------------

cat > "$WORKDIR/netom.conf" <<EOF
log_level = "debug"
log_target = "stderr"
http_listen = ["$HTTP_ADDR"]

[units.bgp-in]
type = "bgp-tcp-in"
listen = "$BGP_ADDR"
my_asn = 65100
my_bgp_id = [127, 0, 0, 1]

[units.bgp-in.peers."127.0.0.1"]
name = "exabgp"
remote_asn = 65101
protocols = ["Ipv4Unicast", "Ipv6Unicast", "Ipv4FlowSpec", "Ipv6FlowSpec"]

[units.rib]
type = "rib"
sources = ["bgp-in"]

[targets.null]
type = "null-out"
sources = ["rib"]
EOF

# --- exabgp: 8 diverse FlowSpec rules + 1 unicast route ------------------------
# Coverage: dst/src prefix, protocol, dst/src port, port ranges, tcp-flags,
# packet-length, icmp type/code, dscp, fragment, IPv6 next-header and
# flow-label, rules with no dst prefix (keyed at the family default route),
# and the discard / rate-limit / redirect / mark actions.

cat > "$WORKDIR/exabgp.conf" <<'EOF'
neighbor 127.0.0.1 {
    router-id 198.51.100.2;
    local-address 127.0.0.1;
    local-as 65101;
    peer-as 65100;
    connect 11179;

    family {
        ipv4 unicast;
        ipv4 flow;
        ipv6 flow;
    }

    static {
        route 192.0.2.0/24 {
            next-hop 198.51.100.1;
        }
    }

    flow {
        route web-discard {
            match {
                destination 192.0.2.0/24;
                protocol tcp;
                destination-port [ =80 =443 ];
            }
            then {
                discard;
            }
        }
        route dns-rate {
            match {
                source 203.0.113.0/24;
                protocol udp;
                source-port =53;
                packet-length [ >512&<1500 ];
            }
            then {
                rate-limit 1000000;
            }
        }
        route syn-redirect {
            match {
                destination 198.51.100.0/24;
                protocol tcp;
                tcp-flags [ syn ];
            }
            then {
                redirect 65100:999;
            }
        }
        route icmp-mark {
            match {
                destination 198.51.100.0/24;
                protocol icmp;
                icmp-type [ echo-request ];
                icmp-code [ 0 ];
            }
            then {
                mark 22;
            }
        }
        route frag-discard {
            match {
                destination 198.51.100.0/24;
                fragment [ is-fragment ];
                dscp [ 46 ];
            }
            then {
                discard;
            }
        }
        route ntp-nodst {
            match {
                protocol udp;
                destination-port =123;
            }
            then {
                rate-limit 128000;
            }
        }
        route v6-https {
            match {
                destination 2001:db8:1::/48;
                next-header tcp;
                destination-port =443;
            }
            then {
                rate-limit 500000;
            }
        }
        route v6-label {
            match {
                source 2001:db8:2::/48;
                flow-label >100;
            }
            then {
                discard;
            }
        }
    }
}
EOF

"$NETOM_BIN" -c "$WORKDIR/netom.conf" > "$WORKDIR/netom.log" 2>&1 &
NETOM_PID=$!

# Wait for the BGP listener before letting exabgp connect.
for i in $(seq 1 60); do
    curl -sf "http://$HTTP_ADDR/metrics" > /dev/null 2>&1 && break
    if ! kill -0 "$NETOM_PID" 2>/dev/null; then
        echo "netom exited early" >&2
        exit 1
    fi
    sleep 0.5
done

env exabgp.daemon.daemonize=false \
    exabgp.daemon.user="$(id -un)" \
    exabgp.log.destination=stdout \
    "$EXABGP" "$WORKDIR/exabgp.conf" > "$WORKDIR/exabgp.log" 2>&1 &
EXABGP_PID=$!

echo "Waiting for the BGP session and the FlowSpec rules..."
for i in $(seq 1 120); do
    COUNT="$(curl -sf "http://$HTTP_ADDR/api/v1/ribs/ipv4flowspec/routes" \
        | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["data"]))' \
        2>/dev/null || echo 0)"
    [[ "$COUNT" == "6" ]] && break
    if ! kill -0 "$EXABGP_PID" 2>/dev/null; then
        echo "exabgp exited early" >&2
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

check("6 IPv4 rules stored", len(v4) == 6)
check("2 IPv6 rules stored", len(v6) == 2)

keys4 = Counter(r["keyPrefix"] for r in v4)
keys6 = Counter(r["keyPrefix"] for r in v6)
check("v4 keying (dst prefixes + default route for dst-less rules)",
      keys4 == {"192.0.2.0/24": 1, "198.51.100.0/24": 3, "0.0.0.0/0": 2})
check("v6 keying (dst prefix + default route)",
      keys6 == {"2001:db8:1::/48": 1, "::/0": 1})

for r in v4 + v6:
    check(f"NLRI decodes at {r['keyPrefix']}: {r['nlri']}",
          r["nlri"] != "<malformed>")
    check(f"actions decoded at {r['keyPrefix']}: {r['actions']}",
          len(r["actions"]) >= 1)

# Validity is evaluated at rule-insert time; the relative order of the
# unicast route and the flowspec rules on the wire is not guaranteed, so
# dst-keyed rules may be valid or invalid — but never unvalidatable, and
# dst-less rules always are.
for r in v4 + v6:
    if r["keyPrefix"] in ("0.0.0.0/0", "::/0"):
        check(f"dst-less rule unvalidatable ({r['nlri']})",
              r["validity"] == "unvalidatable")
    else:
        check(f"dst rule validated ({r['nlri']}: {r['validity']})",
              r["validity"] in ("valid", "invalid"))

print("PASS: flowspec BGP (exabgp) end-to-end")
EOF

trap 'cleanup ok' EXIT
