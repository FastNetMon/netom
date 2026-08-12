#!/usr/bin/env bash
# End-to-end test for netom-cli against a live netom.
#
# Starts netom with a BGP listener and a configured-but-unreachable peer,
# drives a real BGP session into it, then asserts that netom-cli reports
# what an operator would expect: an established peer with prefix counts, a
# peer that never came up shown as Active rather than missing, working
# abbreviation, output filters, --json passthrough and exit codes.
#
# Requirements: cargo, python3. Set NETOM_BIN / NETOM_CLI_BIN to skip the
# build.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d /tmp/netom-e2e-cli.XXXXXX)"
HTTP_ADDR="127.0.0.1:8829"
BGP_ADDR="127.0.0.1:1794"
NETOM_PID=""
SPEAKER_PID=""

cleanup() {
    [[ -n "$SPEAKER_PID" ]] && kill "$SPEAKER_PID" 2>/dev/null || true
    [[ -n "$NETOM_PID" ]] && kill "$NETOM_PID" 2>/dev/null || true
    if [[ -f "$WORKDIR/netom.log" && "${1:-}" != "ok" ]]; then
        echo "--- netom log ---"
        tail -50 "$WORKDIR/netom.log"
    fi
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

if [[ -z "${NETOM_BIN:-}" || -z "${NETOM_CLI_BIN:-}" ]]; then
    echo "building..."
    (cd "$REPO_ROOT" && cargo build --release)
    NETOM_BIN="${NETOM_BIN:-$REPO_ROOT/target/release/netom}"
    NETOM_CLI_BIN="${NETOM_CLI_BIN:-$REPO_ROOT/target/release/netom-cli}"
fi

cat > "$WORKDIR/netom.conf" <<EOF
log_level = "warn"
log_target = "stderr"
http_listen = ["$HTTP_ADDR"]

[units.bgp-in]
type = "bgp-tcp-in"
listen = "$BGP_ADDR"
my_asn = 64512
my_bgp_id = [10,1,0,254]

[units.bgp-in.peers."127.0.0.1"]
name = "PeerLocal"
remote_asn = 65001

# Configured but unreachable: must still appear, as Active.
[units.bgp-in.peers."127.0.0.9"]
name = "PeerDead"
remote_asn = 65003
connect = true
connect_retry_secs = 5

# Exists only to give the redaction assertion an md5_key to find. Kept on a
# peer of its own: TCP-MD5 needs privileges we may not have, so putting it
# on either peer above would change their behaviour rather than just the
# rendered config.
[units.bgp-in.peers."10.1.0.77"]
name = "PeerSecret"
remote_asn = 65004
md5_key = "e2e-secret-must-not-leak"

[units.rib]
type = "rib"
sources = ["bgp-in"]

[targets.null]
type = "null-out"
sources = ["rib"]
EOF

"$NETOM_BIN" -c "$WORKDIR/netom.conf" > "$WORKDIR/netom.log" 2>&1 &
NETOM_PID=$!

for _ in $(seq 1 30); do
    curl -sf "http://$HTTP_ADDR/api/v1/status" > /dev/null 2>&1 && break
    sleep 0.5
done
curl -sf "http://$HTTP_ADDR/api/v1/status" > /dev/null \
    || fail "netom did not come up"

cli() { "$NETOM_CLI_BIN" -u "http://$HTTP_ADDR" "$@"; }

# --- commands that need no BGP session ------------------------------------

cli show version | grep -q "^netom " || fail "show version"
cli sh ver | grep -q "^netom " || fail "abbreviated show version"
cli show status | grep -q "^Units:" || fail "show status units"

# The API is unauthenticated, so a leaked MD5 key would be readable by
# anyone who can reach the port.
if cli show running-config | grep -q "e2e-secret-must-not-leak"; then
    fail "show running-config leaked the configured md5_key"
fi
cli show running-config | grep -q "<redacted>" \
    || fail "show running-config did not redact"

# --- a configured peer that never came up ---------------------------------

sleep 6  # let the dialer fail at least once
cli show ip bgp summary | grep "127.0.0.9" | grep -qE "Active|Connect" \
    || fail "configured-but-unreachable peer not reported as Active"

# --- a real session --------------------------------------------------------

python3 "$REPO_ROOT/scripts/e2e-cli-speaker.py" "$BGP_ADDR" \
    > "$WORKDIR/speaker.log" 2>&1 &
SPEAKER_PID=$!

# Assert on the JSON, not the table: when a session is up the
# State/PfxRcd column shows the prefix count rather than the word
# "Established", exactly as a router does.
peer_field() {
    cli --json show ip bgp summary | python3 -c "
import json, sys
for n in json.load(sys.stdin)['data']:
    if n.get('peerAddress') == '127.0.0.1':
        print(n.get('$1', ''))
        break
"
}
peer_state() { peer_field state; }

# Wait for the announcements, not just for the session: the state flips to
# Established a moment before the UPDATEs are processed.
for _ in $(seq 1 60); do
    [[ "$(peer_field prefixesReceived)" == "3" ]] && break
    sleep 0.5
done

SUMMARY="$(cli show ip bgp summary)"
[[ "$(peer_state)" == "Established" ]] \
    || fail "session not established; summary was:
$SUMMARY"
# Up, so the row carries a prefix count and an uptime rather than a state.
echo "$SUMMARY" | grep "127.0.0.1" | grep -qE "[0-9]{2}:[0-9]{2}:[0-9]{2} +3$" \
    || fail "established row lacks uptime and prefix count:
$SUMMARY"
echo "$SUMMARY" | grep -q "Total neighbors" || fail "summary total missing"

cli show ip bgp neighbors 127.0.0.1 | grep -q "remote AS 65001" \
    || fail "neighbor detail"

# Routes: one prefix, then the streamed whole table.
cli show ip bgp 10.0.0.0/24 | grep -q "10.0.0.0/24" \
    || fail "prefix lookup"
cli show ip bgp | grep -q "Total routes 3" \
    || fail "whole-table dump: $(cli show ip bgp)"

# --json is a raw passthrough, so it must parse as the API's own output.
cli --json show ip bgp summary | python3 -c 'import json,sys; json.load(sys.stdin)' \
    || fail "--json summary is not valid JSON"
# Whole-table dumps are NDJSON: every line parses on its own.
cli --json show ip bgp | python3 -c '
import json, sys
n = 0
for line in sys.stdin:
    if line.strip():
        json.loads(line)
        n += 1
sys.exit(0 if n == 3 else 1)
' || fail "--json whole table is not 3 NDJSON records"

# --- output filters and exit codes ----------------------------------------

cli show ip bgp summary \| include 127.0.0.1 | grep -q "127.0.0.1" \
    || fail "| include"
cli show ip bgp summary \| exclude 127.0.0.1 | grep -q "127.0.0.1" \
    && fail "| exclude did not drop matching lines"
cli show ip bgp summary \| count | grep -q "Number of lines which match:" \
    || fail "| count"

# A broken pipe must not turn into an error.
cli show ip bgp | head -1 > /dev/null || fail "head on a streamed dump"

printf 'show version\nexit\n' | cli > /dev/null || fail "batch stdin"

set +e
cli show bogus > /dev/null 2>&1; [[ $? -eq 1 ]] || fail "bad command exit code"
cli show > /dev/null 2>&1; [[ $? -eq 1 ]] || fail "incomplete exit code"
"$NETOM_CLI_BIN" -u http://127.0.0.1:9 show version > /dev/null 2>&1
[[ $? -eq 2 ]] || fail "unreachable daemon exit code"
set -e

# --- endpoint discovery from the config file ------------------------------

"$NETOM_CLI_BIN" -c "$WORKDIR/netom.conf" show version | grep -q "^netom " \
    || fail "endpoint discovery via -c"

echo "e2e-cli: OK"
trap 'cleanup ok' EXIT
