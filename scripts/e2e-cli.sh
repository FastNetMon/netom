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

# `help` lists the whole tree, and `?` lists what may follow — including
# when only one keyword does, which must be listed and not auto-completed.
cli help | grep -q "show ip bgp summary bmp" || fail "help command list"
cli 'show ip ?' | grep -q "bgp" || fail "? with a single continuation"
cli 'show ip bgp ?' | grep -q "^  <cr>$" \
    || fail "? did not mark a runnable command with <cr>"

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

# Route filters. The speaker is a session netom terminates itself, so every
# route is `source bgp` and none is `source bmp`; the brackets in
# filter[ingressType] have to survive the wire, not just the unit tests.
cli show ip bgp source bgp | grep -q "Total routes 3" \
    || fail "source bgp: $(cli show ip bgp source bgp)"
cli show ip bgp source bmp | grep -q "Total routes 0" \
    || fail "source bmp should be empty: $(cli show ip bgp source bmp)"
cli show ip bgp source mrt | grep -q "Total routes 0" \
    || fail "source mrt should be empty: $(cli show ip bgp source mrt)"

cli show ip bgp neighbors 127.0.0.1 routes | grep -q "Total routes 3" \
    || fail "neighbor routes: $(cli show ip bgp neighbors 127.0.0.1 routes)"
cli show ip bgp neighbors 127.0.0.9 routes | grep -q "Total routes 0" \
    || fail "routes of a peer that never came up should be empty"

cli show ip bgp origin-as 65001 | grep -q "Total routes 3" \
    || fail "origin-as: $(cli show ip bgp origin-as 65001)"
cli show ip bgp origin-as 65999 | grep -q "Total routes 0" \
    || fail "origin-as of an AS with no routes should be empty"

INGRESS_ID="$(cli --json show ingresses | python3 -c '
import json, sys
data = json.load(sys.stdin)["data"]
print(next(i["id"] for i in data if i.get("ingress_type") == "bgp"))
')"
cli show ip bgp ingress "$INGRESS_ID" | grep -q "Total routes 3" \
    || fail "ingress $INGRESS_ID: $(cli show ip bgp ingress "$INGRESS_ID")"

# A filter that narrows to nothing must still be a well-formed empty table,
# not a 400 from the daemon.
cli show ip bgp community 65000:100 | grep -q "Total routes 0" \
    || fail "community: $(cli show ip bgp community 65000:100)"

# FlowSpec answers buffered JSON, not NDJSON, so it has its own renderer:
# an empty table must read as a table, not as a 400 about format=jsonl.
cli show ip bgp flowspec | grep -q "Total rules 0" \
    || fail "flowspec table: $(cli show ip bgp flowspec)"
cli show ip bgp flowspec 10.0.0.0/24 | grep -q "Total rules 0" \
    || fail "flowspec prefix: $(cli show ip bgp flowspec 10.0.0.0/24)"
cli show ip bgp flowspec source bmp | grep -q "Total rules 0" \
    || fail "flowspec source bmp: $(cli show ip bgp flowspec source bmp)"
# ... and only the filters the daemon implements for it are typeable.
if cli show ip bgp flowspec origin-as 65001 > /dev/null 2>&1; then
    fail "flowspec should not accept origin-as"
fi

# --- best path -------------------------------------------------------------

# One session, so each prefix has a single candidate: the assertions here are
# that the endpoint answers, resolves the right prefix, and marks a winner --
# the tie-breakers themselves are unit-tested against a multi-peer corpus.
BEST="$(cli show ip bgp 10.0.0.0/24 best)"
echo "$BEST" | grep -q "BGP routing table entry for 10.0.0.0/24" \
    || fail "best path for a prefix: $BEST"
echo "$BEST" | grep -q "^>" || fail "best path did not mark a winner: $BEST"
echo "$BEST" | grep -q "excluded from the decision process" \
    && fail "a plain session route must not be ineligible: $BEST"

# The address form is a longest-prefix match, so the answer names the covering
# prefix rather than the /32 that was asked for.
LOOKUP="$(cli show ip bgp best 10.0.1.7)"
echo "$LOOKUP" | grep -q "10.0.1.0/24" \
    || fail "best path for an address did not resolve the covering prefix: $LOOKUP"
echo "$LOOKUP" | grep -q "best path for 10.0.1.7" \
    || fail "best path for an address did not echo the address: $LOOKUP"

# An address with no covering route is "not in table", not an error.
cli show ip bgp best 203.0.113.9 | grep -q "Network not in table" \
    || fail "best path for an unrouted address: $(cli show ip bgp best 203.0.113.9)"

# `best` is a narrowing keyword in the CLI grammar, so the route filters hang
# off it and must still reach the best-path endpoint rather than falling back
# to a plain route query.
cli show ip bgp 10.0.0.0/24 best source bgp | grep -q "^>" \
    || fail "best path with a filter: $(cli show ip bgp 10.0.0.0/24 best source bgp)"
cli show ip bgp 10.0.0.0/24 best source bmp | grep -q "Network not in table" \
    || fail "a filter that excludes every candidate must empty the decision"

# The JSON contract: a best-path row is a /routes row plus the ranking fields.
cli --json show ip bgp 10.0.0.0/24 best | python3 -c '
import json, sys
d = json.load(sys.stdin)["data"]
assert d["nlri"] == "10.0.0.0/24", d["nlri"]
assert d["strategy"] == "rfc4271", d["strategy"]
assert d["counts"]["eligible"] == 1, d["counts"]
assert d["counts"]["ineligible"] == 0, d["counts"]
best = d["best"]
assert best["rank"] == 1, best
# A lone candidate has nothing to be compared against.
assert best.get("decidedBy") is None, best
# Shared with /routes, so existing consumers keep working.
for key in ("status", "source", "pathAttributes"):
    assert key in best, (key, sorted(best))
assert d["alternatives"] == [], d["alternatives"]
' || fail "best path JSON shape"

# skipMed is the other decision process routecore offers; with one candidate
# it changes nothing, but the parameter must be accepted rather than 400.
curl -sf "http://$HTTP_ADDR/api/v1/ribs/ipv4unicast/best-path/10.0.0.0/24?strategy=skipMed" \
    | grep -q '"strategy":"skipMed"' || fail "strategy=skipMed rejected"

# Parameters that cannot be honoured are refused by name rather than ignored.
curl -s "http://$HTTP_ADDR/api/v1/ribs/ipv4unicast/best-path/10.0.0.0/24?strategy=bogus" \
    | grep -q '"error"' || fail "an unknown strategy must be a 400"
curl -s "http://$HTTP_ADDR/api/v1/ribs/ipv4unicast/best-path/10.0.0.0/24?include=moreSpecifics" \
    | grep -q '"error"' || fail "include must be refused on best-path"

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
