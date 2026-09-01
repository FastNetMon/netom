#!/usr/bin/env python3
"""Reproduce ADD-PATH path-child accumulation, and measure it.

A router that allocates a fresh RFC 7911 path id per advertisement — and
never reuses one — makes netom mint a permanent child ingress per
`(session, path_id)`. Children are only reclaimed when their *session* goes
down, so on a session that stays up for weeks the ingress register grows
without bound while the RIB it describes stays exactly the same size.

Observed on a production collector: 1.34M children from 166 peers, one
peer holding 110,914 of them, path ids spanning 146.8M values at a density
of 0.001. See MEMLEAK_TRACKING.md.

This drives the same shape against a local netom: announce one prefix under
a fresh path id, withdraw it, repeat. The RIB should hold one prefix
throughout, and the register should not grow with the churn.

**This currently fails**, which is the point: it is the regression test for
the fix, and until then it is a reproduction. As of 0.6.0-fnm13 a 2000-pair
run produces +2000 children (100% of churn) and 2001 records under a single
prefix. Usage:

    scripts/addpath-churn.sh              # 2000 iterations, default
    CHURN=20000 scripts/addpath-churn.sh  # longer run

Environment: BMP_IN_ADDR, HTTP_ADDR, CHURN, TOLERANCE (fraction of churn
iterations the register may grow by before the run is called a failure).
"""

import json
import os
import socket
import struct
import sys
import time
import urllib.request

BMP_IN_ADDR = os.environ.get("BMP_IN_ADDR", "127.0.0.1:11021")
HTTP_ADDR = os.environ.get("HTTP_ADDR", "127.0.0.1:8831")
CHURN = int(os.environ.get("CHURN", "2000"))
# How much register growth counts as "bounded". A fix that retires a child
# when its last route leaves should keep this near zero; anything above a
# few percent of the iteration count is the leak.
TOLERANCE = float(os.environ.get("TOLERANCE", "0.05"))
# How long to wait for the reap to catch up after the churn stops.
REAP_WAIT = float(os.environ.get("REAP_WAIT", "120"))

PEER_AS = 65001
PEER_IP = "10.99.0.1"
PREFIX_WIRE = bytes([24, 10, 0, 0])  # 10.0.0.0/24

# ADD-PATH (cap 69) for v4 unicast, SendReceive, plus the MP family and the
# 4-octet ASN capability. Without cap 69 negotiated the 4-byte path id is
# parsed as part of the NLRI and every id becomes a *different* prefix --
# which is what this test would otherwise measure by accident.
ADDPATH_CAP = bytes([69, 4]) + bytes([0, 1, 1, 3])
MP_CAPS = bytes([1, 4, 0, 1, 0, 1])

DEADLINE = time.monotonic() + 900


def addr_port(addr):
    host, port = addr.rsplit(":", 1)
    return host, int(port)


def connect(addr):
    host, port = addr_port(addr)
    last = None
    while time.monotonic() < DEADLINE:
        try:
            s = socket.create_connection((host, port), timeout=2)
            s.settimeout(10)
            return s
        except OSError as e:  # netom may still be binding
            last = e
            time.sleep(0.1)
    raise SystemExit(f"FAIL: could not connect to {addr}: {last}")


# --- BMP/BGP message crafting -------------------------------------------------


def bmp_msg(msg_type, body):
    return struct.pack("!BIB", 3, 6 + len(body), msg_type) + body


def initiation():
    # sysName (type 2) is mandatory: netom rejects the session without it.
    def tlv(t, val):
        return struct.pack("!HH", t, len(val)) + val

    return bmp_msg(4, tlv(2, b"addpath-churn-feeder") + tlv(1, b"feeder"))


def pph():
    b = struct.pack("!BB", 0, 0)  # global instance, v4, pre-policy
    b += b"\x00" * 8  # distinguisher
    b += b"\x00" * 12 + socket.inet_aton(PEER_IP)
    b += struct.pack("!I", PEER_AS)
    b += socket.inet_aton(PEER_IP)  # BGP ID
    b += struct.pack("!II", 0, 0)  # timestamp
    return b


def bgp_open():
    caps = MP_CAPS + ADDPATH_CAP + bytes([65, 4]) + struct.pack("!I", PEER_AS)
    opt = bytes([2, len(caps)]) + caps
    body = struct.pack("!BHH", 4, PEER_AS, 0)
    body += socket.inet_aton(PEER_IP)
    body += bytes([len(opt)]) + opt
    return b"\xff" * 16 + struct.pack("!HB", 19 + len(body), 1) + body


def peer_up():
    body = pph()
    body += b"\x00" * 12 + socket.inet_aton("10.99.0.254")
    body += struct.pack("!HH", 179, 33001)
    o = bgp_open()
    return bmp_msg(3, body + o + o)


def bgp_update(pas, nlri, withdrawn=b""):
    body = struct.pack("!H", len(withdrawn)) + withdrawn
    body += struct.pack("!H", len(pas)) + pas + nlri
    return b"\xff" * 16 + struct.pack("!HB", 19 + len(body), 2) + body


def pa(flags, type_code, val):
    return bytes([flags, type_code, len(val)]) + val


def announce(path_id):
    pas = pa(0x40, 1, b"\x00")  # ORIGIN IGP
    pas += pa(0x40, 2, bytes([2, 1]) + struct.pack("!I", PEER_AS))
    pas += pa(0x40, 3, socket.inet_aton("10.99.0.1"))  # NEXT_HOP
    return bmp_msg(0, pph() + bgp_update(pas, struct.pack("!I", path_id) + PREFIX_WIRE))


def withdraw(path_id):
    wd = struct.pack("!I", path_id) + PREFIX_WIRE
    return bmp_msg(0, pph() + bgp_update(b"", b"", withdrawn=wd))


# --- measurement --------------------------------------------------------------


def metrics():
    """The counters this test is about, from /metrics."""
    want = {
        "netom_ingress_register_entries_total": "entries",
        "netom_ingress_register_addpath_path_children_total": "children",
        "netom_rib_unit_num_unique_prefixes_total": "prefixes",
        "netom_rib_unit_num_items_total": "records",
    }
    out = {v: 0 for v in want.values()}
    with urllib.request.urlopen(f"http://{HTTP_ADDR}/metrics", timeout=30) as r:
        for line in r.read().decode().splitlines():
            if line.startswith("#"):
                continue
            name = line.split("{", 1)[0].split(" ", 1)[0]
            if name in want:
                out[want[name]] = int(float(line.rsplit(" ", 1)[1]))
    return out


def settle(timeout=30):
    """Wait until the counters stop moving, so they are not read mid-flight."""
    last = None
    stable = 0
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        now = metrics()
        if now == last:
            stable += 1
            if stable >= 3:
                return now
        else:
            stable = 0
            last = now
        time.sleep(0.5)
    return metrics()


def wait_for_reap(baseline_children, timeout=REAP_WAIT):
    """Poll until the reap has retired the idle children, or give up.

    Retirement takes several sweeps by design: the reap needs two passes to
    confirm a child owns nothing, and the GC then needs two more to reclaim
    a Disconnected entry. The script shortens both intervals through
    NETOM_RIB_GC_INTERVAL_SECS / NETOM_RIB_REAP_EVERY_TICKS.
    """
    end = time.monotonic() + timeout
    best = metrics()
    print(f"waiting up to {timeout}s for the reap to retire idle children...")
    while time.monotonic() < end:
        now = metrics()
        if now["children"] != best["children"]:
            print(
                f"  children={now['children']} entries={now['entries']} "
                f"records={now['records']}"
            )
            best = now
        if now["children"] <= baseline_children:
            return now
        time.sleep(1.0)
    return metrics()


def main():
    feeder = connect(BMP_IN_ADDR)
    feeder.sendall(initiation())
    feeder.sendall(peer_up())

    # One announcement to establish the session and its first child.
    feeder.sendall(announce(1))
    feeder.sendall(withdraw(1))
    base = settle()
    print(
        f"baseline: entries={base['entries']} children={base['children']} "
        f"prefixes={base['prefixes']} records={base['records']}"
    )

    # The churn: each iteration is one path id used exactly once, which is
    # what a router allocating ids monotonically does over time.
    print(f"churning {CHURN} announce+withdraw pairs with fresh path ids...")
    t0 = time.monotonic()
    for i in range(2, CHURN + 2):
        feeder.sendall(announce(i))
        feeder.sendall(withdraw(i))
        if i % 500 == 0:
            now = metrics()
            print(
                f"  {i - 1:6} pairs: entries={now['entries']} "
                f"children={now['children']} prefixes={now['prefixes']}"
            )
    elapsed = time.monotonic() - t0

    peak = settle()
    print(
        f"peak:     entries={peak['entries']} children={peak['children']} "
        f"prefixes={peak['prefixes']} records={peak['records']}"
    )

    after = wait_for_reap(base["children"])
    grown = after["children"] - base["children"]
    ratio = grown / CHURN

    print()
    print(f"churn:    {CHURN} path ids in {elapsed:.1f}s")
    print(
        f"before:   entries={base['entries']} children={base['children']} "
        f"prefixes={base['prefixes']} records={base['records']}"
    )
    print(
        f"after:    entries={after['entries']} children={after['children']} "
        f"prefixes={after['prefixes']} records={after['records']}"
    )
    retained = peak["children"] - after["children"]
    print(
        f"minted:   {peak['children'] - base['children']} children for "
        f"{CHURN} path ids"
    )
    print(
        f"reclaimed:{retained} of them after the paths were withdrawn "
        f"({ratio:+.0%} of churn still held)"
    )

    # Checked at the peak, not after the reap: during the churn the RIB must
    # hold exactly the prefix that was announced. If it grew, cap 69 was not
    # negotiated and each path id became its own prefix -- the run would then
    # be measuring nothing. (After the reap the prefix legitimately goes away
    # with the last route.)
    if peak["prefixes"] != base["prefixes"]:
        print(
            f"FAIL: prefix count moved during churn ({base['prefixes']} -> "
            f"{peak['prefixes']}); ADD-PATH was probably not negotiated, so "
            "each path id became a separate prefix"
        )
        return 1

    if ratio > TOLERANCE:
        print()
        print(
            f"FAIL: the ingress register grew by {ratio:.0%} of the churn "
            f"while the RIB held {after['prefixes']} prefix(es) throughout."
        )
        print(
            "      Every (session, path_id) mints a child ingress that is "
            "only reclaimed when the *session* goes down, so a peer that "
            "never reuses a path id grows the register forever."
        )
        print(
            f"      Each dead path also leaves a record behind: "
            f"{after['records']} records under {after['prefixes']} prefix(es), "
            "one withdrawn tombstone per retired path id."
        )
        print("      See MEMLEAK_TRACKING.md open item 2. Expected to fail "
              "until a child is retired when its last route leaves.")
        return 1

    print()
    print(
        f"OK: {peak['children'] - base['children']} children minted and "
        f"reclaimed; register growth {max(ratio, 0.0):.1%} of churn, within "
        f"{TOLERANCE:.0%}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
