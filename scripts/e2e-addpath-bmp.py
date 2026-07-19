#!/usr/bin/env python3
"""ADD-PATH (RFC 7911) end-to-end driver/assertor for netom's BMP pipeline,
covering v4 unicast and v4 flowspec (RFC 8955) ADD-PATH.

Run via scripts/e2e-addpath-bmp.sh, which starts netom and passes the
endpoints in HTTP_ADDR / BMP_IN_ADDR / BMP_OUT_ADDR.
"""

import json
import os
import socket
import struct
import sys
import time
import urllib.request

HTTP_ADDR = os.environ["HTTP_ADDR"]
BMP_IN_ADDR = os.environ["BMP_IN_ADDR"]
BMP_OUT_ADDR = os.environ["BMP_OUT_ADDR"]
BMP_OUT_REBUILD_ADDR = os.environ["BMP_OUT_REBUILD_ADDR"]

PEER_IP = "10.99.0.1"
PEER_AS = 65001
PREFIX_WIRE = bytes([24, 10, 0, 0])  # 10.0.0.0/24

# ADD-PATH (cap 69) families the feeder negotiates: v4 unicast and v4
# flowspec, both SendReceive. The synthesized downstream Peer Up must
# advertise exactly these quads (any order).
ADDPATH_QUAD_UNICAST = bytes([0, 1, 1, 3])
ADDPATH_QUAD_FLOWSPEC = bytes([0, 1, 133, 3])
ADDPATH_CAP = bytes([69, 8]) + ADDPATH_QUAD_UNICAST + ADDPATH_QUAD_FLOWSPEC
# MP-BGP capabilities so the flowspec family is negotiated at all.
MP_CAPS = bytes([1, 4, 0, 1, 0, 1]) + bytes([1, 4, 0, 1, 0, 133])

# RFC 8955 raw flowspec NLRI (no length header):
FS_RULE_A = bytes([0x01, 0x18, 10, 0, 1, 0x03, 0x81, 0x11])  # dst+proto=17
FS_RULE_B = bytes([0x01, 0x18, 10, 0, 1, 0x05, 0x81, 0x35])  # dst+dport=53

DEADLINE = time.monotonic() + 60.0


def remaining():
    left = DEADLINE - time.monotonic()
    if left <= 0:
        raise SystemExit("FAIL: global test deadline exceeded")
    return left


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
        except OSError as e:
            last = e
            time.sleep(0.2)
    raise SystemExit(f"FAIL: cannot connect to {addr}: {last}")


# --- BMP/BGP message crafting -------------------------------------------------


def bmp_msg(msg_type, body):
    return struct.pack("!BIB", 3, 6 + len(body), msg_type) + body


def initiation():
    def tlv(t, val):
        return struct.pack("!HH", t, len(val)) + val

    return bmp_msg(4, tlv(2, b"e2e-addpath-feeder") + tlv(1, b"feeder"))


def pph():
    b = struct.pack("!BB", 0, 0)  # global instance, v4, pre-policy
    b += b"\x00" * 8  # distinguisher
    b += b"\x00" * 12 + socket.inet_aton(PEER_IP)
    b += struct.pack("!I", PEER_AS)
    b += socket.inet_aton(PEER_IP)  # BGP ID
    b += struct.pack("!II", 0, 0)  # timestamp
    return b


def bgp_open():
    # Capabilities: MP families + ADD-PATH (69) + 4-octet ASN (65), one
    # type-2 parameter.
    caps = MP_CAPS + ADDPATH_CAP + bytes([65, 4]) + struct.pack("!I", PEER_AS)
    opt = bytes([2, len(caps)]) + caps
    body = struct.pack("!BHH", 4, PEER_AS, 0)
    body += socket.inet_aton(PEER_IP)
    body += bytes([len(opt)]) + opt
    return b"\xff" * 16 + struct.pack("!HB", 19 + len(body), 1) + body


def peer_up():
    body = pph()
    body += b"\x00" * 12 + socket.inet_aton("10.99.0.254")  # local addr
    body += struct.pack("!HH", 179, 33001)
    o = bgp_open()
    return bmp_msg(3, body + o + o)


def bgp_update(pas, nlri, withdrawn=b""):
    body = struct.pack("!H", len(withdrawn)) + withdrawn
    body += struct.pack("!H", len(pas)) + pas + nlri
    return b"\xff" * 16 + struct.pack("!HB", 19 + len(body), 2) + body


def pa(flags, type_code, val):
    return bytes([flags, type_code, len(val)]) + val


def announce(path_id, nexthop):
    pas = pa(0x40, 1, b"\x00")  # ORIGIN IGP
    pas += pa(0x40, 2, bytes([2, 1]) + struct.pack("!I", PEER_AS))  # AS_PATH
    pas += pa(0x40, 3, socket.inet_aton(nexthop))  # NEXT_HOP
    nlri = struct.pack("!I", path_id) + PREFIX_WIRE
    return bmp_msg(0, pph() + bgp_update(pas, nlri))


def withdraw(path_id):
    wd = struct.pack("!I", path_id) + PREFIX_WIRE
    return bmp_msg(0, pph() + bgp_update(b"", b"", withdrawn=wd))


def fs_announce(path_id, rule):
    # MP_REACH_NLRI: AFI 1, SAFI 133, next hop length 0, reserved, then the
    # RFC 7911 path id + RFC 8955 length header + raw rule bytes.
    mp = struct.pack("!HBBB", 1, 133, 0, 0)
    mp += struct.pack("!I", path_id) + bytes([len(rule)]) + rule
    pas = pa(0x40, 1, b"\x00")  # ORIGIN IGP
    pas += pa(0x40, 2, bytes([2, 1]) + struct.pack("!I", PEER_AS))  # AS_PATH
    pas += pa(0x80, 14, mp)
    return bmp_msg(0, pph() + bgp_update(pas, b""))


def fs_withdraw(path_id, rule):
    # MP_UNREACH_NLRI: AFI 1, SAFI 133, then path id + length header + rule.
    mp = struct.pack("!HB", 1, 133)
    mp += struct.pack("!I", path_id) + bytes([len(rule)]) + rule
    pas = pa(0x80, 15, mp)
    return bmp_msg(0, pph() + bgp_update(pas, b""))


def peer_down():
    # Reason 4: remote system closed without notification.
    return bmp_msg(2, pph() + bytes([4]))


# --- BMP consumer-side parsing --------------------------------------------------


class BmpReader:
    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def read_msg(self):
        self.sock.settimeout(min(10.0, remaining()))
        while True:
            if len(self.buf) >= 6:
                version, length, msg_type = struct.unpack(
                    "!BIB", self.buf[:6]
                )
                assert version == 3, f"bad BMP version {version}"
                if len(self.buf) >= length:
                    msg = self.buf[:length]
                    self.buf = self.buf[length:]
                    return msg_type, msg
            chunk = self.sock.recv(65536)
            if not chunk:
                raise SystemExit("FAIL: bmp-out closed the connection")
            self.buf += chunk


def parse_route_monitoring(msg):
    """Return (withdrawn_bytes, nlri_bytes) of the encapsulated UPDATE."""
    bgp = msg[6 + 42 :]
    assert bgp[18] == 2, "not a BGP UPDATE"
    wd_len = struct.unpack("!H", bgp[19:21])[0]
    wd = bgp[21 : 21 + wd_len]
    pa_len = struct.unpack("!H", bgp[21 + wd_len : 23 + wd_len])[0]
    nlri = bgp[23 + wd_len + pa_len :]
    return wd, nlri


def addpath_entries(field):
    """Split a path-id-carrying NLRI/withdrawn field into (pid, wire) pairs."""
    out = []
    while field:
        pid = struct.unpack("!I", field[:4])[0]
        plen = field[4]
        nbytes = (plen + 7) // 8
        out.append((pid, field[4 : 5 + nbytes]))
        field = field[5 + nbytes :]
    return out


def open_cap69_quads(open_msg):
    """Return the set of 4-byte family quads of cap 69 in one BGP OPEN."""
    opt_len = open_msg[28]
    opts = open_msg[29 : 29 + opt_len]
    quads = set()
    i = 0
    while i < len(opts):
        ptype, plen = opts[i], opts[i + 1]
        pval = opts[i + 2 : i + 2 + plen]
        if ptype == 2:
            j = 0
            while j < len(pval):
                code, clen = pval[j], pval[j + 1]
                if code == 69:
                    val = pval[j + 2 : j + 2 + clen]
                    for k in range(0, len(val), 4):
                        quads.add(bytes(val[k : k + 4]))
                j += 2 + clen
        i += 2 + plen
    return quads


def expect_peer_up_with_cap69(reader, context):
    """Skip to the next Peer Up; assert cap 69 in both OPENs advertises
    exactly the negotiated unicast + flowspec quads."""
    want = {ADDPATH_QUAD_UNICAST, ADDPATH_QUAD_FLOWSPEC}
    while True:
        msg_type, msg = reader.read_msg()
        if msg_type != 3:
            continue
        off = 6 + 42 + 16 + 2 + 2  # headers, local addr, ports
        for which in ("sent", "received"):
            olen = struct.unpack("!H", msg[off + 16 : off + 18])[0]
            quads = open_cap69_quads(msg[off : off + olen])
            assert quads == want, (
                f"FAIL ({context}): {which} OPEN of the synthesized Peer "
                f"Up advertises cap-69 quads {sorted(quads)}, "
                f"expected {sorted(want)}"
            )
            off += olen
        return


def collect_announced_pids(reader, want, context):
    """Read Route Monitoring announcements until `want` path ids are seen."""
    pids = []
    while len(pids) < want:
        msg_type, msg = reader.read_msg()
        if msg_type != 0:
            continue
        wd, nlri = parse_route_monitoring(msg)
        if not nlri:
            continue  # EoR, withdraw-only, or MP-only (flowspec)
        for pid, wire in addpath_entries(nlri):
            assert wire == PREFIX_WIRE, (
                f"FAIL ({context}): unexpected NLRI {wire.hex()}"
            )
            pids.append(pid)
    return pids


def parse_path_attrs(msg):
    """Return {type_code: value} of the encapsulated UPDATE's attributes."""
    bgp = msg[6 + 42 :]
    wd_len = struct.unpack("!H", bgp[19:21])[0]
    pa_len = struct.unpack("!H", bgp[21 + wd_len : 23 + wd_len])[0]
    pas = bgp[23 + wd_len : 23 + wd_len + pa_len]
    attrs = {}
    i = 0
    while i < len(pas):
        flags, code = pas[i], pas[i + 1]
        if flags & 0x10:  # extended length
            alen = struct.unpack("!H", pas[i + 2 : i + 4])[0]
            i += 4
        else:
            alen = pas[i + 2]
            i += 3
        attrs[code] = pas[i : i + alen]
        i += alen
    return attrs


def fs_addpath_entries(value, reach):
    """Split an MP_REACH (reach=True) or MP_UNREACH flowspec attribute value
    into (path_id, raw_rule) pairs."""
    afi, safi = struct.unpack("!HB", value[:3])
    assert (afi, safi) == (1, 133), f"unexpected family {afi}/{safi}"
    if reach:
        nhlen = value[3]
        field = value[3 + 1 + nhlen + 1 :]
    else:
        field = value[3:]
    out = []
    while field:
        pid = struct.unpack("!I", field[:4])[0]
        ln = field[4]
        assert ln < 240, "long flowspec NLRI unexpected in this test"
        out.append((pid, bytes(field[5 : 5 + ln])))
        field = field[5 + ln :]
    return out


def collect_fs_announced(reader, want, context):
    """Read Route Monitoring messages until `want` flowspec (pid, rule)
    announcements are seen."""
    entries = []
    while len(entries) < want:
        msg_type, msg = reader.read_msg()
        if msg_type != 0:
            continue
        attrs = parse_path_attrs(msg)
        if 14 not in attrs:
            continue
        entries.extend(fs_addpath_entries(attrs[14], reach=True))
    return entries


# --- test sequence ---------------------------------------------------------------


def main():
    # Two consumers connect first and observe the whole session live:
    # b_fast on the fastpath unit (verbatim raw forwarding — its duplicate
    # suppression must map path-child payloads back to the session, or
    # every route arrives twice), b_reb on the rebuild unit (NLRI
    # re-encoded with path ids by bmp-out itself).
    consumers = [
        ("fastpath", BmpReader(connect(BMP_OUT_ADDR))),
        ("rebuild", BmpReader(connect(BMP_OUT_REBUILD_ADDR))),
    ]

    feeder = connect(BMP_IN_ADDR)
    feeder.sendall(initiation())
    feeder.sendall(peer_up())
    feeder.sendall(announce(1, "192.0.2.1"))
    feeder.sendall(announce(2, "192.0.2.2"))

    # Each consumer: Peer Up advertising cap 69 in both OPENs, then both
    # paths with their ids (one Route Monitoring per payload/raw copy).
    for context, reader in consumers:
        expect_peer_up_with_cap69(reader, context)
        pids = collect_announced_pids(reader, want=2, context=context)
        assert sorted(pids) == [1, 2], f"FAIL ({context}): pids {pids}"
        print(
            f"{context} live restream: cap 69 advertised, paths 1+2 "
            "with path ids: OK"
        )

    # FlowSpec ADD-PATH: two rules under distinct path ids; both consumers
    # must see them restreamed with their path ids inside MP_REACH.
    feeder.sendall(fs_announce(1, FS_RULE_A))
    feeder.sendall(fs_announce(2, FS_RULE_B))
    for context, reader in consumers:
        entries = collect_fs_announced(reader, want=2, context=context)
        assert sorted(entries) == [(1, FS_RULE_A), (2, FS_RULE_B)], (
            f"FAIL ({context} flowspec): {entries}"
        )
        print(f"{context} live flowspec restream with path ids: OK")

    # Withdraw path 1; both consumers must see a withdrawal carrying path
    # id 1 — and NO duplicate announcements of pids 1/2 in between (the
    # fastpath duplicate-suppression check would otherwise deliver every
    # parsed payload on top of its raw copy).
    feeder.sendall(withdraw(1))
    for context, reader in consumers:
        while True:
            msg_type, msg = reader.read_msg()
            if msg_type != 0:
                continue
            wd, nlri = parse_route_monitoring(msg)
            if not wd:
                assert not nlri, (
                    f"FAIL ({context}): duplicate announcement "
                    f"{addpath_entries(nlri)} after the initial paths"
                )
                continue
            entries = addpath_entries(wd)
            assert entries == [(1, PREFIX_WIRE)], (
                f"FAIL ({context} withdraw): {entries}"
            )
            break
        print(f"{context} withdraw of path 1 carries its path id: OK")

    # FlowSpec withdrawal of path 1's rule: MP_UNREACH carrying the path id
    # — and no duplicate flowspec announcements in between (the fastpath
    # duplicate-suppression must cover flowspec child payloads too).
    feeder.sendall(fs_withdraw(1, FS_RULE_A))
    for context, reader in consumers:
        while True:
            msg_type, msg = reader.read_msg()
            if msg_type != 0:
                continue
            attrs = parse_path_attrs(msg)
            if 15 in attrs:
                entries = fs_addpath_entries(attrs[15], reach=False)
                assert entries == [(1, FS_RULE_A)], (
                    f"FAIL ({context} flowspec withdraw): {entries}"
                )
                break
            assert 14 not in attrs, (
                f"FAIL ({context}): duplicate flowspec announcement "
                f"{fs_addpath_entries(attrs[14], reach=True)}"
            )
        print(f"{context} flowspec withdraw of path 1 carries its id: OK")

    # Consumer B2 connects now: its initial dump must advertise cap 69 and
    # replay ONLY the still-active path 2 — unicast prefix and flowspec
    # rule alike, each with its path id (the flowspec table walk follows
    # the unicast walk).
    b2 = BmpReader(connect(BMP_OUT_ADDR))
    expect_peer_up_with_cap69(b2, "dump")
    pids = collect_announced_pids(b2, want=1, context="dump")
    assert pids == [2], f"FAIL (dump): pids {pids}"
    entries = collect_fs_announced(b2, want=1, context="dump")
    assert entries == [(2, FS_RULE_B)], f"FAIL (dump flowspec): {entries}"
    print(
        "reconnect dump replays only path 2 (unicast + flowspec), "
        "with path ids: OK"
    )

    # HTTP: the register shows both bgpPath children with pathId and a
    # shared parentIngress (the session).
    with urllib.request.urlopen(
        f"http://{HTTP_ADDR}/api/v1/ingresses", timeout=10
    ) as resp:
        ingresses = json.load(resp)["data"]
    children = [
        e for e in ingresses if e.get("ingress_type") == "bgpPath"
    ]
    assert len(children) == 2, (
        f"FAIL: expected 2 bgpPath children, got {len(children)}: "
        f"{json.dumps(ingresses, indent=2)[:2000]}"
    )
    assert sorted(c.get("path_id") for c in children) == [1, 2], children
    parents = {c.get("parent_ingress") for c in children}
    assert len(parents) == 1 and None not in parents, children
    print("/ingresses shows two bgpPath children with pathId + parent: OK")

    # Peer down: exactly ONE downstream Peer Down per consumer (the
    # session; the path children never became downstream peers).
    feeder.sendall(peer_down())
    for context, reader in consumers:
        peer_downs = 0
        end = time.monotonic() + 3.0
        while time.monotonic() < end:
            reader.sock.settimeout(max(0.1, end - time.monotonic()))
            try:
                msg_type, _msg = reader.read_msg()
            except (socket.timeout, TimeoutError):
                break
            if msg_type == 2:
                peer_downs += 1
        assert peer_downs == 1, (
            f"FAIL ({context}): expected exactly 1 Peer Down, "
            f"saw {peer_downs}"
        )
        print(f"{context}: peer down emitted exactly once: OK")

    feeder.close()
    for _, reader in consumers:
        reader.sock.close()
    b2.sock.close()


if __name__ == "__main__":
    try:
        main()
    except AssertionError as e:
        print(e, file=sys.stderr)
        sys.exit(1)
