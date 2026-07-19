#!/usr/bin/env python3
"""ADD-PATH (RFC 7911) end-to-end driver/assertor for netom's BMP pipeline.

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

PEER_IP = "10.99.0.1"
PEER_AS = 65001
PREFIX_WIRE = bytes([24, 10, 0, 0])  # 10.0.0.0/24
ADDPATH_CAP = bytes([69, 4, 0, 1, 1, 3])  # v4 unicast, SendReceive

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
    # Capabilities: ADD-PATH (69) + 4-octet ASN (65), one type-2 parameter.
    caps = ADDPATH_CAP + bytes([65, 4]) + struct.pack("!I", PEER_AS)
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


def expect_peer_up_with_cap69(reader, context):
    """Skip to the next Peer Up; assert cap 69 appears in both OPENs."""
    while True:
        msg_type, msg = reader.read_msg()
        if msg_type != 3:
            continue
        count = 0
        for i in range(len(msg) - len(ADDPATH_CAP) + 1):
            if msg[i : i + len(ADDPATH_CAP)] == ADDPATH_CAP:
                count += 1
        assert count == 2, (
            f"FAIL ({context}): expected cap 69 in both OPENs of the "
            f"synthesized Peer Up, found {count} occurrence(s)"
        )
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
            continue  # EoR or withdraw-only
        for pid, wire in addpath_entries(nlri):
            assert wire == PREFIX_WIRE, (
                f"FAIL ({context}): unexpected NLRI {wire.hex()}"
            )
            pids.append(pid)
    return pids


# --- test sequence ---------------------------------------------------------------


def main():
    # Consumer B1 connects first: it observes the (empty) initial dump and
    # then the whole session live.
    b1 = BmpReader(connect(BMP_OUT_ADDR))

    feeder = connect(BMP_IN_ADDR)
    feeder.sendall(initiation())
    feeder.sendall(peer_up())
    feeder.sendall(announce(1, "192.0.2.1"))
    feeder.sendall(announce(2, "192.0.2.2"))

    # B1: Peer Up advertising cap 69 in both OPENs, then both paths with
    # their ids (the live path emits one Route Monitoring per payload).
    expect_peer_up_with_cap69(b1, "live")
    pids = collect_announced_pids(b1, want=2, context="live")
    assert sorted(pids) == [1, 2], f"FAIL (live): pids {pids}"
    print("live restream: cap 69 advertised, paths 1+2 with path ids: OK")

    # Withdraw path 1; B1 must see a withdrawal carrying path id 1.
    feeder.sendall(withdraw(1))
    while True:
        msg_type, msg = b1.read_msg()
        if msg_type != 0:
            continue
        wd, _nlri = parse_route_monitoring(msg)
        if not wd:
            continue
        entries = addpath_entries(wd)
        assert entries == [(1, PREFIX_WIRE)], (
            f"FAIL (live withdraw): {entries}"
        )
        break
    print("live withdraw of path 1 carries its path id: OK")

    # Consumer B2 connects now: its initial dump must advertise cap 69 and
    # replay ONLY the still-active path 2, with its path id.
    b2 = BmpReader(connect(BMP_OUT_ADDR))
    expect_peer_up_with_cap69(b2, "dump")
    pids = collect_announced_pids(b2, want=1, context="dump")
    assert pids == [2], f"FAIL (dump): pids {pids}"
    print("reconnect dump replays only path 2, with its path id: OK")

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

    # Peer down: exactly ONE downstream Peer Down (the session; the path
    # children never became downstream peers).
    feeder.sendall(peer_down())
    peer_downs = 0
    end = time.monotonic() + 3.0
    while time.monotonic() < end:
        b1.sock.settimeout(max(0.1, end - time.monotonic()))
        try:
            msg_type, _msg = b1.read_msg()
        except (socket.timeout, TimeoutError):
            break
        if msg_type == 2:
            peer_downs += 1
    assert peer_downs == 1, (
        f"FAIL: expected exactly 1 Peer Down, saw {peer_downs}"
    )
    print("peer down emitted exactly once for the session: OK")

    feeder.close()
    b1.sock.close()
    b2.sock.close()


if __name__ == "__main__":
    try:
        main()
    except AssertionError as e:
        print(e, file=sys.stderr)
        sys.exit(1)
