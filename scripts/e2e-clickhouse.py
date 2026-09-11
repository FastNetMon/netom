#!/usr/bin/env python3
"""Feed an already-running Netom and check its ClickHouse observations.

No service changes or table deletion. --feed-only permits an outage/restart test;
use --verify TOKEN later. Each run has a distinct BMP router name for isolation.
"""
import argparse
import json
import socket
import ssl
import struct
import time
import urllib.parse
import urllib.request
import uuid


def bmp(typ, body):
    return struct.pack("!BIB", 3, 6 + len(body), typ) + body


def pph():
    return (b"\0\0" + b"\0" * 8 + b"\0" * 12 + socket.inet_aton("10.99.0.1")
            + struct.pack("!I", 65001) + socket.inet_aton("10.99.0.1") + b"\0" * 8)


def bgp(typ, body):
    return b"\xff" * 16 + struct.pack("!HB", 19 + len(body), typ) + body


def opening():
    caps = bytes([1, 4, 0, 1, 0, 1, 1, 4, 0, 2, 0, 1])
    caps += bytes([69, 8, 0, 1, 1, 3, 0, 2, 1, 3])
    caps += bytes([65, 4]) + struct.pack("!I", 65001)
    opt = bytes([2, len(caps)]) + caps
    return bgp(1, struct.pack("!BHH4sB", 4, 65001, 90, socket.inet_aton("10.99.0.1"), len(opt)) + opt)


def pa(typ, body, flags=0x40):
    return bytes([flags, typ, len(body)]) + body


def attrs():
    return (pa(1, b"\0") + pa(2, bytes([2, 1]) + struct.pack("!I", 65001))
            + pa(3, socket.inet_aton("192.0.2.1"))
            + pa(4, struct.pack("!I", 37), 0x80)
            + pa(5, struct.pack("!I", 100))
            + pa(8, struct.pack("!I", 65001 << 16 | 42), 0xc0)
            + pa(99, bytes([0, 255, 128]), 0x80))


def update(attributes=b"", nlri=b"", withdrawn=b""):
    body = struct.pack("!H", len(withdrawn)) + withdrawn
    body += struct.pack("!H", len(attributes)) + attributes + nlri
    return bmp(0, pph() + bgp(2, body))


def feed(address, token, routes, serve=False, tls_cert=None, tls_key=None):
    host, port = address.rsplit(":", 1)
    host = host.strip("[]")
    if serve:
        with socket.create_server((host, int(port)), family=socket.AF_INET6 if ":" in host else socket.AF_INET) as listener:
            listener.settimeout(60)
            print(f"Serving BMP on {address}", flush=True)
            sock, _ = listener.accept()
            with sock:
                if tls_cert:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain(tls_cert, tls_key)
                    with context.wrap_socket(sock, server_side=True) as tls:
                        send_observations(tls, token, routes)
                else:
                    send_observations(sock, token, routes)
    else:
        with socket.create_connection((host, int(port)), timeout=30) as sock:
            send_observations(sock, token, routes)


def send_observations(sock, token, routes):
    sock.settimeout(30)
    name = token.encode()
    sock.sendall(bmp(4, struct.pack("!HH", 2, len(name)) + name))
    peer_up = bmp(3, pph() + b"\0" * 12 + socket.inet_aton("10.99.0.254")
                  + struct.pack("!HH", 179, 33001) + opening() * 2)
    sock.sendall(peer_up)
    prefix = struct.pack("!I", 1) + bytes([24, 192, 0, 2])
    # Two identical observations must remain two rows.
    sock.sendall(update(attrs(), prefix) * 2)
    sock.sendall(update(withdrawn=prefix))
    sock.sendall(update(attrs(), prefix))
    mp = struct.pack("!HBB", 2, 1, 16) + socket.inet_pton(socket.AF_INET6, "2001:db8::1") + b"\0"
    mp += struct.pack("!I", 2) + bytes([48]) + bytes.fromhex("20010db80042")
    sock.sendall(update(attrs() + pa(14, mp, 0x80)))
    for base in range(0, routes, 300):
        nlri = b"".join(struct.pack("!IBI", 3, 32, 0x0a000000 + n)
                        for n in range(base, min(routes, base + 300)))
        sock.sendall(update(attrs(), nlri))
    sock.sendall(bmp(2, pph() + b"\x04"))
    time.sleep(0.25)
    # Same peer, new session generation, must have a distinct peer_key.
    sock.sendall(peer_up)
    sock.sendall(update(attrs(), prefix))
    time.sleep(0.25)
    sock.sendall(bmp(2, pph() + b"\x04"))
    time.sleep(0.25)


def query(endpoint, sql):
    request = urllib.request.Request(endpoint + "/?" + urllib.parse.urlencode({"query": sql}), data=b"\n")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=30) as response:
        return json.load(response)["data"]


def verify(endpoint, token, routes):
    # token only comes from our generated UUID or constrained CLI input.
    assert token.startswith("netom-ch-") and token[9:].isalnum()
    scope = f"peer_key IN (SELECT peer_key FROM netom_test.events WHERE event_kind=3 AND position(identity, '{token}')>0)"
    sql = f"""SELECT count() AS rows, countIf(event_kind=1) AS announcements,
        countIf(event_kind=2) AS withdrawals, uniqExact(peer_key) AS peers,
        countIf(afi=2) AS ipv6, uniqExact(tuple(stream_id,epoch,event_seq)) AS ids
        FROM netom_test.events WHERE event_class=1 AND {scope} FORMAT JSON"""
    deadline = time.monotonic() + 120
    while True:
        result = query(endpoint, sql)[0]
        if int(result["rows"]) >= routes + 6:
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"Timed out waiting for {routes+6} routes: {result}")
        time.sleep(1)
    assert int(result["rows"]) == routes + 6, result
    assert int(result["announcements"]) == routes + 5, result
    assert int(result["withdrawals"]) == 1, result
    assert int(result["ipv6"]) == 1, result
    assert int(result["peers"]) == 2, result
    assert int(result["ids"]) == routes + 6, result
    detail = query(endpoint, f"SELECT hex(raw_attrs) AS raw, as_path, communities, med, local_pref, path_id, toString(next_hop) AS nh FROM netom_test.events WHERE event_kind=1 AND afi=1 AND {scope} LIMIT 1 FORMAT JSON")[0]
    assert detail["raw"] == attrs().hex().upper(), detail
    assert detail["as_path"] == [65001] and detail["communities"] == [65001 << 16 | 42], detail
    assert detail["med"] == 37 and detail["local_pref"] == 100 and detail["path_id"] in (1, 3), detail
    assert detail["nh"] == "::ffff:192.0.2.1", detail
    invalidations = query(endpoint, f"SELECT count() AS n FROM netom_test.events WHERE event_kind=4 AND {scope} FORMAT JSON")[0]
    assert int(invalidations["n"]) >= 2, invalidations
    print(json.dumps({"token": token, "passed": result, "compact_invalidations": invalidations["n"]}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bmp", default="127.0.0.1:11019")
    parser.add_argument("--clickhouse", default="http://127.0.0.1:8123")
    parser.add_argument("--routes", type=int, default=1000)
    parser.add_argument("--feed-only", action="store_true")
    parser.add_argument("--serve", action="store_true", help="Accept an active Netom BMP input instead of connecting to a listener")
    parser.add_argument("--tls-cert", help="PEM certificate for --serve")
    parser.add_argument("--tls-key", help="PEM private key for --serve")
    parser.add_argument("--verify")
    args = parser.parse_args()
    if bool(args.tls_cert) != bool(args.tls_key) or (args.tls_cert and not args.serve):
        parser.error("--tls-cert and --tls-key require each other and --serve")
    assert 0 <= args.routes <= 1_000_000
    token = args.verify or "netom-ch-" + uuid.uuid4().hex
    print(token, flush=True)
    if not args.verify:
        feed(args.bmp, token, args.routes, args.serve, args.tls_cert, args.tls_key)
    if not args.feed_only:
        verify(args.clickhouse, token, args.routes)
