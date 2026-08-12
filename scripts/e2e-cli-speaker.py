#!/usr/bin/env python3
"""Minimal BGP speaker for scripts/e2e-cli.sh.

Connects to netom's bgp-tcp-in listener, establishes a session and
announces three prefixes, then holds the session open with KEEPALIVEs so
netom-cli can be run against a live, established peer.
"""
import socket
import struct
import sys
import time

ADDR = sys.argv[1]
MY_AS = 65001
MY_ID = "10.1.0.1"
HOLD = 90

MARKER = b"\xff" * 16


def msg(typ, body):
    return MARKER + struct.pack("!HB", 19 + len(body), typ) + body


def open_msg():
    caps = bytes([1, 4]) + struct.pack("!HBB", 1, 0, 1)      # MP v4 unicast
    caps += bytes([65, 4]) + struct.pack("!I", MY_AS)        # 4-octet ASN
    opt = bytes([2, len(caps)]) + caps
    body = struct.pack("!BHH", 4, MY_AS, HOLD)
    body += socket.inet_aton(MY_ID) + bytes([len(opt)]) + opt
    return msg(1, body)


def keepalive():
    return msg(4, b"")


def pa(flags, code, val):
    return bytes([flags, code, len(val)]) + val


def update(prefix_bytes):
    pas = pa(0x40, 1, b"\x00")                                  # ORIGIN
    pas += pa(0x40, 2, bytes([2, 1]) + struct.pack("!I", MY_AS))  # AS_PATH
    pas += pa(0x40, 3, socket.inet_aton("192.0.2.1"))            # NEXT_HOP
    body = struct.pack("!H", 0)
    body += struct.pack("!H", len(pas)) + pas + prefix_bytes
    return msg(2, body)


host, port = ADDR.split(":")
s = socket.create_connection((host, int(port)))
s.settimeout(10)
s.sendall(open_msg())
s.sendall(keepalive())
time.sleep(1)

# Three prefixes: 10.0.0.0/24, 10.0.1.0/24, 10.0.2.0/24
for third in (0, 1, 2):
    s.sendall(update(bytes([24, 10, 0, third])))
    time.sleep(0.2)

print("BGP session established and 3 prefixes announced")

# Keep the session alive so the CLI can observe it.
deadline = time.time() + 90
while time.time() < deadline:
    s.sendall(keepalive())
    time.sleep(10)
