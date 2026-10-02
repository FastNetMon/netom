#!/usr/bin/env python3
"""Exercise automatic BMP reconciliation against isolated real daemons.

Reconnection replays the exporter's authoritative current peers and routes.
Includes issue #11 churn, parallel sessions, silent disappearance, partial
frames and capacity limits. Python stdlib only; exit 0 on success, 1 on failure.
"""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def bmp(kind, body):
    return struct.pack("!BIB", 3, len(body) + 6, kind) + body


def bgp(kind, body):
    return b"\xff" * 16 + struct.pack("!HB", len(body) + 19, kind) + body


def header(address):
    # Global instance, IPv6 peer, pre-policy, fixed ASN and BGP identifier.
    return (bytes([0, 0x80]) + bytes(8)
            + socket.inet_pton(socket.AF_INET6, address)
            + struct.pack("!I", 65001) + socket.inet_aton("10.0.0.7")
            + bytes(8))


def peer_up(address):
    caps = bytes([1, 4, 0, 1, 0, 1, 65, 4]) + struct.pack("!I", 65001)
    opt = bytes([2, len(caps)]) + caps
    def open_msg(asn, identifier):
        return bgp(1, struct.pack("!BHH", 4, asn, 0)
                   + socket.inet_aton(identifier) + bytes([len(opt)]) + opt)
    return bmp(3, header(address)
               + socket.inet_pton(socket.AF_INET6, "fe80::ffff")
               + struct.pack("!HH", 179, 33001)
               + open_msg(65001, "10.0.0.254")
               + open_msg(65001, "10.0.0.7"))


def announce(address):
    # One identical IPv4 prefix via every incarnation of the IPv6 peer.
    attrs = bytes([0x40, 1, 1, 0, 0x40, 2, 6, 2, 1])
    attrs += struct.pack("!I", 65001)
    attrs += bytes([0x40, 3, 4]) + socket.inet_aton("10.0.0.7")
    update = bgp(2, bytes(2) + struct.pack("!H", len(attrs))
                 + attrs + bytes([32, 10, 0, 0, 7]))
    return bmp(0, header(address) + update)


def free_port():
    # Small bind race, as with other local integration harnesses. Startup
    # checks below fail explicitly if another process takes the port.
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_until(read, predicate, timeout, description):
    end = time.monotonic() + timeout
    last = None
    while time.monotonic() < end:
        last = read()
        if predicate(last):
            return last
        time.sleep(0.1)
    raise RuntimeError(f"timeout waiting for {description}: {last}")


class Exporter:
    """Authoritative exporter: reconnects replay only current sessions."""

    def __init__(self, port, snapshot):
        self.port = port
        self.snapshot = snapshot
        self.current = []
        self.socket = None
        self.replays = 0

    def connect(self):
        self.socket = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        name = b"peer-churn-feeder"
        self.socket.sendall(bmp(4, struct.pack("!HH", 2, len(name)) + name))
        self.replays += 1
        for address in self.current:
            self.socket.sendall(peer_up(address) + announce(address))
            # Empty IPv4 UPDATE = End-of-RIB for this peer.
            self.socket.sendall(bmp(0, header(address) + bgp(2, bytes(4))))
        wait_until(self.snapshot,
                   lambda s: set(s["addresses"]) == set(self.current),
                   5, "authoritative replay")

    def send(self, data):
        try:
            self.socket.sendall(data)
        except (BrokenPipeError, ConnectionResetError):
            # Reset can precede the new Peer Up; replay supplies it instead.
            pass

    def expect_reset(self, timeout=5):
        self.socket.settimeout(timeout)
        try:
            data = self.socket.recv(1)
            if data:
                raise RuntimeError("collector unexpectedly sent BMP data")
        except ConnectionResetError:
            pass
        except socket.timeout as error:
            raise RuntimeError("collector failed to reconcile") from error
        self.socket.close()
        self.socket = None

    def expect_open(self, seconds):
        self.socket.settimeout(seconds)
        try:
            self.socket.recv(1)
        except socket.timeout:
            return
        except ConnectionResetError:
            pass
        raise RuntimeError("unexpected reconnect: parallel replay/control must remain connected")

    def close(self):
        if self.socket:
            self.socket.close()
            self.socket = None


def simulate(binary, scenario, cycles, grace):
    http_port, bmp_port = free_port(), free_port()
    while bmp_port == http_port:
        bmp_port = free_port()
    # Production defaults stay enabled. Shorten only deadlines for the test.
    interval = 6 if scenario in {"silent", "partial"} else 120
    limit = 3 if scenario == "limit" else 65536
    with tempfile.TemporaryDirectory(prefix="netom-peer-churn-") as directory:
        directory = Path(directory)
        config = directory / "netom.conf"
        config.write_text(f'''http_listen = ["127.0.0.1:{http_port}"]
[units.bmp-in]
type = "bmp-tcp-in"
listen = "127.0.0.1:{bmp_port}"
reconciliation = {{ interval_secs = {interval}, min_session_secs = 1, replay_grace_secs = 1, max_peer_states = {limit} }}
[units.rib]
type = "rib"
sources = ["bmp-in"]
[targets.null]
type = "null-out"
sources = ["rib"]
''')
        env = dict(os.environ, NETOM_RIB_GC_INTERVAL_SECS="1",
                   NETOM_RIB_REAP_EVERY_TICKS="1")
        with (directory / "netom.log").open("w+") as log:
            process = subprocess.Popen([str(binary), "-c", str(config)],
                                       stdout=log, stderr=log, env=env)

            def get(path):
                if process.poll() is not None:
                    raise RuntimeError(f"daemon exited: {process.returncode}")
                with urllib.request.urlopen(
                        f"http://127.0.0.1:{http_port}{path}", timeout=3) as res:
                    return res.read().decode()

            def snapshot():
                peers = [p for p in json.loads(get("/api/v1/ingresses"))["data"]
                         if p.get("ingress_type") == "bgpViaBmp"]
                records = None
                for line in get("/metrics").splitlines():
                    name = line.split("{", 1)[0].split(" ", 1)[0]
                    if name == "netom_rib_unit_num_items_total":
                        records = (records or 0) + int(float(line.rsplit(" ", 1)[1]))
                if records is None:
                    raise RuntimeError("RIB record metric missing")
                return {"peers": len(peers), "records": records,
                        "addresses": sorted(p["remote_addr"] for p in peers
                                            if p.get("state") == "Connected")}

            exporter = Exporter(bmp_port, snapshot)
            try:
                def ready():
                    try:
                        return bool(get("/metrics"))
                    except (OSError, urllib.error.URLError):
                        return False
                wait_until(ready, bool, 30, "HTTP startup")
                exporter.current = ["fe80::1"]
                if scenario == "parallel":
                    exporter.current.append("fe80::2")
                exporter.connect()
                wait_until(snapshot, lambda s: s["records"] >= len(exporter.current),
                           5, "initial routes")
                if scenario in {"matching", "mismatched", "missing"}:
                    for i in range(1, cycles + 1):
                        # Move beyond the replay grace before introducing a new
                        # address. During replay it is deliberately not guessed
                        # to be a replacement.
                        if scenario != "matching":
                            time.sleep(1.1)
                        old = exporter.current[0]
                        address = str(ipaddress.IPv6Address(int(ipaddress.IPv6Address("fe80::1")) + i))
                        exporter.current = [address]
                        if scenario != "missing":
                            down = old if scenario == "matching" else "::"
                            exporter.send(bmp(2, header(down) + bytes([4])))
                        exporter.send(peer_up(address) + announce(address))
                        if scenario != "matching":
                            exporter.expect_reset()
                            exporter.connect()
                        else:
                            wait_until(snapshot, lambda s: s["addresses"] == [address],
                                       5, "matching Peer Down replacement")
                        if i in {1, cycles // 2, cycles}:
                            print(f"{scenario}: replacements={i}, replays={exporter.replays}: {snapshot()}", flush=True)
                elif scenario == "parallel":
                    # Startup siblings must coexist without an anomaly reset.
                    exporter.expect_open(1.3)
                    exporter.current.append("fe80::3")
                    exporter.send(peer_up("fe80::3") + announce("fe80::3"))
                    exporter.expect_reset()
                    exporter.connect()  # replay all three legitimate peers
                    exporter.expect_open(2)
                elif scenario in {"silent", "partial"}:
                    exporter.current = []  # real peer vanished; no Peer Down
                    if scenario == "partial":
                        exporter.send(bytes([3, 0, 0]))  # stalled common header
                    exporter.expect_reset(timeout=9)
                    exporter.connect()  # empty authoritative snapshot
                elif scenario == "limit":
                    # Startup growth must still be bounded by the capacity guard.
                    exporter.send(peer_up("fe80::2") + announce("fe80::2")
                                  + peer_up("fe80::3"))
                    exporter.expect_reset()
                    exporter.connect()  # only fe80::1 still exists

                expected = len(exporter.current)
                state = wait_until(snapshot, lambda s: s["peers"] == expected
                                   and s["records"] == expected
                                   and set(s["addresses"]) == set(exporter.current),
                                   grace, "reclamation after authoritative replay")
                # The control and parallel case must remain live; no false pass
                # because the collector disconnected and dropped everything.
                if expected:
                    exporter.expect_open(0.2)
                print(f"{scenario}: PASS, replays={exporter.replays}, after GC: {state}", flush=True)
                exporter.close()
                wait_until(snapshot, lambda s: s["peers"] == 0 and s["records"] == 0,
                           grace, "final BMP disconnect cleanup")
                return True
            except Exception:
                log.flush()
                log.seek(0)
                print("Daemon log (tail):\n" + log.read()[-6000:])
                raise
            finally:
                exporter.close()
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, help="existing netom binary; otherwise build release")
    parser.add_argument("--cycles", type=int, default=5, help="peer replacements (default: 5)")
    parser.add_argument("--grace", type=float, default=10, help="GC wait deadline in seconds (minimum: 4)")
    scenarios = ["matching", "mismatched", "missing", "parallel", "silent", "partial", "limit"]
    parser.add_argument("--scenario", choices=["all"] + scenarios, default="all")
    args = parser.parse_args()
    if args.cycles < 1 or not 4 <= args.grace < float("inf"):
        parser.error("cycles must be positive and grace must be finite and >= 4 seconds")
    root = Path(__file__).resolve().parent.parent
    if args.binary is None:
        subprocess.run(["cargo", "build", "--release", "--bin", "netom"], cwd=root, check=True)
        args.binary = root / "target/release/netom"
    if args.scenario != "all":
        scenarios = [args.scenario]
    for scenario in scenarios:
        simulate(args.binary.resolve(), scenario, args.cycles, args.grace)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", flush=True)
        raise SystemExit(1)
