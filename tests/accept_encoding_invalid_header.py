#!/usr/bin/env python3
import argparse
import os
import socket
import subprocess
import sys
import threading
import time

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover - fallback for older Pythons
    import tomli as tomllib  # type: ignore


def load_listen_addr(config_path: str) -> str:
    with open(config_path, "rb") as f:
        data = tomllib.load(f)
    listen = data.get("http_listen")
    if listen is None:
        raise SystemExit(
            f"config {config_path} has no http_listen; "
            "use a config that enables the HTTP API"
        )
    if isinstance(listen, str):
        return listen
    if isinstance(listen, list) and listen:
        if not isinstance(listen[0], str):
            raise SystemExit("http_listen entries must be strings")
        return listen[0]
    raise SystemExit("http_listen is empty or invalid")


def split_host_port(addr: str) -> tuple[str, int]:
    if addr.startswith("["):
        host, rest = addr[1:].split("]", 1)
        if not rest.startswith(":"):
            raise SystemExit(f"invalid listen address: {addr}")
        port = rest[1:]
    else:
        if addr.count(":") > 1:
            raise SystemExit(
                "IPv6 addresses must be bracketed like [::1]:9090"
            )
        host, port = addr.rsplit(":", 1)
    return host, int(port)


def normalize_host(host: str) -> str:
    if host in ("0.0.0.0", ""):
        return "127.0.0.1"
    if host in ("::", "[::]"):
        return "::1"
    return host


def wait_for_port(
    host: str,
    port: int,
    timeout: float,
    proc: subprocess.Popen | None = None,
    stderr_lines: list[str] | None = None,
) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc is not None and proc.poll() is not None:
            raise SystemExit(
                "server exited before opening port; "
                f"exit={proc.returncode}\n"
                f"stderr:\n{format_stderr(stderr_lines)}"
            )
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise SystemExit(
        f"server did not open {host}:{port} within {timeout}s\n"
        f"stderr:\n{format_stderr(stderr_lines)}"
    )


def send_invalid_header(host: str, port: int) -> None:
    req = (
        b"GET /metrics HTTP/1.1\r\n"
        + b"Host: "
        + host.encode("ascii", "ignore")
        + b"\r\n"
        + b"Accept-Encoding: \xff\xfe\r\n"
        + b"Connection: close\r\n\r\n"
    )
    with socket.create_connection((host, port), timeout=2) as sock:
        sock.sendall(req)
        try:
            sock.recv(1024)
        except OSError:
            pass


def collect_stderr(proc: subprocess.Popen, sink: list[str]) -> None:
    assert proc.stderr is not None
    for line in iter(proc.stderr.readline, b""):
        try:
            sink.append(line.decode("utf-8", "replace").rstrip())
        except Exception:
            sink.append(repr(line))


def format_stderr(lines: list[str] | None) -> str:
    if not lines:
        return "(no stderr captured)"
    return "\n".join(lines[-40:])


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Trigger invalid Accept-Encoding bytes and detect panic."
    )
    parser.add_argument(
        "--config",
        default="netom-mrt.conf",
        help="Path to Netom config with http_listen enabled.",
    )
    parser.add_argument(
        "--cargo-cmd",
        default="cargo",
        help="Cargo executable (default: cargo).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        help="Seconds to wait for startup and panic.",
    )
    args = parser.parse_args()

    config_path = os.path.abspath(args.config)
    listen_addr = load_listen_addr(config_path)
    host, port = split_host_port(listen_addr)
    host = normalize_host(host)

    proc = subprocess.Popen(
        [args.cargo_cmd, "run", "--release", "--", "-c", config_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=False,
    )

    stderr_lines: list[str] = []
    stderr_thread = threading.Thread(
        target=collect_stderr, args=(proc, stderr_lines), daemon=True
    )
    stderr_thread.start()

    try:
        wait_for_port(
            host, port, timeout=args.timeout, proc=proc, stderr_lines=stderr_lines
        )
        send_invalid_header(host, port)
        time.sleep(min(2.0, args.timeout))

        proc.poll()
        panic_markers = (
            "panicked at",
            "called `Result::unwrap()` on an `Err` value",
        )
        if proc.returncode not in (None, 0):
            print("Process exited after invalid Accept-Encoding header.")
            return 0
        if any(marker in line for line in stderr_lines for marker in panic_markers):
            print("Observed panic output after invalid Accept-Encoding header.")
            return 0

        print(
            "Did not observe a panic or process exit; "
            "check stderr for details."
        )
        return 1
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)


if __name__ == "__main__":
    raise SystemExit(main())
