"""Live rule-policy test: real WinDivert, real proxyclaw.exe, real TCP.

Starts proxyclaw.exe (administrator required) with a throwaway config whose
default group points at a SOCKS5 server run by this script. Each case runs a
private copy of System32 curl.exe under a unique name, so exactly one rule
matches it, and checks whether the connection went through the SOCKS5 server
(proxied) or not (direct). Both paths must still complete the request.

Destinations are public anycast addresses (1.1.1.1 / 1.0.0.1), so the runner
needs outbound internet. No other proxy or service is needed.

Usage (elevated):
    python tests/e2e_rule_policy.py --exe build/Release/proxyclaw.exe
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import pathlib
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

API = "http://127.0.0.1:18080/api"
SYSTEM_CURL = pathlib.Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "curl.exe"


class Socks5Server:
    """Minimal SOCKS5 CONNECT relay that records every requested destination."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.seen: list[tuple[str, int]] = []
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(64)
        self.port = self.listener.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def take(self) -> list[tuple[str, int]]:
        with self.lock:
            out, self.seen = self.seen, []
        return out

    def _accept(self) -> None:
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def _exact(sock: socket.socket, n: int) -> bytes:
        data = b""
        while len(data) < n:
            part = sock.recv(n - len(data))
            if not part:
                raise EOFError
            data += part
        return data

    def _serve(self, conn: socket.socket) -> None:
        conn.settimeout(15)
        try:
            ver, nmethods = self._exact(conn, 2)
            self._exact(conn, nmethods)
            conn.sendall(b"\x05\x00")
            ver, cmd, _, atyp = self._exact(conn, 4)
            if atyp == 1:
                host = socket.inet_ntoa(self._exact(conn, 4))
            elif atyp == 3:
                host = self._exact(conn, self._exact(conn, 1)[0]).decode()
            elif atyp == 4:
                host = socket.inet_ntop(socket.AF_INET6, self._exact(conn, 16))
            else:
                return
            port = struct.unpack("!H", self._exact(conn, 2))[0]
            with self.lock:
                self.seen.append((host, port))
            if cmd != 1:
                conn.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
                return
            upstream = socket.create_connection((host, port), timeout=10)
            conn.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00")
            self._pump(conn, upstream)
        except Exception:
            pass
        finally:
            conn.close()

    @staticmethod
    def _pump(a: socket.socket, b: socket.socket) -> None:
        def one_way(src: socket.socket, dst: socket.socket) -> None:
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        t = threading.Thread(target=one_way, args=(b, a), daemon=True)
        t.start()
        one_way(a, b)
        t.join(20)
        b.close()


def rule(name: str, protocol: str = "tcp", **dst) -> dict:
    return {
        "id": f"e2e_{name}",
        "name": f"e2e {name}",
        "enabled": True,
        "process_name": f"pc_e2e_{name}.exe",
        "cmdline_pattern": "",
        "image_path_pattern": "",
        "hack_tree": True,
        "protocol": protocol,
        "proxy_group_id": 0,
        "dst_filter": {
            "include_cidrs": dst.get("include_cidrs", []),
            "exclude_cidrs": dst.get("exclude_cidrs", []),
            "include_ports": dst.get("include_ports", []),
            "exclude_ports": dst.get("exclude_ports", []),
        },
    }


# (rule, [(url, expect_proxied)])
CASES = [
    (rule("control", "both"), [("http://1.1.1.1/", True)]),
    (rule("inc443", include_ports=["443"]), [("https://1.1.1.1/", True), ("http://1.1.1.1/", False)]),
    (rule("exc80", exclude_ports=["80"]), [("http://1.1.1.1/", False), ("https://1.1.1.1/", True)]),
    (rule("inccidr", include_cidrs=["1.0.0.0/24"]), [("http://1.0.0.1/", True), ("http://1.1.1.1/", False)]),
    (rule("exccidr", exclude_cidrs=["1.1.1.0/24"]), [("http://1.1.1.1/", False), ("http://1.0.0.1/", True)]),
    (rule("udponly", "udp"), [("http://1.1.1.1/", False)]),
]


def api_get(path: str, token: str) -> object:
    req = urllib.request.Request(API + path, headers={"X-ProxyClaw-Token": token})
    with urllib.request.urlopen(req, timeout=3) as resp:
        return json.loads(resp.read())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True, type=pathlib.Path)
    ap.add_argument("--keep", action="store_true", help="keep the temp dir")
    args = ap.parse_args()

    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("SKIP: needs an elevated shell (WinDivert)")
        return 2

    exe = args.exe.resolve()
    work = pathlib.Path(tempfile.mkdtemp(prefix="pc_e2e_rules_"))
    socks = Socks5Server()
    token = secrets.token_hex(32)

    config = {
        "version": 2,
        "default_proxy": {"type": "socks5", "host": "127.0.0.1", "port": socks.port},
        "proxy_groups": [{"id": 0, "name": "default", "host": "127.0.0.1",
                          "port": socks.port, "type": "socks5"}],
        "next_group_id": 1,
        "auto_rules": [c[0] for c in CASES],
        "log_level": "debug",
        "dns": {"enabled": False},
    }
    cfg_path = work / "proxyclaw.json"
    cfg_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

    probes = {}
    for r, _ in CASES:
        dst = work / r["process_name"]
        shutil.copy2(SYSTEM_CURL, dst)
        probes[r["id"]] = dst

    env = dict(os.environ, PROXYCLAW_API_TOKEN=token)
    proc = subprocess.Popen([str(exe), "--minimized", "--config", str(cfg_path)],
                            cwd=exe.parent, env=env)
    failures: list[str] = []
    try:
        deadline = time.time() + 30
        while True:
            if proc.poll() is not None:
                raise RuntimeError(f"proxyclaw.exe exited early with {proc.returncode}")
            try:
                rules = api_get("/auto-rules", token)
                if len(rules) >= len(CASES):
                    break
            except Exception:
                pass
            if time.time() > deadline:
                raise RuntimeError("proxyclaw API did not come up in 30s")
            time.sleep(0.5)
        time.sleep(2)  # let the WinDivert layers settle

        for r, checks in CASES:
            for url, expect_proxied in checks:
                socks.take()
                cmd = [str(probes[r["id"]]), "-s", "-k", "-o", os.devnull,
                       "-w", "%{http_code}", "--noproxy", "*",
                       "--connect-timeout", "10", "-m", "20", url]
                res = subprocess.run(cmd, capture_output=True, text=True)
                time.sleep(0.3)
                seen = socks.take()
                host = url.split("/")[2]
                port = 443 if url.startswith("https") else 80
                proxied = (host, port) in seen
                ok = res.returncode == 0 and proxied == expect_proxied
                verdict = "PASS" if ok else "FAIL"
                print(f"{verdict} {r['id']:<12} {url:<20} expect={'proxy' if expect_proxied else 'direct'}"
                      f" got={'proxy' if proxied else 'direct'} curl_rc={res.returncode} http={res.stdout}")
                if not ok:
                    failures.append(f"{r['id']} {url}")
    finally:
        proc.terminate()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
        log = exe.parent / "proxyclaw.log"
        if failures and log.exists():
            print("---- proxyclaw.log (WD-SOCKET / RULE lines, last 80) ----")
            lines = [l for l in log.read_text(encoding="utf-8", errors="replace").splitlines()
                     if "WD-SOCKET" in l or "[RULE]" in l or "[E]" in l]
            print("\n".join(lines[-80:]))
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)

    total = sum(len(c[1]) for c in CASES)
    print(f"{total - len(failures)}/{total} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
